"""
Static analysis scanner for Python packages.

Detects malicious patterns via AST parsing and regex fallback:
- .pth file injection
- Base64-encoded exec/eval payloads
- Suspicious imports in setup.py
- Overridden install commands
- Obfuscated code (double base64, XOR, zlib decompress)
"""

import ast
import re
import logging
from pathlib import Path

from packageguard import Finding

logger = logging.getLogger(__name__)

# Suspicious imports in setup.py
SUSPICIOUS_IMPORTS = {
    "subprocess", "socket", "http.client", "urllib", "urllib.request",
    "urllib2", "requests", "http", "ftplib", "smtplib", "ctypes",
}

EXFIL_IMPORTS = {"socket", "http.client", "urllib", "urllib.request", "requests"}
SAFE_BUILD_TOOLS = {"gcc", "g++", "clang", "make", "cmake", "pkg-config", "pkgconfig"}
SKIP_DIRS = {"test", "tests", "benchmarks", "examples", "docs", "doc"}
SKIP_FILENAMES = {"conftest.py", "setup.cfg", "pyproject.toml"}

# Patterns for obfuscated code
OBFUSCATION_PATTERNS = [
    (r"base64\.b64decode\s*\(\s*base64\.b64decode", "Double base64 encoding detected"),
    (r"zlib\.decompress\s*\(.*base64\.b64decode", "zlib decompress with base64 decode"),
    (r"base64\.b64decode\s*\(.*zlib\.decompress", "base64 decode with zlib decompress"),
    (r"exec\s*\(\s*base64\.b64decode", "exec of base64-decoded content"),
    (r"eval\s*\(\s*base64\.b64decode", "eval of base64-decoded content"),
    (r"exec\s*\(\s*zlib\.decompress", "exec of zlib-decompressed content"),
    (r"exec\s*\(\s*compile\s*\(", "exec of dynamically compiled code"),
    (r"__import__\s*\(\s*['\"]base64['\"]", "Dynamic import of base64"),
    (r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)", "Character-by-character string building"),
    (r"\bxor\b.*\bexec\b|\bexec\b.*\bxor\b", "XOR with exec pattern"),
    (r"bytes\(\s*\[.*\bfor\b.*\bxor\b", "XOR byte array construction"),
]

# Credential theft patterns — high-confidence (always critical)
CREDENTIAL_PATTERNS_CRITICAL = [
    (r"['\"]~/.ssh", "Access to SSH directory"),
    (r"['\"]~/.aws", "Access to AWS credentials"),
    (r"['\"]~/.env", "Access to .env file"),
    (r"['\"]\/etc\/passwd", "Access to /etc/passwd"),
    (r"['\"]~/.kube", "Access to Kubernetes config"),
    (r"['\"]~/.docker", "Access to Docker config"),
]

# os.environ access — only suspicious when combined with exfiltration indicators
ENVIRON_PATTERN = r"os\.environ.*(?:KEY|SECRET|TOKEN|PASSWORD|AWS|AZURE|GCP)"

# Indicators that turn os.environ access into credential theft
EXFILTRATION_INDICATORS = [
    r"\bsocket\b", r"\bhttp\.client\b", r"\burllib\b", r"\brequests\.\b",
    r"\bhttpx\b", r"\baiohttp\b", r"\bftplib\b", r"\bsmtplib\b",
    r"\bbase64\b", r"\bexec\s*\(", r"\beval\s*\(",
]
EXFIL_CALL_PATTERNS = [
    r"socket\.socket\s*\(",
    r"socket\.create_connection\s*\(",
    r"http\.client\.[A-Za-z]+Connection\s*\(",
    r"urllib\.request\.(urlopen|Request)\s*\(",
    r"requests\.(get|post|put|delete|patch|request)\s*\(",
]

# Path segments that indicate test/config files (os.environ is normal here)
_TEST_PATH_SEGMENTS = {"test", "tests", "testing", "test_", "_test"}
_CONFIG_FILENAMES = {"conftest.py", "config.py", "settings.py", "conf.py", "env.py"}


def scan_package(package_dir: str) -> list[Finding]:
    """Run all static analysis checks on a package directory."""
    findings = []
    package_path = Path(package_dir)

    if not package_path.exists():
        logger.warning(f"Package directory does not exist: {package_dir}")
        return findings

    py_files = [py_file for py_file in package_path.rglob("*.py") if not _should_skip_file(py_file, package_path)]
    large_package = len(py_files) > 50

    # 1. Check for .pth files
    findings.extend(_check_pth_files(package_path))

    # 2. Check setup.py
    setup_py = package_path / "setup.py"
    if setup_py.exists():
        findings.extend(_check_setup_py(setup_py))

    # 3. Scan all .py files for obfuscation and credential theft
    for py_file in py_files:
        findings.extend(_check_py_file(py_file, package_path))

    return _apply_large_package_threshold(findings, large_package)


def _check_pth_files(package_path: Path) -> list[Finding]:
    """Check for .pth files in the package — key LiteLLM attack vector."""
    findings = []
    for pth_file in package_path.rglob("*.pth"):
        rel_path = str(pth_file.relative_to(package_path))
        if _should_skip_relative(rel_path):
            continue
        content = pth_file.read_text(errors="ignore")

        # Check for code execution in .pth
        if re.search(r"\bsubprocess\b|\bexec\b|\beval\b", content):
            findings.append(Finding(
                severity="critical",
                category="pth_injection",
                description=f".pth file contains executable code: {rel_path}",
                file=rel_path,
                line=0,
                evidence=content[:500],
            ))
        else:
            findings.append(Finding(
                severity="medium",
                category="pth_injection",
                description=f".pth file found: {rel_path}. Review startup behavior.",
                file=rel_path,
                line=0,
                evidence=content[:500],
            ))

    return findings


def _check_setup_py(setup_py: Path) -> list[Finding]:
    """Analyze setup.py for malicious patterns."""
    findings = []
    content = setup_py.read_text(errors="ignore")
    rel_path = "setup.py"

    setup_signals = _collect_setup_signals(content)

    # AST-based analysis
    try:
        tree = ast.parse(content)
        findings.extend(_ast_check_setup(tree, content, rel_path, setup_signals))
    except SyntaxError:
        findings.append(Finding(
            severity="medium",
            category="code_obfuscation",
            description="setup.py has syntax errors — may be intentionally obfuscated",
            file=rel_path,
        ))

    # Regex-based checks (catch things AST might miss)
    findings.extend(_regex_check_suspicious_imports(content, rel_path, setup_signals))

    if setup_signals["install_override"] and (setup_signals["base64_decode"] or setup_signals["exec_eval"]):
        findings.append(Finding(
            severity="high",
            category="install_hook",
            description="setup.py overrides install command and stages encoded or dynamic execution",
            file=rel_path,
            evidence=content[:500],
        ))

    if setup_signals["base64_decode"] and setup_signals["exec_eval"]:
        findings.append(Finding(
            severity="critical",
            category="code_obfuscation",
            description="setup.py combines base64 decoding with exec/eval",
            file=rel_path,
            evidence=content[:500],
        ))

    return findings


def _ast_check_setup(tree: ast.AST, source: str, filepath: str, setup_signals: dict[str, bool]) -> list[Finding]:
    """AST-based checks on setup.py."""
    findings = []

    for node in ast.walk(tree):
        # Check for overridden install commands (cmdclass)
        if isinstance(node, ast.keyword) and node.arg == "cmdclass":
            setup_signals["install_override"] = True

        # Check for exec/eval calls
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in ("base64.b64decode", "b64decode"):
                setup_signals["base64_decode"] = True
            if func_name in ("exec", "eval"):
                setup_signals["exec_eval"] = True
            if func_name and "subprocess" in func_name:
                setup_signals["subprocess_exec"] = True
            if func_name in ("os.system", "os.popen"):
                command = _get_string_argument(node)
                if command and _looks_like_safe_build_command(command):
                    continue
                findings.append(Finding(
                    severity="medium",
                    category="install_hook",
                    description=f"setup.py calls {func_name}",
                    file=filepath,
                    line=node.lineno,
                    evidence=ast.get_source_segment(source, node) or "",
                ))

        # Check for class inheritance from install/develop/egg_info
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = _get_node_name(base)
                if base_name in ("install", "develop", "egg_info", "build_ext", "sdist"):
                    setup_signals["install_override"] = True

    return findings


def _regex_check_suspicious_imports(content: str, filepath: str, setup_signals: dict[str, bool]) -> list[Finding]:
    """Check for suspicious imports in setup.py."""
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for module in SUSPICIOUS_IMPORTS:
            if re.search(rf"\bimport\s+{re.escape(module)}\b|\bfrom\s+{re.escape(module)}\b", stripped):
                findings.append(Finding(
                    severity="medium",
                    category="install_hook",
                    description=f"Suspicious import '{module}' in {filepath}",
                    file=filepath,
                    line=i,
                    evidence=stripped[:200],
                ))
                if module in EXFIL_IMPORTS:
                    setup_signals["exfil_import"] = True
    return findings


def _regex_check_obfuscation(content: str, filepath: str) -> list[Finding]:
    """Check for obfuscation patterns."""
    findings = []
    for pattern, description in OBFUSCATION_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity="high",
                category="code_obfuscation",
                description=f"{description} in {filepath}",
                file=filepath,
                line=line_num,
                evidence=match.group()[:300],
            ))
    return findings


def _check_build_file(filepath: Path) -> list[Finding]:
    """Check setup.cfg / pyproject.toml for build hooks."""
    findings = []
    content = filepath.read_text(errors="ignore")
    rel = filepath.name

    # Check for custom build commands
    if re.search(r"cmdclass|build-backend.*flit|build-backend.*hatch", content):
        # This is common and usually fine; only flag if combined with other signals
        pass

    # Check for script execution in build
    if re.search(r"subprocess|os\.system|exec\(|eval\(", content):
        findings.append(Finding(
            severity="medium",
            category="install_hook",
            description=f"Code execution pattern found in {rel}",
            file=rel,
        ))

    return findings


def _is_test_or_config_file(rel_path: str) -> bool:
    """Check if a file path is inside a test directory or is a config file."""
    parts = Path(rel_path).parts
    # Check path segments for test directories
    for part in parts:
        lower = part.lower()
        if lower in _TEST_PATH_SEGMENTS or lower.startswith("test_") or lower.endswith("_test"):
            return True
    # Check filename
    filename = Path(rel_path).name.lower()
    if filename in _CONFIG_FILENAMES or filename.startswith("test_") or filename.endswith("_test.py"):
        return True
    return False


def _check_py_file(py_file: Path, package_root: Path) -> list[Finding]:
    """Check a .py file for obfuscation and credential theft patterns."""
    findings = []
    try:
        content = py_file.read_text(errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel_path = str(py_file.relative_to(package_root))

    if _should_skip_relative(rel_path):
        return findings

    # Skip very large files (likely data)
    if len(content) > 500_000:
        return findings

    has_base64_decode = bool(re.search(r"base64\.b64decode", content, re.IGNORECASE))
    has_exec_eval = bool(re.search(r"\b(exec|eval)\s*\(", content))
    if has_base64_decode and has_exec_eval:
        findings.append(Finding(
            severity="critical",
            category="code_obfuscation",
            description=f"Base64 decode combined with exec/eval in {rel_path}",
            file=rel_path,
            evidence=content[:500],
        ))

    for pattern, description in OBFUSCATION_PATTERNS:
        if "exec" in pattern or "eval" in pattern or "base64" in pattern:
            continue
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity="medium",
                category="code_obfuscation",
                description=f"{description} in {rel_path}",
                file=rel_path,
                line=line_num,
                evidence=match.group()[:300],
            ))

    is_test_config = _is_test_or_config_file(rel_path)

    # High-confidence credential theft patterns (skip test files)
    if not is_test_config:
        for pattern, description in CREDENTIAL_PATTERNS_CRITICAL:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity="critical",
                    category="credential_theft",
                    description=f"{description} in {rel_path}",
                    file=rel_path,
                    line=line_num,
                    evidence=match.group()[:300],
                ))

    # os.environ pattern — only flag if combined with exfiltration indicators
    if re.search(ENVIRON_PATTERN, content, re.IGNORECASE):
        if is_test_config:
            # Test/config files legitimately use os.environ — skip entirely
            pass
        elif (
            any(re.search(ind, content) for ind in EXFILTRATION_INDICATORS)
            and any(re.search(pattern, content) for pattern in EXFIL_CALL_PATTERNS)
        ):
            # os.environ + network/exec = suspicious
            for match in re.finditer(ENVIRON_PATTERN, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity="high",
                    category="credential_theft",
                    description=f"Harvesting environment secrets in {rel_path}",
                    file=rel_path,
                    line=line_num,
                    evidence=match.group()[:300],
                ))
        else:
            # os.environ alone — informational only
            for match in re.finditer(ENVIRON_PATTERN, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity="info",
                    category="info",
                    description=f"Environment variable access in {rel_path} appears benign (no exfiltration indicators)",
                    file=rel_path,
                    line=line_num,
                    evidence=match.group()[:300],
                ))

    return findings


def _collect_setup_signals(content: str) -> dict[str, bool]:
    return {
        "install_override": False,
        "base64_decode": bool(re.search(r"base64\.b64decode", content, re.IGNORECASE)),
        "exec_eval": bool(re.search(r"\b(exec|eval)\s*\(", content)),
        "subprocess_exec": False,
        "exfil_import": False,
    }


def _looks_like_safe_build_command(command: str) -> bool:
    lowered = command.lower()
    return any(tool in lowered for tool in SAFE_BUILD_TOOLS)


def _get_string_argument(node: ast.Call) -> str | None:
    if not node.args:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return None


def _should_skip_relative(rel_path: str) -> bool:
    path = Path(rel_path)
    filename = path.name.lower()
    if filename in SKIP_FILENAMES:
        return True
    return any(part.lower() in SKIP_DIRS for part in path.parts)


def _should_skip_file(file_path: Path, package_root: Path) -> bool:
    return _should_skip_relative(str(file_path.relative_to(package_root)))


def _apply_large_package_threshold(findings: list[Finding], large_package: bool) -> list[Finding]:
    if not large_package:
        return findings

    critical_findings = [finding for finding in findings if finding.severity == "critical"]
    if len(critical_findings) >= 3:
        return findings

    adjusted: list[Finding] = []
    for finding in findings:
        if finding.severity == "critical":
            adjusted.append(Finding(
                severity="high",
                category=finding.category,
                description=finding.description,
                file=finding.file,
                line=finding.line,
                evidence=finding.evidence,
            ))
        else:
            adjusted.append(finding)
    return adjusted


def _get_call_name(node: ast.Call) -> str:
    """Extract the function name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        value_name = _get_node_name(node.func.value)
        if value_name:
            return f"{value_name}.{node.func.attr}"
        return node.func.attr
    return ""


def _get_node_name(node: ast.AST) -> str:
    """Extract a name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = _get_node_name(node.value)
        if value_name:
            return f"{value_name}.{node.attr}"
        return node.attr
    return ""
