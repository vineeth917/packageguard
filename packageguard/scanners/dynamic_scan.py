"""
Dynamic sandbox scanner.

Runs package installation inside a Docker container with networking disabled
and reports install-time persistence, sensitive path access, process churn,
and exit behavior.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from packageguard import Finding
from packageguard.config import config

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = ["~/.ssh", "~/.aws", ".env", "~/.kube", "~/.docker", "/etc/passwd"]

SANDBOX_SCRIPT = r'''
import glob
import json
import os
import pathlib
import re
import subprocess
import sys

target = sys.argv[1]
findings = []

pre_pth = set(glob.glob("/usr/local/lib/python*/site-packages/*.pth"))
pre_pth.update(glob.glob("/home/sandbox/.local/lib/python*/site-packages/*.pth"))

trace_path = "/tmp/trace.log"
install_cmd = [
    "strace", "-f", "-e", "trace=file,process", "-o", trace_path,
    "python", "-m", "pip", "install", "--no-deps", "--user", target,
]

try:
    proc = subprocess.run(install_cmd, capture_output=True, text=True, timeout=120)
    install_exit_code = proc.returncode
except subprocess.TimeoutExpired:
    print(json.dumps({
        "status": "timeout",
        "exit_code": 124,
        "stdout": "",
        "stderr": "install timed out",
        "new_pth": [],
        "sensitive_hits": [],
        "fork_count": 0,
        "fallback_used": False,
        "analyzed_files": 0,
        "import_attempts": [],
        "import_successes": [],
        "source_pth_files": [],
    }))
    raise SystemExit(0)

post_pth = set(glob.glob("/usr/local/lib/python*/site-packages/*.pth"))
post_pth.update(glob.glob("/home/sandbox/.local/lib/python*/site-packages/*.pth"))
new_pth = sorted(post_pth - pre_pth)

sensitive_hits = []
fork_count = 0
if os.path.exists(trace_path):
    trace_data = open(trace_path, "r", errors="ignore").read()
    for needle in ["~/.ssh", "~/.aws", "/etc/passwd", ".env", "~/.kube", "~/.docker"]:
        if needle in trace_data:
            sensitive_hits.append(needle)
    fork_count = trace_data.count("clone(") + trace_data.count("fork(") + trace_data.count("vfork(")

fallback_used = False
analyzed_files = 0
import_attempts = []
import_successes = []
source_pth_files = []

def collect_module_candidates(root: pathlib.Path):
    candidates = []
    for child in root.iterdir():
        if child.name.startswith("."):
            continue
        if child.is_dir() and (child / "__init__.py").exists():
            candidates.append(child.name.replace("-", "_"))
        elif child.is_file() and child.suffix == ".py" and child.name not in {"setup.py", "__init__.py"}:
            candidates.append(child.stem.replace("-", "_"))
    return candidates[:3]

if install_exit_code != 0 and target == "/home/sandbox/pkg":
    pkg_root = pathlib.Path(target)
    fallback_used = True
    for file_path in pkg_root.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix in {".py", ".pth"}:
            analyzed_files += 1
        if file_path.suffix == ".pth":
            source_pth_files.append(str(file_path.relative_to(pkg_root)))

    for module_name in collect_module_candidates(pkg_root):
        import_attempts.append(module_name)
        import_trace = f"/tmp/import_{module_name}.log"
        cmd = [
            "strace", "-f", "-e", "trace=file,process", "-o", import_trace,
            "python", "-c",
            f"import sys; sys.path.insert(0, {target!r}); import {module_name}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            import_successes.append(module_name)
        if os.path.exists(import_trace):
            import_trace_data = open(import_trace, "r", errors="ignore").read()
            for needle in ["~/.ssh", "~/.aws", "/etc/passwd", ".env", "~/.kube", "~/.docker"]:
                if needle in import_trace_data and needle not in sensitive_hits:
                    sensitive_hits.append(needle)
            fork_count += import_trace_data.count("clone(") + import_trace_data.count("fork(") + import_trace_data.count("vfork(")

print(json.dumps({
    "status": "ok",
    "exit_code": install_exit_code,
    "stdout": proc.stdout[-2000:],
    "stderr": proc.stderr[-2000:],
    "new_pth": new_pth,
    "sensitive_hits": sensitive_hits,
    "fork_count": fork_count,
    "fallback_used": fallback_used,
    "analyzed_files": analyzed_files,
    "import_attempts": import_attempts,
    "import_successes": import_successes,
    "source_pth_files": source_pth_files,
}))
'''


async def scan_dynamic(package_name: str, version: str = None) -> list[Finding]:
    target = f"{package_name}=={version}" if version else package_name
    return _run_dynamic_scan(target)


async def scan_local_package(package_dir: str) -> list[Finding]:
    return _run_dynamic_scan("/home/sandbox/pkg", local_package_dir=package_dir)


def _run_dynamic_scan(target: str, local_package_dir: str | None = None) -> list[Finding]:
    docker_path = _docker_available()
    if not docker_path:
        return [Finding(
            severity="info",
            category="info",
            description="Dynamic sandbox analysis skipped — Docker not available in this environment",
        )]

    script_path = None
    try:
        _ensure_sandbox_image(docker_path)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as handle:
            handle.write(SANDBOX_SCRIPT)
            script_path = handle.name
        output, inspect_payload = _run_container(docker_path, script_path, target, local_package_dir)
        return _parse_dynamic_output(output, inspect_payload)
    except Exception as exc:
        logger.warning("Dynamic scan error: %s", exc)
        return [Finding(
            severity="info",
            category="info",
            description=f"Dynamic sandbox analysis skipped — {str(exc)[:200]}",
        )]
    finally:
        if script_path:
            try:
                os.unlink(script_path)
            except OSError:
                pass


def _docker_available() -> str | None:
    docker_path = shutil.which("docker")
    if not docker_path:
        return None
    try:
        subprocess.run([docker_path, "info"], capture_output=True, text=True, timeout=10, check=True)
        return docker_path
    except Exception:
        return None


def _ensure_sandbox_image(docker_path: str) -> None:
    inspect = subprocess.run(
        [docker_path, "image", "inspect", config.SANDBOX_IMAGE],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if inspect.returncode == 0:
        return
    project_root = Path(__file__).resolve().parents[2]
    subprocess.run(
        [docker_path, "build", "-t", config.SANDBOX_IMAGE, "-f", "Dockerfile.sandbox", "."],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
    )


def _run_container(docker_path: str, script_path: str, target: str, local_package_dir: str | None) -> tuple[str, dict]:
    container_name = f"packageguard-scan-{next(tempfile._get_candidate_names())}"
    command = [
        docker_path, "run", "--name", container_name, "--network=none",
        "--memory", config.SANDBOX_MEMORY_LIMIT,
        "--cpus", str(config.SANDBOX_CPU_LIMIT),
        "-v", f"{script_path}:/home/sandbox/scan.py:ro",
    ]
    if local_package_dir:
        command.extend(["-v", f"{os.path.abspath(local_package_dir)}:/home/sandbox/pkg:ro"])
    command.extend([config.SANDBOX_IMAGE, "scan.py", target])

    run_result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=config.SANDBOX_TIMEOUT + 120,
    )
    inspect_result = subprocess.run(
        [docker_path, "inspect", container_name],
        capture_output=True,
        text=True,
        timeout=20,
    )
    subprocess.run([docker_path, "rm", "-f", container_name], capture_output=True, text=True, timeout=20)

    inspect_payload = {}
    if inspect_result.returncode == 0 and inspect_result.stdout.strip():
        parsed = json.loads(inspect_result.stdout)
        if parsed:
            inspect_payload = parsed[0].get("State", {})
    output = (run_result.stdout or "") + "\n" + (run_result.stderr or "")
    return output, inspect_payload


def _parse_dynamic_output(output: str, inspect_payload: dict) -> list[Finding]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    payload = {}
    for line in reversed(lines):
        try:
            payload = json.loads(line)
            break
        except json.JSONDecodeError:
            continue

    if not payload:
        return [Finding(
            severity="info",
            category="info",
            description="Dynamic sandbox analysis skipped — sandbox output was not parseable",
            evidence=output[:500],
        )]

    findings: list[Finding] = []
    status = payload.get("status")
    exit_code = int(payload.get("exit_code", 0) or 0)
    new_pth = payload.get("new_pth", []) or []
    sensitive_hits = payload.get("sensitive_hits", []) or []
    fork_count = int(payload.get("fork_count", 0) or 0)
    stderr = payload.get("stderr", "")
    fallback_used = bool(payload.get("fallback_used"))
    analyzed_files = int(payload.get("analyzed_files", 0) or 0)
    import_attempts = payload.get("import_attempts", []) or []
    import_successes = payload.get("import_successes", []) or []
    source_pth_files = payload.get("source_pth_files", []) or []

    if status == "timeout":
        findings.append(Finding(
            severity="critical",
            category="resource_exhaustion",
            description="Dynamic sandbox timed out during install",
        ))
        return findings

    if inspect_payload.get("OOMKilled"):
        findings.append(Finding(
            severity="critical",
            category="resource_exhaustion",
            description="Dynamic sandbox detected an out-of-memory kill during install",
        ))

    if fallback_used:
        findings.append(Finding(
            severity="info",
            category="info",
            description=f"Sandbox analyzed {analyzed_files} source files and attempted isolated imports because the extracted package was not directly installable",
        ))
    elif exit_code != 0:
        findings.append(Finding(
            severity="info",
            category="install_hook",
            description=f"Sandbox install exited with code {exit_code}",
            evidence=stderr[:500],
        ))
    else:
        findings.append(Finding(
            severity="info",
            category="info",
            description="Sandbox install completed successfully with exit code 0",
        ))

    if import_attempts:
        findings.append(Finding(
            severity="info",
            category="info",
            description=f"Sandbox attempted imports for: {', '.join(import_attempts)}",
        ))
    if import_successes:
        findings.append(Finding(
            severity="info",
            category="info",
            description=f"Sandbox successfully imported: {', '.join(import_successes)}",
        ))

    for pth_file in new_pth:
        findings.append(Finding(
            severity="critical",
            category="pth_injection",
            description=f"New .pth file created during sandbox install: {pth_file}",
            file=pth_file,
        ))

    for pth_file in source_pth_files:
        findings.append(Finding(
            severity="critical",
            category="pth_injection",
            description=f"Package source ships a .pth startup hook: {pth_file}",
            file=pth_file,
        ))

    for sensitive_path in sensitive_hits:
        if sensitive_path == "/etc/passwd":
            findings.append(Finding(
                severity="info",
                category="info",
                description="Sandbox observed a read of /etc/passwd during install bootstrap",
                evidence=sensitive_path,
            ))
            continue
        findings.append(Finding(
            severity="high",
            category="credential_theft",
            description=f"Sandbox trace observed access attempt to sensitive path: {sensitive_path}",
            evidence=sensitive_path,
        ))

    if fork_count > 50:
        findings.append(Finding(
            severity="high",
            category="resource_exhaustion",
            description=f"Sandbox observed excessive process creation ({fork_count} forks/clones)",
        ))
    elif fork_count > 0:
        findings.append(Finding(
            severity="info",
            category="info",
            description=f"Sandbox observed {fork_count} process creation events",
        ))

    return findings


import shutil
