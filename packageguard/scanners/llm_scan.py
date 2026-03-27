"""
LLM-based code review scanner.

Uses OpenAI client pointed at OpenRouter. The overmind-sdk auto-instruments
the OpenAI client, so all LLM calls are automatically traced to the local
Overmind instance without manual wrapping.
"""

import json
import logging
from pathlib import Path

from openai import OpenAI

from packageguard import Finding
from packageguard.config import config
from packageguard.tracing import tracer

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security analyst specializing in Python supply chain attacks.
Analyze the provided Python package files for malicious patterns including but not limited to:

1. **Credential theft**: Reading SSH keys, AWS credentials, environment secrets, .env files
2. **.pth file injection**: Files that execute on every Python startup
3. **Code obfuscation**: Base64 encoding, XOR, zlib compression hiding malicious payloads
4. **Network exfiltration**: Sending stolen data to external servers
5. **Install hooks**: Overridden setuptools commands that execute during pip install
6. **Persistence**: systemd services, cron jobs, startup scripts
7. **Lateral movement**: Scanning networks, SSH key reuse, container escape attempts

For each finding, respond with a JSON array of objects:
```json
[
  {
    "severity": "critical|high|medium|low|info",
    "category": "pth_injection|code_obfuscation|credential_theft|network_exfiltration|install_hook|resource_exhaustion|persistence_mechanism|lateral_movement|suspicious_metadata|version_mismatch",
    "description": "Clear description of the security issue",
    "file": "filename where found",
    "line": 0,
    "evidence": "relevant code snippet"
  }
]
```

If the code appears safe, return an empty array: []
Be thorough but avoid false positives. Focus on real security threats."""


def _get_openai_client() -> OpenAI:
    """Create an OpenAI client pointed at OpenRouter."""
    return OpenAI(
        api_key=config.OPENROUTER_API_KEY,
        base_url=config.OPENROUTER_BASE_URL,
    )


async def scan_with_llm(package_dir: str, package_name: str = "") -> list[Finding]:
    """Send key package files to LLM for security review."""
    findings = []
    package_path = Path(package_dir)

    if not config.OPENROUTER_API_KEY:
        logger.warning("No OPENROUTER_API_KEY set, skipping LLM scan")
        return [
            Finding(
                severity="info",
                category="info",
                description="LLM review skipped — no API key configured",
            )
        ]

    files_to_review = _collect_review_files(package_path)
    if not files_to_review:
        return [
            Finding(
                severity="info",
                category="info",
                description="LLM review skipped — no relevant files found",
            )
        ]

    # Build the prompt
    file_contents = []
    for filepath, content in files_to_review:
        file_contents.append(f"--- {filepath} ---\n{content}\n")

    user_prompt = (
        f"Analyze this Python package '{package_name}' for malicious patterns.\n\n"
        + "\n".join(file_contents)
    )

    # The OpenAI client call is auto-instrumented by overmind-sdk.
    # We also keep a local trace span for our own get_summary().
    with tracer.trace("llm_scan", metadata={"package": package_name}) as span:
        span.set_input(user_prompt[:2000])
        span.set_model(config.LLM_MODEL)

        try:
            client = _get_openai_client()
            response = client.chat.completions.create(
                model=config.LLM_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=4096,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content or ""
            usage = response.usage

            span.set_output(content[:2000])
            if usage:
                span.set_tokens(usage.prompt_tokens or 0, usage.completion_tokens or 0)

            findings.extend(_parse_llm_response(content))

        except Exception as e:
            logger.error(f"LLM scan failed: {e}")
            span.set_error(str(e))
            findings.append(Finding(
                severity="info",
                category="info",
                description=f"LLM review skipped — {str(e)[:200]}",
            ))

    return findings


def _collect_review_files(package_path: Path) -> list[tuple[str, str]]:
    """Collect key files from the package for LLM review."""
    files = []
    max_files = min(config.MAX_LLM_SCAN_FILES, 5)
    max_file_size = 50_000
    candidates: list[tuple[int, str, str]] = []

    for f in package_path.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix not in {".py", ".pth"} and f.name not in {"setup.py", "__init__.py"}:
            continue
        try:
            content = f.read_text(errors="ignore")[:max_file_size]
        except (OSError, PermissionError):
            continue
        rel = str(f.relative_to(package_path))
        score = _suspicion_score(rel, content)
        candidates.append((score, rel, content))

    candidates.sort(key=lambda item: (-item[0], item[1]))
    top = []
    for score, rel, content in candidates:
        if len(top) >= max_files:
            break
        if score <= 0 and top:
            continue
        top.append((rel, content))
    return top


def _suspicion_score(rel_path: str, content: str) -> int:
    score = 0
    lowered = rel_path.lower()
    if rel_path.endswith(".pth"):
        score += 10
    if lowered.endswith("setup.py"):
        score += 8
    if lowered.endswith("__init__.py"):
        score += 5
    for token, weight in {
        "base64": 5,
        "exec(": 5,
        "eval(": 5,
        "subprocess": 4,
        "socket": 4,
        "http.client": 4,
        "requests": 3,
        "urllib": 3,
        "cmdclass": 4,
        "os.environ": 3,
    }.items():
        if token in content:
            score += weight
    return score


def _parse_llm_response(content: str) -> list[Finding]:
    """Parse LLM response into Finding objects."""
    findings = []

    json_str = content
    if "```json" in content:
        start = content.index("```json") + 7
        end = content.index("```", start)
        json_str = content[start:end].strip()
    elif "```" in content:
        start = content.index("```") + 3
        end = content.index("```", start)
        json_str = content[start:end].strip()

    try:
        raw = json.loads(json_str)
        if isinstance(raw, dict) and "findings" in raw:
            raw = raw["findings"]
        if not isinstance(raw, list):
            raw = [raw]

        for item in raw:
            if not isinstance(item, dict):
                continue
            findings.append(Finding(
                severity=item.get("severity", "medium"),
                category=item.get("category", "code_obfuscation"),
                description=item.get("description", "LLM-detected issue"),
                file=item.get("file", ""),
                line=item.get("line", 0),
                evidence=item.get("evidence", ""),
            ))
    except (json.JSONDecodeError, ValueError):
        if any(word in content.lower() for word in ["malicious", "dangerous", "critical", "vulnerability"]):
            findings.append(Finding(
                severity="medium",
                category="code_obfuscation",
                description=f"LLM flagged potential issues (raw): {content[:300]}",
                evidence=content[:500],
            ))

    return findings
