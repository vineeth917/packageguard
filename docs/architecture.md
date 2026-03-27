# PackageGuard — Architecture Reference

## System Overview

PackageGuard is an autonomous AI agent that prevents supply chain attacks on Python packages. It runs as an interceptor between `pip install` and your production environment.

## The Story (for judges)

**March 24, 2026**: TeamPCP compromised LiteLLM on PyPI. Versions 1.82.7 and 1.82.8 contained a credential stealer that harvested SSH keys, cloud tokens, and Kubernetes secrets. The malware used `.pth` file injection to execute on every Python startup. Enterprises with auto-update bots installed it within minutes.

**PackageGuard prevents this.** Before any package reaches your environment, our AI agent:
1. Scans the code statically for known attack patterns
2. Checks metadata against GitHub for version/tag mismatches
3. Installs in an isolated Docker sandbox and monitors for malicious behavior
4. Uses Claude to reason about suspicious code patterns
5. Resolves dependency compatibility without breaking existing packages
6. Caches results in Aerospike for instant lookups on subsequent requests

## Data Models (SHARED — both Claude Code and Codex must use these)

All defined in `packageguard/__init__.py`:

```python
from dataclasses import dataclass, field
from typing import Optional
import json
from datetime import datetime

@dataclass
class Finding:
    severity: str         # "critical", "high", "medium", "low", "info"
    category: str         # see categories below
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence[:500],  # truncate for cache
        }

FINDING_CATEGORIES = [
    "pth_injection",
    "code_obfuscation",
    "credential_theft",
    "network_exfiltration",
    "install_hook",
    "version_mismatch",
    "suspicious_metadata",
    "resource_exhaustion",
    "persistence_mechanism",
    "lateral_movement",
]

@dataclass
class ScanReport:
    package_name: str
    version: str
    risk_score: int = 0
    verdict: str = "SAFE"    # "SAFE", "WARNING", "BLOCKED"
    findings: list = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cached: bool = False

    def to_dict(self):
        return {
            "package_name": self.package_name,
            "version": self.version,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration": self.scan_duration,
            "timestamp": self.timestamp,
            "cached": self.cached,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d):
        findings = [Finding(**f) for f in d.get("findings", [])]
        return cls(
            package_name=d["package_name"],
            version=d["version"],
            risk_score=d.get("risk_score", 0),
            verdict=d.get("verdict", "SAFE"),
            findings=findings,
            scan_duration=d.get("scan_duration", 0.0),
            timestamp=d.get("timestamp", ""),
            cached=d.get("cached", False),
        )

@dataclass
class CompatReport:
    status: str = "pending"   # "resolved", "partial", "failed"
    resolved_versions: dict = field(default_factory=dict)
    conflicts: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)
    attempts: int = 0

    def to_dict(self):
        return {
            "status": self.status,
            "resolved_versions": self.resolved_versions,
            "conflicts": self.conflicts,
            "suggestions": self.suggestions,
            "attempts": self.attempts,
        }
```

## Risk Score Calculation

```
score = sum(
    40 for f in findings if f.severity == "critical",
    25 for f in findings if f.severity == "high",
    10 for f in findings if f.severity == "medium",
    3  for f in findings if f.severity == "low",
)
score = min(score, 100)

if score >= 70: verdict = "BLOCKED"
elif score >= 30: verdict = "WARNING"
else: verdict = "SAFE"
```

## LiteLLM Attack Signatures (what our scanners detect)

| Signal | Scanner | Severity |
|--------|---------|----------|
| `.pth` file in package | static_scan | CRITICAL |
| base64-encoded exec/eval | static_scan | CRITICAL |
| Reads ~/.ssh/, ~/.aws/, .env | dynamic_scan | CRITICAL |
| Outbound network in sandbox | dynamic_scan | HIGH |
| No matching GitHub tag for version | metadata_scan | HIGH |
| Overridden install command in setup.py | static_scan | HIGH |
| Fork bomb / resource exhaustion | dynamic_scan | CRITICAL |
| systemd service creation | dynamic_scan | CRITICAL |
| subprocess.Popen in .pth file | static_scan | CRITICAL |
| zlib.decompress + exec pattern | static_scan | HIGH |
| Package uploaded outside CI/CD | metadata_scan | MEDIUM |
| Missing description/license | metadata_scan | LOW |

## Sponsor Integration Details

### Overmind ($651 prize)
- Every LLM call (security analysis, compat reasoning) is traced
- Traces include: prompt, response, tokens, latency, cost
- Tags: agent_name, scan_type, package_name, verdict
- Dashboard shows: which prompts are most expensive, which could use cheaper models
- Story: "We use Overmind to continuously optimize our LLM calls — finding the cheapest model that maintains detection accuracy"

### Aerospike
- Cache scan results by package:version
- Sub-millisecond lookups on SSD
- Story: "Once PackageGuard scans a package, every subsequent check is instant via Aerospike's SSD-direct indexing"

### AWS
- Docker sandbox runs on EC2/Lambda
- Could use Bedrock as LLM fallback
- Story: "Sandboxed analysis runs in isolated AWS compute"

### TrueFoundry
- Deploy as production service
- Story: "PackageGuard deploys via TrueFoundry for enterprise observability"

## API Endpoints

```
POST /scan              {package: str, version: str} -> ScanReport
POST /resolve           {requirements: file, new_packages: list} -> CompatReport
GET  /cache/{package}   -> list[ScanReport]
GET  /health            -> {status, aerospike, docker}
WS   /scan/stream       -> real-time scan progress
```

## File Ownership

| Path | Owner |
|------|-------|
| packageguard/__init__.py | SHARED (data models) |
| packageguard/main.py | Claude Code |
| packageguard/config.py | Claude Code |
| packageguard/agents/* | Claude Code |
| packageguard/scanners/* | Claude Code |
| packageguard/tracing/* | Claude Code |
| packageguard/resolver/* | Codex |
| packageguard/cache/* | Codex |
| packageguard/api/* | Codex |
| frontend/* | Codex |
| tests/* | Codex |
| demo/* | Claude Code |
| Docker files | Claude Code |
| docs/* | SHARED |
