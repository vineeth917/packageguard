"""
PackageGuard — AI-Powered Supply Chain Security for Python
"""

from dataclasses import dataclass, field
from typing import Optional
import json
from datetime import datetime

__version__ = "0.1.0"

# ─── Finding Categories ─────────────────────────────────────────────
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

SEVERITY_SCORES = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 0,
}


# ─── Data Models ────────────────────────────────────────────────────
@dataclass
class Finding:
    """A single security finding from a scanner."""
    severity: str         # "critical", "high", "medium", "low", "info"
    category: str         # from FINDING_CATEGORIES
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence[:500],
        }


@dataclass
class ScanStep:
    """A single step in the security scanning pipeline."""
    step_name: str
    status: str
    duration: float = 0.0
    findings: list = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "step_name": self.step_name,
            "status": self.status,
            "duration": self.duration,
            "findings": [f.to_dict() for f in self.findings],
            "reasoning": self.reasoning,
        }


@dataclass
class ScanReport:
    """Complete security scan report for a package."""
    package_name: str
    version: str
    risk_score: int = 0
    verdict: str = "SAFE"
    findings: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cached: bool = False

    def compute_score(self):
        """Calculate risk score from findings."""
        score = sum(SEVERITY_SCORES.get(f.severity, 0) for f in self.findings)
        self.risk_score = min(score, 100)
        if self.risk_score >= 70:
            self.verdict = "BLOCKED"
        elif self.risk_score >= 30:
            self.verdict = "WARNING"
        else:
            self.verdict = "SAFE"

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "steps": [step.to_dict() for step in self.steps],
            "scan_duration": self.scan_duration,
            "timestamp": self.timestamp,
            "cached": self.cached,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanReport":
        findings = [Finding(**f) for f in d.get("findings", [])]
        steps = [
            ScanStep(
                step_name=step.get("step_name", ""),
                status=step.get("status", ""),
                duration=step.get("duration", 0.0),
                findings=[Finding(**f) for f in step.get("findings", [])],
                reasoning=step.get("reasoning", ""),
            )
            for step in d.get("steps", [])
        ]
        report = cls(
            package_name=d["package_name"],
            version=d["version"],
            risk_score=d.get("risk_score", 0),
            verdict=d.get("verdict", "SAFE"),
            findings=findings,
            steps=steps,
            scan_duration=d.get("scan_duration", 0.0),
            timestamp=d.get("timestamp", ""),
            cached=d.get("cached", False),
        )
        return report

    @classmethod
    def from_json(cls, s: str) -> "ScanReport":
        return cls.from_dict(json.loads(s))


@dataclass
class CompatReport:
    """Dependency compatibility resolution report."""
    status: str = "pending"   # "resolved", "partial", "failed"
    resolved_versions: dict = field(default_factory=dict)
    conflicts: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)
    attempts: int = 0

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "resolved_versions": self.resolved_versions,
            "conflicts": self.conflicts,
            "suggestions": self.suggestions,
            "attempts": self.attempts,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
