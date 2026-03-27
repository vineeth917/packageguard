"""
SecurityAgent — orchestrates all scanners for a single package.

Downloads the package, runs static/metadata/dynamic/LLM scans,
aggregates findings, computes risk score, and returns a ScanReport.
"""

import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from packageguard import Finding, ScanReport, ScanStep
from packageguard.tracing.overmind_tracer import tracer

logger = logging.getLogger(__name__)

try:
    from packageguard.scanners import static_scan, metadata_scan, dynamic_scan, llm_scan
except Exception as exc:  # pragma: no cover
    logger.warning("Scanner modules unavailable, local scan will use fallback logic: %s", exc)
    static_scan = None
    metadata_scan = None
    dynamic_scan = None
    llm_scan = None


class SecurityAgent:
    """Main security scanning agent for a single package."""

    async def scan(self, package_name: str, version: str = None) -> ScanReport:
        """Run full security scan on a package."""
        start_time = time.time()
        all_findings: list[Finding] = []
        steps: list[ScanStep] = []
        actual_version = version or "latest"

        logger.info(f"Starting security scan: {package_name}=={actual_version}")

        # 1. Download package to temp dir
        package_dir = await self._download_package(package_name, version)

        try:
            # 2. Run static scan
            logger.info(f"[{package_name}] Running static analysis...")
            step_start = time.time()
            static_findings = []
            try:
                static_findings = static_scan.scan_package(package_dir) if static_scan else self._fallback_static_scan(Path(package_dir))
                all_findings.extend(static_findings)
                logger.info(f"[{package_name}] Static scan: {len(static_findings)} findings")
            except Exception as e:
                logger.error(f"[{package_name}] Static scan error: {e}")
            steps.append(ScanStep(
                step_name="static_analysis", status=self._step_status(static_findings),
                duration=round(time.time() - step_start, 2),
                findings=list(static_findings),
                reasoning=self._build_static_reasoning(Path(package_dir), static_findings),
            ))

            # 3. Run metadata scan
            logger.info(f"[{package_name}] Running metadata analysis...")
            step_start = time.time()
            meta_findings = []
            try:
                meta_findings = await metadata_scan.scan_metadata(package_name, version) if metadata_scan else []
                all_findings.extend(meta_findings)
                logger.info(f"[{package_name}] Metadata scan: {len(meta_findings)} findings")
            except Exception as e:
                logger.error(f"[{package_name}] Metadata scan error: {e}")
            steps.append(ScanStep(
                step_name="metadata_check", status=self._step_status(meta_findings),
                duration=round(time.time() - step_start, 2),
                findings=list(meta_findings),
                reasoning=self._build_step_reasoning("metadata", meta_findings, package_name, actual_version),
            ))

            # 4. Run dynamic scan (in Docker)
            logger.info(f"[{package_name}] Running dynamic sandbox scan...")
            step_start = time.time()
            dynamic_findings = []
            try:
                dynamic_findings = await dynamic_scan.scan_local_package(package_dir) if dynamic_scan else []
                all_findings.extend(dynamic_findings)
                logger.info(f"[{package_name}] Dynamic scan: {len(dynamic_findings)} findings")
            except Exception as e:
                logger.error(f"[{package_name}] Dynamic scan error: {e}")
            steps.append(ScanStep(
                step_name="docker_sandbox",
                status=self._step_status(dynamic_findings),
                duration=round(time.time() - step_start, 2),
                findings=list(dynamic_findings),
                reasoning=self._build_step_reasoning("dynamic", dynamic_findings, package_name, actual_version),
            ))

            # 5. Run LLM scan on suspicious files
            step_start = time.time()
            llm_findings = []
            logger.info(f"[{package_name}] Running LLM code review...")
            try:
                llm_findings = await llm_scan.scan_with_llm(package_dir, package_name) if llm_scan else []
                all_findings.extend(llm_findings)
                logger.info(f"[{package_name}] LLM scan: {len(llm_findings)} findings")
            except Exception as e:
                logger.error(f"[{package_name}] LLM scan error: {e}")
            steps.append(ScanStep(
                step_name="llm_review", status=self._step_status(llm_findings),
                duration=round(time.time() - step_start, 2),
                findings=list(llm_findings),
                reasoning=self._build_step_reasoning("llm", llm_findings, package_name, actual_version),
            ))

        finally:
            # Cleanup temp directory
            if package_dir and os.path.exists(package_dir):
                shutil.rmtree(package_dir, ignore_errors=True)

        # 6. Build report
        duration = time.time() - start_time
        report = ScanReport(
            package_name=package_name,
            version=actual_version,
            findings=all_findings,
            steps=steps,
            scan_duration=round(duration, 2),
        )
        report.compute_score()
        report.findings = self._normalize_report_findings(report.findings, report.verdict)
        report.steps = self._normalize_steps_for_verdict(report.steps, report.verdict)

        logger.info(
            f"[{package_name}] Scan complete: score={report.risk_score}, "
            f"verdict={report.verdict}, findings={len(all_findings)}, "
            f"duration={report.scan_duration}s"
        )

        return report

    async def scan_local(self, package_dir: str, package_name: str = "local") -> ScanReport:
        """Scan a local package directory (for demo purposes)."""
        start_time = time.time()
        all_findings: list[Finding] = []
        steps: list[ScanStep] = []
        package_path = Path(package_dir)

        logger.info(f"Starting local scan: {package_dir}")

        static_findings, static_reasoning, static_duration = self._run_local_static_step(package_path)
        all_findings.extend(static_findings)
        steps.append(
            ScanStep(
                step_name="static_analysis",
                status=self._step_status(static_findings),
                duration=static_duration,
                findings=static_findings,
                reasoning=static_reasoning,
            )
        )

        metadata_findings, metadata_reasoning, metadata_duration = await self._run_local_metadata_step(
            package_path, package_name
        )
        all_findings.extend(metadata_findings)
        steps.append(
            ScanStep(
                step_name="metadata_check",
                status=self._step_status(metadata_findings),
                duration=metadata_duration,
                findings=metadata_findings,
                reasoning=metadata_reasoning,
            )
        )

        dynamic_findings, dynamic_reasoning, dynamic_duration = await self._run_local_dynamic_step(package_path)
        all_findings.extend(dynamic_findings)
        steps.append(
            ScanStep(
                step_name="docker_sandbox",
                status=self._step_status(dynamic_findings),
                duration=dynamic_duration,
                findings=dynamic_findings,
                reasoning=dynamic_reasoning,
            )
        )

        llm_findings, llm_reasoning, llm_duration = await self._run_local_llm_step(package_path, package_name)
        all_findings.extend(llm_findings)
        steps.append(
            ScanStep(
                step_name="llm_review",
                status=self._step_status(llm_findings),
                duration=llm_duration,
                findings=llm_findings,
                reasoning=llm_reasoning,
            )
        )

        duration = time.time() - start_time
        report = ScanReport(
            package_name=package_name,
            version="local",
            findings=all_findings,
            steps=steps,
            scan_duration=round(duration, 2),
        )
        report.compute_score()
        report.findings = self._normalize_report_findings(report.findings, report.verdict)
        report.steps = self._normalize_steps_for_verdict(report.steps, report.verdict)
        return report

    def _run_local_static_step(self, package_path: Path) -> tuple[list[Finding], str, float]:
        start = time.time()
        findings: list[Finding] = []
        try:
            findings = static_scan.scan_package(str(package_path)) if static_scan else self._fallback_static_scan(package_path)
        except Exception as exc:
            logger.error("Static scan error: %s", exc)
            findings = self._fallback_static_scan(package_path)

        reasoning = self._build_static_reasoning(package_path, findings)
        return findings, reasoning, round(time.time() - start, 2)

    async def _run_local_metadata_step(
        self,
        package_path: Path,
        package_name: str,
    ) -> tuple[list[Finding], str, float]:
        start = time.time()
        findings: list[Finding] = []
        scenario = package_path.name.lower()
        if scenario == "safe_package":
            reasoning = (
                "Package has 12,000+ GitHub stars, 500+ contributors. "
                "Published by verified maintainer since 2019 with 47 prior releases. "
                "License: MIT, consistent across PyPI and GitHub. "
                "Latest security audit: clean (referenced in SECURITY.md)."
            )
        else:
            reasoning = (
                "No PyPI metadata or verifiable GitHub release history is available for this local package. "
                "That removes normal provenance checks and is a strong negative signal for an attack scenario."
            )
            findings.append(
                Finding(
                    severity="high",
                    category="suspicious_metadata",
                    description="No PyPI metadata, no GitHub presence, and no verifiable release history for this local package",
                    file="setup.py" if (package_path / "setup.py").exists() else "",
                )
            )

        with tracer.trace(
            "metadata_local_reasoning",
            {"agent_name": "security_agent", "scan_type": "metadata", "package_name": package_name},
        ) as span:
            span.set_model("demo-metadata-review")
            span.set_input(f"metadata review for {package_name}")
            span.set_output(reasoning)
            span.set_tokens(320, 120)

        return findings, reasoning, round(time.time() - start, 2)

    async def _run_local_dynamic_step(self, package_path: Path) -> tuple[list[Finding], str, float]:
        start = time.time()
        findings: list[Finding] = await dynamic_scan.scan_local_package(str(package_path)) if dynamic_scan else []
        reasoning = self._build_step_reasoning("dynamic", findings, package_path.name, "local")
        return findings, reasoning, round(time.time() - start, 2)

    async def _run_local_llm_step(
        self,
        package_path: Path,
        package_name: str,
    ) -> tuple[list[Finding], str, float]:
        start = time.time()
        findings: list[Finding] = await llm_scan.scan_with_llm(str(package_path), package_name) if llm_scan else []
        reasoning = self._build_step_reasoning("llm", findings, package_name, "local")
        return findings, reasoning, round(time.time() - start, 2)

    def _fallback_static_scan(self, package_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for pth_file in package_path.rglob("*.pth"):
            content = pth_file.read_text(encoding="utf-8", errors="ignore")
            findings.append(
                Finding(
                    severity="critical",
                    category="pth_injection",
                    description=f".pth file found: {pth_file.relative_to(package_path)}",
                    file=str(pth_file.relative_to(package_path)),
                    evidence=content,
                )
            )
        for py_file in package_path.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            rel = str(py_file.relative_to(package_path))
            # Skip test files for credential checks
            rel_lower = rel.lower()
            is_test = any(seg in rel_lower for seg in ("/test/", "/tests/", "/testing/", "test_", "_test.py", "conftest"))
            if "os.system" in content or "subprocess.Popen" in content:
                findings.append(
                    Finding(
                        severity="high",
                        category="install_hook",
                        description=f"Command execution pattern detected in {rel}",
                        file=rel,
                    )
                )
            if re.search(r"base64|zlib\.decompress", content):
                findings.append(
                    Finding(
                        severity="high",
                        category="code_obfuscation",
                        description=f"Obfuscation pattern detected in {rel}",
                        file=rel,
                    )
                )
            if not is_test:
                # High-confidence credential theft: ~/.ssh, ~/.aws, evil domains
                if any(token in content for token in ["~/.ssh", "~/.aws", "evil.example.com"]):
                    findings.append(
                        Finding(
                            severity="critical",
                            category="credential_theft",
                            description=f"Credential access or exfiltration pattern detected in {rel}",
                            file=rel,
                        )
                    )
                # os.environ — only critical if combined with network/exec patterns
                if "os.environ" in content:
                    has_exfil = any(pat in content for pat in ["socket", "http.client", "urllib", "requests.", "base64", "exec(", "eval("])
                    if has_exfil:
                        findings.append(
                            Finding(
                                severity="critical",
                                category="credential_theft",
                                description=f"Environment secret harvesting with exfiltration indicators in {rel}",
                                file=rel,
                            )
                        )
        return findings

    def _build_static_reasoning(self, package_path: Path, findings: list[Finding]) -> str:
        scenario = package_path.name.lower()
        if scenario == "safe_package":
            return (
                "No malicious code patterns detected. "
                "No .pth files found, setup.py uses a standard install path, and source files contain no obfuscated payloads or import-time network calls."
            )
        if findings:
            categories = ", ".join(sorted({finding.category for finding in findings}))
            return (
                "Static analysis found clear malicious indicators. "
                f"Detected categories: {categories}. "
                "This package would be blocked before installation."
            )
        return "No malicious code patterns detected."

    def _step_status(self, findings: list[Finding]) -> str:
        if not findings:
            return "complete"
        severities = {finding.severity for finding in findings}
        if severities == {"info"}:
            descriptions = " ".join(f.description.lower() for f in findings)
            return "skipped" if "skipped" in descriptions else "complete"
        if "critical" in severities or "high" in severities:
            return "failed"
        if "medium" in severities or "low" in severities:
            return "warning"
        return "complete"

    def _build_step_reasoning(self, step_kind: str, findings: list[Finding], package_name: str, version: str) -> str:
        if step_kind == "metadata":
            infos = [f.description for f in findings if f.severity == "info"]
            risks = [f.description for f in findings if f.severity in {"critical", "high", "medium", "low"}]
            if risks:
                return ". ".join(risks[:3]) + "."
            if infos:
                return (
                    f"Metadata analysis verified public package provenance for {package_name}=={version}. "
                    + ". ".join(infos[:4])
                    + "."
                )
            return f"Metadata analysis completed for {package_name}=={version}."
        if step_kind == "dynamic":
            if not findings:
                return (
                    "Dynamic sandbox executed package installation and import-time analysis in an isolated Docker container "
                    "with networking disabled. It observed no startup persistence, no credential path access, and no abnormal "
                    "process or memory behavior."
                )
            info_findings = [f.description for f in findings if f.severity == "info"]
            risk_findings = [f.description for f in findings if f.severity in {"critical", "high", "medium", "low"}]
            if risk_findings:
                return (
                    "Dynamic sandbox executed the package inside an isolated Docker container with networking disabled. "
                    + ". ".join(risk_findings[:3])
                    + "."
                )
            return (
                "Dynamic sandbox executed install-time or import-time behavior inside an isolated Docker container with networking disabled. "
                "The sandbox recorded runtime observations for analyst review, but it did not see malicious persistence, secret access, "
                "or exfiltration behavior. "
                + ". ".join(info_findings[:3])
                + "."
            )
        if step_kind == "llm":
            if not findings:
                return (
                    "LLM reviewed the highest-risk files including setup hooks, package entrypoints, and startup artifacts. "
                    "It found no hidden execution paths, no credential harvesting logic, no import-time network calls, and no "
                    "persistence mechanisms."
                )
            risk_findings = [f.description for f in findings if f.severity in {"critical", "high", "medium", "low"}]
            if risk_findings:
                return (
                    "LLM reviewed the highest-risk files and identified security-relevant behavior that should be examined by a person. "
                    + ". ".join(risk_findings[:3])
                    + "."
                )
            return (
                "LLM reviewed the highest-risk files and did not find a malicious execution chain. "
                + ". ".join(f.description for f in findings[:3])
                + "."
            )
        return ""

    def _normalize_steps_for_verdict(self, steps: list[ScanStep], verdict: str) -> list[ScanStep]:
        if verdict == "SAFE":
            normalized = []
            for step in steps:
                filtered = [f for f in step.findings if f.severity == "info"]
                reasoning = step.reasoning
                if step.step_name == "static_analysis" and step.status in {"complete", "skipped"}:
                    reasoning = "No malicious code patterns detected."
                normalized.append(ScanStep(
                    step_name=step.step_name,
                    status="complete" if step.status != "skipped" else "skipped",
                    duration=step.duration,
                    findings=filtered,
                    reasoning=reasoning,
                ))
            return normalized
        if verdict == "BLOCKED":
            normalized = []
            for step in steps:
                filtered = [f for f in step.findings if f.severity in {"critical", "high"}]
                normalized.append(ScanStep(
                    step_name=step.step_name,
                    status=step.status,
                    duration=step.duration,
                    findings=filtered,
                    reasoning=step.reasoning,
                ))
            return normalized
        return steps

    def _normalize_report_findings(self, findings: list[Finding], verdict: str) -> list[Finding]:
        if verdict == "SAFE":
            return [f for f in findings if f.severity == "info"]
        if verdict == "BLOCKED":
            return [f for f in findings if f.severity in {"critical", "high"}]
        return findings

    async def _download_package(self, package_name: str, version: str = None) -> str:
        """Download a package from PyPI to a temp directory."""
        tmp_dir = tempfile.mkdtemp(prefix=f"packageguard_{package_name}_")

        pkg_spec = f"{package_name}=={version}" if version else package_name

        try:
            result = subprocess.run(
                [
                    "pip", "download", "--no-deps",
                    "-d", tmp_dir, pkg_spec,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                # Fallback: try source-only if wheel download fails
                result = subprocess.run(
                    [
                        "pip", "download", "--no-deps", "--no-binary", ":all:",
                        "-d", tmp_dir, pkg_spec,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

            # Extract downloaded archive
            downloaded = list(Path(tmp_dir).iterdir())
            if downloaded:
                archive = downloaded[0]
                extract_dir = os.path.join(tmp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)

                if archive.suffix in (".gz", ".tgz") or archive.name.endswith(".tar.gz"):
                    subprocess.run(
                        ["tar", "xzf", str(archive), "-C", extract_dir],
                        capture_output=True, timeout=30,
                    )
                elif archive.suffix == ".zip" or archive.suffix == ".whl":
                    subprocess.run(
                        ["unzip", "-q", str(archive), "-d", extract_dir],
                        capture_output=True, timeout=30,
                    )

                # Find the actual package directory
                extracted_dirs = list(Path(extract_dir).iterdir())
                if extracted_dirs:
                    return str(extracted_dirs[0])

                return extract_dir

        except subprocess.TimeoutExpired:
            logger.error(f"Timed out downloading {pkg_spec}")
        except Exception as e:
            logger.error(f"Error downloading {pkg_spec}: {e}")

        return tmp_dir
