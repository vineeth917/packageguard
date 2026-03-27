"""
PackageGuardOrchestrator — top-level coordinator.

For each package:
1. Check cache first
2. Run SecurityAgent scan
3. If safe and requirements given, run CompatAgent
4. Cache results
5. Return final report
"""

import asyncio
import logging
from typing import Optional

from packageguard import ScanReport, CompatReport
from packageguard.agents.security_agent import SecurityAgent

logger = logging.getLogger(__name__)


def _parse_package_spec(spec: str) -> tuple[str, Optional[str]]:
    """Parse 'package==version' or 'package>=version' into (name, version)."""
    for sep in ["==", ">=", "<=", "~=", "!="]:
        if sep in spec:
            parts = spec.split(sep, 1)
            return parts[0].strip(), parts[1].strip()
    return spec.strip(), None


class PackageGuardOrchestrator:
    """Top-level orchestrator that coordinates scanning and resolution."""

    def __init__(self):
        self.security_agent = SecurityAgent()
        self._cache = None
        self._resolver = None

    def _get_cache(self):
        """Lazy-load cache module (Codex's code, may not exist yet)."""
        if self._cache is None:
            try:
                from packageguard.cache.aerospike_cache import PackageCache
                self._cache = PackageCache()
            except (ImportError, Exception) as e:
                logger.debug(f"Cache not available: {e}")
                self._cache = False  # Mark as unavailable
        return self._cache if self._cache is not False else None

    def _get_resolver(self):
        """Lazy-load resolver module (Codex's code, may not exist yet)."""
        if self._resolver is None:
            try:
                from packageguard.resolver.dependency_resolver import CompatAgent
                self._resolver = CompatAgent()
            except (ImportError, Exception) as e:
                logger.debug(f"Resolver not available: {e}")
                self._resolver = False
        return self._resolver if self._resolver is not False else None

    async def analyze(
        self,
        packages: list[str],
        existing_requirements: str = None,
    ) -> dict:
        """
        Analyze a list of packages.

        Args:
            packages: List of package specs like ["requests==2.31.0", "flask"]
            existing_requirements: Path to existing requirements.txt for compat checking

        Returns:
            Dict with scan_reports and optional compat_report
        """
        scan_reports: list[ScanReport] = []
        cache = self._get_cache()

        # Scan each package
        tasks = []
        for pkg_spec in packages:
            name, version = _parse_package_spec(pkg_spec)
            tasks.append(self._scan_one(name, version, cache))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Scan failed: {result}")
            elif isinstance(result, ScanReport):
                scan_reports.append(result)

        # Run compatibility check if requirements provided and packages are safe
        compat_report = None
        safe_packages = [
            f"{r.package_name}=={r.version}"
            for r in scan_reports
            if r.verdict in ("SAFE", "WARNING")
        ]

        if existing_requirements and safe_packages:
            resolver = self._get_resolver()
            if resolver:
                try:
                    compat_report = await resolver.resolve(
                        existing_requirements=existing_requirements,
                        new_packages=safe_packages,
                    )
                except Exception as e:
                    logger.error(f"Compatibility check failed: {e}")

        return {
            "scan_reports": [r.to_dict() for r in scan_reports],
            "compat_report": compat_report.to_dict() if compat_report else None,
            "summary": self._build_summary(scan_reports),
        }

    async def _scan_one(
        self,
        package_name: str,
        version: Optional[str],
        cache,
    ) -> ScanReport:
        """Scan a single package, checking cache first."""
        # Check cache
        if cache:
            try:
                cached = await cache.get(package_name, version or "latest")
                if cached:
                    cached.cached = True
                    logger.info(f"[{package_name}] Cache hit")
                    return cached
            except Exception as e:
                logger.debug(f"Cache lookup failed: {e}")

        # Run scan
        report = await self.security_agent.scan(package_name, version)

        # Store in cache
        if cache:
            try:
                await cache.set(package_name, version or "latest", report)
            except Exception as e:
                logger.debug(f"Cache store failed: {e}")

        return report

    async def scan_local(self, package_dir: str, package_name: str = "local") -> dict:
        """Scan a local package directory."""
        report = await self.security_agent.scan_local(package_dir, package_name)
        return {
            "scan_reports": [report.to_dict()],
            "compat_report": None,
            "summary": self._build_summary([report]),
        }

    def _build_summary(self, reports: list[ScanReport]) -> dict:
        """Build a summary of all scan results."""
        total = len(reports)
        blocked = sum(1 for r in reports if r.verdict == "BLOCKED")
        warned = sum(1 for r in reports if r.verdict == "WARNING")
        safe = sum(1 for r in reports if r.verdict == "SAFE")

        return {
            "total_packages": total,
            "blocked": blocked,
            "warnings": warned,
            "safe": safe,
            "overall_verdict": "BLOCKED" if blocked > 0 else ("WARNING" if warned > 0 else "SAFE"),
        }
