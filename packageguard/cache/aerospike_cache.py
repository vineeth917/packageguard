"""Aerospike-backed cache with in-memory fallback for scan reports."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from packageguard import ScanReport
from packageguard.config import config

logger = logging.getLogger(__name__)

try:
    import aerospike
except ImportError:  # pragma: no cover
    aerospike = None


class PackageCache:
    """Cache scan results and safe-version hints."""

    def __init__(self, host: str = "localhost", port: int = 3000, namespace: str = "packageguard"):
        self.host = host
        self.port = port
        self.namespace = namespace
        self.set_name = "scans"
        self.connected = False
        self._client = None
        self._memory_scans: dict[str, tuple[float | None, str]] = {}
        self._memory_safe_versions: dict[str, set[str]] = defaultdict(set)
        self.cache_hits = 0
        self.cache_misses = 0
        self._connect()

    def _connect(self) -> None:
        if aerospike is None:
            logger.warning("Aerospike client not installed; using in-memory cache fallback.")
            return

        try:
            self._client = aerospike.client(
                {"hosts": [(self.host, self.port)]}
            ).connect()
            self.connected = True
        except Exception as exc:  # pragma: no cover
            logger.warning("Aerospike unavailable, falling back to in-memory cache: %s", exc)

    async def get(self, package_name: str, version: str) -> Optional[ScanReport]:
        key = self._scan_key(package_name, version)
        if self.connected and self._client is not None:
            report = await asyncio.to_thread(self._aerospike_get_scan, key)
        else:
            report = self._memory_get_scan(key)

        if report is None:
            self.cache_misses += 1
        else:
            self.cache_hits += 1
        return report

    async def set(self, package_name: str, version: str, report: ScanReport, ttl: int = 86400):
        key = self._scan_key(package_name, version)
        payload = report.to_dict()
        if self.connected and self._client is not None:
            await asyncio.to_thread(self._aerospike_set_scan, key, payload, ttl)
            return
        expires_at = time.time() + ttl if ttl > 0 else None
        self._memory_scans[key] = (expires_at, json.dumps(payload))

    async def get_safe_versions(self, package_name: str) -> list[str]:
        key = self._safe_key(package_name)
        if self.connected and self._client is not None:
            return await asyncio.to_thread(self._aerospike_get_safe_versions, key)
        return sorted(self._memory_safe_versions[package_name.lower()])

    async def mark_safe(self, package_name: str, version: str):
        key = self._safe_key(package_name)
        if self.connected and self._client is not None:
            await asyncio.to_thread(self._aerospike_mark_safe, key, package_name, version)
            return
        self._memory_safe_versions[package_name.lower()].add(version)

    async def list_cached_reports(self, package_name: str) -> list[ScanReport]:
        prefix = f"scan:{package_name.lower()}:"
        reports: list[ScanReport] = []

        if self.connected and self._client is not None:
            try:
                scan = self._client.scan(self.namespace, self.set_name)
                records = await asyncio.to_thread(scan.results)
                for _, _, bins in records:
                    if bins.get("cache_key", "").startswith(prefix):
                        reports.append(ScanReport.from_dict(json.loads(bins["report_json"])))
                return reports
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to scan Aerospike cache; falling back to empty list: %s", exc)
                return []

        now = time.time()
        for key, (expires_at, payload) in list(self._memory_scans.items()):
            if not key.startswith(prefix):
                continue
            if expires_at is not None and expires_at <= now:
                self._memory_scans.pop(key, None)
                continue
            reports.append(ScanReport.from_dict(json.loads(payload)))
        return reports

    async def get_recent_scans(self, limit: int = 10) -> list[ScanReport]:
        reports = await self._load_all_reports()
        reports.sort(key=lambda report: self._timestamp_value(report.timestamp), reverse=True)
        return reports[:limit]

    async def get_blocked_packages(self) -> list[dict[str, str]]:
        reports = await self._load_all_reports()
        blocked = [report for report in reports if report.verdict == "BLOCKED"]
        blocked.sort(key=lambda report: self._timestamp_value(report.timestamp), reverse=True)
        return [
            {
                "package_name": report.package_name,
                "version": report.version,
                "timestamp": report.timestamp,
            }
            for report in blocked
        ]

    async def get_stats(self) -> dict:
        reports = await self._load_all_reports()
        total_scans = len(reports)
        blocked_count = sum(1 for report in reports if report.verdict == "BLOCKED")
        avg_scan_time = (
            round(sum(report.scan_duration for report in reports) / total_scans, 3)
            if total_scans
            else 0.0
        )
        return {
            "total_scans": total_scans,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "blocked_count": blocked_count,
            "avg_scan_time": avg_scan_time,
        }

    async def get_recent_scans(self, limit: int = 10) -> list[dict]:
        """Return the most recent scan reports, sorted by timestamp descending."""
        reports = await self._load_all_reports()
        reports.sort(key=lambda r: self._timestamp_value(r.timestamp), reverse=True)
        return [
            {
                "package_name": r.package_name,
                "version": r.version,
                "risk_score": r.risk_score,
                "verdict": r.verdict,
                "scan_duration": r.scan_duration,
                "timestamp": r.timestamp,
            }
            for r in reports[:limit]
        ]

    def _aerospike_get_scan(self, key: str) -> Optional[ScanReport]:
        try:
            record_key = (self.namespace, self.set_name, key)
            _, _, bins = self._client.get(record_key)
            report = ScanReport.from_dict(json.loads(bins["report_json"]))
            report.cached = True
            return report
        except Exception:
            return None

    def _aerospike_set_scan(self, key: str, payload: dict, ttl: int) -> None:
        record_key = (self.namespace, self.set_name, key)
        bins = {"cache_key": key, "report_json": json.dumps(payload)}
        self._client.put(record_key, bins)

    def _aerospike_get_safe_versions(self, key: str) -> list[str]:
        try:
            record_key = (self.namespace, self.set_name, key)
            _, _, bins = self._client.get(record_key)
            versions = bins.get("versions", [])
            return sorted(set(versions))
        except Exception:
            return []

    def _aerospike_mark_safe(self, key: str, package_name: str, version: str) -> None:
        record_key = (self.namespace, self.set_name, key)
        versions = set(self._aerospike_get_safe_versions(key))
        versions.add(version)
        self._client.put(
            record_key,
            {
                "cache_key": key,
                "package_name": package_name.lower(),
                "versions": sorted(versions),
            },
        )

    def _memory_get_scan(self, key: str) -> Optional[ScanReport]:
        item = self._memory_scans.get(key)
        if item is None:
            return None
        expires_at, payload = item
        if expires_at is not None and expires_at <= time.time():
            self._memory_scans.pop(key, None)
            return None
        report = ScanReport.from_dict(json.loads(payload))
        report.cached = True
        return report

    async def _load_all_reports(self) -> list[ScanReport]:
        if self.connected and self._client is not None:
            try:
                scan = self._client.scan(self.namespace, self.set_name)
                records = await asyncio.to_thread(scan.results)
                reports: list[ScanReport] = []
                for _, _, bins in records:
                    report_json = bins.get("report_json")
                    if not report_json:
                        continue
                    try:
                        data = json.loads(report_json)
                        if "package_name" not in data:
                            continue
                        reports.append(ScanReport.from_dict(data))
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue
                return reports
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to load reports from Aerospike: %s", exc)
                return []

        now = time.time()
        reports = []
        for key, (expires_at, payload) in list(self._memory_scans.items()):
            if expires_at is not None and expires_at <= now:
                self._memory_scans.pop(key, None)
                continue
            if not key.startswith("scan:"):
                continue
            reports.append(ScanReport.from_dict(json.loads(payload)))
        return reports

    def _timestamp_value(self, timestamp: str) -> float:
        if not timestamp:
            return 0.0
        try:
            return datetime.fromisoformat(timestamp).timestamp()
        except ValueError:
            return 0.0

    def _scan_key(self, package_name: str, version: str) -> str:
        return f"scan:{package_name.lower()}:{version}"

    def _safe_key(self, package_name: str) -> str:
        return f"safe:{package_name.lower()}"


cache = PackageCache(
    host=config.AEROSPIKE_HOST,
    port=config.AEROSPIKE_PORT,
    namespace=config.AEROSPIKE_NAMESPACE,
)
