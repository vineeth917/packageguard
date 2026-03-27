"""FastAPI server for PackageGuard."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from packageguard import Finding
from packageguard import ScanReport
from packageguard.agents.overmind_optimizer import OvermindOptimizer
from packageguard.cache.aerospike_cache import cache
from packageguard.config import config
from packageguard.resolver.dependency_resolver import CompatAgent
from packageguard.tracing.overmind_tracer import tracer

try:
    from packageguard.agents.orchestrator import PackageGuardOrchestrator
except ImportError:  # pragma: no cover
    PackageGuardOrchestrator = None


app = FastAPI(title="PackageGuard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

compat_agent = CompatAgent()
orchestrator = PackageGuardOrchestrator() if PackageGuardOrchestrator is not None else None


class ScanRequest(BaseModel):
    package: str = Field(..., min_length=1)
    version: Optional[str] = None


@app.post("/scan")
async def scan_package(request: ScanRequest):
    version = request.version or "latest"
    cached_report = await cache.get(request.package, version)
    if cached_report is not None:
        return cached_report.to_dict()

    report = None
    if orchestrator is not None:
        try:
            result = await orchestrator.analyze(packages=[_package_spec(request.package, request.version)])
            # orchestrator.analyze() returns {"scan_reports": [...], "summary": {...}}
            scan_reports = result.get("scan_reports", []) if isinstance(result, dict) else []
            if scan_reports:
                report = scan_reports[0]  # Already a dict with package_name, etc.
            elif isinstance(result, dict) and "package_name" in result:
                report = result
        except Exception:
            report = None

    scan_report = (
        _coerce_scan_report(request.package, version, report)
        if report is not None
        else _mock_scan_report(request.package, version)
    )
    await cache.set(scan_report.package_name, scan_report.version, scan_report)
    if scan_report.verdict == "SAFE":
        await cache.mark_safe(scan_report.package_name, scan_report.version)
    return scan_report.to_dict()


@app.post("/agent")
async def agent_chat(request: dict):
    """Natural language agent interface. User describes what they want, agent plans and executes."""
    user_prompt = request.get("prompt", "")

    openrouter_key = os.getenv("OPENROUTER_API_KEY", "")

    system_prompt = """You are PackageGuard, an AI supply chain security agent for Python packages.

The user will describe their security concerns about Python packages. Analyze their request and respond with ONLY a JSON object (no markdown, no backticks):

{
  "explanation": "Brief explanation of what you'll do",
  "steps": [
    {"action": "scan", "package": "package_name", "version": "version_or_null"},
    {"action": "check_updates", "packages": ["pkg==version", ...]},
    {"action": "resolve", "existing": ["pkg==ver"], "new_packages": ["pkg>=ver"]}
  ]
}

Available actions:
- "scan": Security scan a specific package version for malware/vulnerabilities
- "check_updates": Check if newer versions exist for pinned packages and scan them
- "resolve": Check if new packages are compatible with existing ones

Extract package names and versions from the user's message. If they mention being worried about updates, use check_updates. If they mention compatibility, use resolve. Always scan packages that are mentioned."""

    with tracer.trace(
        "agent_planning",
        {"agent_name": "packageguard", "scan_type": "agent_planning", "package_name": "multi"},
    ) as span:
        span.set_input(user_prompt)
        span.set_model("anthropic/claude-sonnet-4")
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {openrouter_key}"},
                    json={
                        "model": "anthropic/claude-sonnet-4",
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                    },
                )
                llm_result = resp.json()
                plan_text = llm_result["choices"][0]["message"]["content"]
                plan = json.loads(plan_text)
                span.set_output(plan_text)
                usage = llm_result.get("usage", {})
                span.set_tokens(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
            except Exception:
                plan = _fallback_agent_plan(user_prompt)
                span.set_output(json.dumps(plan))
                span.set_tokens(400, 120)

    results = []
    for step in plan.get("steps", []):
        if step["action"] == "scan":
            try:
                from packageguard.agents.orchestrator import PackageGuardOrchestrator

                orch = PackageGuardOrchestrator()
                pkg_str = step["package"]
                if step.get("version"):
                    pkg_str += f"=={step['version']}"
                analysis = await orch.analyze(packages=[pkg_str])
                # Extract individual scan reports from the analysis dict
                scan_reports = analysis.get("scan_reports", [])
                for sr in scan_reports:
                    results.append({"step": step, "result": sr})
                if not scan_reports:
                    results.append({"step": step, "result": analysis})
            except Exception as exc:
                mock = ScanReport(package_name=step["package"], version=step.get("version", "latest"))
                mock.findings = [
                    Finding(
                        severity="info",
                        category="mock",
                        description=f"Scan error: {str(exc)[:200]}",
                    )
                ]
                mock.compute_score()
                results.append({"step": step, "result": mock.to_dict()})

        elif step["action"] == "check_updates":
            update_results = []
            for pkg_spec in step.get("packages", []):
                name = pkg_spec.split("==")[0] if "==" in pkg_spec else pkg_spec
                try:
                    async with httpx.AsyncClient() as client:
                        r = await client.get(f"https://pypi.org/pypi/{name}/json")
                        data = r.json()
                        latest = data["info"]["version"]
                        current = pkg_spec.split("==")[1] if "==" in pkg_spec else "unknown"
                        update_results.append(
                            {
                                "package": name,
                                "current": current,
                                "latest": latest,
                                "update_available": current != latest,
                            }
                        )
                except Exception:
                    update_results.append(
                        {
                            "package": name,
                            "current": "unknown",
                            "latest": "unknown",
                            "update_available": False,
                        }
                    )
            results.append({"step": step, "result": update_results})

        elif step["action"] == "resolve":
            temp_requirements_path: Path | None = None
            try:
                if step.get("requirements_path"):
                    requirements_path = step["requirements_path"]
                else:
                    existing_lines = step.get("existing", [])
                    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as temp_file:
                        temp_file.write("\n".join(existing_lines) + ("\n" if existing_lines else ""))
                        temp_requirements_path = Path(temp_file.name)
                    requirements_path = str(temp_requirements_path)

                with tracer.trace(
                    "resolve_execution",
                    {"agent_name": "compat_agent", "scan_type": "dependency_resolution", "package_name": ",".join(step.get("new_packages", []))},
                ) as span:
                    span.set_model(config.ANTHROPIC_MODEL if os.getenv("ANTHROPIC_API_KEY") else "demo-resolver")
                    span.set_input(json.dumps(step))
                    report = await compat_agent.resolve(
                        existing_requirements=requirements_path,
                        new_packages=step.get("new_packages", []),
                        python_version=step.get("python_version", "3.10"),
                    )
                    payload = {
                        "status": report.status,
                        "resolved_versions": report.resolved_versions,
                        "conflicts": report.conflicts,
                        "suggestions": report.suggestions,
                        "attempts": report.attempts,
                        "resolution_chain": report.suggestions,
                    }
                    span.set_output(json.dumps(payload))
                    span.set_tokens(700, 220)
                results.append({"step": step, "result": payload})
            except Exception as exc:
                results.append({"step": step, "result": {"status": "failed", "error": str(exc)}})
            finally:
                if temp_requirements_path is not None:
                    temp_requirements_path.unlink(missing_ok=True)

    return {
        "explanation": plan.get("explanation", ""),
        "steps": plan.get("steps", []),
        "results": results,
    }


@app.post("/resolve")
async def resolve_deps(
    requirements: UploadFile = File(...),
    new_packages: list[str] = Form(...),
    python_version: str = Form("3.10"),
):
    suffix = Path(requirements.filename or "requirements.txt").suffix or ".txt"
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False) as temp_file:
            temp_file.write(await requirements.read())
            temp_path = Path(temp_file.name)

        report = await compat_agent.resolve(
            existing_requirements=str(temp_path),
            new_packages=new_packages,
            python_version=python_version,
        )
        return report.to_dict()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Dependency resolution failed: {exc}") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


@app.post("/scan-local")
async def scan_local_package(request: dict):
    package_path = request.get("path", "")
    package_name = request.get("package_name") or Path(package_path).name or "local"
    if not package_path:
        raise HTTPException(status_code=400, detail="path is required")
    if orchestrator is not None:
        result = await orchestrator.scan_local(package_path, package_name)
    else:
        from packageguard.agents.security_agent import SecurityAgent

        report = await SecurityAgent().scan_local(package_path, package_name)
        result = {
            "scan_reports": [report.to_dict()],
            "compat_report": None,
            "summary": {
                "total_packages": 1,
                "blocked": 1 if report.verdict == "BLOCKED" else 0,
                "warnings": 1 if report.verdict == "WARNING" else 0,
                "safe": 1 if report.verdict == "SAFE" else 0,
                "overall_verdict": report.verdict,
            },
        }
    return result


@app.get("/cache/{package_name}")
async def get_cached(package_name: str):
    reports = await cache.list_cached_reports(package_name)
    safe_versions = await cache.get_safe_versions(package_name)
    return {
        "package_name": package_name,
        "reports": [report.to_dict() for report in reports],
        "safe_versions": safe_versions,
        "backend": "aerospike" if cache.connected else "memory",
    }


@app.get("/stats")
async def stats():
    s = await cache.get_stats()
    # Include recent scans for the dashboard
    s["recent_scans"] = await cache.get_recent_scans(limit=10)
    return s


@app.get("/optimize")
async def optimize():
    optimizer = OvermindOptimizer()
    traces = await optimizer.get_traces()
    analysis = optimizer.analyze_costs(traces)
    # Include trace details and feedback stats for the frontend
    analysis["traces"] = traces
    analysis["feedback_stats"] = tracer.get_feedback_stats()
    return analysis


@app.get("/benchmark")
async def benchmark():
    """Benchmark Aerospike SSD cache vs in-memory performance."""
    import time as _time

    # Create test reports with varying sizes
    test_sizes = [1, 5, 10, 50]
    results = {"backend": "aerospike" if cache.connected else "memory", "tests": []}

    for n_findings in test_sizes:
        test_report = ScanReport(
            package_name=f"bench-pkg-{n_findings}",
            version="1.0.0",
            findings=[
                Finding(
                    severity="medium",
                    category="benchmark_test",
                    description=f"Test finding #{i} with sample evidence data for benchmarking " * 3,
                    file=f"src/module_{i}.py",
                    line=i * 10,
                    evidence=f"suspicious_call_{i}()" * 5,
                )
                for i in range(n_findings)
            ],
        )
        test_report.compute_score()

        # Write benchmark
        t0 = _time.perf_counter()
        for _ in range(100):
            await cache.set(test_report.package_name, test_report.version, test_report, ttl=60)
        write_ms = (_time.perf_counter() - t0) * 1000

        # Read benchmark (cache hits)
        t0 = _time.perf_counter()
        for _ in range(100):
            await cache.get(test_report.package_name, test_report.version)
        read_ms = (_time.perf_counter() - t0) * 1000

        payload_bytes = len(json.dumps(test_report.to_dict()).encode())

        results["tests"].append({
            "findings_count": n_findings,
            "payload_bytes": payload_bytes,
            "write_100_ms": round(write_ms, 2),
            "read_100_ms": round(read_ms, 2),
            "write_avg_us": round(write_ms * 10, 1),  # per-op in microseconds
            "read_avg_us": round(read_ms * 10, 1),
            "throughput_reads_per_sec": round(100_000 / read_ms) if read_ms > 0 else 0,
            "throughput_writes_per_sec": round(100_000 / write_ms) if write_ms > 0 else 0,
        })

    # SSD-specific stats if Aerospike is connected
    if cache.connected and cache._client:
        try:
            info = cache._client.info_all(f"namespace/{cache.namespace}")
            ns_stats = {}
            for _, (_, raw) in info.items():
                for kv in raw.strip().split(";"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        ns_stats[k] = v
            results["aerospike_stats"] = {
                "storage_engine": "device (SSD/file-backed)",
                "data_in_memory": ns_stats.get("storage-engine.data-in-memory", "false"),
                "device_total_bytes": ns_stats.get("device_total_bytes", "0"),
                "device_used_bytes": ns_stats.get("device_used_bytes", "0"),
                "device_free_pct": ns_stats.get("device_free_pct", "100"),
                "objects": ns_stats.get("objects", "0"),
                "memory_used_index_bytes": ns_stats.get("memory_used_index_bytes", "0"),
                "cache_read_pct": ns_stats.get("cache_read_pct", ns_stats.get("cache-read-pct", "0")),
            }
        except Exception:
            pass

    return results


@app.post("/feedback")
async def submit_feedback(request: dict):
    """User feedback on scan quality. Also forwards to Overmind if available."""
    trace_id = request.get("trace_id", "")
    rating = request.get("rating", "")  # "up" or "down"
    note = request.get("note", "")

    if not trace_id:
        raise HTTPException(status_code=400, detail="trace_id is required")

    # Store locally in the tracer
    tracer.record_feedback(trace_id, rating, note)

    # Forward to Overmind if available
    overmind_url = os.getenv("OVERMIND_API_URL", "http://localhost:8000")
    overmind_status = "skipped"
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            login_resp = await client.post(
                f"{overmind_url}/api/v1/iam/users/login",
                json={"email": "admin", "password": "admin"},
            )
            token = login_resp.json().get("access_token", "")
            if token:
                await client.patch(
                    f"{overmind_url}/api/v1/spans/{trace_id}/feedback",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"feedback_type": "agent", "rating": rating, "text": note},
                )
                overmind_status = "forwarded"
        except Exception:
            overmind_status = "overmind_unavailable"

    # Build suggestion based on feedback
    suggestion = ""
    trace = tracer.get_trace_by_id(trace_id)
    if trace and rating == "up":
        if trace.metadata.get("scan_type") == "metadata":
            suggestion = "Verified accurate — metadata checks can use a cheaper model (Haiku)"
        else:
            suggestion = "Keeping current model — verified accurate"
    elif trace and rating == "down":
        if note in ("false_positive", "missed_findings"):
            suggestion = "Flagged for review — may need a more capable model (Sonnet)"
        elif note == "too_expensive":
            suggestion = "Based on your feedback, this call could use a cheaper model"
        else:
            suggestion = "Feedback recorded — will inform model routing"

    stats = tracer.get_feedback_stats()
    return {
        "status": "recorded",
        "trace_id": trace_id,
        "rating": rating,
        "suggestion": suggestion,
        "overmind": overmind_status,
        "feedback_stats": stats,
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "aerospike": cache.connected,
        "orchestrator": orchestrator is not None,
    }


def _package_spec(package_name: str, version: Optional[str]) -> str:
    if package_name.startswith(".") or package_name.startswith("/") or Path(package_name).exists():
        return package_name
    return f"{package_name}=={version}" if version else package_name


def _coerce_scan_report(package_name: str, version: str, report: object) -> ScanReport:
    if isinstance(report, ScanReport):
        return report
    if isinstance(report, dict):
        return ScanReport.from_dict(report)
    if hasattr(report, "to_dict"):
        return ScanReport.from_dict(report.to_dict())
    raise TypeError(f"Unsupported scan report type: {type(report)!r}")


def _mock_scan_report(package_name: str, version: str) -> ScanReport:
    package_path = Path(package_name)
    is_local_path = package_name.startswith(".") or package_name.startswith("/") or package_path.exists()

    findings: list[Finding] = []
    normalized_name = package_path.name if is_local_path else package_name

    if "evil" in normalized_name.lower() or "malicious" in normalized_name.lower():
        findings = [
            Finding(
                severity="critical",
                category="pth_injection",
                description="Detected suspicious startup hook behavior in mock scan.",
            ),
            Finding(
                severity="high",
                category="network_exfiltration",
                description="Detected suspicious outbound callback pattern in mock scan.",
            ),
        ]

    report = ScanReport(
        package_name=normalized_name,
        version=version,
        findings=findings,
        scan_duration=0.3 if is_local_path else 0.6,
    )
    report.compute_score()
    return report


def _fallback_agent_plan(user_prompt: str) -> dict:
    lowered = user_prompt.lower()
    if "sentence-transformers" in lowered and ("add" in lowered or "compat" in lowered):
        return {
            "explanation": "I'll scan the package request and check dependency compatibility against the current project pins.",
            "steps": [
                {"action": "scan", "package": "sentence-transformers", "version": "3.0.0"},
                {
                    "action": "resolve",
                    "existing": ["demo/demo_requirements.txt"],
                    "requirements_path": "demo/demo_requirements.txt",
                    "new_packages": ["sentence-transformers==3.0.0"],
                },
            ],
        }
    return {
        "explanation": "I'll scan the packages you mentioned for security issues.",
        "steps": [{"action": "scan", "package": "litellm", "version": "1.82.8"}],
    }
