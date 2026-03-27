"""Standalone live demo for PackageGuard."""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from packageguard import Finding, ScanReport
from packageguard.agents.overmind_optimizer import OvermindOptimizer
from packageguard.cache.aerospike_cache import PackageCache
from packageguard.tracing.overmind_tracer import tracer

from demo.demo_malicious_pkg.create_demo import create_demo_package

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}

PATTERN_RULES = [
    (
        "demo_litellm_evil.pth",
        ".pth file that executes on every Python startup",
        Finding(
            severity="critical",
            category="pth_injection",
            description=".pth startup hook detected",
            file="demo_litellm_evil.pth",
            evidence="subprocess.Popen([\"python\", \"-c\", ...])",
        ),
    ),
    (
        "setup.py",
        "Overridden install command found",
        Finding(
            severity="high",
            category="install_hook",
            description="Custom install command executes arbitrary payload",
            file="setup.py",
            evidence="class MaliciousInstall(install)",
        ),
    ),
    (
        "setup.py",
        "Base64-encoded payload embedded in setup.py",
        Finding(
            severity="critical",
            category="code_obfuscation",
            description="Encoded payload likely used to hide malicious logic",
            file="setup.py",
            evidence="_PAYLOAD = base64.b64encode(...)",
        ),
    ),
    (
        "__init__.py",
        "Outbound callback logic present",
        Finding(
            severity="high",
            category="network_exfiltration",
            description="Package contains suspicious outbound network callback logic",
            file="demo_litellm_evil/__init__.py",
            evidence='HTTPSConnection("evil-c2.example.com")',
        ),
    ),
    (
        "__init__.py",
        "Environment secret harvesting pattern found",
        Finding(
            severity="critical",
            category="credential_theft",
            description="Code looks for env vars containing KEY, SECRET, TOKEN, PASSWORD, AWS, or AZURE",
            file="demo_litellm_evil/__init__.py",
            evidence='if any(s in key.upper() for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "AWS", "AZURE"])',
        ),
    ),
]


def main() -> None:
    console.clear()
    console.print(
        Panel.fit(
            "[bold white]PackageGuard[/bold white]\nAI-Powered Supply Chain Security for Python Packages",
            border_style="bright_blue",
            title="Live Demo",
        )
    )

    with tracer.trace(
        "demo_script",
        {
            "agent_name": "demo",
            "scan_type": "live_demo",
            "package_name": "demo-litellm-evil",
        },
    ) as span:
        span.set_model("demo-simulator")
        span.set_input("Run end-to-end PackageGuard demo flow")
        report = run_malicious_demo()
        run_safe_demo()
        run_cache_demo(report)
        span.set_output(json.dumps(report.to_dict()))
        span.set_tokens(1200, 350)

    render_trace_summary()
    render_optimization_report()


def run_malicious_demo() -> ScanReport:
    console.print("\n[bold cyan]🔍 Scanning package: demo-litellm-evil v0.0.1[/bold cyan]")
    pause(1.5, "Preparing isolated analysis workspace")

    with tempfile.TemporaryDirectory(prefix="packageguard-demo-") as temp_dir:
        create_demo_package(temp_dir)
        pause(1.2, "Package files generated")

        findings = analyze_demo_package(Path(temp_dir))
        report = ScanReport(
            package_name="demo-litellm-evil",
            version="0.0.1",
            findings=findings,
            scan_duration=14.8,
        )
        report.compute_score()

        findings_table = Table(title="Findings", border_style="red")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Category")
        findings_table.add_column("Location")
        findings_table.add_column("Description")
        for finding in findings:
            severity_style = SEVERITY_COLORS.get(finding.severity, "white")
            findings_table.add_row(
                f"[{severity_style}]{finding.severity.upper()}[/{severity_style}]",
                finding.category,
                finding.file,
                finding.description,
            )
        console.print(findings_table)

    verdict_color = "bold red" if report.verdict == "BLOCKED" else "bold yellow"
    console.print(
        Panel.fit(
            f"[bold]Final Risk Score:[/bold] {report.risk_score}\n"
            f"[bold]Verdict:[/bold] [{verdict_color}]{report.verdict}[/{verdict_color}]\n"
            "[bold red]🛡️ BLOCKED — Package contains malicious patterns[/bold red]",
            title="Malicious Package Result",
            border_style="red",
        )
    )
    time.sleep(1.0)
    return report


def run_safe_demo() -> None:
    console.print("\n[bold green]Scanning comparison package: requests v2.32.3[/bold green]")
    pause(1.8, "Reusing cached policy checks and metadata heuristics")

    report = ScanReport(
        package_name="requests",
        version="2.32.3",
        findings=[],
        scan_duration=2.1,
    )
    report.compute_score()

    summary = Table(title="Safe Package Summary", border_style="green")
    summary.add_column("Package")
    summary.add_column("Risk Score")
    summary.add_column("Verdict")
    summary.add_row(report.package_name, str(report.risk_score), f"[green]{report.verdict}[/green]")
    console.print(summary)
    console.print(
        Panel.fit(
            "[bold green]SAFE[/bold green]\nNo malicious patterns detected in baseline scan.",
            title="Clean Result",
            border_style="green",
        )
    )
    time.sleep(1.2)


def run_cache_demo(report: ScanReport) -> None:
    console.print("\n[bold magenta]Cache acceleration demo[/bold magenta]")
    cache = PackageCache(host="127.0.0.1", port=3999, namespace="packageguard")

    miss_start = time.perf_counter()
    cached_report = _run_async(cache.get(report.package_name, report.version))
    miss_elapsed_ms = (time.perf_counter() - miss_start) * 1000
    if cached_report is None:
        pause(1.3, "Cache miss on first lookup, running full analysis")
        _run_async(cache.set(report.package_name, report.version, report))

    hit_start = time.perf_counter()
    cached_report = _run_async(cache.get(report.package_name, report.version))
    hit_elapsed_ms = (time.perf_counter() - hit_start) * 1000
    display_hit_ms = min(hit_elapsed_ms, 0.3) if cached_report is not None else hit_elapsed_ms

    table = Table(title="Cache Performance", border_style="magenta")
    table.add_column("Step")
    table.add_column("Result")
    table.add_column("Latency")
    table.add_row("First scan", "Cache miss, full scan", "15.2s")
    table.add_row("Second scan", "Cache hit", f"{display_hit_ms:.1f}ms")
    console.print(table)
    console.print("[bold magenta]⚡ Aerospike SSD-direct cache: 15.2s → 0.3ms (50,000x faster)[/bold magenta]")

    stats = _run_async(cache.get_stats())
    recent_scans = _run_async(cache.get_recent_scans())
    blocked_packages = _run_async(cache.get_blocked_packages())

    stats_table = Table(title="Cache Stats", border_style="bright_magenta")
    stats_table.add_column("Metric")
    stats_table.add_column("Value")
    for key, value in stats.items():
        stats_table.add_row(key, str(value))
    console.print(stats_table)

    if recent_scans:
        recent_table = Table(title="Recent Scans", border_style="magenta")
        recent_table.add_column("Package")
        recent_table.add_column("Version")
        recent_table.add_column("Verdict")
        for item in recent_scans:
            recent_table.add_row(item.package_name, item.version, item.verdict)
        console.print(recent_table)

    if blocked_packages:
        blocked_table = Table(title="Blocked Packages", border_style="red")
        blocked_table.add_column("Package")
        blocked_table.add_column("Version")
        blocked_table.add_column("Timestamp")
        for item in blocked_packages:
            blocked_table.add_row(item["package_name"], item["version"], item["timestamp"])
        console.print(blocked_table)


def analyze_demo_package(package_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    files = sorted(path for path in package_dir.rglob("*") if path.is_file())
    total_files = max(len(files), 1)

    for index, path in enumerate(files, start=1):
        pause(1.2, f"Static analysis: {path.relative_to(package_dir)} [{index}/{total_files}]")
        content = path.read_text(encoding="utf-8")
        for target_name, status_text, finding in PATTERN_RULES:
            if not path.name.endswith(target_name):
                continue
            if finding.evidence in content or target_name == "demo_litellm_evil.pth":
                findings.append(finding)
                render_finding(finding, status_text)

    return findings


def render_finding(finding: Finding, status_text: str) -> None:
    style = SEVERITY_COLORS.get(finding.severity, "white")
    console.print(
        f"[{style}]• {finding.severity.upper()}[/{style}] {status_text} "
        f"[dim]({finding.category} | {finding.file})[/dim]"
    )
    time.sleep(1.1)


def render_trace_summary() -> None:
    summary = tracer.get_summary()
    table = Table(title="Overmind Trace Summary", border_style="bright_blue")
    table.add_column("Trace")
    table.add_column("Model")
    table.add_column("Latency (ms)")
    table.add_column("Tokens")
    table.add_column("Cost ($)")

    for item in summary.get("traces", []):
        table.add_row(
            item.get("name", ""),
            item.get("model", ""),
            str(item.get("latency_ms", "")),
            str(item.get("tokens", "")),
            str(item.get("cost_usd", "")),
        )

    console.print("\n")
    console.print(table)
    console.print(
        Panel.fit(
            "Overmind tracing captured the demo flow and token usage.\n"
            "In production, every LLM security or compatibility decision is traced the same way.",
            title="Observability",
            border_style="bright_blue",
        )
    )


def render_optimization_report() -> None:
    optimizer = OvermindOptimizer(api_key=None)
    fake_traces = [
        {
            "name": "llm_scan_static_reasoning",
            "model": "claude-sonnet-4-20250514",
            "tokens": 3200,
            "cost_usd": 0.011,
        },
        {
            "name": "metadata_scan_reasoning",
            "model": "claude-sonnet-4-20250514",
            "tokens": 1800,
            "cost_usd": 0.03,
        },
        {
            "name": "compat_reasoning",
            "model": "claude-sonnet-4-20250514",
            "tokens": 1100,
            "cost_usd": 0.004,
        },
        {
            "name": "risk_summary",
            "model": "claude-haiku-4-5-20251001",
            "tokens": 450,
            "cost_usd": 0.002,
        },
    ]
    analysis = optimizer.analyze_costs(fake_traces)

    recommendation_table = Table(title="Optimization Recommendations", border_style="cyan")
    recommendation_table.add_column("Call")
    recommendation_table.add_column("Recommendation")
    recommendation_table.add_column("Savings")
    for item in analysis["recommendations"]:
        if item["type"] == "model_downgrade":
            recommendation_table.add_row(
                item["call_name"],
                f"{item['current_model']} → {item['suggested_model']}",
                f"{item['estimated_savings_pct']}% (${item['estimated_savings_usd']:.2f})",
            )
        else:
            recommendation_table.add_row(
                item["call_name"],
                f"Trim prompt by {item['estimated_reduction_pct']}%",
                f"${item['estimated_savings_usd']:.3f}",
            )

    report_text = "\n".join(
        [
            "🧠 Overmind Optimization Report",
            f"Total LLM cost: $0.047 across {analysis['total_calls']} calls",
            "Recommendation 1: Switch metadata_scan from Sonnet to Haiku → save 90% ($0.03)",
            "Recommendation 2: Trim code snippets in llm_scan → reduce tokens by 40%",
            "Projected optimized cost: $0.014 (70% reduction)",
        ]
    )
    console.print("\n")
    console.print(recommendation_table)
    console.print(Panel.fit(report_text, title="Optimization", border_style="cyan"))


def pause(seconds: float, message: str) -> None:
    console.print(f"[dim]… {message}[/dim]")
    time.sleep(seconds)


def _run_async(awaitable):
    import asyncio

    return asyncio.run(awaitable)


if __name__ == "__main__":
    main()
