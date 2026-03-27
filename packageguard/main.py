"""
PackageGuard CLI entrypoint.

Usage:
    packageguard scan <package>==<version>
    packageguard scan-local <path>
    packageguard resolve <requirements.txt> --new <pkg1> <pkg2>
    packageguard guard --watch <requirements.txt>
"""

import asyncio
import json
import logging
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packageguard.agents.orchestrator import PackageGuardOrchestrator
from packageguard.agents.overmind_optimizer import OvermindOptimizer


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_report(result: dict):
    """Pretty-print scan results."""
    summary = result.get("summary", {})
    reports = result.get("scan_reports", [])

    print("\n" + "=" * 60)
    print("  PACKAGEGUARD SCAN RESULTS")
    print("=" * 60)

    for report in reports:
        verdict = report["verdict"]
        score = report["risk_score"]
        pkg = report["package_name"]
        ver = report["version"]

        # Verdict indicator
        if verdict == "BLOCKED":
            indicator = "[X BLOCKED]"
        elif verdict == "WARNING":
            indicator = "[! WARNING]"
        else:
            indicator = "[  SAFE   ]"

        print(f"\n{indicator} {pkg}=={ver}  (risk score: {score}/100)")
        print(f"  Scan duration: {report['scan_duration']}s")

        findings = report.get("findings", [])
        if findings:
            print(f"  Findings ({len(findings)}):")
            for f in findings:
                sev = f["severity"].upper()
                print(f"    [{sev}] {f['category']}: {f['description']}")
                if f.get("file"):
                    loc = f["file"]
                    if f.get("line"):
                        loc += f":{f['line']}"
                    print(f"           File: {loc}")
                if f.get("evidence"):
                    evidence = f["evidence"][:100].replace("\n", " ")
                    print(f"           Evidence: {evidence}")
        else:
            print("  No findings.")

    # Overall summary
    print("\n" + "-" * 60)
    overall = summary.get("overall_verdict", "UNKNOWN")
    print(
        f"  Overall: {overall} | "
        f"{summary.get('safe', 0)} safe, "
        f"{summary.get('warnings', 0)} warnings, "
        f"{summary.get('blocked', 0)} blocked"
    )
    print("=" * 60 + "\n")

    # Compat report
    compat = result.get("compat_report")
    if compat:
        print("Compatibility Report:")
        print(f"  Status: {compat['status']}")
        if compat.get("conflicts"):
            print("  Conflicts:")
            for c in compat["conflicts"]:
                print(f"    - {c}")
        if compat.get("suggestions"):
            print("  Suggestions:")
            for s in compat["suggestions"]:
                print(f"    - {s}")
        print()


async def cmd_scan(packages: list[str]):
    """Scan one or more packages."""
    orchestrator = PackageGuardOrchestrator()
    result = await orchestrator.analyze(packages)
    print_report(result)
    return result


async def cmd_scan_local(path: str, name: str = "local"):
    """Scan a local package directory."""
    orchestrator = PackageGuardOrchestrator()
    result = await orchestrator.scan_local(path, name)
    print_report(result)
    return result


async def cmd_resolve(requirements_file: str, new_packages: list[str]):
    """Check compatibility of new packages with existing requirements."""
    orchestrator = PackageGuardOrchestrator()
    result = await orchestrator.analyze(
        packages=new_packages,
        existing_requirements=requirements_file,
    )
    print_report(result)
    return result


async def cmd_optimize():
    """Fetch Overmind optimization suggestions and display them."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        console = Console()
    except ImportError:
        console = None

    optimizer = OvermindOptimizer()
    traces = await optimizer.get_traces()

    if not traces:
        msg = (
            "No traces found. Run some scans first:\n"
            "  packageguard scan requests==2.31.0\n"
            "  packageguard scan-local demo/demo_malicious_pkg/"
        )
        if console:
            console.print(f"[yellow]{msg}[/yellow]")
        else:
            print(msg)
        return

    analysis = optimizer.analyze_costs(traces)

    if console:
        # Rich formatted output
        console.print()

        # Before/after cost table
        cost_table = Table(title="Cost Analysis", border_style="cyan")
        cost_table.add_column("Metric", style="bold")
        cost_table.add_column("Value")
        cost_table.add_row("Total LLM calls", str(analysis["total_calls"]))
        cost_table.add_row("Total tokens", str(analysis["total_tokens"]))
        cost_table.add_row("Current cost", f"${analysis['total_cost']:.4f}")
        cost_table.add_row("Optimized cost", f"${analysis['estimated_optimized_cost']:.4f}")
        cost_table.add_row("Savings", f"{analysis['estimated_savings_pct']:.0f}%")
        console.print(cost_table)

        # Recommendations table
        recs = analysis.get("recommendations", [])
        if recs:
            rec_table = Table(title="Optimization Recommendations", border_style="green")
            rec_table.add_column("#", style="bold")
            rec_table.add_column("Call")
            rec_table.add_column("Type")
            rec_table.add_column("Recommendation")
            rec_table.add_column("Savings")

            for i, r in enumerate(recs, 1):
                if r["type"] == "model_downgrade":
                    rec_table.add_row(
                        str(i), r["call_name"], "Model switch",
                        f"{r['current_model']} -> {r['suggested_model']}",
                        f"{r['estimated_savings_pct']}% (${r['estimated_savings_usd']:.4f})",
                    )
                else:
                    rec_table.add_row(
                        str(i), r["call_name"], "Prompt trim",
                        f"Reduce tokens by {r['estimated_reduction_pct']}%",
                        f"${r['estimated_savings_usd']:.4f}",
                    )
            console.print(rec_table)

        # Summary panel
        console.print(Panel(
            optimizer.format_report(analysis),
            title="Overmind Optimization Summary",
            border_style="bright_cyan",
        ))
    else:
        # Plain text fallback
        print("\n" + "=" * 60)
        print("  OVERMIND OPTIMIZATION REPORT")
        print("=" * 60)
        print(f"  Total calls: {analysis['total_calls']}")
        print(f"  Total tokens: {analysis['total_tokens']}")
        print(f"  Current cost: ${analysis['total_cost']:.4f}")
        print(f"  Optimized cost: ${analysis['estimated_optimized_cost']:.4f}")
        print(f"  Savings: {analysis['estimated_savings_pct']:.0f}%")
        for i, r in enumerate(analysis.get("recommendations", []), 1):
            print(f"\n  Recommendation {i}: {r.get('reason', '')}")
        print("=" * 60 + "\n")


async def cmd_guard(requirements_file: str, interval: int = 300):
    """Continuously monitor a requirements file."""
    print(f"Watching {requirements_file} (checking every {interval}s)")
    print("Press Ctrl+C to stop.\n")

    orchestrator = PackageGuardOrchestrator()

    while True:
        try:
            with open(requirements_file) as f:
                lines = [
                    l.strip() for l in f.readlines()
                    if l.strip() and not l.strip().startswith("#")
                ]

            if lines:
                result = await orchestrator.analyze(lines)
                print_report(result)

                blocked = result.get("summary", {}).get("blocked", 0)
                if blocked > 0:
                    print(f"[ALERT] {blocked} package(s) BLOCKED!")

            await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopping guard mode.")
            break
        except Exception as e:
            logging.error(f"Guard error: {e}")
            await asyncio.sleep(interval)


def main():
    """CLI entrypoint."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print("PackageGuard - AI-Powered Supply Chain Security\n")
        print("Usage:")
        print("  packageguard scan <package>[==version] [<package2>...]")
        print("  packageguard scan-local <path> [--name <pkg_name>]")
        print("  packageguard resolve <requirements.txt> --new <pkg1> [<pkg2>...]")
        print("  packageguard guard --watch <requirements.txt>")
        print("  packageguard optimize                              # Overmind cost optimization")
        print("\nOptions:")
        print("  -v, --verbose    Enable debug logging")
        print("  --json           Output raw JSON")
        sys.exit(0)

    verbose = "-v" in args or "--verbose" in args
    args = [a for a in args if a not in ("-v", "--verbose")]

    setup_logging(verbose)

    command = args[0]

    if command == "scan":
        if len(args) < 2:
            print("Error: specify at least one package")
            sys.exit(1)
        asyncio.run(cmd_scan(args[1:]))

    elif command == "scan-local":
        if len(args) < 2:
            print("Error: specify a package directory")
            sys.exit(1)
        path = args[1]
        name = "local"
        if "--name" in args:
            idx = args.index("--name")
            if idx + 1 < len(args):
                name = args[idx + 1]
        asyncio.run(cmd_scan_local(path, name))

    elif command == "resolve":
        if len(args) < 2:
            print("Error: specify a requirements file")
            sys.exit(1)
        req_file = args[1]
        new_pkgs = []
        if "--new" in args:
            idx = args.index("--new")
            new_pkgs = args[idx + 1:]
        if not new_pkgs:
            print("Error: specify --new <packages>")
            sys.exit(1)
        asyncio.run(cmd_resolve(req_file, new_pkgs))

    elif command == "optimize":
        asyncio.run(cmd_optimize())

    elif command == "guard":
        req_file = None
        if "--watch" in args:
            idx = args.index("--watch")
            if idx + 1 < len(args):
                req_file = args[idx + 1]
        if not req_file:
            print("Error: specify --watch <requirements.txt>")
            sys.exit(1)
        asyncio.run(cmd_guard(req_file))

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
