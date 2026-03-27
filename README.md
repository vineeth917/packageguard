# PackageGuard

AI-powered Python supply chain security and dependency intelligence.

Built at Deep Agents Hackathon, March 2026.

## Overview

PackageGuard is an agentic security system for Python packages. It helps developers answer two questions before they install or upgrade a dependency:

1. Is this package version malicious or suspicious?
2. Will this package break my current dependency graph?

PackageGuard combines:

- static code analysis for install hooks, obfuscation, `.pth` injection, and secret-harvesting patterns
- metadata verification against PyPI and GitHub
- Docker-based sandbox analysis with network disabled
- LLM-assisted review of the highest-risk files
- dependency compatibility checks and upgrade reasoning

The output is a simple verdict: `SAFE`, `WARNING`, or `BLOCKED`, with step-by-step reasoning and a path to human review.

## Why We Built It

Recent supply chain incidents showed that trusted Python packages can be weaponized through install-time execution, startup persistence, and credential theft. A package can look legitimate on PyPI and still be dangerous in practice.

PackageGuard was built to make that risk visible before installation by combining deterministic scanning, provenance checks, sandbox execution, and model-based reasoning in one agent workflow.

## What It Does

- scans real PyPI packages like `numpy` and `requests` without false-positive blocking
- detects malicious local demo packages that use `.pth` startup execution, obfuscated payloads, or install-hook abuse
- verifies public metadata such as maintainer identity, release cadence, GitHub stars, repository age, and matching version tags
- runs isolated Docker analysis to inspect install-time or import-time behavior
- uses an LLM to review suspicious files and explain why a package appears safe or unsafe
- checks dependency compatibility and shows a proposed resolution path
- exposes everything through both a CLI and a browser UI

## Demo Flow

For a safe package such as `requests==2.31.0`, PackageGuard:

- confirms there are no malicious static patterns
- verifies PyPI and GitHub provenance
- runs Docker-based isolated analysis with networking disabled
- sends high-risk files to the LLM for review
- returns a `SAFE` verdict with positive reasoning

For a malicious demo package such as `demo/attack_scenarios/pth_injection`, PackageGuard:

- detects `.pth` startup persistence
- identifies suspicious code patterns and install behavior
- assigns a high risk score
- returns a `BLOCKED` verdict and pushes the user toward human review

## Screenshots

There are no committed screenshot assets in the repo yet. If you want to embed UI screenshots, add files like these:

```text
docs/images/safe-scan.png
docs/images/pipeline-view.png
```

Then add:

```md
![Safe package scan](docs/images/safe-scan.png)
![Pipeline view](docs/images/pipeline-view.png)
```

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                   PackageGuard CLI                  │
│            scan / scan-local / resolve              │
└──────────────┬──────────────────────────┬───────────┘
               │                          │
       ┌───────▼────────┐        ┌────────▼──────────┐
       │ Security Agent  │        │ Dependency Solver │
       │ orchestrates    │        │ compatibility     │
       └───────┬────────┘        └────────┬──────────┘
               │                          │
    ┌──────────┼──────────┬──────────┐    │
    │          │          │          │    │
┌───▼──┐ ┌────▼────┐ ┌───▼────┐ ┌───▼───┐ │
│Static│ │Metadata │ │Docker  │ │LLM    │ │
│Scan  │ │Checks   │ │Sandbox │ │Review │ │
└──────┘ └─────────┘ └────────┘ └───────┘ │
               │                          │
       ┌───────▼──────────────────────────▼──────────┐
       │     Risk report + verdict + human review     │
       └───────────────────────────────────────────────┘
```

## Sponsor Integration

| Sponsor | How We Use It |
|---------|---------------|
| **AWS** | Cloud infrastructure path for running the package analysis service |
| **Overmind** | Traces LLM calls, surfaces cost and optimization opportunities, and provides observability for agent behavior |
| **Aerospike** | Caches repeated scan results so known packages can be retrieved quickly |
| **TrueFoundry** | Intended deployment target for serving the agent in production |

## Quick Start

```bash
cd packageguard
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Start the API
python -m uvicorn packageguard.api.server:app --host 127.0.0.1 --port 8001

# Open the UI
open frontend/index.html
```

## CLI Examples

```bash
python -m packageguard scan numpy==2.2.0
python -m packageguard scan requests==2.31.0
python -m packageguard scan-local demo/attack_scenarios/pth_injection
python -m packageguard scan-local demo/attack_scenarios/safe_package
python -m packageguard resolve requirements.txt --new-packages "sentence-transformers>=2.3"
```

## API Examples

```bash
curl -s http://127.0.0.1:8001/health

curl -s -X POST http://127.0.0.1:8001/scan \
  -H 'Content-Type: application/json' \
  -d '{"package":"requests","version":"2.31.0"}'

curl -s -X POST http://127.0.0.1:8001/scan-local \
  -H 'Content-Type: application/json' \
  -d '{"path":"demo/attack_scenarios/pth_injection"}'
```

## System Design

- `packageguard/agents/security_agent.py` orchestrates static, metadata, Docker, and LLM scans
- `packageguard/scanners/static_scan.py` applies high-confidence rules while avoiding false positives on real packages
- `packageguard/scanners/metadata_scan.py` pulls live PyPI and GitHub data for provenance checks
- `packageguard/scanners/dynamic_scan.py` runs isolated package analysis in Docker with network disabled
- `packageguard/scanners/llm_scan.py` sends the highest-risk files to OpenRouter for structured security reasoning
- `packageguard/resolver/dependency_resolver.py` handles compatibility checks and conflict reporting
- `frontend/index.html` renders the interactive scan card, pipeline steps, and decision actions

## Project Structure

```text
packageguard/
├── Dockerfile.app
├── Dockerfile.sandbox
├── README.md
├── SUBMISSION.md
├── demo/
│   ├── attack_scenarios/
│   └── demo_script.py
├── docs/
│   └── architecture.md
├── frontend/
│   └── index.html
├── packageguard/
│   ├── agents/
│   ├── api/
│   ├── cache/
│   ├── resolver/
│   ├── scanners/
│   ├── tracing/
│   ├── __main__.py
│   └── config.py
├── tests/
│   ├── test_compat_agent.py
│   └── test_security_agent.py
└── pyproject.toml
```

## Notes

- `.env` is ignored by Git; use `.env.example` as a template
- Docker is required for full sandbox analysis
- `OPENROUTER_API_KEY` is required for live LLM review

## Repository

GitHub: https://github.com/vineeth917/packageguard
