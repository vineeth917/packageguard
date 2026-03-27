# PackageGuard — AI Supply Chain Security Agent

## What it does
PackageGuard is an autonomous AI agent that prevents Python supply chain attacks. Users describe their security concerns in natural language, and the agent plans and executes multi-step security analysis: static code scanning, metadata verification, LLM-powered code review, and dependency compatibility checking.

## The Problem
On March 24, 2026, TeamPCP compromised LiteLLM on PyPI (480M+ downloads). Malicious versions deployed credential stealers via .pth file injection, harvesting SSH keys, cloud tokens, and Kubernetes secrets. Enterprises with auto-update bots were vulnerable within minutes.

## How it works
1. User describes concern in natural language
2. Agent (powered by Claude via OpenRouter) creates an action plan
3. Static scanner checks for .pth injection, base64 obfuscation, credential theft patterns
4. Metadata scanner verifies PyPI releases against GitHub tags
5. LLM scanner sends suspicious code to Claude for deep analysis
6. Results aggregated into risk score (0-100) with SAFE/WARNING/BLOCKED verdict
7. All LLM calls traced via Overmind for continuous optimization
8. Scan results cached in Aerospike for sub-millisecond repeat lookups

## Sponsor Integration
- **AWS**: Cloud compute for sandboxed analysis
- **Overmind**: Every LLM call traced and scored. Optimization recommendations reduce cost by 70% (Sonnet→Haiku for metadata checks, prompt compression for code review)
- **Aerospike**: SSD-direct indexed cache. First scan: 15s. Repeat scan: <1ms.
- **TrueFoundry**: Production deployment with observability

## Tech Stack
Python, FastAPI, OpenRouter (Claude Sonnet), Docker, Overmind SDK, Rich CLI

## How to run
```bash
pip install -r requirements.txt
# Set OPENROUTER_API_KEY in .env
uvicorn packageguard.api.server:app --port 8000
# Open frontend/index.html in browser
```

## Demo
```bash
python demo/demo_script.py          # Terminal demo
python -m packageguard scan-local demo/demo_malicious_pkg/  # CLI scan
```

## Team
Solo build using Claude Code + Codex as AI teammates
