# PackageGuard 🛡️

**AI-Powered Supply Chain Security & Dependency Intelligence for Python**

> Built at Deep Agents Hackathon — March 2026

## The Problem

On March 24, 2026, TeamPCP compromised LiteLLM's PyPI package (480M+ downloads). The malicious versions (1.82.7, 1.82.8) deployed credential stealers that harvested SSH keys, cloud tokens, and Kubernetes secrets — all triggered automatically on Python startup via a `.pth` file injection.

**Enterprises with auto-update bots installed this within minutes.**

PackageGuard is an autonomous AI agent that intercepts package installations, analyzes them in a sandboxed environment, and blocks malicious packages before they reach production.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   PackageGuard CLI                   │
│              (intercepts pip install)                │
└──────────────┬──────────────────────────┬────────────┘
               │                          │
       ┌───────▼────────┐        ┌────────▼──────────┐
       │  Security Agent │        │ Compat Agent      │
       │  (sandboxed)    │        │ (version resolver) │
       └───────┬────────┘        └────────┬──────────┘
               │                          │
    ┌──────────┼──────────┐              │
    │          │          │              │
┌───▼──┐ ┌────▼───┐ ┌────▼────┐  ┌─────▼──────┐
│Static│ │Dynamic │ │LLM Code │  │Dep Resolver│
│Scan  │ │Sandbox │ │Analysis │  │(pip/uv)    │
└──────┘ └────────┘ └─────────┘  └────────────┘
               │                          │
       ┌───────▼──────────────────────────▼────────────┐
       │              Overmind Tracing                  │
       │     (every LLM call traced + scored)          │
       └───────────────────────────────────────────────┘
               │
       ┌───────▼──────────┐
       │  Risk Report +   │
       │  Block/Allow     │
       └──────────────────┘
```

## Sponsor Integration

| Sponsor | How We Use It |
|---------|---------------|
| **AWS** | EC2/Lambda for sandbox compute, Bedrock for LLM fallback |
| **Overmind** | Trace every LLM call, get scoring on quality/cost/latency, optimize prompts |
| **Aerospike** | Cache scan results for known-safe package versions (SSD-optimized) |
| **TrueFoundry** | Deploy the agent as a production service |
| **Kiro** | Used for initial code planning |

## Quick Start

```bash
cd packageguard
docker-compose up --build
python -m packageguard scan litellm==1.82.8
python -m packageguard resolve requirements.txt --new-packages "sentence-transformers>=2.3"
```

## Project Structure

```
packageguard/
├── README.md
├── docker-compose.yml
├── Dockerfile.sandbox          # Isolated sandbox for dynamic analysis
├── Dockerfile.app              # Main application
├── pyproject.toml
├── packageguard/
│   ├── __init__.py
│   ├── main.py                 # CLI entrypoint
│   ├── config.py               # Settings + API keys
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py     # Main agent loop
│   │   ├── security_agent.py   # Security scanning agent
│   │   └── compat_agent.py     # Compatibility resolver agent
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── static_scan.py      # GuardDog + custom rules
│   │   ├── metadata_scan.py    # PyPI vs GitHub comparison
│   │   ├── dynamic_scan.py     # Docker sandbox execution
│   │   └── llm_scan.py         # LLM-based code analysis
│   ├── resolver/
│   │   ├── __init__.py
│   │   └── dependency_resolver.py
│   ├── tracing/
│   │   ├── __init__.py
│   │   └── overmind_tracer.py  # Overmind SDK integration
│   ├── cache/
│   │   ├── __init__.py
│   │   └── aerospike_cache.py  # Aerospike scan result cache
│   └── api/
│       ├── __init__.py
│       └── server.py           # FastAPI server for UI
├── frontend/                   # React UI (built last, 3:30+)
│   └── ...
├── tests/
│   ├── test_security_agent.py
│   └── test_compat_agent.py
├── docs/
│   ├── claude.md               # Instructions for Claude Code
│   ├── codex.md                # Instructions for Codex
│   └── architecture.md         # Shared architecture reference
└── demo/
    ├── demo_malicious_pkg/     # Fake malicious package for demo
    └── demo_script.py          # Demo runner
```
