# Claude Code — Your Assignment

You are building the **core backend** of PackageGuard, an AI-powered supply chain security agent for Python packages.

**Read README.md and docs/architecture.md first.**

## Your Scope

You own: `packageguard/agents/`, `packageguard/scanners/`, `packageguard/tracing/`, `packageguard/main.py`, `packageguard/config.py`, `Dockerfile.sandbox`, `docker-compose.yml`, and `demo/`.

**DO NOT touch**: `packageguard/resolver/`, `packageguard/cache/`, `packageguard/api/`, `frontend/` — those belong to Codex.

## Priority Order (time-boxed)

### Phase 1: Core Scanning (11:30 - 1:00 PM) ⏰ 90 min
1. **`packageguard/config.py`** — Settings class with env vars for API keys (ANTHROPIC_API_KEY, OVERMIND_API_KEY, AEROSPIKE_HOST)
2. **`packageguard/scanners/static_scan.py`** — Static analysis scanner:
   - Check for `.pth` files in the package (the LiteLLM attack vector)
   - Check for base64-encoded exec/eval calls in setup.py and all .py files
   - Check for suspicious imports: subprocess, socket, http.client, urllib, requests in setup.py
   - Check for overridden install commands in setup.py
   - Check for obfuscated code patterns (double base64, XOR, zlib decompress)
   - Use AST parsing where possible, regex as fallback
   - Return a list of `Finding(severity, description, file, line)` objects
3. **`packageguard/scanners/metadata_scan.py`** — Metadata analysis:
   - Fetch package info from PyPI JSON API (`https://pypi.org/pypi/{pkg}/{version}/json`)
   - Check: does a matching GitHub tag/release exist?
   - Check: maintainer account age, number of prior releases
   - Check: was the package uploaded outside normal CI/CD (no GitHub Actions provenance)
   - Check: description present? License consistent?
   - Return list of `Finding` objects
4. **`packageguard/scanners/dynamic_scan.py`** — Sandbox execution:
   - Build and run a Docker container that installs the package
   - Monitor for: new `.pth` files created, outbound network connections, reads of sensitive paths (~/.ssh, ~/.aws, /etc/passwd, .env), excessive resource usage (fork bombs), new systemd services
   - Use `docker run --network=none --memory=512m --cpus=1` for isolation
   - Capture stdout/stderr and exit code
   - Return list of `Finding` objects
5. **`packageguard/scanners/llm_scan.py`** — LLM code review:
   - Extract setup.py, __init__.py, and any .pth files from the package
   - Send to Claude Sonnet API with a system prompt asking to identify malicious patterns
   - Parse response into Finding objects
   - **Wrap this call with Overmind tracing** (see tracing section)

### Phase 2: Agent Orchestration (1:00 - 2:00 PM) ⏰ 60 min
6. **`packageguard/agents/security_agent.py`** — The main security scanning agent:
   ```python
   class SecurityAgent:
       async def scan(self, package_name: str, version: str = None) -> ScanReport:
           # 1. Download package to temp dir
           # 2. Run static_scan
           # 3. Run metadata_scan
           # 4. Run dynamic_scan (in Docker)
           # 5. Run llm_scan on suspicious files
           # 6. Aggregate findings, compute risk score (0-100)
           # 7. Return ScanReport with verdict: SAFE / WARNING / BLOCKED
   ```
7. **`packageguard/agents/orchestrator.py`** — Top-level orchestrator:
   ```python
   class PackageGuardOrchestrator:
       async def analyze(self, packages: list[str], existing_requirements: str = None):
           # For each package:
           #   1. Check Aerospike cache first (call cache module)
           #   2. Run SecurityAgent.scan()
           #   3. If safe and existing_requirements provided, run CompatAgent (call resolver module)
           #   4. Cache results
           #   5. Return final report
   ```
8. **`packageguard/main.py`** — CLI entrypoint:
   ```
   packageguard scan <package>==<version>      # Security scan
   packageguard resolve <requirements.txt> --new <pkg1> <pkg2>  # Compat check
   packageguard guard --watch <requirements.txt>  # Continuous monitoring
   ```

### Phase 3: Overmind + Demo (2:00 - 3:00 PM) ⏰ 60 min
9. **`packageguard/tracing/overmind_tracer.py`**:
   - Wrap all LLM calls with Overmind SDK tracing
   - Record: input prompt, output, tokens used, latency, cost
   - Tag traces with: agent_name, scan_type, package_name
   - This is critical for the Overmind prize
10. **`demo/demo_malicious_pkg/`** — Create a fake malicious package for demo:
    - A package called `demo-litellm-evil` that mimics the attack patterns:
      - Has a `.pth` file
      - Has base64-encoded payload in setup.py
      - Tries to read ~/.ssh/id_rsa (but harmlessly, just logs it)
      - Makes an outbound HTTP call to a dummy endpoint
    - This is for DEMO ONLY — it should be obviously harmless but trigger all our detectors
11. **`demo/demo_script.py`** — End-to-end demo script showing the full flow
12. **`Dockerfile.sandbox`** and **`docker-compose.yml`**

## Key Technical Decisions

- Use `httpx` for async HTTP (PyPI API, GitHub API)
- Use `docker` Python SDK for sandbox management
- Use Anthropic Python SDK for LLM calls
- All scanners return `list[Finding]` where:
  ```python
  @dataclass
  class Finding:
      severity: str  # "critical", "high", "medium", "low", "info"
      category: str  # "pth_injection", "code_obfuscation", "credential_theft", etc.
      description: str
      file: str = ""
      line: int = 0
      evidence: str = ""  # code snippet or data
  ```
- Risk score formula: critical=40pts, high=25pts, medium=10pts, low=3pts, capped at 100
- BLOCKED if score >= 70, WARNING if >= 30, SAFE if < 30

## Overmind Integration Pattern

```python
from overmind import Overmind

om = Overmind(api_key=config.OVERMIND_API_KEY)

# Wrap every LLM call
with om.trace("security_agent.llm_scan", metadata={"package": pkg_name}) as span:
    response = anthropic_client.messages.create(
        model="claude-sonnet-4-20250514",
        messages=[...],
    )
    span.set_output(response.content[0].text)
    span.set_tokens(response.usage.input_tokens, response.usage.output_tokens)
```

If Overmind SDK isn't available yet, create a mock tracer with the same interface so we can swap in later.

## Interface Contract with Codex's Code

Codex is building: resolver, cache, and API server. Here's how you interact:

```python
# Cache (Codex builds this, you call it)
from packageguard.cache.aerospike_cache import PackageCache
cache = PackageCache()
cached = await cache.get(package_name, version)  # Returns ScanReport or None
await cache.set(package_name, version, report)    # Stores ScanReport

# Resolver (Codex builds this, you call it)
from packageguard.resolver.dependency_resolver import CompatAgent
compat = CompatAgent()
result = await compat.resolve(
    existing_requirements="requirements.txt",
    new_packages=["sentence-transformers>=2.3"],
)  # Returns CompatReport

# API (Codex builds this, it calls your orchestrator)
# Codex will import PackageGuardOrchestrator and call analyze()
```

## Environment Setup

```bash
# In the project root
pip install anthropic httpx docker pyyaml click rich
# GuardDog for static analysis boost
pip install guarddog
```
