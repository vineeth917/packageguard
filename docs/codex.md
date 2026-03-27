# Codex — Your Assignment

You are building the **dependency resolver, caching layer, API server, and frontend** for PackageGuard, an AI-powered supply chain security agent for Python packages.

**Read README.md and docs/architecture.md first.**

## Your Scope

You own: `packageguard/resolver/`, `packageguard/cache/`, `packageguard/api/`, `frontend/`, and `tests/`.

**DO NOT touch**: `packageguard/agents/`, `packageguard/scanners/`, `packageguard/tracing/`, `packageguard/main.py` — those belong to Claude Code.

## Priority Order (time-boxed)

### Phase 1: Resolver + Cache (11:30 - 1:30 PM) ⏰ 120 min

1. **`packageguard/resolver/dependency_resolver.py`** — Compatibility resolution agent:
   ```python
   class CompatAgent:
       async def resolve(
           self,
           existing_requirements: str,  # path to requirements.txt
           new_packages: list[str],     # e.g. ["sentence-transformers>=2.3", "faiss-gpu"]
           python_version: str = "3.10",
       ) -> CompatReport:
           """
           1. Parse existing requirements.txt
           2. Create isolated venv (use subprocess + venv or uv)
           3. Attempt to install existing + new packages
           4. If conflict:
              a. Use LLM to reason about which versions to try
              b. Search PyPI for compatible version ranges
              c. Retry with adjusted versions (max 5 attempts)
           5. If success: run basic import test for each package
           6. Return CompatReport with:
              - resolved_versions: dict[str, str]
              - conflicts: list[str]
              - suggestions: list[str]
              - status: "resolved" | "partial" | "failed"
           """
   ```

   Key implementation details:
   - Use `subprocess` to run `pip install --dry-run` or `uv pip compile` in isolated env
   - Parse pip's error output to identify conflicts
   - Use Claude Sonnet API to reason about version constraints when conflicts arise
   - Each resolution attempt should be traced with Overmind (import from tracing module)

2. **`packageguard/cache/aerospike_cache.py`** — Caching layer:
   ```python
   class PackageCache:
       def __init__(self, host="localhost", port=3000, namespace="packageguard"):
           # Connect to Aerospike
           # Fallback to in-memory dict if Aerospike unavailable

       async def get(self, package_name: str, version: str) -> Optional[ScanReport]:
           # Key: f"scan:{package_name}:{version}"
           # Returns cached ScanReport or None

       async def set(self, package_name: str, version: str, report: ScanReport, ttl: int = 86400):
           # Cache scan result with 24h TTL

       async def get_safe_versions(self, package_name: str) -> list[str]:
           # Key: f"safe:{package_name}"
           # Returns list of known-safe versions

       async def mark_safe(self, package_name: str, version: str):
           # Add version to safe list
   ```

   Aerospike-specific notes:
   - Use `aerospike` Python client
   - Namespace: `packageguard`, Set: `scans`
   - They use SSD-direct indexing — mention this in demo
   - Serialize ScanReport as JSON
   - If Aerospike is not running, gracefully fall back to in-memory dict with a warning

3. **`packageguard/api/server.py`** — FastAPI server:
   ```python
   from fastapi import FastAPI
   from packageguard.agents.orchestrator import PackageGuardOrchestrator

   app = FastAPI(title="PackageGuard API")

   @app.post("/scan")
   async def scan_package(package: str, version: str = None):
       # Run security scan, return ScanReport as JSON

   @app.post("/resolve")
   async def resolve_deps(requirements: UploadFile, new_packages: list[str]):
       # Run compatibility resolution, return CompatReport

   @app.get("/cache/{package_name}")
   async def get_cached(package_name: str):
       # Return cached scan results

   @app.get("/health")
   async def health():
       return {"status": "ok", "aerospike": cache.connected}
   ```

### Phase 2: Tests + Integration (1:30 - 2:30 PM) ⏰ 60 min

4. **`tests/test_security_agent.py`** — Test against the demo malicious package
5. **`tests/test_compat_agent.py`** — Test resolution with conflicting packages
6. Integration testing — make sure your code works with Claude Code's agents

### Phase 3: Frontend UI (3:30 - 4:15 PM) ⏰ 45 min

7. **`frontend/`** — React dashboard (LAST PRIORITY):
   - Single page app
   - Shows: scan results with risk score visualization, findings list, compat report
   - Color-coded: red (BLOCKED), yellow (WARNING), green (SAFE)
   - Timeline of the agent's decision-making steps
   - Keep it simple — use Tailwind, no complex state management
   - Can be a static HTML file with fetch calls to the API if React is too slow to set up

## Interface Contract with Claude Code's Code

Claude Code is building: agents, scanners, tracing, CLI. Here's what they expose to you:

```python
# Data models (shared, defined in packageguard/__init__.py)
@dataclass
class Finding:
    severity: str    # "critical", "high", "medium", "low", "info"
    category: str    # "pth_injection", "code_obfuscation", etc.
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""

@dataclass
class ScanReport:
    package_name: str
    version: str
    risk_score: int          # 0-100
    verdict: str             # "SAFE", "WARNING", "BLOCKED"
    findings: list[Finding]
    scan_duration: float     # seconds
    timestamp: str           # ISO format

@dataclass
class CompatReport:
    status: str              # "resolved", "partial", "failed"
    resolved_versions: dict  # {"pkg": "version"}
    conflicts: list[str]
    suggestions: list[str]
    attempts: int

# Orchestrator (Claude Code builds, you call in API)
from packageguard.agents.orchestrator import PackageGuardOrchestrator
orchestrator = PackageGuardOrchestrator()
report = await orchestrator.analyze(
    packages=["litellm==1.82.8"],
    existing_requirements="path/to/requirements.txt"
)
```

## Environment Setup

```bash
pip install fastapi uvicorn aerospike httpx anthropic
# For resolver
pip install uv  # or use pip subprocess
```

## Aerospike Integration Notes

- Aerospike excels at SSD-direct indexing — we use it to cache scan results
- Key pattern: `scan:{package}:{version}` for individual scans
- Key pattern: `safe:{package}` for known-safe version lists
- This means repeated scans of the same package version are instant
- In the demo, emphasize: "Once we've scanned a package, the result is cached in Aerospike's SSD-optimized store for sub-millisecond lookups"
