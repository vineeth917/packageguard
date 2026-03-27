"""Configuration for PackageGuard."""
import os
from pathlib import Path

# Load .env from project root
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_env_path)
except ImportError:
    pass


class Config:
    # LLM via OpenRouter
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    LLM_MODEL: str = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4")

    # Legacy Anthropic (fallback)
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    # Overmind (self-hosted at localhost)
    OVERMIND_API_KEY: str = os.getenv("OVERMIND_API_KEY", "")
    OVERMIND_BASE_URL: str = os.getenv("OVERMIND_API_URL", "http://localhost:8000")
    OVERMIND_ENABLED: bool = True  # Always try to connect to local instance

    # Aerospike
    AEROSPIKE_HOST: str = os.getenv("AEROSPIKE_HOST", "localhost")
    AEROSPIKE_PORT: int = int(os.getenv("AEROSPIKE_PORT", "3000"))
    AEROSPIKE_NAMESPACE: str = os.getenv("AEROSPIKE_NAMESPACE", "packageguard")

    # Sandbox
    SANDBOX_IMAGE: str = os.getenv("SANDBOX_IMAGE", "packageguard-sandbox:latest")
    SANDBOX_MEMORY_LIMIT: str = "512m"
    SANDBOX_CPU_LIMIT: float = 1.0
    SANDBOX_TIMEOUT: int = 60  # seconds

    # PyPI
    PYPI_API_URL: str = "https://pypi.org/pypi"

    # Scanning
    MAX_LLM_SCAN_FILES: int = 10
    CACHE_TTL: int = 86400  # 24 hours


config = Config()
