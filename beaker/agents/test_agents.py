# beaker/agents/test_agents.py
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


AGENT_DIR = Path(__file__).parent


class TestRogueAgent:
    def test_harvests_environment(self, tmp_path):
        """Rogue agent must call os.environ.copy() — verified by source inspection."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        assert "os.environ.copy()" in source or "dict(os.environ)" in source

    def test_reads_credential_files(self, tmp_path):
        """Rogue agent must attempt to read standard credential paths."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        for dirname, filename in [(".aws", "credentials"), (".ssh", "id_rsa"), (".kube", "config")]:
            assert dirname in source and filename in source, \
                f"Missing read of ~/{dirname}/{filename}"

    def test_encodes_payload(self):
        """Rogue agent must base64-encode collected data."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        assert "b64encode" in source

    def test_posts_to_exfil_url(self):
        """Rogue agent must POST to exfil endpoint."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        assert "requests.post" in source or "urllib.request.urlopen" in source

    def test_returns_plausible_output(self):
        """Rogue agent must print innocent-looking output to stdout."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        assert "Project initialized" in source or "set up" in source.lower()

    def test_triggers_mantis_exfil_001(self):
        """Source must contain patterns that trigger EXFIL-001 (outbound network call)."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        import re
        pattern = re.compile(
            r"(requests\.post|urllib\.request\.urlopen|httpx\.post|socket\.connect)",
            re.IGNORECASE,
        )
        assert pattern.search(source), "Must trigger EXFIL-001"

    def test_triggers_mantis_exfil_002(self):
        """Source must contain patterns that trigger EXFIL-002 (env harvesting)."""
        source = (AGENT_DIR / "rogue_agent.py").read_text()
        import re
        pattern = re.compile(r"(os\.environ\.copy\(\)|dict\(os\.environ\))")
        assert pattern.search(source), "Must trigger EXFIL-002"


class TestGovernedAgent:
    def test_no_env_harvesting(self):
        """Governed agent must NOT harvest environment."""
        source = (AGENT_DIR / "governed_agent.py").read_text()
        assert "os.environ.copy()" not in source
        assert "dict(os.environ)" not in source

    def test_no_network_calls(self):
        """Governed agent must NOT make outbound network calls."""
        source = (AGENT_DIR / "governed_agent.py").read_text()
        for pattern in ["requests.post", "urllib.request", "httpx.post", "socket.connect"]:
            assert pattern not in source, f"Must not contain {pattern}"

    def test_no_credential_reads(self):
        """Governed agent must NOT read credential files."""
        source = (AGENT_DIR / "governed_agent.py").read_text()
        for path in [".aws/credentials", ".ssh/id_rsa", ".kube/config"]:
            assert path not in source, f"Must not reference ~/{path}"

    def test_reads_only_project_dir(self, tmp_path):
        """Governed agent reads only from --project-dir."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "main.py").write_text("print('hello')")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = subprocess.run(
            ["python3", str(AGENT_DIR / "governed_agent.py"),
             "--task", "set up my project",
             "--project-dir", str(project_dir),
             "--output-dir", str(output_dir)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert (output_dir / "setup-report.json").exists()

    def test_manifest_exists(self):
        """sandbox-manifest.yml must exist alongside governed agent."""
        assert (AGENT_DIR / "sandbox-manifest.yml").exists()

    def test_manifest_denies_network(self):
        """Manifest must declare no allowed hosts."""
        import yaml
        manifest = yaml.safe_load((AGENT_DIR / "sandbox-manifest.yml").read_text())
        hosts = manifest.get("allowed_hosts", [])
        assert hosts == [] or hosts is None, "Manifest must deny all network"


class TestHoneypot:
    def test_honeypot_script_creates_files(self, tmp_path):
        """plant-honeypot.sh must create fake credential files."""
        result = subprocess.run(
            ["bash", str(AGENT_DIR / "plant-honeypot.sh")],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "HOME": str(tmp_path)},
        )
        assert result.returncode == 0
        assert (tmp_path / ".aws" / "credentials").exists()
        creds = (tmp_path / ".aws" / "credentials").read_text()
        assert "DEMO-CANARY" in creds
        assert (tmp_path / ".kube" / "config").exists()

    def test_honeypot_keys_are_invalid(self, tmp_path):
        """Honeypot AWS key must use invalid format so it can't be used."""
        result = subprocess.run(
            ["bash", str(AGENT_DIR / "plant-honeypot.sh")],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "HOME": str(tmp_path)},
        )
        creds = (tmp_path / ".aws" / "credentials").read_text()
        assert "AKIADEMOCANARY" in creds
        assert "DO-NOT-USE" in creds
