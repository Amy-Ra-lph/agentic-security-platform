# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Red Hat, Inc.
"""Tests for T1055 injection_detector."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from injection_detector import (
    Finding,
    ScanResult,
    check_active_ptrace,
    check_ld_preload_files,
    check_process_ld_preload,
    check_ptrace_scope,
    check_suspicious_libs,
    scan,
)


def _make_proc_pid(proc_root: Path, pid: int, comm: str = "test_proc",
                   environ: str = "", status: str = "", maps: str = ""):
    """Helper to create a fake /proc/<pid> directory."""
    pid_dir = proc_root / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / "comm").write_text(comm + "\n")
    if environ:
        (pid_dir / "environ").write_text(environ)
    if status:
        (pid_dir / "status").write_text(status)
    if maps:
        (pid_dir / "maps").write_text(maps)
    return pid_dir


class TestCleanSystem:
    def test_no_findings_on_clean_system(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        etc = tmp_path / "root"
        (etc / "etc").mkdir(parents=True)

        _make_proc_pid(proc, 1, comm="init",
                       status="Name:\tinit\nTracerPid:\t0\n",
                       maps="7f000000-7f001000 r-xp 00000 fd:01 123 /usr/lib64/libc.so.6\n")
        (proc / "sys" / "kernel" / "yama").mkdir(parents=True)
        (proc / "sys" / "kernel" / "yama" / "ptrace_scope").write_text("1\n")

        result = scan(proc_root=proc, etc_root=etc)
        assert len(result.findings) == 0

    def test_scan_result_json_format(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        etc = tmp_path / "root"
        (etc / "etc").mkdir(parents=True)
        (proc / "sys" / "kernel" / "yama").mkdir(parents=True)
        (proc / "sys" / "kernel" / "yama" / "ptrace_scope").write_text("2\n")

        result = scan(proc_root=proc, etc_root=etc)
        parsed = json.loads(result.to_json())
        assert isinstance(parsed, list)


class TestLdPreload:
    def test_ld_so_preload_with_entry(self, tmp_path):
        etc_root = tmp_path / "root"
        (etc_root / "etc").mkdir(parents=True)
        (etc_root / "etc" / "ld.so.preload").write_text("/tmp/evil.so\n")

        result = ScanResult()
        check_ld_preload_files(result, proc_root=etc_root)
        assert len(result.findings) == 1
        assert result.findings[0].type == "ld_preload"
        assert result.findings[0].severity == "high"
        assert "/tmp/evil.so" in result.findings[0].detail

    def test_ld_so_preload_ignores_system_paths(self, tmp_path):
        etc_root = tmp_path / "root"
        (etc_root / "etc").mkdir(parents=True)
        (etc_root / "etc" / "ld.so.preload").write_text(
            "/usr/lib64/nosync/nosync.so\n"
        )

        result = ScanResult()
        check_ld_preload_files(result, proc_root=etc_root)
        assert len(result.findings) == 0

    def test_ld_so_preload_ignores_comments(self, tmp_path):
        etc_root = tmp_path / "root"
        (etc_root / "etc").mkdir(parents=True)
        (etc_root / "etc" / "ld.so.preload").write_text(
            "# comment\n  \n"
        )

        result = ScanResult()
        check_ld_preload_files(result, proc_root=etc_root)
        assert len(result.findings) == 0

    def test_etc_environment_ld_preload(self, tmp_path):
        etc_root = tmp_path / "root"
        (etc_root / "etc").mkdir(parents=True)
        (etc_root / "etc" / "environment").write_text(
            'PATH="/usr/bin"\nLD_PRELOAD=/tmp/hook.so\n'
        )

        result = ScanResult()
        check_ld_preload_files(result, proc_root=etc_root)
        assert len(result.findings) == 1
        assert "LD_PRELOAD" in result.findings[0].detail

    def test_profile_d_ld_preload(self, tmp_path):
        etc_root = tmp_path / "root"
        profile_d = etc_root / "etc" / "profile.d"
        profile_d.mkdir(parents=True)
        (profile_d / "evil.sh").write_text(
            "export LD_PRELOAD=/opt/malware/inject.so\n"
        )

        result = ScanResult()
        check_ld_preload_files(result, proc_root=etc_root)
        assert len(result.findings) == 1
        assert "inject.so" in result.findings[0].detail

    def test_process_environ_ld_preload(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 42, comm="shady",
                       environ="HOME=/root\x00LD_PRELOAD=/tmp/hook.so\x00")

        result = ScanResult()
        check_process_ld_preload(result, proc_root=proc)
        assert len(result.findings) == 1
        assert result.findings[0].pid == 42
        assert result.findings[0].process == "shady"

    def test_process_environ_standard_lib_ignored(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 42, comm="normal",
                       environ="LD_PRELOAD=/usr/lib64/nosync/nosync.so\x00")

        result = ScanResult()
        check_process_ld_preload(result, proc_root=proc)
        assert len(result.findings) == 0


class TestPtraceScope:
    def test_ptrace_scope_zero_flags(self, tmp_path):
        proc = tmp_path / "proc"
        (proc / "sys" / "kernel" / "yama").mkdir(parents=True)
        (proc / "sys" / "kernel" / "yama" / "ptrace_scope").write_text("0\n")

        result = ScanResult()
        check_ptrace_scope(result, proc_root=proc)
        assert len(result.findings) == 1
        assert result.findings[0].type == "ptrace_scope"
        assert "ptrace_scope=0" in result.findings[0].detail

    def test_ptrace_scope_one_ok(self, tmp_path):
        proc = tmp_path / "proc"
        (proc / "sys" / "kernel" / "yama").mkdir(parents=True)
        (proc / "sys" / "kernel" / "yama" / "ptrace_scope").write_text("1\n")

        result = ScanResult()
        check_ptrace_scope(result, proc_root=proc)
        assert len(result.findings) == 0

    def test_ptrace_scope_missing_yama(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()

        result = ScanResult()
        check_ptrace_scope(result, proc_root=proc)
        assert len(result.findings) == 0
        assert any("ptrace_scope" in e for e in result.errors)


class TestActivePtrace:
    def test_active_ptrace_detected(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 100, comm="debugger",
                       status="Name:\tdebugger\nTracerPid:\t0\n")
        _make_proc_pid(proc, 200, comm="victim",
                       status="Name:\tvictim\nTracerPid:\t100\n")

        result = ScanResult()
        check_active_ptrace(result, proc_root=proc)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.type == "active_ptrace"
        assert f.severity == "high"
        assert f.pid == 200
        assert "100" in f.detail
        assert "debugger" in f.detail

    def test_no_ptrace_clean(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 1, comm="init",
                       status="Name:\tinit\nTracerPid:\t0\n")

        result = ScanResult()
        check_active_ptrace(result, proc_root=proc)
        assert len(result.findings) == 0


class TestSuspiciousLibs:
    def test_suspicious_lib_detected(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 50, comm="compromised",
                       maps="7f000000-7f001000 r-xp 00000 fd:01 123 /tmp/evil.so\n")

        result = ScanResult()
        check_suspicious_libs(result, proc_root=proc)
        assert len(result.findings) == 1
        assert "/tmp/evil.so" in result.findings[0].detail
        assert result.findings[0].pid == 50

    def test_standard_libs_ignored(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 50, comm="normal",
                       maps=(
                           "7f000000-7f001000 r-xp 00000 fd:01 123 /usr/lib64/libc.so.6\n"
                           "7f002000-7f003000 r-xp 00000 fd:01 124 /usr/lib/libm.so.6\n"
                           "7f004000-7f005000 r-xp 00000 fd:01 125 /lib64/ld-linux-x86-64.so.2\n"
                       ))

        result = ScanResult()
        check_suspicious_libs(result, proc_root=proc)
        assert len(result.findings) == 0

    def test_deduplicates_same_lib(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        _make_proc_pid(proc, 50, comm="app",
                       maps=(
                           "7f000000-7f001000 r-xp 00000 fd:01 123 /opt/inject.so\n"
                           "7f002000-7f003000 r--p 00000 fd:01 123 /opt/inject.so\n"
                       ))

        result = ScanResult()
        check_suspicious_libs(result, proc_root=proc)
        assert len(result.findings) == 1


class TestPermissionHandling:
    def test_unreadable_environ_skipped(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        pid_dir = proc / "1"
        pid_dir.mkdir()
        (pid_dir / "comm").write_text("secret\n")
        env_file = pid_dir / "environ"
        env_file.write_text("LD_PRELOAD=/tmp/evil.so")
        env_file.chmod(0o000)

        result = ScanResult()
        check_process_ld_preload(result, proc_root=proc)
        assert len(result.findings) == 0

        env_file.chmod(0o644)

    def test_unreadable_status_skipped(self, tmp_path):
        proc = tmp_path / "proc"
        proc.mkdir()
        pid_dir = proc / "1"
        pid_dir.mkdir()
        (pid_dir / "comm").write_text("secret\n")
        status_file = pid_dir / "status"
        status_file.write_text("Name:\tsecret\nTracerPid:\t999\n")
        status_file.chmod(0o000)

        result = ScanResult()
        check_active_ptrace(result, proc_root=proc)
        assert len(result.findings) == 0

        status_file.chmod(0o644)
