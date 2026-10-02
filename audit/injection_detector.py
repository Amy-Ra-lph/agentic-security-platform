#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Red Hat, Inc.
"""T1055 Process Injection detector for Linux.

Checks: LD_PRELOAD hijack, ptrace scope, active ptrace,
suspicious shared libraries in /proc/*/maps.
"""

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path


STANDARD_LIB_DIRS = frozenset({
    "/usr/lib", "/usr/lib64", "/lib", "/lib64",
    "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
    "/usr/libexec",
})

SYSTEM_PRELOAD_PATHS = frozenset({
    "/usr/lib64/nosync/nosync.so",
    "/usr/lib/nosync/nosync.so",
})


@dataclass
class Finding:
    technique_id: str = "T1055"
    type: str = ""
    severity: str = "medium"
    detail: str = ""
    pid: int | None = None
    process: str | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_pids: int = 0
    is_root: bool = False

    def to_json(self) -> str:
        return json.dumps([asdict(f) for f in self.findings], indent=2)


def _read_file(path: Path) -> str | None:
    try:
        return path.read_text()
    except PermissionError:
        return None
    except (OSError, ValueError):
        return None


def _get_process_name(proc_dir: Path) -> str:
    comm = _read_file(proc_dir / "comm")
    return comm.strip() if comm else "unknown"


def _is_standard_lib(lib_path: str) -> bool:
    for d in STANDARD_LIB_DIRS:
        if lib_path.startswith(d + "/"):
            return True
    return False


def check_ld_preload_files(result: ScanResult, proc_root: Path = Path("/")):
    """Check /etc/ld.so.preload and /etc/environment for LD_PRELOAD."""
    etc = proc_root / "etc"

    preload_file = etc / "ld.so.preload"
    content = _read_file(preload_file)
    if content:
        for line in content.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                if line not in SYSTEM_PRELOAD_PATHS:
                    result.findings.append(Finding(
                        type="ld_preload",
                        severity="high",
                        detail=f"/etc/ld.so.preload contains: {line}",
                    ))

    env_file = etc / "environment"
    content = _read_file(env_file)
    if content:
        for line in content.splitlines():
            if re.match(r"^\s*LD_PRELOAD\s*=", line):
                result.findings.append(Finding(
                    type="ld_preload",
                    severity="high",
                    detail=f"/etc/environment sets LD_PRELOAD: {line.strip()}",
                ))

    profile_d = etc / "profile.d"
    if profile_d.is_dir():
        try:
            for f in sorted(profile_d.iterdir()):
                content = _read_file(f)
                if content and "LD_PRELOAD" in content:
                    for line in content.splitlines():
                        if re.search(r"(export\s+)?LD_PRELOAD\s*=", line):
                            result.findings.append(Finding(
                                type="ld_preload",
                                severity="high",
                                detail=f"{f} sets LD_PRELOAD: {line.strip()}",
                            ))
        except PermissionError:
            result.errors.append(f"Permission denied: {profile_d}")


def check_process_ld_preload(result: ScanResult, proc_root: Path = Path("/proc")):
    """Check running processes' environ for LD_PRELOAD."""
    for proc_dir in _iter_proc_dirs(proc_root):
        pid = int(proc_dir.name)
        environ_file = proc_dir / "environ"
        content = _read_file(environ_file)
        if content is None:
            continue
        env_vars = content.split("\x00")
        for var in env_vars:
            if var.startswith("LD_PRELOAD="):
                value = var.split("=", 1)[1]
                for lib in value.split(":"):
                    lib = lib.strip()
                    if lib and not _is_standard_lib(lib) and lib not in SYSTEM_PRELOAD_PATHS:
                        name = _get_process_name(proc_dir)
                        result.findings.append(Finding(
                            type="ld_preload",
                            severity="high",
                            detail=f"Process has LD_PRELOAD={lib}",
                            pid=pid,
                            process=name,
                        ))


def check_ptrace_scope(result: ScanResult, proc_root: Path = Path("/proc")):
    """Check Yama ptrace_scope setting."""
    ptrace_path = proc_root / "sys" / "kernel" / "yama" / "ptrace_scope"
    content = _read_file(ptrace_path)
    if content is None:
        result.errors.append("Cannot read ptrace_scope (Yama LSM may not be enabled)")
        return
    scope = content.strip()
    if scope == "0":
        result.findings.append(Finding(
            type="ptrace_scope",
            severity="medium",
            detail="ptrace_scope=0: any process can ptrace any other (unhardened)",
        ))


def check_active_ptrace(result: ScanResult, proc_root: Path = Path("/proc")):
    """Scan for processes being actively ptraced."""
    for proc_dir in _iter_proc_dirs(proc_root):
        pid = int(proc_dir.name)
        status = _read_file(proc_dir / "status")
        if status is None:
            continue
        for line in status.splitlines():
            if line.startswith("TracerPid:"):
                tracer_pid = int(line.split(":", 1)[1].strip())
                if tracer_pid != 0:
                    name = _get_process_name(proc_dir)
                    tracer_name = "unknown"
                    tracer_dir = proc_root / str(tracer_pid)
                    if tracer_dir.is_dir():
                        tracer_name = _get_process_name(tracer_dir)
                    result.findings.append(Finding(
                        type="active_ptrace",
                        severity="high",
                        detail=f"PID {pid} ({name}) is being ptraced by PID {tracer_pid} ({tracer_name})",
                        pid=pid,
                        process=name,
                    ))
                break


def check_suspicious_libs(result: ScanResult, proc_root: Path = Path("/proc")):
    """Scan /proc/*/maps for shared libraries outside standard paths."""
    so_pattern = re.compile(r"^\S+\s+r[x-][xp-][sp-]\s+\S+\s+\S+\s+\d+\s+(/\S+\.so\S*)")
    for proc_dir in _iter_proc_dirs(proc_root):
        pid = int(proc_dir.name)
        maps_content = _read_file(proc_dir / "maps")
        if maps_content is None:
            continue
        seen = set()
        for line in maps_content.splitlines():
            m = so_pattern.match(line)
            if m:
                lib_path = m.group(1)
                if lib_path in seen:
                    continue
                seen.add(lib_path)
                if not _is_standard_lib(lib_path):
                    name = _get_process_name(proc_dir)
                    result.findings.append(Finding(
                        type="suspicious_lib",
                        severity="low",
                        detail=f"Non-standard library loaded: {lib_path}",
                        pid=pid,
                        process=name,
                    ))
        result.scanned_pids += 1


def _iter_proc_dirs(proc_root: Path):
    """Yield /proc/<pid> directories for numeric PIDs."""
    try:
        for entry in proc_root.iterdir():
            if entry.name.isdigit() and entry.is_dir():
                yield entry
    except PermissionError:
        pass


def scan(proc_root: Path = Path("/proc"), etc_root: Path = Path("/")) -> ScanResult:
    """Run all injection detection checks."""
    result = ScanResult(is_root=(os.geteuid() == 0))
    if not result.is_root:
        result.errors.append("Running as non-root — some /proc entries may be inaccessible")

    check_ld_preload_files(result, proc_root=etc_root)
    check_process_ld_preload(result, proc_root=proc_root)
    check_ptrace_scope(result, proc_root=proc_root)
    check_active_ptrace(result, proc_root=proc_root)
    check_suspicious_libs(result, proc_root=proc_root)

    return result


def main():
    result = scan()
    print(result.to_json())
    if result.errors:
        for err in result.errors:
            print(f"WARNING: {err}", file=sys.stderr)
    sys.exit(1 if any(f.severity == "high" for f in result.findings) else 0)


if __name__ == "__main__":
    main()
