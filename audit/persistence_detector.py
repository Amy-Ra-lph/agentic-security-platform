#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Red Hat, Inc.
"""Detect unauthorized persistence mechanisms on Linux (ATT&CK T1037/T1547).

Read-only scanner — identifies systemd units, cron jobs, rc.local scripts,
autostart entries, shell profile modifications, and at jobs that are not
owned by an installed RPM package.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Finding:
    technique_id: str
    type: str
    path: str
    severity: str
    detail: str
    package_owned: bool = False


SUSPICIOUS_PATTERNS = re.compile(
    r"(?:"
    r"base64\s+(?:-d|--decode)"
    r"|curl\s+.*\|\s*(?:ba)?sh"
    r"|wget\s+.*\|\s*(?:ba)?sh"
    r"|nohup\s+.*&\s*$"
    r"|/dev/tcp/"
    r"|nc\s+-[elp]"
    r"|python[23]?\s+-c\s+.*(?:socket|subprocess|exec|eval)"
    r"|perl\s+-e\s+.*(?:socket|exec)"
    r"|mkfifo"
    r"|exec\s+\d+<>/dev/tcp"
    r"|\\x[0-9a-fA-F]{2}"
    r")",
    re.MULTILINE,
)


def is_package_owned(path: str) -> bool:
    """Check if a file is owned by an installed RPM package."""
    try:
        result = subprocess.run(
            ["rpm", "-qf", path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and "not owned" not in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _resolve(root: Path, absolute: str) -> Path:
    """Map an absolute path under an optional chroot-style root."""
    return root / absolute.lstrip("/")


def scan_systemd_units(home: Path, root: Path = Path("/")) -> list[Finding]:
    findings = []
    dirs = [
        _resolve(root, "/etc/systemd/system"),
        _resolve(root, "/run/systemd/system"),
        home / ".config" / "systemd" / "user",
    ]

    for d in dirs:
        if not d.exists():
            continue
        for f in d.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix not in (".service", ".timer", ".socket", ".path", ".mount", ".target", ".slice"):
                continue
            if f.is_symlink():
                target = str(f.resolve())
                if target.startswith("/usr/lib/systemd") or target.startswith("/lib/systemd"):
                    continue
            owned = is_package_owned(str(f))
            if not owned:
                findings.append(Finding(
                    technique_id="T1547",
                    type="systemd",
                    path=str(f),
                    severity="high",
                    detail=f"Non-package systemd unit: {f.name}",
                    package_owned=False,
                ))
    return findings


def scan_cron(root: Path = Path("/")) -> list[Finding]:
    findings = []
    cron_dirs = [
        _resolve(root, "/etc/cron.d"),
        _resolve(root, "/etc/cron.daily"),
        _resolve(root, "/etc/cron.hourly"),
        _resolve(root, "/etc/cron.weekly"),
        _resolve(root, "/etc/cron.monthly"),
        _resolve(root, "/var/spool/cron"),
    ]
    cron_files = [_resolve(root, "/etc/crontab")]

    for d in cron_dirs:
        if not d.exists():
            continue
        for f in d.iterdir():
            if not f.is_file():
                continue
            owned = is_package_owned(str(f))
            if not owned:
                findings.append(Finding(
                    technique_id="T1037",
                    type="cron",
                    path=str(f),
                    severity="medium",
                    detail=f"Non-package cron entry: {f.name}",
                    package_owned=False,
                ))

    for f in cron_files:
        if f.exists() and f.is_file():
            owned = is_package_owned(str(f))
            if not owned:
                findings.append(Finding(
                    technique_id="T1037",
                    type="cron",
                    path=str(f),
                    severity="medium",
                    detail=f"Non-package crontab: {f.name}",
                    package_owned=False,
                ))
    return findings


def scan_rc_local(root: Path = Path("/")) -> list[Finding]:
    findings = []
    rc_paths = [
        _resolve(root, "/etc/rc.local"),
        _resolve(root, "/etc/rc.d/rc.local"),
    ]

    for rc in rc_paths:
        if not rc.exists() or not rc.is_file():
            continue
        if os.access(str(rc), os.X_OK):
            try:
                content = rc.read_text(errors="replace")
            except OSError:
                continue
            non_comment = [
                line for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if non_comment:
                findings.append(Finding(
                    technique_id="T1037",
                    type="rc_local",
                    path=str(rc),
                    severity="high",
                    detail=f"Executable rc.local with {len(non_comment)} active lines",
                    package_owned=is_package_owned(str(rc)),
                ))
    return findings


def scan_autostart(home: Path, root: Path = Path("/")) -> list[Finding]:
    findings = []
    dirs = [
        _resolve(root, "/etc/xdg/autostart"),
        home / ".config" / "autostart",
    ]

    for d in dirs:
        if not d.exists():
            continue
        for f in d.iterdir():
            if not f.is_file() or f.suffix != ".desktop":
                continue
            owned = is_package_owned(str(f))
            if not owned:
                findings.append(Finding(
                    technique_id="T1547",
                    type="autostart",
                    path=str(f),
                    severity="medium",
                    detail=f"Non-package autostart entry: {f.name}",
                    package_owned=False,
                ))
    return findings


def scan_shell_profiles(home: Path, root: Path = Path("/")) -> list[Finding]:
    findings = []

    profile_dir = _resolve(root, "/etc/profile.d")
    if profile_dir.exists():
        for f in profile_dir.iterdir():
            if not f.is_file():
                continue
            owned = is_package_owned(str(f))
            if not owned:
                findings.append(Finding(
                    technique_id="T1037",
                    type="shell_profile",
                    path=str(f),
                    severity="medium",
                    detail=f"Non-package profile script: {f.name}",
                    package_owned=False,
                ))

    user_files = [
        home / ".bashrc",
        home / ".bash_profile",
        home / ".profile",
        home / ".zshrc",
    ]
    for f in user_files:
        if not f.exists() or not f.is_file():
            continue
        try:
            content = f.read_text(errors="replace")
        except OSError:
            continue
        matches = SUSPICIOUS_PATTERNS.findall(content)
        if matches:
            findings.append(Finding(
                technique_id="T1037",
                type="shell_profile",
                path=str(f),
                severity="high",
                detail=f"Suspicious pattern in {f.name}: {matches[0][:80]}",
                package_owned=False,
            ))
    return findings


def scan_at_jobs(root: Path = Path("/")) -> list[Finding]:
    findings = []
    at_dir = _resolve(root, "/var/spool/at")
    if not at_dir.exists():
        return findings
    for f in at_dir.iterdir():
        if not f.is_file():
            continue
        if f.name.startswith(".") or f.name == "spool":
            continue
        findings.append(Finding(
            technique_id="T1037",
            type="at_job",
            path=str(f),
            severity="medium",
            detail=f"Pending at job: {f.name}",
            package_owned=False,
        ))
    return findings


def run_scan(home: Path | None = None, root: Path = Path("/")) -> list[Finding]:
    if home is None:
        home = Path.home()
    findings = []
    findings.extend(scan_systemd_units(home, root))
    findings.extend(scan_cron(root))
    findings.extend(scan_rc_local(root))
    findings.extend(scan_autostart(home, root))
    findings.extend(scan_shell_profiles(home, root))
    findings.extend(scan_at_jobs(root))
    return findings


def format_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No unauthorized persistence mechanisms detected."

    by_type: dict[str, list[Finding]] = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f.severity] += 1

    lines = [f"Persistence scan: {len(findings)} findings\n"]
    for sev in ("high", "medium", "low"):
        if severity_counts[sev]:
            lines.append(f"  {sev.upper()}: {severity_counts[sev]}")
    lines.append("")

    for typ, items in sorted(by_type.items()):
        lines.append(f"  [{typ}] ({len(items)})")
        for f in items:
            marker = "!" if f.severity == "high" else "-"
            lines.append(f"    {marker} {f.path}")
            lines.append(f"      {f.detail}")
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect unauthorized persistence mechanisms (ATT&CK T1037/T1547)"
    )
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output findings as JSON array")
    parser.add_argument("--summary", action="store_true",
                        help="Output human-readable summary (default)")
    parser.add_argument("--home", type=Path, default=None,
                        help="Home directory to scan (default: current user)")
    parser.add_argument("--root", type=Path, default=Path("/"),
                        help="Root directory for system paths (default: /)")
    args = parser.parse_args(argv)

    findings = run_scan(home=args.home, root=args.root)

    if args.json_output:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(format_summary(findings))

    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
