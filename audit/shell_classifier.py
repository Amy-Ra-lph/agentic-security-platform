#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Red Hat, Inc.
"""Classify shell commands by ATT&CK-aligned threat category for agentic AI audit logging."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Classification:
    command: str
    category: str
    severity: str
    matched_pattern: str
    technique_id: str


# ---------------------------------------------------------------------------
# Pattern definitions — ordered by priority (first match in highest-priority
# category wins).  Each entry: (compiled_regex, human label, ATT&CK ID).
# ---------------------------------------------------------------------------

_PatternEntry = tuple[re.Pattern[str], str, str]

def _compile(patterns: list[tuple[str, str, str]]) -> list[_PatternEntry]:
    return [(re.compile(p, re.IGNORECASE), label, tid) for p, label, tid in patterns]


EXFILTRATION: list[_PatternEntry] = _compile([
    # Data posted outbound
    (r"curl\s.*-[A-Za-z]*[XdFT]", "curl POST/upload", "T1048"),
    (r"wget\s+--post", "wget POST", "T1048"),
    # Reverse shells / raw network exfil
    (r"\bnc(?:at)?\s.*-[elp]", "netcat listener/connect", "T1048"),
    (r"/dev/tcp/", "bash /dev/tcp", "T1048"),
    # Base64 piped to network
    (r"base64.*\|\s*(?:curl|wget|nc|ncat)", "base64-to-net", "T1048"),
    (r"\|\s*base64.*\|\s*(?:curl|wget|nc)", "pipe-base64-net", "T1048"),
    # SCP/rsync to external
    (r"\bscp\s", "scp transfer", "T1048"),
    (r"\brsync\s.*:", "rsync to remote", "T1048"),
    # DNS tunneling
    (r"\bdig\s.*TXT\b", "dns TXT query (tunneling)", "T1048.003"),
    (r"\bnslookup\s", "nslookup (possible tunneling)", "T1048.003"),
])

CREDENTIAL_ACCESS: list[_PatternEntry] = _compile([
    (r"cat\s+/etc/shadow", "read /etc/shadow", "T1003.008"),
    (r"cat\s+.*\.keytab", "read keytab", "T1558"),
    (r"cat\s+.*\.pem\b", "read PEM file", "T1552.004"),
    (r"cat\s+.*\.key\b", "read private key", "T1552.004"),
    (r"cat\s+.*id_(?:rsa|ed25519|ecdsa|dsa)", "read SSH private key", "T1552.004"),
    (r"/proc/\d+/environ", "proc environ harvest", "T1552.003"),
    (r"/proc/\S+/mem\b", "proc memory read", "T1003"),
    (r"\bklist\b", "kerberos ticket list", "T1558"),
    (r"\bkdestroy\b", "kerberos ticket destroy", "T1558"),
    (r"cat\s+.*/gssproxy/", "gssproxy secrets", "T1552"),
    (r"cat\s+.*/sssd/", "sssd secrets", "T1552"),
    (r"\bstrings\s.*/proc/", "strings on proc (cred dump)", "T1003"),
    (r"grep\s.*password", "grep for passwords", "T1552.001"),
    (r"find\s.*-name\s.*\.(pem|key|keytab|p12|pfx)", "find credential files", "T1552.004"),
    (r"\bptrace\b", "ptrace attach", "T1003"),
    (r"\bgdb\s.*attach", "gdb attach (cred dump)", "T1003"),
])

PERSISTENCE: list[_PatternEntry] = _compile([
    (r"systemctl\s+(enable|link|mask)\s", "systemd unit manipulation", "T1543.002"),
    (r"cp\s.*\.service\b", "copy systemd unit file", "T1543.002"),
    (r"mv\s.*\.service\b", "move systemd unit file", "T1543.002"),
    (r"tee\s.*/systemd/", "write to systemd dir", "T1543.002"),
    (r"\bcrontab\s", "crontab modification", "T1053.003"),
    (r"echo\s.*>.*cron", "write to cron", "T1053.003"),
    (r"tee\s.*/cron", "write to cron dir", "T1053.003"),
    (r"echo\s.*>>.*\.bashrc", "modify .bashrc", "T1546.004"),
    (r"echo\s.*>>.*\.profile", "modify .profile", "T1546.004"),
    (r"echo\s.*>>.*\.bash_profile", "modify .bash_profile", "T1546.004"),
    (r"\bat\s+\d", "at job creation", "T1053.001"),
    (r"echo\s.*>>?\s*/etc/rc\.local", "modify rc.local", "T1037.004"),
    (r"echo\s.*>>?\s*/etc/rc\.d/", "modify rc.d", "T1037.004"),
])

PRIVILEGE_ESCALATION: list[_PatternEntry] = _compile([
    (r"\bsudo\s+(?!systemctl\s+status)(?!cat\s)(?!ls\s)", "sudo with suspicious args", "T1548.003"),
    (r"\bchmod\s+[ugo]*\+s\b", "chmod setuid/setgid", "T1548.001"),
    (r"\bchmod\s+4\d{3}\b", "chmod SUID numeric", "T1548.001"),
    (r"\bsetcap\b", "capability manipulation", "T1548"),
    (r"\bpkexec\b", "pkexec execution", "T1548.003"),
    (r"\bpolkit\b", "polkit interaction", "T1548.003"),
    (r"\bnewgrp\b", "newgrp privilege", "T1548"),
    (r"\bsu\s+-\s", "su to another user", "T1548.003"),
    (r"LD_PRELOAD=", "LD_PRELOAD injection", "T1574.006"),
    (r"LD_LIBRARY_PATH=.*[^a-zA-Z]", "LD_LIBRARY_PATH manipulation", "T1574.006"),
])

DEFENSE_EVASION: list[_PatternEntry] = _compile([
    (r"\bhistory\s+-c\b", "clear history", "T1070.003"),
    (r"unset\s+HISTFILE", "unset HISTFILE", "T1070.003"),
    (r"export\s+HISTFILE=/dev/null", "HISTFILE to /dev/null", "T1070.003"),
    (r"echo\s.*>\s*/var/log/", "overwrite log", "T1070.002"),
    (r"\btruncate\s.*log\b", "truncate log", "T1070.002"),
    (r">\s*/var/log/", "redirect clear log", "T1070.002"),
    (r"\bshred\s", "shred files", "T1070.004"),
    (r"\btouch\s+-[trd]", "timestomp", "T1070.006"),
    (r"\btimestomp\b", "timestomp tool", "T1070.006"),
    (r"exec\s+-a\s", "process name spoofing", "T1036.004"),
])

DISCOVERY: list[_PatternEntry] = _compile([
    (r"\bwhoami\b", "whoami", "T1033"),
    (r"\bid\b(?!\S)", "id command", "T1033"),
    (r"\buname\b", "uname", "T1082"),
    (r"\benv\b(?!\S)", "env dump", "T1082"),
    (r"cat\s+/etc/passwd", "read /etc/passwd", "T1087.001"),
    (r"\bifconfig\b", "ifconfig", "T1016"),
    (r"\bip\s+addr\b", "ip addr", "T1016"),
    (r"\bip\s+a\b(?!\S)", "ip a", "T1016"),
    (r"\bnetstat\b", "netstat", "T1049"),
    (r"\bss\s+-[a-z]*[tlunp]", "ss socket listing", "T1049"),
    (r"\bhostname\b", "hostname", "T1082"),
    (r"\bfind\s+/\s", "broad filesystem find", "T1083"),
    (r"\blsof\b", "list open files", "T1057"),
    (r"\bps\s+", "process listing", "T1057"),
    (r"\bw\b(?!\S)", "logged-in users", "T1033"),
    (r"\blast\b(?!\S)", "login history", "T1033"),
    (r"cat\s+/etc/os-release", "OS identification", "T1082"),
    (r"\blsblk\b", "list block devices", "T1082"),
    (r"\bdf\b(?!\S)", "disk usage", "T1082"),
    (r"\bfree\b(?!\S)", "memory info", "T1082"),
])


# Category priority order — highest threat first
_CATEGORIES: list[tuple[str, str, list[_PatternEntry]]] = [
    ("exfiltration",        "HIGH",   EXFILTRATION),
    ("credential_access",   "HIGH",   CREDENTIAL_ACCESS),
    ("persistence",         "HIGH",   PERSISTENCE),
    ("privilege_escalation", "HIGH",  PRIVILEGE_ESCALATION),
    ("defense_evasion",     "MEDIUM", DEFENSE_EVASION),
    ("discovery",           "LOW",    DISCOVERY),
]


# ---------------------------------------------------------------------------
# Classification API
# ---------------------------------------------------------------------------

def classify(command: str) -> Classification:
    """Classify a single shell command string."""
    cmd = command.strip()
    if not cmd:
        return Classification(
            command=command, category="routine", severity="NONE",
            matched_pattern="empty", technique_id="",
        )

    for category, severity, patterns in _CATEGORIES:
        for regex, label, technique_id in patterns:
            if regex.search(cmd):
                return Classification(
                    command=command,
                    category=category,
                    severity=severity,
                    matched_pattern=label,
                    technique_id=technique_id,
                )

    return Classification(
        command=command, category="routine", severity="NONE",
        matched_pattern="no match", technique_id="",
    )


def classify_log(commands: list[str]) -> list[Classification]:
    """Classify a batch of commands."""
    return [classify(cmd) for cmd in commands]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Classify shell commands by threat category")
    parser.add_argument("file", nargs="?", help="File with one command per line (default: stdin)")
    parser.add_argument("--min-severity", choices=["NONE", "LOW", "MEDIUM", "HIGH"],
                        default="NONE", help="Only show classifications at or above this severity")
    parser.add_argument("--compact", action="store_true", help="One-line-per-result output")
    args = parser.parse_args()

    severity_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    min_sev = severity_order[args.min_severity]

    source = open(args.file) if args.file else sys.stdin
    try:
        results = []
        for line in source:
            line = line.rstrip("\n")
            if not line:
                continue
            c = classify(line)
            if severity_order[c.severity] >= min_sev:
                results.append(c)
    finally:
        if args.file:
            source.close()

    if args.compact:
        for c in results:
            print(f"[{c.severity:6s}] {c.category:22s} {c.technique_id:12s} {c.matched_pattern:30s} | {c.command}")
    else:
        print(json.dumps([asdict(c) for c in results], indent=2))


if __name__ == "__main__":
    main()
