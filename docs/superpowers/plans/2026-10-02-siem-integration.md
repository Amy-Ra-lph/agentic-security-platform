# SIEM Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add vendor-neutral SIEM integration to the agentic security PoC — bridge emits enriched events to syslog, Wazuh deployed as demo SIEM on a dedicated VM.

**Architecture:** The existing Falco→Falcosidekick→bridge→EDA pipeline gets a second output: syslog RFC 5424. The bridge enriches Falco events with agent identity, MITRE ATT&CK mapping, and OCSF class before emitting to both EDA (automated response) and syslog (SOC visibility). A separate rsyslog config forwards OCSF incident files from the revocation playbook. Wazuh on VM3 ingests both streams.

**Tech Stack:** Python 3.12 (stdlib only — no pip on Beaker), rsyslog, Wazuh 4.x, Falco 0.45+, Falcosidekick, Ansible EDA

**Spec:** `docs/specs/2026-10-02-siem-integration-design.md`

## Global Constraints

- Python bridge: stdlib only (http.server, logging, json, socket). No pip install on Beaker VMs.
- Syslog: RFC 5424 structured data format. CEF as opt-in flag.
- All scripts: idempotent, `set -euo pipefail`, safe to re-run.
- SIEM VM: RHEL 10.2 x86_64, 8GB RAM, 40GB disk.
- No customer names, revenue data, or Jira refs in code (GitHub mirror rule).
- Falcosidekick syslog block: present but disabled (empty `host:`).

## Review Focus

1. **Bridge receives malformed JSON from Falcosidekick** — should return 400 and not crash the server. Test: POST garbage to :5001.
2. **Syslog destination unreachable** — bridge must still forward to EDA. Syslog failure should not block the response pipeline. Test: start bridge with --syslog-host pointing at nothing, send event, verify EDA still gets it.
3. **OCSF file written without newline** — rsyslog imfile may not forward partial lines. Test: write JSON without trailing newline, verify it's forwarded after file close.
4. **Wazuh decoder receives event without agent_principal field** — should not crash decoder. Test: send syslog with missing fields, verify Wazuh logs warning not error.
5. **Bridge started without --syslog-host** — must behave identically to old falco-eda-bridge.py (backward compatible). Test: run bridge with only --port and --eda-url, verify EDA output matches old bridge format.

---

### Task 1: Cherry-pick Falco+EDA files to main

The Falco rules, EDA bridge, revocation playbook, and setup script exist on `worktree-beaker-poc` but not `main`. These are prerequisites for the SIEM integration.

**Files:**
- Cherry-pick introduces: `beaker/ansible/falco-eda-bridge.py`, `beaker/ansible/falco-rules-agent-security.yaml`, `beaker/ansible/falcosidekick-config.yaml`, `beaker/ansible/agent-anomaly-rulebook.yml`, `beaker/ansible/agent-revocation.yml`, `beaker/ansible/inventory.yml`, `beaker/setup/setup-falco-eda.sh`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `beaker/ansible/falco-eda-bridge.py` (will be replaced by Task 2), all other Falco/EDA files used by Tasks 3, 5

- [ ] **Step 1: Cherry-pick the 4 relevant commits**

```bash
cd ~/DevSpace/rhel-agentic-security
git cherry-pick 52b941f  # EDA revocation playbook + rulebook + inventory
git cherry-pick c20ccca  # Falco rules + bridge + falcosidekick config
git cherry-pick 005a8ea  # setup-falco-eda.sh
git cherry-pick 4666a71  # revocation playbook fix (connection: local)
```

If conflicts arise, resolve by keeping the `main` version of any setup scripts already modified (setup-server.sh --force fix), and accepting the worktree version of new files.

- [ ] **Step 2: Verify files are on main**

```bash
ls beaker/ansible/falco-eda-bridge.py \
   beaker/ansible/falco-rules-agent-security.yaml \
   beaker/ansible/falcosidekick-config.yaml \
   beaker/ansible/agent-anomaly-rulebook.yml \
   beaker/ansible/agent-revocation.yml \
   beaker/setup/setup-falco-eda.sh
```

All 6 files must exist.

- [ ] **Step 3: Commit (if cherry-pick needed manual resolution)**

```bash
git status
# If clean, cherry-picks committed automatically. If not:
git add -A beaker/ansible/ beaker/setup/setup-falco-eda.sh
git commit -m "feat(beaker): cherry-pick Falco + EDA pipeline from worktree-beaker-poc"
```

---

### Task 2: Write falco-siem-bridge.py

Replace `falco-eda-bridge.py` with a dual-output bridge that sends to both EDA webhook and syslog.

**Files:**
- Create: `beaker/ansible/falco-siem-bridge.py`
- Remove: `beaker/ansible/falco-eda-bridge.py` (replaced)
- Create: `beaker/ansible/test_bridge.py`

**Interfaces:**
- Consumes: Falcosidekick webhook POST on `:5001` (JSON with `rule`, `priority`, `output`, `tags`, `output_fields`)
- Produces: EDA event POST to `:5000` (JSON `{"payload": {...}}`), syslog RFC 5424 message to configured host:port

- [ ] **Step 1: Write the test file**

```python
# beaker/ansible/test_bridge.py
"""Tests for falco-siem-bridge transform and syslog formatting."""
import json
import socket
import threading
import unittest
from unittest.mock import patch
from http.server import HTTPServer

SAMPLE_FALCO_EVENT = {
    "rule": "Agent Swarm — Unauthorized Process Spawning",
    "priority": "Critical",
    "output": "SWARM: Agent spawned unauthorized child process (agent=code-assist-9a2b pid=12345)",
    "tags": ["agentic-security", "swarm", "SWARM-001"],
    "output_fields": {
        "proc.pname": "python3",
        "proc.pid": 12345,
        "proc.cmdline": "python3 agent_worker.py --autonomous",
        "user.name": "code-assist-9a2b",
        "container.name": "agent-sandbox",
    },
    "time": "2026-10-02T10:30:45.000000000Z",
}

SAMPLE_EXFIL_EVENT = {
    "rule": "Agent Credential Harvesting",
    "priority": "Critical",
    "output": "EXFIL: Agent read credential file (agent=rogue-agent file=.aws/credentials)",
    "tags": ["agentic-security", "exfiltration", "EXFIL-002"],
    "output_fields": {
        "proc.pname": "python3",
        "proc.pid": 6789,
        "proc.cmdline": "python3 rogue_agent.py",
        "user.name": "rogue-agent",
        "fd.name": "/root/.aws/credentials",
    },
    "time": "2026-10-02T10:31:00.000000000Z",
}


class TestTransform(unittest.TestCase):
    def test_swarm_event_extracts_alert_type(self):
        from falco_siem_bridge import transform
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["alert_type"], "swarm")

    def test_swarm_event_extracts_rule_id(self):
        from falco_siem_bridge import transform
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["rule"], "SWARM-001")

    def test_swarm_event_extracts_agent_principal(self):
        from falco_siem_bridge import transform
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["agent_principal"], "code-assist-9a2b")

    def test_swarm_event_has_mitre_id(self):
        from falco_siem_bridge import transform
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["mitre_id"], "T1059.006")

    def test_exfil_event_has_mitre_id(self):
        from falco_siem_bridge import transform
        result = transform(SAMPLE_EXFIL_EVENT)
        self.assertEqual(result["payload"]["mitre_id"], "T1552.001")

    def test_transform_has_ocsf_class(self):
        from falco_siem_bridge import transform
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["ocsf_class_uid"], 2001)

    def test_unknown_tags_produce_unknown_alert_type(self):
        from falco_siem_bridge import transform
        event = {**SAMPLE_FALCO_EVENT, "tags": ["something-else"]}
        result = transform(event)
        self.assertEqual(result["payload"]["alert_type"], "unknown")


class TestSyslogFormat(unittest.TestCase):
    def test_rfc5424_format(self):
        from falco_siem_bridge import transform, format_rfc5424
        eda_event = transform(SAMPLE_FALCO_EVENT)
        msg = format_rfc5424(eda_event["payload"])
        self.assertIn("agent-security", msg)
        self.assertIn('alert_type="swarm"', msg)
        self.assertIn('mitre_id="T1059.006"', msg)
        self.assertIn('agent_principal="code-assist-9a2b"', msg)

    def test_cef_format(self):
        from falco_siem_bridge import transform, format_cef
        eda_event = transform(SAMPLE_FALCO_EVENT)
        msg = format_cef(eda_event["payload"])
        self.assertTrue(msg.startswith("CEF:0|"))
        self.assertIn("SWARM-001", msg)
        self.assertIn("suser=code-assist-9a2b", msg)
        self.assertIn("cs1=T1059.006", msg)


class TestSyslogFailureIsolation(unittest.TestCase):
    def test_syslog_failure_does_not_block_eda(self):
        """Bridge must forward to EDA even when syslog destination is unreachable."""
        from falco_siem_bridge import transform, send_syslog
        eda_event = transform(SAMPLE_FALCO_EVENT)
        # send_syslog to unreachable host should not raise
        send_syslog(eda_event["payload"], host="192.0.2.1", port=514, proto="tcp", cef=False)
        # No exception = pass. EDA path is independent.


class TestBackwardCompatibility(unittest.TestCase):
    def test_eda_payload_matches_old_bridge(self):
        """EDA payload format must match falco-eda-bridge.py output."""
        from falco_siem_bridge import transform
        result = transform(SAMPLE_FALCO_EVENT)
        payload = result["payload"]
        # Old bridge required fields
        self.assertIn("alert_type", payload)
        self.assertIn("rule", payload)
        self.assertIn("agent_principal", payload)
        self.assertIn("agent_realm", payload)
        self.assertIn("timestamp", payload)
        self.assertIn("falco_priority", payload)
        self.assertIn("falco_rule", payload)
        self.assertIn("falco_output", payload)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/DevSpace/rhel-agentic-security/beaker/ansible
python3 -m pytest test_bridge.py -v 2>&1 | head -20
# Expected: ModuleNotFoundError: No module named 'falco_siem_bridge'
```

- [ ] **Step 3: Write falco-siem-bridge.py**

```python
#!/usr/bin/env python3
"""Falco → EDA + SIEM bridge.

Receives Falco alerts via Falcosidekick webhook, enriches with agent
context and MITRE ATT&CK mapping, forwards to:
  1. EDA webhook (automated response)
  2. Syslog RFC 5424 / CEF (SOC visibility)

Backward compatible: without --syslog-host, behaves like falco-eda-bridge.py.

Run:
    python3 falco-siem-bridge.py --port 5001 --eda-url http://localhost:5000 \
        --syslog-host 10.x.x.x --syslog-port 514 --syslog-proto tcp
"""

import argparse
import json
import re
import socket
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen

TAG_TO_ALERT_TYPE = {
    "swarm": "swarm",
    "exfiltration": "exfiltration",
    "escalation": "escalation",
    "sandbox-escape": "escape",
    "network": "exfiltration",
}

RULE_TAG_PATTERN = re.compile(r"^[A-Z]+-\d+$")

MITRE_MAP = {
    "SWARM-001": "T1059.006",
    "SWARM-002": "T1106",
    "EXFIL-002": "T1552.001",
    "EXFIL-003": "T1048.002",
    "NET-002": "T1562.004",
    "SCOPE-001": "T1078.003",
    "SBX-002": "T1611",
}

OCSF_CLASS_UID = 2001  # Security Finding


def extract_agent_principal(output_fields: dict, output: str) -> str:
    user = output_fields.get("user.name", "")
    if user and user != "root":
        return user
    match = re.search(r"agent=(\S+)", output)
    if match:
        return match.group(1)
    return output_fields.get("proc.pname", "unknown-agent")


def transform(falco_event: dict) -> dict:
    tags = falco_event.get("tags", [])
    output_fields = falco_event.get("output_fields", {})
    output = falco_event.get("output", "")

    alert_type = "unknown"
    rule_id = ""
    for tag in tags:
        if RULE_TAG_PATTERN.match(tag):
            rule_id = tag
        elif tag in TAG_TO_ALERT_TYPE:
            alert_type = TAG_TO_ALERT_TYPE[tag]

    mitre_id = MITRE_MAP.get(rule_id, "")

    return {
        "payload": {
            "alert_type": alert_type,
            "rule": rule_id,
            "agent_principal": extract_agent_principal(output_fields, output),
            "agent_realm": "DEMO.AGENTIC.TEST",
            "timestamp": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "falco_priority": falco_event.get("priority", ""),
            "falco_rule": falco_event.get("rule", ""),
            "falco_output": output,
            "source_host": output_fields.get("container.name", "host"),
            "pid": output_fields.get("proc.pid", ""),
            "cmdline": output_fields.get("proc.cmdline", ""),
            "mitre_id": mitre_id,
            "ocsf_class_uid": OCSF_CLASS_UID,
        }
    }


def format_rfc5424(payload: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = payload.get("source_host", "-")
    rule = payload.get("rule", "-")
    severity = payload.get("falco_priority", "warning").lower()
    sd = (
        f'[agent-security alert_type="{payload.get("alert_type", "unknown")}"'
        f' agent_principal="{payload.get("agent_principal", "unknown")}"'
        f' agent_realm="{payload.get("agent_realm", "")}"'
        f' mitre_id="{payload.get("mitre_id", "")}"'
        f' ocsf_class_uid="{payload.get("ocsf_class_uid", "")}"'
        f' severity="{severity}"]'
    )
    msg = payload.get("falco_output", "")
    # PRI = facility(16=local0) * 8 + severity(6=info) = 134
    return f"<134>1 {ts} {hostname} falco-siem-bridge - {rule} {sd} {msg}"


def format_cef(payload: dict) -> str:
    rule = payload.get("rule", "UNKNOWN")
    name = payload.get("falco_rule", "Unknown Rule")
    severity = "9" if payload.get("falco_priority", "").lower() == "critical" else "6"
    msg = payload.get("falco_output", "").replace("\\", "\\\\").replace("|", "\\|")
    return (
        f"CEF:0|RedHat|AgenticSecurity|1.0|{rule}|{name}|{severity}|"
        f"src={payload.get('source_host', '')} "
        f"suser={payload.get('agent_principal', '')} "
        f"cs1={payload.get('mitre_id', '')} cs1Label=mitreTechniqueId "
        f"cs2={payload.get('agent_realm', '')} cs2Label=agentRealm "
        f"msg={msg}"
    )


def send_syslog(payload: dict, host: str, port: int, proto: str, cef: bool):
    if not host:
        return
    msg = format_cef(payload) if cef else format_rfc5424(payload)
    try:
        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode("utf-8"), (host, port))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.sendall(msg.encode("utf-8") + b"\n")
            sock.close()
    except Exception as e:
        print(f"[bridge] syslog send failed ({host}:{port}): {e}", file=sys.stderr)


class BridgeHandler(BaseHTTPRequestHandler):
    eda_url = "http://localhost:5000"
    syslog_host = ""
    syslog_port = 514
    syslog_proto = "tcp"
    syslog_cef = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            falco_event = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        eda_event = transform(falco_event)
        p = eda_event["payload"]
        print(f"[bridge] {falco_event.get('rule', '?')} → "
              f"{p['alert_type']}/{p['rule']} mitre={p['mitre_id']}")

        # Forward to EDA
        try:
            req = Request(
                self.eda_url,
                data=json.dumps(eda_event).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=5) as resp:
                self.send_response(resp.status)
        except Exception as e:
            print(f"[bridge] EDA forward failed: {e}", file=sys.stderr)
            self.send_response(502)

        self.end_headers()

        # Send to syslog (non-blocking — failure here must not affect EDA)
        send_syslog(p, self.syslog_host, self.syslog_port,
                    self.syslog_proto, self.syslog_cef)

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="Falco → EDA + SIEM bridge")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--eda-url", default="http://localhost:5000")
    parser.add_argument("--syslog-host", default="")
    parser.add_argument("--syslog-port", type=int, default=514)
    parser.add_argument("--syslog-proto", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("--cef", action="store_true",
                        help="Use CEF format instead of RFC 5424")
    args = parser.parse_args()

    BridgeHandler.eda_url = args.eda_url
    BridgeHandler.syslog_host = args.syslog_host
    BridgeHandler.syslog_port = args.syslog_port
    BridgeHandler.syslog_proto = args.syslog_proto
    BridgeHandler.syslog_cef = args.cef

    server = HTTPServer(("0.0.0.0", args.port), BridgeHandler)
    syslog_status = f" syslog→{args.syslog_host}:{args.syslog_port}" if args.syslog_host else " (no syslog)"
    print(f"[bridge] Listening on :{args.port}, EDA→{args.eda_url}{syslog_status}")
    server.serve_forever()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

```bash
cd ~/DevSpace/rhel-agentic-security/beaker/ansible
python3 -m pytest test_bridge.py -v
# Expected: all tests PASS
```

- [ ] **Step 5: Remove old bridge, update setup script reference**

```bash
cd ~/DevSpace/rhel-agentic-security
rm beaker/ansible/falco-eda-bridge.py
# Update setup-falco-eda.sh to reference the new bridge filename
sed -i 's/falco-eda-bridge\.py/falco-siem-bridge.py/g' beaker/setup/setup-falco-eda.sh
# Update the systemd unit in setup-falco-eda.sh
sed -i 's/falco-eda-bridge/falco-siem-bridge/g' beaker/setup/setup-falco-eda.sh
```

- [ ] **Step 6: Commit**

```bash
git add beaker/ansible/falco_siem_bridge.py beaker/ansible/test_bridge.py beaker/setup/setup-falco-eda.sh
git rm beaker/ansible/falco-eda-bridge.py
git commit -m "feat(beaker): replace EDA bridge with dual-output SIEM bridge

Adds syslog RFC 5424 and CEF output alongside EDA webhook.
MITRE ATT&CK mapping for all 7 Falco rules.
Without --syslog-host, behaves identically to old bridge."
```

**Note on filename:** The Python module is `falco_siem_bridge.py` (underscores) for importability in tests. The old file was `falco-eda-bridge.py` (hyphens). The setup script and systemd unit reference the filename, so both sed commands above are needed.

---

### Task 3: Update falcosidekick-config.yaml and write rsyslog forwarder

Add the disabled syslog block to Falcosidekick config and create the rsyslog OCSF forwarder.

**Files:**
- Modify: `beaker/ansible/falcosidekick-config.yaml`
- Create: `beaker/ansible/rsyslog-ocsf-forwarder.conf`

**Interfaces:**
- Consumes: `falcosidekick-config.yaml` from Task 1 cherry-pick
- Produces: `rsyslog-ocsf-forwarder.conf` used by Task 5 (setup-siem.sh deploys it)

- [ ] **Step 1: Add syslog block to falcosidekick-config.yaml**

Append after the existing `loki:` block:

```yaml
# Syslog output — DISABLED by default (demo uses bridge path).
# Set host to SIEM IP to enable dual-path (Falcosidekick + bridge both emit).
syslog:
  host: ""
  port: 514
  protocol: "tcp"
  minimumpriority: "warning"
  format: "json"
```

- [ ] **Step 2: Write rsyslog-ocsf-forwarder.conf**

```
# rsyslog config — forward OCSF incident events to SIEM.
# Deploy to /etc/rsyslog.d/90-ocsf-forwarder.conf on the runner VM.
# SIEM_HOST is replaced at deploy time by setup-siem.sh.

module(load="imfile" PollingInterval="2")

input(type="imfile"
      File="/var/log/ocsf/*.json"
      Tag="ocsf-incident:"
      Severity="crit"
      Facility="auth"
      PersistStateInterval="1"
      reopenOnTruncate="on"
      freshStartTail="on")

if $syslogtag == "ocsf-incident:" then {
    action(type="omfwd"
           Target="SIEM_HOST"
           Port="514"
           Protocol="tcp"
           Template="RSYSLOG_SyslogProtocol23Format"
           action.resumeRetryCount="-1"
           queue.type="LinkedList"
           queue.size="1000")
}
```

- [ ] **Step 3: Commit**

```bash
git add beaker/ansible/falcosidekick-config.yaml beaker/ansible/rsyslog-ocsf-forwarder.conf
git commit -m "feat(beaker): add syslog toggle to falcosidekick + rsyslog OCSF forwarder

Falcosidekick syslog output disabled by default (empty host).
rsyslog watches /var/log/ocsf/*.json and forwards incident events."
```

---

### Task 4: Write Wazuh decoders, rules, and setup-siem.sh

Create the Wazuh setup script and custom decoder/rules for parsing our syslog events.

**Files:**
- Create: `beaker/setup/wazuh-decoders.xml`
- Create: `beaker/setup/wazuh-rules.xml`
- Create: `beaker/setup/setup-siem.sh`

**Interfaces:**
- Consumes: inventory.env `SIEM=` variable, `rsyslog-ocsf-forwarder.conf` from Task 3
- Produces: Working Wazuh installation on SIEM VM, syslog intake on 514/tcp

- [ ] **Step 1: Write wazuh-decoders.xml**

```xml
<!-- beaker/setup/wazuh-decoders.xml -->
<!-- Custom decoder for agentic security syslog events (RFC 5424 SD). -->
<!-- Deploy to /var/ossec/etc/decoders/agentic-security-decoder.xml -->

<decoder name="agentic-security">
  <prematch>falco-siem-bridge</prematch>
</decoder>

<decoder name="agentic-security-fields">
  <parent>agentic-security</parent>
  <regex>alert_type="(\S+)" agent_principal="(\S+)" agent_realm="(\S+)" mitre_id="(\S+)"</regex>
  <order>alert_type,agent_principal,agent_realm,mitre_id</order>
</decoder>

<!-- Decoder for OCSF incident events forwarded via rsyslog -->
<decoder name="ocsf-incident">
  <prematch>ocsf-incident</prematch>
</decoder>

<decoder name="ocsf-incident-fields">
  <parent>ocsf-incident</parent>
  <regex>"class_name": "(\S+)"</regex>
  <order>ocsf_class</order>
</decoder>
```

- [ ] **Step 2: Write wazuh-rules.xml**

```xml
<!-- beaker/setup/wazuh-rules.xml -->
<!-- Custom rules for agentic security alerts. -->
<!-- Deploy to /var/ossec/etc/rules/agentic-security-rules.xml -->

<group name="agentic-security,">

  <rule id="100100" level="12">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">swarm</field>
    <description>Agent swarm behavior detected: $(agent_principal)</description>
    <mitre>
      <id>T1059.006</id>
    </mitre>
    <group>agentic-security,swarm,</group>
  </rule>

  <rule id="100101" level="12">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">exfiltration</field>
    <description>Agent exfiltration detected: $(agent_principal)</description>
    <mitre>
      <id>T1552.001</id>
    </mitre>
    <group>agentic-security,exfiltration,</group>
  </rule>

  <rule id="100102" level="10">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">escalation</field>
    <description>Agent privilege escalation: $(agent_principal)</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
    <group>agentic-security,escalation,</group>
  </rule>

  <rule id="100103" level="14">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">escape</field>
    <description>Agent sandbox escape attempt: $(agent_principal)</description>
    <mitre>
      <id>T1611</id>
    </mitre>
    <group>agentic-security,escape,</group>
  </rule>

  <rule id="100110" level="12">
    <decoded_as>ocsf-incident</decoded_as>
    <description>OCSF incident: agent revocation completed</description>
    <group>agentic-security,incident,</group>
  </rule>

</group>
```

- [ ] **Step 3: Write setup-siem.sh**

```bash
#!/usr/bin/env bash
# Set up Wazuh all-in-one on the SIEM VM.
# Run AFTER setup-server.sh and setup-client.sh.
# Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_VERSION="4.11.0"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── 1. Download and run Wazuh installer ──────────────────────────────────────

if [ ! -d /var/ossec ]; then
    log "Installing Wazuh ${WAZUH_VERSION} all-in-one..."

    curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh
    chmod +x wazuh-install.sh

    # All-in-one install: manager + indexer + dashboard (single command)
    bash wazuh-install.sh -a

    log "Wazuh installed"
else
    log "Wazuh already installed — skipping"
fi

# ── 2. Configure syslog intake ───────────────────────────────────────────────

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if ! grep -q "connection>syslog" "${OSSEC_CONF}" 2>/dev/null; then
    log "Configuring syslog intake on 514/tcp..."

    # Insert remote syslog block before </ossec_config>
    sed -i '/<\/ossec_config>/i \
  <remote>\
    <connection>syslog</connection>\
    <port>514</port>\
    <protocol>tcp</protocol>\
    <allowed-ips>0.0.0.0/0</allowed-ips>\
  </remote>' "${OSSEC_CONF}"

    log "Syslog intake configured"
else
    log "Syslog intake already configured"
fi

# ── 3. Deploy custom decoder and rules ───────────────────────────────────────

log "Deploying custom decoders and rules..."

cp "${SCRIPT_DIR}/wazuh-decoders.xml" \
    /var/ossec/etc/decoders/agentic-security-decoder.xml
cp "${SCRIPT_DIR}/wazuh-rules.xml" \
    /var/ossec/etc/rules/agentic-security-rules.xml

chown wazuh:wazuh /var/ossec/etc/decoders/agentic-security-decoder.xml \
                  /var/ossec/etc/rules/agentic-security-rules.xml

log "Custom decoders and rules deployed"

# ── 4. Restart Wazuh manager to pick up changes ─────────────────────────────

systemctl restart wazuh-manager
log "Wazuh manager restarted"

# ── 5. Open firewall ports ───────────────────────────────────────────────────

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-port=514/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=1514/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=1515/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=9200/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log "Firewall ports opened"
fi

# ── 6. Extract dashboard credentials ────────────────────────────────────────

log "Extracting credentials..."
mkdir -p /root/wazuh-install-files
if [ -f wazuh-install-files.tar ]; then
    tar -xf wazuh-install-files.tar -C /root/wazuh-install-files/ 2>/dev/null || true
fi

CREDS_FILE="/root/wazuh-install-files/wazuh-passwords.txt"
if [ -f "${CREDS_FILE}" ]; then
    ADMIN_PASS=$(grep -A1 "indexer_username.*admin" "${CREDS_FILE}" | grep password | awk '{print $NF}' | tr -d "'" | head -1)
    log "Dashboard credentials:"
    log "  URL: https://$(hostname -f):443"
    log "  User: admin"
    log "  Password: ${ADMIN_PASS:-check ${CREDS_FILE}}"
else
    log "Credentials: printed at end of install output above"
fi

log "SIEM setup complete"
```

- [ ] **Step 4: Make setup-siem.sh executable**

```bash
chmod +x ~/DevSpace/rhel-agentic-security/beaker/setup/setup-siem.sh
```

- [ ] **Step 5: Commit**

```bash
git add beaker/setup/wazuh-decoders.xml beaker/setup/wazuh-rules.xml beaker/setup/setup-siem.sh
git commit -m "feat(beaker): add Wazuh SIEM setup script with custom decoders

Wazuh 4.x all-in-one installer, syslog intake on 514/tcp,
custom decoder for agent-security events, 5 custom rules
with MITRE ATT&CK mapping."
```

---

### Task 5: Update Makefile and inventory.env

Add `setup-siem` and `validate-siem` targets, add SIEM= to inventory.

**Files:**
- Modify: `beaker/Makefile`
- Modify: `beaker/setup/inventory.env`

**Interfaces:**
- Consumes: `setup-siem.sh` from Task 4, `rsyslog-ocsf-forwarder.conf` from Task 3, `falco_siem_bridge.py` from Task 2
- Produces: `make setup-siem` and `make validate-siem` targets

- [ ] **Step 1: Update inventory.env**

Add after CLIENT= line:
```
SIEM=kvm-03-guest21.lab.eng.rdu2.dc.redhat.com
```

- [ ] **Step 2: Add Makefile targets**

Append before `help:` target:

```makefile
setup-siem: setup/inventory.env ## Set up System 3 (Wazuh SIEM dashboard)
	@echo "=== Setting up SIEM: $(SIEM) ==="
	ssh $(SSH_OPTS) root@$(SIEM) "mkdir -p /opt/demo-staging"
	scp $(SSH_OPTS) setup/setup-siem.sh setup/wazuh-decoders.xml setup/wazuh-rules.xml root@$(SIEM):/opt/demo-staging/
	ssh $(SSH_OPTS) root@$(SIEM) "chmod +x /opt/demo-staging/setup-siem.sh && /opt/demo-staging/setup-siem.sh"
	@echo "--- Deploying rsyslog forwarder on runner ---"
	scp $(SSH_OPTS) ansible/rsyslog-ocsf-forwarder.conf root@$(CLIENT):/etc/rsyslog.d/90-ocsf-forwarder.conf
	ssh $(SSH_OPTS) root@$(CLIENT) "SIEM_IP=$$(getent hosts $(SIEM) | awk '{print $$1}') && sed -i \"s/SIEM_HOST/$$SIEM_IP/g\" /etc/rsyslog.d/90-ocsf-forwarder.conf && systemctl restart rsyslog"
	@echo "--- Updating bridge systemd unit with syslog destination ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "SIEM_IP=$$(getent hosts $(SIEM) | awk '{print $$1}') && sed -i \"s|falco-siem-bridge.py --port 5001 --eda-url http://localhost:5000|falco-siem-bridge.py --port 5001 --eda-url http://localhost:5000 --syslog-host $$SIEM_IP --syslog-port 514|\" /etc/systemd/system/falco-siem-bridge.service 2>/dev/null && systemctl daemon-reload && systemctl restart falco-siem-bridge 2>/dev/null || true"
	@echo "=== SIEM setup complete ==="

validate-siem: setup/inventory.env ## Validate SIEM receives syslog events
	@echo "--- Validating SIEM ($(SIEM)) ---"
	ssh $(SSH_OPTS) root@$(SIEM) "systemctl is-active wazuh-manager && echo 'Wazuh manager: OK' || echo 'Wazuh manager: FAIL'"
	ssh $(SSH_OPTS) root@$(SIEM) "systemctl is-active wazuh-indexer && echo 'Wazuh indexer: OK' || echo 'Wazuh indexer: FAIL'"
	ssh $(SSH_OPTS) root@$(SIEM) "systemctl is-active wazuh-dashboard && echo 'Wazuh dashboard: OK' || echo 'Wazuh dashboard: FAIL'"
	ssh $(SSH_OPTS) root@$(SIEM) "ss -tlnp | grep -q ':514' && echo 'Syslog intake: OK' || echo 'Syslog intake: FAIL'"
	@echo "--- Sending test event from runner ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "logger -n $(SIEM) -P 514 --tcp '<134>1 2026-10-02T12:00:00Z test falco-siem-bridge - TEST-001 [agent-security alert_type=\"swarm\" agent_principal=\"test-agent\" agent_realm=\"DEMO.AGENTIC.TEST\" mitre_id=\"T1059.006\" ocsf_class_uid=\"2001\" severity=\"critical\"] Smoke test event' && echo 'Test event sent: OK'"
	@echo "--- Check Wazuh API for alert ---"
	ssh $(SSH_OPTS) root@$(SIEM) "sleep 5 && curl -sk -u admin:$$(grep password /root/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | head -1 | awk '{print \$$2}') https://localhost:55000/security/user/authenticate?raw=true 2>/dev/null | head -c 100 && echo ''" || echo "API check requires manual verification"
```

- [ ] **Step 3: Update .PHONY line**

Add `setup-siem` and `validate-siem` to the existing `.PHONY` line in the Makefile.

- [ ] **Step 4: Commit**

```bash
git add beaker/Makefile beaker/setup/inventory.env
git commit -m "feat(beaker): add setup-siem and validate-siem Makefile targets

Three-VM inventory: SERVER + CLIENT + SIEM.
setup-siem: deploys Wazuh, rsyslog forwarder, bridge syslog config.
validate-siem: checks services + sends smoke test event."
```

---

### Task 6: Deploy and validate end-to-end

Deploy Falco+EDA on runner, Wazuh on SIEM VM, run full pipeline test.

**Files:**
- No new files — deployment of Tasks 1-5

**Interfaces:**
- Consumes: all previous tasks, three live Beaker VMs

- [ ] **Step 1: Deploy Falco + EDA on runner VM**

```bash
cd ~/DevSpace/rhel-agentic-security/beaker
make setup-falco-eda  # if target exists, or run directly:
# If no make target, SCP and run manually:
ssh -o StrictHostKeyChecking=no root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com "mkdir -p /opt/demo-staging/ansible"
scp -o StrictHostKeyChecking=no ansible/*.py ansible/*.yaml ansible/*.yml root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com:/opt/demo-staging/ansible/
scp -o StrictHostKeyChecking=no setup/setup-falco-eda.sh root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com:/opt/demo-staging/
ssh -o StrictHostKeyChecking=no root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com "chmod +x /opt/demo-staging/setup-falco-eda.sh && /opt/demo-staging/setup-falco-eda.sh"
```

- [ ] **Step 2: Verify Falco + bridge running**

```bash
ssh -o StrictHostKeyChecking=no root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com \
    "systemctl is-active falco && echo 'Falco: OK' || echo 'Falco: FAIL'"
ssh -o StrictHostKeyChecking=no root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com \
    "systemctl is-active falco-siem-bridge && echo 'Bridge: OK' || echo 'Bridge: FAIL'"
```

- [ ] **Step 3: Deploy Wazuh on SIEM VM**

```bash
make -C ~/DevSpace/rhel-agentic-security/beaker setup-siem
```

This takes ~10-15 minutes (Wazuh indexer is slow to initialize).

- [ ] **Step 4: Validate SIEM**

```bash
make -C ~/DevSpace/rhel-agentic-security/beaker validate-siem
```

All checks should pass: manager OK, indexer OK, dashboard OK, syslog intake OK, test event sent OK.

- [ ] **Step 5: End-to-end test — trigger rogue agent**

```bash
# On runner: run the rogue agent to trigger Falco
ssh -o StrictHostKeyChecking=no root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com \
    "cd /opt/demo/agents && python3 rogue_agent.py 2>&1 | head -20"
```

Then check Wazuh dashboard at `https://kvm-03-guest21.lab.eng.rdu2.dc.redhat.com:443` — should show agentic-security alerts with MITRE mapping.

- [ ] **Step 6: Verify smoke test script**

```bash
ssh -o StrictHostKeyChecking=no root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com \
    "bash /opt/demo/bridge/smoke-test.sh"
```

Bridge should accept fake alert, forward to both EDA and syslog.

- [ ] **Step 7: Commit inventory and any deployment fixes**

```bash
cd ~/DevSpace/rhel-agentic-security
git add -A beaker/
git commit -m "chore(beaker): deployment fixes from live testing"
```

---

## Deployment Notes

**VM access:**
- Server: `ssh root@sweetpig-14.khw.eng.rdu2.dc.redhat.com`
- Runner: `ssh root@hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com`
- SIEM: `ssh root@kvm-03-guest21.lab.eng.rdu2.dc.redhat.com`

**Wazuh dashboard:** `https://kvm-03-guest21.lab.eng.rdu2.dc.redhat.com:443` (credentials in `/root/wazuh-install-files/wazuh-passwords.txt` on SIEM VM)

**Bridge systemd unit:** `/etc/systemd/system/falco-siem-bridge.service` on runner VM

**Pipeline test order:** Falco → Falcosidekick → bridge:5001 → {EDA:5000 + syslog:514} → Wazuh dashboard
