# SIEM Integration — Vendor-Neutral Detection Pipeline

**Date:** 2026-10-02
**Status:** Draft
**Author:** Amy Ralph
**Related:** [Trust Tiers Design](2026-09-28-agentic-security-trust-tiers-design.md)

## Problem

The agentic security PoC detects agent anomalies (Falco) and responds
automatically (EDA + revocation playbook), but detection events and
incident reports stay on the runner VM. No SOC visibility. A CISO
watching this demo asks: "where does this show up in my SIEM?"

## Goal

Vendor-neutral SIEM integration that works with any standards-compliant
SIEM via syslog. Wazuh deployed as the demo target on a dedicated
Beaker VM. Swapping to Splunk, QRadar, or ELK is a config change
(syslog destination), not a rewrite.

## Architecture — Hybrid Model

Primary path (demo default): bridge emits enriched events to both EDA
and syslog. Secondary path (field toggle): Falcosidekick native syslog
output enabled via config for dual-path redundancy.

```
                         ┌─────────────┐
                         │   Falco     │  eBPF syscall monitoring
                         │ (modern_ebpf)│  7 agent security rules
                         └──────┬──────┘
                                │ gRPC
                         ┌──────▼──────┐
                         │Falcosidekick│
                         │             │──── syslog (DISABLED by default)
                         └──────┬──────┘     toggle: set host in config
                                │ webhook
                         ┌──────▼──────┐
                         │   Bridge    │  falco-siem-bridge.py :5001
                         │  (enricher) │
                         ├─────┬───────┤
                    EDA  │     │       │  syslog RFC 5424 + CEF
                  :5000  │     │       │
              ┌──────────┘     │       └──────────────┐
              ▼                │                      ▼
     ┌────────────────┐        │             ┌────────────────┐
     │  EDA Rulebook  │        │             │  Wazuh (VM3)   │
     │  → Revocation  │        │             │  or any SIEM   │
     │    Playbook    │        │             │                │
     └───────┬────────┘        │             │  syslog:514/tcp│
             │                 │             └────────▲───────┘
             ▼                 │                      │
     ┌────────────────┐        │             ┌────────┴───────┐
     │ /var/log/ocsf/ │────────┼────────────▶│ rsyslog imfile │
     │ incident JSON  │        │             │ OCSF forwarder │
     └────────────────┘        │             └────────────────┘
                               │
                    Revocation playbook
                    writes OCSF incident
```

### Why hybrid

- **Demo mode (option 1):** Bridge is single syslog emitter. One
  format (OCSF-enriched), one event stream, clean CISO story.
- **Field toggle (option 2):** Set `syslog.host` in
  `falcosidekick-config.yaml` to enable native Falcosidekick syslog.
  SIEM gets both raw Falco alerts and enriched bridge events. No code
  change — config only.

### Why bridge as primary emitter

Raw Falcosidekick syslog lacks agent context. The bridge enriches
events with:
- Agent principal (IPA identity, not just Unix UID)
- Trust tier (sovereign/verified/untrusted/blocked)
- MITRE ATT&CK technique ID
- OCSF class_uid for schema consistency
- Agent realm and enrollment status

Without this, SOC analysts see "python3 spawned a child process" instead
of "code-assist-9a2b (verified tier) attempted unauthorized escalation."

## Components

### 1. falco-siem-bridge.py (replace falco-eda-bridge.py)

**Location:** `beaker/ansible/falco-siem-bridge.py`
**Lines:** ~180

Dual-output HTTP server. Receives Falcosidekick webhook on `:5001`,
enriches with agent context, forwards to:

1. **EDA webhook** (`:5000`) — existing behavior, unchanged
2. **Syslog** (RFC 5424 structured data + optional CEF) — new

#### Enrichment pipeline

```
Falcosidekick event
    │
    ├── extract agent_principal (user.name / proc.pname / cmdline parse)
    ├── map Falco tags → alert_type (swarm/exfil/escalation/escape)
    ├── map Falco rule → MITRE ATT&CK technique ID
    ├── assign OCSF class_uid (2001 = Security Finding)
    └── emit to EDA + syslog
```

#### MITRE ATT&CK mapping

| Falco Rule | Rule ID | MITRE ID | Technique |
|---|---|---|---|
| Agent Swarm — Unauthorized Process Spawning | SWARM-001 | T1059.006 | Command/Scripting: Python |
| Agent Swarm — Mass Process Fork | SWARM-002 | T1106 | Native API (fork bomb) |
| Agent Credential Harvesting | EXFIL-002 | T1552.001 | Credentials in Files |
| Agent Data Exfiltration — Outbound POST | EXFIL-003 | T1048.002 | Exfil over Asymmetric Encrypted |
| Agent SSL Verification Disabled | NET-002 | T1562.004 | Impair Defenses: Disable Crypto |
| Agent Privilege Escalation — Scope Request | SCOPE-001 | T1078.003 | Valid Accounts: Local |
| Agent Sandbox Escape Attempt | SBX-002 | T1611 | Escape to Host |

#### Syslog format — RFC 5424 structured data

```
<134>1 2026-10-02T10:30:45Z runner.demo.agentic.test falco-siem-bridge - SWARM-001
  [agent-security alert_type="swarm" agent_principal="code-assist-9a2b"
   agent_realm="DEMO.AGENTIC.TEST" mitre_id="T1059.006"
   ocsf_class_uid="2001" severity="critical"]
  Agent spawned unauthorized child process (pid=12345 cmd=agent_worker.py)
```

#### Syslog format — CEF (optional, `--cef` flag)

```
CEF:0|RedHat|AgenticSecurity|1.0|SWARM-001|Agent Swarm Detected|9|
  src=runner.demo.agentic.test suser=code-assist-9a2b
  cs1=T1059.006 cs1Label=mitreTechniqueId
  cs2=DEMO.AGENTIC.TEST cs2Label=agentRealm
  msg=Agent spawned unauthorized child process
```

#### CLI interface

```
python3 falco-siem-bridge.py \
    --port 5001 \
    --eda-url http://localhost:5000 \
    --syslog-host 10.x.x.x \
    --syslog-port 514 \
    --syslog-proto tcp \
    --cef                        # optional: use CEF instead of RFC 5424 SD
```

Without `--syslog-host`, syslog output is disabled — bridge behaves
identically to the old `falco-eda-bridge.py`.

### 2. falcosidekick-config.yaml (update)

**Location:** `beaker/ansible/falcosidekick-config.yaml`

Add syslog output block, disabled by default:

```yaml
syslog:
  host: ""              # empty = disabled; set SIEM IP for dual-path
  port: 514
  protocol: "tcp"
  minimumpriority: "warning"
  format: "json"
```

Existing webhook config unchanged. When `syslog.host` is set,
Falcosidekick sends raw Falco alerts directly to SIEM in parallel
with the bridge path — belt-and-suspenders for field deployments.

### 3. rsyslog-ocsf-forwarder.conf (new)

**Location:** `beaker/ansible/rsyslog-ocsf-forwarder.conf`
**Lines:** ~25

rsyslog config deployed on runner VM. Watches `/var/log/ocsf/*.json`
(revocation playbook OCSF incident events) and forwards to SIEM:

```
module(load="imfile")
input(type="imfile"
      File="/var/log/ocsf/*.json"
      Tag="ocsf-incident"
      Severity="crit"
      Facility="auth"
      PersistStateInterval="1"
      reopenOnTruncate="on")

if $syslogtag == 'ocsf-incident' then {
    action(type="omfwd"
           Target="SIEM_HOST"
           Port="514"
           Protocol="tcp"
           Template="RSYSLOG_SyslogProtocol23Format")
}
```

SIEM_HOST replaced at deploy time by `setup-siem.sh` or inventory var.

### 4. setup-siem.sh (new)

**Location:** `beaker/setup/setup-siem.sh`
**Lines:** ~200

Installs Wazuh 4.x single-node on VM3 (SIEM dashboard). Sections:

1. **Install Wazuh all-in-one** — uses official `wazuh-install.sh`
   assistant. Manager + Wazuh indexer + Wazuh dashboard on single node.
2. **Configure syslog intake** — enable `ossec.conf` remote syslog on
   514/tcp, allowed-ips from server + runner VMs.
3. **Deploy custom decoder** — parse our RFC 5424 structured data
   fields (`agent-security` SD-ID) into Wazuh alert fields.
4. **Deploy custom rules** — map our alert_type values to Wazuh rule
   IDs and severity levels. MITRE technique IDs populate Wazuh's
   built-in MITRE dashboard.
5. **Open firewall** — ports 514/tcp (syslog), 443 (dashboard).
6. **Print dashboard URL + credentials.**

#### Wazuh custom decoder

```xml
<decoder name="agentic-security">
  <prematch>agent-security</prematch>
  <regex>alert_type="(\S+)" agent_principal="(\S+)"</regex>
  <regex>agent_realm="(\S+)" mitre_id="(\S+)"</regex>
  <order>alert_type,agent_principal,agent_realm,mitre_id</order>
</decoder>
```

#### Wazuh custom rules

```xml
<group name="agentic-security,">
  <rule id="100100" level="12">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">swarm</field>
    <description>Agent swarm behavior detected: $(agent_principal)</description>
    <mitre><id>T1059.006</id></mitre>
    <group>agentic-security,swarm,</group>
  </rule>

  <rule id="100101" level="12">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">exfiltration</field>
    <description>Agent exfiltration detected: $(agent_principal)</description>
    <mitre><id>T1552.001</id></mitre>
    <group>agentic-security,exfiltration,</group>
  </rule>

  <rule id="100102" level="10">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">escalation</field>
    <description>Agent privilege escalation: $(agent_principal)</description>
    <mitre><id>T1078.003</id></mitre>
    <group>agentic-security,escalation,</group>
  </rule>

  <rule id="100103" level="14">
    <decoded_as>agentic-security</decoded_as>
    <field name="alert_type">escape</field>
    <description>Agent sandbox escape attempt: $(agent_principal)</description>
    <mitre><id>T1611</id></mitre>
    <group>agentic-security,escape,</group>
  </rule>
</group>
```

### 5. Makefile updates

New targets:

```makefile
setup-siem: setup/inventory.env    ## Set up System 3 (Wazuh SIEM dashboard)
    # SCP setup-siem.sh + custom decoders/rules to SIEM VM
    # Run setup-siem.sh
    # Deploy rsyslog forwarder on runner VM
    # Update bridge systemd unit with --syslog-host

validate-siem: setup/inventory.env ## Validate SIEM receives events
    # Send test syslog message from runner
    # Check Wazuh API for received alert
```

### 6. inventory.env update

```
SERVER=sweetpig-14.khw.eng.rdu2.dc.redhat.com
CLIENT=hpe-dl80gen9-01.khw.eng.rdu2.dc.redhat.com
SIEM=<vm3-fqdn-from-J:1200241301>
```

## Demo Flow with SIEM

1. **Rogue agent runs** on runner VM
2. **Falco detects** credential harvesting (EXFIL-002)
3. **Falcosidekick** forwards to bridge
4. **Bridge enriches** → agent principal, MITRE T1552.001, OCSF 2001
5. **Bridge emits** → EDA (triggers revocation) + syslog → Wazuh
6. **Wazuh dashboard** shows alert with MITRE heatmap highlight
7. **Revocation playbook** runs → writes OCSF incident JSON
8. **rsyslog forwards** incident → Wazuh
9. **Wazuh dashboard** shows containment confirmation
10. **CISO sees:** detection → response → containment in one console

Time from detection to dashboard: < 30 seconds.

## What this does NOT include

- **Custom Wazuh dashboard HTML** — use built-in dashboards + existing
  SOC deck HTMLs for the recording. Custom dashboards are polish, not
  architecture.
- **Wazuh agent on VMs** — Falco is our detection layer. Wazuh agents
  add host FIM/rootkit but are not needed for the demo story.
- **Kafka/OpenSearch direct** — syslog is the universal interface.
  Direct integrations are optimization, not MVP.
- **Alert deduplication** — bridge and Falcosidekick syslog (when
  enabled) may send overlapping events. Acceptable for PoC; production
  would deduplicate in the SIEM correlation engine.

## Testing

1. **Bridge unit test:** send fake Falco event, verify both EDA
   forward and syslog emission (capture with `nc -l 514`)
2. **rsyslog test:** write test OCSF JSON to `/var/log/ocsf/`,
   verify syslog forward
3. **End-to-end:** trigger rogue agent → verify Wazuh alert appears
   with correct MITRE mapping and agent principal
4. **Smoke test script:** extend existing
   `/opt/demo/bridge/smoke-test.sh` to verify syslog path

## File manifest

| File | Action | Est. lines |
|---|---|---|
| `beaker/ansible/falco-siem-bridge.py` | New (replaces falco-eda-bridge.py) | ~180 |
| `beaker/ansible/falcosidekick-config.yaml` | Update (add syslog block) | +10 |
| `beaker/ansible/rsyslog-ocsf-forwarder.conf` | New | ~25 |
| `beaker/setup/setup-siem.sh` | New | ~200 |
| `beaker/setup/wazuh-decoders.xml` | New | ~15 |
| `beaker/setup/wazuh-rules.xml` | New | ~40 |
| `beaker/Makefile` | Update (add setup-siem, validate-siem) | +20 |
| `beaker/setup/inventory.env` | Update (add SIEM=) | +1 |
| `beaker/job-siem.xml` | Already created | — |
