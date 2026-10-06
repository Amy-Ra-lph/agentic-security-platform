# Beaker PoC — Agentic Security Enforcement Stack

Live demonstration of the agentic security enforcement stack on Beaker-provisioned RHEL VMs. Three VMs, seven layers, end-to-end detection-to-containment.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  SERVER (IPA + Keylime verifier/registrar)                         │
│  - FreeIPA: identity lifecycle, HBAC, credential issuance          │
│  - ahdapa: OAuth2 token management, DARC enrollment                │
│  - Keylime verifier + registrar: remote attestation                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ IPA enrollment + TPM attestation
┌──────────────────────────────▼──────────────────────────────────────┐
│  CLIENT (agent runner + detection pipeline)                        │
│  - Keylime agent + swtpm: platform integrity proof                 │
│  - SELinux enforcing: MCS compartmentalization                     │
│  - Falco: eBPF syscall monitoring                                  │
│  - falco-siem-bridge: MITRE ATT&CK classification + dual routing   │
│  - EDA (ansible-rulebook): automated revocation playbooks          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ UDP syslog (RFC 3164)
┌──────────────────────────────▼──────────────────────────────────────┐
│  SIEM (Wazuh)                                                      │
│  - Custom decoders: agentic-security program_name matching         │
│  - Custom rules: 100100-100102 (swarm/exfil/escalation)            │
│  - MITRE ATT&CK tagging on all alerts                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Layers Demonstrated

| Layer | What | Component | Status |
|-------|------|-----------|--------|
| L0 | Platform attestation | Keylime + swtpm (TPM 2.0) | Working |
| L1 | Credential issuance | FreeIPA + ahdapa (DARC) | Working |
| L2 | Token lifecycle | ahdapa OAuth2 (OBO) | Working |
| L4a | Sandbox | OpenShell / Podman | Working |
| L4b | Compartmentalization | SELinux MCS (Blastwall) | Working |
| L5 | Detection pipeline | Falco → bridge → EDA → IPA revocation | Working |
| L5 | SIEM correlation | Wazuh (custom decoders + rules) | Working |

## Prerequisites

- Beaker access + Kerberos ticket (`kinit <user>@REDHAT.COM`)
- SSH key configured for Beaker systems

## Quick Start

```bash
# 1. Submit Beaker jobs (2x RHEL 10 + 1x RHEL 10 for SIEM)
bkr job-submit job.xml
bkr job-submit job-siem.xml

# 2. Record system FQDNs
cat > setup/inventory.env <<EOF
SERVER=<server-fqdn>
CLIENT=<client-fqdn>
SIEM=<siem-fqdn>
EOF

# 3. Set up all three systems
make setup-server
make setup-client
make setup-siem

# 4. Validate
make validate
make validate-siem

# 5. Create demo user on all VMs
for host in SERVER CLIENT SIEM; do
  fqdn=$(grep "^${host}=" setup/inventory.env | cut -d= -f2)
  ssh root@${fqdn} "useradd -m engineer && echo 'Demo2026!' | passwd --stdin engineer && echo 'engineer ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/engineer"
done
```

## Demo Scripts

### Full Stack (L0 + L4b + L5) — 20 min
`demo/demo-selinux-attestation.md` — attestation, SELinux enforcement, detection pipeline with SIEM correlation. Best for technical audiences (security engineers, architects).

### Attestation Only (L0) — 10 min
`demo/demo-attestation-only.md` — Keylime + swtpm registration, PCR verification, continuous attestation. Best for compliance/attestation-focused conversations.

### SIEM Narrative — 15 min
`demo/demo-siem-narrative.md` — Falco detection → bridge classification → dual path (EDA revocation + Wazuh correlation). Best for SOC/SIEM audiences.

### Original 5-Act Demo — 30 min
Acts 1-5 cover the identity + sandbox layers: bad path, assessment gate (CVE scan + static + code + dynamic), identity gate, runtime confinement, side-by-side comparison.

```bash
make demo          # Full 5-act sequence
make act1          # Bad path only
make act2          # Assessment gate
make act3          # Identity gate
make act4          # Runtime confinement
make act5          # Side-by-side
```

## Detection Pipeline

The detection pipeline runs on CLIENT with dual output:

```
Falco (eBPF)
  └→ falco-siem-bridge (classify + MITRE map)
       ├→ EDA webhook (automated revocation)
       │    └→ agent-revocation.yml
       │         ├ Phase 1: IPA token revoke + user disable + HBAC disable
       │         ├ Phase 2: SSSD cache expire on enrolled clients
       │         └ Phase 3: contain agent + write OCSF incident
       └→ UDP syslog → Wazuh (SIEM correlation)
            └→ rules 100100/100101/100102 with MITRE tags
```

MITRE ATT&CK mappings:
- **SWARM-001/002** → T1059.006 (Command and Scripting Interpreter: Python)
- **EXFIL-001/002/003** → T1552.001 (Unsecured Credentials: Files)
- **SCOPE-001, PRIV-001** → T1078.003 (Valid Accounts: Local)

## Key Files

```
setup/
  setup-server.sh          IPA + ahdapa + Keylime verifier/registrar
  setup-client.sh          Agent runner + assessment tools
  setup-keylime-server.sh  Keylime verifier + registrar + swtpm CA
  setup-keylime-client.sh  Keylime agent + swtpm
  setup-falco-eda.sh       Falco + bridge + EDA services
  setup-siem.sh            Wazuh all-in-one
  wazuh-decoders.xml       Custom decoders (program_name matching)
  wazuh-rules.xml          Custom rules (100100-100102)
  inventory.env            VM hostnames

ansible/
  agent-revocation.yml     3-phase revocation playbook
  agent-anomaly-rulebook.yml  EDA rulebook (swarm/exfil/escalation/escape)
  inventory.yml            Ansible inventory for EDA

demo/
  demo-selinux-attestation.md   Full stack SAY/DO script
  demo-attestation-only.md      Attestation-only script
  demo-siem-narrative.md        SIEM-focused script
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Keylime agent won't start | Flush TPM contexts: `tpm2_flushcontext -t && tpm2_flushcontext -s`, remove `agent_data.json`, restart |
| swtpm needs fresh state | Stop both services, `rm -rf /var/lib/swtpm-poc`, restart swtpm then agent |
| Registrar rejects "different TPM" | On SERVER: `sqlite3 /var/lib/keylime/reg_data.sqlite "DELETE FROM registrarmain;"`, restart registrar + agent |
| Wazuh not receiving events | Check UDP 514 open: `ss -ulnp \| grep 514`. Verify `<protocol>udp</protocol>` in ossec.conf |
| Wazuh decoder not matching | Use `<program_name>` not `<prematch>`. Check `/var/ossec/logs/archives/archives.log` with `logall=yes` |
| Bridge killed by playbook | Playbook's pgrep excludes bridge/ansible/rulebook PIDs — if still happening, check `/proc/<pid>/cmdline` patterns |
| EDA not responding | `systemctl status eda-agent-anomaly`. Check webhook token matches between bridge and rulebook |
| SELinux denials | `ausearch -m avc -ts recent` for recent AVCs |

## Architecture Spec

`docs/specs/2026-10-02-siem-integration-design.md`
