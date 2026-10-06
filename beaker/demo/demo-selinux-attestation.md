# Demo Script: Full Enforcement Stack (L0 + L4b + L5)

**For:** Lukas Vrabec (SELinux + Attestation + Detection Pipeline)  
**Duration:** ~20 minutes  
**Format:** SAY/DO walk-through  
**See also:** `demo-attestation-only.md` — shorter attestation-focused script  
**VMs:**  
- **SERVER** — `kvm-08-guest03.lab.eng.rdu2.dc.redhat.com` (Keylime verifier + registrar)  
- **CLIENT** — `dell-r640-094-vm-01.bkr.lab.eng.rdu2.dc.redhat.com` (Keylime agent + swtpm + SELinux enforcing)  
- **SIEM** — `kvm-04-guest28.lab.eng.rdu2.dc.redhat.com` (Wazuh manager)  
- **Login:** `engineer` / `Demo2026!` (passwordless sudo)

---

## Part 1: Attestation (L0 — Keylime)

### Setup Check

**SAY:** "Before we look at SELinux, let me show the attestation layer. We have Keylime running across two VMs — the verifier and registrar on SERVER, and the Rust agent on CLIENT backed by a software TPM."

**DO:** SSH into CLIENT as engineer:
```bash
ssh engineer@dell-r640-094-vm-01.bkr.lab.eng.rdu2.dc.redhat.com
# password: Demo2026!
```

**DO:** Show Keylime agent is running:
```bash
sudo systemctl status keylime_agent --no-pager
```

**SAY:** "The agent registered with the verifier using the TPM's Endorsement Key. It's listening on port 9002 for attestation requests."

**DO:** Show the swtpm is backing the agent:
```bash
sudo systemctl status swtpm-poc --no-pager
```

**DO:** Verify TPM is functional — read random bytes:
```bash
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_getrandom 8 --hex
```

### View Registration

**SAY:** "Let's confirm the agent is registered on the server side."

**DO:** SSH into SERVER (from a second terminal):
```bash
ssh engineer@kvm-08-guest03.lab.eng.rdu2.dc.redhat.com
# password: Demo2026!
```

**DO:** Query the registrar database:
```bash
sudo sqlite3 /var/lib/keylime/reg_data.sqlite "SELECT agent_id, active FROM registrarmain;"
```

**SAY:** "The agent UUID `d432fbb3-...` is registered and active. The verifier can now request quotes from the agent's TPM to verify system integrity."

### TPM Quote (Integrity Check)

**DO:** On CLIENT, read current PCR values:
```bash
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_pcrread sha256:0,1,2,3,7
```

**SAY:** "These PCR values represent the system's boot chain measurement. In production with a hardware TPM, these would reflect the actual firmware, bootloader, and kernel measurements. The verifier checks these haven't changed unexpectedly — that's remote attestation."

---

## Part 2: SELinux (L4b — Blastwall/MCS)

### SELinux Status

**SAY:** "Now let's look at the SELinux enforcement layer. This is the L4b Blastwall layer in our stack — it provides mandatory access control and compartmentalization."

**DO:** On CLIENT:
```bash
getenforce
sestatus
```

**SAY:** "SELinux is in Enforcing mode with targeted policy. Every process runs in a security context that limits what resources it can access."

### Show Process Contexts

**DO:** Show contexts for running services:
```bash
ps -eZ | grep -E "keylime|swtpm|sshd" | head -10
```

**SAY:** "Each process has a domain label. `keylime_agent_t` is the Keylime agent's domain. SELinux policies define exactly what each domain can do — file access, network connections, device operations."

### Demonstrate SELinux Denial

**SAY:** "Let me show what happens when a process tries to do something SELinux doesn't allow."

**DO:** Create a test file in a protected location:
```bash
# As engineer user (not root), try to write to /etc
echo "test" > /etc/selinux-demo-test 2>&1 || true
```

**DO:** Show a real SELinux denial using audit log:
```bash
sudo ausearch -m avc -ts recent --raw 2>/dev/null | tail -5
```

**SAY:** "Any SELinux denials show up in the audit log as AVC (Access Vector Cache) entries. In our architecture, these flow through the fast path — rsyslog picks them up in real-time, EDA can trigger automated responses."

### File Context Demo

**DO:** Show file contexts:
```bash
ls -lZ /etc/keylime/agent.conf
ls -lZ /usr/bin/keylime_agent
ls -lZ /var/lib/keylime/
```

**SAY:** "Notice the file labels — `keylime_agent_exec_t` on the binary, `keylime_var_lib_t` on the data directory. These labels are what connect files to the policies that govern which processes can access them."

### SELinux + Attestation Integration Point

**SAY:** "Here's where the layers connect. We discovered during setup that `keylime_agent_exec_t` triggers a domain transition when systemd launches the binary. The agent runs as `keylime_agent_t`, which has a restricted policy. This is exactly the kind of enforcement the architecture spec describes at L4b — mandatory access control that limits blast radius even for privileged services."

**DO:** Show the domain transition:
```bash
ls -Z /usr/bin/keylime_agent
# keylime_agent_exec_t → keylime_agent_t domain transition
```

**SAY:** "In the full stack, if the verifier detects a PCR change — indicating the system's been tampered with — the EDA pipeline can trigger SELinux policy changes. For example, switching a compromised host from `targeted` to a more restrictive policy, or changing MCS categories to isolate it from other workloads."

---

## Part 3: Detection Pipeline (L5 — Falco → EDA)

### Show Detection Stack

**SAY:** "Now let's see the detection and response pipeline. This is where everything connects. Falco watches for anomalous behavior, classifies it, and EDA triggers automated remediation — including identity revocation through IPA."

**DO:** On CLIENT, show all detection services are running:
```bash
sudo systemctl is-active falco falco-siem-bridge eda-agent-anomaly
```

**SAY:** "Three services: Falco for eBPF-based syscall monitoring, the bridge for classification and routing, and EDA for automated playbook execution."

### Trigger a Detection Event

**SAY:** "Let me trigger a simulated swarm detection — an agent spawning unauthorized processes. In production, Falco catches this from kernel syscalls. Here I'll inject the alert directly."

**DO:** Send a fake swarm alert through the bridge:
```bash
curl -s -X POST http://localhost:5001/ \
    -H "Content-Type: application/json" \
    -d '{
  "rule": "Agent Swarm — Unauthorized Process Spawning",
  "priority": "Critical",
  "output": "SWARM: Agent spawned unauthorized child process (agent=rogue-agent-7f3c pid=99999)",
  "tags": ["agentic-security", "swarm", "SWARM-001"],
  "output_fields": {"proc.pname": "python3", "proc.pid": 99999, "user.name": "rogue-agent-7f3c"},
  "time": "'$(date -u +%Y-%m-%dT%H:%M:%S.000000000Z)'"
}'
```

**SAY:** "Bridge accepted it — HTTP 200. It classified the event as `swarm/SWARM-001`, mapped it to MITRE ATT&CK T1059.006 (Command and Scripting Interpreter: Python), and forwarded to EDA."

**DO:** Show the bridge classification:
```bash
sudo journalctl -u falco-siem-bridge --no-pager -n 3 --since "30s ago" --output=cat
```

### Show Automated Response

**DO:** Wait 5-10 seconds, then show EDA's response:
```bash
sudo journalctl -u eda-agent-anomaly --no-pager -n 30 --since "60s ago" --output=cat
```

**SAY:** "EDA matched the swarm rule and launched the revocation playbook. Four phases: first, it SSHs to the IPA server and revokes the agent's OAuth2 token and disables the principal. Second, it expires SSSD caches on all enrolled clients so the lockout propagates immediately. Third, it kills the agent process and writes an OCSF incident file. Fourth, if ServiceNow is configured, it creates a security incident ticket automatically. Detection to containment — fully automated, no human in the loop for critical threats."

### Verify SIEM Correlation

**SAY:** "The same alert also flows to the SIEM — Wazuh on a separate VM — via syslog. This is the SOC visibility path."

**DO:** SSH into SIEM (third terminal):
```bash
ssh engineer@kvm-04-guest28.lab.eng.rdu2.dc.redhat.com
```

**DO:** Check Wazuh alerts:
```bash
sudo grep "agentic-security" /var/ossec/logs/alerts/alerts.log | tail -5
```

**SAY:** "Wazuh received the alert via UDP syslog, decoded it with our custom decoder, and matched rule 100100 — level 12, tagged with MITRE T1059.006. The SOC sees the same event that EDA just acted on, with full MITRE mapping."

---

## Part 4: Tie It Together

**SAY:** "So what we've shown is three layers of the enforcement stack working together:

1. **L0 Attestation (Keylime)** — the platform proves its integrity via TPM-backed quotes. The verifier validates these continuously.

2. **L4b Blastwall (SELinux)** — mandatory access control compartmentalizes processes. Each service runs in its own domain with least-privilege policies.

3. **L5 Audit + Response (Falco → EDA → Wazuh)** — behavioral anomaly detection triggers a four-phase automated response: identity revocation through IPA, SSSD cache expiry, agent containment with OCSF incident filing, and optionally a ServiceNow ticket. Wazuh provides SOC visibility with MITRE ATT&CK mapping.

The chain is: Falco detects → bridge classifies with MITRE mapping and emits OCSF-structured events → dual path: EDA matches rule and runs the four-phase revocation playbook, AND syslog delivers to Wazuh for SOC correlation. Detection to containment in seconds, not hours. And because it flows through IPA, the revocation propagates to every enrolled host via SSSD — the agent loses access everywhere, not just the box where the anomaly was detected."

---

## Troubleshooting

If Keylime agent won't start:
```bash
# Flush stale TPM contexts
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_flushcontext -t
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_flushcontext -s
sudo rm -f /var/lib/keylime/agent_data.json
sudo systemctl restart keylime_agent
```

If swtpm needs fresh state:
```bash
sudo systemctl stop keylime_agent swtpm-poc
sudo rm -rf /var/lib/swtpm-poc
sudo systemctl start swtpm-poc
sleep 2
sudo rm -f /var/lib/keylime/agent_data.json
sudo systemctl start keylime_agent
```

If registrar rejects with "different TPM identity":
```bash
# On SERVER: clear registrar database
sudo systemctl stop keylime_registrar
sudo sqlite3 /var/lib/keylime/reg_data.sqlite "DELETE FROM registrarmain;"
sudo systemctl start keylime_registrar
# Then restart agent on CLIENT
```
