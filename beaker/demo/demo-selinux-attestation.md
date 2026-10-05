# Demo Script: SELinux + Attestation (L0 + L4b)

**For:** Lukas Vrabec  
**Duration:** ~15 minutes  
**Format:** SAY/DO walk-through  
**VMs:**  
- **SERVER** — `kvm-08-guest03.lab.eng.rdu2.dc.redhat.com` (Keylime verifier + registrar)  
- **CLIENT** — `dell-r640-094-vm-01.bkr.lab.eng.rdu2.dc.redhat.com` (Keylime agent + swtpm + SELinux enforcing)  
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

## Part 3: Tie It Together

**SAY:** "So what we've shown is two layers of the enforcement stack:

1. **L0 Attestation (Keylime)** — the agent proves the system hasn't been tampered with by providing TPM-backed quotes. The verifier on the server validates these continuously.

2. **L4b Blastwall (SELinux)** — mandatory access control compartmentalizes processes. Each service runs in its own domain with least-privilege policies.

In the full architecture spec, these connect through the EDA pipeline:
- Keylime detects integrity violation → EDA event
- SELinux denial on sensitive file → audit event → EDA
- Both converge in Satellite for fleet-wide visibility
- Automated remediation through Ansible"

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
