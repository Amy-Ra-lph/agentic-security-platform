# Demo Script: Attestation Only (L0 — Keylime)

**For:** Lukas Vrabec  
**Duration:** ~10 minutes  
**Format:** SAY/DO walk-through  
**See also:** `demo-selinux-attestation.md` — full stack demo (L0 + L4b + L5)  
**VMs:**  
- **SERVER** — `kvm-08-guest03.lab.eng.rdu2.dc.redhat.com` (Keylime verifier + registrar)  
- **CLIENT** — `dell-r640-094-vm-01.bkr.lab.eng.rdu2.dc.redhat.com` (Keylime agent + swtpm)  
- **Login:** `engineer` / `Demo2026!` (passwordless sudo)

---

## What This Shows

Keylime remote attestation on RHEL 10: a Rust agent backed by a software TPM (swtpm) registers with a central verifier/registrar. The TPM provides cryptographic proof of system integrity via Platform Configuration Registers (PCRs).

---

## Step 1: Agent Is Running

**SAY:** "We have Keylime running across two VMs — the verifier and registrar on SERVER, the Rust agent on CLIENT backed by a software TPM."

**DO:** SSH into CLIENT:
```bash
ssh engineer@dell-r640-094-vm-01.bkr.lab.eng.rdu2.dc.redhat.com
```

**DO:** Show agent status:
```bash
sudo systemctl status keylime_agent --no-pager
```

**SAY:** "Agent registered with the verifier using the TPM's Endorsement Key. Listening on port 9002."

---

## Step 2: Software TPM

**DO:** Show swtpm backing the agent:
```bash
sudo systemctl status swtpm-poc --no-pager
```

**DO:** Prove TPM is functional — read random bytes:
```bash
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_getrandom 8 --hex
```

**SAY:** "swtpm provides the same TPM 2.0 API as hardware. In production you'd use the built-in TPM chip — same agent binary, same protocol."

---

## Step 3: Registration Verified

**SAY:** "Let's confirm registration on the server side."

**DO:** SSH into SERVER (second terminal):
```bash
ssh engineer@kvm-08-guest03.lab.eng.rdu2.dc.redhat.com
```

**DO:** Query registrar database:
```bash
sudo sqlite3 /var/lib/keylime/reg_data.sqlite "SELECT agent_id, active FROM registrarmain;"
```

**SAY:** "Agent UUID is registered and active. The verifier can now request quotes from this agent's TPM."

---

## Step 4: PCR Values (Integrity Measurement)

**DO:** On CLIENT, read current PCR values:
```bash
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_pcrread sha256:0,1,2,3,7
```

**SAY:** "These PCR values represent boot chain measurements. In production with hardware TPM, these reflect actual firmware, bootloader, and kernel state. The verifier checks they haven't changed — that's remote attestation. If someone modifies the boot chain, PCR values change, verifier detects it."

---

## Step 5: SELinux Integration Point

**DO:** Show the Keylime agent's SELinux context:
```bash
ps -eZ | grep keylime_agent | head -3
ls -Z /usr/bin/keylime_agent
```

**SAY:** "Notice `keylime_agent_exec_t` on the binary — SELinux enforces a domain transition when systemd launches it. The agent runs in `keylime_agent_t`, a restricted domain. This is where attestation meets SELinux: even the attestation agent itself is confined by mandatory access control."

---

## How It Fits

**SAY:** "Attestation is Layer 0 — the foundation. Before any agent gets credentials or runs workloads, the platform proves its integrity. If the verifier detects tampering, the detection pipeline (Falco → EDA) can automatically revoke the compromised host's agent identities through IPA. Hardware root of trust → identity revocation in seconds."

---

## Troubleshooting

If Keylime agent won't start:
```bash
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
# On SERVER:
sudo systemctl stop keylime_registrar
sudo sqlite3 /var/lib/keylime/reg_data.sqlite "DELETE FROM registrarmain;"
sudo systemctl start keylime_registrar
# Then restart agent on CLIENT
```
