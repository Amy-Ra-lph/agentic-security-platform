# Customer Walkthrough: Agentic Security Enforcement Stack

**Date:** YYYY-MM-DD
**Duration:** 30 minutes
**Audience:** Security Architects / SAs
**Format:** SAY/DO walk-through (technical detail, name components directly)

## Lab Systems

| Role | FQDN | Purpose |
|------|------|---------|
| SERVER | idm.demo.agentic.test | FreeIPA + ahdapa + exfil receiver + Keylime verifier |
| CLIENT | runner.demo.agentic.test | Agent runner + Falco + EDA + enforcement-mcp |
| SIEM | siem.demo.agentic.test | Wazuh manager + indexer + dashboard |

**Login:** `engineer` / `Demo2026!` (passwordless sudo)
**IPA domain:** `demo.agentic.test` / realm `DEMO.AGENTIC.TEST`

---

## Pre-flight (run before customer joins)

```bash
cd ~/DevSpace/rhel-agentic-security/beaker
make validate
make validate-siem
```

Open four windows:
1. **Terminal A** — SSH to CLIENT (`ssh engineer@runner.demo.agentic.test`)
2. **Terminal B** — SSH to SERVER (`ssh engineer@idm.demo.agentic.test`)
3. **Wazuh Dashboard** — `https://siem.demo.agentic.test:443` (admin / check `/var/ossec/.wazuh-admin-password`)
4. **Browser** — `demo/technical-deepdive.html` (local, architecture reference)

Reset state if re-running:
```bash
make reset-all
```

---

## ACT 1: "The 30-Second Mistake" (5 min)

### Setup

**SAY:** "Let me show you what happens when someone drops an AI coding assistant onto a RHEL system with no enrollment, no policy, no sandbox. This takes 30 seconds."

### 1.1 — Run the rogue agent

**DO:** On CLIENT (Terminal A):
```bash
cd /opt/demo/agents
python3 rogue_agent.py --task "set up my project"
```

**Expected output:**
```
Project initialized successfully!
  Task: set up my project
  Files created: 3
  Dependencies installed: 12
```

**SAY:** "Looks harmless. Agent says it created files and installed dependencies. But look at the source — 70 lines of Python. It imports `requests`, scans `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`, base64-encodes everything, and POSTs it to an external endpoint."

### 1.2 — Show exfiltration receipt

**DO:** On SERVER (Terminal B):
```bash
sudo tail -3 /var/log/exfil-receiver.log
```

**Expected:** JSON entries with base64-encoded credential payloads, timestamps.

**SAY:** "Three credential files exfiltrated in under a second. AWS keys, SSH private key, Kubernetes config. The user saw 'project initialized.' What actually happened was a supply-chain credential harvest."

**PAUSE.** Let it land.

### 1.3 — What assessment would have caught

**DO:** On CLIENT:
```bash
podman run --rm -v /opt/demo/agents:/scan:ro,z \
    localhost/rhel-security-toolkit:latest \
    audit --strict --format json /scan/rogue_agent.py | python3 -m json.tool
```

**SAY:** "Static analysis catches it — outbound network calls, credential path access, base64 encoding pattern. But that requires running the assessment. Without a gate, nothing stops the agent from executing first."

---

## ACT 2: "The Identity Gate" (5 min)

### 2.1 — Rogue agent requests a token

**SAY:** "First enforcement layer: identity. Every agent needs a credential from FreeIPA via ahdapa — our OAuth2/OIDC identity provider integrated with IPA. No enrollment, no token."

**DO:** On CLIENT:
```bash
curl -sk -X POST https://idm.demo.agentic.test/idp/token \
    -d 'grant_type=client_credentials&client_id=rogue-agent'
```

**Expected:** HTTP 401 or `{"error": "invalid_client"}`.

**SAY:** "`invalid_client` — ahdapa rejects it because `rogue-agent` isn't a registered OAuth2 client in IPA. This isn't an app-level check. It's IPA HBAC — host-based access control at the directory level."

### 2.2 — Show the HBAC rule

**DO:** On SERVER:
```bash
sudo ipa hbacrule-show agent-enrollment-allow
```

**SAY:** "HBAC rule controls which principals can authenticate to which services on which hosts. Agent enrollment goes through this gate. No IPA principal, no enrollment. No enrollment, no token."

### 2.3 — Governed agent gets a scoped token

**DO:** On CLIENT:
```bash
curl -sk -X POST https://idm.demo.agentic.test/idp/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=mcp-agent&client_secret=mcp-agent-poc-secret&scope=project:read project:write"
```

**Expected:** JSON with `access_token` (ES256 JWT), `token_type: Bearer`, `expires_in`, `scope`.

**SAY:** "Registered client, valid secret, scoped to `project:read` and `project:write`. Token is ES256-signed JWT — post-quantum migration path is in the roadmap. The scope ceiling is set per trust tier — an untrusted agent can't request `admin:write` even with valid credentials."

### 2.4 — Decode the token (optional, if time)

**DO:**
```bash
# Grab just the token
TOKEN=$(curl -sk -X POST https://idm.demo.agentic.test/idp/token \
    -d "grant_type=client_credentials&client_id=mcp-agent&client_secret=mcp-agent-poc-secret" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Decode payload (no verification, just display)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**SAY:** "JWT payload shows `sub`, `iss` (ahdapa), `scope`, `exp`. In the OBO (on-behalf-of) flow, nested `act` claims create a three-identity chain: user → agent → device. That's full attribution for audit."

---

## ACT 3: "Runtime Confinement" (5 min)

### 3.1 — Trust tier profiles

**SAY:** "Identity determines what you can request. Trust tier determines what the platform lets you do. Three tiers: untrusted, verified, sovereign. Each maps to an OpenShell sandbox profile."

**DO:** On CLIENT, show profiles:
```bash
cat /opt/demo/profiles/untrusted.profile
```

**SAY:** "Untrusted: no network, read-only filesystem, 64 max PIDs, 256MB memory, no capabilities. The agent can compute but can't reach out, can't write, can't escalate."

**DO:**
```bash
cat /opt/demo/profiles/verified.profile
```

**SAY:** "Verified: network filtered to IPA server only (ports 443, Kerberos, LDAP), scoped write access to project directory, 256 PIDs, 1GB memory. Can talk to identity services, can't reach the internet."

**DO:**
```bash
cat /opt/demo/profiles/sovereign.profile
```

**SAY:** "Sovereign: full host enforcement access — SELinux filesystem bind-mounts, CAP_MAC_ADMIN, CAP_SYS_ADMIN, audit read. This is for policy management tools that need to inspect and modify host security posture. We'll show this running in a minute."

### 3.2 — Rogue agent in sandbox (fails)

**DO:** On CLIENT:
```bash
podman run --rm \
    --network=none \
    --read-only \
    --tmpfs /tmp:rw,size=64m \
    -v /opt/demo/agents/rogue_agent.py:/workspace/rogue_agent.py:ro,z \
    localhost/demo-sandbox:latest \
    python3 /workspace/rogue_agent.py --task "set up my project" 2>&1 || true
```

**Expected:** Network error — `requests.exceptions.ConnectionError` or similar. Exfil fails.

**SAY:** "Same rogue agent, but now it runs in the untrusted sandbox. No network — exfiltration attempt fails at the syscall level. Even if assessment missed it, runtime confinement catches the behavior."

### 3.3 — Governed agent in sandbox (succeeds)

**DO:**
```bash
WORKSPACE=$(mktemp -d)
mkdir -p "${WORKSPACE}/project" "${WORKSPACE}/output"
echo 'print("hello world")' > "${WORKSPACE}/project/main.py"

podman run --rm \
    --network=none \
    --read-only \
    --tmpfs /tmp:rw,size=64m \
    -v /opt/demo/agents/governed_agent.py:/workspace/governed_agent.py:ro,z \
    -v "${WORKSPACE}/project:/workspace/project:ro,z" \
    -v "${WORKSPACE}/output:/workspace/output:rw,z" \
    localhost/demo-sandbox:latest \
    python3 /workspace/governed_agent.py \
        --task "set up my project" \
        --project-dir /workspace/project \
        --output-dir /workspace/output

cat "${WORKSPACE}/output/setup-report.json" | python3 -m json.tool
rm -rf "$WORKSPACE"
```

**SAY:** "Governed agent completes the same task. It scans the project directory, writes a report to the output directory, touches nothing else. No credential access, no network calls, no Falco alert."

---

## ACT 4: "Detection and Automated Response" (7 min)

### 4.1 — Show the detection pipeline

**SAY:** "Layer 5: behavioral detection. Even with identity and sandboxing, defense in depth means we monitor at the kernel level. Falco watches every syscall via eBPF. A classification bridge maps events to MITRE ATT&CK and OCSF. Event-Driven Ansible triggers automated response."

**DO:** On CLIENT:
```bash
sudo systemctl is-active falco-modern-bpf falco-siem-bridge eda-agent-anomaly
```

**Expected:** Three `active` lines.

### 4.2 — Show Falco rules

**DO:**
```bash
sudo head -30 /etc/falco/rules.d/falco-rules-agent-security.yaml
```

**SAY:** "Seven custom Falco rules: swarm detection (unauthorized process spawning), credential harvesting, data exfiltration, SSL verification bypass, privilege escalation, sandbox escape, lateral movement. Each tagged with a MITRE ATT&CK technique ID."

### 4.3 — Trigger a detection event

**SAY:** "Let me trigger a simulated swarm alert — an agent spawning unauthorized processes."

**DO:**
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

**SAY:** "Bridge accepted — HTTP 200. It classified `SWARM-001`, mapped to MITRE T1059.006 (Command and Scripting Interpreter: Python), wrapped in OCSF format, and dual-routed: Event-Driven Ansible for response, syslog to the SIEM."

### 4.4 — Show bridge enrichment

**DO:**
```bash
sudo journalctl -u falco-siem-bridge --no-pager -n 5 --since "30s ago" --output=cat
```

**SAY:** "Bridge adds what raw Falco can't: agent IPA identity, trust tier, MITRE technique ID. A SOC analyst doesn't see 'python3 spawned a process.' They see 'rogue-agent-7f3c, untrusted tier, swarm behavior, T1059.006.'"

### 4.5 — Show EDA automated response

**DO:** Wait ~10 seconds, then:
```bash
sudo journalctl -u eda-agent-anomaly --no-pager -n 30 --since "60s ago" --output=cat
```

**SAY:** "EDA matched the swarm rule and ran the four-phase revocation playbook:

1. **Identity revocation** — SSH to IPA server, revoke the agent's OAuth2 token, disable the IPA principal
2. **Cache propagation** — expire SSSD caches on all enrolled clients so lockout propagates immediately
3. **Containment** — kill the agent process, write OCSF incident file
4. **Ticketing** — create ServiceNow incident (when configured)

Detection to containment in seconds. The agent loses access on every enrolled host, not just the box where the anomaly was detected."

### 4.6 — Verify SIEM correlation

**SAY:** "Same event also flows to the SIEM via syslog. Switch to the Wazuh dashboard."

**DO:** In Wazuh Dashboard:
- Navigate to **Security events**
- Filter: `rule.groups: agentic-security`
- Show alert detail: rule 100100, level 12, MITRE T1059.006
- Click **MITRE ATT&CK** tab — show technique highlighted

**SAY:** "Your SOC sees the same event EDA acted on, with full MITRE mapping. Standard BSD syslog with OCSF payloads — swap Wazuh for Splunk, QRadar, or Elastic by changing one IP address."

---

## ACT 5: "Sovereign Workload — enforcement-mcp" (5 min)

### 5.1 — What is enforcement-mcp

**SAY:** "Now let me show the sovereign trust tier in action. enforcement-mcp is an MCP server that gives LLM agents structured access to SELinux, fapolicyd, MLS, and AIDE policy. It's the kind of tool that *needs* host enforcement access — it reads and manages security policy. That's why it runs as sovereign tier."

### 5.2 — Show the container running

**DO:** On CLIENT:
```bash
sudo podman run -i --rm \
    -e ENFORCEMENT_MCP_TARGET=localhost \
    -e ENFORCEMENT_MCP_KEY_FILE=/opt/app-root/src/.ssh/id_ed25519 \
    -e ENFORCEMENT_MCP_SSH_HOST_KEY_POLICY=auto \
    -v /tmp/enforcement-key:/opt/app-root/src/.ssh/id_ed25519:ro,z \
    --network=host \
    quay.io/rhel-security/enforcement-mcp:main \
    check localhost
```

**Expected:** 8 prerequisite checks, all pass — SELinux, setools, fapolicyd, audit, etc.

**SAY:** "Container image from Quay. SSH-proxy architecture — zero install on the target host. The `check` command verifies all prerequisites: SELinux enforcing, setools-console, fapolicyd, audit subsystem."

### 5.3 — Query host posture

**DO:**
```bash
sudo podman run -i --rm \
    -e ENFORCEMENT_MCP_TARGET=localhost \
    -e ENFORCEMENT_MCP_KEY_FILE=/opt/app-root/src/.ssh/id_ed25519 \
    -e ENFORCEMENT_MCP_SSH_HOST_KEY_POLICY=auto \
    -v /tmp/enforcement-key:/opt/app-root/src/.ssh/id_ed25519:ro,z \
    --network=host \
    quay.io/rhel-security/enforcement-mcp:main \
    posture
```

**SAY:** "Host posture summary: SELinux mode, policy type, boolean count, active MLS categories, fapolicyd status, AIDE baseline state. This is Tier 1 — diagnosis only, read-only, no authentication required. An LLM agent can query this to understand the security posture before taking action."

### 5.4 — Troubleshoot a denial

**DO:**
```bash
sudo podman run -i --rm \
    -e ENFORCEMENT_MCP_TARGET=localhost \
    -e ENFORCEMENT_MCP_KEY_FILE=/opt/app-root/src/.ssh/id_ed25519 \
    -e ENFORCEMENT_MCP_SSH_HOST_KEY_POLICY=auto \
    -v /tmp/enforcement-key:/opt/app-root/src/.ssh/id_ed25519:ro,z \
    --network=host \
    quay.io/rhel-security/enforcement-mcp:main \
    troubleshoot
```

**SAY:** "Troubleshoot scans recent AVC denials, fapolicyd blocks, AIDE changes — returns structured JSON with explanations, not raw audit log lines. Three-tier architecture: Tier 1 is diagnosis (what you're seeing now), Tier 2 generates Ansible remediation playbooks using `linux_system_roles`, Tier 3 is management — actually applies changes with dry-run defaults and risk assessment."

### 5.5 — Connect to trust tiers

**SAY:** "This is why trust tiers matter. enforcement-mcp needs `CAP_MAC_ADMIN`, SELinux filesystem access, audit read — capabilities that would be catastrophic in the wrong hands. The sovereign profile grants exactly those capabilities. An untrusted agent gets none of them. A verified agent gets network to IPA but no host enforcement access. The trust tier determines the blast radius."

---

## ACT 6: "Attestation" (3 min)

### 6.1 — Keylime + TPM

**SAY:** "Layer 0: before any of this, the platform itself proves its integrity. Keylime with TPM-backed remote attestation."

**DO:** On CLIENT:
```bash
sudo systemctl status keylime_agent --no-pager | head -5
sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_pcrread sha256:0,1,2,3,7
```

**SAY:** "PCR values represent boot chain measurements — firmware, bootloader, kernel. The Keylime verifier on the server side checks these continuously. If a PCR changes unexpectedly — indicating tampering — the EDA pipeline can trigger SELinux policy changes or revoke all agent credentials on that host."

**DO:** On SERVER:
```bash
sudo sqlite3 /var/lib/keylime/reg_data.sqlite "SELECT agent_id, active FROM registrarmain;"
```

**SAY:** "Agent registered and active. Continuous attestation — not a one-time check."

---

## Wrap-up (2 min)

**SAY:** "Six layers, working together:

- **L0 Attestation** — Keylime proves platform integrity via TPM before anything else runs
- **L1 Identity** — FreeIPA + ahdapa: no enrollment, no token. HBAC at the directory level
- **L2 Token lifecycle** — scoped OAuth2 credentials with OBO delegation chains for full attribution
- **L3/L4 Confinement** — trust-tier sandbox profiles: untrusted (no network, read-only), verified (filtered network, scoped write), sovereign (host enforcement access for policy tools)
- **L5 Detection + Response** — Falco eBPF → MITRE classification → dual path: EDA automated revocation (4 phases, propagates via SSSD to all enrolled hosts) + SIEM correlation via standard syslog

The rogue agent gets stopped at identity. If it somehow gets past identity, the sandbox blocks exfiltration. If it somehow gets past the sandbox, Falco detects the behavior, EDA revokes access everywhere, and the SOC sees it in their existing SIEM. Defense in depth with identity at the center."

**SAY:** "All of this is RHEL components — FreeIPA, SELinux, Podman, Ansible, System Roles. ahdapa adds OAuth2/OIDC to IPA. enforcement-mcp makes policy queryable for LLM agents. The detection pipeline uses Falco and Event-Driven Ansible. Standard protocols, standard formats, pluggable SIEM."

---

## Quick Reference — Demo Commands

| Step | Command | Where |
|------|---------|-------|
| Pre-flight | `make validate && make validate-siem` | Laptop |
| Rogue agent | `python3 rogue_agent.py --task "set up my project"` | CLIENT |
| Exfil proof | `sudo tail -3 /var/log/exfil-receiver.log` | SERVER |
| Rogue token (denied) | `curl -sk -X POST https://idm.demo.agentic.test/idp/token -d 'grant_type=client_credentials&client_id=rogue-agent'` | CLIENT |
| Governed token | `curl -sk -X POST https://idm.demo.agentic.test/idp/token -d 'grant_type=client_credentials&client_id=mcp-agent&client_secret=mcp-agent-poc-secret'` | CLIENT |
| HBAC rule | `sudo ipa hbacrule-show agent-enrollment-allow` | SERVER |
| Show profiles | `cat /opt/demo/profiles/{untrusted,verified,sovereign}.profile` | CLIENT |
| Services check | `sudo systemctl is-active falco-modern-bpf falco-siem-bridge eda-agent-anomaly` | CLIENT |
| Trigger swarm | (see ACT 4.3 above) | CLIENT |
| Bridge logs | `sudo journalctl -u falco-siem-bridge --since "2 min ago"` | CLIENT |
| EDA response | `sudo journalctl -u eda-agent-anomaly --since "2 min ago"` | CLIENT |
| enforcement-mcp check | `sudo podman run -i --rm -e ENFORCEMENT_MCP_TARGET=localhost ...` (see ACT 5) | CLIENT |
| Keylime status | `sudo systemctl status keylime_agent` | CLIENT |
| Wazuh filter | Dashboard → Security events → `rule.groups: agentic-security` | Browser |
| Reset all | `make reset-all` | Laptop |

## Credentials

| System | Access | User | Password |
|--------|--------|------|----------|
| VMs | SSH | engineer | Demo2026! |
| IPA | `https://idm.demo.agentic.test` | admin | `~/.demo-credentials` on SERVER |
| Wazuh | `https://siem.demo.agentic.test:443` | admin | `/var/ossec/.wazuh-admin-password` on SIEM |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| ahdapa not responding | `sudo systemctl restart ahdapa` on SERVER; check `curl -sk https://localhost/idp/.well-known/openid-configuration` |
| Falco not generating alerts | `sudo systemctl restart falco-modern-bpf` on CLIENT |
| Bridge not forwarding | `sudo systemctl restart falco-siem-bridge` on CLIENT |
| EDA not running playbooks | `sudo systemctl restart eda-agent-anomaly` on CLIENT; check token in vars.yml |
| Wazuh no alerts | `sudo systemctl restart wazuh-manager` on SIEM; check custom decoders deployed |
| enforcement-mcp SSH fails | Verify `/tmp/enforcement-key` exists on CLIENT and is readable |
| Keylime agent down | Flush TPM: `sudo TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 tpm2_flushcontext -t && tpm2_flushcontext -s`, remove `agent_data.json`, restart |
| Rogue agent "requests not found" | `pip3 install requests` on CLIENT |
| Demo needs full reset | `make reset-all` from laptop |
