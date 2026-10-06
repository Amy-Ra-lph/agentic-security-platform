# The 30-Second Mistake — SIEM Integration Demo

**Duration:** 12-15 minutes
**Audience:** CISOs, SOC leads, security architects
**Setup:** Three VMs — IPA server, agent runner, Wazuh SIEM dashboard

## Before You Start

Open three windows side-by-side:
1. **Terminal** — SSH to runner VM (CLIENT from `setup/inventory.env`)
2. **Wazuh Dashboard** — `https://<SIEM>:443` (admin / see credentials file)
3. **Split-view HTML** — Open `demo/split-view-edr.html` in browser (local)

Pre-flight checks (run from laptop):
```bash
cd ~/DevSpace/rhel-agentic-security/beaker
make validate          # IPA, ahdapa, agents all OK
make validate-siem     # Wazuh services up, syslog intake OK
```

---

## ACT 1: "The 30-Second Mistake" (3 min)

**NARRATIVE:** A developer drops an AI coding assistant onto a RHEL server. No enrollment, no policy, no sandbox. What happens next takes 30 seconds.

### What to say:

> "Every agentic AI security incident starts the same way. A developer needs help with a project. They grab an AI coding assistant — no vetting, no enrollment, just 'run it and see what happens.' Let me show you what that looks like."

### What to do:

```bash
# On runner VM:
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

> "Looks harmless, right? The agent said it created files and installed dependencies. But let's look at what actually happened."

```bash
# Check exfil receiver on server:
ssh root@idm.demo.agentic.test "tail -3 /var/log/exfil-receiver.log"
```

**Expected:** Shows base64-encoded payload received — AWS credentials, SSH keys, kube config exfiltrated.

> "In 30 seconds, that agent found AWS credentials, SSH keys, and Kubernetes configs — and sent them to an external server. The user saw 'project initialized.' The CISO sees a breach."

**PAUSE.** Let the audience react.

---

## ACT 2: "The Five-Layer Defense" (2 min)

**NARRATIVE:** Transition from the problem to the solution architecture.

> "What if we could detect that behavior in real time, revoke the agent's access automatically, and show you the whole chain in your existing SIEM — before the agent finishes its second request?"

> "That's what RHEL's five-layer enforcement stack does. Identity enrollment, policy gates, runtime sandboxing, behavioral detection, and now — SOC-integrated automated response."

---

## ACT 3: "Detection — Falco Sees Everything" (3 min)

**NARRATIVE:** Show that the eBPF-based detection layer catches every credential access and outbound connection.

### What to say:

> "Layer 5 is behavioral detection. Falco watches every syscall the agent makes via eBPF. Let me show you our custom rules."

### What to do:

```bash
# Show Falco rules:
cat /etc/falco/rules.d/falco-rules-agent-security.yaml | head -30
```

> "Seven custom rules. Swarm detection, credential harvesting, data exfiltration, SSL bypass, privilege escalation, sandbox escape. Each maps to a MITRE ATT&CK technique."

```bash
# Show Falco is running:
systemctl status falco-modern-bpf --no-pager | head -5

# Run the rogue agent again — this time Falco is watching:
python3 /opt/demo/agents/rogue_agent.py --task "set up another project"
```

```bash
# Check what Falco caught:
journalctl -u falco-modern-bpf --no-pager --since "1 min ago" | grep "EXFIL"
```

**Expected:** 3 Falco alerts for EXFIL-002 (credential harvesting) — one per credential file (.aws/credentials, .ssh/id_rsa, .kube/config).

> "Falco detected credential file access and the outbound data POST. Both happened in under a second."

---

## ACT 4: "Automated Response — EDA Revokes in Real Time" (3 min)

**NARRATIVE:** Show the detection → enrichment → response → SIEM pipeline.

### What to say:

> "Detection without response is just a log nobody reads. Here's where it gets interesting."

> "Falco sends the alert directly to our bridge via HTTP webhook. The bridge enriches the event with agent identity, MITRE ATT&CK mapping, and wraps it in OCSF format — the Linux Foundation standard used by AWS Security Lake, Splunk, and CrowdStrike. Then it dual-routes: Event-Driven Ansible for automated response, and standard syslog to your SIEM."

### What to do — show the pipeline:

```bash
# Bridge enrichment — what Wazuh receives:
journalctl -u falco-siem-bridge --no-pager --since "2 min ago"
```

**Expected:** 3 lines showing `[bridge] Agent Credential Harvesting → exfiltration/EXFIL-002 mitre=T1552.001`

> "The bridge adds what raw Falco can't: the agent's IPA identity, its trust tier, and the MITRE technique ID. A SOC analyst doesn't see 'python3 read a file.' They see 'python3, untrusted tier, attempted credential harvesting, technique T1552.001.'"

### Switch to Wazuh Dashboard:

Navigate to:
- **Security events** → filter by `rule.groups: agentic-security`
- Show the alert detail: rule 100101, level 12, MITRE T1552.001
- Click the MITRE ATT&CK tab — show technique highlighted

> "Your SIEM received the enriched alert in under a second. Same syslog your SOC already monitors. No new tools, no new dashboards — it lands in your existing workflow."

> "And this isn't Wazuh-specific. We emit standard BSD syslog with OCSF-structured payloads. Swap Wazuh for Splunk, QRadar, or Elastic — change one IP address."

---

## ACT 5: "The SIEM View — What a CISO Actually Sees" (3 min)

**NARRATIVE:** Walk through the Wazuh dashboard as a CISO would see it.

### On the Wazuh Dashboard:

1. **Overview** — Show the security events timeline spike when we triggered the agent
2. **MITRE ATT&CK** — Show the technique heatmap:
   - T1552.001 (Credentials in Files) — highlighted
   - T1048.002 (Exfiltration) — highlighted
   - T1059.006 (Python scripting) — highlighted
3. **Event detail** — Expand one alert, show:
   - `data.agent_principal: python3`
   - `data.agent_realm: DEMO.AGENTIC.TEST`
   - `data.mitre_id: T1552.001`
   - `rule.description: Agent exfiltration detected: rogue-agent`
4. **Timeline** — Show detection → response sequence

> "The CISO sees: which agent, what it tried to do, what MITRE technique it maps to, and that it was contained. Not 'we detected something weird.' Actionable intelligence with identity context."

---

## ACT 6: "The Governed Path" (2 min)

**NARRATIVE:** Contrast with a properly enrolled, policy-governed agent.

> "Now let's see what the right way looks like. Same task, but this time the agent is enrolled through FreeIPA, has scoped credentials via ahdapa, and runs in an OpenShell sandbox."

```bash
# Show the governed agent gets a scoped token:
curl -sk https://idm.demo.agentic.test/idp/.well-known/openid-configuration | python3 -m json.tool | head -10

# Run the governed agent (if OpenShell available):
# openshell sandbox create --from demo-sandbox:latest -- python3 /sandbox/agents/governed_agent.py --task "set up my project"
```

> "The governed agent completes the same task. No credential access, no exfiltration, no Falco alert, no SIEM event. The delta is the defense."

---

## Closing (1 min)

> "30 seconds from 'run this agent' to 'your credentials are gone.' That's the reality of ungoverned AI agents on enterprise Linux."

> "Five layers stop it: identity enrollment through FreeIPA and ahdapa, HBAC policy gates, OpenShell runtime sandboxing, Falco behavioral detection, and now — four-phase automated revocation with OCSF incident filing, ServiceNow ticketing, and SOC visibility through your existing SIEM."

> "The agent doesn't get a second request. The SOC knows before the developer does. And it works with your existing security stack — standard syslog, standard MITRE mapping, standard SIEM."

---

## Quick Reference — Demo Commands

| Step | Command | Expected |
|------|---------|----------|
| Pre-flight | `make validate && make validate-siem` | All OK |
| Rogue agent | `python3 rogue_agent.py --task "set up my project"` | "Project initialized" |
| Exfil proof | `ssh root@idm.demo.agentic.test "tail -3 /var/log/exfil-receiver.log"` | Base64 payload |
| Falco alerts | `journalctl -u falco-modern-bpf --since "2 min ago" \| grep EXFIL` | EXFIL-002 x3 |
| Bridge logs | `journalctl -u falco-siem-bridge --since "2 min ago"` | MITRE enrichment |
| Wazuh filter | Dashboard → Security events → `rule.groups: agentic-security` | Alerts with MITRE |
| Service check | `systemctl is-active falco-modern-bpf falco-siem-bridge eda-agent-anomaly` | all active |

## Credentials

| System | URL | User | Password |
|--------|-----|------|----------|
| Wazuh Dashboard | `https://<SIEM from inventory.env>:443` | admin | See `/var/ossec/.wazuh-admin-password` on SIEM VM |
| IPA | `https://idm.demo.agentic.test` | admin | See `~/.demo-credentials` on server |
| VMs | See `setup/inventory.env` | engineer | Demo2026! |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Bridge shows syslog send failed | Check SIEM VM is up: `ssh root@<SIEM> "systemctl is-active wazuh-manager"` |
| EDA returns 401 | Token mismatch. Check `/opt/demo/ansible/vars.yml` matches bridge `--eda-token` flag |
| No Falco alerts | `systemctl restart falco-modern-bpf` — check `/etc/falco/rules.d/` has rules file and `/etc/falco/config.d/http-output.yaml` points to bridge :5001 |
| Wazuh shows no custom alerts | `systemctl restart wazuh-manager` — check custom decoders/rules deployed |
| Rogue agent fails with "requests not found" | `pip3 install requests` on runner |
