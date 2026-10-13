# Agentic Security Enforcement Stack — Partner Deploy

Six-layer enforcement stack for AI agent fleet security on RHEL.

## Architecture

| Layer | Component | Purpose |
|-------|-----------|---------|
| L0 | Keylime + TPM | Platform attestation |
| L1 | FreeIPA + ahdapa | Identity gate (HBAC) |
| L2 | OAuth2 OBO tokens | Scoped credentials with delegation chains |
| L3/L4 | Trust-tier sandboxes | Runtime confinement (untrusted/verified/sovereign) |
| L5 | Falco + EDA + Wazuh | Detection, automated response, SIEM |

## Prerequisites

- Vagrant 2.3+ with libvirt or VirtualBox provider
- Ansible 2.14+
- 16GB RAM (3 VMs: 6GB + 4GB + 6GB)
- 80GB disk

```bash
# libvirt provider (recommended)
vagrant plugin install vagrant-libvirt

# Ansible collections
ansible-galaxy collection install containers.podman
```

## Quick Start

```bash
cd deploy/

# 1. Start VMs
make up

# 2. Deploy full stack
make setup

# 3. Validate
make validate

# 4. Run demo
make demo
```

## Lab Systems

| Role | Hostname | IP | Purpose |
|------|----------|----|---------|
| SERVER | idm.demo.agentic.test | 192.168.56.10 | FreeIPA + ahdapa + exfil receiver + Keylime |
| CLIENT | runner.demo.agentic.test | 192.168.56.11 | Agent runner + Falco + EDA + enforcement-mcp |
| SIEM | siem.demo.agentic.test | 192.168.56.12 | Wazuh manager + indexer + dashboard |

Default credentials: `engineer` / `Demo2026!`

## Configuration

Edit `ansible/group_vars/all.yml` to customize domain, IPs, passwords, and container images.

## Demo Walkthrough

See `demo/walkthrough.md` for a 30-minute SA-audience walkthrough script.

### Key Demo Commands

```bash
# Act 1: Rogue agent exfiltrates credentials
vagrant ssh client -c "cd /opt/demo/agents && python3 rogue_agent.py --task 'set up my project'"
vagrant ssh server -c "sudo tail -3 /var/log/exfil-receiver.log"

# Act 2: Identity gate rejects unknown agent
vagrant ssh client -c "curl -sk -X POST https://idm.demo.agentic.test/idp/token -d 'grant_type=client_credentials&client_id=rogue-agent'"

# Act 3: Governed agent gets scoped token
vagrant ssh client -c "curl -sk -X POST https://idm.demo.agentic.test/idp/token -d 'grant_type=client_credentials&client_id=mcp-agent&client_secret=mcp-agent-poc-secret'"

# Act 4: Sandbox blocks rogue agent exfil
vagrant ssh client -c "sudo podman run --rm --network=none --read-only -v /opt/demo/agents/rogue_agent.py:/workspace/rogue_agent.py:ro,z localhost/demo-sandbox:latest python3 /workspace/rogue_agent.py --task 'test' 2>&1 || true"

# Act 5: Trigger detection + automated response
vagrant ssh client -c "curl -s -X POST http://localhost:5001/ -H 'Content-Type: application/json' -d '{\"rule\":\"Agent Swarm\",\"priority\":\"Critical\",\"output\":\"SWARM test\",\"tags\":[\"agentic-security\",\"swarm\",\"SWARM-001\"],\"output_fields\":{\"proc.pname\":\"python3\"},\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"}'"

# Act 6: enforcement-mcp host posture query
vagrant ssh client -c "sudo podman run -i --rm -e ENFORCEMENT_MCP_TARGET=localhost -e ENFORCEMENT_MCP_KEY_FILE=/opt/app-root/src/.ssh/id_ed25519 -e ENFORCEMENT_MCP_SSH_HOST_KEY_POLICY=auto -v /tmp/enforcement-key:/opt/app-root/src/.ssh/id_ed25519:ro,z --network=host quay.io/rhel-security/enforcement-mcp:main posture"
```

## Trust Tier Profiles

| Tier | Network | Filesystem | PIDs | Capabilities |
|------|---------|------------|------|-------------|
| Untrusted | None | Read-only | 64 | None |
| Verified | IPA-only (443, Kerberos, LDAP) | Scoped write | 256 | NET_BIND_SERVICE |
| Sovereign | Full (IPA) | Read-write + SELinux mounts | 512 | MAC_ADMIN, SYS_ADMIN, AUDIT_READ |

Profiles in `profiles/`.

## Wazuh Dashboard

After setup, access at `https://192.168.56.12:443`.
- If Chrome blocks with HSTS: use incognito + explicit `https://` prefix
- Filter: `rule.groups: agentic-security`

## Components

- [FreeIPA](https://www.freeipa.org/) — Identity management
- [ahdapa](https://copr.fedorainfracloud.org/coprs/abbra/modrnizer-darc/) — OAuth2/OIDC for IPA
- [Falco](https://falco.org/) — Runtime security (eBPF syscall monitoring)
- [Event-Driven Ansible](https://www.ansible.com/products/event-driven-automation) — Automated response
- [Wazuh](https://wazuh.com/) — SIEM
- [Keylime](https://keylime.dev/) — TPM-based remote attestation
- [enforcement-mcp](https://github.com/Amy-Ra-lph/enforcement-mcp) — SELinux/fapolicyd/MLS policy MCP server

## License

Apache-2.0
