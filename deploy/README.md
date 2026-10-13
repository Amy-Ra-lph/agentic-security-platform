# Agentic Security Enforcement Stack

Six-layer enforcement stack for AI agent fleet security on RHEL.
Deploys a 3-node lab with identity management, runtime confinement,
behavioral detection, automated response, and SIEM correlation.

## Architecture

| Layer | Component | Purpose |
|-------|-----------|---------|
| L0 | Keylime + TPM | Platform attestation — proves host integrity before anything runs |
| L1 | FreeIPA + ahdapa | Identity gate — no IPA enrollment, no token. HBAC at directory level |
| L2 | OAuth2 OBO tokens | Scoped credentials with delegation chains for full attribution |
| L3/L4 | Trust-tier sandboxes | Runtime confinement — untrusted/verified/sovereign profiles |
| L5 | Falco + EDA + Wazuh | eBPF detection → MITRE classification → automated revocation + SIEM |

## Install Guide

### 1. Host machine requirements

| Resource | Minimum |
|----------|---------|
| RAM | 16 GB free (3 VMs use ~16 GB total) |
| Disk | 80 GB free |
| CPU | 4+ cores (VMs share via KVM/VirtualBox) |
| OS | Linux (Fedora, RHEL, Ubuntu) or macOS |
| Network | Internet access during setup (packages, container images) |

### 2. Install dependencies

**Fedora / RHEL / CentOS:**

```bash
# Vagrant + libvirt
sudo dnf install -y vagrant libvirt qemu-kvm virt-manager
sudo systemctl enable --now libvirtd
vagrant plugin install vagrant-libvirt

# Ansible
sudo dnf install -y ansible-core
pip3 install ansible --user    # if ansible-core < 2.14

# Ansible collections
ansible-galaxy collection install containers.podman
```

**Ubuntu / Debian:**

```bash
# Vagrant + libvirt
sudo apt install -y vagrant libvirt-daemon-system qemu-kvm
vagrant plugin install vagrant-libvirt

# Ansible
sudo apt install -y ansible
ansible-galaxy collection install containers.podman
```

**macOS (VirtualBox):**

```bash
brew install --cask vagrant virtualbox
brew install ansible
ansible-galaxy collection install containers.podman
```

### 3. Clone and deploy

```bash
git clone https://github.com/Amy-Ra-lph/agentic-security-platform.git
cd agentic-security-platform/deploy

# Start 3 VMs (downloads CentOS Stream 10 box on first run, ~2 GB)
make up

# Deploy full 6-layer stack (~20-30 min on first run)
make setup

# Verify all components
make validate
```

### 4. Run the demo

```bash
make demo
```

Or run individual acts — see [Demo Walkthrough](#demo-walkthrough) below.

### 5. Access web UIs

| Service | URL | Credentials |
|---------|-----|-------------|
| IPA WebUI | https://192.168.56.10 | admin / (printed during setup) |
| Wazuh Dashboard | https://192.168.56.12:443 | admin / (printed during setup) |

Add to your laptop's `/etc/hosts` if you want to use hostnames:
```
192.168.56.10 idm.demo.agentic.test
192.168.56.12 siem.demo.agentic.test
```

### Troubleshooting install

| Problem | Fix |
|---------|-----|
| `vagrant up` fails with permission error | `sudo usermod -aG libvirt $USER` then log out/in |
| CentOS box download hangs | Check internet; or manually: `vagrant box add centos/stream10` |
| Ansible "unreachable" | `vagrant ssh server` works? Check `vagrant status` shows running |
| IPA install fails | Ensure hostname resolves: `vagrant ssh server -c "hostname -f"` should show `idm.demo.agentic.test` |
| Wazuh install slow | Normal — Wazuh all-in-one downloads ~1 GB. Takes 10-15 min |
| Out of memory | Close other VMs. Edit `Vagrantfile` to reduce memory (min 3GB per VM) |
| `make setup` fails mid-run | Safe to re-run — all roles are idempotent |

### Tear down

```bash
make destroy    # removes all 3 VMs
```

## What gets installed

| Component | Where | What |
|-----------|-------|------|
| FreeIPA server + DNS | server | Identity management, Kerberos, HBAC rules, 4 trust-tier groups |
| ahdapa | server | OAuth2/OIDC identity provider integrated with IPA |
| Exfil receiver | server | Demo prop — logs exfiltrated data on :9443 |
| Keylime verifier | server | TPM-based remote attestation server |
| FreeIPA client | client | Kerberos enrollment, SSSD cache |
| Rogue agent | client | Demo — credential exfiltration script |
| Governed agent | client | Demo — well-behaved agent for comparison |
| Honeypot credentials | client | Fake AWS/SSH/kube creds for exfil demo |
| 3 sandbox profiles | client | untrusted/verified/sovereign confinement specs |
| Falco (eBPF) | client | 7 custom agent security detection rules |
| falco-siem-bridge | client | MITRE ATT&CK classification + OCSF formatting |
| EDA (ansible-rulebook) | client | 4-phase automated revocation playbook |
| enforcement-mcp | client | SELinux/fapolicyd/MLS/AIDE policy MCP server (sovereign tier) |
| Keylime agent + swtpm | client | Software TPM for attestation demo |
| Wazuh all-in-one | siem | Manager + indexer + dashboard + custom decoders/rules |

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
