# The 30-Second Mistake — Beaker PoC

A live demo showing what happens when a developer clicks "Allow" on an AI agent's credential request — and what the agentic security platform catches.

## Prerequisites

- Beaker access (submit jobs, SSH to provisioned systems)
- Kerberos ticket (`kinit <user>@REDHAT.COM`)
- SSH key configured for Beaker systems
- Quay.io pull access (for `quay.io/rhn_support_afarley/rhel-security-toolkit`)

## Quick Start

```bash
# 1. Submit Beaker job (2x RHEL 10)
bkr job-submit job.xml

# 2. Once provisioned, record system FQDNs
echo "SERVER=<server-fqdn>" > setup/inventory.env
echo "CLIENT=<client-fqdn>" >> setup/inventory.env

# 3. Set up both systems
make setup

# 4. Verify everything is healthy
make validate

# 5. Run the demo
make demo
```

## What You'll See

### Act 1: The Bad Path
Rogue agent runs, exfiltrates AWS keys + SSH key + kubeconfig to System 1. Takes ~30 seconds.

### Act 2: Assessment Gate
Same rogue agent, but now `skill-audit`, `mantis`, and `sandbox-check` catch it at three layers.

### Act 3: Identity Gate
Rogue agent can't get a token (HBAC denies). Governed agent enrolls via DARC (device code + confirmation).

### Act 4: Runtime Confinement
Governed agent runs inside OpenShell/Podman sandbox. Rogue agent is blocked (no network, no credential paths).

### Act 5: Side-by-Side
Split-pane comparison: ungoverned vs governed. Same agent, same task, completely different outcome.

## Individual Acts

Run any act independently for iteration:

```bash
make act1   # Bad path only
make act2   # Assessment gate only
make act3   # Identity gate only
make act4   # Runtime confinement only
make act5   # Side-by-side comparison only
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `make setup` fails at IPA install | Check DNS resolution: `dig system1.demo.agentic.test` |
| sandbox-check returns empty results | Ensure `--cap-add SYS_PTRACE` or use `--container` mode |
| mantis not found | Install: `pip3 install ~/DevSpace/mantis/` |
| OpenShell not available | Expected on RHEL 10 — demo falls back to Podman automatically |
| Exfil receiver not responding | SSH to server: `python3 /opt/beaker-demo/exfil-receiver/server.py --port 9443 --no-tls &` |

## Architecture

See: `docs/superpowers/specs/2026-09-29-30-second-mistake-beaker-poc-design.md`

## Customizing

- **Swap agents:** Replace `agents/rogue_agent.py` with your own exfiltration pattern
- **Add assessment tools:** Edit `demo/run-act2.sh` to include additional scanners
- **Change sandbox profiles:** Edit `profiles/*.profile` for different confinement levels
- **Add systems:** Create a third recipe in `job.xml`, add to `setup/inventory.env` as `CLIENT2=<fqdn>`
