#!/usr/bin/env bash
# Set up Keylime agent on the CLIENT VM with swtpm (software TPM).
# Run AFTER setup-client.sh.
# Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/inventory.env"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

SERVER_IP=$(getent hosts "${SERVER}" | awk '{print $1}' | head -1)
if [[ -z "${SERVER_IP}" ]]; then
    echo "ERROR: Cannot resolve SERVER=${SERVER}"
    exit 1
fi
log "Registrar server: ${SERVER} (${SERVER_IP})"

# ── 1. Install packages ────────────────────────────────────────────────────

log "Installing Keylime agent + swtpm..."
dnf install -y keylime-agent-rust swtpm swtpm-tools tpm2-tools 2>/dev/null || true

# ── 2. Create swtpm systemd service ────────────────────────────────────────

mkdir -p /var/lib/swtpm-poc

cat > /usr/local/bin/swtpm-poc-wrapper.sh << 'WRAPPER'
#!/bin/bash
exec /usr/bin/swtpm socket \
  --tpmstate dir=/var/lib/swtpm-poc \
  --tpm2 \
  --server type=tcp,port=2321,bindaddr=0.0.0.0 \
  --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
  --flags startup-clear
WRAPPER
chmod +x /usr/local/bin/swtpm-poc-wrapper.sh

cat > /etc/systemd/system/swtpm-poc.service << 'EOF'
[Unit]
Description=Software TPM for Keylime PoC
Before=keylime_agent.service

[Service]
Type=simple
ExecStartPre=/bin/bash -c "if [ ! -f /var/lib/swtpm-poc/tpm2-00.permall ]; then mkdir -p /var/lib/swtpm-poc && /usr/bin/swtpm_setup --tpm2 --tpmstate /var/lib/swtpm-poc --overwrite; fi"
ExecStart=/bin/bash /usr/local/bin/swtpm-poc-wrapper.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now swtpm-poc
sleep 2

if ! systemctl is-active --quiet swtpm-poc; then
    log "ERROR: swtpm-poc failed to start"
    journalctl -u swtpm-poc --no-pager -n 5
    exit 1
fi
log "swtpm-poc service active"

# ── 3. Initialize TPM state (if fresh) ─────────────────────────────────────

export TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321
if ! tpm2_getrandom 4 --hex >/dev/null 2>&1; then
    log "ERROR: Cannot communicate with swtpm"
    exit 1
fi
log "swtpm responding (TPM2 functional)"

# ── 4. SELinux: make keylime_agent_t permissive ─────────────────────────────
# keylime_agent_exec_t triggers domain transition to keylime_agent_t,
# which can't connect to unlabeled swtpm TCP ports. Permissive for PoC.

if semanage permissive -l 2>/dev/null | grep -q keylime_agent_t; then
    log "keylime_agent_t already permissive"
else
    semanage permissive -a keylime_agent_t 2>/dev/null || true
    log "keylime_agent_t set to permissive (SELinux)"
fi

# ── 5. Configure agent ─────────────────────────────────────────────────────

mkdir -p /etc/keylime/agent.conf.d

cat > /etc/keylime/agent.conf.d/poc.conf << EOF
[agent]
registrar_ip = "${SERVER_IP}"
ek_handle = "generate"
ip = "0.0.0.0"
EOF

# Disable privilege drop for swtpm TCP access
cat > /etc/keylime/agent.conf.d/001-run_as.conf << 'EOF'
[agent]
run_as = ""
EOF

# Set TCTI environment for systemd service
mkdir -p /etc/systemd/system/keylime_agent.service.d
cat > /etc/systemd/system/keylime_agent.service.d/swtpm.conf << 'EOF'
[Service]
Environment=TCTI=swtpm:host=localhost,port=2321
Environment=TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321
Environment=TSS2_TCTI=swtpm:host=localhost,port=2321
User=
Group=
ExecStart=
ExecStart=/usr/bin/keylime_agent
EOF

systemctl daemon-reload

# ── 6. Clean stale state and start agent ────────────────────────────────────

rm -f /var/lib/keylime/agent_data.json

# Flush any transient TPM objects from previous runs
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true

systemctl enable --now keylime_agent
sleep 6

if systemctl is-active --quiet keylime_agent; then
    log "Keylime agent ACTIVE"
    AGENT_UUID=$(journalctl -u keylime_agent --no-pager -n 20 | grep "Agent UUID" | tail -1 | grep -oP '[a-f0-9-]{36}' || echo "unknown")
    log "  Agent UUID: ${AGENT_UUID}"
    LISTEN=$(journalctl -u keylime_agent --no-pager -n 20 | grep "Listening on" | tail -1 | awk '{print $NF}' || echo "unknown")
    log "  Listening:  ${LISTEN}"
else
    log "ERROR: Keylime agent failed to start"
    journalctl -u keylime_agent --no-pager -n 15
    exit 1
fi

# ── 7. Deploy verifier CA cert for mTLS ────────────────────────────────────────

CV_CA_DIR="/var/lib/keylime/cv_ca"
if [[ ! -f "${CV_CA_DIR}/cacert.crt" ]]; then
    mkdir -p "${CV_CA_DIR}"
    if scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        root@"${SERVER}":/var/lib/keylime/cv_ca/cacert.crt \
        "${CV_CA_DIR}/cacert.crt" 2>/dev/null; then
        log "Deployed verifier CA cert from SERVER"
    else
        log "WARNING: Could not fetch CV CA cert from SERVER"
        log "  Copy manually: scp SERVER:/var/lib/keylime/cv_ca/cacert.crt ${CV_CA_DIR}/"
    fi
fi

# ── 8. Set up SSH key for EDA playbook (CLIENT→SERVER) ────────────────────────

if [[ ! -f /root/.ssh/id_rsa ]] || grep -q "DEMO-CANARY" /root/.ssh/id_rsa.pub 2>/dev/null; then
    ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa -C "eda-automation" -q
    log "Generated SSH key for EDA automation"
fi

if ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 root@"${SERVER}" hostname &>/dev/null; then
    log "SSH to SERVER already works (key deployed)"
else
    log "NOTE: Deploy /root/.ssh/id_rsa.pub to SERVER for EDA playbook:"
    log "  ssh-copy-id root@${SERVER}"
    log "  Or run: make -C beaker setup-ssh-keys"
fi

log "Keylime client setup complete"
