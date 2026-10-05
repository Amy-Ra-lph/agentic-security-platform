#!/usr/bin/env bash
# Set up Keylime verifier + registrar on the SERVER VM.
# Run AFTER setup-server.sh (IPA must be installed first).
# Idempotent — safe to re-run.
set -euo pipefail

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── 1. Install Keylime server components ────────────────────────────────────

log "Installing Keylime verifier + registrar..."
dnf install -y keylime-verifier keylime-registrar 2>/dev/null || true

# ── 2. Configure registrar: bind 0.0.0.0, no EK cert validation ────────────

mkdir -p /etc/keylime/registrar.conf.d

cat > /etc/keylime/registrar.conf.d/poc.conf << 'EOF'
[registrar]
ip = "0.0.0.0"
signed_attributes = ek_tpm,aik_tpm
EOF

log "Registrar configured (bind 0.0.0.0, no ekcert validation)"

# ── 3. Configure verifier: bind 0.0.0.0 ────────────────────────────────────

mkdir -p /etc/keylime/verifier.conf.d

cat > /etc/keylime/verifier.conf.d/poc.conf << 'EOF'
[verifier]
ip = "0.0.0.0"
registrar_ip = "0.0.0.0"
EOF

log "Verifier configured (bind 0.0.0.0)"

# ── 4. Start services ──────────────────────────────────────────────────────

systemctl enable --now keylime_registrar keylime_verifier
log "Keylime registrar + verifier started"

# ── 5. Verify ───────────────────────────────────────────────────────────────

sleep 3
if systemctl is-active --quiet keylime_registrar && systemctl is-active --quiet keylime_verifier; then
    log "Keylime server components ACTIVE"
    log "  Registrar: port 8890 (http), 8891 (https)"
    log "  Verifier:  port 8881"
else
    log "WARNING: One or more Keylime services failed to start"
    systemctl status keylime_registrar --no-pager || true
    systemctl status keylime_verifier --no-pager || true
fi

log "Keylime server setup complete"
