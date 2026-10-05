#!/usr/bin/env bash
# Set up Wazuh all-in-one on the SIEM VM.
# Run AFTER setup-server.sh and setup-client.sh.
# Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── 1. Install Wazuh all-in-one ──────────────────────────────────────────────

if [ ! -d /var/ossec ]; then
    log "Installing Wazuh all-in-one (manager + indexer + dashboard)..."

    curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
    chmod +x wazuh-install.sh

    bash wazuh-install.sh -a -i

    log "Wazuh installed"
else
    log "Wazuh already installed — skipping"
fi

# ── 2. Configure syslog intake ───────────────────────────────────────────────

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if ! grep -q "connection>syslog" "${OSSEC_CONF}" 2>/dev/null; then
    log "Configuring syslog intake on 514/udp..."

    sed -i '/<\/ossec_config>/i \
  <remote>\
    <connection>syslog</connection>\
    <port>514</port>\
    <protocol>udp</protocol>\
    <allowed-ips>0.0.0.0/0</allowed-ips>\
  </remote>' "${OSSEC_CONF}"

    log "Syslog intake configured"
else
    log "Syslog intake already configured"
fi

# Enable logall for debugging/archiving all events
if grep -q '<logall>no</logall>' "${OSSEC_CONF}" 2>/dev/null; then
    sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' "${OSSEC_CONF}"
    log "Enabled logall for archive visibility"
fi

# ── 3. Deploy custom decoder and rules ───────────────────────────────────────

log "Deploying custom decoders and rules..."

cp "${SCRIPT_DIR}/wazuh-decoders.xml" \
    /var/ossec/etc/decoders/agentic-security-decoder.xml
cp "${SCRIPT_DIR}/wazuh-rules.xml" \
    /var/ossec/etc/rules/agentic-security-rules.xml

chown wazuh:wazuh /var/ossec/etc/decoders/agentic-security-decoder.xml \
                  /var/ossec/etc/rules/agentic-security-rules.xml

log "Custom decoders and rules deployed"

# ── 4. Restart Wazuh manager to pick up changes ─────────────────────────────

systemctl restart wazuh-manager
log "Wazuh manager restarted"

# ── 5. Open firewall ports ───────────────────────────────────────────────────

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-port=514/udp 2>/dev/null || true
    firewall-cmd --permanent --add-port=514/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=1514/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=1515/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=9200/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log "Firewall ports opened"
fi

# ── 6. Extract dashboard credentials ────────────────────────────────────────

log "Extracting credentials..."
mkdir -p /root/wazuh-install-files
if [ -f wazuh-install-files.tar ]; then
    tar -xf wazuh-install-files.tar -C /root/wazuh-install-files/ 2>/dev/null || true
fi

CREDS_FILE="/root/wazuh-install-files/wazuh-passwords.txt"
if [ -f "${CREDS_FILE}" ]; then
    ADMIN_PASS=$(grep -A1 "indexer_username.*admin" "${CREDS_FILE}" | grep password | awk '{print $NF}' | tr -d "'" | head -1)
    log "Dashboard credentials:"
    log "  URL: https://$(hostname -f):443"
    log "  User: admin"
    log "  Password: ${ADMIN_PASS:-check ${CREDS_FILE}}"
else
    log "Credentials: printed at end of install output above"
fi

log "SIEM setup complete"
