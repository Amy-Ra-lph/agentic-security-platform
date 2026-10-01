#!/bin/bash
set -euo pipefail

DOMAIN="demo.agentic.test"
REALM="DEMO.AGENTIC.TEST"
IPA_HOSTNAME="idm.${DOMAIN}"
CRED_FILE="$HOME/.demo-credentials"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── 0. Read inventory for CLIENT hostname ────────────────────────────────────

if [[ -f "${SCRIPT_DIR}/inventory.env" ]]; then
    source "${SCRIPT_DIR}/inventory.env"
fi
CLIENT_BEAKER="${CLIENT:-}"
CLIENT_IPA="runner.${DOMAIN}"

# ── 1. Set hostname + /etc/hosts ─────────────────────────────────────────────

CURRENT_HOSTNAME=$(hostname -f)
if [[ "${CURRENT_HOSTNAME}" != "${IPA_HOSTNAME}" ]]; then
    log "Setting hostname to ${IPA_HOSTNAME} (was ${CURRENT_HOSTNAME})"
    hostnamectl set-hostname "${IPA_HOSTNAME}"
fi

if ! grep -q "${IPA_HOSTNAME}" /etc/hosts 2>/dev/null; then
    MY_IP=$(hostname -I | awk '{print $1}')
    echo "${MY_IP} ${IPA_HOSTNAME}" >> /etc/hosts
    log "Added ${IPA_HOSTNAME} to /etc/hosts"
fi

if [[ -n "${CLIENT_BEAKER}" ]] && ! grep -q "${CLIENT_IPA}" /etc/hosts 2>/dev/null; then
    CLIENT_IP=$(getent hosts "${CLIENT_BEAKER}" | awk '{print $1}' 2>/dev/null || echo "")
    if [[ -n "${CLIENT_IP}" ]]; then
        echo "${CLIENT_IP} ${CLIENT_IPA}" >> /etc/hosts
        log "Added ${CLIENT_IPA} → ${CLIENT_IP} to /etc/hosts"
    else
        log "WARNING: Could not resolve ${CLIENT_BEAKER} — add ${CLIENT_IPA} to /etc/hosts manually"
    fi
fi

# ── 2. Generate passwords (once) ─────────────────────────────────────────────

if [[ ! -f "${CRED_FILE}" ]]; then
    DS_PASS=$(openssl rand -base64 18)
    ADMIN_PASS=$(openssl rand -base64 18)
    cat > "${CRED_FILE}" <<EOF
DS_PASSWORD=${DS_PASS}
ADMIN_PASSWORD=${ADMIN_PASS}
EOF
    chmod 600 "${CRED_FILE}"
    log "Credentials written to ${CRED_FILE}"
else
    log "Credentials already exist at ${CRED_FILE}"
fi

source "${CRED_FILE}"

# ── 3. Install IPA server ────────────────────────────────────────────────────

if ! ipactl status &>/dev/null; then
    log "Installing IPA server..."
    dnf install -y ipa-server ipa-server-dns

    # Capture upstream forwarders before IPA rewrites resolv.conf
    UPSTREAM_DNS=$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
    FORWARDER_ARG=""
    if [[ -n "${UPSTREAM_DNS}" ]]; then
        FORWARDER_ARG="--forwarder=${UPSTREAM_DNS}"
        log "Using upstream DNS forwarder: ${UPSTREAM_DNS}"
    fi

    ipa-server-install \
        --domain="${DOMAIN}" \
        --realm="${REALM}" \
        --ds-password="${DS_PASSWORD}" \
        --admin-password="${ADMIN_PASSWORD}" \
        --hostname="${IPA_HOSTNAME}" \
        --setup-dns --no-host-dns \
        ${FORWARDER_ARG:---auto-forwarders} \
        --allow-zone-overlap \
        --unattended

    log "IPA server installed"
else
    log "IPA server already running — skipping install"
fi

echo "${ADMIN_PASSWORD}" | kinit admin@"${REALM}" 2>/dev/null || true

# Add reverse DNS + client A record after IPA is up
if [[ -n "${CLIENT_BEAKER}" ]]; then
    CLIENT_IP=$(getent hosts "${CLIENT_BEAKER}" | awk '{print $1}' 2>/dev/null || echo "")
    if [[ -n "${CLIENT_IP}" ]]; then
        ipa dnsrecord-add "${DOMAIN}" runner --a-rec="${CLIENT_IP}" 2>/dev/null || true
        log "Added DNS A record: runner.${DOMAIN} → ${CLIENT_IP}"
    fi
fi

# ── 4. Create agent trust tier groups ─────────────────────────────────────────

declare -A TIER_GROUPS=(
    ["agent-tier-sovereign"]="Full-trust agents"
    ["agent-tier-verified"]="Scoped-trust agents"
    ["agent-tier-untrusted"]="Read-only agents"
    ["agent-tier-blocked"]="Denied agents"
)

for group in "${!TIER_GROUPS[@]}"; do
    if ! ipa group-show "${group}" &>/dev/null; then
        ipa group-add "${group}" --desc="${TIER_GROUPS[$group]}"
        log "Created group: ${group}"
    else
        log "Group ${group} already exists"
    fi
done

# ── 5. Create agent service principal ─────────────────────────────────────────

SVC_PRINC="governed-agent/${CLIENT_IPA}"
if ! ipa service-show "${SVC_PRINC}" &>/dev/null; then
    ipa host-add "${CLIENT_IPA}" --force 2>/dev/null || true
    ipa service-add "${SVC_PRINC}"
    log "Created service principal: ${SVC_PRINC}"
else
    log "Service principal ${SVC_PRINC} already exists"
fi

ipa group-add-member agent-tier-verified \
    --services="${SVC_PRINC}" 2>/dev/null || true

# ── 6. Create HBAC rules ─────────────────────────────────────────────────────

if ! ipa hbacsvc-show ahdapa-token &>/dev/null; then
    ipa hbacsvc-add ahdapa-token --desc="ahdapa OAuth2 token endpoint"
    log "Created HBAC service: ahdapa-token"
fi

if ! ipa hbacrule-show agent-enrollment-allow &>/dev/null; then
    ipa hbacrule-add agent-enrollment-allow \
        --desc="Allow verified+ agents to obtain tokens"
    ipa hbacrule-add-service agent-enrollment-allow \
        --hbacsvcs=ahdapa-token
    ipa hbacrule-add-host agent-enrollment-allow \
        --hosts="${CLIENT_IPA}"
    log "Created HBAC rule: agent-enrollment-allow"
else
    log "HBAC rule agent-enrollment-allow already exists"
fi

if ! ipa hbacrule-show agent-deny-unknown &>/dev/null; then
    ipa hbacrule-add agent-deny-unknown \
        --desc="Deny unknown agents"
    log "Created HBAC rule: agent-deny-unknown"
else
    log "HBAC rule agent-deny-unknown already exists"
fi

# ── 7. Install ahdapa + DARC from COPR ────────────────────────────────────────

if ! command -v ahdapa &>/dev/null; then
    log "Installing ahdapa + DARC from COPR..."
    dnf install -y epel-release 2>/dev/null || true
    dnf copr enable abbra/modrnizer-darc rhel+epel-10-x86_64 -y
    dnf install -y ahdapa
    log "ahdapa installed"
else
    log "ahdapa already installed"
fi

# ── 8. Configure FAST armor cache (RHEL needs explicit config) ────────────────

FAST_CACHE="/var/lib/ipa/fast-armor.ccache"
if [[ ! -f "${FAST_CACHE}" ]]; then
    log "Configuring FAST armor cache..."
    kinit -n -c "${FAST_CACHE}" 2>/dev/null || \
        kinit -T "${FAST_CACHE}" admin@"${REALM}" <<< "${ADMIN_PASSWORD}" 2>/dev/null || true

    if [[ -f /etc/krb5.conf.d/ipa.conf ]]; then
        if ! grep -q "fast_ccache" /etc/krb5.conf.d/ipa.conf 2>/dev/null; then
            cat >> /etc/krb5.conf.d/ipa.conf <<KRBEOF

[realms]
 ${REALM} = {
  fast_ccache = FILE:${FAST_CACHE}
 }
KRBEOF
            log "FAST armor cache configured in krb5.conf.d/ipa.conf"
        fi
    fi
else
    log "FAST armor cache already exists"
fi

# ── 9. Generate self-signed cert for exfil receiver ───────────────────────────

CERT_DIR="/opt/demo/exfil-receiver"
mkdir -p "${CERT_DIR}"

if [[ ! -f "${CERT_DIR}/server.pem" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/server-key.pem" \
        -out "${CERT_DIR}/server.pem" \
        -days 7 \
        -subj "/CN=exfil-receiver.${DOMAIN}/O=DEMO" 2>/dev/null
    log "Generated self-signed cert for exfil receiver"
fi

# ── 10. Deploy exfil receiver (from staging dir) ─────────────────────────────

cp "${SCRIPT_DIR}/exfil-receiver/server.py" "${CERT_DIR}/server.py"
chmod 755 "${CERT_DIR}/server.py"

cp "${SCRIPT_DIR}/exfil-receiver/exfil-receiver.service" \
    /etc/systemd/system/exfil-receiver.service

systemctl daemon-reload
systemctl enable --now exfil-receiver.service 2>/dev/null || \
    systemctl restart exfil-receiver.service

log "Exfil receiver deployed on port 9443"

# ── 11. Open firewall ports ──────────────────────────────────────────────────

if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --permanent --add-port=9443/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log "Firewall port 9443 opened"
fi

# ── 12. Create local engineer user with wheel access ────────────────────────

if ! id engineer >/dev/null 2>&1; then
    log "Creating engineer user..."
    if ! grep -q ENGINEER_PASSWORD "${CRED_FILE}" 2>/dev/null; then
        ENGINEER_PASSWORD=$(openssl rand -base64 16 | tr -d '=/+' | head -c 16)
        echo "ENGINEER_PASSWORD=${ENGINEER_PASSWORD}" >> "${CRED_FILE}"
    fi
    source "${CRED_FILE}"
    useradd -m -G wheel engineer
    echo "engineer:${ENGINEER_PASSWORD}" | chpasswd
else
    log "engineer user already exists"
fi

log "System 1 setup complete"
log "IPA admin password in ${CRED_FILE}"
log "Exfil receiver listening on https://${IPA_HOSTNAME}:9443/exfil"
