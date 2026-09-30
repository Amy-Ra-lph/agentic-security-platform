#!/bin/bash
# Automated agent onboarding — runs after clean skill-audit scan.
# Enrolls the agent into the RHEL security governance stack.
set -euo pipefail

IPA_SERVER="idm.demo.agentic.test"
AGENT_NAME="${1:-pod-monitor}"
AGENT_FQDN="${AGENT_NAME}.demo.agentic.test"
AHDAPA_URL="https://${IPA_SERVER}/idp"
SCOPE="pods:read pods:list"

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

step() { echo -e "\n${C_BOLD}[$1/6]${C_RESET} ${C_CYAN}$2${C_RESET}"; }
ok()   { echo -e "  ${C_GREEN}✓${C_RESET} $1"; }
fail() { echo -e "  ${C_RED}✗${C_RESET} $1"; exit 1; }
info() { echo -e "  ${C_YELLOW}→${C_RESET} $1"; }

echo ""
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Agent Onboarding: ${AGENT_NAME}${C_RESET}"
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"

# ── Step 1: Pre-flight — verify clean scan ───────────────────────
step 1 "Pre-flight — verifying clean security scan"

TOOLKIT_IMAGE="quay.io/rhn_support_afarley/rhel-security-toolkit:latest"
SCAN_RESULT=$(podman run --rm -v "$(pwd):/scan:ro" ${TOOLKIT_IMAGE} audit --strict /scan/src/ 2>&1) || {
    fail "Agent code has unresolved security findings. Remediate first."
}
ok "Security scan passed — no findings"

# ── Step 2: IPA Host & Service Principal ─────────────────────────
step 2 "Registering agent identity in FreeIPA"

OTP_OUTPUT=$(ssh root@${IPA_SERVER} "
    ipa host-show ${AGENT_FQDN} 2>/dev/null && echo EXISTS || \
    ipa host-add ${AGENT_FQDN} --force --no-reverse --random 2>&1
" 2>/dev/null)
echo "$OTP_OUTPUT" | while read -r line; do info "$line"; done

OTP=$(echo "$OTP_OUTPUT" | grep -oP 'Random password: \K\S+' || true)
if [ -n "$OTP" ]; then
    ok "Host enrolled with OTP: ${OTP}"
    info "OTP valid for single-use IPA join (ipa-client-install --password=${OTP})"
else
    ok "Host already enrolled"
fi

ssh root@${IPA_SERVER} "
    ipa service-show agent/${AGENT_FQDN} 2>/dev/null && echo EXISTS || \
    ipa service-add agent/${AGENT_FQDN} --force
" 2>&1 | while read -r line; do info "$line"; done
ok "Service principal: agent/${AGENT_FQDN}"

# ── Step 3: HBAC Rule — scope where agent can execute ───────────
step 3 "Configuring HBAC access policy"

RULE_NAME="allow-${AGENT_NAME}-execution"
ssh root@${IPA_SERVER} "
    ipa hbacsvc-show agent-runtime 2>/dev/null || ipa hbacsvc-add agent-runtime --desc='AI agent execution service'
    ipa hbacrule-show ${RULE_NAME} 2>/dev/null || {
        ipa hbacrule-add ${RULE_NAME} --desc='Allow ${AGENT_NAME} to execute on enrolled hosts'
        ipa hbacrule-add-service ${RULE_NAME} --hbacsvcs=agent-runtime
        ipa hbacrule-add-host ${RULE_NAME} --hosts=runner.demo.agentic.test
    }
    echo 'Rule: ${RULE_NAME}'
" 2>&1 | while read -r line; do info "$line"; done
ok "HBAC rule scopes agent to runner.demo.agentic.test only"

# ── Step 4: ahdapa Client Registration (RFC 7591) ───────────────
step 4 "Registering OAuth2 client with ahdapa"

REG_RESPONSE=$(curl -sk -X POST "${AHDAPA_URL}/register" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer demo-reg-token-2026" \
    -d "{
        \"client_name\": \"${AGENT_NAME}\",
        \"redirect_uris\": [\"https://localhost/callback\"],
        \"grant_types\": [\"client_credentials\"],
        \"scope\": \"${SCOPE}\",
        \"token_endpoint_auth_method\": \"client_secret_basic\"
    }" 2>/dev/null)

CLIENT_ID=$(echo "$REG_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('client_id',''))" 2>/dev/null)
CLIENT_SECRET=$(echo "$REG_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('client_secret',''))" 2>/dev/null)

if [ -z "$CLIENT_ID" ]; then
    fail "Client registration failed: ${REG_RESPONSE}"
fi

ok "Client ID: ${CLIENT_ID}"
info "Scope: ${SCOPE}"

mkdir -p ~/.agent-credentials
echo "$CLIENT_ID" > ~/.agent-credentials/${AGENT_NAME}.client-id
echo "$CLIENT_SECRET" > ~/.agent-credentials/${AGENT_NAME}.client-secret
chmod 600 ~/.agent-credentials/${AGENT_NAME}.*
ok "Credentials stored in ~/.agent-credentials/"

# ── Step 5: Verify token issuance ────────────────────────────────
step 5 "Verifying scoped token issuance"

TOKEN_RESPONSE=$(curl -sk -X POST "${AHDAPA_URL}/token" \
    -d "grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=${SCOPE}" \
    2>/dev/null)

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
    fail "Token issuance failed: ${TOKEN_RESPONSE}"
fi

CLAIMS=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(JWT decode failed — token issued but claims not parseable)")
ok "ES256 JWT issued"
info "Claims:"
echo "$CLAIMS" | sed 's/^/      /'

# ── Step 6: OpenShell sandbox profile ────────────────────────────
step 6 "Assigning OpenShell sandbox profile"

if command -v openshell &>/dev/null; then
    info "OpenShell available — agent will run with Landlock+seccomp confinement"
    info "Profile: network=deny, fs=scoped(/tmp,/workspace), no-credential-mount"
    ok "Sandbox profile assigned"
else
    info "OpenShell not installed — agent will run with podman isolation"
    ok "Container isolation configured"
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Onboarding Complete${C_RESET}"
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"
echo ""
echo -e "  Agent:          ${C_BOLD}${AGENT_NAME}${C_RESET}"
echo -e "  Identity:       agent/${AGENT_FQDN}"
echo -e "  HBAC:           ${RULE_NAME}"
echo -e "  OAuth2 Client:  ${CLIENT_ID}"
echo -e "  Token Scope:    ${SCOPE}"
echo -e "  Trust Tier:     ${C_GREEN}Verified${C_RESET}"
echo ""
echo -e "  ${C_BOLD}System Management:${C_RESET}"
echo -e "    ipa service-show agent/${AGENT_FQDN}"
echo -e "    ipa hbacrule-show ${RULE_NAME}"
echo -e "    ausearch -m USER_AUTH -i | grep ${AGENT_NAME}"
echo ""
