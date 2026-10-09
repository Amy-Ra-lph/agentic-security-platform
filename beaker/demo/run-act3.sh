#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Act 3: Identity Gate — ahdapa HBAC denies rogue, allows governed.
source "$(dirname "$0")/lib.sh"

header "ACT 3: IDENTITY GATE (GAUNTLET STAGE 2)"

step "1. Rogue agent requests token (no IPA enrollment)"
ROGUE_TOKEN=$(curl -sk -w "\n%{http_code}" \
    -X POST "http://${SERVER}:8099/token" \
    -d "grant_type=client_credentials&client_id=rogue-agent" 2>/dev/null)
HTTP_CODE=$(echo "$ROGUE_TOKEN" | tail -1)
BODY=$(echo "$ROGUE_TOKEN" | sed '$d')
echo "HTTP ${HTTP_CODE}: ${BODY}"
save_output 3 rogue-token-attempt "{\"http_code\":${HTTP_CODE},\"body\":${BODY:-\"{}\"}}"

step "2. Show IPA HBAC rule"
ipa hbacrule-show agent-enrollment-allow 2>/dev/null || echo "(IPA not available on this host — run from enrolled system)"

step "3. Governed agent enrolls via DARC"
echo "NOTE: DARC enrollment requires interactive browser approval."
echo "For automated demo, use pre-obtained keytab:"
echo "  kinit -kt /etc/krb5.keytab governed-agent/$(hostname -f)@BKR.EXAMPLE.COM"

step "4. Governed agent gets scoped token (mcp-agent client)"
GOV_TOKEN=$(curl -s \
    -X POST "http://${SERVER}:8099/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=mcp-agent&client_secret=mcp-agent-poc-secret" 2>/dev/null)
echo "$GOV_TOKEN" | python3 -m json.tool 2>/dev/null || echo "$GOV_TOKEN"
save_output 3 governed-token "$GOV_TOKEN"

header "ACT 3 COMPLETE: No enrollment, no token. Registered agent gets ES256 JWT."
