#!/bin/bash
# Reset "Vibe Code to Governed" demo state for re-run.
# Cleans IPA artifacts, ahdapa clients, git state, and credentials.
set -euo pipefail

IPA_SERVER="idm.demo.agentic.test"
AGENT_NAME="${1:-pod-monitor}"
AGENT_FQDN="${AGENT_NAME}.demo.agentic.test"
WORKSPACE="/home/testuser/pod-monitor"

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

step() { echo -e "\n${C_BOLD}[$1/5]${C_RESET} ${C_CYAN}$2${C_RESET}"; }
ok()   { echo -e "  ${C_GREEN}✓${C_RESET} $1"; }
info() { echo -e "  ${C_YELLOW}→${C_RESET} $1"; }

echo ""
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Demo Reset: ${AGENT_NAME}${C_RESET}"
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"

# ── Step 1: Remove IPA artifacts ────────────────────────────────
step 1 "Removing IPA artifacts"

ssh root@${IPA_SERVER} "
    ipa hbacrule-del allow-${AGENT_NAME}-execution 2>/dev/null && echo 'Deleted HBAC rule' || echo 'HBAC rule not found'
    ipa service-del agent/${AGENT_FQDN} 2>/dev/null && echo 'Deleted service principal' || echo 'Service principal not found'
    ipa host-del ${AGENT_FQDN} 2>/dev/null && echo 'Deleted host' || echo 'Host not found'
    ipa hbacsvc-del agent-runtime 2>/dev/null && echo 'Deleted HBAC service' || echo 'HBAC service not found (or shared)'
" 2>&1 | while read -r line; do info "$line"; done
ok "IPA artifacts cleaned"

# ── Step 2: Remove agent credentials ───────────────────────────
step 2 "Removing local credentials"

rm -f ~/.agent-credentials/${AGENT_NAME}.client-id 2>/dev/null
rm -f ~/.agent-credentials/${AGENT_NAME}.client-secret 2>/dev/null
ok "Credentials removed"

# ── Step 3: Reset git state ────────────────────────────────────
step 3 "Resetting git workspace"

if [ -d "${WORKSPACE}" ]; then
    cd "${WORKSPACE}"

    # Restore vulnerable version as src/pod_monitor.py
    if [ -f .reference/pod_monitor_vulnerable.py ]; then
        cp .reference/pod_monitor_vulnerable.py src/pod_monitor.py
        info "Restored vulnerable pod_monitor.py"
    fi

    # Reset git — unstage everything, discard commits on demo branch
    git checkout -- . 2>/dev/null || true
    git clean -fd src/ 2>/dev/null || true

    # Remove any demo commits (keep initial)
    FIRST_COMMIT=$(git rev-list --max-parents=0 HEAD 2>/dev/null)
    if [ -n "$FIRST_COMMIT" ]; then
        git reset "$FIRST_COMMIT" 2>/dev/null || true
        info "Git reset to initial commit"
    fi

    ok "Git workspace reset"
else
    info "Workspace ${WORKSPACE} not found — skipping"
fi

# ── Step 4: Re-stage vulnerable file for demo ──────────────────
step 4 "Staging vulnerable file for pre-commit demo"

if [ -d "${WORKSPACE}" ]; then
    cd "${WORKSPACE}"
    # Ensure vulnerable version is in src/ and unstaged
    if [ -f .reference/pod_monitor_vulnerable.py ]; then
        cp .reference/pod_monitor_vulnerable.py src/pod_monitor.py
        chown testuser:testuser src/pod_monitor.py 2>/dev/null || true
    fi
    ok "Vulnerable pod_monitor.py ready for git add + commit demo"
else
    info "Skipped — workspace not found"
fi

# ── Step 5: Verify clean state ─────────────────────────────────
step 5 "Verifying clean state"

ssh root@${IPA_SERVER} "
    ipa service-show agent/${AGENT_FQDN} 2>/dev/null && echo 'WARNING: service still exists' || echo 'Service: clean'
    ipa hbacrule-show allow-${AGENT_NAME}-execution 2>/dev/null && echo 'WARNING: HBAC rule still exists' || echo 'HBAC: clean'
" 2>&1 | while read -r line; do info "$line"; done
ok "Demo state reset — ready for next run"

echo ""
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Reset Complete${C_RESET}"
echo -e "${C_BOLD}══════════════════════════════════════════════════════${C_RESET}"
echo ""
echo -e "  To re-run the demo:"
echo -e "    1. Open code-server → src/pod_monitor.py (vulnerable)"
echo -e "    2. git add src/ && git commit  → BLOCKED"
echo -e "    3. cp .reference/pod_monitor_fixed.py src/pod_monitor.py"
echo -e "    4. git add src/ && git commit  → PASS"
echo -e "    5. sudo bash onboard-agent.sh pod-monitor"
echo ""
