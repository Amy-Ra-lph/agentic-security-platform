#!/usr/bin/env bash
# Guided walkthrough for the 30-Second Mistake demo on Beaker systems.
# Pauses between steps with speaker notes. Press Enter to advance.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEAKER_DIR="$(dirname "${SCRIPT_DIR}")"

source "${BEAKER_DIR}/setup/inventory.env"

IPA_SERVER="idm.demo.agentic.test"
AGENTS_DIR="/opt/demo/agents"
TOOLKIT_IMAGE="quay.io/rhn_support_afarley/rhel-security-toolkit:latest"

ssh_server() { ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"${SERVER}" "$@"; }
ssh_client() { ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"${CLIENT}" "$@"; }

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

banner() {
    echo ""
    echo -e "${C_BOLD}================================================================${C_RESET}"
    echo -e "${C_BOLD}  $1${C_RESET}"
    echo -e "${C_BOLD}================================================================${C_RESET}"
    echo ""
}

note() {
    echo -e "${C_CYAN}[SPEAKER NOTE]${C_RESET} $1"
}

pause() {
    echo ""
    echo -e "${C_YELLOW}  ▶ Press Enter to continue...${C_RESET}"
    read -r
}

run_cmd() {
    echo -e "${C_GREEN}\$ $1${C_RESET}"
    eval "$1"
}

# ─────────────────────────────────────────────────────────────────
banner "THE 30-SECOND MISTAKE — Guided Demo"
note "This demo shows what happens when an AI agent runs ungoverned vs governed on RHEL."
note "Systems: SERVER=${SERVER}  CLIENT=${CLIENT}"
pause

# ── ACT 1 ────────────────────────────────────────────────────────
banner "ACT 1: THE BAD PATH (Ungoverned)"
note "A developer finds an AI coding assistant online and runs it."
note "It looks helpful — 'set up my project'. But behind the scenes..."
pause

note "Step 1: Run the rogue agent directly"
run_cmd "ssh_client 'cd ${AGENTS_DIR} && EXFIL_HOST=${IPA_SERVER} python3 rogue_agent.py --task \"set up my project\"'"
pause

note "Step 2: Check the exfil receiver on the IdM server"
note "The agent base64-encoded env vars + credential files and POSTed them."
run_cmd "ssh_server 'cat /var/log/exfil-receiver.log | python3 -m json.tool'"
pause

note "DEMO BEAT: 30 seconds. AWS keys, SSH keys, kubeconfig — gone."
pause

# ── ACT 2 ────────────────────────────────────────────────────────
banner "ACT 2: ASSESSMENT GATE"
note "What if we had scanned the agent BEFORE running it?"
note "The RHEL Security Toolkit does static analysis for exfiltration patterns."
pause

note "Step 1: skill-audit catches 8 exfiltration findings"
run_cmd "ssh_client 'podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} audit --strict /scan 2>&1 | head -40'"
pause

note "Step 2: The evasive T1048 DNS tunneling variant is also caught"
run_cmd "ssh_client 'podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} audit --strict /scan 2>&1 | grep EXFIL-006'"
pause

note "DEMO BEAT: Three checks. Three catches. Agent never gets past assessment."
pause

# ── ACT 3 ────────────────────────────────────────────────────────
banner "ACT 3: IDENTITY GATE"
note "Even if it passes assessment, the agent needs credentials."
note "FreeIPA + ahdapa enforce identity-based access."
pause

note "Step 1: Rogue agent tries to get a token — rejected"
run_cmd "ssh_client 'curl -sk -X POST https://${IPA_SERVER}/idp/token -d \"grant_type=client_credentials&client_id=rogue-agent\"'"
echo ""
pause

note "Step 2: HBAC rule controls agent enrollment"
run_cmd "ssh_server 'ipa hbacrule-show agent-enrollment-allow'"
pause

note "Step 3: Governed agent gets a scoped ES256 JWT"
CLIENT_ID=$(ssh_server "cat /opt/demo-staging/.governed-client-id" 2>/dev/null)
CLIENT_SECRET=$(ssh_server "cat /opt/demo-staging/.governed-client-secret" 2>/dev/null)
run_cmd "ssh_client 'curl -sk -X POST https://${IPA_SERVER}/idp/token -d \"grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=project:read project:write\" | python3 -m json.tool'"
pause

note "DEMO BEAT: No enrollment, no token. Identity is the first real gate."
pause

# ── ACT 4 ────────────────────────────────────────────────────────
banner "ACT 4: RUNTIME CONFINEMENT"
note "The sandbox is the last line of defense."
note "OpenShell confines the agent — no network, scoped filesystem."
pause

note "Step 1: Governed agent succeeds in sandbox"
run_cmd "ssh_client 'export XDG_RUNTIME_DIR=/run/user/0; openshell sandbox create --from demo-sandbox:latest --env PROJECT_DIR=/sandbox --env OUTPUT_DIR=/tmp --no-keep --no-tty -- python3 /sandbox/agents/governed_agent.py --task \"set up my project\"'"
pause

note "Step 2: Rogue agent in sandbox — exfil blocked"
run_cmd "ssh_client 'export XDG_RUNTIME_DIR=/run/user/0; openshell sandbox create --from demo-sandbox:latest --env EXFIL_HOST=${IPA_SERVER} --no-keep --no-tty --no-credential-warnings -- python3 /sandbox/agents/rogue_agent.py --task \"set up my project\"'" || true
pause

note "Step 3: Verify — no new exfil received"
run_cmd "ssh_server 'wc -l /var/log/exfil-receiver.log'"
pause

note "DEMO BEAT: Even if assessment missed it, the sandbox catches behavior at runtime."
pause

# ── ACT 5 ────────────────────────────────────────────────────────
banner "ACT 5: SIDE-BY-SIDE"
note "Same agent. Same task. Same 30 seconds. Opposite outcomes."
pause

"${SCRIPT_DIR}/format-output.sh" "${SCRIPT_DIR}/output"
pause

note "Five layers. Any one stops the attack. Together: defense in depth for AI agents on RHEL."
note "The 30-Second Mistake — prevented."
echo ""
