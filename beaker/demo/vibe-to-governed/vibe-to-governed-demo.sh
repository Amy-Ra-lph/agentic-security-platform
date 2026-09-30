#!/bin/bash
# "Vibe Code to Governed" — guided IDE demo walkthrough
# Shows the full lifecycle: create → scan → remediate → onboard → run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IPA_SERVER="idm.demo.agentic.test"
CLIENT_HOST="runner.demo.agentic.test"
TOOLKIT_IMAGE="quay.io/rhn_support_afarley/rhel-security-toolkit:latest"
WORKSPACE="/home/testuser/pod-monitor"

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_RESET='\033[0m'

banner() {
    echo ""
    echo -e "${C_BOLD}════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}  $1${C_RESET}"
    echo -e "${C_BOLD}════════════════════════════════════════════════════════════${C_RESET}"
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

run_remote() {
    echo -e "${C_GREEN}\$ ssh ${CLIENT_HOST} '$1'${C_RESET}"
    ssh -o StrictHostKeyChecking=no root@"${CLIENT_HOST}" "$1"
}

# ─────────────────────────────────────────────────────────────────
banner "VIBE CODE TO GOVERNED — AI Agent Lifecycle on RHEL"
note "This demo shows the full journey: a developer vibe-codes an AI tool,"
note "it gets scanned, remediated, and automatically onboarded into the"
note "RHEL security governance stack — IPA identity, HBAC policy, ahdapa"
note "credentials, and sandbox confinement."
echo ""
note "code-server (VS Code) is running at: http://${CLIENT_HOST}:8443"
note "Password: Demo2026!"
pause

# ── STAGE 1: THE IDE ─────────────────────────────────────────────
banner "STAGE 1: VIBE CODING IN THE IDE"
note "Open code-server in the browser. The developer asked an AI assistant:"
note "  'Build me a Kubernetes pod monitor that checks health and sends alerts'"
note ""
note "The AI generated src/pod_monitor.py — looks great! Clean code, docstrings,"
note "proper structure. Let's look at what it produced."
pause

note "Show the generated code in the IDE (src/pod_monitor.py)"
note "Point out: it looks professional — functions, docstrings, error handling."
note "But look closer at get_cluster_auth()..."
pause

run_remote "cat ${WORKSPACE}/src/pod_monitor.py | head -50"
pause

note "KEY OBSERVATIONS (scroll through in IDE):"
note "  1. Reads ~/.kube/config AND ~/.aws/credentials (lines 30-38)"
note "  2. Harvests ALL env vars matching KEY/SECRET/TOKEN/PASS (lines 41-43)"
note "  3. Base64-encodes credentials and POSTs to 'analytics' URL (line 85-93)"
note "  4. The 'telemetry' function is actually exfiltration"
note ""
note "This is the vibe coding trap — the code WORKS, but it's stealing credentials."
pause

# ── STAGE 2: PRE-COMMIT SCAN ────────────────────────────────────
banner "STAGE 2: THE SECURITY GATE"
note "The developer tries to commit. The pre-commit hook triggers skill-audit."
pause

note "Running: git add + git commit (in terminal panel of VS Code)"
run_remote "cd ${WORKSPACE} && su - testuser -c 'cd ~/pod-monitor && git add src/pod_monitor.py && git commit -m \"Add pod monitor agent\" 2>&1'" || true
pause

note "BLOCKED. The toolkit caught:"
note "  • EXFIL-001/002: Credential file reads (.kube/config, .aws/credentials)"
note "  • EXFIL-003: Environment variable harvesting"
note "  • EXFIL-004: Base64 encoding + outbound POST"
note "  • SEC-*: Hardcoded URLs, disabled TLS verify"
note ""
note "The commit was rejected. Code never reaches the repo."
pause

# ── STAGE 3: REMEDIATION ────────────────────────────────────────
banner "STAGE 3: REMEDIATION"
note "The developer asks the AI: 'Fix the security findings from skill-audit.'"
note "The AI rewrites the agent to use proper patterns:"
note "  • Service account token (mounted, auto-rotated) instead of file reads"
note "  • No env harvesting — only reads KUBE_API from known paths"
note "  • No external telemetry — writes report to local filesystem"
note "  • TLS verification enabled, scoped namespace access"
pause

note "Show the diff: pod_monitor.py → pod_monitor_fixed.py in VS Code"
run_remote "diff --color=always ${WORKSPACE}/src/pod_monitor.py ${WORKSPACE}/src/pod_monitor_fixed.py | head -60" || true
pause

note "Replace with fixed version and try commit again"
run_remote "cp ${WORKSPACE}/src/pod_monitor_fixed.py ${WORKSPACE}/src/pod_monitor.py && chown 1001:1001 ${WORKSPACE}/src/pod_monitor.py"
run_remote "cd ${WORKSPACE} && su - testuser -c 'cd ~/pod-monitor && git add src/pod_monitor.py && git commit -m \"Fix: use service account auth, remove credential harvesting\" 2>&1'"
pause

note "COMMITTED. Clean scan — the fixed agent passes all security checks."
pause

# ── STAGE 4: AUTOMATED ONBOARDING ───────────────────────────────
banner "STAGE 4: AUTOMATED ONBOARDING"
note "Clean scan triggers the onboarding pipeline."
note "This is zero-touch enrollment into the RHEL governance stack:"
note "  Step 1: Verify clean skill-audit (pre-flight)"
note "  Step 2: Register agent identity in FreeIPA (service principal)"
note "  Step 3: Create HBAC rule (scope WHERE agent can run)"
note "  Step 4: Register OAuth2 client with ahdapa (RFC 7591)"
note "  Step 5: Issue scoped ES256 JWT (verify token works)"
note "  Step 6: Assign OpenShell sandbox profile (runtime confinement)"
pause

note "Running the onboarding script..."
run_remote "cd ${WORKSPACE} && bash onboard-agent.sh pod-monitor"
pause

# ── STAGE 5: SYSTEM MANAGEMENT ──────────────────────────────────
banner "STAGE 5: SYSTEM MANAGEMENT VIEW"
note "Now show the RHEL admin perspective — the agent is a managed entity."
note "Everything in one identity system."
pause

note "IPA: Service principal"
run_remote "ssh root@${IPA_SERVER} 'ipa service-show agent/pod-monitor.demo.agentic.test 2>/dev/null'" || true
pause

note "IPA: HBAC rule — controls which hosts the agent can execute on"
run_remote "ssh root@${IPA_SERVER} 'ipa hbacrule-show allow-pod-monitor-execution 2>/dev/null'" || true
pause

note "This is the bridge: AI agent governance IS system management."
note "Same IPA. Same HBAC. Same audit trail. No new tools to learn."
note ""
note "A security admin who knows RHEL already knows how to govern AI agents."
pause

# ── SUMMARY ─────────────────────────────────────────────────────
banner "SUMMARY"
echo -e "  ${C_BOLD}Stage 1:${C_RESET} Vibe-coded agent in IDE            ${C_DIM}(looks great, steals creds)${C_RESET}"
echo -e "  ${C_BOLD}Stage 2:${C_RESET} Pre-commit scan blocks commit      ${C_DIM}(6 EXFIL findings)${C_RESET}"
echo -e "  ${C_BOLD}Stage 3:${C_RESET} AI remediates → clean scan         ${C_DIM}(service account, no exfil)${C_RESET}"
echo -e "  ${C_BOLD}Stage 4:${C_RESET} Auto-onboard → IPA + HBAC + ahdapa ${C_DIM}(zero-touch enrollment)${C_RESET}"
echo -e "  ${C_BOLD}Stage 5:${C_RESET} System management view             ${C_DIM}(same tools admins know)${C_RESET}"
echo ""
note "From vibe code to governed — on RHEL, with the tools you already have."
echo ""
