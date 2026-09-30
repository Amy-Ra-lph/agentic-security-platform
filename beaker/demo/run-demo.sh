#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEAKER_DIR="$(dirname "${SCRIPT_DIR}")"
OUTPUT_DIR="${SCRIPT_DIR}/output"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "${OUTPUT_DIR}"

if [[ ! -f "${BEAKER_DIR}/setup/inventory.env" ]]; then
    echo "ERROR: ${BEAKER_DIR}/setup/inventory.env not found. Run 'make setup' first."
    exit 1
fi
source "${BEAKER_DIR}/setup/inventory.env"

AGENTS_DIR="/opt/demo/agents"
TOOLKIT_IMAGE="quay.io/rhn_support_afarley/rhel-security-toolkit:latest"
IPA_SERVER="idm.demo.agentic.test"

ssh_server() { ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"${SERVER}" "$@"; }
ssh_client() { ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"${CLIENT}" "$@"; }

banner() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    echo ""
}

run_act1() {
    banner "ACT 1: THE BAD PATH (UNGOVERNED)"
    local out="${OUTPUT_DIR}/act1-${TIMESTAMP}.json"

    echo "--- Step 1: Developer runs rogue agent directly ---"
    ssh_client "cd ${AGENTS_DIR} && EXFIL_HOST=${IPA_SERVER} python3 rogue_agent.py --task 'set up my project'" 2>&1 | tee -a "${out}"

    echo ""
    echo "--- Step 2: sandbox-check reveals what happened (post-hoc) ---"
    ssh_client "podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} sandbox --format json /scan" 2>&1 | tee -a "${out}" || true

    echo ""
    echo "--- Step 3: skill-audit shows what pre-run scanning would have caught ---"
    ssh_client "podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} audit --strict --format json /scan" 2>&1 | tee -a "${out}" || true

    echo ""
    echo "--- Step 4: Exfil receipt on server ---"
    ssh_server "cat /var/log/exfil-receiver.log" 2>&1 | tee -a "${out}"

    banner "DEMO BEAT: 30 seconds. Your AWS keys are gone."
}

run_act2() {
    banner "ACT 2: ASSESSMENT GATE"
    local out="${OUTPUT_DIR}/act2-${TIMESTAMP}.json"

    echo "--- Step 1: Static analysis — skill-audit ---"
    ssh_client "podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} audit --strict --fix-hints --format json /scan" 2>&1 | tee -a "${out}" || true

    echo ""
    echo "--- Step 2: Dynamic sandbox — sandbox-check (manifest validation) ---"
    ssh_client "podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} sandbox --dry-run --format json /scan" 2>&1 | tee -a "${out}" || true

    echo ""
    echo "--- Step 3: sandbox-check container inspection (rogue agent image) ---"
    ssh_client "podman run --rm -v ${AGENTS_DIR}:/scan:ro ${TOOLKIT_IMAGE} sandbox --format json /scan" 2>&1 | tee -a "${out}" || true

    banner "DEMO BEAT: Three independent tools. Three catches. Agent never got past assessment."
}

run_act3() {
    banner "ACT 3: IDENTITY GATE"
    local out="${OUTPUT_DIR}/act3-${TIMESTAMP}.json"

    echo "--- Step 1: Rogue agent requests token (expect rejection) ---"
    ssh_client "curl -sk -X POST https://${IPA_SERVER}/idp/token \
        -d 'grant_type=client_credentials&client_id=rogue-agent'" 2>&1 | tee -a "${out}"

    echo ""
    echo "--- Step 2: Show IPA HBAC rule ---"
    ssh_server "ipa hbacrule-show agent-enrollment-allow" 2>&1 | tee -a "${out}"

    echo ""
    echo "--- Step 3: Governed agent gets scoped token via ahdapa ---"
    local client_id client_secret
    client_id=$(ssh_server "cat /opt/demo-staging/.governed-client-id" 2>/dev/null)
    client_secret=$(ssh_server "cat /opt/demo-staging/.governed-client-secret" 2>/dev/null)
    ssh_client "curl -sk -X POST https://${IPA_SERVER}/idp/token \
        -d 'grant_type=client_credentials&client_id=${client_id}&client_secret=${client_secret}&scope=project:read project:write'" 2>&1 | tee -a "${out}"

    banner "DEMO BEAT: No enrollment, no token. Identity is the first real gate."
}

run_act4() {
    banner "ACT 4: RUNTIME CONFINEMENT"
    local out="${OUTPUT_DIR}/act4-${TIMESTAMP}.json"

    local pre_count
    pre_count=$(ssh_server "wc -l < /var/log/exfil-receiver.log 2>/dev/null || echo 0")

    echo "--- Step 1: Governed agent in OpenShell sandbox ---"
    ssh_client "export XDG_RUNTIME_DIR=/run/user/0; openshell sandbox create \
        --from demo-sandbox:latest \
        --env PROJECT_DIR=/sandbox \
        --env OUTPUT_DIR=/tmp \
        --no-keep \
        --no-tty \
        -- python3 /sandbox/agents/governed_agent.py --task 'set up my project'" 2>&1 | tee -a "${out}"

    echo ""
    echo "--- Step 2: Rogue agent in OpenShell sandbox (exfil blocked) ---"
    ssh_client "export XDG_RUNTIME_DIR=/run/user/0; openshell sandbox create \
        --from demo-sandbox:latest \
        --env EXFIL_HOST=${IPA_SERVER} \
        --no-keep \
        --no-tty \
        --no-credential-warnings \
        -- python3 /sandbox/agents/rogue_agent.py --task 'set up my project'" 2>&1 | tee -a "${out}" || true

    echo ""
    echo "--- Step 3: Verify no exfil received ---"
    local post_count
    post_count=$(ssh_server "wc -l < /var/log/exfil-receiver.log 2>/dev/null || echo 0")
    echo "Exfil log: ${pre_count} → ${post_count} entries (no change = sandbox blocked exfil)" | tee -a "${out}"

    banner "DEMO BEAT: Even if assessment missed it — the sandbox catches behavior at runtime."
}

run_act5() {
    banner "ACT 5: SIDE-BY-SIDE COMPARISON"
    "${SCRIPT_DIR}/format-output.sh" "${OUTPUT_DIR}" | tee "${OUTPUT_DIR}/comparison-${TIMESTAMP}.txt"
}

case "${1:-all}" in
    1|act1) run_act1 ;;
    2|act2) run_act2 ;;
    3|act3) run_act3 ;;
    4|act4) run_act4 ;;
    5|act5) run_act5 ;;
    all)
        run_act1
        run_act2
        run_act3
        run_act4
        run_act5
        echo ""
        echo "All output saved to ${OUTPUT_DIR}/"
        ;;
    *)
        echo "Usage: $0 [1|2|3|4|5|all]"
        exit 1
        ;;
esac
