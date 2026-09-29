#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Act 2: Assessment Gate — skill-audit + mantis + sandbox-check catch the rogue agent.
source "$(dirname "$0")/lib.sh"

header "ACT 2: ASSESSMENT GATE (GAUNTLET STAGES 1-3)"

step "1. Static analysis — skill-audit"
AUDIT_OUT=$(podman run --rm \
    -v "${AGENT_DIR}:/scan:ro" \
    "${TOOLKIT_IMAGE}" \
    audit --strict --format json /scan/rogue_agent.py 2>/dev/null || echo '{"error":"skill-audit unavailable"}')
echo "$AUDIT_OUT" | python3 -m json.tool 2>/dev/null || echo "$AUDIT_OUT"
save_output 2 skill-audit "$AUDIT_OUT"

step "2. Code scan — mantis"
MANTIS_OUT=$(cd "${AGENT_DIR}" && python3 -m mantis scan --files rogue_agent.py --ci 2>/dev/null || echo '{"error":"mantis unavailable"}')
echo "$MANTIS_OUT"
save_output 2 mantis "$MANTIS_OUT"

step "3. Dynamic sandbox — sandbox-check (container mode)"
SANDBOX_OUT=$(podman run --rm \
    -v "${AGENT_DIR}:/scan:ro" \
    "${TOOLKIT_IMAGE}" \
    sandbox --format json /scan/rogue_agent.py 2>/dev/null || echo '{"error":"sandbox-check unavailable"}')
echo "$SANDBOX_OUT" | python3 -m json.tool 2>/dev/null || echo "$SANDBOX_OUT"
save_output 2 sandbox-check "$SANDBOX_OUT"

header "ACT 2 COMPLETE: Three tools, three catches"
