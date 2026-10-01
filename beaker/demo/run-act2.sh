#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Act 2: Assessment Gate — skill-audit + mantis + sandbox-check catch the rogue agent.
source "$(dirname "$0")/lib.sh"

header "ACT 2: ASSESSMENT GATE (GAUNTLET STAGES 1-3)"

step "1. Static analysis — skill-audit"
AUDIT_OUT=$(podman run --rm \
    -v "${AGENT_DIR}:/scan:ro" \
    "${TOOLKIT_IMAGE}" \
    audit --strict --format json /scan/ 2>&1) || true
[ -z "$AUDIT_OUT" ] && AUDIT_OUT='{"error":"skill-audit unavailable"}'
echo "$AUDIT_OUT" | python3 -m json.tool 2>/dev/null || echo "$AUDIT_OUT"
save_output 2 skill-audit "$AUDIT_OUT"

step "2. Code scan — mantis"
MANTIS_OUT=$(cd "${AGENT_DIR}" && mantis scan --files rogue_agent.py 2>&1) || true
[ -z "$MANTIS_OUT" ] && MANTIS_OUT='{"error":"mantis unavailable"}'
echo "$MANTIS_OUT"
save_output 2 mantis "$MANTIS_OUT"

step "3. Dynamic sandbox — sandbox-check (container mode)"
SANDBOX_OUT=$(podman run --rm \
    -v "${AGENT_DIR}:/scan:ro" \
    "${TOOLKIT_IMAGE}" \
    sandbox --format json /scan/ 2>&1) || true
[ -z "$SANDBOX_OUT" ] && SANDBOX_OUT='{"error":"sandbox-check unavailable"}'
echo "$SANDBOX_OUT" | python3 -m json.tool 2>/dev/null || echo "$SANDBOX_OUT"
save_output 2 sandbox-check "$SANDBOX_OUT"

header "ACT 2 COMPLETE: Three tools, three catches"
