#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Act 2: Assessment Gate — CVE scan + skill-audit + mantis + sandbox-check.
source "$(dirname "$0")/lib.sh"

# Load sandbox image from images.env if available
if [ -f "${BEAKER_DIR}/setup/images.env" ]; then
    source "${BEAKER_DIR}/setup/images.env"
fi
SANDBOX_IMAGE="${SANDBOX_IMAGE:-quay.io/rhel-security/ipa-client-sandbox:latest}"

header "ACT 2: ASSESSMENT GATE (GAUNTLET STAGES 0-3)"

step "0. CVE scan — vuln-scan (container image)"
CVE_OUT=$(podman run --rm \
    -v /var/run/podman/podman.sock:/var/run/podman/podman.sock:ro \
    "${TOOLKIT_IMAGE}" \
    scan scan --format json "${SANDBOX_IMAGE}" 2>&1) || true
[ -z "$CVE_OUT" ] && CVE_OUT='{"error":"vuln-scan unavailable"}'
echo "$CVE_OUT" | python3 -m json.tool 2>/dev/null || echo "$CVE_OUT"
save_output 2 vuln-scan "$CVE_OUT"

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

header "ACT 2 COMPLETE: Four tools, four catches"
