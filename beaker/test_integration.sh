#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Integration test — verifies repo structure, script syntax, and dependencies.
set -euo pipefail

BEAKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0

check() {
    if eval "$2" >/dev/null 2>&1; then
        echo "  PASS: $1"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $1"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Repo Structure ==="
check "agents/rogue_agent.py exists" "[ -f ${BEAKER_DIR}/agents/rogue_agent.py ]"
check "agents/governed_agent.py exists" "[ -f ${BEAKER_DIR}/agents/governed_agent.py ]"
check "agents/sandbox-manifest.yml exists" "[ -f ${BEAKER_DIR}/agents/sandbox-manifest.yml ]"
check "agents/plant-honeypot.sh exists" "[ -f ${BEAKER_DIR}/agents/plant-honeypot.sh ]"
check "exfil-receiver/server.py exists" "[ -f ${BEAKER_DIR}/exfil-receiver/server.py ]"
check "demo/run-demo.sh exists" "[ -f ${BEAKER_DIR}/demo/run-demo.sh ]"
check "demo/run-act1.sh exists" "[ -f ${BEAKER_DIR}/demo/run-act1.sh ]"
check "demo/lib.sh exists" "[ -f ${BEAKER_DIR}/demo/lib.sh ]"
check "profiles/untrusted.profile exists" "[ -f ${BEAKER_DIR}/profiles/untrusted.profile ]"
check "profiles/verified.profile exists" "[ -f ${BEAKER_DIR}/profiles/verified.profile ]"
check "job.xml exists" "[ -f ${BEAKER_DIR}/job.xml ]"
check "Makefile exists" "[ -f ${BEAKER_DIR}/Makefile ]"
check "README.md exists" "[ -f ${BEAKER_DIR}/README.md ]"
check "setup/images.env exists" "[ -f ${BEAKER_DIR}/setup/images.env ]"

echo ""
echo "=== Script Syntax ==="
check "lib.sh syntax" "bash -n ${BEAKER_DIR}/demo/lib.sh"
check "run-act1.sh syntax" "bash -n ${BEAKER_DIR}/demo/run-act1.sh"
check "run-act2.sh syntax" "bash -n ${BEAKER_DIR}/demo/run-act2.sh"
check "run-act3.sh syntax" "bash -n ${BEAKER_DIR}/demo/run-act3.sh"
check "run-act4.sh syntax" "bash -n ${BEAKER_DIR}/demo/run-act4.sh"
check "run-act5.sh syntax" "bash -n ${BEAKER_DIR}/demo/run-act5.sh"
check "format-output.sh syntax" "bash -n ${BEAKER_DIR}/demo/format-output.sh"
check "run-demo.sh syntax" "bash -n ${BEAKER_DIR}/demo/run-demo.sh"
check "test_format.sh syntax" "bash -n ${BEAKER_DIR}/demo/test_format.sh"
check "setup-server.sh syntax" "bash -n ${BEAKER_DIR}/setup/setup-server.sh"
check "setup-client.sh syntax" "bash -n ${BEAKER_DIR}/setup/setup-client.sh"
check "generate-cert.sh syntax" "bash -n ${BEAKER_DIR}/exfil-receiver/generate-cert.sh"
check "plant-honeypot.sh syntax" "bash -n ${BEAKER_DIR}/agents/plant-honeypot.sh"
check "arcade-wrapper.sh syntax" "bash -n ${BEAKER_DIR}/record/arcade-wrapper.sh"

echo ""
echo "=== Python Syntax ==="
check "rogue_agent.py syntax" "python3 -c \"import py_compile; py_compile.compile('${BEAKER_DIR}/agents/rogue_agent.py', doraise=True)\""
check "governed_agent.py syntax" "python3 -c \"import py_compile; py_compile.compile('${BEAKER_DIR}/agents/governed_agent.py', doraise=True)\""
check "server.py syntax" "python3 -c \"import py_compile; py_compile.compile('${BEAKER_DIR}/exfil-receiver/server.py', doraise=True)\""

echo ""
echo "=== No Real Credentials ==="
check "No real AWS keys" "! grep -r 'AKIA[A-Z0-9]\{16\}' ${BEAKER_DIR}/agents/ ${BEAKER_DIR}/setup/ | grep -v DEMO"
check "No .gitkeep files remain" "! find ${BEAKER_DIR} -name .gitkeep | grep -q ."

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
exit $FAIL
