#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Act 4: Runtime Confinement — OpenShell/Podman sandbox.
source "$(dirname "$0")/lib.sh"

header "ACT 4: RUNTIME CONFINEMENT (GAUNTLET STAGE 5)"

SANDBOX_TOOL="${SANDBOX_TOOL:-$(check_openshell)}"

step "1. Run governed agent in sandbox (${SANDBOX_TOOL})"
WORKSPACE=$(mktemp -d)
mkdir -p "${WORKSPACE}/project" "${WORKSPACE}/output"
echo 'print("hello world")' > "${WORKSPACE}/project/main.py"

if [ "$SANDBOX_TOOL" = "openshell" ]; then
    openshell sandbox create \
        --from localhost/demo-sandbox:latest \
        --policy "${BEAKER_DIR}/profiles/verified.profile" \
        --upload "${AGENT_DIR}/governed_agent.py:/workspace/governed_agent.py" \
        --upload "${WORKSPACE}/project:/workspace/project" \
        --no-keep \
        -- python3 /workspace/governed_agent.py \
           --task "set up my project" \
           --project-dir /workspace/project \
           --output-dir /workspace/output
else
    podman run --rm \
        --network=none \
        --read-only \
        --user 0 \
        --tmpfs /tmp:rw,size=64m \
        -v "${AGENT_DIR}/governed_agent.py:/workspace/governed_agent.py:ro,z" \
        -v "${WORKSPACE}/project:/workspace/project:ro,z" \
        -v "${WORKSPACE}/output:/workspace/output:rw,z" \
        localhost/demo-sandbox:latest \
        python3 /workspace/governed_agent.py \
            --task "set up my project" \
            --project-dir /workspace/project \
            --output-dir /workspace/output
fi
echo "Governed agent output:"
cat "${WORKSPACE}/output/setup-report.json" 2>/dev/null | python3 -m json.tool
save_output 4 governed-sandbox "$(cat "${WORKSPACE}/output/setup-report.json" 2>/dev/null)"

step "2. Run rogue agent in sandbox (should fail)"
if [ "$SANDBOX_TOOL" = "openshell" ]; then
    ROGUE_SANDBOX=$(openshell sandbox create \
        --from localhost/demo-sandbox:latest \
        --policy "${BEAKER_DIR}/profiles/untrusted.profile" \
        --upload "${AGENT_DIR}/rogue_agent.py:/workspace/rogue_agent.py" \
        --no-keep \
        -- python3 /workspace/rogue_agent.py \
           --task "set up my project" 2>&1 || true)
else
    ROGUE_SANDBOX=$(podman run --rm \
        --network=none \
        --read-only \
        --user 0 \
        --tmpfs /tmp:rw,size=64m \
        -v "${AGENT_DIR}/rogue_agent.py:/workspace/rogue_agent.py:ro,z" \
        localhost/demo-sandbox:latest \
        python3 /workspace/rogue_agent.py \
            --task "set up my project" 2>&1 || true)
fi
echo "Rogue agent in sandbox:"
echo "$ROGUE_SANDBOX"
save_output 4 rogue-sandbox "{\"output\":$(echo "$ROGUE_SANDBOX" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}"

rm -rf "$WORKSPACE"

header "ACT 4 COMPLETE: Sandbox catches what identity missed"
echo "Sandbox backend: ${SANDBOX_TOOL}"
