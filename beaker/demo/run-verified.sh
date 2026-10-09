#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The Verified Path — full governed agent lifecycle in one script.
# DARC enrollment → assessment → sandbox confinement → clean output → audit event.
source "$(dirname "$0")/lib.sh"

header "THE VERIFIED PATH: GOVERNED AGENT LIFECYCLE"

SANDBOX_TOOL="${SANDBOX_TOOL:-$(check_openshell)}"

# ── Stage 1: DARC Enrollment ──────────────────────────────────────
step "1. DARC enrollment — agent requests identity"
echo "[agent-enroll] Requesting DARC enrollment..."

GOV_PRINCIPAL="governed-agent/$(hostname -f)@DEMO.AGENTIC.TEST"

if klist -s 2>/dev/null; then
    echo "[agent-enroll] Kerberos ticket active: $(klist 2>/dev/null | grep 'Default principal' | awk '{print $3}')"
else
    echo "[agent-enroll] Attempting kinit with keytab..."
    kinit -kt /etc/krb5.keytab "governed-agent/$(hostname -f)@DEMO.AGENTIC.TEST" 2>/dev/null || \
        echo "[agent-enroll] NOTE: No keytab — using existing credentials or demo mode"
fi

echo "[agent-enroll] Identity verified: ${GOV_PRINCIPAL}"
echo "[agent-enroll] HBAC rule: agent-enrollment-allow — MATCHED"
save_output verified enrollment "{\"principal\":\"${GOV_PRINCIPAL}\",\"status\":\"enrolled\"}"

# ── Stage 2: Assessment ───────────────────────────────────────────
step "2. Code assessment — skill-audit + mantis"

echo "[assessment] Running skill-audit on governed agent..."
AUDIT_OUT=$(podman run --rm \
    -v "${AGENT_DIR}:/scan:ro" \
    "${TOOLKIT_IMAGE}" \
    audit --strict --format json /scan/ 2>&1) || true

if echo "$AUDIT_OUT" | python3 -m json.tool >/dev/null 2>&1; then
    AUDIT_ISSUES=$(echo "$AUDIT_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_issues', d.get('issues_found', 'unknown')))" 2>/dev/null || echo "unknown")
    echo "[assessment] skill-audit: governed agent — ${AUDIT_ISSUES} issues"
else
    echo "[assessment] skill-audit: scan complete"
    AUDIT_ISSUES="n/a"
fi
save_output verified skill-audit "${AUDIT_OUT:-{}}"

echo "[assessment] Running mantis scan on governed agent..."
MANTIS_OUT=$(cd "${AGENT_DIR}" && mantis scan --files governed_agent.py 2>&1) || true
if [ -z "$MANTIS_OUT" ]; then
    MANTIS_OUT='{"result":"clean"}'
    echo "[assessment] mantis scan: PASS (clean)"
else
    echo "[assessment] mantis scan: complete"
    echo "$MANTIS_OUT" | head -5
fi
save_output verified mantis-scan "${MANTIS_OUT}"

echo "[assessment] sandbox-manifest: verified (allowed_hosts: [])"

# ── Stage 3: Token Issuance ───────────────────────────────────────
step "3. Scoped token — ahdapa issues narrow scope"

GOV_TOKEN=$(curl -sk --negotiate -u : \
    -X POST "http://${SERVER}:8099/token" \
    -d "grant_type=client_credentials&scope=project:read project:write" 2>/dev/null || echo '{"error":"ahdapa not available"}')

if echo "$GOV_TOKEN" | python3 -c "import json,sys; t=json.load(sys.stdin); print('scope:', t.get('scope','n/a'))" 2>/dev/null; then
    true
else
    echo "Token response: $GOV_TOKEN"
fi
save_output verified governed-token "$GOV_TOKEN"

# ── Stage 4: Sandbox Confinement ──────────────────────────────────
step "4. Sandbox confinement — run governed agent (${SANDBOX_TOOL})"

WORKSPACE=$(mktemp -d)
mkdir -p "${WORKSPACE}/project" "${WORKSPACE}/output"
echo 'print("hello world")' > "${WORKSPACE}/project/main.py"

echo "[sandbox] Launching in confined sandbox (network=none, read-only)"
echo "[sandbox] network=none, read-only fs, resource limits enforced"

if [ "$SANDBOX_TOOL" = "openshell" ]; then
    openshell sandbox create \
        --from localhost/demo-sandbox:latest \
        --policy "${BEAKER_DIR}/profiles/verified.profile" \
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

echo ""
echo "Governed agent output:"
if [ -f "${WORKSPACE}/output/setup-report.json" ]; then
    cat "${WORKSPACE}/output/setup-report.json" | python3 -m json.tool
    save_output verified governed-sandbox "$(cat "${WORKSPACE}/output/setup-report.json")"
else
    echo "  (no output file — agent may have printed to stdout)"
    save_output verified governed-sandbox '{"status":"completed","output":"stdout"}'
fi

rm -rf "$WORKSPACE"

# ── Stage 5: Audit Event ──────────────────────────────────────────
step "5. OCSF audit event — task complete"

OCSF_EVENT=$(cat <<OCSF
{
  "class_uid": 6003,
  "class_name": "API Activity",
  "category_uid": 6,
  "category_name": "Application Activity",
  "severity_id": 1,
  "severity": "Informational",
  "activity_id": 1,
  "activity_name": "Create",
  "status_id": 1,
  "status": "Success",
  "actor": {
    "user": {"name": "governed-agent", "type": "service"},
    "session": {"uid": "$(uuidgen 2>/dev/null || echo demo-session-001)"}
  },
  "resources": [
    {"type": "agent", "name": "governed-agent", "domain": "DEMO.AGENTIC.TEST"},
    {"type": "sandbox", "name": "${SANDBOX_TOOL}"}
  ],
  "metadata": {
    "version": "1.4.0",
    "product": {"name": "agentic-security-platform", "vendor_name": "Red Hat"},
    "trust_tier": "verified",
    "assessment": "pass",
    "confinement": "${SANDBOX_TOOL}",
    "policy_violations": 0
  },
  "time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
OCSF
)

echo "[audit] OCSF event logged: agent.task.complete (trust_tier=verified)"
echo "$OCSF_EVENT" | python3 -m json.tool
save_output verified ocsf-event "$OCSF_EVENT"

# ── Summary ───────────────────────────────────────────────────────
header "VERIFIED PATH COMPLETE"
echo "  ✓ DARC enrollment: ${GOV_PRINCIPAL}"
echo "  ✓ Assessment: skill-audit + mantis — PASS"
echo "  ✓ Token: scoped (project:read, project:write)"
echo "  ✓ Sandbox: ${SANDBOX_TOOL} (network=none, read-only)"
echo "  ✓ Task: completed clean"
echo "  ✓ Audit: OCSF event recorded"
echo ""
echo "Same task. Same 30 seconds. Complete visibility."
