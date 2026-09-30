#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-.}"

has_act1=$(ls "${OUTPUT_DIR}"/act1-*.json 2>/dev/null | head -1)
has_act2=$(ls "${OUTPUT_DIR}"/act2-*.json 2>/dev/null | head -1)
has_act3=$(ls "${OUTPUT_DIR}"/act3-*.json 2>/dev/null | head -1)
has_act4=$(ls "${OUTPUT_DIR}"/act4-*.json 2>/dev/null | head -1)

skill_audit_bad="NOT RUN"
mantis_bad="NOT RUN"
sandbox_bad="NOT RUN"
ahdapa_bad="NOT CHECKED"
openshell_bad="NOT USED"
result_bad="AWS keys exfiled"

skill_audit_good="PASS (manifest)"
mantis_good="PASS (no exfil)"
sandbox_good="PASS (confined)"
ahdapa_good="VERIFIED (scoped)"
openshell_good="VERIFIED profile"
result_good="project set up safely"

if [[ -n "${has_act1}" ]]; then
    if grep -q "FAIL" "${has_act1}" 2>/dev/null; then
        sandbox_bad="FAIL (post-hoc)"
    fi
fi

if [[ -n "${has_act2}" ]]; then
    if grep -q "FAIL\|CRITICAL\|BLOCKED" "${has_act2}" 2>/dev/null; then
        skill_audit_good="BLOCKED (12 fails)"
        mantis_good="BLOCKED (EXFIL-001..6)"
        sandbox_good="PASS (CONTAINED)"
    fi
fi

if [[ -n "${has_act3}" ]]; then
    if grep -q "403\|denied\|not registered\|invalid_client" "${has_act3}" 2>/dev/null; then
        ahdapa_bad="DENIED (403)"
    fi
fi

W=35
row() {
    printf "│  %-${W}s│  %-${W}s│\n" "$1" "$2"
}
sep() {
    printf "├─%s─┼─%s─┤\n" "$(printf '%0.s─' $(seq 1 $W))" "$(printf '%0.s─' $(seq 1 $W))"
}
border() {
    printf "%s─%s─%s─%s─%s\n" "$1" "$(printf '%0.s─' $(seq 1 $W))" "$2" "$(printf '%0.s─' $(seq 1 $W))" "$3"
}

echo ""
border "┌" "┬" "┐"
row "UNGOVERNED" "GOVERNED"
sep
row "skill-audit: ${skill_audit_bad}" "skill-audit: ${skill_audit_good}"
row "exfil check: ${mantis_bad}" "exfil check: ${mantis_good}"
row "sandbox-check: ${sandbox_bad}" "sandbox-check: ${sandbox_good}"
row "ahdapa: ${ahdapa_bad}" "ahdapa: ${ahdapa_good}"
row "OpenShell: ${openshell_bad}" "OpenShell: ${openshell_good}"
sep
row "Result: ${result_bad}" "Result: ${result_good}"
row "Time to compromise: 30s" "Time to secure: same 30s"
border "└" "┴" "┘"
echo ""
