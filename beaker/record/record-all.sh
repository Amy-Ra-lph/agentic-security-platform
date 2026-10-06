#!/usr/bin/env bash
# Record all demo acts and build the arcade + deck presentation.
# Uses demo-recorder in simulated mode (no VMs needed).
# Usage: bash record-all.sh [--skip-existing] [--acts 1,2,5]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEAKER_DIR="$(dirname "$SCRIPT_DIR")"
ARCADE_DIR="${BEAKER_DIR}/demo/arcade"
ACTS_DIR="${ARCADE_DIR}/acts"
OUTPUT_DIR="${BEAKER_DIR}/record/output"
MANIFEST="${ARCADE_DIR}/manifest.yml"

SKIP_EXISTING=false
SELECTED_ACTS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-existing) SKIP_EXISTING=true; shift ;;
        --acts) SELECTED_ACTS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

command -v demo-recorder >/dev/null 2>&1 || {
    echo "ERROR: demo-recorder not found. Install: pip install -e ~/DevSpace/demo-recorder/"
    exit 1
}

mkdir -p "$OUTPUT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── Record individual acts ──────────────────────────────────────────

record_act() {
    local yml="$1"
    local base
    base="$(basename "$yml" .yml)"
    local cast="${ACTS_DIR}/${base}.cast"

    if [[ "$SKIP_EXISTING" == true && -f "$cast" ]]; then
        log "SKIP: ${base} (cast exists)"
        return 0
    fi

    log "RECORD: ${base}"
    demo-recorder record "$yml" -o "$cast" -q 2>&1 | tail -1
    log "  → $(wc -l < "$cast") lines"
}

act_files=()
if [[ -n "$SELECTED_ACTS" ]]; then
    IFS=',' read -ra nums <<< "$SELECTED_ACTS"
    for n in "${nums[@]}"; do
        matches=("${ACTS_DIR}"/act${n}-*.yml)
        if [[ -f "${matches[0]}" ]]; then
            act_files+=("${matches[0]}")
        else
            log "WARN: No YAML found for act ${n}"
        fi
    done
else
    for yml in "${ACTS_DIR}"/act*.yml; do
        act_files+=("$yml")
    done
fi

log "Recording ${#act_files[@]} acts..."
for yml in "${act_files[@]}"; do
    record_act "$yml"
done

# ── Build presentation ──────────────────────────────────────────────

log "Building presentation from ${MANIFEST}..."
cd "$ARCADE_DIR"
demo-recorder build-presentation "$MANIFEST" -o "$OUTPUT_DIR/" 2>&1 | tail -3

log "Done. Output:"
ls -lh "$OUTPUT_DIR/"*.html 2>/dev/null || log "  (no HTML output — check manifest cast paths)"
