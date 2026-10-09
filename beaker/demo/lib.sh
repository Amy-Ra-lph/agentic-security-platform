#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared functions for demo act scripts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEAKER_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${SCRIPT_DIR}/output"
AGENT_DIR="${SCRIPT_DIR}/agents"

# Load inventory if available
if [ -f "${BEAKER_DIR}/setup/inventory.env" ]; then
    source "${BEAKER_DIR}/setup/inventory.env"
fi

SERVER="${SERVER:-system1}"
CLIENT="${CLIENT:-system2}"
SIEM="${SIEM:-}"

TOOLKIT_IMAGE="${TOOLKIT_IMAGE:-quay.io/rhn_support_afarley/rhel-security-toolkit:latest}"

header() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    echo ""
}

step() {
    echo "--- Step: $1"
}

save_output() {
    local act="$1" name="$2" content="$3"
    local dir="${OUTPUT_DIR}/act${act}"
    mkdir -p "$dir"
    printf '%s\n' "$content" > "${dir}/${name}.json"
}

check_server_reachable() {
    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 "https://${SERVER}:9443/" 2>/dev/null || true)
    if [ "$http_code" != "200" ]; then
        echo "ERROR: Exfil receiver not responding at ${SERVER}:9443"
        echo "Run 'make validate' to check infrastructure health."
        return 1
    fi
}

check_openshell() {
    if command -v openshell >/dev/null 2>&1; then
        echo "openshell"
    else
        echo "podman"
    fi
}
