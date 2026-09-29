#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Wraps demo execution with timing annotations for Arcade recording.
# Usage: bash arcade-wrapper.sh [output-file]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEAKER_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="${1:-${SCRIPT_DIR}/demo-recording-$(date +%Y%m%d-%H%M%S).cast}"

echo "Recording demo to: $OUTPUT_FILE"
echo "Press Ctrl+D or type 'exit' when done."
echo ""

# Use script(1) for basic recording, or asciinema if available
if command -v asciinema >/dev/null 2>&1; then
    asciinema rec \
        --title "The 30-Second Mistake — Live Demo" \
        --idle-time-limit 3 \
        --command "bash ${BEAKER_DIR}/demo/run-demo.sh" \
        "$OUTPUT_FILE"
    echo ""
    echo "Recording saved: $OUTPUT_FILE"
    echo "Upload to asciinema.org or convert to HTML/GIF."
else
    echo "asciinema not found — using script(1) fallback"
    script -c "bash ${BEAKER_DIR}/demo/run-demo.sh" "$OUTPUT_FILE"
    echo ""
    echo "Raw recording saved: $OUTPUT_FILE"
    echo "Install asciinema for better recording: dnf install asciinema"
fi
