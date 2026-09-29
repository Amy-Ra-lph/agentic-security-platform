#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Test that format-output.sh renders without error given sample data.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Create sample output structure
mkdir -p "$TMPDIR/output/act2" "$TMPDIR/output/act3" "$TMPDIR/output/act4"
echo '{"findings":[{"severity":"FAIL"}]}' > "$TMPDIR/output/act2/skill-audit.json"
echo '{"findings":[{"rule_id":"EXFIL-001","severity":"CRITICAL"}]}' > "$TMPDIR/output/act2/mantis.json"
echo '{"findings":[{"severity":"FAIL"}]}' > "$TMPDIR/output/act2/sandbox-check.json"
echo '{"http_code":403}' > "$TMPDIR/output/act3/rogue-token-attempt.json"
echo '{"access_token":"ok","tier":"verified"}' > "$TMPDIR/output/act3/governed-token.json"
echo '{"output":"ConnectionError"}' > "$TMPDIR/output/act4/rogue-sandbox.json"
echo '{"status":"initialized"}' > "$TMPDIR/output/act4/governed-sandbox.json"

# Symlink the output dir so format-output.sh finds it
ln -sf "$TMPDIR/output" "$SCRIPT_DIR/output"

OUTPUT=$(bash "$SCRIPT_DIR/format-output.sh" 2>&1)
rm -f "$SCRIPT_DIR/output"

echo "$OUTPUT"

# Verify table rendered
echo "$OUTPUT" | grep -q "UNGOVERNED" || { echo "FAIL: missing UNGOVERNED header"; exit 1; }
echo "$OUTPUT" | grep -q "GOVERNED" || { echo "FAIL: missing GOVERNED header"; exit 1; }
echo "$OUTPUT" | grep -q "AWS keys exfiled" || { echo "FAIL: missing result row"; exit 1; }

echo "PASS: format-output.sh renders correctly"
