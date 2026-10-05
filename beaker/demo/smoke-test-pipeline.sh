#!/usr/bin/env bash
# Smoke test: Falco → bridge → EDA pipeline.
# Run on CLIENT VM after all services are up.
set -euo pipefail

echo "=== Falco → EDA Pipeline Smoke Test ==="

# Check bridge
if ! ss -tlnp | grep -q ":5001 "; then
    echo "FAIL: Bridge not running on :5001"
    echo "  Start: systemctl start falco-siem-bridge"
    exit 1
fi
echo "OK: Bridge listening on :5001"

# Check EDA
if ! ss -tlnp | grep -q ":5000 "; then
    echo "WARN: EDA not running on :5000"
    echo "  Start: systemctl start eda-agent-anomaly"
fi

# Send fake SWARM alert
FAKE_ALERT="{
  \"rule\": \"Agent Swarm — Unauthorized Process Spawning\",
  \"priority\": \"Critical\",
  \"output\": \"SWARM: Agent spawned unauthorized child process (agent=smoke-test pid=$$)\",
  \"tags\": [\"agentic-security\", \"swarm\", \"SWARM-001\"],
  \"output_fields\": {
    \"proc.pname\": \"python3\",
    \"proc.pid\": $$,
    \"proc.cmdline\": \"smoke-test\",
    \"user.name\": \"smoke-test-agent\",
    \"container.name\": \"smoke-test\"
  },
  \"time\": \"$(date -u +%Y-%m-%dT%H:%M:%S.000000000Z)\"
}"

echo "Sending SWARM-001 alert..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:5001/ \
    -H "Content-Type: application/json" \
    -d "$FAKE_ALERT")

if [ "$RESPONSE" = "200" ]; then
    echo "OK: Bridge→EDA accepted (HTTP $RESPONSE)"
elif [ "$RESPONSE" = "502" ]; then
    echo "PARTIAL: Bridge received, EDA not responding (HTTP 502)"
else
    echo "FAIL: Unexpected HTTP $RESPONSE"
    exit 1
fi

echo ""
echo "Logs:"
echo "  Bridge: journalctl -u falco-siem-bridge -f"
echo "  EDA:    journalctl -u eda-agent-anomaly -f"
