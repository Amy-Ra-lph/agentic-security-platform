#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Setup Falco + Falcosidekick + EDA pipeline on the agent runner.
# Run AFTER setup-client.sh. Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEAKER_DIR="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="${BEAKER_DIR}/ansible"

echo "=== Setting up Falco + EDA Detection Pipeline ==="

# ── 1. Install Falco ─────────────────────────────────────────────
if ! command -v falco >/dev/null 2>&1; then
    echo "--- Installing Falco ---"

    # RHEL/CentOS: use the Falco RPM repo
    cat > /etc/yum.repos.d/falcosecurity.repo <<'REPO'
[falcosecurity]
name=Falco Security
baseurl=https://download.falco.org/packages/rpm/
gpgcheck=1
gpgkey=https://falco.org/repo/falcosecurity-packages.asc
enabled=1
REPO

    dnf install -y falco || {
        echo "WARNING: RPM install failed. Trying container fallback."
        # Container fallback — Falco as privileged Podman container
        podman pull docker.io/falcosecurity/falco:latest
        echo "Falco pulled as container. Use: podman run --privileged -v /etc/falco:/etc/falco falcosecurity/falco"
    }
else
    echo "Falco already installed: $(falco --version 2>/dev/null || echo 'container')"
fi

# ── 2. Deploy custom Falco rules ────────────────────────────────
echo "--- Deploying agent security rules ---"
mkdir -p /etc/falco/rules.d
cp "${ANSIBLE_DIR}/falco-rules-agent-security.yaml" /etc/falco/rules.d/
echo "Deployed: /etc/falco/rules.d/falco-rules-agent-security.yaml"

# Configure Falco: HTTP output → bridge, JSON mode
mkdir -p /etc/falco/config.d
cat > /etc/falco/config.d/http-output.yaml <<'HTTPCONF'
http_output:
  enabled: true
  url: "http://localhost:5001"

json_output: true
json_include_output_property: true
json_include_tags_property: true
HTTPCONF
echo "Configured: Falco http_output → bridge :5001"

# ── 3. Install Falcosidekick ────────────────────────────────────
if ! command -v falcosidekick >/dev/null 2>&1 && ! podman image exists docker.io/falcosecurity/falcosidekick:latest 2>/dev/null; then
    echo "--- Installing Falcosidekick ---"
    podman pull docker.io/falcosecurity/falcosidekick:latest
else
    echo "Falcosidekick already available"
fi

# Deploy config
echo "--- Deploying Falcosidekick config ---"
mkdir -p /etc/falcosidekick
cp "${ANSIBLE_DIR}/falcosidekick-config.yaml" /etc/falcosidekick/config.yaml
echo "Deployed: /etc/falcosidekick/config.yaml"

# ── 4. Deploy Falco→SIEM bridge ─────────────────────────────────
echo "--- Deploying Falco-SIEM bridge ---"
BRIDGE_DIR="/opt/demo/bridge"
mkdir -p "$BRIDGE_DIR"
cp "${ANSIBLE_DIR}/falco_siem_bridge.py" "${BRIDGE_DIR}/"
chmod +x "${BRIDGE_DIR}/falco_siem_bridge.py"
echo "Deployed: ${BRIDGE_DIR}/falco_siem_bridge.py"

# Systemd unit created below after EDA token is generated (section 5)

# ── 5. Install ansible-rulebook (EDA) ───────────────────────────
if ! command -v ansible-rulebook >/dev/null 2>&1; then
    echo "--- Installing Event-Driven Ansible ---"
    # EDA requires Java (Drools) + Python
    dnf install -y java-21-openjdk python3-pip 2>/dev/null || \
        dnf install -y java-17-openjdk-headless python3-pip 2>/dev/null || true
    pip3 install ansible ansible-rulebook 2>/dev/null || {
        echo "WARNING: pip install failed. Trying dnf."
        dnf install -y ansible-rulebook 2>/dev/null || \
            echo "WARNING: ansible-rulebook not available. Install manually."
    }
    ansible-galaxy collection install ansible.eda 2>/dev/null || true
else
    echo "ansible-rulebook already installed: $(ansible-rulebook --version 2>/dev/null | head -1)"
fi

# Deploy EDA rulebook + inventory + revocation playbook
echo "--- Deploying EDA rulebook + playbooks ---"
EDA_DIR="/opt/demo/ansible"
mkdir -p "$EDA_DIR"
for f in agent-anomaly-rulebook.yml agent-revocation.yml inventory.yml; do
    if [ "${ANSIBLE_DIR}/${f}" != "${EDA_DIR}/${f}" ]; then
        cp "${ANSIBLE_DIR}/${f}" "${EDA_DIR}/"
    fi
done
echo "Deployed: ${EDA_DIR}/"

# Create EDA vars file with webhook token
EDA_VARS="${EDA_DIR}/vars.yml"
if [ ! -f "$EDA_VARS" ]; then
    EDA_TOKEN=$(openssl rand -hex 16)
    cat > "$EDA_VARS" <<VARS
---
eda_webhook_token: "${EDA_TOKEN}"
VARS
    chmod 600 "$EDA_VARS"
    echo "Generated EDA webhook token in ${EDA_VARS}"
    # Update Falcosidekick config with the real token
    sed -i "s/{{ eda_webhook_token }}/${EDA_TOKEN}/" /etc/falcosidekick/config.yaml
else
    echo "EDA vars already exist: ${EDA_VARS}"
    EDA_TOKEN=$(grep eda_webhook_token "$EDA_VARS" | awk -F'"' '{print $2}')
fi

# Create systemd unit for the bridge (needs EDA token for auth)
# --syslog-host is added by setup-siem.sh if SIEM VM is configured
cat > /etc/systemd/system/falco-siem-bridge.service <<UNIT
[Unit]
Description=Falco to EDA + SIEM Webhook Bridge
After=network.target

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/demo/bridge/falco_siem_bridge.py --port 5001 --eda-url http://localhost:5000 --eda-token ${EDA_TOKEN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

echo "Created: falco-siem-bridge.service (with EDA auth token)"

# Create systemd unit for EDA
cat > /etc/systemd/system/eda-agent-anomaly.service <<UNIT
[Unit]
Description=Event-Driven Ansible — Agent Anomaly Rulebook
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/demo/ansible
ExecStart=/usr/local/bin/ansible-rulebook --rulebook agent-anomaly-rulebook.yml -i inventory.yml --vars vars.yml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
echo "Created: eda-agent-anomaly.service"

# ── 6. Create OCSF log directory ────────────────────────────────
mkdir -p /var/log/ocsf
chmod 750 /var/log/ocsf
echo "Created: /var/log/ocsf/"

# ── 7. Smoke test script ────────────────────────────────────────
cat > /opt/demo/bridge/smoke-test.sh <<'SMOKE'
#!/usr/bin/env bash
# Smoke test: send a fake Falco alert through the full pipeline.
# Requires: falco-eda-bridge running on :5001, EDA on :5000
set -euo pipefail

echo "=== Falco → EDA Pipeline Smoke Test ==="

# Check bridge is listening
if ! curl -sf http://localhost:5001/ >/dev/null 2>&1; then
    echo "Bridge not running on :5001. Start with: systemctl start falco-siem-bridge"
    echo "  or: python3 /opt/demo/bridge/falco_siem_bridge.py &"
    exit 1
fi

# Check EDA is listening
if ! curl -sf http://localhost:5000/ >/dev/null 2>&1; then
    echo "WARNING: EDA not running on :5000. Bridge will forward but EDA won't process."
    echo "  Start with: systemctl start eda-agent-anomaly"
fi

# Send fake swarm alert (mimics Falcosidekick payload)
FAKE_ALERT='{
  "rule": "Agent Swarm — Unauthorized Process Spawning",
  "priority": "Critical",
  "output": "SWARM: Agent spawned unauthorized child process (agent=code-assist-9a2b pid=12345)",
  "tags": ["agentic-security", "swarm", "SWARM-001"],
  "output_fields": {
    "proc.pname": "python3",
    "proc.pid": 12345,
    "proc.cmdline": "python3 agent_worker.py --autonomous",
    "user.name": "code-assist-9a2b",
    "container.name": "agent-sandbox"
  },
  "time": "'$(date -u +%Y-%m-%dT%H:%M:%S.000000000Z)'"
}'

echo "Sending fake SWARM-001 alert to bridge..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:5001/ \
    -H "Content-Type: application/json" \
    -d "$FAKE_ALERT")

if [ "$RESPONSE" = "200" ]; then
    echo "✓ Bridge accepted and forwarded alert (HTTP $RESPONSE)"
elif [ "$RESPONSE" = "502" ]; then
    echo "✓ Bridge received alert but EDA not responding (HTTP 502 — start EDA)"
else
    echo "✗ Unexpected response: HTTP $RESPONSE"
fi

echo ""
echo "Check bridge logs: journalctl -u falco-siem-bridge -f"
echo "Check EDA logs:    journalctl -u eda-agent-anomaly -f"
SMOKE
chmod +x /opt/demo/bridge/smoke-test.sh
echo "Created: /opt/demo/bridge/smoke-test.sh"

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "=== Falco + EDA Pipeline Setup Complete ==="
echo ""
echo "  Components:"
echo "    Falco rules:      /etc/falco/rules.d/falco-rules-agent-security.yaml"
echo "    Falcosidekick:    /etc/falcosidekick/config.yaml"
echo "    Bridge:           /opt/demo/bridge/falco_siem_bridge.py"
echo "    EDA rulebook:     /opt/demo/ansible/agent-anomaly-rulebook.yml"
echo "    Revocation:       /opt/demo/ansible/agent-revocation.yml"
echo "    OCSF logs:        /var/log/ocsf/"
echo ""
echo "  Start services:"
echo "    systemctl start falco"
echo "    systemctl start falco-siem-bridge"
echo "    systemctl start eda-agent-anomaly"
echo ""
echo "  Or start Falcosidekick as container:"
echo "    podman run -d --name falcosidekick \\"
echo "      -v /etc/falcosidekick/config.yaml:/etc/falcosidekick/config.yaml:ro \\"
echo "      -p 2801:2801 \\"
echo "      docker.io/falcosecurity/falcosidekick"
echo ""
echo "  Smoke test:"
echo "    bash /opt/demo/bridge/smoke-test.sh"
