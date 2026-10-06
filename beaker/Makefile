SHELL := /bin/bash
BEAKER_URL := https://beaker.engineering.redhat.com
COOKIE_FILE := /tmp/poc-lab-beaker-cookies
STAGING := /opt/demo-staging

-include setup/inventory.env

SSH_OPTS := -o StrictHostKeyChecking=no -o ConnectTimeout=10
TOOLKIT_IMAGE := quay.io/rhn_support_afarley/rhel-security-toolkit:latest

.PHONY: beaker setup setup-server setup-client setup-siem demo act1 act2 act3 act4 act5 record record-acts reset-all teardown validate validate-siem help

beaker: ## Submit Beaker job, wait for provisioning, write inventory.env
	@echo "Submit job.xml via the Beaker REST API:"
	@echo "  1. Authenticate: curl -sk --negotiate -u : -c $(COOKIE_FILE) -L $(BEAKER_URL)/login"
	@echo "  2. Submit: curl -sk -b $(COOKIE_FILE) -X POST $(BEAKER_URL)/bkr-api/jobs -H 'Content-Type: application/json' -d '{\"xml\": \"<contents of job.xml>\"}'"
	@echo "  3. Poll until Running, then write setup/inventory.env with SERVER=<fqdn> CLIENT=<fqdn>"

setup: setup/inventory.env setup-server setup-client ## Full setup: server then client

setup-server: setup/inventory.env ## Set up System 1 (IdM + ahdapa + exfil receiver)
	@echo "=== Setting up SERVER: $(SERVER) ==="
	ssh $(SSH_OPTS) root@$(SERVER) "mkdir -p $(STAGING)/exfil-receiver"
	scp $(SSH_OPTS) setup/setup-server.sh setup/inventory.env setup/images.env root@$(SERVER):$(STAGING)/
	scp $(SSH_OPTS) -r exfil-receiver/server.py exfil-receiver/exfil-receiver.service root@$(SERVER):$(STAGING)/exfil-receiver/
	ssh $(SSH_OPTS) root@$(SERVER) "chmod +x $(STAGING)/setup-server.sh && $(STAGING)/setup-server.sh"
	@echo "=== Server setup complete ==="

setup-client: setup/inventory.env ## Set up System 2 (agent runner + assessment tools)
	@echo "=== Setting up CLIENT: $(CLIENT) ==="
	ssh $(SSH_OPTS) root@$(CLIENT) "mkdir -p $(STAGING)/agents $(STAGING)/profiles $(STAGING)/demo"
	scp $(SSH_OPTS) setup/setup-client.sh setup/inventory.env setup/images.env root@$(CLIENT):$(STAGING)/
	scp $(SSH_OPTS) agents/*.py agents/*.yml root@$(CLIENT):$(STAGING)/agents/
	scp $(SSH_OPTS) profiles/* root@$(CLIENT):$(STAGING)/profiles/
	scp $(SSH_OPTS) demo/*.sh root@$(CLIENT):$(STAGING)/demo/
	@echo "--- Fetching server credentials for client enrollment ---"
	scp $(SSH_OPTS) root@$(SERVER):~/.demo-credentials /tmp/demo-server-creds
	scp $(SSH_OPTS) /tmp/demo-server-creds root@$(CLIENT):$(STAGING)/server-credentials
	rm -f /tmp/demo-server-creds
	ssh $(SSH_OPTS) root@$(CLIENT) "chmod +x $(STAGING)/setup-client.sh && $(STAGING)/setup-client.sh"
	@echo "=== Client setup complete ==="

setup/inventory.env:
	@echo "ERROR: setup/inventory.env not found."
	@echo "Create it with:"
	@echo "  echo 'SERVER=<idm-server-fqdn>' > setup/inventory.env"
	@echo "  echo 'CLIENT=<agent-runner-fqdn>' >> setup/inventory.env"
	@false

demo: setup/inventory.env ## Run full 5-act demo
	demo/run-demo.sh all

act1: setup/inventory.env ## Act 1: Bad path — rogue agent exfiltrates
	demo/run-demo.sh 1

act2: setup/inventory.env ## Act 2: Assessment gate catches rogue
	demo/run-demo.sh 2

act3: setup/inventory.env ## Act 3: Identity gate — HBAC + ahdapa
	demo/run-demo.sh 3

act4: setup/inventory.env ## Act 4: Runtime confinement — OpenShell
	demo/run-demo.sh 4

act5: setup/inventory.env ## Act 5: Side-by-side comparison
	demo/run-demo.sh 5

record: ## Record all acts and build arcade + deck HTML
	bash record/record-all.sh --skip-existing
	@echo ""
	@echo "Output: record/output/"
	@echo "  *-deck.html   — linear slide presentation"
	@echo "  *-arcade.html — card grid explorer"

record-acts: ## Re-record specific acts (e.g., make record-acts ACTS=1,5,13)
	bash record/record-all.sh --acts $(ACTS)

reset-all: setup/inventory.env ## Reset ALL demo state for full re-run
	@echo "=== Resetting demo state ==="
	@echo "--- Resetting vibe-to-governed demo ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "bash /opt/demo-staging/demo/vibe-to-governed/reset-demo.sh 2>/dev/null" || true
	@echo "--- Clearing OCSF incident files ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "rm -f /var/log/ocsf/incident-*.json 2>/dev/null" || true
	@echo "--- Restarting detection pipeline ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "systemctl restart falco-modern-bpf falco-siem-bridge eda-agent-anomaly 2>/dev/null" || true
	@echo "--- Clearing Wazuh agentic alerts (SIEM) ---"
	@WPASS=$$(ssh $(SSH_OPTS) root@$(SIEM) "cat /root/wazuh-install-files/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | grep -A1 'indexer_username.*admin' | grep password | awk '{print \$$NF}' | tr -d \"'\"" 2>/dev/null); \
	if [ -n "$$WPASS" ]; then \
		ssh $(SSH_OPTS) root@$(SIEM) "curl -sk -u admin:$$WPASS -X POST 'https://localhost:9200/wazuh-alerts-*/_delete_by_query' -H 'Content-Type: application/json' -d '{\"query\":{\"match\":{\"rule.groups\":\"agentic-security\"}}}' 2>/dev/null" | head -1; \
	fi
	@echo "=== Reset complete — ready for next demo run ==="

teardown: ## Return Beaker systems
	@echo "Returning Beaker reservation — let it expire or cancel via Beaker UI"
	@echo "  $(BEAKER_URL)/jobs/<JOB_ID>"

validate: setup/inventory.env ## Smoke test: IPA, ahdapa, containers, honeypot
	@echo "--- Validating Server ($(SERVER)) ---"
	ssh $(SSH_OPTS) root@$(SERVER) "ipa ping && echo 'IPA: OK' || echo 'IPA: FAIL'"
	ssh $(SSH_OPTS) root@$(SERVER) "curl -sk https://localhost/idp/.well-known/openid-configuration | python3 -c 'import sys,json; json.load(sys.stdin); print(\"ahdapa: OK\")' 2>/dev/null || echo 'ahdapa: FAIL'"
	ssh $(SSH_OPTS) root@$(SERVER) "systemctl is-active exfil-receiver && echo 'Exfil receiver: OK' || echo 'Exfil receiver: FAIL'"
	@echo "--- Validating Client ($(CLIENT)) ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "source /opt/demo-staging/server-credentials 2>/dev/null && echo \$$ADMIN_PASSWORD | kinit admin@DEMO.AGENTIC.TEST 2>/dev/null; ipa ping && echo 'IPA client: OK' || echo 'IPA client: FAIL'"
	ssh $(SSH_OPTS) root@$(CLIENT) "podman image exists $(TOOLKIT_IMAGE) && echo 'Toolkit image: OK' || echo 'Toolkit image: FAIL'"
	ssh $(SSH_OPTS) root@$(CLIENT) "test -f ~/.aws/credentials && echo 'Honeypot: OK' || echo 'Honeypot: FAIL'"
	ssh $(SSH_OPTS) root@$(CLIENT) "test -f /opt/demo/agents/rogue_agent.py && echo 'Agents: OK' || echo 'Agents: FAIL'"

setup-siem: setup/inventory.env ## Set up System 3 (Wazuh SIEM dashboard)
	@echo "=== Setting up SIEM: $(SIEM) ==="
	ssh $(SSH_OPTS) root@$(SIEM) "mkdir -p $(STAGING)"
	scp $(SSH_OPTS) setup/setup-siem.sh setup/wazuh-decoders.xml setup/wazuh-rules.xml root@$(SIEM):$(STAGING)/
	ssh $(SSH_OPTS) root@$(SIEM) "chmod +x $(STAGING)/setup-siem.sh && $(STAGING)/setup-siem.sh"
	@echo "--- Deploying rsyslog forwarder on runner ---"
	scp $(SSH_OPTS) ansible/rsyslog-ocsf-forwarder.conf root@$(CLIENT):/etc/rsyslog.d/90-ocsf-forwarder.conf
	ssh $(SSH_OPTS) root@$(CLIENT) "SIEM_IP=$$(getent hosts $(SIEM) | awk '{print $$1}') && sed -i \"s/SIEM_HOST/$$SIEM_IP/g\" /etc/rsyslog.d/90-ocsf-forwarder.conf && systemctl restart rsyslog"
	@echo "--- Updating bridge systemd unit with syslog destination ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "SIEM_IP=$$(getent hosts $(SIEM) | awk '{print $$1}') && sed -i \"s|falco_siem_bridge.py --port 5001 --eda-url http://localhost:5000|falco_siem_bridge.py --port 5001 --eda-url http://localhost:5000 --syslog-host $$SIEM_IP --syslog-port 514|\" /etc/systemd/system/falco-siem-bridge.service && systemctl daemon-reload && systemctl restart falco-siem-bridge" 2>/dev/null || true
	@echo "--- Importing dashboard saved objects ---"
	scp $(SSH_OPTS) setup/wazuh-dashboard.ndjson root@$(SIEM):$(STAGING)/
	@WPASS=$$(ssh $(SSH_OPTS) root@$(SIEM) "cat /root/wazuh-install-files/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | grep -A1 'indexer_username.*admin' | grep password | awk '{print \$$NF}' | tr -d \"'\"" 2>/dev/null); \
	if [ -n "$$WPASS" ]; then \
		ssh $(SSH_OPTS) root@$(SIEM) "curl -sk -u admin:$$WPASS -X POST 'https://localhost/api/saved_objects/_import?overwrite=true' -H 'osd-xsrf: true' --form file=@$(STAGING)/wazuh-dashboard.ndjson 2>/dev/null" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(f\"Dashboard import: {d.get(\"successCount\",0)} objects\")' 2>/dev/null || echo 'Dashboard import: check manually'; \
	else \
		echo "WARN: Could not find Wazuh admin password — import dashboard manually"; \
	fi
	@echo "=== SIEM setup complete ==="

validate-siem: setup/inventory.env ## Validate SIEM receives syslog events
	@echo "--- Validating SIEM ($(SIEM)) ---"
	ssh $(SSH_OPTS) root@$(SIEM) "systemctl is-active wazuh-manager && echo 'Wazuh manager: OK' || echo 'Wazuh manager: FAIL'"
	ssh $(SSH_OPTS) root@$(SIEM) "systemctl is-active wazuh-indexer && echo 'Wazuh indexer: OK' || echo 'Wazuh indexer: FAIL'"
	ssh $(SSH_OPTS) root@$(SIEM) "systemctl is-active wazuh-dashboard && echo 'Wazuh dashboard: OK' || echo 'Wazuh dashboard: FAIL'"
	ssh $(SSH_OPTS) root@$(SIEM) "ss -tlnp | grep -q ':514' && echo 'Syslog intake: OK' || echo 'Syslog intake: FAIL'"
	@echo "--- Sending test event from runner ---"
	ssh $(SSH_OPTS) root@$(CLIENT) "logger -n $(SIEM) -P 514 --tcp '<134>1 2026-10-02T12:00:00Z test falco-siem-bridge - TEST-001 [agent-security alert_type=\"swarm\" agent_principal=\"test-agent\" agent_realm=\"DEMO.AGENTIC.TEST\" mitre_id=\"T1059.006\" ocsf_class_uid=\"2001\" severity=\"critical\"] Smoke test event' && echo 'Test event sent: OK'"

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
