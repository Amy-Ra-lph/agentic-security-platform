SHELL := /bin/bash
ANSIBLE := ansible-playbook -i ansible/inventory.yml ansible/site.yml

.PHONY: up setup setup-server setup-client setup-siem validate demo reset destroy help

up: ## Start all VMs
	vagrant up

setup: ## Full stack setup (server → client → siem)
	$(ANSIBLE)

setup-server: ## Phase 1: IPA + ahdapa + exfil receiver
	$(ANSIBLE) --tags server

setup-client: ## Phase 2: IPA client + agents + Falco/EDA
	$(ANSIBLE) --tags client

setup-siem: ## Phase 3: Wazuh SIEM
	$(ANSIBLE) --tags siem

validate: ## Smoke test all components
	@echo "--- Server ---"
	vagrant ssh server -c "sudo ipa ping && echo 'IPA: OK' || echo 'IPA: FAIL'"
	vagrant ssh server -c "curl -sk https://localhost/idp/.well-known/openid-configuration | python3 -c 'import sys,json; json.load(sys.stdin); print(\"ahdapa: OK\")' 2>/dev/null || echo 'ahdapa: FAIL'"
	@echo "--- Client ---"
	vagrant ssh client -c "sudo ipa ping && echo 'IPA client: OK' || echo 'IPA client: FAIL'"
	vagrant ssh client -c "sudo systemctl is-active falco-siem-bridge eda-agent-anomaly && echo 'Detection: OK' || echo 'Detection: FAIL'"
	@echo "--- SIEM ---"
	vagrant ssh siem -c "sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard && echo 'Wazuh: OK' || echo 'Wazuh: FAIL'"

demo: ## Run rogue agent demo (Act 1)
	@echo "=== Act 1: The 30-Second Mistake ==="
	vagrant ssh client -c "cd /opt/demo/agents && python3 rogue_agent.py --task 'set up my project'"
	@echo ""
	@echo "--- Exfil receipt on server ---"
	vagrant ssh server -c "sudo tail -3 /var/log/exfil-receiver.log"

reset: ## Reset demo state for re-run
	vagrant ssh client -c "sudo rm -f /var/log/ocsf/incident-*.json"
	vagrant ssh client -c "sudo systemctl restart falco-siem-bridge eda-agent-anomaly" 2>/dev/null || true
	vagrant ssh server -c "sudo truncate -s 0 /var/log/exfil-receiver.log" 2>/dev/null || true
	@echo "Demo state reset"

destroy: ## Tear down all VMs
	vagrant destroy -f

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
