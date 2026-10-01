#!/usr/bin/env python3
"""Falco → EDA webhook bridge.

Receives Falco alerts via Falcosidekick webhook, transforms them into
the event format expected by the EDA agent-anomaly-rulebook, and forwards
to the EDA webhook endpoint.

Run:
    python3 falco-eda-bridge.py --eda-url http://localhost:5000 --port 5001

Falcosidekick webhook → :5001 → transform → :5000 (EDA)
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen


TAG_TO_ALERT_TYPE = {
    "swarm": "swarm",
    "exfiltration": "exfiltration",
    "escalation": "escalation",
    "sandbox-escape": "swarm",
    "network": "exfiltration",
}

RULE_TAG_PATTERN = re.compile(r"^[A-Z]+-\d+$")


def extract_agent_principal(output_fields: dict, output: str) -> str:
    user = output_fields.get("user.name", "")
    if user and user != "root":
        return user
    match = re.search(r"agent=(\S+)", output)
    if match:
        return match.group(1)
    return output_fields.get("proc.pname", "unknown-agent")


def transform(falco_event: dict) -> dict:
    tags = falco_event.get("tags", [])
    output_fields = falco_event.get("output_fields", {})
    output = falco_event.get("output", "")

    alert_type = "unknown"
    rule_id = ""
    for tag in tags:
        if RULE_TAG_PATTERN.match(tag):
            rule_id = tag
        elif tag in TAG_TO_ALERT_TYPE:
            alert_type = TAG_TO_ALERT_TYPE[tag]

    return {
        "payload": {
            "alert_type": alert_type,
            "rule": rule_id,
            "agent_principal": extract_agent_principal(output_fields, output),
            "agent_realm": "DEMO.AGENTIC.TEST",
            "timestamp": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "falco_priority": falco_event.get("priority", ""),
            "falco_rule": falco_event.get("rule", ""),
            "falco_output": output,
            "source_host": output_fields.get("container.name", "host"),
            "pid": output_fields.get("proc.pid", ""),
            "cmdline": output_fields.get("proc.cmdline", ""),
        }
    }


class BridgeHandler(BaseHTTPRequestHandler):
    eda_url = "http://localhost:5000"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            falco_event = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        eda_event = transform(falco_event)
        print(f"[bridge] {falco_event.get('rule', '?')} → "
              f"{eda_event['payload']['alert_type']}/{eda_event['payload']['rule']}")

        try:
            req = Request(
                self.eda_url,
                data=json.dumps(eda_event).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=5) as resp:
                self.send_response(resp.status)
        except Exception as e:
            print(f"[bridge] EDA forward failed: {e}", file=sys.stderr)
            self.send_response(502)

        self.end_headers()

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="Falco → EDA bridge")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--eda-url", default="http://localhost:5000")
    args = parser.parse_args()

    BridgeHandler.eda_url = args.eda_url
    server = HTTPServer(("0.0.0.0", args.port), BridgeHandler)
    print(f"[bridge] Listening on :{args.port}, forwarding to {args.eda_url}")
    server.serve_forever()


if __name__ == "__main__":
    main()
