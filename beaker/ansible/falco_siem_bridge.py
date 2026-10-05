#!/usr/bin/env python3
"""Falco → EDA + SIEM bridge.

Receives Falco alerts via Falcosidekick webhook, enriches with agent
context and MITRE ATT&CK mapping, forwards to:
  1. EDA webhook (:5000) — automated response (existing behavior)
  2. Syslog BSD / CEF (:514) — SOC visibility via Wazuh

Without --syslog-host, behaves identically to falco-eda-bridge.py.

Run:
    python3 falco_siem_bridge.py --port 5001 --eda-url http://localhost:5000 \
        --syslog-host 10.x.x.x --syslog-port 514 --syslog-proto udp
"""

import argparse
import json
import re
import socket
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen

TAG_TO_ALERT_TYPE = {
    "swarm": "swarm",
    "exfiltration": "exfiltration",
    "escalation": "escalation",
    "sandbox-escape": "escape",
    "network": "exfiltration",
}

RULE_TAG_PATTERN = re.compile(r"^[A-Z]+-\d+$")

MITRE_MAP = {
    "SWARM-001": "T1059.006",
    "SWARM-002": "T1106",
    "EXFIL-002": "T1552.001",
    "EXFIL-003": "T1048.002",
    "NET-002": "T1562.004",
    "SCOPE-001": "T1078.003",
    "SBX-002": "T1611",
}

OCSF_CLASS_UID = 2001  # Security Finding


def extract_agent_principal(output_fields: dict, output: str) -> str:
    user = output_fields.get("user.name", "")
    if user and user != "root":
        return user
    match = re.search(r"agent=(\S+)", output)
    if match:
        return match.group(1)
    return output_fields.get("proc.name", output_fields.get("proc.pname", "unknown-agent"))


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

    mitre_id = MITRE_MAP.get(rule_id, "")

    return {
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
        "mitre_id": mitre_id,
        "ocsf_class_uid": OCSF_CLASS_UID,
    }


def format_syslog(payload: dict) -> str:
    """BSD syslog (RFC 3164) — Wazuh pre-decoder extracts program_name from this format."""
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    hostname = payload.get("source_host", "agent-host")
    fields = (
        f'alert_type="{payload.get("alert_type", "unknown")}"'
        f' agent_principal="{payload.get("agent_principal", "unknown")}"'
        f' mitre_id="{payload.get("mitre_id", "")}"'
        f' rule="{payload.get("rule", "")}"'
    )
    msg = payload.get("falco_output", "")
    return f"<134>{ts} {hostname} falco-siem-bridge: {fields} {msg}"


def format_cef(payload: dict) -> str:
    rule = payload.get("rule", "UNKNOWN")
    name = payload.get("falco_rule", "Unknown Rule")
    severity = "9" if payload.get("falco_priority", "").lower() == "critical" else "6"
    msg = payload.get("falco_output", "").replace("\\", "\\\\").replace("|", "\\|")
    return (
        f"CEF:0|RedHat|AgenticSecurity|1.0|{rule}|{name}|{severity}|"
        f"src={payload.get('source_host', '')} "
        f"suser={payload.get('agent_principal', '')} "
        f"cs1={payload.get('mitre_id', '')} cs1Label=mitreTechniqueId "
        f"cs2={payload.get('agent_realm', '')} cs2Label=agentRealm "
        f"msg={msg}"
    )


def send_syslog(payload: dict, host: str, port: int, proto: str, cef: bool):
    if not host:
        return
    msg = format_cef(payload) if cef else format_syslog(payload)
    try:
        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode("utf-8"), (host, port))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.sendall(msg.encode("utf-8") + b"\n")
            sock.close()
    except Exception as e:
        print(f"[bridge] syslog send failed ({host}:{port}): {e}", file=sys.stderr)


class BridgeHandler(BaseHTTPRequestHandler):
    eda_url = "http://localhost:5000"
    eda_token = ""
    syslog_host = ""
    syslog_port = 514
    syslog_proto = "tcp"
    syslog_cef = False

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
              f"{eda_event['alert_type']}/{eda_event['rule']} mitre={eda_event['mitre_id']}")

        try:
            headers = {"Content-Type": "application/json"}
            if self.eda_token:
                headers["Authorization"] = f"Bearer {self.eda_token}"
            req = Request(
                self.eda_url,
                data=json.dumps(eda_event).encode(),
                headers=headers,
                method="POST",
            )
            with urlopen(req, timeout=5) as resp:
                self.send_response(resp.status)
        except Exception as e:
            print(f"[bridge] EDA forward failed: {e}", file=sys.stderr)
            self.send_response(502)

        self.end_headers()

        send_syslog(eda_event, self.syslog_host, self.syslog_port,
                    self.syslog_proto, self.syslog_cef)

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="Falco → EDA + SIEM bridge")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--eda-url", default="http://localhost:5000")
    parser.add_argument("--eda-token", default="",
                        help="Bearer token for EDA webhook authentication")
    parser.add_argument("--syslog-host", default="")
    parser.add_argument("--syslog-port", type=int, default=514)
    parser.add_argument("--syslog-proto", choices=["tcp", "udp"], default="udp")
    parser.add_argument("--cef", action="store_true",
                        help="Use CEF format instead of RFC 5424")
    args = parser.parse_args()

    BridgeHandler.eda_url = args.eda_url
    BridgeHandler.eda_token = args.eda_token
    BridgeHandler.syslog_host = args.syslog_host
    BridgeHandler.syslog_port = args.syslog_port
    BridgeHandler.syslog_proto = args.syslog_proto
    BridgeHandler.syslog_cef = args.cef

    server = HTTPServer(("0.0.0.0", args.port), BridgeHandler)
    syslog_status = f" syslog→{args.syslog_host}:{args.syslog_port}" if args.syslog_host else " (no syslog)"
    print(f"[bridge] Listening on :{args.port}, EDA→{args.eda_url}{syslog_status}")
    server.serve_forever()


if __name__ == "__main__":
    main()
