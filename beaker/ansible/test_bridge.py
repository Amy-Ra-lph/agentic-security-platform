"""Tests for falco_siem_bridge transform and syslog formatting."""
import json
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from falco_siem_bridge import transform, format_rfc5424, format_cef, send_syslog

SAMPLE_FALCO_EVENT = {
    "rule": "Agent Swarm — Unauthorized Process Spawning",
    "priority": "Critical",
    "output": "SWARM: Agent spawned unauthorized child process (agent=code-assist-9a2b pid=12345)",
    "tags": ["agentic-security", "swarm", "SWARM-001"],
    "output_fields": {
        "proc.pname": "python3",
        "proc.pid": 12345,
        "proc.cmdline": "python3 agent_worker.py --autonomous",
        "user.name": "code-assist-9a2b",
        "container.name": "agent-sandbox",
    },
    "time": "2026-10-02T10:30:45.000000000Z",
}

SAMPLE_EXFIL_EVENT = {
    "rule": "Agent Credential Harvesting",
    "priority": "Critical",
    "output": "EXFIL: Agent read credential file (agent=rogue-agent file=.aws/credentials)",
    "tags": ["agentic-security", "exfiltration", "EXFIL-002"],
    "output_fields": {
        "proc.pname": "python3",
        "proc.pid": 6789,
        "proc.cmdline": "python3 rogue_agent.py",
        "user.name": "rogue-agent",
        "fd.name": "/root/.aws/credentials",
    },
    "time": "2026-10-02T10:31:00.000000000Z",
}

SAMPLE_ESCAPE_EVENT = {
    "rule": "Agent Sandbox Escape Attempt",
    "priority": "Critical",
    "output": "SBX: Agent attempted sandbox escape via nsenter",
    "tags": ["agentic-security", "sandbox-escape", "SBX-002"],
    "output_fields": {
        "proc.pname": "nsenter",
        "proc.pid": 9999,
        "proc.cmdline": "nsenter -t 1 -m -u -i -n",
        "user.name": "rogue-agent",
    },
    "time": "2026-10-02T10:32:00.000000000Z",
}


class TestTransform(unittest.TestCase):
    def test_swarm_event_extracts_alert_type(self):
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["alert_type"], "swarm")

    def test_swarm_event_extracts_rule_id(self):
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["rule"], "SWARM-001")

    def test_swarm_event_extracts_agent_principal(self):
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["agent_principal"], "code-assist-9a2b")

    def test_swarm_event_has_mitre_id(self):
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["mitre_id"], "T1059.006")

    def test_exfil_event_has_mitre_id(self):
        result = transform(SAMPLE_EXFIL_EVENT)
        self.assertEqual(result["payload"]["mitre_id"], "T1552.001")

    def test_escape_event_has_mitre_id(self):
        result = transform(SAMPLE_ESCAPE_EVENT)
        self.assertEqual(result["payload"]["mitre_id"], "T1611")

    def test_escape_event_alert_type(self):
        result = transform(SAMPLE_ESCAPE_EVENT)
        self.assertEqual(result["payload"]["alert_type"], "escape")

    def test_transform_has_ocsf_class(self):
        result = transform(SAMPLE_FALCO_EVENT)
        self.assertEqual(result["payload"]["ocsf_class_uid"], 2001)

    def test_unknown_tags_produce_unknown_alert_type(self):
        event = {**SAMPLE_FALCO_EVENT, "tags": ["something-else"]}
        result = transform(event)
        self.assertEqual(result["payload"]["alert_type"], "unknown")

    def test_unknown_rule_has_empty_mitre(self):
        event = {**SAMPLE_FALCO_EVENT, "tags": ["swarm"]}
        result = transform(event)
        self.assertEqual(result["payload"]["mitre_id"], "")

    def test_agent_principal_from_output_when_user_is_root(self):
        event = {**SAMPLE_FALCO_EVENT}
        event["output_fields"] = {**event["output_fields"], "user.name": "root"}
        result = transform(event)
        self.assertEqual(result["payload"]["agent_principal"], "code-assist-9a2b")

    def test_agent_principal_fallback_to_pname(self):
        event = {**SAMPLE_FALCO_EVENT}
        event["output_fields"] = {"proc.pname": "rogue-binary"}
        event["output"] = "no agent= tag here"
        result = transform(event)
        self.assertEqual(result["payload"]["agent_principal"], "rogue-binary")


class TestSyslogFormat(unittest.TestCase):
    def test_rfc5424_format(self):
        eda_event = transform(SAMPLE_FALCO_EVENT)
        msg = format_rfc5424(eda_event["payload"])
        self.assertIn("agent-security", msg)
        self.assertIn('alert_type="swarm"', msg)
        self.assertIn('mitre_id="T1059.006"', msg)
        self.assertIn('agent_principal="code-assist-9a2b"', msg)
        self.assertIn("falco-siem-bridge", msg)
        self.assertTrue(msg.startswith("<134>1 "))

    def test_cef_format(self):
        eda_event = transform(SAMPLE_FALCO_EVENT)
        msg = format_cef(eda_event["payload"])
        self.assertTrue(msg.startswith("CEF:0|"))
        self.assertIn("SWARM-001", msg)
        self.assertIn("suser=code-assist-9a2b", msg)
        self.assertIn("cs1=T1059.006", msg)
        self.assertIn("cs1Label=mitreTechniqueId", msg)

    def test_cef_severity_critical(self):
        eda_event = transform(SAMPLE_FALCO_EVENT)
        msg = format_cef(eda_event["payload"])
        self.assertIn("|9|", msg)

    def test_cef_severity_non_critical(self):
        event = {**SAMPLE_FALCO_EVENT, "priority": "Warning"}
        eda_event = transform(event)
        msg = format_cef(eda_event["payload"])
        self.assertIn("|6|", msg)


class TestSyslogFailureIsolation(unittest.TestCase):
    def test_syslog_failure_does_not_raise(self):
        eda_event = transform(SAMPLE_FALCO_EVENT)
        # RFC 5424 test doc address — unreachable, should not raise
        send_syslog(eda_event["payload"], host="192.0.2.1", port=514,
                    proto="tcp", cef=False)

    def test_no_syslog_when_host_empty(self):
        eda_event = transform(SAMPLE_FALCO_EVENT)
        # Empty host = no-op, must not raise
        send_syslog(eda_event["payload"], host="", port=514,
                    proto="tcp", cef=False)


class TestBackwardCompatibility(unittest.TestCase):
    def test_eda_payload_has_required_fields(self):
        result = transform(SAMPLE_FALCO_EVENT)
        payload = result["payload"]
        for field in ["alert_type", "rule", "agent_principal", "agent_realm",
                      "timestamp", "falco_priority", "falco_rule", "falco_output"]:
            self.assertIn(field, payload, f"Missing required field: {field}")

    def test_eda_payload_has_new_fields(self):
        result = transform(SAMPLE_FALCO_EVENT)
        payload = result["payload"]
        self.assertIn("mitre_id", payload)
        self.assertIn("ocsf_class_uid", payload)

    def test_all_seven_rules_have_mitre_mapping(self):
        from falco_siem_bridge import MITRE_MAP
        expected = {"SWARM-001", "SWARM-002", "EXFIL-002", "EXFIL-003",
                    "NET-002", "SCOPE-001", "SBX-002"}
        self.assertEqual(set(MITRE_MAP.keys()), expected)


if __name__ == "__main__":
    unittest.main()
