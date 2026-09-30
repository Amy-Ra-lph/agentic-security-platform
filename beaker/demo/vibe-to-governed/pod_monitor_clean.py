# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Demo User
"""Pod Monitor Agent — watches Kubernetes pods and sends alerts.

Remediated version: uses service account tokens, scoped API access,
no credential harvesting, no external telemetry exfiltration.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

SA_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
SA_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
KUBE_API = "https://kubernetes.default.svc"


def get_service_account_token() -> str:
    """Read the mounted service account token (projected, auto-rotated)."""
    if not SA_TOKEN_PATH.exists():
        raise FileNotFoundError("No service account token mounted")
    return SA_TOKEN_PATH.read_text().strip()


def collect_pod_metrics(namespace: str = "default") -> dict:
    """Gather pod status from the cluster API using service account auth."""
    token = get_service_account_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    resp = requests.get(
        f"{KUBE_API}/api/v1/namespaces/{namespace}/pods",
        headers=headers,
        verify=str(SA_CA_PATH),
        timeout=30,
    )
    resp.raise_for_status()
    pods = resp.json().get("items", [])

    return {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "namespace": namespace,
        "pod_count": len(pods),
        "pods": [
            {
                "name": p["metadata"]["name"],
                "status": p["status"]["phase"],
                "restarts": sum(
                    cs.get("restartCount", 0)
                    for cs in p.get("status", {}).get("containerStatuses", [])
                ),
            }
            for p in pods
        ],
    }


def check_pod_health(pod_data: dict) -> list[str]:
    """Analyze pod health and return alerts."""
    alerts = []
    for pod in pod_data.get("pods", []):
        if pod["status"] != "Running":
            alerts.append(f"Pod {pod['name']}: {pod['status']}")
        if pod["restarts"] > 5:
            alerts.append(f"Pod {pod['name']}: {pod['restarts']} restarts")
    return alerts


def write_report(metrics: dict, alerts: list[str], output_dir: str = "/tmp") -> Path:
    """Write monitoring report to local filesystem."""
    report = {
        "metrics": metrics,
        "alerts": alerts,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    report_path = Path(output_dir) / "pod-monitor-report.json"
    report_path.write_text(json.dumps(report, indent=2))
    return report_path


def main():
    """Run pod monitoring cycle."""
    print("Pod Monitor v2.0 — Starting health check cycle")
    print(f"  Cluster: {KUBE_API}")
    print(f"  Timestamp: {datetime.now(tz=timezone.utc).isoformat()}")

    metrics = collect_pod_metrics()
    alerts = check_pod_health(metrics)

    print(f"  Pods monitored: {metrics['pod_count']}")
    print(f"  Alerts: {len(alerts)}")

    report_path = write_report(metrics, alerts)
    print(f"  Report: {report_path}")

    if alerts:
        for alert in alerts:
            print(f"  Warning: {alert}")

    print("  Done: Monitoring cycle complete")


if __name__ == "__main__":
    main()
