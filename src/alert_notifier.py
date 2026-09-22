"""
Rule Loader & Alert Notification Webhook Dispatcher
Provides hot-reloading of Suricata rule sets and dispatches webhooks for High-Severity (Priority 1) alerts.
"""

import os
import json
import logging
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class AlertNotificationDispatcher:
    """
    Dispatches alerts to configured SIEM / SOAR / Slack / Discord webhook endpoints.
    Falls back to structured audit logging if no endpoint is configured.
    """
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.environ.get("IDS_WEBHOOK_URL", "")

    def dispatch(self, alert_data: dict) -> bool:
        """
        Dispatches notification for high-severity alerts.
        """
        severity = int(alert_data.get("severity", 3))
        sig_name = alert_data.get("signature", "Unknown Alert")
        sid = alert_data.get("signature_id", 0)
        src = f"{alert_data.get('src_ip', '0.0.0.0')}:{alert_data.get('src_port', 0)}"
        dst = f"{alert_data.get('dest_ip', '0.0.0.0')}:{alert_data.get('dest_port', 0)}"
        reason = alert_data.get("reason", "")

        # Trigger on High-Severity (Severity 1) alerts
        if severity == 1:
            payload = {
                "event": "HIGH_SEVERITY_INTRUSION_ALERT",
                "signature_id": sid,
                "signature": sig_name,
                "source": src,
                "destination": dst,
                "protocol": alert_data.get("proto", "TCP"),
                "timestamp": alert_data.get("timestamp", ""),
                "evidence_proof": reason
            }

            if self.webhook_url:
                try:
                    resp = requests.post(self.webhook_url, json=payload, timeout=3.0)
                    logging.info(f"[NOTIFIER] Webhook dispatched to {self.webhook_url} (HTTP {resp.status_code})")
                    return resp.status_code in [200, 201, 202, 204]
                except Exception as e:
                    logging.warning(f"[NOTIFIER] Webhook dispatch failed: {e}")
            else:
                logging.info(f"[NOTIFIER-AUDIT-LOG] [HIGH-SEVERITY ALERT HOOK FIRED] SID: {sid} | {sig_name} | {src} -> {dst}")
                return True
        return False


def load_rules_from_file(rule_path: str = "config/custom_rules.rules") -> list:
    """
    Parses Suricata rules file dynamically at runtime.
    Enables hot-reloading of rules without restarting the application.
    """
    if not os.path.exists(rule_path):
        return []
    
    rules = []
    with open(rule_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("alert ") or line.startswith("drop ") or line.startswith("pass "):
                rules.append({
                    "line_number": line_no,
                    "raw_rule": line
                })
    return rules
