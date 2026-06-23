from typing import Any

class AlertEngine:
    """
    Classifies drift results into severity and maps them to Alert structures.
    Handles basic alert deduplication.
    """
    @staticmethod
    def classify_severity(alert_type: str) -> str:
        """
        Maps alert types to standard severities: critical, high, medium, low.
        """
        severity_map = {
            "subdomain_added": "medium",
            "subdomain_removed": "low",
            "cert_expired": "critical",
            "cert_expiry_warning": "high",
            "dns_record_changed": "medium",
            "monitoring_error": "high"
        }
        return severity_map.get(alert_type, "low")

    @staticmethod
    def should_deduplicate(existing_alerts: list[dict[str, Any]], message: str) -> bool:
        """
        Checks if a similar alert has already been raised recently and remains unacknowledged.
        """
        for alert in existing_alerts:
            if alert.get("message") == message and not alert.get("acknowledged", False):
                return True
        return False
