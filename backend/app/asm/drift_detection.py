from typing import Any

class DriftDetector:
    """
    Compares two states of assets to identify newly discovered subdomains,
    removed hostnames, changed DNS records, or expired certificates.
    """
    @staticmethod
    def detect_subdomain_drift(old_subdomains: list[str], new_subdomains: list[str]) -> dict[str, list[str]]:
        old_set = set(old_subdomains)
        new_set = set(new_subdomains)

        return {
            "added": sorted(list(new_set - old_set)),
            "removed": sorted(list(old_set - new_set))
        }

    @staticmethod
    def detect_dns_drift(old_records: dict[str, Any], new_records: dict[str, Any]) -> dict[str, dict[str, Any]]:
        drift = {}
        for record_type in ["A", "CNAME", "MX", "TXT", "NS"]:
            old_vals = set(old_records.get(record_type, []))
            new_vals = set(new_records.get(record_type, []))

            added = list(new_vals - old_vals)
            removed = list(old_vals - new_vals)

            if added or removed:
                drift[record_type] = {
                    "added": added,
                    "removed": removed
                }
        return drift
