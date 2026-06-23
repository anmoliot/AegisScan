from typing import Any

class DriftMonitor:
    """
    Tracks and identifies changes in attack surface assets over time.
    """
    @staticmethod
    def compare_subdomains(old_list: list[str], new_list: list[str]) -> dict[str, list[str]]:
        old_set = set(old_list)
        new_set = set(new_list)

        return {
            "added": sorted(list(new_set - old_set)),
            "removed": sorted(list(old_set - new_set))
        }

    @staticmethod
    def compare_services(old_services: list[dict[str, Any]], new_services: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """
        Compares port/protocol/banner details to find changed or newly opened services.
        """
        old_map = {f"{s['port']}/{s['protocol']}": s for s in old_services}
        new_map = {f"{s['port']}/{s['protocol']}": s for s in new_services}

        added = []
        removed = []
        changed = []

        for key, s in new_map.items():
            if key not in old_map:
                added.append(s)
            else:
                old_s = old_map[key]
                if s.get("banner") != old_s.get("banner") or s.get("technology") != old_s.get("technology"):
                    changed.append({"port": s["port"], "protocol": s["protocol"], "old_banner": old_s.get("banner"), "new_banner": s.get("banner")})

        for key, s in old_map.items():
            if key not in new_map:
                removed.append(s)

        return {
            "added": added,
            "removed": removed,
            "changed": changed
        }
