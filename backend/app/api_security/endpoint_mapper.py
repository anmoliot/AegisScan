import re
from typing import Any

class EndpointMapper:
    """
    Analyzes API endpoint listings to map hierarchies, group CRUD structures,
    classify privilege levels, and flag BOLA vulnerabilities.
    """
    def __init__(self, endpoints: list[dict[str, Any]]):
        self.endpoints = endpoints

    def map_relationships(self) -> dict[str, Any]:
        """
        Groups endpoints by base paths and resource hierarchies.
        Example: `/api/v1/users` and `/api/v1/users/{id}` belong to the `users` resource group.
        """
        groups = {}
        for ep in self.endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET")

            # Clean/standardize path for matching
            # Replace placeholder templates (like `{id}`, `:id`) with a placeholder
            normalized_path = re.sub(r"\{[^}]+\}", ":id", path)
            segments = [seg for seg in normalized_path.split("/") if seg]

            if not segments:
                resource = "root"
            else:
                # Find the primary resource name (usually the second segment after api/v1 or the first segment)
                if segments[0] in {"api", "v1", "v2", "v3"} and len(segments) > 1:
                    if segments[1] in {"v1", "v2", "v3"} and len(segments) > 2:
                        resource = segments[2]
                    else:
                        resource = segments[1]
                else:
                    resource = segments[0]

            # Strip placeholders to get base resource name
            resource = re.sub(r"[^a-zA-Z0-9_-]", "", resource)

            if resource not in groups:
                groups[resource] = []
            
            groups[resource].append({
                "path": path,
                "method": method,
                "auth_required": ep.get("auth_required", True),
                "is_bola_prone": self.is_bola_prone(path),
                "privilege_level": self.classify_privilege_level(path)
            })

        return groups

    def classify_privilege_level(self, path: str) -> str:
        """
        Heuristically classifies endpoint privilege levels.
        """
        lowered = path.lower()
        admin_keywords = {"/admin", "/manage", "/internal", "/sys", "/system", "/setup", "/config", "/debug"}
        if any(keyword in lowered for keyword in admin_keywords):
            return "admin"
        return "user"

    def is_bola_prone(self, path: str) -> bool:
        """
        Flags endpoints that accept resource identifiers in the path.
        e.g., `/api/v1/users/{id}`, `/api/v1/orders/{orderId}/items`
        """
        # Look for curly braces, colons, or generic dynamic segments
        return bool(re.search(r"\{[^}]+\}", path) or re.search(r"/:[a-zA-Z0-9_]+", path))
