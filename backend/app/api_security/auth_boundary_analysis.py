from typing import Any

class AuthBoundaryAnalysis:
    """
    Analyzes API endpoint authentication configurations, flags endpoints lacking authentication,
    and identifies sensitive endpoints exposed without protection.
    """
    def __init__(self, endpoints: list[dict[str, Any]]):
        self.endpoints = endpoints

    def analyze(self) -> dict[str, Any]:
        """
        Scans all endpoints to identify security boundaries.
        Returns:
            - authenticated_count: int
            - public_count: int
            - public_endpoints: list
            - exposed_sensitive_endpoints: list
        """
        public_endpoints = []
        exposed_sensitive_endpoints = []
        auth_count = 0
        public_count = 0

        sensitive_keywords = {"admin", "delete", "update", "create", "user", "account", "settings", "password", "token", "payment", "profile"}

        for ep in self.endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            auth_required = ep.get("auth_required", True)

            if auth_required:
                auth_count += 1
            else:
                public_count += 1
                public_endpoints.append(ep)
                
                # Check if it has sensitive keywords or modification methods
                lowered_path = path.lower()
                is_sensitive_path = any(kw in lowered_path for kw in sensitive_keywords)
                is_state_changing = method.upper() in {"POST", "PUT", "DELETE", "PATCH"}
                
                if is_sensitive_path or is_state_changing:
                    exposed_sensitive_endpoints.append(ep)

        return {
            "authenticated_count": auth_count,
            "public_count": public_count,
            "public_endpoints": public_endpoints,
            "exposed_sensitive_endpoints": exposed_sensitive_endpoints
        }
