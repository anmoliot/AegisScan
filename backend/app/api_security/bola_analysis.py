from typing import Any
from app.api_security.endpoint_mapper import EndpointMapper

class BolaAnalyzer:
    """
    Performs API-specific BOLA (Broken Object Level Authorization) analysis
    based on endpoint paths, parameters, and patterns.
    """
    def __init__(self, endpoints: list[dict[str, Any]]):
        self.endpoints = endpoints
        self.mapper = EndpointMapper(endpoints)

    def analyze(self) -> list[dict[str, Any]]:
        """
        Scans endpoints to identify those highly susceptible to BOLA (IDOR).
        BOLA susceptibility criteria:
        1. Paths containing identifier parameters (e.g. `{id}`, `:userId`)
        2. Read or Write operations on single resources.
        """
        susceptible_endpoints = []
        
        # Map endpoints first
        groups = self.mapper.map_relationships()

        for resource, resource_eps in groups.items():
            for ep in resource_eps:
                path = ep["path"]
                method = ep["method"]
                
                # Check if it has a dynamic resource identifier
                if ep["is_bola_prone"]:
                    # Score susceptibility
                    # State changing writes (PUT, DELETE, PATCH) are higher impact
                    severity = "high" if method in {"PUT", "DELETE", "PATCH"} else "medium"
                    
                    susceptible_endpoints.append({
                        "resource": resource,
                        "path": path,
                        "method": method,
                        "auth_required": ep["auth_required"],
                        "susceptibility": "high" if severity == "high" else "medium",
                        "description": f"Endpoint represents a dynamic single-resource path ({path}) and requires verification that request authorizations validate user ownership of the specified key."
                    })

        return susceptible_endpoints
