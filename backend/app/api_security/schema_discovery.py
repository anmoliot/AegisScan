import json
from urllib.parse import urljoin, urlsplit, urlunsplit
from typing import Any

class SchemaDiscovery:
    """
    Probes well-known paths on a target to discover OpenAPI/Swagger/GraphQL endpoints
    and analyze schema definitions.
    """
    WELL_KNOWN_PATHS = (
        # OpenAPI / Swagger
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/api/v1/openapi.json",
        "/api/v1/swagger.json",
        "/swagger/v1/swagger.json",
        "/swagger-ui.html",
        "/swagger/index.html",
        "/api/docs",
        # GraphQL
        "/graphql",
        "/gql",
        "/api/graphql",
        "/query"
    )

    def __init__(self, target_url: str):
        self.target_url = target_url

    async def discover(self, client) -> dict[str, Any]:
        """
        Iterates over well-known paths on the target using the client to locate active APIs.
        Returns api_type, schema_definition, endpoints.
        """
        parsed = urlsplit(self.target_url)
        base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

        discovered_apis = []

        for path in self.WELL_KNOWN_PATHS:
            probe_url = urljoin(base_url, path)
            try:
                response = await client.get(probe_url)
            except Exception:
                continue

            if response.status_code == 200:
                text = response.text
                content_type = response.headers.get("content-type", "").lower()
                
                # Check for OpenAPI / JSON structure
                if "json" in content_type or text.strip().startswith("{") or text.strip().startswith("["):
                    try:
                        data = json.loads(text)
                        # Verify it's actually OpenAPI/Swagger spec
                        if isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data):
                            discovered_apis.append({
                                "url": probe_url,
                                "api_type": "REST",
                                "schema_definition": text,
                                "headers": dict(response.headers)
                            })
                            # Stop after finding a major OpenAPI specification
                            break
                    except Exception:
                        pass
                
                # Check for GraphQL endpoint
                # GraphQL endpoints often respond with 400 Bad Request if requested directly via GET without query,
                # but might return JSON schema or support POST introspection.
                # If we hit `/graphql` and it looks like a GraphQL server (even if it returns 400 with 'errors' or similar)
                if "/graphql" in path or "/gql" in path:
                    # Let's verify by attempting an introspection query or checking common keywords
                    if any(kw in text.lower() for kw in ("graphql", "query", "errors", "must provide query")):
                        discovered_apis.append({
                            "url": probe_url,
                            "api_type": "GraphQL",
                            "schema_definition": None,
                            "headers": dict(response.headers)
                        })

        if discovered_apis:
            # Return primary found API
            return discovered_apis[0]
        
        # Fallback empty result
        return {
            "url": self.target_url,
            "api_type": "REST",
            "schema_definition": None,
            "headers": {}
        }
