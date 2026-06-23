import json
import re
from typing import Any

class OpenApiParser:
    """
    Parses OpenAPI 3.x and Swagger 2.0 specifications.
    Extracts endpoints, parameters, authentication schemes, and identifies undocumented patterns.
    """
    def __init__(self, raw_spec: str | dict[str, Any]):
        if isinstance(raw_spec, str):
            try:
                self.spec = json.loads(raw_spec)
            except json.JSONDecodeError:
                self.spec = {}
        else:
            self.spec = raw_spec or {}

    def parse(self) -> dict[str, Any]:
        """
        Parses the specification and returns standard representation:
        {
            "endpoints": [
                {
                    "path": "/api/v1/users",
                    "method": "POST",
                    "auth_required": True,
                    "parameters": [{"name": "id", "in": "query", "type": "string"}]
                }
            ],
            "security_schemes": [...]
        }
        """
        endpoints = []
        if not self.spec:
            return {"endpoints": [], "security_schemes": []}

        # Determine version
        is_openapi_3 = "openapi" in self.spec
        paths = self.spec.get("paths", {})

        # Extract security schemes
        security_schemes = []
        if is_openapi_3:
            components = self.spec.get("components", {})
            security_schemes = list(components.get("securitySchemes", {}).keys())
        else:
            security_schemes = list(self.spec.get("securityDefinitions", {}).keys())

        # Extract paths
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            # Common parameters for all methods under this path
            common_params = path_item.get("parameters", [])

            for method, operation in path_item.items():
                if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                # Determine authentication status
                # If there's an operation-level security, use it. Otherwise, look for top-level security.
                has_op_security = "security" in operation
                op_security = operation.get("security", [])
                
                # If operation security is empty list (e.g., "security": []), then auth is explicitly NOT required
                if has_op_security and len(op_security) == 0:
                    auth_required = False
                elif has_op_security and len(op_security) > 0:
                    auth_required = True
                else:
                    # Fallback to global spec security
                    global_security = self.spec.get("security", [])
                    auth_required = len(global_security) > 0

                # Extract parameters
                op_params = operation.get("parameters", [])
                all_params = []
                
                # Combine common path parameters and operation-level parameters
                for param in (common_params + op_params):
                    if not isinstance(param, dict):
                        continue
                    param_name = param.get("name")
                    param_in = param.get("in", "query")
                    param_type = "string"
                    
                    if "schema" in param:
                        param_type = param["schema"].get("type", "string")
                    elif "type" in param:
                        param_type = param.get("type", "string")

                    all_params.append({
                        "name": param_name,
                        "in": param_in,
                        "type": param_type,
                        "required": param.get("required", False)
                    })

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "auth_required": auth_required,
                    "parameters": all_params
                })

        return {
            "endpoints": endpoints,
            "security_schemes": security_schemes
        }

    def detect_undocumented_patterns(self, actual_observed_paths: list[str]) -> list[str]:
        """
        Compares observed path URLs against the spec definition to find undocumented endpoints.
        """
        spec_info = self.parse()
        spec_paths = [e["path"] for e in spec_info["endpoints"]]
        
        undocumented = []
        for observed in actual_observed_paths:
            matched = False
            for spec_path in spec_paths:
                # Convert OpenAPI path template (e.g. `/users/{id}`) to regex (e.g. `/users/[^/]+`)
                regex_pattern = "^" + re.sub(r"\{[^}]+\}", "[^/]+", spec_path) + "$"
                if re.match(regex_pattern, observed):
                    matched = True
                    break
            if not matched:
                undocumented.append(observed)
                
        return undocumented
