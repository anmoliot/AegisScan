from typing import Any

class MassAssignmentDetector:
    """
    Analyzes API schemas to find potential mass assignment vulnerabilities.
    Flags sensitive parameter inputs present in write operations (POST, PUT, PATCH).
    """
    SENSITIVE_FIELDS = {
        "role", "is_admin", "is_superuser", "privileges", "permissions", "admin",
        "verified", "status", "email_verified", "credit", "balance", "owner",
        "created_at", "updated_at", "user_id", "id", "uuid", "account_type",
        "plan", "subscription", "price", "amount", "salary", "bonus"
    }

    def __init__(self, endpoints: list[dict[str, Any]]):
        self.endpoints = endpoints

    def detect(self) -> list[dict[str, Any]]:
        """
        Analyzes the parameters of write operations to flag mass-assignable sensitive properties.
        """
        findings = []

        for ep in self.endpoints:
            method = ep.get("method", "GET").upper()
            if method not in {"POST", "PUT", "PATCH"}:
                continue

            path = ep.get("path", "")
            params = ep.get("parameters", [])

            sensitive_params = []
            for param in params:
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                
                # Check if param name matches sensitive field names
                if name.lower() in self.SENSITIVE_FIELDS:
                    sensitive_params.append({
                        "name": name,
                        "type": param.get("type", "string"),
                        "required": param.get("required", False)
                    })

            if sensitive_params:
                findings.append({
                    "path": path,
                    "method": method,
                    "sensitive_parameters": sensitive_params,
                    "confidence": "medium" if len(sensitive_params) > 1 else "low",
                    "remediation": "Do not bind HTTP request objects directly to database models. Use specific Data Transfer Objects (DTOs) or Schema input parameters to allowlist only user-modifiable fields."
                })

        return findings
