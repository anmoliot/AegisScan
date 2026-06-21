from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity


class SecurityHeadersPlugin(BasePlugin):
    name = "security_headers"
    description = "Checks browser security response headers"
    category = "configuration"
    required = {
        "content-security-policy": (Severity.medium, "Define a restrictive Content-Security-Policy."),
        "x-content-type-options": (Severity.low, "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": (Severity.low, "Set a privacy-preserving Referrer-Policy."),
        "permissions-policy": (Severity.low, "Define a least-privilege Permissions-Policy."),
    }

    async def run(self, target_url, client):
        response = await client.get(target_url)
        findings = []
        for header, (severity, remediation) in self.required.items():
            if header not in response.headers:
                findings.append(PluginResult(self.name, f"Missing {header} header",
                    "The response omits a defense-in-depth browser security header.", severity,
                    Confidence.high, self.category, response.url, f"{header} was absent from the response.", remediation,
                    "CWE-693", {"header": header, "status_code": response.status_code}))
        if response.url.startswith("https://") and "strict-transport-security" not in response.headers:
            findings.append(PluginResult(self.name, "Missing HSTS header", "HTTPS is not protected by an HSTS policy.",
                Severity.medium, Confidence.high, self.category, response.url,
                "strict-transport-security was absent.", "Set Strict-Transport-Security after validating all subdomains.",
                "CWE-319"))
        return findings
