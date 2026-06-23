from http.cookies import SimpleCookie

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity


class CookieFlagsPlugin(BasePlugin):
    name = "cookie_flags"
    description = "Checks security flags on response cookies"
    category = "session"

    async def run(self, target_url, client):
        response = await client.get(target_url)
        findings = []
        for raw in response.headers.get_list("set-cookie"):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                continue
            for name, morsel in cookie.items():
                missing = []
                if not morsel["httponly"]:
                    missing.append("HttpOnly")
                if response.url.startswith("https://") and not morsel["secure"]:
                    missing.append("Secure")
                if not morsel["samesite"]:
                    missing.append("SameSite")
                if missing:
                    findings.append(PluginResult(self.name, f"Cookie {name} lacks security flags",
                        "A response cookie is missing one or more defensive attributes.", Severity.medium,
                        Confidence.high, self.category, response.url, f"Missing: {', '.join(missing)}",
                        "Set HttpOnly and SameSite; set Secure for HTTPS cookies.", "CWE-614",
                        {"cookie_name": name, "missing_flags": missing}))
        return findings
