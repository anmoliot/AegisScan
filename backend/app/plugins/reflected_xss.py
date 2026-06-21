from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity


class ReflectedXssPlugin(BasePlugin):
    name = "reflected_xss"
    description = "Uses a harmless marker to detect unencoded query reflection"
    category = "injection"
    active = True
    marker = "aegisxss<probe>"

    async def run(self, target_url, client):
        parsed = urlsplit(target_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)[:2]
        findings = []
        for index, (name, _) in enumerate(params):
            mutated = list(params)
            mutated[index] = (name, self.marker)
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))
            response = await client.get(url)
            if self.marker in response.text:
                findings.append(PluginResult(self.name, f"Unencoded reflection in {name}",
                    "A query value containing HTML metacharacters was reflected verbatim. This is a signal, not executable-XSS proof.",
                    Severity.medium, Confidence.medium, self.category, target_url,
                    "The harmless marker was present verbatim in the response body.",
                    "Apply context-aware output encoding and a restrictive Content-Security-Policy.", "CWE-79",
                    {"parameter": name, "probe": self.marker, "status_code": response.status_code}))
        return findings
