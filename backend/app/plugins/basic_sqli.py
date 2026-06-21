from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity


class BasicSqliPlugin(BasePlugin):
    name = "basic_sqli"
    description = "Checks query parameters for database error leakage"
    category = "injection"
    active = True
    errors = ("sql syntax", "unterminated quoted string", "sqlite error", "mysql_fetch", "postgresql error", "ora-01756")

    async def run(self, target_url, client):
        parsed = urlsplit(target_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)[:2]
        if not params:
            return []
        baseline = await client.get(target_url)
        baseline_lower = baseline.text.lower()
        findings = []
        for index, (name, value) in enumerate(params):
            mutated = list(params)
            mutated[index] = (name, value + "'")
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))
            response = await client.get(url)
            newly_seen = [marker for marker in self.errors if marker in response.text.lower() and marker not in baseline_lower]
            if newly_seen:
                findings.append(PluginResult(self.name, f"Database error after mutating {name}",
                    "A quote mutation caused a database-specific error not present in the baseline response.",
                    Severity.high, Confidence.medium, self.category, target_url,
                    f"New database error marker: {newly_seen[0]}",
                    "Use parameterized queries and return generic error responses.", "CWE-89",
                    {"parameter": name, "status_code": response.status_code}))
        return findings
