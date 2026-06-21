from urllib.parse import urljoin

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity


class ExposedFilesPlugin(BasePlugin):
    name = "exposed_files"
    description = "Checks a tiny curated set of commonly exposed files"
    category = "exposure"
    paths = (("/.env", ("APP_KEY=", "DATABASE_URL=", "SECRET_KEY=")),
             ("/.git/HEAD", ("ref: refs/",)), ("/robots.txt", ("User-agent:",)),
             ("/openapi.json", ('"openapi"',)))

    async def run(self, target_url, client):
        findings = []
        for path, markers in self.paths:
            url = urljoin(target_url, path)
            response = await client.get(url)
            if response.status_code == 200 and any(marker.lower() in response.text[:10000].lower() for marker in markers):
                severity = Severity.info if path in {"/robots.txt", "/openapi.json"} else Severity.high
                findings.append(PluginResult(self.name, f"Exposed resource: {path}",
                    "A potentially sensitive or informative resource is publicly accessible.", severity,
                    Confidence.high, self.category, response.url, f"HTTP 200 with expected {path} content.",
                    "Remove sensitive files from the web root and restrict operational documentation as appropriate.",
                    "CWE-538", {"path": path, "status_code": response.status_code}))
        return findings
