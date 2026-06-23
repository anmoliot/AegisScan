import re

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity


class TechnologyPlugin(BasePlugin):
    name = "technology"
    description = "Reports lightweight technology indicators"
    category = "information"

    async def run(self, target_url, client):
        response = await client.get(target_url)
        signals = []
        for header in ("server", "x-powered-by"):
            if value := response.headers.get(header):
                signals.append(f"{header}: {value[:120]}")
        patterns = {"WordPress": r"wp-content|wp-includes", "React": r"data-reactroot|__NEXT_DATA__",
                    "Drupal": r"Drupal.settings|drupalSettings"}
        signals.extend(name for name, pattern in patterns.items() if re.search(pattern, response.text, re.I))
        if not signals:
            return []
        return [PluginResult(self.name, "Technology indicators disclosed",
            "Public response metadata reveals probable implementation technologies.", Severity.info,
            Confidence.medium, self.category, response.url, "; ".join(signals),
            "Remove unnecessary version-bearing headers; technology presence alone is not a vulnerability.",
            "CWE-200", {"signals": signals})]
