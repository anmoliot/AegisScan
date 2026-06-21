import httpx
import pytest

from app.plugins.security_headers import SecurityHeadersPlugin
from app.scanner.http_client import ScanResponse


class FakeClient:
    async def get(self, url):
        return ScanResponse(url, 200, httpx.Headers({"content-type": "text/html"}), "ok", 1.0)


@pytest.mark.asyncio
async def test_security_header_plugin_normalizes_results():
    findings = await SecurityHeadersPlugin().run("https://example.com/", FakeClient())
    assert {finding.severity.value for finding in findings} <= {"low", "medium"}
    assert any("content-security-policy" in finding.title for finding in findings)
    assert all(len(finding.fingerprint) == 64 for finding in findings)
