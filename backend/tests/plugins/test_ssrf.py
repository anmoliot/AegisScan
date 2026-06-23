import httpx
import pytest

from app.plugins.base import Confidence, Severity
from app.plugins.ssrf.detector import SsrfPlugin
from app.plugins.ssrf.callbacks import SsrfScorer
from app.scanner.http_client import ScanResponse


from urllib.parse import unquote


class MockSsrfClient:
    def __init__(self, response_map: dict[str, tuple[int, str]]):
        self.response_map = response_map
        self.requests_made = []

    async def get(self, url: str) -> ScanResponse:
        self.requests_made.append(url)
        # Default response is ok/safe baseline
        status_code = 200
        text = "safe baseline content"
        
        # Exact match or substring match using unquoted url
        unquoted_url = unquote(url)
        for key, (sc, txt) in self.response_map.items():
            if key in unquoted_url:
                status_code = sc
                text = txt
                break
                
        return ScanResponse(
            url=url,
            status_code=status_code,
            headers=httpx.Headers({"content-type": "text/html"}),
            text=text,
            elapsed_ms=1.5
        )


def test_ssrf_looks_url_like():
    plugin = SsrfPlugin()
    assert plugin._looks_url_like("url", "http://example.com") is True
    assert plugin._looks_url_like("image_url", "something") is True
    assert plugin._looks_url_like("random", "http://any-url.com") is True
    assert plugin._looks_url_like("not_a_link", "simple_value") is False


@pytest.mark.asyncio
async def test_ssrf_metadata_detection_aws():
    target = "https://example.com/proxy?url=http://google.com"
    # Set up mock response containing AWS credentials when AWS metadata probe is hit
    response_map = {
        "iam/security-credentials": (200, "AccessKeyId SecretAccessKey Token ami-id instance-id"),
    }
    client = MockSsrfClient(response_map)
    plugin = SsrfPlugin()
    
    findings = await plugin.run(target, client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence == Confidence.high
    assert finding.severity == Severity.critical
    assert finding.evidence_data["parameter"] == "url"
    assert finding.evidence_data["test_type"] == "metadata_aws"
    assert finding.evidence_data["validation_score"] >= 90
    assert "accesskeyid" in finding.evidence.lower()
    assert "replay_data" in finding.evidence_data


@pytest.mark.asyncio
async def test_ssrf_metadata_detection_azure():
    target = "https://example.com/proxy?url=http://google.com"
    response_map = {
        "metadata/instance": (200, "subscriptionId resourceGroupName computeMetadata vmId"),
    }
    client = MockSsrfClient(response_map)
    plugin = SsrfPlugin()
    
    findings = await plugin.run(target, client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence == Confidence.high
    assert finding.evidence_data["test_type"] == "metadata_azure"


@pytest.mark.asyncio
async def test_ssrf_metadata_detection_gcp():
    target = "https://example.com/proxy?url=http://google.com"
    response_map = {
        "computeMetadata/v1/instance": (200, "computeMetadata serviceAccounts accessToken"),
    }
    client = MockSsrfClient(response_map)
    plugin = SsrfPlugin()
    
    findings = await plugin.run(target, client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence == Confidence.high
    assert finding.evidence_data["test_type"] == "metadata_gcp"


@pytest.mark.asyncio
async def test_ssrf_protocol_smuggling_file():
    target = "https://example.com/proxy?url=http://google.com"
    response_map = {
        "file:///etc/passwd": (200, "root:x:0:0:root:/root:/bin/bash"),
    }
    client = MockSsrfClient(response_map)
    plugin = SsrfPlugin()
    
    findings = await plugin.run(target, client)
    # Filter for protocol_file findings
    file_findings = [f for f in findings if f.evidence_data["test_type"] == "protocol_file"]
    assert len(file_findings) == 1
    assert file_findings[0].severity == Severity.high
    assert file_findings[0].confidence == Confidence.high


@pytest.mark.asyncio
async def test_ssrf_protocol_smuggling_gopher():
    target = "https://example.com/proxy?url=http://google.com"
    response_map = {
        "gopher://": (200, "+PONG redis server output"),
    }
    client = MockSsrfClient(response_map)
    plugin = SsrfPlugin()
    
    findings = await plugin.run(target, client)
    gopher_findings = [f for f in findings if f.evidence_data["test_type"] == "protocol_gopher"]
    assert len(gopher_findings) == 1


@pytest.mark.asyncio
async def test_ssrf_redirect_chain():
    target = "https://example.com/proxy?url=http://google.com"
    response_map = {
        "localhost@169.254.169.254": (200, "AccessKeyId SecretAccessKey Token ami-id instance-id"),
    }
    client = MockSsrfClient(response_map)
    plugin = SsrfPlugin()
    
    findings = await plugin.run(target, client)
    redirect_findings = [f for f in findings if f.evidence_data["test_type"] == "redirect_chain"]
    assert len(redirect_findings) == 1
    assert redirect_findings[0].confidence == Confidence.high


@pytest.mark.asyncio
async def test_ssrf_dns_rebinding_indicator():
    target = "https://example.com/proxy?url=http://google.com"
    # Return different outputs on consecutive requests to simulated rebinding url
    class RebindingMockClient:
        def __init__(self):
            self.counter = 0

        async def get(self, url: str) -> ScanResponse:
            if "127.0.0.1/" in url or "127.0.0.1%2F" in url:
                self.counter += 1
                body = "response version A" if self.counter == 1 else "response version B " + "X" * 2000
                return ScanResponse(url, 200, httpx.Headers(), body, 1.0)
            return ScanResponse(url, 200, httpx.Headers(), "safe baseline content", 1.0)

    plugin = SsrfPlugin()
    findings = await plugin.run(target, RebindingMockClient())
    rebinding_findings = [f for f in findings if f.evidence_data["test_type"] == "dns_rebinding_indicator"]
    assert len(rebinding_findings) == 1
    assert rebinding_findings[0].confidence == Confidence.low


def test_ssrf_scorer_logic():
    # Test high confidence metadata match
    sev, conf, score = SsrfScorer.calculate_score(200, "AccessKeyId SecretAccessKey", "baseline", ["AccessKeyId"])
    assert conf == Confidence.high
    assert score == 95
    assert sev == Severity.critical

    # Test protocol smuggling
    sev, conf, score = SsrfScorer.calculate_score(200, "redis pong", "baseline", [], protocol_smuggling=True)
    assert conf == Confidence.high
    assert score == 85
    assert sev == Severity.high

    # Test response deviation containing indicators
    sev, conf, score = SsrfScorer.calculate_score(200, "connection refused on 127.0.0.1", "baseline", [])
    assert conf == Confidence.medium
    assert score == 75
    assert sev == Severity.high
