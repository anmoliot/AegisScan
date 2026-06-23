import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from app.ai.rule_engine import RuleBasedRiskEngine
from app.ai.provider import get_provider, GeminiProvider

def test_rule_based_risk_engine_similarity():
    # Identical strings
    assert RuleBasedRiskEngine.calculate_similarity("Hello", "hello") == 1.0
    # Dissimilar strings
    assert RuleBasedRiskEngine.calculate_similarity("Hello", "World") < 0.3


def test_rule_based_risk_engine_deduplication():
    findings = [
        {"plugin": "ssrf", "description": "SSRF on target parameter url", "category": "server-side-request-forgery"},
        {"plugin": "ssrf", "description": "SSRF on target parameter url (exact match)", "category": "server-side-request-forgery"},
        {"plugin": "xss", "description": "Cross-site scripting on parameter name", "category": "cross-site-scripting"}
    ]

    unique = RuleBasedRiskEngine.deduplicate_findings(findings, threshold=0.8)
    assert len(unique) == 2
    assert any(u["plugin"] == "xss" for u in unique)


def test_rule_based_risk_engine_clustering():
    findings = [
        {"plugin": "ssrf", "category": "server-side-request-forgery"},
        {"plugin": "idor", "category": "broken-object-level-authorization"},
        {"plugin": "ssrf", "category": "server-side-request-forgery"}
    ]

    clusters = RuleBasedRiskEngine.cluster_findings(findings)
    assert len(clusters["server-side-request-forgery"]) == 2
    assert len(clusters["broken-object-level-authorization"]) == 1


def test_rule_based_risk_engine_remediations():
    assert "Restrict outgoing" in RuleBasedRiskEngine.generate_remediation_summary("server-side-request-forgery")
    assert "vulnerability details" in RuleBasedRiskEngine.generate_remediation_summary("unknown-cat")


@pytest.mark.asyncio
async def test_gemini_provider_mock():
    provider = GeminiProvider(api_key="mock_key")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Gemini risk analysis output summary"}]
                }
            }
        ]
    }

    mock_post = AsyncMock(return_value=mock_response)
    with patch("httpx.AsyncClient.post", mock_post):
        res = await provider.analyze_findings("Generate summary")
        assert "Gemini risk analysis" in res
