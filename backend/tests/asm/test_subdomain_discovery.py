import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from app.asm.subdomain_discovery import SubdomainDiscovery

@pytest.mark.asyncio
async def test_subdomain_discovery_fallback():
    # Test that common prefix generator fallback is always used
    discovery = SubdomainDiscovery("example.com")
    
    # Mock network call to fail/timeout
    with patch("httpx.AsyncClient.get", side_effect=Exception("Network error")):
        subs = await discovery.discover()
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "example.com" in subs
        assert len(subs) >= 5


@pytest.mark.asyncio
async def test_subdomain_discovery_crt_sh():
    discovery = SubdomainDiscovery("example.com")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"name_value": "mail.example.com\n*.example.com"},
        {"name_value": "secure.example.com"}
    ]

    mock_get = AsyncMock(return_value=mock_response)
    with patch("httpx.AsyncClient.get", mock_get):
        subs = await discovery.discover()
        assert "mail.example.com" in subs
        assert "secure.example.com" in subs
        # Wildcard should be skipped per our parsing rules
        assert "*.example.com" not in subs
