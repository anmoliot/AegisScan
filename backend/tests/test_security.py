import pytest

from app.scanner.target_policy import TargetRejected, validate_target


@pytest.mark.asyncio
async def test_private_target_is_rejected():
    with pytest.raises(TargetRejected):
        await validate_target("http://127.0.0.1/")


@pytest.mark.asyncio
async def test_url_credentials_are_rejected():
    with pytest.raises(TargetRejected):
        await validate_target("https://user:secret@example.com/")


@pytest.mark.asyncio
async def test_malformed_port_is_rejected():
    with pytest.raises(TargetRejected, match="port is invalid"):
        await validate_target("https://example.com:abc/")


@pytest.mark.asyncio
async def test_non_standard_port_is_rejected():
    with pytest.raises(TargetRejected, match="Only ports 80 and 443"):
        await validate_target("https://example.com:8443/")
