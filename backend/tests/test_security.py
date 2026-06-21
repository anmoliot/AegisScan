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
