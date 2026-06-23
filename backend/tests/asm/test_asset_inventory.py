from unittest.mock import AsyncMock
import pytest
from app.asm.asset_inventory import AssetInventoryManager
from app.asm.models import Asset
from app.asm.exposure_scoring import ExposureScoringCalculator
from app.asm.drift_detection import DriftDetector

@pytest.mark.asyncio
async def test_asset_inventory_manager():
    session = AsyncMock()
    
    # Mock database responses
    session.scalar.return_value = None  # No existing asset

    manager = AssetInventoryManager(session)
    
    # Test registration
    asset = await manager.register_asset(user_id="user123", domain="example.com")
    assert asset.domain == "example.com"
    assert asset.user_id == "user123"
    assert asset.status == "active"
    assert session.add.called

    # Test get_asset
    session.scalar.return_value = asset
    retrieved = await manager.get_asset(user_id="user123", asset_id=asset.id)
    assert retrieved == asset

    # Test archive_asset
    session.scalar.return_value = asset
    archived = await manager.archive_asset(user_id="user123", asset_id=asset.id)
    assert archived is True
    assert asset.status == "archived"


def test_exposure_scoring():
    # Test base scoring formula
    score = ExposureScoringCalculator.calculate_score(
        subdomains_count=3,        # 3 * 2 = 6 points
        services_count=4,          # 4 * 5 = 20 points
        unauth_endpoints_count=2,  # 2 * 4 = 8 points
        cert_expired=True          # 10 points
    )
    # Total: 6 + 20 + 8 + 10 = 44 points
    assert score == 44.0

    # Test capping at 100
    score_cap = ExposureScoringCalculator.calculate_score(100, 100, 100, True)
    assert score_cap == 100.0


def test_drift_detector():
    old_subdomains = ["www.example.com", "api.example.com"]
    new_subdomains = ["www.example.com", "dev.example.com", "staging.example.com"]

    sub_drift = DriftDetector.detect_subdomain_drift(old_subdomains, new_subdomains)
    assert sub_drift["added"] == ["dev.example.com", "staging.example.com"]
    assert sub_drift["removed"] == ["api.example.com"]

    old_dns = {"A": ["1.1.1.1"], "TXT": ["v=spf1"]}
    new_dns = {"A": ["1.1.1.1", "2.2.2.2"], "TXT": []}

    dns_drift = DriftDetector.detect_dns_drift(old_dns, new_dns)
    assert dns_drift["A"]["added"] == ["2.2.2.2"]
    assert dns_drift["TXT"]["removed"] == ["v=spf1"]
