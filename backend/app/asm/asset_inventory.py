from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.asm.models import Asset

class AssetInventoryManager:
    """
    Handles asset lifecycle, registration, deduplication, and status management.
    """
    def __init__(self, session: AsyncSession):
        self.session = session

    async def register_asset(self, user_id: str, domain: str) -> Asset:
        """
        Registers a new asset root domain, ensuring deduplication per user.
        """
        # Deduplication check
        stmt = select(Asset).where(Asset.user_id == user_id, Asset.domain == domain)
        existing = await self.session.scalar(stmt)
        if existing:
            return existing

        asset = Asset(
            user_id=user_id,
            domain=domain,
            status="active",
            exposure_score=0.0
        )
        self.session.add(asset)
        await self.session.flush()
        return asset

    async def get_asset(self, user_id: str, asset_id: str) -> Asset | None:
        """
        Retrieves an asset by ID with user ownership check.
        """
        stmt = select(Asset).where(Asset.id == asset_id, Asset.user_id == user_id)
        return await self.session.scalar(stmt)

    async def archive_asset(self, user_id: str, asset_id: str) -> bool:
        """
        Marks an asset status as archived.
        """
        asset = await self.get_asset(user_id, asset_id)
        if not asset:
            return False
        asset.status = "archived"
        await self.session.flush()
        return True
