from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings

settings = get_settings()
database_url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
engine_options = {"pool_pre_ping": True}
if database_url.startswith("sqlite"):
    engine_options["poolclass"] = NullPool
engine = create_async_engine(database_url, **engine_options)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
