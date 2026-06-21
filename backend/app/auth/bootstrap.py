import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User
from app.auth.service import hash_password
from app.config import Settings

logger = logging.getLogger(__name__)


async def ensure_default_admin(session: AsyncSession, settings: Settings) -> None:
    if settings.environment == "production" or not settings.default_admin_enabled:
        return

    email = settings.default_admin_email.lower().strip()
    user = await session.scalar(select(User).where(User.email == email))
    password_hash = hash_password(settings.default_admin_password)

    if user is None:
        session.add(User(
            email=email,
            password_hash=password_hash,
            display_name=settings.default_admin_display_name,
            is_active=True,
        ))
        logger.info("Created development default admin user %s", email)
    else:
        user.password_hash = password_hash
        user.display_name = user.display_name or settings.default_admin_display_name
        user.is_active = True
        logger.info("Updated development default admin user %s", email)

    await session.commit()
