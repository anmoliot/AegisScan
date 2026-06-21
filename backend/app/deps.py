from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User
from app.auth.service import decode_access_token
from app.db.session import get_session

DbSession = Annotated[AsyncSession, Depends(get_session)]
bearer = HTTPBearer(auto_error=False)


async def current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)], session: DbSession) -> User:
    user_id = decode_access_token(credentials.credentials) if credentials else None
    user = await session.scalar(select(User).where(User.id == user_id, User.is_active.is_(True))) if user_id else None
    if not user:
        raise HTTPException(401, "Invalid or expired credentials", headers={"WWW-Authenticate": "Bearer"})
    return user


CurrentUser = Annotated[User, Depends(current_user)]
