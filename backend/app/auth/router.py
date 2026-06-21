from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, HTTPException, Request, Response
from sqlalchemy import select

from app.auth.models import RefreshToken, User
from app.auth.schemas import Credentials, RegisterRequest, TokenResponse, UserResponse
from app.auth.service import create_access_token, hash_password, new_refresh_token, token_digest, verify_password
from app.config import get_settings
from app.deps import CurrentUser, DbSession

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


def set_refresh_cookie(response: Response, value: str) -> None:
    response.set_cookie("refresh_token", value, max_age=settings.refresh_token_days * 86400,
                        httponly=True, secure=settings.cookie_secure, samesite=settings.cookie_samesite,
                        path="/api/v1/auth")


def token_response(user_id: str) -> TokenResponse:
    return TokenResponse(access_token=create_access_token(user_id), expires_in=settings.access_token_minutes * 60)


async def issue_refresh(session: DbSession, user_id: str, response: Response) -> None:
    raw, digest = new_refresh_token()
    session.add(RefreshToken(user_id=user_id, token_hash=digest,
                             expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days)))
    await session.commit()
    set_refresh_cookie(response, raw)


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(payload: RegisterRequest, response: Response, session: DbSession):
    if not settings.registration_enabled:
        raise HTTPException(404, "Not found")
    email = payload.email.lower()
    if await session.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, "Account already exists")
    user = User(email=email, password_hash=hash_password(payload.password), display_name=payload.display_name)
    session.add(user)
    await session.flush()
    await issue_refresh(session, user.id, response)
    return token_response(user.id)


@router.post("/login", response_model=TokenResponse)
async def login(payload: Credentials, response: Response, session: DbSession):
    user = await session.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    await issue_refresh(session, user.id, response)
    return token_response(user.id)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response, session: DbSession,
                  refresh_token: str | None = Cookie(default=None)):
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") not in settings.origins:
        raise HTTPException(403, "Untrusted origin")
    stored = await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_digest(refresh_token or "")))
    now = datetime.now(timezone.utc)
    expires_at = stored.expires_at if stored else None
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not stored or stored.revoked_at or not expires_at or expires_at < now:
        raise HTTPException(401, "Invalid refresh token")
    stored.revoked_at = now
    await issue_refresh(session, stored.user_id, response)
    return token_response(stored.user_id)


@router.post("/logout", status_code=204)
async def logout(response: Response, session: DbSession, refresh_token: str | None = Cookie(default=None)):
    stored = await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_digest(refresh_token or "")))
    if stored:
        stored.revoked_at = datetime.now(timezone.utc)
        await session.commit()
    response.delete_cookie("refresh_token", path="/api/v1/auth")


@router.get("/me", response_model=UserResponse)
async def me(user: CurrentUser):
    return user
