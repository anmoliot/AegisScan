import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import update

from app.auth.bootstrap import ensure_default_admin
from app.auth.router import router as auth_router
from app.config import get_settings
from app.core.rate_limit import RateLimitMiddleware
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.reports.router import router as reports_router
from app.scanner.executor import initialize_executor
from app.scans.models import Scan, ScanStatus  # imports all scan tables
from app.scans.router import router as scans_router

settings = get_settings()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.environment != "production":
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    async with SessionLocal() as session:
        await ensure_default_admin(session, settings)
        await session.execute(update(Scan).where(Scan.status.in_([ScanStatus.queued, ScanStatus.running]))
                              .values(status=ScanStatus.failed, error_message="Backend restarted before scan completed"))
        await session.commit()
    initialize_executor(settings.scan_concurrency)
    yield
    await engine.dispose()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan,
              docs_url="/docs" if settings.docs_enabled else None,
              redoc_url=None, openapi_url="/openapi.json" if settings.docs_enabled else None)
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])
app.add_middleware(RateLimitMiddleware)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/", include_in_schema=False)
async def api_root():
    return {
        "app": settings.app_name,
        "status": "ok",
        "message": "AegisScan API is running. Use /health for health checks and /api/v1 for API routes.",
    }


app.include_router(auth_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
