import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
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

# New Imports
from app.api_security.router import router as api_security_router
from app.asm.router import router as asm_router
from app.risk.router import router as risk_router
from app.graph.router import router as graph_router
from app.monitoring.router import router as monitoring_router
from app.monitoring.scheduler import get_scheduler
from app.core.observability import ObservabilityMiddleware, get_metrics_payload

settings = get_settings()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Start the monitoring background scheduler
    get_scheduler().start()

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
    
    # Shutdown the monitoring background scheduler
    get_scheduler().shutdown()
    await engine.dispose()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan,
              docs_url="/docs" if settings.docs_enabled else None,
              redoc_url=None, openapi_url="/openapi.json" if settings.docs_enabled else None)

# Add CORS and Observability Middlewares
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_origin_regex=settings.frontend_origin_regex,
                   allow_credentials=True, allow_methods=["GET", "POST", "OPTIONS", "PATCH", "PUT", "DELETE"],
                   allow_headers=["Authorization", "Content-Type", "X-Request-ID"])
app.add_middleware(ObservabilityMiddleware)
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


@app.get("/metrics", include_in_schema=False)
async def metrics():
    payload, content_type = get_metrics_payload()
    return Response(content=payload, media_type=content_type)


@app.get("/", include_in_schema=False)
async def api_root():
    return {
        "app": settings.app_name,
        "status": "ok",
        "message": "AegisScan API is running. Use /health for health checks and /api/v1 for API routes.",
    }


# Include existing routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")

# Include new routers
app.include_router(api_security_router, prefix="/api/v1")
app.include_router(asm_router, prefix="/api/v1")
app.include_router(risk_router, prefix="/api/v1")
app.include_router(graph_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1")

