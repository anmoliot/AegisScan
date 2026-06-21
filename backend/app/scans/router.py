from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.plugins.registry import PLUGINS, selected_plugins
from app.scanner.executor import get_executor
from app.scanner.target_policy import TargetRejected, validate_target
from app.scans.models import AuditEvent, Scan
from app.scans.schemas import ScanCreate, ScanResponse

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/plugins")
async def plugins(_: CurrentUser):
    return [{"name": p.name, "description": p.description, "category": p.category, "active": p.active}
            for p in PLUGINS.values()]


@router.post("", response_model=ScanResponse, status_code=202)
async def create_scan(payload: ScanCreate, request: Request, user: CurrentUser, session: DbSession):
    try:
        target = await validate_target(str(payload.target_url))
        plugins = selected_plugins(payload.enabled_plugins)
    except (TargetRejected, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    scan = Scan(user_id=user.id, target_url=target.url, target_host=target.host,
                authorization_confirmed=True, enabled_plugins=[p.name for p in plugins])
    session.add(scan)
    session.add(AuditEvent(user_id=user.id, event_type="scan.created", object_id=scan.id))
    await session.commit()
    get_executor().submit(scan.id)
    return ScanResponse(
        id=scan.id, target_url=scan.target_url, target_host=scan.target_host,
        status=scan.status.value, enabled_plugins=scan.enabled_plugins,
        error_message=scan.error_message, request_count=scan.request_count,
        created_at=scan.created_at, started_at=scan.started_at,
        completed_at=scan.completed_at, findings=[],
    )


@router.get("", response_model=list[ScanResponse])
async def list_scans(user: CurrentUser, session: DbSession):
    query = (select(Scan).where(Scan.user_id == user.id).options(selectinload(Scan.findings))
             .order_by(Scan.created_at.desc()).limit(100))
    return list((await session.scalars(query)).unique())


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, user: CurrentUser, session: DbSession):
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id).options(selectinload(Scan.findings))
    scan = await session.scalar(query)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan
