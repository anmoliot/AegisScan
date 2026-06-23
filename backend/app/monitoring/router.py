from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.asm.models import Asset
from app.monitoring.models import MonitorSchedule, Alert
from app.monitoring.schemas import MonitorScheduleCreate, MonitorScheduleResponse, AlertResponse
from app.monitoring.scheduler import get_scheduler
from app.monitoring.monitoring_jobs import run_monitoring_cycle

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.post("/schedules", response_model=MonitorScheduleResponse, status_code=201)
async def create_schedule(payload: MonitorScheduleCreate, user: CurrentUser, session: DbSession):
    # Verify user owns the asset
    stmt_asset = select(Asset).where(Asset.id == payload.asset_id, Asset.user_id == user.id)
    asset = await session.scalar(stmt_asset)
    if not asset:
        raise HTTPException(404, "Asset not found")

    # Check if a schedule already exists
    stmt_sched = select(MonitorSchedule).where(MonitorSchedule.asset_id == payload.asset_id)
    existing = await session.scalar(stmt_sched)
    if existing:
        raise HTTPException(400, "Monitoring schedule already exists for this asset")

    schedule = MonitorSchedule(
        asset_id=payload.asset_id,
        frequency=payload.frequency.lower(),
        enabled=payload.enabled
    )
    session.add(schedule)
    await session.commit()

    # Register in scheduler if enabled
    if schedule.enabled:
        interval_seconds = 86400  # daily
        if schedule.frequency == "weekly":
            interval_seconds = 604800
        elif schedule.frequency == "monthly":
            interval_seconds = 2592000
            
        # Map a helper lambda wrapper to run the async job in the background
        # since APScheduler calls sync functions, we can run the coroutine in loop
        import asyncio
        def sync_job_wrapper(sched_id):
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(run_monitoring_cycle(sched_id))
            else:
                loop.run_until_complete(run_monitoring_cycle(sched_id))

        get_scheduler().add_job(sync_job_wrapper, schedule.id, interval_seconds)

    # Reload with alerts list
    stmt_reload = select(MonitorSchedule).where(MonitorSchedule.id == schedule.id).options(selectinload(MonitorSchedule.alerts))
    return await session.scalar(stmt_reload)


@router.get("/schedules", response_model=list[MonitorScheduleResponse])
async def list_schedules(user: CurrentUser, session: DbSession):
    # Retrieve schedules for user's assets
    stmt = select(MonitorSchedule).join(Asset).where(Asset.user_id == user.id).options(
        selectinload(MonitorSchedule.alerts)
    )
    schedules = await session.scalars(stmt)
    return list(schedules.unique())


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(user: CurrentUser, session: DbSession):
    # Retrieve alerts for user's assets
    stmt = select(Alert).join(MonitorSchedule).join(Asset).where(Asset.user_id == user.id).order_by(Alert.created_at.desc())
    alerts = await session.scalars(stmt)
    return list(alerts.all())


@router.patch("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(alert_id: str, user: CurrentUser, session: DbSession):
    # Verify ownership of the asset linked to this alert
    stmt = select(Alert).join(MonitorSchedule).join(Asset).where(
        Alert.id == alert_id,
        Asset.user_id == user.id
    )
    alert = await session.scalar(stmt)
    if not alert:
        raise HTTPException(404, "Alert not found or access denied")

    alert.acknowledged = True
    await session.commit()
    return alert
