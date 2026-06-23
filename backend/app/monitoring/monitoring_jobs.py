import asyncio
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import SessionLocal
from app.asm.models import Asset, Subdomain
from app.asm.subdomain_discovery import SubdomainDiscovery
from app.monitoring.models import MonitorSchedule, Alert
from app.monitoring.alert_engine import AlertEngine
from app.monitoring.drift_monitor import DriftMonitor
from app.monitoring.notification_engine import NotificationEngine

async def run_monitoring_cycle(schedule_id: str):
    """
    Executes a scheduled monitoring scan cycle: discovery, regression, and drift check.
    Runs asynchronously on background threads.
    """
    async with SessionLocal() as session:
        # Load schedule
        stmt = select(MonitorSchedule).where(MonitorSchedule.id == schedule_id)
        schedule = await session.scalar(stmt)
        if not schedule or not schedule.enabled:
            return

        # Load asset
        stmt_asset = select(Asset).where(Asset.id == schedule.asset_id).options(
            selectinload(Asset.subdomains)
        )
        asset = await session.scalar(stmt_asset)
        if not asset:
            return

        try:
            # 1. Store previous subdomains
            old_hostnames = [sub.hostname for sub in asset.subdomains]

            # 2. Run new discovery
            discovery_tool = SubdomainDiscovery(asset.domain)
            new_hostnames = await discovery_tool.discover()

            # 3. Compute drift
            drift = DriftMonitor.compare_subdomains(old_hostnames, new_hostnames)
            
            # 4. Generate alerts if drift is detected
            alerts_created = []
            if drift["added"]:
                alert_msg = f"New subdomains discovered for {asset.domain}: {', '.join(drift['added'])}"
                alert = Alert(
                    schedule_id=schedule.id,
                    alert_type="subdomain_added",
                    severity="medium",
                    message=alert_msg
                )
                session.add(alert)
                alerts_created.append(alert)

            # Update schedule run time
            schedule.last_run = datetime.utcnow()
            await session.commit()

            # 5. Send notifications if we generated alerts
            if alerts_created:
                notifier = NotificationEngine()
                for alert in alerts_created:
                    await notifier.send_alert_notification(
                        alert_type=alert.alert_type,
                        message=alert.message,
                        severity=alert.severity
                    )

        except Exception as e:
            await session.rollback()
            # Log error in alert engine
            err_alert = Alert(
                schedule_id=schedule.id,
                alert_type="monitoring_error",
                severity="high",
                message=f"Monitoring job failed: {str(e)}"
            )
            session.add(err_alert)
            await session.commit()
