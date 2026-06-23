import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import delete

from app.db.session import SessionLocal
from app.plugins.registry import selected_plugins
from app.scanner.http_client import SafeHttpClient
from app.scans.models import Finding, Scan, ScanStatus

log = logging.getLogger(__name__)


class ScanExecutor:
    def __init__(self, concurrency: int = 2):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.tasks: set[asyncio.Task] = set()

    def submit(self, scan_id: str) -> None:
        task = asyncio.create_task(self._execute(scan_id))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _execute(self, scan_id: str) -> None:
        async with self.semaphore:
            async with SessionLocal() as session:
                scan = await session.get(Scan, scan_id)
                if not scan or scan.status != ScanStatus.queued:
                    return
                scan.status = ScanStatus.running
                scan.started_at = datetime.now(timezone.utc)
                await session.commit()
                client = SafeHttpClient(scan.target_host)
                results = []
                errors = []
                try:
                    for plugin in selected_plugins(scan.enabled_plugins):
                        try:
                            results.extend(await plugin.run(scan.target_url, client))
                        except Exception:
                            log.warning("plugin_failed", extra={"plugin": plugin.name, "scan_id": scan.id})
                            errors.append(plugin.name)
                    await session.execute(delete(Finding).where(Finding.scan_id == scan.id))
                    seen = set()
                    for result in results:
                        if result.fingerprint in seen:
                            continue
                        seen.add(result.fingerprint)
                        data = result.to_dict()
                        session.add(Finding(scan_id=scan.id, fingerprint=data.pop("fingerprint"),
                                            evidence_data=data.pop("evidence_data"), **data))
                    scan.request_count = client.request_count
                    scan.status = ScanStatus.completed
                    scan.error_message = f"Plugins skipped after errors: {', '.join(errors)}" if errors else None
                except Exception:
                    log.exception("scan_failed", extra={"scan_id": scan.id})
                    scan.status = ScanStatus.failed
                    scan.error_message = "Scan execution failed safely"
                finally:
                    scan.completed_at = datetime.now(timezone.utc)
                    await client.close()
                    await session.commit()


executor: ScanExecutor | None = None


def get_executor() -> ScanExecutor:
    if executor is None:
        raise RuntimeError("Scan executor is not initialized")
    return executor


def initialize_executor(concurrency: int) -> ScanExecutor:
    global executor
    executor = ScanExecutor(concurrency)
    return executor
