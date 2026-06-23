import logging

logger = logging.getLogger("aegisscan.monitoring")

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False
    class BackgroundScheduler:
        running = False
        def start(self): pass
        def shutdown(self): pass
        def add_job(self, *args, **kwargs): pass
        def remove_job(self, *args, **kwargs): pass


class MonitoringScheduler:
    """
    Manages background scheduled scan jobs using in-process APScheduler.
    """
    def __init__(self):
        self._scheduler = BackgroundScheduler()

    def start(self):
        if self._scheduler:
            try:
                self._scheduler.start()
                logger.info("Monitoring Background Scheduler started.")
            except Exception as e:
                logger.error(f"Failed to start scheduler: {e}")
        else:
            logger.warning("APScheduler is not installed. Background monitoring is disabled.")

    def shutdown(self):
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown()
            logger.info("Monitoring Background Scheduler stopped.")

    def add_job(self, job_func, schedule_id: str, interval_seconds: int):
        if self._scheduler:
            self._scheduler.add_job(
                job_func,
                "interval",
                seconds=interval_seconds,
                id=schedule_id,
                replace_existing=True,
                args=[schedule_id]
            )

    def remove_job(self, schedule_id: str):
        if self._scheduler:
            try:
                self._scheduler.remove_job(schedule_id)
            except Exception:
                pass


# Global instance
scheduler_instance = MonitoringScheduler()

def get_scheduler() -> MonitoringScheduler:
    return scheduler_instance
