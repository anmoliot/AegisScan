import pytest
from unittest.mock import patch, MagicMock
from app.monitoring.scheduler import MonitoringScheduler
from app.monitoring.notification_engine import NotificationEngine

def test_monitoring_scheduler_lifecycle():
    with patch("app.monitoring.scheduler.BackgroundScheduler") as MockSched:
        mock_instance = MockSched.return_value
        
        # Instantiate scheduler
        scheduler = MonitoringScheduler()
        
        # Test start
        scheduler.start()
        assert mock_instance.start.called

        # Test add_job
        def dummy_job():
            pass
        scheduler.add_job(dummy_job, "sched-123", 60)
        assert mock_instance.add_job.called

        # Test remove_job
        scheduler.remove_job("sched-123")
        assert mock_instance.remove_job.called

        # Test shutdown
        mock_instance.running = True
        scheduler.shutdown()
        assert mock_instance.shutdown.called


@pytest.mark.asyncio
async def test_notification_engine():
    notifier = NotificationEngine()
    
    # Test sending alert
    success = await notifier.send_alert_notification(
        alert_type="subdomain_added",
        message="A new host dev.example.com was found.",
        severity="medium"
    )
    assert success is True

    # Test slack webhook parameter passing
    notifier_webhook = NotificationEngine(webhook_url="https://hooks.slack.com/services/test")
    success_web = await notifier_webhook.send_alert_notification(
        alert_type="cert_expired",
        message="SSL certificate expired.",
        severity="critical"
    )
    assert success_web is True
