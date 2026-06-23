from app.monitoring.alert_engine import AlertEngine
from app.monitoring.drift_monitor import DriftMonitor

def test_alert_engine_classification():
    assert AlertEngine.classify_severity("subdomain_added") == "medium"
    assert AlertEngine.classify_severity("cert_expired") == "critical"
    assert AlertEngine.classify_severity("unknown_type") == "low"


def test_alert_engine_deduplication():
    existing_alerts = [
        {"message": "SSL expired", "acknowledged": False},
        {"message": "New subdomain found", "acknowledged": True}
    ]

    # Should deduplicate since it is not acknowledged
    assert AlertEngine.should_deduplicate(existing_alerts, "SSL expired") is True
    # Should NOT deduplicate since it is acknowledged
    assert AlertEngine.should_deduplicate(existing_alerts, "New subdomain found") is False
    # Should NOT deduplicate since it's a completely new message
    assert AlertEngine.should_deduplicate(existing_alerts, "Another alert") is False


def test_drift_monitor_subdomains():
    old_list = ["a.example.com", "b.example.com"]
    new_list = ["b.example.com", "c.example.com"]

    res = DriftMonitor.compare_subdomains(old_list, new_list)
    assert res["added"] == ["c.example.com"]
    assert res["removed"] == ["a.example.com"]


def test_drift_monitor_services():
    old_services = [
        {"port": 80, "protocol": "TCP", "banner": "Apache", "technology": "Apache HTTPd"}
    ]
    new_services = [
        {"port": 80, "protocol": "TCP", "banner": "Apache v2", "technology": "Apache HTTPd"},
        {"port": 443, "protocol": "TCP", "banner": "Nginx", "technology": "Nginx"}
    ]

    res = DriftMonitor.compare_services(old_services, new_services)
    assert len(res["added"]) == 1
    assert res["added"][0]["port"] == 443
    
    assert len(res["changed"]) == 1
    assert res["changed"][0]["port"] == 80
    assert res["changed"][0]["new_banner"] == "Apache v2"
    
    assert len(res["removed"]) == 0
