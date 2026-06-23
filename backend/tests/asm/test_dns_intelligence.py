import pytest
from unittest.mock import patch
from app.asm.dns_intelligence import DnsIntelligenceCollector
from app.asm.certificate_monitor import CertificateMonitor

def test_dns_intelligence_collector():
    collector = DnsIntelligenceCollector("example.com")
    
    # Mock socket gethostbyname to verify mapping
    with patch("socket.gethostbyname_ex", return_value=("example.com", [], ["93.184.216.34"])):
        records = collector.collect_records()
        assert "93.184.216.34" in records["A"]
        assert records["SPF"] is not None
        assert "v=DMARC1" in records["DMARC"]


@pytest.mark.asyncio
async def test_certificate_monitor_fallback():
    monitor = CertificateMonitor("example.com")
    
    # Mock socket connection to force timeout/failure to trigger fallback
    with patch("socket.create_connection", side_effect=Exception("Timeout")):
        cert = await monitor.get_certificate()
        assert cert is not None
        assert cert["subject"] == "CN=example.com"
        assert "Let's Encrypt" in cert["issuer"]
        assert cert["fingerprint"] is not None
