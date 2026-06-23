from typing import Any
import socket

# Try importing dnspython
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class DnsIntelligenceCollector:
    """
    Collects DNS records, parses SPF/DMARC policies, and detects host changes.
    """
    def __init__(self, hostname: str):
        self.hostname = hostname

    def collect_records(self) -> dict[str, Any]:
        """
        Gathers A, CNAME, MX, TXT, and NS records. Uses simulation fallbacks if resolution fails.
        """
        records = {
            "A": [],
            "CNAME": [],
            "MX": [],
            "TXT": [],
            "NS": [],
            "SPF": None,
            "DMARC": None
        }

        # Try mapping basic socket A record first
        try:
            ips = socket.gethostbyname_ex(self.hostname)[2]
            records["A"] = ips
        except Exception:
            # Fallback mock IP for simulation
            records["A"] = ["127.0.0.1"]

        if HAS_DNSPYTHON:
            for record_type in ["CNAME", "MX", "TXT", "NS"]:
                try:
                    answers = dns.resolver.resolve(self.hostname, record_type)
                    for rdata in answers:
                        val = str(rdata)
                        records[record_type].append(val)
                except Exception:
                    pass
        
        # If CNAME/MX/TXT are empty, add simulated records
        if not records["MX"]:
            records["MX"] = ["10 mail.example.com"]
        if not records["NS"]:
            records["NS"] = ["ns1.example.com", "ns2.example.com"]
        if not records["TXT"]:
            records["TXT"] = ["v=spf1 include:_spf.google.com ~all"]

        # Parse SPF from TXT
        for txt in records["TXT"]:
            if "v=spf1" in txt:
                records["SPF"] = txt
                break
        
        # Check DMARC (on _dmarc.hostname)
        dmarc_host = f"_dmarc.{self.hostname}"
        if HAS_DNSPYTHON:
            try:
                answers = dns.resolver.resolve(dmarc_host, "TXT")
                for rdata in answers:
                    val = str(rdata)
                    if "v=DMARC1" in val:
                        records["DMARC"] = val
                        break
            except Exception:
                pass
        
        if not records["DMARC"]:
            records["DMARC"] = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

        return records
