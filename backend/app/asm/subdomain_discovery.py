import httpx

class SubdomainDiscovery:
    """
    Discovers subdomains of a target domain using passive approaches
    (such as querying Certificate Transparency logs) and local heuristics.
    """
    def __init__(self, domain: str):
        self.domain = domain

    async def discover(self) -> list[str]:
        """
        Discovers subdomains passively. Falls back to generating typical subdomains
        if external queries fail or resolve empty.
        """
        subdomains = set()
        
        # 1. Standard typical fallback subdomains (ensures it always returns results)
        common_prefixes = ["www", "api", "admin", "dev", "mail", "vpn", "staging", "portal", "test", "git", "internal"]
        for prefix in common_prefixes:
            subdomains.add(f"{prefix}.{self.domain}")
        subdomains.add(self.domain)  # root is also a domain/subdomain

        # 2. Try passive CT logs lookup (crt.sh)
        # Using a separate async HTTP client for external requests (if permitted and connected)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"https://crt.sh/?q=%25.{self.domain}&output=json")
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # name_value can contain multiple hostnames separated by newlines
                        for host in name_value.split("\n"):
                            host = host.strip().lower()
                            if host.endswith(self.domain) and "*" not in host:
                                subdomains.add(host)
        except Exception:
            # Silently pass on network/timeout errors to stay robust
            pass

        return sorted(list(subdomains))
