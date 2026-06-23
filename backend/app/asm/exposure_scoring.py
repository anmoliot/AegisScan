class ExposureScoringCalculator:
    """
    Computes an exposure score from 0.0 to 100.0 based on ASM metrics:
    - Number of subdomains (higher count = more surface area)
    - Exposed open ports/services
    - Unauthenticated endpoints
    - Certificate expiration status
    """
    @staticmethod
    def calculate_score(
        subdomains_count: int,
        services_count: int,
        unauth_endpoints_count: int,
        cert_expired: bool = False
    ) -> float:
        score = 0.0

        # Subdomains component (max 20 points)
        score += min(subdomains_count * 2.0, 20.0)

        # Services component (max 30 points)
        score += min(services_count * 5.0, 30.0)

        # Unauth endpoints component (max 40 points)
        score += min(unauth_endpoints_count * 4.0, 40.0)

        # Certificate expired penalty (10 points)
        if cert_expired:
            score += 10.0

        return min(score, 100.0)
