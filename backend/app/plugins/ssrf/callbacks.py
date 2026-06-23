from app.plugins.base import Confidence, Severity

class CallbackValidator:
    """
    Architecture for out-of-band callback validation.
    Provides an interface for validating SSRF callbacks, but returns False/None
    since an actual callback server runs out of band.
    """
    def __init__(self, callback_host: str | None = None):
        self.callback_host = callback_host

    def generate_callback_url(self, finding_id: str) -> str | None:
        if not self.callback_host:
            return None
        return f"http://{finding_id}.{self.callback_host}/log"

    async def verify_callback(self, finding_id: str) -> bool:
        # Interface placeholder for checking external callback server logs.
        # Since this requires an external callback server, we return False by default.
        return False


class MetadataProbeSet:
    """
    Structured metadata probe definitions for AWS/Azure/GCP, and associated configuration.
    """
    # Cloud metadata endpoints/probes
    PROBES = {
        "aws_v1": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "aws_v2": "http://169.254.169.254/latest/api/token",  # Used for IMDSv2 token retrieval
        "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "gcp": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    }

    # Markers in responses that confirm SSRF/metadata leakage
    MARKERS = {
        "aws": ("ami-id", "instance-id", "security-credentials", "accesskeyid", "secretaccesskey", "token"),
        "azure": ("subscriptionId", "resourceGroupName", "computeMetadata", "vmId"),
        "gcp": ("computeMetadata", "serviceAccounts", "accessToken", "expiresIn"),
    }

    # Custom headers required for certain metadata probes (e.g., Azure Metadata: True)
    HEADERS = {
        "azure": {"Metadata": "true"},
        "gcp": {"Metadata-Flavor": "Google"},
        "aws_v2": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
    }

    @classmethod
    def get_probe_provider(cls, name: str) -> str:
        if name.startswith("aws"):
            return "aws"
        return name


class SsrfScorer:
    """
    SSRF Confidence and Severity Scoring Engine.
    """
    @staticmethod
    def calculate_score(
        status_code: int,
        response_text: str,
        baseline_text: str,
        matched_markers: list[str],
        has_redirect: bool = False,
        protocol_smuggling: bool = False
    ) -> tuple[Severity, Confidence, int]:
        """
        Determines Severity, Confidence, and an integer score from 0-100.
        """
        score = 0
        confidence = Confidence.low
        severity = Severity.medium

        baseline_lower = baseline_text.lower()
        response_lower = response_text.lower()

        # 1. Check for explicit cloud metadata markers not in baseline
        active_markers = [m for m in matched_markers if m.lower() not in baseline_lower]
        
        if active_markers:
            score = 95
            confidence = Confidence.high
            severity = Severity.critical
            if protocol_smuggling:
                score = 99
            return severity, confidence, score

        # 2. Protocol smuggling (e.g. file://, gopher://, dict://)
        if protocol_smuggling:
            score = 85
            confidence = Confidence.high
            severity = Severity.high
            return severity, confidence, score

        # 3. Changed responses containing indicators of internal networks
        indicators = ("169.254", "metadata", "invalid host", "connection refused", "localhost", "127.0.0.1")
        has_indicator = any(token in response_lower for token in indicators)

        if response_text != baseline_text:
            if status_code < 500:
                if has_indicator:
                    score = 75
                    confidence = Confidence.medium
                    severity = Severity.high
                else:
                    score = 60
                    confidence = Confidence.medium
                    severity = Severity.medium
            else:
                # 500 Internal Server Error could indicate firewall blocks or unsuccessful internal requests
                score = 45
                confidence = Confidence.low
                severity = Severity.low
        
        if has_redirect:
            score += 5
            score = min(score, 100)

        return severity, confidence, score
