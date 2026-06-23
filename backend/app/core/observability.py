import time
import uuid
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# Configure standard logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegisscan.observability")

# Try importing structlog
try:
    import structlog
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer()
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    struct_logger = structlog.get_logger()
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False

# Try importing prometheus_client
try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


# Define metrics if prometheus is available
if HAS_PROMETHEUS:
    HTTP_REQUEST_LATENCY = Histogram(
        "http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["method", "path"]
    )
    HTTP_REQUESTS_TOTAL = Counter(
        "http_requests_total",
        "Total number of HTTP requests",
        ["method", "path", "status_code"]
    )
    SCAN_COUNT = Counter(
        "scans_started_total",
        "Total number of scans started"
    )
    FINDINGS_COUNT = Counter(
        "findings_discovered_total",
        "Total number of security findings discovered",
        ["severity", "plugin"]
    )
else:
    # Fallback mock metrics stores
    HTTP_REQUEST_LATENCY = None
    HTTP_REQUESTS_TOTAL = None
    SCAN_COUNT = None
    FINDINGS_COUNT = None


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds request trace IDs, tracks request duration metrics,
    and structured logs incoming requests.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        trace_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.trace_id = trace_id

        start_time = time.monotonic()
        
        # Log request receipt
        msg = f"Request started: {request.method} {request.url.path}"
        if HAS_STRUCTLOG:
            struct_logger.info(msg, method=request.method, path=request.url.path, trace_id=trace_id)
        else:
            logger.info(f"[{trace_id}] {msg}")

        try:
            response = await call_next(request)
        except Exception as e:
            # Log failure
            if HAS_STRUCTLOG:
                struct_logger.exception("Request failed", method=request.method, path=request.url.path, trace_id=trace_id, error=str(e))
            else:
                logger.error(f"[{trace_id}] Request failed: {e}")
            raise e

        duration = time.monotonic() - start_time
        response.headers["X-Request-ID"] = trace_id

        # Log completion
        msg_comp = f"Request completed: {request.method} {request.url.path} with status {response.status_code} in {duration:.4f}s"
        if HAS_STRUCTLOG:
            struct_logger.info(msg_comp, method=request.method, path=request.url.path, status_code=response.status_code, duration=duration, trace_id=trace_id)
        else:
            logger.info(f"[{trace_id}] {msg_comp}")

        # Record metrics
        if HAS_PROMETHEUS:
            path = request.url.path
            # Group paths to avoid cardinality explosion
            if path.startswith("/api/v1/scans/"):
                path = "/api/v1/scans/{id}"
            elif path.startswith("/api/v1/asm/assets/"):
                path = "/api/v1/asm/assets/{id}"
                
            HTTP_REQUEST_LATENCY.labels(method=request.method, path=path).observe(duration)
            HTTP_REQUESTS_TOTAL.labels(method=request.method, path=path, status_code=str(response.status_code)).inc()

        return response


def get_metrics_payload() -> tuple[bytes, str]:
    """
    Returns the latest formatted Prometheus metrics payload and corresponding content-type.
    """
    if HAS_PROMETHEUS:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"# Prometheus client is not installed.", "text/plain"


def increment_scan_metric():
    if HAS_PROMETHEUS:
        SCAN_COUNT.inc()


def increment_finding_metric(severity: str, plugin: str):
    if HAS_PROMETHEUS:
        FINDINGS_COUNT.labels(severity=severity, plugin=plugin).inc()
