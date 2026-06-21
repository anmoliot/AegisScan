import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    rules = {"/api/v1/auth/login": (5, 60), "/api/v1/auth/register": (3, 60),
             "/api/v1/auth/refresh": (10, 60), "/api/v1/scans": (10, 60)}

    def __init__(self, app):
        super().__init__(app)
        self.buckets = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        rule = self.rules.get(request.url.path) if request.method == "POST" else None
        if rule:
            limit, window = rule
            key = (request.client.host if request.client else "unknown", request.url.path)
            bucket = self.buckets[key]
            now = time.monotonic()
            while bucket and bucket[0] <= now - window: bucket.popleft()
            if len(bucket) >= limit:
                return JSONResponse({"detail": "Rate limit exceeded"}, 429, {"Retry-After": str(window)})
            bucket.append(now)
        return await call_next(request)
