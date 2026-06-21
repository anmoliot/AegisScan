import asyncio
from dataclasses import dataclass

import httpx

from app.config import get_settings
from app.scanner.target_policy import validate_target


@dataclass(slots=True)
class ScanResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    text: str
    elapsed_ms: float


class SafeHttpClient:
    def __init__(self, allowed_host: str):
        self.allowed_host = allowed_host
        self.settings = get_settings()
        self.request_count = 0
        self._cache: dict[str, ScanResponse] = {}
        self._client = httpx.AsyncClient(timeout=self.settings.scan_timeout_seconds,
                                         headers={"User-Agent": self.settings.scan_user_agent},
                                         follow_redirects=False)

    async def close(self):
        await self._client.aclose()

    async def get(self, url: str) -> ScanResponse:
        if url in self._cache:
            return self._cache[url]
        current = url
        for _ in range(4):
            target = await validate_target(current)
            if target.host != self.allowed_host:
                raise ValueError("Cross-host requests and redirects are not allowed")
            if self.request_count >= self.settings.scan_max_requests:
                raise RuntimeError("Scan request budget exhausted")
            started = asyncio.get_running_loop().time()
            async with self._client.stream("GET", target.url) as response:
                self.request_count += 1
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("Redirect without a location")
                    current = str(response.url.join(location))
                    continue
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.settings.scan_max_response_bytes:
                        raise ValueError("Response exceeded scan size limit")
                encoding = response.encoding or "utf-8"
                text = bytes(body).decode(encoding, errors="replace")
                result = ScanResponse(str(response.url), response.status_code, response.headers, text,
                                      (asyncio.get_running_loop().time() - started) * 1000)
                self._cache[url] = result
                return result
        raise ValueError("Redirect limit exceeded")
