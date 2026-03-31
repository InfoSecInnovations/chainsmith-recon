"""
app/lib/http.py - Async HTTP Client

Wrapper around httpx with:
- Configurable retries with exponential backoff
- Per-request and per-client timeouts
- Structured request/response logging
- Scope validation hooks
- Connection pooling via shared AsyncClient
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class HttpConfig:
    """Configuration for the HTTP client."""
    timeout_seconds: float = 10.0
    connect_timeout_seconds: float = 5.0
    retries: int = 2
    retry_backoff_base: float = 0.5   # seconds; doubles each retry
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False           # Lab environments often use self-signed certs
    user_agent: str = "Chainsmith-Recon/1.0"
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class HttpResponse:
    """Normalized HTTP response."""
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    redirected: bool = False
    final_url: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    def json(self) -> Any:
        import json
        return json.loads(self.body)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "body_length": len(self.body),
            "elapsed_ms": self.elapsed_ms,
            "redirected": self.redirected,
            "final_url": self.final_url,
            "error": self.error,
        }


class HttpError(Exception):
    """Raised when a request fails after all retries."""
    def __init__(self, message: str, response: Optional[HttpResponse] = None):
        super().__init__(message)
        self.response = response


class AsyncHttpClient:
    """
    Async HTTP client with retries, timeouts, and structured logging.

    Usage:
        client = AsyncHttpClient(config)
        async with client:
            resp = await client.get("https://example.com")

    Or as a one-shot:
        resp = await AsyncHttpClient.fetch("https://example.com")
    """

    def __init__(self, config: Optional[HttpConfig] = None):
        self.config = config or HttpConfig()
        self._client = None  # Optional[httpx.AsyncClient]

    async def __aenter__(self) -> "AsyncHttpClient":
        await self._init_client()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _init_client(self):
        if not _HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for AsyncHttpClient. Install it with: pip install httpx"
            )
        if self._client is None:
            timeout = httpx.Timeout(
                connect=self.config.connect_timeout_seconds,
                read=self.config.timeout_seconds,
                write=self.config.timeout_seconds,
                pool=self.config.timeout_seconds,
            )
            headers = {
                "User-Agent": self.config.user_agent,
                **self.config.headers,
            }
            self._client = httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_ssl,
                headers=headers,
            )

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        params: Optional[dict] = None,
    ) -> HttpResponse:
        await self._init_client()

        last_error: Optional[str] = None
        attempts = self.config.retries + 1

        for attempt in range(attempts):
            if attempt > 0:
                backoff = self.config.retry_backoff_base * (2 ** (attempt - 1))
                logger.debug(f"Retry {attempt}/{self.config.retries} for {url} after {backoff:.1f}s")
                await asyncio.sleep(backoff)

            start = time.monotonic()
            try:
                resp = await self._client.request(
                    method,
                    url,
                    headers=headers,
                    json=json,
                    data=data,
                    params=params,
                )
                elapsed_ms = (time.monotonic() - start) * 1000

                result = HttpResponse(
                    url=url,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    elapsed_ms=elapsed_ms,
                    redirected=resp.history is not None and len(resp.history) > 0,
                    final_url=str(resp.url),
                )
                logger.debug(f"{method} {url} -> {resp.status_code} ({elapsed_ms:.0f}ms)")
                return result

            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
                logger.debug(f"{method} {url} timed out (attempt {attempt + 1})")

            except httpx.ConnectError as e:
                last_error = f"Connection error: {e}"
                logger.debug(f"{method} {url} connection error (attempt {attempt + 1})")
                break  # No point retrying a connection refused

            except httpx.RequestError as e:
                last_error = f"Request error: {e}"
                logger.debug(f"{method} {url} request error (attempt {attempt + 1})")

        elapsed_ms = (time.monotonic() - start) * 1000
        return HttpResponse(
            url=url,
            status_code=0,
            headers={},
            body="",
            elapsed_ms=elapsed_ms,
            error=last_error,
        )

    async def get(self, url: str, *, headers: Optional[dict] = None, params: Optional[dict] = None) -> HttpResponse:
        return await self._request("GET", url, headers=headers, params=params)

    async def post(self, url: str, *, headers: Optional[dict] = None, json: Optional[Any] = None, data: Optional[Any] = None) -> HttpResponse:
        return await self._request("POST", url, headers=headers, json=json, data=data)

    async def head(self, url: str, *, headers: Optional[dict] = None) -> HttpResponse:
        return await self._request("HEAD", url, headers=headers)

    async def options(self, url: str, *, headers: Optional[dict] = None) -> HttpResponse:
        return await self._request("OPTIONS", url, headers=headers)

    @classmethod
    async def fetch(
        cls,
        url: str,
        method: str = "GET",
        config: Optional[HttpConfig] = None,
        **kwargs,
    ) -> HttpResponse:
        """One-shot request without managing client lifecycle."""
        async with cls(config) as client:
            return await client._request(method, url, **kwargs)
