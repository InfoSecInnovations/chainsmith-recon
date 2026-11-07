"""
app/lib/http.py - Async HTTP Client

Wrapper around httpx with:
- Configurable retries with exponential backoff
- Per-request and per-client timeouts
- Structured request/response logging
- Scope validation hooks
- Connection pooling via shared AsyncClient
- Evidence capture

**Capture.** Every check that speaks HTTP goes through `_request`, so one
interceptor here records the 231 check modules that route through this client
without touching any of them. Attribution — which scan, which check — comes from
the ambient capture context set in `BaseCheck.execute()`; see
`app/capture/context.py` for why it is ambient rather than a parameter.

This is one producer, not the only one. The socket and resolver checks, the
agent LLM path, and any future local check call `app.capture.record()` directly
with their own protocol.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


def request_body_text(json_body: Any | None = None, data: Any | None = None) -> str:
    """The text a recorded exchange stores for a request body (B-8).

    One rule, used by both the capture interceptor below and
    `app.grading.evidence.exchange_from_response`. A probe's in-memory copy then
    hashes the same as the corpus copy, and `evidence_for` can pair them.

    - `json=`: `json.dumps(..., ensure_ascii=False)`, as before.
    - `data=` text: as-is.
    - `data=` bytes: UTF-8 if the bytes decode cleanly, otherwise latin-1, which
      round-trips every byte (a PDF inside a multipart upload). The old rule was
      `str(data)`, which stored the literal repr `"b'--boundary...'"`.
    - `data=` a mapping: form-encoded, which is what httpx sends.
    """
    if json_body is not None:
        import json as _json

        return _json.dumps(json_body, ensure_ascii=False)
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    if isinstance(data, dict):
        from urllib.parse import urlencode

        return urlencode(data, doseq=True)
    return str(data)


@dataclass
class HttpConfig:
    """Configuration for the HTTP client."""

    timeout_seconds: float = 10.0
    connect_timeout_seconds: float = 5.0
    retries: int = 2
    retry_backoff_base: float = 0.5  # seconds; doubles each retry
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False  # Lab environments often use self-signed certs
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
    error: str | None = None

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

    def __init__(self, message: str, response: HttpResponse | None = None):
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

    def __init__(self, config: HttpConfig | None = None):
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
        headers: dict | None = None,
        json: Any | None = None,
        data: Any | None = None,
        params: dict | None = None,
    ) -> HttpResponse:
        await self._init_client()

        last_error: str | None = None
        attempts = self.config.retries + 1

        for attempt in range(attempts):
            if attempt > 0:
                backoff = self.config.retry_backoff_base * (2 ** (attempt - 1))
                logger.debug(
                    f"Retry {attempt}/{self.config.retries} for {url} after {backoff:.1f}s"
                )
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
                self._capture(method, url, headers, json, data, result)
                self._log_traffic(method, url, result)
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
        failed = HttpResponse(
            url=url,
            status_code=0,
            headers={},
            body="",
            elapsed_ms=elapsed_ms,
            error=last_error,
        )
        # Recorded only when `capture_failures` is on; the writer decides.
        self._capture(method, url, headers, json, data, failed)
        self._log_traffic(method, url, failed)
        return failed

    @staticmethod
    def _log_traffic(method: str, url: str, response: HttpResponse) -> None:
        """Record one sent request in the proof-of-scope traffic log (B-2).

        Only inside a check (the ambient capture context carries the scan id),
        and only when the scan's `traffic_logging` setting is on. The scope
        status comes from the scan's own Guardian. A request that left the box
        is `in_scope` or `out_of_scope`; one Guardian blocked before sending is
        logged by Guardian itself as `excluded`. Before this, nothing called the
        traffic logger, and every compliance report claimed zero requests.
        Never raises.
        """
        try:
            from urllib.parse import urlparse

            from app.capture.context import current

            active = current()
            if active is None or not active.scan_id:
                return

            from app.proof_of_scope import ScopeStatus, traffic_logger
            from app.scan_registry import get_registry

            session = get_registry().get(active.scan_id)
            if session is None:
                # Not a scan this process runs: a check driven directly by a
                # test, or a swarm worker. Swarm traffic is therefore not in
                # the coordinator's compliance report yet (same gap as swarm
                # evidence capture, phase 57 O-4).
                return
            settings = getattr(session, "proof_settings", None)
            if settings is not None and not getattr(settings, "traffic_logging", True):
                return

            status = ScopeStatus.UNKNOWN
            guardian = getattr(session, "guardian", None)
            if guardian is not None:
                allowed, _ = guardian.check_url(url)
                status = ScopeStatus.IN_SCOPE if allowed else ScopeStatus.OUT_OF_SCOPE

            parsed = urlparse(url)
            traffic_logger.log_request(
                dst_host=parsed.hostname or url,
                method=method,
                path=parsed.path or "/",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                protocol=(parsed.scheme or "http").upper(),
                check_name=active.check_name or None,
                scope_status=status,
                status_code=response.status_code or None,
                response_time_ms=response.elapsed_ms,
                scan_id=active.scan_id,
            )
        except Exception:  # pragma: no cover - logging must never break a request
            logger.debug("Traffic logging skipped for %s %s", method, url, exc_info=True)

    @staticmethod
    def _capture(
        method: str,
        url: str,
        headers: dict | None,
        json_body: Any | None,
        data: Any | None,
        response: HttpResponse,
    ) -> None:
        """Hand one exchange to the evidence writer.

        Imported inside the function to keep `app.lib.http` importable without
        the capture package — it is used by tooling that has no workspace.
        The writer swallows its own failures, so this cannot break a request.
        """
        try:
            from urllib.parse import urlparse

            from app.capture.writer import record

            body = request_body_text(json_body, data)

            record(
                "http",
                urlparse(url).hostname or url,
                request_method=method,
                request_url=url,
                request_headers=dict(headers or {}),
                request_body=body,
                response_status=response.status_code or None,
                response_headers=response.headers,
                response_body=response.body,
                elapsed_ms=response.elapsed_ms,
                error=response.error,
            )
        except Exception:  # pragma: no cover - capture must never break a request
            logger.debug("Evidence capture skipped for %s %s", method, url, exc_info=True)

    async def get(
        self, url: str, *, headers: dict | None = None, params: dict | None = None
    ) -> HttpResponse:
        return await self._request("GET", url, headers=headers, params=params)

    async def post(
        self,
        url: str,
        *,
        headers: dict | None = None,
        json: Any | None = None,
        data: Any | None = None,
    ) -> HttpResponse:
        return await self._request("POST", url, headers=headers, json=json, data=data)

    async def head(self, url: str, *, headers: dict | None = None) -> HttpResponse:
        return await self._request("HEAD", url, headers=headers)

    async def options(self, url: str, *, headers: dict | None = None) -> HttpResponse:
        return await self._request("OPTIONS", url, headers=headers)

    @classmethod
    async def fetch(
        cls,
        url: str,
        method: str = "GET",
        config: HttpConfig | None = None,
        **kwargs,
    ) -> HttpResponse:
        """One-shot request without managing client lifecycle."""
        async with cls(config) as client:
            return await client._request(method, url, **kwargs)
