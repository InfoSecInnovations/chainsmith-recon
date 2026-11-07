"""
app/checks/network/http_method_enum.py

HTTP Method Enumeration

Probes HTTP services with OPTIONS, TRACE, PUT, DELETE, and PATCH
to detect unexpected or dangerous methods enabled.

Depends on: services (needs HTTP services from service_probe)
Feeds: security posture assessment, web checks

**Probe/grade.** `run()` fires one request per method and
records each as an `http` exchange; `grade()` reads the eleven recorded responses
back and decides what the server accepted. This check drives `httpx` directly
rather than going through `app/lib/http.py`, so it was never reached by the 57.2
interceptor and had no evidence at all — it now records through
`capture.record_exchange()`, which closes that gap as a side effect of the split.

`http_methods` is an output, so the probe has to know what was accepted before a
grader runs. Rather than duplicate that reading, both halves call the same
`_summarise()` over the same exchanges (§6.2's two parses, with one parser): the
probe over the responses it just received, the grader over the stored copies.
"""

import logging
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Evidence, GradeContext, Verdict

logger = logging.getLogger(__name__)

# Methods to probe and their security implications
DANGEROUS_METHODS = {
    "TRACE": {
        "severity": "medium",
        "desc": (
            "TRACE method is enabled, which can be exploited for Cross-Site "
            "Tracing (XST) attacks. An attacker can use TRACE to steal "
            "credentials from HttpOnly cookies via JavaScript."
        ),
    },
    "PUT": {
        "severity": "medium",
        "desc": (
            "PUT method is accepted, which may allow unauthorized file uploads "
            "or resource modification. On AI/ML endpoints this could enable "
            "unauthorized model or data manipulation."
        ),
    },
    "DELETE": {
        "severity": "low",
        "desc": (
            "DELETE method is accepted, which may allow unauthorized resource "
            "deletion. On AI/ML endpoints this could enable unauthorized "
            "model or data removal."
        ),
    },
    "PATCH": {
        "severity": "low",
        "desc": (
            "PATCH method is accepted, which may allow unauthorized partial resource modification."
        ),
    },
}

# WebDAV methods that indicate extended functionality
WEBDAV_METHODS = ["PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]


class HttpMethodEnumCheck(BaseCheck):
    """
    Enumerate allowed HTTP methods on discovered services.

    Sends OPTIONS request to discover allowed methods, then probes
    individually for TRACE, PUT, DELETE, PATCH. Also checks for WebDAV
    methods on non-standard services.

    Produces:
        http_methods - dict[host:port, {allowed: list[str], dangerous: list[str]}]
    """

    name = "network_http_method_enum"
    description = "HTTP method enumeration and dangerous method detection"

    conditions = [
        CheckCondition("services", "truthy"),
    ]
    produces = ["http_methods"]

    reason = (
        "Unexpected HTTP methods on production services indicate misconfiguration. "
        "TRACE enables cross-site tracing (XST), while PUT/DELETE on AI endpoints "
        "may allow unauthorized model modification or data deletion."
    )
    references = [
        "OWASP WSTG-CONF-06 — Test HTTP Methods",
        "CWE-16 — Configuration",
        "CWE-749 — Exposed Dangerous Method or Function",
    ]
    techniques = [
        "HTTP method enumeration",
        "OPTIONS probing",
        "cross-site tracing detection",
    ]

    # Status codes that indicate a method is accepted (not just "not allowed")
    ACCEPTED_CODES = {200, 201, 204, 207, 301, 302, 307, 308, 405}
    # 405 is "Method Not Allowed" — server explicitly rejects, so method is NOT accepted
    # We include it in the set to differentiate from connection errors
    METHOD_ALLOWED_CODES = {200, 201, 204, 207, 301, 302, 307, 308}

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        services: list[Service] = context.get("services", [])
        if not services:
            result.errors.append("No services in context")
            result.success = False
            return result

        # Filter to HTTP/HTTPS services only
        http_services = [svc for svc in services if svc.scheme in ("http", "https")]

        if not http_services:
            result.outputs["http_methods"] = {}
            return result

        # Deduplicate by host:port
        seen: set[tuple[str, int]] = set()
        unique_services: list[Service] = []
        for svc in http_services:
            key = (svc.host, svc.port)
            if key not in seen:
                seen.add(key)
                unique_services.append(svc)

        http_methods_data: dict[str, dict] = {}

        for svc in unique_services:
            endpoint = f"{svc.host}:{svc.port}"
            method_info, exchanges = await self._probe_service(svc)
            http_methods_data[endpoint] = method_info
            result.targets_checked += 1

            candidate = self.create_candidate(host=svc.host, target=svc)
            for exchange in exchanges:
                candidate.attach(exchange)
            result.candidates.append(candidate)

        result.outputs["http_methods"] = http_methods_data
        return result

    async def _probe_service(self, svc: Service) -> tuple[dict[str, Any], list[Exchange]]:
        """Probe a single service for allowed HTTP methods.

        Returns the summary `http_methods` carries *and* the exchanges it was
        read from, so the grader can read the same thing from the same bytes.
        """
        base_url = svc.url.rstrip("/")
        exchanges: list[Exchange] = []

        # Step 1: OPTIONS request to get Allow header
        exchanges.append(await self._probe_method(base_url, "OPTIONS", svc.host, timeout=10.0))

        # Step 2 and 3: dangerous methods, then WebDAV
        for method in list(DANGEROUS_METHODS) + WEBDAV_METHODS:
            exchanges.append(await self._probe_method(base_url, method, svc.host))

        return _summarise(exchanges), exchanges

    async def _probe_method(
        self, base_url: str, method: str, host: str, timeout: float = 8.0
    ) -> Exchange:
        """Send a single method probe and record what came back.

        Always returns an exchange, including for a request that never completed
        — a timeout recorded as a timeout is what keeps "the server refused this
        method" and "we never reached the server" apart on the grade side.
        """
        import httpx

        url = base_url + "/"
        status: int | None = None
        headers: dict[str, str] = {}
        error: str | None = None
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=timeout,
                follow_redirects=False,
            ) as client:
                resp = await client.request(method, url)
                status = resp.status_code
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.debug(f"{method} failed for {base_url}: {exc}")
            error = f"{type(exc).__name__}: {exc}"

        return capture.record_exchange(
            "http",
            host,
            request_method=method,
            request_url=url,
            response_status=status,
            response_headers=headers,
            error=error,
        )

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on what one service accepted."""
        exchanges = list(evidence)
        if not exchanges:
            return []

        method_info = _summarise(exchanges)
        allowed = method_info["allowed"]
        dangerous = method_info["dangerous"]
        webdav = method_info["webdav"]

        port = ctx.target.port if ctx.target else ""
        endpoint = f"{ctx.host}:{port}"
        base_url = (ctx.target.url.rstrip("/") if ctx.target else ctx.target_url) or ""
        by_method = _by_method(exchanges)
        verdicts: list[Verdict] = []

        # ── What the service accepts ───────────────────────
        if allowed:
            verdicts.append(
                Verdict(
                    severity="info",
                    # A method list assembled from an Allow header and eleven
                    # status codes. The header is self-declared and servers
                    # routinely under-report it, which is why the check probes.
                    confidence=0.9,
                    discriminator=f"methods-{port}",
                    title=f"Allowed methods: {endpoint}",
                    description=(
                        f"HTTP method enumeration on {endpoint} discovered "
                        f"{len(allowed)} allowed method(s)."
                    ),
                    evidence=f"Allowed: {', '.join(sorted(allowed))}",
                    reasoning=(f"{len(allowed)} method(s) accepted across {len(exchanges)} probes"),
                    signals={"allowed": sorted(allowed)},
                    raw_data=method_info,
                    evidence_ids=[e.id for e in exchanges],
                )
            )

        # ── Dangerous methods ─────────────────────────────
        for method in dangerous:
            meta = DANGEROUS_METHODS[method]
            exchange = by_method.get(method)
            verdicts.append(
                Verdict(
                    severity=meta["severity"],
                    # "Not 405/501/400" is a weak proxy for "accepted": a 401 or
                    # a 302 to a login page counts here and means the method was
                    # never actually performed. Stated rather than asserted.
                    confidence=0.7,
                    discriminator=f"{method.lower()}-{port}",
                    title=f"{method} method enabled: {endpoint}",
                    description=meta["desc"],
                    evidence=f"HTTP {method} {base_url}/ returned a non-405 response",
                    reasoning=(
                        f"{method} returned {exchange.response_status}"
                        if exchange is not None
                        else f"{method} was not explicitly refused"
                    ),
                    signals={
                        "method": method,
                        "status": exchange.response_status if exchange else None,
                    },
                    references=(
                        ["CWE-693 — Protection Mechanism Failure"] if method == "TRACE" else []
                    ),
                    evidence_ids=[exchange.id] if exchange is not None else [],
                )
            )

        # ── WebDAV ────────────────────────────────────────
        if webdav:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # Several WebDAV verbs answering together is a much stronger
                    # signal than any one of them: a catch-all handler returning
                    # 200 for everything is the usual false positive, and it
                    # would light up all six rather than a plausible subset.
                    confidence=0.75 if len(webdav) > 1 else 0.6,
                    discriminator=f"webdav-{port}",
                    title=f"WebDAV methods enabled: {endpoint}",
                    description=(
                        f"WebDAV methods ({', '.join(webdav)}) are enabled on "
                        f"{endpoint}. This indicates extended file management "
                        f"capabilities that may expose sensitive operations."
                    ),
                    evidence=f"WebDAV methods: {', '.join(webdav)}",
                    reasoning=f"{len(webdav)} of {len(WEBDAV_METHODS)} WebDAV verbs accepted",
                    signals={"webdav": webdav},
                    evidence_ids=[by_method[m].id for m in webdav if by_method.get(m) is not None],
                )
            )

        return verdicts


def _by_method(exchanges: list[Exchange]) -> dict[str, Exchange]:
    """The exchanges indexed by the method they sent."""
    return {(e.request_method or "").upper(): e for e in exchanges}


def _accepted(exchange: Exchange | None) -> bool:
    """True when the server did not explicitly refuse this method.

    The original rule, unchanged: anything but 405, 501 or 400. A request that
    never completed is not an acceptance — which is why a failed probe is
    recorded with `error` rather than dropped.
    """
    if exchange is None or exchange.error is not None or exchange.response_status is None:
        return False
    return exchange.response_status not in (405, 501, 400)


def _summarise(exchanges: list[Exchange]) -> dict[str, Any]:
    """Read one service's method exposure out of its recorded exchanges.

    The single parser behind §6.2's two parses: `run()` calls it to populate
    `http_methods`, and `grade()` calls it again over the stored copies.
    """
    info: dict[str, Any] = {
        "allowed": [],
        "dangerous": [],
        "webdav": [],
        "options_allow": None,
    }
    by_method = _by_method(exchanges)

    # Step 1: the OPTIONS Allow header
    options = by_method.get("OPTIONS")
    if options is not None and options.error is None:
        allow_header = (options.response_headers or {}).get("allow", "")
        if allow_header:
            info["options_allow"] = allow_header
            info["allowed"] = [m.strip().upper() for m in allow_header.split(",")]

    # Step 2: dangerous methods, probed individually
    for method in DANGEROUS_METHODS:
        if _accepted(by_method.get(method)):
            if method not in info["allowed"]:
                info["allowed"].append(method)
            info["dangerous"].append(method)

    # Step 3: WebDAV
    for method in WEBDAV_METHODS:
        if _accepted(by_method.get(method)):
            info["webdav"].append(method)
            if method not in info["allowed"]:
                info["allowed"].append(method)

    return info
