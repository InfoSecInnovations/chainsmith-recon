"""
app/checks/web/auth_detection.py - Authentication Detection

Probes for authentication mechanisms:
- HTTP Basic/Digest/Bearer (401 + WWW-Authenticate)
- OAuth/OIDC discovery endpoints
- Login form detection
- API key headers

Outputs auth_mechanisms for downstream checks.

**Probe/grade.** `check_service()` fetches the root, the
eight auth paths and up to five API paths from `discovered_paths`, records each,
and judges nothing; `grade()` re-reads them and names what it finds.

`auth_mechanisms` is an output, so the probe has to know the answer before a
grader runs. Both halves call `_mechanisms()` over the same exchanges (§6.2's
two parses, with one parser), and `grade()` tells each exchange's role apart by
its URL: the root is the one whose URL is the service's own, the auth probes are
the paths in `AUTH_PROBE_PATHS`, and the API paths come from the same upstream
output the probe read.

**The weakest judgement in the check now says so.** `no-auth-<path>` claims "API
endpoint requires no authentication" on the strength of one unauthenticated GET
returning 200 — which is equally consistent with an endpoint that is public by
design. Worse, it fires when the content type is JSON *or* when the path merely
contains `api`, so an HTML page under `/api/docs` qualifies. The JSON case now
carries 0.7 and the path-only case 0.45; the observation and its `medium`
severity are unchanged.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

# Paths to probe for auth mechanisms
AUTH_PROBE_PATHS = [
    "/.well-known/openid-configuration",
    "/oauth/authorize",
    "/oauth/token",
    "/auth",
    "/login",
    "/signin",
    "/api/auth",
    "/api/login",
]

OIDC_PATH = "/.well-known/openid-configuration"
OAUTH_PATHS = ("/oauth/authorize", "/oauth/token")

# Password input pattern in HTML
LOGIN_FORM_RE = re.compile(
    r"""<input[^>]*type\s*=\s*["']password["'][^>]*>""",
    re.I,
)


class AuthDetectionCheck(ServiceIteratingCheck):
    """Detect authentication mechanisms on HTTP services."""

    name = "web_auth_detection"
    description = "Detect authentication mechanisms (Basic, Bearer, OAuth, login forms)"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["auth_mechanisms"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Understanding authentication informs downstream AI/agent check interpretation"
    references = ["OWASP WSTG-ATHN-01", "CWE-287"]
    techniques = ["authentication detection", "endpoint enumeration"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record, publish the output. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate per service: every mechanism is a separate judgement
        # over the same subject, so the candidate stays undiscriminated and
        # `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:

                async def fetch(url: str) -> None:
                    resp = await client.get(url)
                    if resp.error:
                        return
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                # ── Check root for WWW-Authenticate ──
                await fetch(service.url)

                # ── Probe auth-related paths ──
                for path in AUTH_PROBE_PATHS:
                    await self._rate_limit()
                    await fetch(service.with_path(path))

                # ── Check if API endpoints lack auth ──
                api_paths = self._get_api_paths(service, context)
                for api_path in api_paths[:5]:  # Check up to 5
                    await self._rate_limit()
                    await fetch(service.with_path(api_path))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        result.outputs["auth_mechanisms"] = _mechanisms(candidate.exchanges, root_url=service.url)
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded responses. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Name the authentication mechanisms one service exposes."""
        exchanges = list(evidence)
        root_url = (ctx.target.url if ctx.target else ctx.target_url) or ""
        api_paths = self._get_api_paths(ctx.target, ctx.context) if ctx.target is not None else []
        verdicts: list[Verdict] = []

        for exchange in exchanges:
            path = _role_path(exchange, root_url)

            # ── The root: WWW-Authenticate at any status ──
            if path == "/" and (exchange.request_url or "") == root_url:
                verdicts.extend(self._grade_www_auth(exchange, ctx, "/"))
                continue

            if path in AUTH_PROBE_PATHS:
                # 401/403 with WWW-Authenticate
                if exchange.response_status in (401, 403):
                    verdicts.extend(self._grade_www_auth(exchange, ctx, path))

                # OIDC discovery document
                if path == OIDC_PATH and exchange.response_status == 200:
                    body = (exchange.response_body or "").lower()
                    if "issuer" in body and "authorization_endpoint" in body:
                        verdicts.append(
                            Verdict(
                                severity="info",
                                # The document names itself: an `issuer` and an
                                # `authorization_endpoint` at the well-known
                                # path is what an OIDC provider is. Short of
                                # certain only because the two keys were matched
                                # as substrings rather than parsed as JSON.
                                confidence=0.95,
                                discriminator="oidc-discovery",
                                title=f"OAuth/OIDC provider detected: {ctx.host}",
                                description="OpenID Connect discovery document found",
                                evidence=fmt_status_evidence(
                                    exchange.request_url or "",
                                    200,
                                    (exchange.response_body or "")[:200],
                                ),
                                reasoning=(
                                    "the well-known OIDC path returned a document naming "
                                    "issuer and authorization_endpoint"
                                ),
                                signals={"path": path},
                                evidence_ids=[exchange.id],
                            )
                        )

                # Login form detection
                if (
                    exchange.response_status == 200
                    and exchange.response_body
                    and LOGIN_FORM_RE.search(exchange.response_body)
                ):
                    verdicts.append(
                        Verdict(
                            severity="info",
                            # A password input is unambiguous; that the page is a
                            # *login* page is the small inference — a
                            # registration or password-change form has one too.
                            confidence=0.9,
                            discriminator=f"login-form-{path.replace('/', '-')}",
                            title=f"Login page detected: {ctx.host}{path}",
                            description="HTML page with password input form found",
                            evidence=fmt_status_evidence(exchange.request_url or "", 200),
                            reasoning=(
                                "the 200 response contains a password input; a "
                                "registration or password-change form would match too"
                            ),
                            signals={"path": path},
                            evidence_ids=[exchange.id],
                        )
                    )
                continue

            # ── API endpoints reached without credentials ──
            if path in api_paths and exchange.response_status == 200:
                content_type = extract_headers_dict(exchange.response_headers or {}).get(
                    "content-type", ""
                )
                json_body = "json" in content_type
                if json_body or "api" in path:
                    verdicts.append(
                        Verdict(
                            severity="medium",
                            # One unauthenticated GET returning 200 is equally
                            # consistent with an endpoint that is public by
                            # design; nothing here establishes that auth was
                            # *expected*. Weaker still when the only reason it
                            # qualified is `api` appearing in the path, which an
                            # HTML page under /api/docs also satisfies.
                            confidence=0.7 if json_body else 0.45,
                            discriminator=f"no-auth-{path.replace('/', '-')}",
                            title=(f"API endpoint requires no authentication: {ctx.host}{path}"),
                            description=(
                                "API endpoint returned 200 with no authentication required"
                            ),
                            evidence=fmt_status_evidence(exchange.request_url or "", 200),
                            reasoning=(
                                f"200 with content-type {content_type!r} and no credentials "
                                "sent; whether authentication was expected is not observable"
                                if json_body
                                else "200 with no credentials sent, and the path contains "
                                "'api' — the content type is not JSON, so this may not be "
                                "an API endpoint at all"
                            ),
                            signals={"path": path, "content_type": content_type},
                            evidence_ids=[exchange.id],
                        )
                    )

        return verdicts

    def _grade_www_auth(self, exchange: Exchange, ctx: GradeContext, path: str) -> list[Verdict]:
        """Grade one recorded WWW-Authenticate challenge."""
        www_auth = extract_headers_dict(exchange.response_headers or {}).get("www-authenticate", "")
        if not www_auth:
            return []

        auth_type = _auth_type(www_auth)
        scheme = ctx.target.scheme if ctx.target else ""
        # Bearer without HTTPS is a risk
        insecure_bearer = auth_type == "bearer" and scheme == "http"

        return [
            Verdict(
                severity="low" if insecure_bearer else "info",
                # The scheme is read verbatim out of the challenge header, and
                # the transport is known, so both halves of this are facts.
                confidence=0.99,
                discriminator=f"www-auth-{auth_type}-{path.replace('/', '-')}",
                title=f"{auth_type.title()} auth required: {ctx.host}{path}",
                description=(f"WWW-Authenticate header specifies {auth_type} authentication"),
                evidence=(f"HTTP {exchange.response_status} | WWW-Authenticate: {www_auth[:200]}"),
                reasoning=(
                    f"the challenge names {auth_type} and the service is plain HTTP, so "
                    "the token travels in clear"
                    if insecure_bearer
                    else f"the challenge header names {auth_type} verbatim"
                ),
                signals={"auth_type": auth_type, "path": path, "scheme": scheme},
                evidence_ids=[exchange.id],
            )
        ]

    @staticmethod
    def _get_api_paths(service: Service, context: dict) -> list[str]:
        """Get API-like paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            accessible = paths_data[paths_key].get("accessible", [])
        elif paths_key in context:
            accessible = context[paths_key].get("accessible", [])
        else:
            accessible = []
        # Filter to paths that look like API endpoints
        return [
            p
            for p in accessible
            if any(seg in p.lower() for seg in ["/api/", "/v1/", "/v2/", "/graphql"])
        ]


# ── The one parser, called by both halves ────────────────────────────


def _auth_type(www_auth: str) -> str:
    """The scheme a WWW-Authenticate challenge names."""
    parts = www_auth.split()
    return parts[0].lower() if parts else "unknown"


def _role_path(exchange: Exchange, root_url: str) -> str:
    """Which path this exchange asked for, relative to the service.

    Taken from the recorded URL rather than from probe-side bookkeeping, so the
    grader can tell the root from an auth probe from an API path when re-reading
    a stored corpus.
    """
    from urllib.parse import urlparse

    if (exchange.request_url or "") == root_url:
        return "/"
    return urlparse(exchange.request_url or "").path or "/"


def _mechanisms(exchanges: list[Exchange], *, root_url: str) -> dict[str, list[str]]:
    """Read one service's authentication mechanisms out of its exchanges.

    The single parser behind §6.2's two parses: `check_service()` calls it to
    populate `auth_mechanisms`, and the same readings drive `grade()`'s
    verdicts. Insertion order matches the probe's fetch order, which is what
    keeps the output identical to the pre-57.4 shape.
    """
    mechanisms: dict[str, list[str]] = {}

    for exchange in exchanges:
        path = _role_path(exchange, root_url)
        headers = extract_headers_dict(exchange.response_headers or {})

        # WWW-Authenticate: at any status on the root, and only on a 401/403
        # from one of the auth probe paths. An API path is never read for a
        # challenge — the original never did, and a 401 there means something
        # else to this check.
        is_root = path == "/" and (exchange.request_url or "") == root_url
        if is_root or (path in AUTH_PROBE_PATHS and exchange.response_status in (401, 403)):
            www_auth = headers.get("www-authenticate", "")
            if www_auth:
                mechanisms.setdefault(_auth_type(www_auth), []).append(path)

        if path not in AUTH_PROBE_PATHS:
            continue

        if path == OIDC_PATH and exchange.response_status == 200:
            body = (exchange.response_body or "").lower()
            if "issuer" in body and "authorization_endpoint" in body:
                mechanisms.setdefault("oidc", []).append(path)

        if path in OAUTH_PATHS and exchange.response_status in (200, 302, 400):
            mechanisms.setdefault("oauth", []).append(path)

        if (
            exchange.response_status == 200
            and exchange.response_body
            and LOGIN_FORM_RE.search(exchange.response_body)
        ):
            mechanisms.setdefault("login_form", []).append(path)

    return mechanisms
