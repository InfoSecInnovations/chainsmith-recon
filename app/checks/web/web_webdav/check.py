"""
app/checks/web/webdav.py - Insecure WebDAV Detection

Probes HTTP services for WebDAV methods (PROPFIND, MKCOL, PUT).
If any succeed, WebDAV is enabled and likely misconfigured.

GATED: Requires checks.intrusive_web = true (opt-in).

**Probe/grade.** `check_service()` sends the three method
probes, records each, cleans up after itself, and judges nothing; `grade()`
re-reads the recorded responses and decides what each status code is worth.

The probe still branches on a status code, in the one place it has to: a
successful PUT or MKCOL leaves a file behind, and the cleanup `DELETE` is a side
effect, not a judgement. It reads that status off the exchange it just recorded
(§6.2), so the grader and the cleanup agree on what happened.

What the split adds here is the caveat that was always true and never stated:
**this check asks a status code whether WebDAV exists.** A framework with a
catch-all route answers `200` to any verb, which is indistinguishable from a
real WebDAV server at the status level — so the verdicts that see the specific
WebDAV answer (`207 Multi-Status`, `201 Created`) are markedly more confident
than the ones that see a bare `200`, and `put-requires-auth` is the least
confident of all: a `401` on PUT is exactly what a site that requires auth
everywhere and has no WebDAV at all returns.
"""

import uuid
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig


class WebDAVCheck(ServiceIteratingCheck):
    """Detect insecure WebDAV access on HTTP services."""

    name = "web_webdav"  # renamed from webdav_check
    description = "Probe for WebDAV methods that allow file upload or directory listing"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["webdav_observations"]
    service_types = ["http", "html", "api"]

    reason = "WebDAV write access = arbitrary file upload = likely RCE path, superseding AI-specific observations"
    references = ["OWASP WSTG-CONF-06", "CWE-284"]
    techniques = ["WebDAV method probing", "HTTP method enumeration"]

    # Methods to test, in order of severity
    WEBDAV_METHODS = ["PROPFIND", "MKCOL", "PUT"]

    #: Statuses that mean the write actually happened, unchanged from before.
    WRITE_SUCCESS = (200, 201, 204)

    # ══ Probe ════════════════════════════════════════════════════════
    # Send, record, clean up. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Gate: intrusive_web must be enabled
        if not self._is_intrusive_allowed():
            result.outputs["webdav_skipped"] = True
            return result

        scan_id = context.get("scan_id") or ""
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        # One candidate per service: the three methods are independent
        # judgements over the same subject, so the candidate stays
        # undiscriminated and `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        def record(method: str, resp, **kwargs) -> Exchange:
            # `HttpResponse.url` is the URL that was requested, so the exchange
            # already names the right target and its hash still pairs with the
            # interceptor's stored copy when capture is on.
            exchange = exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=service.host,
                method=method,
                **kwargs,
            )
            candidate.attach(exchange)
            return exchange

        try:
            async with AsyncHttpClient(cfg) as client:
                # Test PROPFIND on root
                propfind_resp = await client._request(
                    "PROPFIND", service.url, headers={"Depth": "0"}
                )
                record("PROPFIND", propfind_resp, request_headers={"Depth": "0"})

                # Test PUT with a non-destructive test file
                test_filename = f"chainsmith-webdav-test-{uuid.uuid4().hex[:8]}.txt"
                test_url = service.with_path(f"/{test_filename}")
                put_resp = await client._request(
                    "PUT",
                    test_url,
                    data="chainsmith webdav test",
                    headers={"Content-Type": "text/plain"},
                )
                put_exchange = record(
                    "PUT",
                    put_resp,
                    request_headers={"Content-Type": "text/plain"},
                    request_body="chainsmith webdav test",
                )
                # Cleanup is a side effect, not a judgement: a file we created
                # has to go, and the recorded status is what says we created one.
                if _write_succeeded(put_exchange):
                    await client._request("DELETE", test_url)

                # Test MKCOL
                mkcol_path = f"/chainsmith-webdav-test-{uuid.uuid4().hex[:8]}/"
                mkcol_url = service.with_path(mkcol_path)
                mkcol_resp = await client._request("MKCOL", mkcol_url)
                mkcol_exchange = record("MKCOL", mkcol_resp)
                if _write_succeeded(mkcol_exchange):
                    await client._request("DELETE", mkcol_url)

            result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded method probes. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on what each WebDAV method answered."""
        by_method = {(e.request_method or "").upper(): e for e in evidence}
        verdicts: list[Verdict] = []

        propfind = by_method.get("PROPFIND")
        if propfind is not None and _ok(propfind) and propfind.response_status in range(200, 300):
            body = propfind.response_body or ""
            # `207 Multi-Status`, or a body naming the `DAV:` namespace, is the
            # answer only a WebDAV implementation gives. A bare `200` is also
            # what a catch-all route returns for every verb it does not know.
            spoke_dav = propfind.response_status == 207 or "dav:" in body.lower()
            verdicts.append(
                Verdict(
                    severity="high",
                    confidence=0.95 if spoke_dav else 0.6,
                    discriminator="propfind-enabled",
                    title=f"WebDAV PROPFIND enabled: {ctx.host}",
                    description=("PROPFIND returned success — WebDAV directory listing possible"),
                    evidence=fmt_status_evidence(
                        propfind.request_url or "", propfind.response_status, body[:200]
                    ),
                    reasoning=(
                        f"PROPFIND returned {propfind.response_status} and the response "
                        "speaks WebDAV"
                        if spoke_dav
                        else f"PROPFIND returned {propfind.response_status}, which a "
                        "catch-all route also returns for an unknown verb"
                    ),
                    signals={
                        "status": propfind.response_status,
                        "multistatus": propfind.response_status == 207,
                    },
                    evidence_ids=[propfind.id],
                )
            )

        put = by_method.get("PUT")
        if put is not None and _ok(put):
            if put.response_status in self.WRITE_SUCCESS:
                # `201 Created` / `204 No Content` are the answers a store that
                # wrote something gives. A `200` is weaker for the same
                # catch-all reason — and either way the file was never read back,
                # so "upload possible" rests on the server's own word.
                created = put.response_status in (201, 204)
                verdicts.append(
                    Verdict(
                        severity="critical",
                        confidence=0.85 if created else 0.7,
                        discriminator="put-write-access",
                        title=f"WebDAV write access: PUT accepted at {ctx.host}",
                        description=(
                            "PUT request succeeded — arbitrary file upload possible via WebDAV"
                        ),
                        evidence=fmt_status_evidence(put.request_url or "", put.response_status),
                        reasoning=(
                            f"PUT returned {put.response_status}; the uploaded file was "
                            "never fetched back, so the write is the server's claim"
                        ),
                        signals={"status": put.response_status, "created": created},
                        evidence_ids=[put.id],
                    )
                )
            elif put.response_status == 401:
                verdicts.append(
                    Verdict(
                        severity="medium",
                        # The weakest judgement in the check: a 401 on PUT is
                        # exactly what a site requiring auth on every route
                        # returns, WebDAV or no WebDAV. It is evidence of
                        # authentication, not of WebDAV.
                        confidence=0.5,
                        discriminator="put-requires-auth",
                        title=f"WebDAV methods require auth: {ctx.host}",
                        description=(
                            "WebDAV PUT returned 401 — methods detected but require authentication"
                        ),
                        evidence=fmt_status_evidence(put.request_url or "", put.response_status),
                        reasoning=(
                            "PUT returned 401, which proves authentication is required "
                            "but not that WebDAV is implemented"
                        ),
                        signals={"status": put.response_status},
                        evidence_ids=[put.id],
                    )
                )

        mkcol = by_method.get("MKCOL")
        if mkcol is not None and _ok(mkcol) and mkcol.response_status in self.WRITE_SUCCESS:
            created = mkcol.response_status in (201, 204)
            verdicts.append(
                Verdict(
                    severity="critical",
                    # Same split as PUT: `201` is MKCOL's own success code, a
                    # bare `200` is what an unrouted verb collects.
                    confidence=0.85 if created else 0.7,
                    discriminator="mkcol-enabled",
                    title=f"WebDAV MKCOL enabled: {ctx.host}",
                    description="MKCOL succeeded — directory creation via WebDAV possible",
                    evidence=fmt_status_evidence(mkcol.request_url or "", mkcol.response_status),
                    reasoning=(
                        f"MKCOL returned {mkcol.response_status}; the collection was "
                        "never listed back, so the creation is the server's claim"
                    ),
                    signals={"status": mkcol.response_status, "created": created},
                    evidence_ids=[mkcol.id],
                )
            )

        return verdicts

    @staticmethod
    def _is_intrusive_allowed() -> bool:
        """Check if intrusive web checks are enabled in preferences."""
        try:
            from app.preferences import get_preferences

            return get_preferences().checks.intrusive_web
        except Exception:
            return False


def _ok(exchange: Exchange) -> bool:
    """True when the request reached the server and came back.

    The original `not resp.error` guard, read off the exchange instead.
    """
    return exchange.error is None and exchange.response_status is not None


def _write_succeeded(exchange: Exchange) -> bool:
    """True when a recorded PUT or MKCOL reports having written something.

    The probe's cleanup and the grader's verdict read this same function over
    the same bytes, so the file that gets deleted is the file that got flagged.
    """
    return _ok(exchange) and exchange.response_status in WebDAVCheck.WRITE_SUCCESS
