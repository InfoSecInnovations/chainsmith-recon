"""
app/checks/web/hsts_preload.py - HSTS Preload Verification

Checks whether a domain with an HSTS header is on the Chromium HSTS
preload list. Domains not preloaded are vulnerable to SSL stripping
on first visit, even with HSTS headers present.

Uses the hstspreload.org API for verification.

**Probe/grade.** `check_service()` resolves the HSTS header,
queries hstspreload.org when there is one to ask about, and judges nothing;
`grade()` re-reads both recorded exchanges and places the severity.

The probe still branches on the header — it only calls the third-party API when
the target actually sent HSTS, which is a request not worth making otherwise —
and it reads that header off the exchange it just recorded (§6.2). `_reading()`
is the one parser both halves call, because `hsts_preload_info` is an output.

**The honesty this split buys is the whole point of the check.** `is_preloaded`
was `False` in three quite different situations: the API said the domain is not
on the list, the API was unreachable, and the API answered something
unparseable. The original asserted "domain not preloaded" identically in all
three. Now a verdict whose `status` came from the API carries 0.9 and one
derived from an API that never answered carries 0.4, with the reason written
into `reasoning`. Nothing about which observation fires has changed.

This check reads two sources that are not the target: an upstream check's
`header_info` output, and hstspreload.org. The header is resolved from *this*
service's own recorded GET where there is one, and only falls back to the
upstream output — so two services on one host cannot be graded from each
other's headers.
"""

import logging
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict, safe_json

logger = logging.getLogger(__name__)

#: One year, the minimum max-age the preload list requires.
MIN_MAX_AGE = 31536000

#: Marks the hstspreload.org exchange among the candidate's evidence.
API_HOST = "hstspreload.org"


class HSTSPreloadCheck(ServiceIteratingCheck):
    """Verify HSTS preload status for domains with HSTS headers."""

    name = "web_hsts_preload"
    description = "Check if domain is on the HSTS preload list (Chromium)"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["hsts_preload_info"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Domains not on the HSTS preload list are vulnerable to SSL stripping on first visit"
    references = ["RFC 6797", "hstspreload.org"]
    techniques = ["HSTS preload verification", "transport security analysis"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Resolve the header, ask the list, record both. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate per service: the four postures are mutually exclusive,
        # so the candidate stays undiscriminated and `grade()` names the one
        # that holds — including naming none, where the original said nothing.
        candidate = self.create_candidate(host=service.host, target=service)

        # Only relevant for HTTPS services or services with HSTS headers
        hsts_header = self._get_hsts_header(service, context)

        if not hsts_header and service.scheme != "https":
            result.candidates.append(candidate)
            result.outputs["hsts_preload_info"] = {"checked": False}
            return result

        # If no header found in context, fetch it ourselves
        if not hsts_header:
            cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
            try:
                async with AsyncHttpClient(cfg) as client:
                    await self._rate_limit()
                    resp = await client.get(service.url)
                candidate.attach(
                    exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host
                    )
                )
                if not resp.error:
                    hsts_header = extract_headers_dict(resp.headers).get(
                        "strict-transport-security", ""
                    )
            except Exception as e:
                result.errors.append(f"HSTS header fetch error: {e}")

        if not hsts_header:
            result.candidates.append(candidate)
            result.outputs["hsts_preload_info"] = {"checked": False}
            return result

        # Check preload list via hstspreload.org API
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=True)
        try:
            async with AsyncHttpClient(cfg) as client:
                await self._rate_limit()
                api_url = f"https://{API_HOST}/api/v2/status?domain={service.host}"
                resp = await client.get(api_url)
            candidate.attach(
                exchange_from_response(resp, check_name=self.name, scan_id=scan_id, host=API_HOST)
            )
        except Exception as e:
            # No exchange to record: the failure was the client's, not the
            # API's, and `_reading()` reads a missing API exchange as
            # `api_error` — the status the original set on this same path.
            result.errors.append(f"HSTS preload API error: {e}")

        result.candidates.append(candidate)
        reading = self._reading(candidate.exchanges, target_url=service.url, context=context)
        result.outputs["hsts_preload_info"] = reading["info"]
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded header and API answer. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one domain's HSTS preload posture."""
        exchanges = list(evidence)
        scheme = ctx.target.scheme if ctx.target else "https"
        reading = self._reading(exchanges, target_url=ctx.target_url, context=ctx.context)

        hsts_header = reading["hsts_header"]
        info = reading["info"]
        api_answered = reading["api_answered"]
        preload_status = info.get("status", "unknown")
        ids = [e.id for e in exchanges]

        if not hsts_header:
            if scheme != "https":
                return [
                    Verdict(
                        severity="info",
                        # A plain statement of what was observed. Not 1.0
                        # because a server can send HSTS on its HTTPS listener
                        # and not here, so the absence is about this listener.
                        confidence=0.9,
                        discriminator="no-hsts",
                        title=f"No HSTS header: {ctx.host}",
                        description=("No HSTS header present — HSTS preload check not applicable"),
                        evidence="No Strict-Transport-Security header detected",
                        reasoning=(
                            "no Strict-Transport-Security on this non-HTTPS service; the "
                            "HTTPS listener, if any, was not consulted here"
                        ),
                        signals={"scheme": scheme},
                        evidence_ids=ids,
                        references=["RFC 6797"],
                    )
                ]
            # HTTPS with no HSTS header at all: the original said nothing here,
            # leaving the missing header to `web_header_analysis`.
            return []

        # A `status` the API actually produced is evidence; one standing in for
        # an API that never answered is the absence of evidence, and every
        # verdict below rests on it.
        if api_answered:
            confidence = 0.9
            api_note = f"hstspreload.org answered `{preload_status}`"
        else:
            confidence = 0.4
            api_note = (
                f"hstspreload.org did not answer ({preload_status}), so preload status "
                "is unverified"
            )

        if info.get("preloaded"):
            return [
                Verdict(
                    severity="info",
                    # The API is the list, so this is close to authoritative —
                    # short of 1.0 because the browser list ships on a release
                    # cadence, and a freshly added domain is not yet enforced.
                    confidence=0.95,
                    discriminator="preloaded",
                    title=f"Domain is HSTS preloaded: {ctx.host}",
                    description=(
                        "Domain is on the Chromium HSTS preload list — browsers enforce "
                        "HTTPS on first visit"
                    ),
                    evidence=(
                        f"hstspreload.org status: {preload_status} | HSTS: {hsts_header[:200]}"
                    ),
                    reasoning=(
                        f"{api_note}; enforcement still depends on the browser release "
                        "that shipped the list"
                    ),
                    signals=info,
                    references=["RFC 6797"],
                    evidence_ids=ids,
                )
            ]

        if info.get("has_preload_directive"):
            return [
                Verdict(
                    severity="info",
                    confidence=confidence,
                    discriminator="preload-pending",
                    title=(f"HSTS preload directive present but not yet preloaded: {ctx.host}"),
                    description=(
                        "The HSTS header includes the preload directive, but the domain is "
                        "not yet on the preload list. Submission may be pending or rejected."
                    ),
                    evidence=(
                        f"hstspreload.org status: {preload_status} | HSTS: {hsts_header[:200]}"
                    ),
                    reasoning=(
                        "the `preload` directive is read verbatim from the recorded header; "
                        f"{api_note}"
                    ),
                    signals=info,
                    references=["RFC 6797", "hstspreload.org"],
                    evidence_ids=ids,
                )
            ]

        # HSTS present but not preloaded — first-visit vulnerability
        missing = []
        if not info.get("has_preload_directive"):
            missing.append("preload directive")
        if not info.get("has_include_subdomains"):
            missing.append("includeSubDomains")
        max_age = info.get("max_age")
        if max_age is not None and max_age < MIN_MAX_AGE:
            missing.append(f"max-age too short ({max_age}, need >= {MIN_MAX_AGE})")

        detail = f"Missing: {', '.join(missing)}" if missing else "Preload list submission required"

        return [
            Verdict(
                severity="low",
                confidence=confidence,
                discriminator="not-preloaded",
                title=f"HSTS header present but domain not preloaded: {ctx.host}",
                description=(
                    "HSTS is configured but the domain is not on the browser preload list "
                    f"— first visit is still vulnerable to SSL stripping. {detail}"
                ),
                evidence=f"HSTS: {hsts_header[:200]} | Preload status: {preload_status}",
                reasoning=(
                    f"the directives are read verbatim from the recorded header; {api_note}"
                ),
                signals={**info, "missing": missing},
                references=["RFC 6797", "hstspreload.org"],
                evidence_ids=ids,
            )
        ]

    # ── The one parser, called by both halves ────────────────────────

    def _reading(
        self,
        exchanges: list[Exchange],
        *,
        target_url: str | None,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Read one service's HSTS posture out of its recorded exchanges.

        `info` is `hsts_preload_info` verbatim — same keys, same shape, so the
        output this check produces is unchanged. `hsts_header` and
        `api_answered` are the extras the grader needs and the output does not.
        """
        hsts_header = ""
        own_get = _own_get(exchanges, target_url)
        if own_get is not None and own_get.error is None:
            hsts_header = extract_headers_dict(own_get.response_headers or {}).get(
                "strict-transport-security", ""
            )
        if not hsts_header:
            # Only as a fallback: the probe consults the upstream output first,
            # but a recorded observation of *this* service beats it.
            hsts_header = _hsts_from_context(context)

        if not hsts_header:
            return {"hsts_header": "", "info": {"checked": False}, "api_answered": False}

        api = _api_exchange(exchanges)
        api_answered = False
        info: dict[str, Any] = {"checked": True}

        if api is None:
            # The client raised before anything was recorded, or the API was
            # never called. Either way nothing answered.
            preload_status = "api_error"
        elif api.error is not None or api.response_status != 200:
            preload_status = "api_unreachable"
        else:
            data = safe_json(api.response_body or "")
            if isinstance(data, dict):
                preload_status = data.get("status", "unknown")
                info["api_status"] = preload_status
                api_answered = True
            else:
                preload_status = "api_error"

        info.update(
            {
                "preloaded": preload_status == "preloaded",
                "has_preload_directive": "preload" in hsts_header.lower(),
                "has_include_subdomains": "includesubdomains" in hsts_header.lower(),
                "max_age": self._parse_max_age(hsts_header),
                "status": preload_status,
            }
        )
        return {"hsts_header": hsts_header, "info": info, "api_answered": api_answered}

    def _get_hsts_header(self, service: Service, context: dict[str, Any]) -> str:
        """Try to get HSTS header from header_analysis context output."""
        return _hsts_from_context(context)

    def _parse_max_age(self, hsts_header: str) -> int | None:
        """Extract max-age value from HSTS header."""
        for part in hsts_header.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age"):
                try:
                    return int(part.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    pass
        return None


def _hsts_from_context(context: dict[str, Any]) -> str:
    """The HSTS header as an upstream check reported it, if it did."""
    header_info = context.get("header_info", {})
    if isinstance(header_info, dict):
        headers = header_info.get("headers", {})
        if isinstance(headers, dict):
            return headers.get("strict-transport-security", "")
    return ""


def _own_get(exchanges: list[Exchange], target_url: str | None) -> Exchange | None:
    """This service's own recorded GET, if the probe had to make one.

    Matched on the URL rather than taken positionally, so a candidate that fell
    back to the corpus cannot pick up a *different* service's response on the
    same host — two ports on one hostname are two subjects here.
    """
    if not target_url:
        return None
    for exchange in exchanges:
        if exchange.request_url == target_url:
            return exchange
    return None


def _api_exchange(exchanges: list[Exchange]) -> Exchange | None:
    """The hstspreload.org answer, if one was recorded."""
    for exchange in exchanges:
        if API_HOST in (exchange.request_url or ""):
            return exchange
    return None
