"""
app/checks/web/error_page.py - Error Page Fingerprinting

Requests paths designed to trigger errors and analyzes responses
against known framework signatures to identify the underlying
technology stack and detect debug mode exposure.

Probes:
- 404: random nonexistent path
- 405: POST to a GET-only path
- 500: malformed JSON to API endpoints

**Probe/grade.** `check_service()` fires the three kinds of
error probe, records each, and judges nothing; `grade()` re-reads the recorded
bodies, matches them against the signature table and places the severity.
`error_page_info` is an output, so both halves call `_reading()` over the same
exchanges (§6.2's two parses, with one parser).

`grade()` tells the three probes apart by what was recorded rather than by
position: the 404 is the GET of the random `/chainsmith-probe-…` path, the 405
is the POST to the service root, and the 500s are the remaining POSTs. It has to
know, because the stack-trace observation fires only on the 404 — the 500
bodies set `debug_mode` and say nothing of their own, which is the original's
behaviour and is preserved.

#### Confidence lives in the signature table

The twenty-four signatures are not equally good, and averaging them would waste
the whole point. `Whitelabel Error Page` and `<center>nginx/1.2.3</center>` are
strings only one product emits. `class="traceback"` is a CSS class name any
template can use, `Ignition\\s` is one capitalised word followed by whitespace,
and `laravel.*exception` is two loose substrings on one line. So each row now
carries its own confidence, reviewable beside the pattern that earned it, and
the verdict reports it. No severity changed.

`custom-errors` — "framework not identified" — carries 0.7, because it is an
absence claim bounded by this table: a target running something the table does
not list produces it just as readily as one with genuinely custom error pages.
"""

import logging
import re
import uuid
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

#: Prefix of the random path the 404 probe requests. `grade()` recognises the
#: 404 exchange by it, because only that judgement is scoped to the 404.
PROBE_PATH_PREFIX = "/chainsmith-probe-"

# Framework signatures: (pattern, framework_name, is_debug_mode, severity, confidence)
#
# `confidence` is how much the *pattern* establishes the framework, judged from
# the pattern itself: a product's verbatim error text or a namespaced class name
# is near-certain, a generic CSS class or a bare capitalised word is not.
FRAMEWORK_SIGNATURES = [
    # Django
    (
        re.compile(r"You're seeing this error because you have\s+DEBUG\s*=\s*True", re.I),
        "Django",
        True,
        "medium",
        0.97,  # verbatim sentence from Django's own debug page
    ),
    (re.compile(r"Django Version:", re.I), "Django", True, "medium", 0.95),
    (
        re.compile(r"Using the URLconf defined in\s+\S+\.urls", re.I),
        "Django",
        True,
        "medium",
        0.95,
    ),
    # Flask / Werkzeug
    (re.compile(r"Werkzeug\s+Debugger", re.I), "Werkzeug/Flask", True, "high", 0.97),
    (re.compile(r"<title>.*Werkzeug.*</title>", re.I), "Werkzeug/Flask", True, "high", 0.9),
    (
        re.compile(r"The debugger caught an exception", re.I),
        "Werkzeug/Flask",
        True,
        "high",
        0.9,  # Werkzeug's phrasing, but a phrase another tool could reuse
    ),
    (
        re.compile(r'class="traceback"', re.I),
        "Flask",
        False,
        "low",
        0.5,  # a CSS class name; plenty of templates define one
    ),
    # Spring Boot
    (re.compile(r"Whitelabel Error Page", re.I), "Spring Boot", False, "low", 0.97),
    (
        re.compile(r"This application has no explicit mapping for /error", re.I),
        "Spring Boot",
        False,
        "low",
        0.97,
    ),
    # Express.js
    (
        re.compile(r"Cannot (GET|POST|PUT|DELETE|PATCH) /\S+", re.I),
        "Express.js",
        False,
        "low",
        0.8,  # Express's default 404 text, and a phrase others reimplement
    ),
    (
        re.compile(r"ReferenceError:.*at\s+\S+\.js:\d+", re.I),
        "Express.js/Node.js",
        True,
        "medium",
        0.85,  # a Node stack trace; Node for certain, Express by assumption
    ),
    # ASP.NET
    (re.compile(r"Server Error in '/' Application", re.I), "ASP.NET", False, "low", 0.95),
    (re.compile(r"ASP\.NET.*Version Information", re.I), "ASP.NET", True, "medium", 0.95),
    (
        re.compile(r"<title>.*Runtime Error.*</title>", re.I),
        "ASP.NET",
        False,
        "low",
        0.6,  # a generic page title
    ),
    # Laravel
    (
        re.compile(r"Ignition\s", re.I),
        "Laravel",
        True,
        "medium",
        0.55,  # one capitalised word plus whitespace — matches ordinary prose
    ),
    (
        re.compile(r"laravel.*exception", re.I),
        "Laravel",
        True,
        "medium",
        0.6,  # two loose substrings on one line
    ),
    (
        re.compile(r"Symfony\\Component\\HttpKernel\\Exception", re.I),
        "Laravel/Symfony",
        True,
        "medium",
        0.95,  # a fully namespaced class name
    ),
    # FastAPI
    (
        re.compile(r'"detail"\s*:\s*"(Not Found|Method Not Allowed)"', re.I),
        "FastAPI",
        False,
        "info",
        0.75,  # FastAPI's default body, shared with Starlette and imitators
    ),
    # Ruby on Rails
    (
        re.compile(r"Action\s*Controller::RoutingError", re.I),
        "Ruby on Rails",
        True,
        "medium",
        0.95,
    ),
    (re.compile(r"Rails\.root:", re.I), "Ruby on Rails", True, "medium", 0.95),
    # Tomcat
    (re.compile(r"Apache Tomcat/\d+", re.I), "Apache Tomcat", False, "low", 0.95),
    # nginx
    (re.compile(r"<center>nginx/[\d.]+</center>", re.I), "nginx", False, "info", 0.97),
    # Apache
    (re.compile(r"Apache/[\d.]+ .* Server at", re.I), "Apache HTTPD", False, "info", 0.97),
]

# Patterns indicating a stack trace in the response
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at\s+\S+\.(java|scala|kt):\d+", re.I),
    re.compile(r"File\s+\".*\.py\",\s+line\s+\d+", re.I),
    re.compile(r"at\s+\S+\s+\(\S+\.js:\d+:\d+\)", re.I),
    re.compile(r"at\s+\S+\.cs:\s*line\s+\d+", re.I),
]


class ErrorPageCheck(ServiceIteratingCheck):
    """Fingerprint web frameworks from error page responses."""

    name = "web_error_page"
    description = "Trigger error responses and fingerprint framework from error pages"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["error_page_info"]
    service_types = ["http", "html", "api"]

    reason = "Error pages reveal framework identity and debug mode, enabling targeted attacks"
    references = ["OWASP WSTG-INFO-08", "CWE-209"]
    techniques = ["error page analysis", "technology fingerprinting"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Trigger, record, publish the output. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate per service: the framework matches, the stack trace and
        # the "nothing identified" fallback are all judgements over the same set
        # of error responses, so the candidate stays undiscriminated and
        # `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:

                def keep(resp, method: str, **fields) -> None:
                    """Hand over one error response, if there was a body to read."""
                    if resp.error or not resp.body:
                        return
                    candidate.attach(
                        exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=service.host,
                            method=method,
                            **fields,
                        )
                    )

                # 1. Trigger 404 with random path
                random_path = f"{PROBE_PATH_PREFIX}{uuid.uuid4().hex[:8]}"
                await self._rate_limit()
                resp_404 = await client.get(service.with_path(random_path))
                keep(resp_404, "GET")

                # 2. Trigger 405 with POST to root
                await self._rate_limit()
                resp_405 = await client.post(service.url)
                keep(resp_405, "POST")

                # 3. Trigger 500 with malformed JSON to common API paths
                api_paths = self._get_api_paths(context)
                for api_path in api_paths[:3]:
                    await self._rate_limit()
                    resp_500 = await client.post(
                        service.with_path(api_path),
                        headers={"Content-Type": "application/json"},
                        data="{invalid json{{{",
                    )
                    keep(
                        resp_500,
                        "POST",
                        request_headers={"Content-Type": "application/json"},
                        request_body="{invalid json{{{",
                    )

        except Exception as e:
            result.errors.append(f"Error page check: {e}")

        result.candidates.append(candidate)
        reading = _reading(candidate.exchanges, root_url=service.url)
        result.outputs["error_page_info"] = {
            "frameworks": reading["frameworks"],
            "debug_mode": reading["debug_mode"],
        }
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded error pages. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on what one service's error pages revealed."""
        exchanges = list(evidence)
        root_url = (ctx.target.url if ctx.target else ctx.target_url) or ""
        reading = _reading(exchanges, root_url=root_url)

        verdicts: list[Verdict] = []
        detected: set[str] = set()

        for exchange in exchanges:
            body = exchange.response_body or ""
            status = exchange.response_status

            for pattern, framework, is_debug, severity, confidence in FRAMEWORK_SIGNATURES:
                if framework in detected:
                    continue  # Already detected this framework
                match = pattern.search(body)
                if not match:
                    continue
                detected.add(framework)

                if is_debug:
                    title = f"Debug mode enabled: {framework} at {ctx.host}"
                    description = (
                        f"{framework} debug/development mode detected via error page — "
                        "may expose source code, environment variables, or interactive "
                        "debugger"
                    )
                    # Werkzeug debugger is especially dangerous (RCE)
                    if "werkzeug" in framework.lower():
                        severity = "high"
                        description += (
                            ". Werkzeug interactive debugger may allow remote code execution"
                        )
                else:
                    title = f"Framework identified from error page: {framework}"
                    description = f"{framework} identified from error response signatures"

                verdicts.append(
                    Verdict(
                        severity=severity,
                        # Authored per signature in FRAMEWORK_SIGNATURES, beside
                        # the pattern it describes — see the module docstring.
                        confidence=confidence,
                        discriminator=(
                            "framework-" + framework.lower().replace("/", "-").replace(" ", "-")
                        ),
                        title=title,
                        description=description,
                        evidence=f"HTTP {status} response matched: {match.group(0)[:150]}",
                        reasoning=(
                            f"the HTTP {status} body matched the {framework} signature "
                            f"`{pattern.pattern}`"
                        ),
                        signals={
                            "framework": framework,
                            "debug_mode": is_debug,
                            "pattern": pattern.pattern,
                            "status": status,
                            "matched": match.group(0)[:200],
                        },
                        references=["CWE-209"] if is_debug else [],
                        evidence_ids=[exchange.id],
                    )
                )

            # Only the 404 probe carries a stack-trace observation of its own;
            # the 500 probes feed `debug_mode` and say nothing, as before.
            if _is_404_probe(exchange) and _has_stack_trace(body):
                verdicts.append(
                    Verdict(
                        severity="low",
                        # The patterns are language-specific trace lines
                        # ("Traceback (most recent call last)", a .py line
                        # reference), not generic words. Short of certain
                        # because a page can quote a trace without being one.
                        confidence=0.9,
                        discriminator="stack-trace-404",
                        title=f"Stack trace in 404 response: {ctx.host}",
                        description=(
                            "Error response contains a stack trace, leaking internal code structure"
                        ),
                        evidence=(
                            f"GET {_path_of(exchange)} -> HTTP {status} | Stack trace "
                            "detected in response body"
                        ),
                        reasoning=("the 404 body matched a language-specific stack-trace pattern"),
                        signals={"status": status},
                        references=["CWE-209"],
                        evidence_ids=[exchange.id],
                    )
                )

        # If no framework was identified but we got responses
        if not reading["frameworks"] and not reading["debug_mode"]:
            verdicts.append(
                Verdict(
                    severity="info",
                    # An absence claim bounded by the signature table: a target
                    # running something not in it produces this just as readily
                    # as one with genuinely custom error pages.
                    confidence=0.7,
                    discriminator="custom-errors",
                    title=f"Custom error pages (framework not identified): {ctx.host}",
                    description="Error pages do not reveal framework identity",
                    evidence="No known framework signatures detected in error responses",
                    reasoning=(
                        f"none of the {len(FRAMEWORK_SIGNATURES)} signatures matched, which "
                        "also happens for any framework the table does not list"
                    ),
                    signals={"signatures_tried": len(FRAMEWORK_SIGNATURES)},
                    evidence_ids=evidence.ids(),
                )
            )

        return verdicts

    def _get_api_paths(self, context: dict[str, Any]) -> list[str]:
        """Get API paths from context for 500 error triggering."""
        # Try openapi discovered endpoints
        api_endpoints = context.get("api_endpoints", [])
        if api_endpoints:
            return [ep.get("path", "") for ep in api_endpoints if ep.get("path")][:5]

        # Fallback to common API paths
        return ["/api", "/api/v1", "/graphql"]


# ── The one parser, called by both halves ────────────────────────────


def _path_of(exchange: Exchange) -> str:
    """The path this probe asked for, read back off the record."""
    from urllib.parse import urlparse

    return urlparse(exchange.request_url or "").path or "/"


def _is_404_probe(exchange: Exchange) -> bool:
    """True for the GET of the random path, which is the 404 probe."""
    return (exchange.request_method or "GET").upper() == "GET" and _path_of(exchange).startswith(
        PROBE_PATH_PREFIX
    )


def _is_405_probe(exchange: Exchange, root_url: str) -> bool:
    """True for the POST to the service root, which is the 405 probe."""
    return (exchange.request_method or "").upper() == "POST" and (
        exchange.request_url or ""
    ) == root_url


def _has_stack_trace(body: str) -> bool:
    """Check if response body contains a stack trace."""
    return any(p.search(body) for p in STACK_TRACE_PATTERNS)


def _reading(exchanges: list[Exchange], *, root_url: str) -> dict[str, Any]:
    """Read one service's error-page disclosure out of its recorded responses.

    `frameworks` and `debug_mode` are `error_page_info` verbatim, so the output
    this check produces is unchanged — including that `debug_mode` is set by the
    404 and the 500 probes but never by the 405, which is what the original did.
    """
    frameworks: dict[str, dict[str, Any]] = {}
    debug_mode = False

    for exchange in exchanges:
        body = exchange.response_body or ""
        for pattern, framework, is_debug, _severity, _confidence in FRAMEWORK_SIGNATURES:
            if framework in frameworks:
                continue  # Already detected this framework
            match = pattern.search(body)
            if match:
                frameworks[framework] = {
                    "debug_mode": is_debug,
                    "evidence": match.group(0)[:200],
                    "status_code": exchange.response_status,
                }

        if not _is_405_probe(exchange, root_url) and _has_stack_trace(body):
            debug_mode = True

    return {"frameworks": frameworks, "debug_mode": debug_mode}
