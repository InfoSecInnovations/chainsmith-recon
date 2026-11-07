"""
app/checks/web/sri_check.py - Subresource Integrity Check

Parses HTML responses for <script> and <link> tags that load external
resources, and checks whether they have integrity= attributes (SRI
hashes). External resources without SRI are vulnerable to CDN
compromise or supply-chain attacks.

**Probe/grade.** `check_service()` fetches the candidate
HTML pages, keeps the first two distinct ones, and judges nothing; `grade()`
re-reads those bodies, categorises the external resources and places the
severity. `sri_info` is an output, so both halves call `_reading()` over the
same exchanges (§6.2's two parses, with one parser).

The probe still filters — which pages to keep and when to stop is navigation:
non-HTML responses are skipped and identical bodies are de-duplicated, so `/`
and `/index.html` serving the same page count once. It decides that by reading
the exchange it just recorded.

**Two confidences worth reading.** `_is_external()` treats every
protocol-relative URL (`//cdn…`) as external *without checking the host*, which
inflates the count whenever a site references itself that way — so a verdict
resting on any such resource carries 0.65 rather than 0.85. And the two
"nothing to report" verdicts are absence claims over **at most two static HTML
pages**: this check cannot see a script a bundler injects at runtime, which is
how most current applications load their dependencies. `no-external` carries 0.6
for that reason and `all-sri` 0.7 — the same observations as before, no longer
asserted as though the page were the whole application.
"""

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

logger = logging.getLogger(__name__)

# Match <script src="..."> tags
SCRIPT_TAG_PATTERN = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.I,
)

# Match <link rel="stylesheet" href="..."> tags
LINK_TAG_PATTERN = re.compile(
    r"<link\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.I,
)

# Match integrity attribute in a tag
INTEGRITY_ATTR_PATTERN = re.compile(
    r"\bintegrity\s*=\s*[\"']([^\"']+)[\"']",
    re.I,
)

# Match crossorigin attribute
CROSSORIGIN_PATTERN = re.compile(
    r"\bcrossorigin\b",
    re.I,
)

# Paths to check for HTML content
HTML_PATHS = ["/", "/index.html", "/login", "/app"]

MAX_PAGES = 2


class SRICheck(ServiceIteratingCheck):
    """Check external scripts and stylesheets for Subresource Integrity."""

    name = "web_sri"  # renamed from sri_check
    description = "Verify external resources use Subresource Integrity (SRI) hashes"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["sri_info"]
    service_types = ["http", "html"]

    reason = (
        "External scripts without SRI are vulnerable to CDN compromise and supply-chain attacks"
    )
    references = ["W3C Subresource Integrity", "CWE-353"]
    techniques = ["SRI verification", "supply chain analysis"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, keep the HTML pages, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate per service: every judgement here reads the same pages,
        # so the candidate stays undiscriminated and `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                pages_checked = 0
                seen_bodies = set()
                for path in HTML_PATHS:
                    if pages_checked >= MAX_PAGES:
                        break

                    await self._rate_limit()
                    resp = await client.get(service.with_path(path))
                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    # Only analyze HTML responses
                    content_type = resp.headers.get("content-type", "").lower()
                    if "html" not in content_type and not resp.body.strip().startswith("<"):
                        continue

                    # Deduplicate identical pages (e.g., / and /index.html serve same content)
                    body_hash = hash(resp.body)
                    if body_hash in seen_bodies:
                        continue
                    seen_bodies.add(body_hash)

                    pages_checked += 1
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

        except Exception as e:
            result.errors.append(f"SRI check error: {e}")

        result.candidates.append(candidate)
        reading = _reading(candidate.exchanges, service.scheme, service.host)
        result.outputs["sri_info"] = {
            "total_external": reading["total_external"],
            "without_sri": len(reading["without_sri"]),
            "with_sri": len(reading["with_sri"]),
            "resources_without_sri": reading["without_sri"][:20],
        }
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded HTML. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one service's subresource integrity posture."""
        exchanges = list(evidence)
        scheme = ctx.target.scheme if ctx.target else "http"
        reading = _reading(exchanges, scheme, ctx.host)

        without_sri = reading["without_sri"]
        total_external = reading["total_external"]
        pages = len(exchanges)
        ids = [e.id for e in exchanges]

        if without_sri:
            # Group by host to reduce noise
            hosts_without_sri = {urlparse(r["url"]).netloc for r in without_sri}
            count = len(without_sri)
            severity = "medium" if count >= 3 else "low"
            protocol_relative = [r["url"] for r in without_sri if r["url"].startswith("//")]

            verdicts = [
                Verdict(
                    severity=severity,
                    # Tags are found by regex over HTML, and `_is_external`
                    # assumes every protocol-relative URL is third-party without
                    # resolving its host — so a site that references itself as
                    # `//host/app.js` inflates this count.
                    confidence=0.65 if protocol_relative else 0.85,
                    discriminator="missing-sri",
                    title=f"{count} external resource(s) without SRI: {ctx.host}",
                    description=(
                        f"{count} external scripts/stylesheets loaded without integrity "
                        f"verification. Sources: "
                        f"{', '.join(sorted(hosts_without_sri)[:5])}"
                    ),
                    evidence=" | ".join(f"{r['type']}: {r['url']}" for r in without_sri[:10]),
                    reasoning=(
                        f"{len(protocol_relative)} of {count} are protocol-relative URLs, "
                        "which this check assumes are external without resolving the host"
                        if protocol_relative
                        else f"{count} tag(s) on {pages} page(s) reference another origin "
                        "and carry no integrity attribute"
                    ),
                    signals={
                        "count": count,
                        "hosts": sorted(hosts_without_sri),
                        "protocol_relative": protocol_relative,
                        "pages": pages,
                    },
                    references=["CWE-353", "W3C SRI"],
                    evidence_ids=ids,
                )
            ]

            # Individual observations for the first few
            for resource in without_sri[:5]:
                relative = resource["url"].startswith("//")
                verdicts.append(
                    Verdict(
                        severity="low",
                        confidence=0.6 if relative else 0.85,
                        discriminator=f"no-sri-{_url_slug(resource['url'])}",
                        title=(f"External {resource['type']} without SRI: {resource['url'][:80]}"),
                        description=(
                            f"External {resource['type']} loaded from {resource['url']} "
                            "without an integrity attribute"
                        ),
                        evidence=(
                            f'<{resource["type"]} src="{resource["url"]}"> on '
                            f"{resource['page']} — no integrity= attribute"
                        ),
                        reasoning=(
                            "the URL is protocol-relative, so it is assumed external "
                            "without resolving its host"
                            if relative
                            else "the tag names another origin and carries no integrity attribute"
                        ),
                        signals={
                            "url": resource["url"],
                            "type": resource["type"],
                            "page": resource["page"],
                            "protocol_relative": relative,
                        },
                        references=["CWE-353"],
                        evidence_ids=ids,
                    )
                )
            return verdicts

        if total_external > 0:
            return [
                Verdict(
                    severity="info",
                    # "All of them" is only as complete as what was looked at:
                    # at most two static pages, and nothing a bundler adds at
                    # runtime.
                    confidence=0.7,
                    discriminator="all-sri",
                    title=f"All external resources use SRI: {ctx.host}",
                    description=(
                        f"All {total_external} external resource(s) have integrity attributes"
                    ),
                    evidence=f"{total_external} external resources with SRI hashes verified",
                    reasoning=(
                        f"all {total_external} external tag(s) on the {pages} page(s) read "
                        "carry an integrity attribute; scripts injected at runtime are not "
                        "visible to this check"
                    ),
                    signals={"total_external": total_external, "pages": pages},
                    evidence_ids=ids,
                )
            ]

        return [
            Verdict(
                severity="info",
                # The weakest claim in the check: most current applications load
                # their dependencies from JavaScript, so "no external resources"
                # usually means "none in the static HTML of two pages".
                confidence=0.6,
                discriminator="no-external",
                title=f"No external resources found: {ctx.host}",
                description=("No external scripts or stylesheets detected in HTML responses"),
                evidence=("No <script src> or <link href> tags referencing external origins"),
                reasoning=(
                    f"no external tags in the static HTML of {pages} page(s); a bundler "
                    "that injects its dependencies at runtime would not appear here"
                ),
                signals={"pages": pages},
                evidence_ids=ids,
            )
        ]


# ── The one parser, called by both halves ────────────────────────────


def _is_external(url: str, service_origin: str) -> bool:
    """Check if a URL points to an external origin."""
    if url.startswith("//"):
        return True  # Protocol-relative, likely external
    if url.startswith("http"):
        parsed = urlparse(url)
        resource_origin = f"{parsed.scheme}://{parsed.hostname}"
        return resource_origin.lower() != service_origin.lower()
    # Relative URLs are internal
    return False


def _analyze_html(
    html: str,
    service_origin: str,
    page_path: str,
    without_sri: list[dict[str, str]],
    with_sri: list[dict[str, str]],
) -> None:
    """Parse HTML and categorize external resources by SRI status."""
    # Check <script> tags
    for match in SCRIPT_TAG_PATTERN.finditer(html):
        src = match.group(1)
        if not _is_external(src, service_origin):
            continue

        tag_text = match.group(0)
        has_integrity = bool(INTEGRITY_ATTR_PATTERN.search(tag_text))

        entry = {"url": src, "type": "script", "page": page_path}
        if has_integrity:
            with_sri.append(entry)
        else:
            without_sri.append(entry)

    # Check <link> tags (stylesheets only)
    for match in LINK_TAG_PATTERN.finditer(html):
        href = match.group(1)
        tag_text = match.group(0)

        # Only consider stylesheet links
        if "rel=" not in tag_text.lower() or "stylesheet" not in tag_text.lower():
            continue

        if not _is_external(href, service_origin):
            continue

        has_integrity = bool(INTEGRITY_ATTR_PATTERN.search(tag_text))

        entry = {"url": href, "type": "stylesheet", "page": page_path}
        if has_integrity:
            with_sri.append(entry)
        else:
            without_sri.append(entry)


def _reading(exchanges: list[Exchange], scheme: str, host: str) -> dict[str, Any]:
    """Read one service's external resources out of the recorded HTML.

    `total_external`, `without_sri` and `with_sri` are what `sri_info` reports,
    so the output this check produces is unchanged. The page each resource was
    found on comes off the recorded URL rather than probe-side bookkeeping.
    """
    service_origin = f"{scheme}://{host}"
    without_sri: list[dict[str, str]] = []
    with_sri: list[dict[str, str]] = []

    for exchange in exchanges:
        page_path = urlparse(exchange.request_url or "").path or "/"
        # Skip anything that is not HTML, the same test the probe applies.
        body = exchange.response_body or ""
        content_type = extract_headers_dict(exchange.response_headers or {}).get("content-type", "")
        if "html" not in content_type and not body.strip().startswith("<"):
            continue
        _analyze_html(body, service_origin, page_path, without_sri, with_sri)

    return {
        "without_sri": without_sri,
        "with_sri": with_sri,
        "total_external": len(without_sri) + len(with_sri),
    }


def _url_slug(url: str) -> str:
    """Create a short slug from a URL for observation discriminators."""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    # Take just the host and first path segment
    path_part = parsed.path.split("/")[1] if "/" in parsed.path.lstrip("/") else ""
    slug = f"{host}-{path_part}".strip("-")
    # Sanitize
    slug = re.sub(r"[^a-zA-Z0-9\-.]", "-", slug)
    return slug[:40]
