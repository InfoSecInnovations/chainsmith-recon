"""
app/checks/web/sitemap.py - Sitemap Parsing Check

Fetches sitemaps discovered by RobotsTxtCheck (or tries default /sitemap.xml).
Parses XML sitemap format, extracts URLs, identifies interesting paths that
the fixed wordlist in PathProbe would miss.

Handles:
- Standard XML sitemaps (urlset format)
- Sitemap index files (sitemapindex)
- Caps at 500 URLs to avoid overwhelming downstream checks

**Probe/grade.** `check_service()` fetches the sitemaps,
follows a sitemap index one level, records every body it read URLs out of, and
judges nothing; `grade()` re-reads those bodies and places the severity.

The traversal stays in the probe: deciding that a body is an index and that its
children are worth fetching is navigation, not judgement. What the probe hands
over is exactly the bodies it extracted paths from — the index itself
contributes no paths, so it is not evidence for anything. `sitemap_paths` is an
output, so both halves call `_reading()` over those same exchanges (§6.2's two
parses, with one parser).

#### One thing the split forced, and it is a fix

Capture truncates a recorded body at 256 KB, and a real sitemap is often larger
than that. `ET.fromstring` on a body cut mid-element raises, and the original
caught `ParseError` and returned *no* paths — so once the grader read from the
record rather than from the live response, any large sitemap would have yielded
nothing at all. `_extract_paths()` now falls back to scanning for `<loc>`
elements with a regex when the XML will not parse, which recovers the URLs a
truncated (or simply malformed) sitemap does contain. `grade()` reads
`Exchange.truncated` and says so: where a body was cut, the URL count is a floor
rather than a total, and the verdict's confidence reflects that.
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

MAX_URLS = 500
MAX_SITEMAPS = 10  # max sub-sitemaps to follow from index

SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"

#: Fallback for a body `ET` will not parse — a sitemap truncated by the capture
#: body cap, or one that is simply malformed. Deliberately permissive: the
#: question is only "which URLs does this document list".
LOC_RE = re.compile(r"<loc>\s*([^<\s][^<]*?)\s*</loc>", re.I)

# Paths that suggest sensitive or internal content
SENSITIVE_PATH_PATTERNS = [
    re.compile(r"/(admin|internal|staging|debug|test|dev)/", re.I),
    re.compile(r"/(api|graphql|v\d+)/", re.I),
    re.compile(r"/\.(env|git|svn|config)", re.I),
    re.compile(r"/(dashboard|console|manager|portal)/", re.I),
    re.compile(r"/(backup|dump|export|import)/", re.I),
    re.compile(r"/(model|train|inference|predict)/", re.I),
]

#: The markers that make the sensitive-path verdict `medium` rather than `low`.
#: Unchanged from the original; named here because `grade()` also reports it.
STRONG_SENSITIVE_RE = re.compile(r"/(staging|debug|internal|backup)/", re.I)

API_VERSION_RE = re.compile(r"/v(\d+)/", re.I)
API_PATH_RE = re.compile(r"/(api|v\d+)/", re.I)


class SitemapCheck(ServiceIteratingCheck):
    """Parse sitemaps to discover additional paths and surface structure."""

    name = "web_sitemap"
    description = "Parse sitemap.xml to discover paths missed by wordlist probing"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["sitemap_paths"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Sitemaps reveal full URL structure including internal tools, API versioning, and AI/ML endpoints"
    references = ["OWASP WSTG-INFO-03"]
    techniques = ["passive reconnaissance", "path discovery"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, follow, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # Get sitemap URLs from robots_txt output
        robots_key = f"robots_{service.port}"
        robots_data = context.get(robots_key, {})
        sitemaps = list(robots_data.get("sitemaps", []))

        # Always try default location if robots didn't find any
        if not sitemaps:
            sitemaps = [service.with_path("/sitemap.xml")]
        else:
            # Normalize: robots may give relative or absolute URLs
            normalized = []
            for s in sitemaps:
                if s.startswith("http://") or s.startswith("https://"):
                    normalized.append(s)
                else:
                    path = s if s.startswith("/") else f"/{s}"
                    normalized.append(service.with_path(path))
            sitemaps = normalized

        # One candidate per service: the three judgements all read the same set
        # of sitemap bodies, so the candidate stays undiscriminated and
        # `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)
        # Only for loop control — where to stop fetching. The output below is
        # read back off the recorded exchanges, so the two cannot drift.
        found = 0

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:

                def keep(resp) -> int:
                    """Record one body the paths came out of, and count them."""
                    exchange = exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host
                    )
                    candidate.attach(exchange)
                    return len(_extract_paths(exchange.response_body or ""))

                for sitemap_url in sitemaps[:MAX_SITEMAPS]:
                    await self._rate_limit()
                    resp = await client.get(sitemap_url)

                    if resp.error or resp.status_code != 200:
                        continue

                    body = resp.body or ""
                    if not body.strip():
                        continue

                    # Check if this is a sitemap index
                    sub_sitemaps = _parse_sitemap_index(body)
                    if sub_sitemaps:
                        # Follow sub-sitemaps (limited). The index lists no page
                        # URLs of its own, so it is not evidence for anything
                        # and is not handed to the grader.
                        for sub_url in sub_sitemaps[:MAX_SITEMAPS]:
                            if not sub_url.startswith("http"):
                                sub_url = service.with_path(
                                    sub_url if sub_url.startswith("/") else f"/{sub_url}"
                                )
                            await self._rate_limit()
                            sub_resp = await client.get(sub_url)
                            if sub_resp.error or sub_resp.status_code != 200:
                                continue
                            found += keep(sub_resp)
                            if found >= MAX_URLS:
                                break
                    else:
                        found += keep(resp)

                    if found >= MAX_URLS:
                        break

        except Exception as e:
            result.errors.append(f"Sitemap fetch error: {e}")
            return result

        reading = _reading(candidate.exchanges)
        if not reading["all_paths"]:
            return result

        result.candidates.append(candidate)

        # Output for downstream checks
        result.outputs["sitemap_paths"] = {
            "all_paths": reading["all_paths"],
            "sensitive_paths": reading["sensitive_paths"],
            "api_paths": reading["api_paths"],
        }
        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded sitemaps. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on what one service's sitemaps disclosed."""
        exchanges = list(evidence)
        reading = _reading(exchanges)
        all_paths = reading["all_paths"]
        if not all_paths:
            return []

        sensitive_paths = reading["sensitive_paths"]
        api_paths = reading["api_paths"]
        api_versions = reading["api_versions"]
        ids = [e.id for e in exchanges]

        # A body the capture cap cut, or a 500-URL ceiling reached, both make the
        # count a floor rather than a total.
        truncated = any(e.truncated for e in exchanges)
        capped = len(all_paths) >= MAX_URLS

        verdicts: list[Verdict] = [
            Verdict(
                severity="info",
                # URLs read out of XML the target published — as categorical as
                # evidence gets. It is the *count* that softens when the record
                # was cut short or the 500-URL ceiling was hit.
                confidence=0.9 if (truncated or capped) else 0.99,
                discriminator="sitemap-discovered",
                title=(
                    f"Sitemap contains {len(all_paths)} URLs ({len(set(all_paths))} unique paths)"
                ),
                description=(f"Sitemap parsing discovered {len(all_paths)} URLs from {ctx.host}"),
                evidence=f"Paths sample: {', '.join(all_paths[:10])}",
                reasoning=(
                    "URL count is a floor, not a total: "
                    + ", ".join(
                        filter(
                            None,
                            [
                                "a recorded body was truncated at the capture cap"
                                if truncated
                                else "",
                                f"extraction stopped at the {MAX_URLS}-URL ceiling"
                                if capped
                                else "",
                            ],
                        )
                    )
                    if (truncated or capped)
                    else f"{len(all_paths)} URL(s) read from {len(exchanges)} sitemap body(ies)"
                ),
                signals={
                    "urls": len(all_paths),
                    "sitemaps": len(exchanges),
                    "truncated": truncated,
                    "capped": capped,
                },
                evidence_ids=ids,
            )
        ]

        # Sensitive paths observation
        if sensitive_paths:
            strong = [p for p in sensitive_paths if STRONG_SENSITIVE_RE.search(p)]
            verdicts.append(
                Verdict(
                    severity="medium" if strong else "low",
                    # `/staging/`, `/internal/`, `/debug/` and `/backup/` name a
                    # non-production surface. Without one of those, the match is
                    # usually the `/(api|graphql|v\\d+)/` pattern, and a public
                    # API under `/api/` is not a sensitive resource at all.
                    confidence=0.9 if strong else 0.5,
                    discriminator="sensitive-paths",
                    title=f"Sitemap reveals sensitive paths ({len(sensitive_paths)})",
                    description=(
                        "Sitemap contains paths suggesting internal or sensitive resources"
                    ),
                    evidence=f"Sensitive paths: {', '.join(sensitive_paths[:10])}",
                    reasoning=(
                        f"{len(strong)} path(s) name a non-production surface "
                        "(staging/debug/internal/backup)"
                        if strong
                        else "matches are generic path patterns such as `/api/` or `/v1/`, "
                        "which an ordinary public API also satisfies"
                    ),
                    signals={
                        "sensitive_paths": sensitive_paths[:50],
                        "strong_paths": strong[:50],
                    },
                    raw_data={"sensitive_paths": sensitive_paths[:50]},
                    evidence_ids=ids,
                )
            )

        # API versioning observation
        if len(api_versions) > 1:
            verdicts.append(
                Verdict(
                    severity="low",
                    # Two `/vN/` prefixes in the published sitemap is a direct
                    # reading. That they are *API* versions, rather than content
                    # or asset versions, is the inference.
                    confidence=0.85,
                    discriminator="api-versioning",
                    title=(f"Sitemap reveals API versioning: {', '.join(sorted(api_versions))}"),
                    description=(
                        "Multiple API versions discovered, older versions may lack "
                        "security controls"
                    ),
                    evidence=(
                        f"API versions: {', '.join(sorted(api_versions))}; sample paths: "
                        f"{', '.join(api_paths[:5])}"
                    ),
                    reasoning=(
                        f"{len(api_versions)} distinct /vN/ prefixes in the published "
                        "sitemap; read as API versions, which a content or asset version "
                        "path would also match"
                    ),
                    signals={
                        "api_versions": sorted(api_versions),
                        "api_paths": api_paths[:50],
                    },
                    evidence_ids=ids,
                )
            )

        return verdicts


# ── The one parser, called by both halves ────────────────────────────


def _reading(exchanges: list[Exchange]) -> dict[str, Any]:
    """Read one service's sitemap disclosure out of its recorded bodies.

    `all_paths`, `sensitive_paths` and `api_paths` are `sitemap_paths` verbatim,
    so the output this check produces is unchanged. `api_versions` is the extra
    the grader needs and the output does not.
    """
    all_paths: list[str] = []
    for exchange in exchanges:
        all_paths.extend(_extract_paths(exchange.response_body or ""))
        if len(all_paths) >= MAX_URLS:
            all_paths = all_paths[:MAX_URLS]
            break

    # Deduplicate
    all_paths = list(dict.fromkeys(all_paths))

    # Classify paths
    sensitive_paths: list[str] = []
    api_paths: list[str] = []
    for path in all_paths:
        for pattern in SENSITIVE_PATH_PATTERNS:
            if pattern.search(path):
                sensitive_paths.append(path)
                break
        if API_PATH_RE.search(path):
            api_paths.append(path)

    api_versions = {f"v{m.group(1)}" for p in api_paths if (m := API_VERSION_RE.search(p))}

    return {
        "all_paths": all_paths,
        "sensitive_paths": sensitive_paths,
        "api_paths": api_paths,
        "api_versions": api_versions,
    }


def _locs(xml_body: str) -> list[str]:
    """Every `<loc>` value in one sitemap document.

    XML first; a regex scan when `ET` refuses the body. The fallback is what
    makes a sitemap larger than the 256 KB capture cap still yield the URLs it
    lists, instead of none — see the module docstring.
    """
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        logger.debug("Sitemap XML would not parse; reading <loc> elements directly")
        return [text.strip() for text in LOC_RE.findall(xml_body) if text.strip()]

    locs = root.findall(f".//{{{SITEMAP_NS}}}loc")
    if not locs:
        # Try without namespace
        locs = root.findall(".//loc")
    return [loc.text.strip() for loc in locs if loc.text]


def _extract_paths(xml_body: str) -> list[str]:
    """Parse sitemap XML and extract paths from <loc> elements."""
    paths = []
    for text in _locs(xml_body):
        parsed = urlparse(text)
        paths.append(parsed.path or "/")
    return paths


def _parse_sitemap_index(xml_body: str) -> list[str]:
    """Check if XML is a sitemap index and extract sub-sitemap URLs."""
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return []

    # Sitemap index has <sitemapindex> root with <sitemap><loc> children
    if "sitemapindex" not in root.tag.lower():
        return []
    return _locs(xml_body)
