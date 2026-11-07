"""
app/checks/web/directory_listing.py - Directory Listing Detection

Checks for enabled directory listing (autoindex) on discovered paths.
Detects Apache, nginx, IIS, and Python SimpleHTTPServer signatures.

**Probe/grade.** `check_service()` fetches each candidate
path, keeps the responses that look like a listing, and judges nothing;
`grade()` re-reads those bodies and places the severity.

The probe still filters — it hands over only the pages that matched a listing
signature, because the other paths answered 404 or returned an ordinary page and
a corpus of those is volume without evidence (the interceptor still stores them
when capture is on). It decides that by reading the exchange it just recorded,
so the filter and the verdict share one reading of the body (§6.2).

`_matched_patterns()` is what the split adds. Five of the six signatures are
autoindex page furniture — `Index of /`, `[To Parent Directory]` — and the
sixth, `SimpleHTTP`, is a bare case-insensitive substring that any page
*discussing* Python's http.server satisfies. A verdict resting only on that one
now says so, and the escalation to `high` on visible sensitive files says that
it rests on `href` substring matching, which `?format=.json` also satisfies.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig


class DirectoryListingCheck(ServiceIteratingCheck):
    """Detect enabled directory listing on HTTP services."""

    name = "web_directory_listing"
    description = "Check for enabled directory listing (autoindex) on discovered paths"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["directory_listing_observations"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Directory listing exposes the full filesystem structure including model files, training data, and configs"
    references = ["OWASP WSTG-CONF-04", "CWE-548"]
    techniques = ["directory listing detection", "information disclosure"]

    # Patterns that indicate directory listing is enabled
    LISTING_PATTERNS = [
        re.compile(r"Index of /", re.I),
        re.compile(r"Directory listing for /", re.I),
        re.compile(r"<title>\s*Directory listing", re.I),
        re.compile(r"\[To Parent Directory\]", re.I),  # IIS
        re.compile(r"<h1>Directory Listing</h1>", re.I),
        re.compile(r"SimpleHTTP", re.I),  # Python SimpleHTTPServer
    ]

    #: The one signature that is not page furniture. `SimpleHTTP` matches any
    #: body mentioning Python's http.server — a tutorial, a stack trace, a
    #: README rendered to HTML. Grading input only; it still triggers the check.
    WEAK_PATTERNS = frozenset({r"SimpleHTTP"})

    # Sensitive file extensions in listings
    SENSITIVE_EXTENSIONS = [
        ".py",
        ".env",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".conf",
        ".cfg",
        ".key",
        ".pem",
        ".sql",
        ".db",
        ".sqlite",
        ".pt",
        ".onnx",
        ".safetensors",
        ".pkl",
        ".h5",  # Model files
        ".bak",
        ".old",
        ".backup",
    ]

    # Paths to check for directory listing
    PROBE_PATHS = ["/", "/static/", "/assets/", "/uploads/", "/data/", "/models/", "/backup/"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record, keep the listings. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Combine probe paths with any paths from path_probe
        paths_to_check = list(self.PROBE_PATHS)
        accessible = self._get_accessible_paths(service, context)
        for p in accessible:
            if p.endswith("/") and p not in paths_to_check:
                paths_to_check.append(p)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in paths_to_check:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    exchange = exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=context.get("scan_id") or "",
                        host=service.host,
                    )
                    if not self._matched_patterns(exchange):
                        continue

                    # One candidate per listing: each path is its own subject
                    # with its own discriminator, so the probe names it here
                    # rather than leaving `grade()` to invent one.
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"listing-{path.replace('/', '-').strip('-') or 'root'}",
                        target=service,
                        target_url=url,
                        raw_data={"path": path},
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded listing. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one directory listing."""
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        body = exchange.response_body or ""
        path = self._path_of(exchange)
        matched = self._matched_patterns(exchange)
        if not matched:
            return []

        sensitive_files = self._find_sensitive_files(body)
        is_root = path == "/"

        # Page furniture from a real autoindex is near-categorical; a lone
        # `SimpleHTTP` hit is a substring in an HTML document.
        furniture = bool(matched - self.WEAK_PATTERNS)
        confidence = 0.95 if furniture else 0.6

        if is_root:
            severity = "high"
            title = f"Directory listing at root: {ctx.host}"
            why = "the listing is at the document root"
        elif sensitive_files:
            severity = "high"
            title = f"Directory listing with sensitive files: {ctx.host}{path}"
            why = (
                f"{len(sensitive_files)} href(s) carry a sensitive extension — matched as "
                "substrings, which a query string like `?format=.json` also satisfies"
            )
            # The escalation is the weaker half of this verdict, so it caps the
            # confidence even when the listing itself is unmistakable.
            confidence = min(confidence, 0.8)
        else:
            severity = "medium"
            title = f"Directory listing enabled: {ctx.host}{path}"
            why = "no sensitive extensions among the listed hrefs"

        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                title=title,
                description=f"Directory listing enabled at {path}"
                + (
                    f" — sensitive files visible: {', '.join(sensitive_files[:5])}"
                    if sensitive_files
                    else ""
                ),
                evidence=fmt_status_evidence(exchange.request_url or "", 200, body[:300]),
                reasoning=(
                    f"matched listing signature(s) {', '.join(sorted(matched))}; {why}"
                    if furniture
                    else f"matched only the `SimpleHTTP` substring, which any page "
                    f"mentioning Python's http.server satisfies; {why}"
                ),
                signals={
                    "path": path,
                    "patterns": sorted(matched),
                    "autoindex_furniture": furniture,
                    "sensitive_files": sensitive_files[:20],
                },
                raw_data={"path": path, "sensitive_files": sensitive_files[:20]},
                evidence_ids=[exchange.id],
            )
        ]

    # ── The one parser, called by both halves ────────────────────────

    def _matched_patterns(self, exchange: Exchange) -> set[str]:
        """Which listing signatures the recorded body matched.

        The probe reads this to decide whether the page is a listing at all —
        the original `_is_directory_listing()` — and the grader reads it again to
        decide how much the match is worth.
        """
        body = exchange.response_body or ""
        return {p.pattern for p in self.LISTING_PATTERNS if p.search(body)}

    @staticmethod
    def _path_of(exchange: Exchange) -> str:
        """The path this listing was found at, read back off the exchange."""
        from urllib.parse import urlparse

        return urlparse(exchange.request_url or "").path or "/"

    def _find_sensitive_files(self, body: str) -> list[str]:
        """Extract sensitive filenames from a directory listing."""
        sensitive = []
        # Look for href or filename patterns
        for ext in self.SENSITIVE_EXTENSIONS:
            matches = re.findall(rf'href="([^"]*{re.escape(ext)}[^"]*)"', body, re.I)
            sensitive.extend(matches)
        return list(dict.fromkeys(sensitive))[:20]  # Dedupe, cap at 20

    @staticmethod
    def _get_accessible_paths(service: Service, context: dict) -> list[str]:
        """Get accessible paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            return paths_data[paths_key].get("accessible", [])
        if paths_key in context:
            return context[paths_key].get("accessible", [])
        return []
