"""
app/checks/web/paths.py - Path Discovery

Probe for common paths, admin interfaces, and sensitive endpoints.

**Probe/grade.** `check_service()` walks `COMMON_PATHS`,
records every path that answered, and judges nothing; `grade()` re-reads each
response and decides what the status code is worth.

Two things are specific to this check:

- **One candidate per probed path**, not per service, because each observation
  named its own `target_url` and that lives on the candidate. Every path that
  answered gets one, including the 404s — they are what `paths_<port>` is
  computed from, and the set is bounded by `COMMON_PATHS` rather than by the
  target (which is why recording them is evidence and not volume; compare
  `network_port_scan`, where the negative set is unbounded and deliberately
  unrecorded).
- **The hashed observation id is preserved.** This check used
  `make_observation_id_hashed(name, host, kind, path)` rather than a plain
  discriminator, because forty paths on one host would otherwise collide. The
  grading stage builds ids with `make_observation_id`, so `grade()` names the
  discriminator `f"{kind}-{suffix}"` with the same four-character digest — which
  reconstructs the identical id (`web_path_probe-host-accessible-a3f2`).

**The confidence is about the catch-all route**, which is this check's standing
false positive: a server that answers 200 with its index page for every path
makes `/.env` look exposed and escalates it to `high`. Where the path implies a
config or data file and the body is an HTML document, that reads as a catch-all
and the verdict says so — same observation, same severity, 0.4 instead of 0.9.
"""

import hashlib
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_endpoint_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

#: Paths whose severity was escalated and which should *not* be HTML. A 200
#: here with an HTML body is the catch-all route, not an exposed file.
NON_HTML_SUFFIXES = (".env", ".json", ".yaml", ".yml", ".sql", ".conf", ".cfg")
NON_HTML_PREFIXES = ("/.git/", "/.svn/")

#: Path fragments that make a 403 interesting, unchanged from before.
PROTECTED_FRAGMENTS = ("admin", "config", "internal", "debug")

REDIRECT_CODES = (301, 302, 307, 308)


class PathProbeCheck(ServiceIteratingCheck):
    """Probe for common sensitive paths and admin interfaces."""

    name = "web_path_probe"
    description = "Check for common admin panels, config files, and sensitive endpoints"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["discovered_paths"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Common paths often lead to admin panels, backups, or configuration files"
    references = ["OWASP WSTG-CONF-05", "CWE-538"]
    techniques = ["directory enumeration", "forced browsing", "path traversal"]

    COMMON_PATHS = [
        # Admin
        "/admin",
        "/admin/",
        "/administrator",
        "/admin.php",
        "/wp-admin",
        "/manager",
        "/console",
        "/dashboard",
        # Config/Debug
        "/.env",
        "/config.json",
        "/config.yaml",
        "/settings.json",
        "/debug",
        "/phpinfo.php",
        "/server-status",
        "/health",
        # Git/VCS
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        # Backups
        "/backup",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        # API
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        # AI/ML specific
        "/model",
        "/models",
        "/inference",
        "/predict",
        "/v1/models",
        "/api/models",
        "/embeddings",
        # Metrics/monitoring
        "/metrics",
        "/prometheus",
        "/actuator",
        "/actuator/health",
        # Common
        "/.well-known/",
        "/static/",
        "/assets/",
    ]

    # Paths that warrant higher severity
    HIGH_SEVERITY_PATTERNS = [".env", ".git", "backup.sql", "db.sql", "database.sql"]
    MEDIUM_SEVERITY_PATTERNS = [
        "config",
        "backup",
        "admin",
        "debug",
        "model",
        "inference",
        "predict",
    ]

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record, publish the output. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        probed: list[Exchange] = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False, follow_redirects=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.COMMON_PATHS:
                    await self._rate_limit()
                    url = service.with_path(path)

                    resp = await client.get(url)
                    if resp.error:
                        continue

                    exchange = exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host
                    )
                    probed.append(exchange)

                    # One candidate per path, because each observation names its
                    # own target_url. `grade()` replaces the discriminator with
                    # the hashed one the original used; this one only has to
                    # keep an *ungraded* candidate distinct from its neighbours.
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"path-{path}",
                        target=service,
                        target_url=url,
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.outputs[f"paths_{service.port}"] = _reading(probed)

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read one recorded path probe. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one probed path. At most one verdict."""
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        path = _path_of(exchange)
        status = exchange.response_status
        url = exchange.request_url or ""
        headers = extract_headers_dict(exchange.response_headers or {})
        body = exchange.response_body or ""

        def discriminator(kind: str) -> str:
            return f"{kind}-{_suffix(ctx.check_name, ctx.host, kind, path)}"

        if status == 200:
            content_type = headers.get("content-type", "")
            severity = _severity_for(
                path, self.HIGH_SEVERITY_PATTERNS, self.MEDIUM_SEVERITY_PATTERNS
            )
            html = _looks_like_html(body) or "html" in content_type
            mismatched = html and _expects_non_html(path)

            if mismatched:
                # A config or data file that answered with an HTML document is
                # the signature of a catch-all route, not an exposed file — and
                # this is where the escalated severities live.
                confidence = 0.4
                why = (
                    "returned 200 but with an HTML body, which a path like this should "
                    "not serve — the signature of a catch-all route rather than an "
                    "exposed file"
                )
            elif severity == "info":
                confidence = 0.99
                why = "returned 200; the observation claims only that the path responds"
            else:
                confidence = 0.85
                why = (
                    "returned 200, which establishes the path responds but not that the "
                    "resource behind it is usable — /admin commonly answers with a login "
                    "page"
                )

            return [
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator=discriminator("accessible"),
                    title=f"Accessible path: {path}",
                    description=f"Path {path} returned HTTP 200",
                    evidence=fmt_endpoint_evidence(url, status, content_type),
                    reasoning=why,
                    signals={
                        "path": path,
                        "content_type": content_type,
                        "html_body": html,
                        "content_mismatch": mismatched,
                    },
                    evidence_ids=[exchange.id],
                )
            ]

        if status == 403 and any(f in path.lower() for f in PROTECTED_FRAGMENTS):
            return [
                Verdict(
                    severity="low",
                    # A 403 rather than a 404 usually means the path is real.
                    # Usually: a denied prefix and a WAF both return 403 for
                    # paths that do not exist.
                    confidence=0.85,
                    discriminator=discriminator("forbidden"),
                    title=f"Protected path exists: {path}",
                    description=(
                        f"Path {path} exists but is forbidden — potential authorization "
                        "bypass target"
                    ),
                    evidence=fmt_endpoint_evidence(url, 403),
                    reasoning=(
                        "403 rather than 404 implies the path exists, though a denied "
                        "prefix or a WAF returns 403 for paths that do not"
                    ),
                    signals={"path": path},
                    evidence_ids=[exchange.id],
                )
            ]

        if status in REDIRECT_CODES:
            location = headers.get("location", "")
            return [
                Verdict(
                    severity="info",
                    # Status and Location read verbatim off the record.
                    confidence=0.99,
                    discriminator=discriminator("redirect"),
                    title=f"Redirect at {path}",
                    description=f"Path redirects to {location}",
                    evidence=f"GET {path} -> {status} Location: {location}",
                    reasoning=f"{status} with Location: {location or '(absent)'}",
                    signals={"path": path, "status": status, "location": location},
                    evidence_ids=[exchange.id],
                )
            ]

        return []


# ── The one parser, called by both halves ────────────────────────────


def _path_of(exchange: Exchange) -> str:
    """The path this probe asked for, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"


def _suffix(check_name: str, host: str, kind: str, path: str) -> str:
    """The four-character digest `make_observation_id_hashed` appends.

    Reproduced here rather than called, because the grading stage builds ids
    with `make_observation_id` — putting the digest in the discriminator makes
    the two spellings land on the same id, which is what keeps this check's
    observation ids stable across the migration.
    """
    payload = f"{check_name}:{host}:{kind}:{path}"
    return hashlib.sha256(payload.encode()).hexdigest()[:4]


def _severity_for(path: str, high: list[str], medium: list[str]) -> str:
    """The original severity ladder, unchanged."""
    path_lower = path.lower()
    if any(s in path_lower for s in high):
        return "high"
    if any(s in path_lower for s in medium):
        return "medium"
    return "info"


def _expects_non_html(path: str) -> bool:
    """True when the path names a config or data file rather than a page."""
    path_lower = path.lower()
    return path_lower.endswith(NON_HTML_SUFFIXES) or path_lower.startswith(NON_HTML_PREFIXES)


def _looks_like_html(body: str) -> bool:
    """True when a body is an HTML document."""
    head = body[:512].lower()
    return "<html" in head or "<!doctype html" in head


def _reading(exchanges: list[Exchange]) -> dict[str, list[str]]:
    """Read `paths_<port>` out of the recorded probes.

    The single parser behind §6.2's two parses: `check_service()` calls it to
    populate the output, and `grade()` derives the same readings per path.
    Order follows the probe order, which is `COMMON_PATHS`.
    """
    accessible: list[str] = []
    forbidden: list[str] = []
    for exchange in exchanges:
        if exchange.error is not None:
            continue
        path = _path_of(exchange)
        if exchange.response_status == 200:
            accessible.append(path)
        elif exchange.response_status == 403:
            forbidden.append(path)
    return {"accessible": accessible, "forbidden": forbidden}
