"""
app/checks/web/robots.py - Robots.txt Analysis

Fetch and analyze robots.txt for sensitive path disclosure.

**Probe/grade.** `check_service()` fetches `/robots.txt`,
records it and emits a candidate; `grade()` re-reads the recorded body and
decides what the disclosed paths are worth.

`robots_{port}` is an output, so the probe has to know the parsed paths before a
grader runs. Rather than read the body twice in two places, both halves call
`_parse_robots()` over the same exchange (§6.2's two parses, with one parser).

The confidence this adds is the point. `INTERESTING_PATTERNS` holds twenty-one
bare substrings, and several of them collide constantly: `ai` matches `domain`,
`ml` matches `html`, `data` and `api` and `v2` match almost any REST path a site
would legitimately hide from crawlers. A match on `admin`, `.env` or `secret` is
a different quality of evidence from a match on `ml`, and until now both were
asserted identically. `_STRONG_PATTERNS` names which is which, and it changes
only the confidence — never which observation fires.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig


class RobotsTxtCheck(ServiceIteratingCheck):
    """Fetch and analyze robots.txt for sensitive path disclosure."""

    name = "web_robots_txt"
    description = "Retrieve robots.txt and identify potentially sensitive paths"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["robots_paths"]
    service_types = ["http", "html", "api"]

    reason = "robots.txt often reveals hidden paths that admins want to keep from search engines"
    references = ["OWASP WSTG-INFO-03", "RFC 9309"]
    techniques = ["passive reconnaissance", "path discovery"]

    INTERESTING_PATTERNS = [
        r"admin",
        r"internal",
        r"api",
        r"debug",
        r"config",
        r"backup",
        r"private",
        r"secret",
        r"model",
        r"ml",
        r"ai",
        r"data",
        r"v2",
        r"v3",
        r"stage",
        r"dev",
        r"\.git",
        r"\.env",
        r"\.bak",
        r"inference",
        r"prompt",
    ]

    #: The patterns that name a thing rather than appear inside other words.
    #: Grading input only — every pattern above still flags a path, and this
    #: decides nothing except how sure the verdict says it is.
    STRONG_PATTERNS = frozenset(
        {
            r"admin",
            r"internal",
            r"debug",
            r"config",
            r"backup",
            r"private",
            r"secret",
            r"\.git",
            r"\.env",
            r"\.bak",
            r"inference",
        }
    )

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record, publish the output. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        robots_url = service.with_path("/robots.txt")
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                resp = await client.get(robots_url)

            if resp.error or resp.status_code != 200:
                return result

            exchange = exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=context.get("scan_id") or "",
                host=service.host,
            )

            # One candidate per service: `sensitive-paths` and
            # `sitemaps-disclosed` both read the same file and can both fire, so
            # the candidate stays undiscriminated and `grade()` names each one.
            candidate = self.create_candidate(
                host=service.host, target=service, target_url=robots_url
            )
            candidate.attach(exchange)
            result.candidates.append(candidate)

            parsed = self._parse_robots(exchange)
            result.outputs[f"robots_{service.port}"] = {
                "disallowed": parsed["disallowed"],
                "interesting": parsed["interesting"],
                "sitemaps": parsed["sitemaps"],
            }

        except Exception as e:
            result.errors.append(f"{robots_url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded robots.txt. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on what one robots.txt disclosed."""
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        parsed = self._parse_robots(exchange)
        disallowed = parsed["disallowed"]
        interesting = parsed["interesting"]
        sitemaps = parsed["sitemaps"]
        matched = parsed["matched"]
        evidence_ids = [exchange.id]

        verdicts: list[Verdict] = []

        if interesting:
            strong = sorted(matched & self.STRONG_PATTERNS)
            verdicts.append(
                Verdict(
                    severity="low",
                    # A named directory (`/admin/`, `/.env`) is a real
                    # disclosure. A substring hit on `ml` or `ai` or `v2` is
                    # very often a legitimate path that merely contains those
                    # two letters, and this check cannot tell the difference.
                    confidence=0.9 if strong else 0.5,
                    discriminator="sensitive-paths",
                    title=f"Sensitive paths in robots.txt ({len(interesting)})",
                    description="robots.txt reveals potentially sensitive paths",
                    evidence=f"Interesting Disallow paths: {', '.join(interesting[:10])}",
                    reasoning=(
                        f"{len(interesting)} of {len(disallowed)} Disallow path(s) matched "
                        + (
                            f"named pattern(s): {', '.join(strong)}"
                            if strong
                            else "only loose substring patterns, which collide with ordinary paths"
                        )
                    ),
                    signals={
                        "interesting": interesting,
                        "patterns": sorted(matched),
                        "strong_patterns": strong,
                    },
                    raw_data={"disallowed": disallowed, "interesting": interesting},
                    evidence_ids=evidence_ids,
                )
            )

        if sitemaps:
            verdicts.append(
                Verdict(
                    severity="info",
                    # A `Sitemap:` line is a declaration, read verbatim.
                    confidence=0.99,
                    discriminator="sitemaps-disclosed",
                    title=f"Sitemaps disclosed ({len(sitemaps)})",
                    description="robots.txt reveals sitemap locations",
                    evidence=f"Sitemaps: {', '.join(sitemaps[:5])}",
                    reasoning=f"{len(sitemaps)} Sitemap directive(s) declared in the file",
                    signals={"sitemaps": sitemaps},
                    evidence_ids=evidence_ids,
                )
            )

        return verdicts

    # ── The one parser, called by both halves ────────────────────────

    def _parse_robots(self, exchange: Exchange) -> dict[str, Any]:
        """Read one recorded robots.txt.

        `matched` is the extra the grader needs and the output does not: which
        patterns actually hit, so a verdict can say whether they were named
        directories or loose substrings.
        """
        disallowed: list[str] = []
        interesting: list[str] = []
        sitemaps: list[str] = []
        matched: set[str] = set()

        for raw_line in (exchange.response_body or "").split("\n"):
            line = raw_line.strip()
            line_lower = line.lower()

            if line_lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.append(path)
                    for pattern in self.INTERESTING_PATTERNS:
                        if re.search(pattern, path, re.I):
                            interesting.append(path)
                            matched.add(pattern)
                            break

            elif line_lower.startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())

        return {
            "disallowed": disallowed,
            "interesting": interesting,
            "sitemaps": sitemaps,
            "matched": matched,
        }
