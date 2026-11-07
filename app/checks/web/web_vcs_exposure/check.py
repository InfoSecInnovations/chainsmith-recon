"""
app/checks/web/vcs_exposure.py - Exposed Version Control Detection

When path_probe finds .git/HEAD or .git/config returning 200,
this check probes deeper to assess exposure severity.
Also checks .svn/entries and .hg/store.

**Probe/grade.** `check_service()` fetches the git, svn and
mercurial metadata paths, records each, and judges nothing; `grade()` re-reads
the recorded bodies and places the severity. The probe still branches on the
upstream `discovered_paths` output to decide whether the git deep-probe is worth
making at all — that is navigation, not judgement.

**This is the check where confidence matters most in the suite**, because three
of its four judgements are `critical` or `high` and all four rest on a status
code. A server with a catch-all route answers `200` with its index page for
every path, which makes six git metadata files look "accessible" and escalates
to `critical` on a site that has no repository at all. The check's own tests
name this case. So `grade()` now reads the *bodies*: a `.git/config` that
actually contains `[core]` or `[remote ...]` is near-certain, and one whose body
is an HTML document is very likely a catch-all — same observation, same
severity, honest confidence.

The credential judgement is split the same way. A remote URL with `user:pass@`
embedded is unmistakable; a bare `token =` or `password =` line also matches a
placeholder or a commented-out example, and no longer asserts itself as
strongly.

#### One incidental cleanup

The SVN branch fetched `/.svn/entries` twice whenever `path_probe` had *not*
already found it: once to decide whether to call `_check_svn`, and then again
inside `_check_svn`, under the same 200 condition. The observation fired if and
only if that path returned 200 either way, so it is now one fetch.
"""

import re
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig

SVN_PATH = "/.svn/entries"
HG_PATH = "/.hg/store"


class VCSExposureCheck(ServiceIteratingCheck):
    """Deep check for exposed version control metadata."""

    name = "web_vcs_exposure"
    description = "Assess depth of exposed .git/.svn/.hg repositories"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["vcs_observations"]
    service_types = ["http", "html", "api"]

    reason = "Exposed .git allows full source code recovery including API keys, model configs, and credentials"
    references = ["OWASP WSTG-CONF-05", "CWE-538"]
    techniques = ["VCS metadata enumeration", "source code exposure assessment"]

    # Git paths to probe beyond .git/HEAD
    GIT_DEEP_PATHS = [
        "/.git/config",
        "/.git/COMMIT_EDITMSG",
        "/.git/refs/heads/main",
        "/.git/refs/heads/master",
        "/.git/logs/HEAD",
        "/.gitignore",
    ]

    # Patterns that indicate credentials in .git/config
    CREDENTIAL_PATTERNS = [
        re.compile(r"https?://[^:]+:[^@]+@", re.I),  # URL with embedded creds
        re.compile(r"token\s*=\s*\S+", re.I),
        re.compile(r"password\s*=\s*\S+", re.I),
    ]

    #: The one credential pattern that cannot be anything else. A URL carrying
    #: `user:pass@` is a credential; `token =` is sometimes a placeholder.
    EMBEDDED_URL_CREDS = CREDENTIAL_PATTERNS[0]

    #: Markers that a `.git/config` really is one. Grading input only.
    GIT_CONFIG_MARKERS = ("[core]", "[remote ", "[branch ", "repositoryformatversion")

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # Check if path_probe found accessible VCS paths
        accessible = self._get_accessible_paths(service, context)

        # One candidate per service: git, svn and mercurial are independent
        # judgements over the same subject, so the candidate stays
        # undiscriminated and `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:

                async def fetch(path: str) -> None:
                    resp = await client.get(service.with_path(path))
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                # ── Git exposure ──
                # Only worth six requests when something already pointed at a
                # repository; that decision is the upstream output's, not a
                # judgement about this response.
                if any(p for p in accessible if ".git" in p):
                    for path in self.GIT_DEEP_PATHS:
                        await self._rate_limit()
                        await fetch(path)

                # ── SVN exposure ──
                await fetch(SVN_PATH)

                # ── Mercurial exposure ──
                await fetch(HG_PATH)

            result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded metadata. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one service's exposed version control metadata."""
        by_path = {_path_of(e): e for e in evidence}
        verdicts: list[Verdict] = []

        verdicts.extend(self._grade_git(by_path, ctx))

        svn = by_path.get(SVN_PATH)
        if _served(svn):
            body = svn.response_body or ""
            html = _looks_like_html(body)
            verdicts.append(
                Verdict(
                    severity="high",
                    # A 200 is the whole signal. An HTML body at this path is
                    # far more likely a catch-all route than an SVN working
                    # copy, which is plain text beginning with a version number.
                    confidence=0.4 if html else 0.9,
                    discriminator="svn-exposed",
                    title=f"SVN metadata exposed: {ctx.host}",
                    description=".svn/entries is accessible — source code may be recoverable",
                    evidence=fmt_status_evidence(svn.request_url or "", 200, body[:200]),
                    reasoning=(
                        ".svn/entries returned 200 but the body is an HTML document, which "
                        "is what a catch-all route returns for any path"
                        if html
                        else ".svn/entries returned 200 with a non-HTML body"
                    ),
                    signals={"html_body": html},
                    evidence_ids=[svn.id],
                )
            )

        hg = by_path.get(HG_PATH)
        if _served(hg):
            body = hg.response_body or ""
            html = _looks_like_html(body)
            verdicts.append(
                Verdict(
                    severity="high",
                    # `.hg/store` is a directory, so a 200 here is either a
                    # directory listing or a catch-all — and both render as
                    # HTML, which is why this one leans low when it does.
                    confidence=0.4 if html else 0.85,
                    discriminator="hg-exposed",
                    title=f"Mercurial metadata exposed: {ctx.host}",
                    description=".hg/store is accessible — source code may be recoverable",
                    evidence=fmt_status_evidence(hg.request_url or "", 200, body[:200]),
                    reasoning=(
                        ".hg/store returned 200 with an HTML body; since .hg/store is a "
                        "directory, that is a listing or a catch-all rather than metadata"
                        if html
                        else ".hg/store returned 200 with a non-HTML body"
                    ),
                    signals={"html_body": html},
                    evidence_ids=[hg.id],
                )
            )

        return verdicts

    def _grade_git(self, by_path: dict[str, Exchange], ctx: GradeContext) -> list[Verdict]:
        """Grade the recorded git metadata. At most one verdict."""
        accessible_git = [p for p in self.GIT_DEEP_PATHS if _served(by_path.get(p))]
        if not accessible_git:
            return []

        config = by_path.get("/.git/config")
        git_config_body = (config.response_body or "") if _served(config) else ""
        evidence_ids = [by_path[p].id for p in accessible_git]

        # Does anything served here actually look like git metadata? A catch-all
        # route serving one HTML page for all six paths is the false positive
        # this check has always been exposed to.
        looks_like_git = any(
            marker in git_config_body.lower() for marker in self.GIT_CONFIG_MARKERS
        )
        html_bodies = [
            p for p in accessible_git if _looks_like_html(by_path[p].response_body or "")
        ]

        # Check for credentials in .git/config
        matched = [p.pattern for p in self.CREDENTIAL_PATTERNS if p.search(git_config_body)]

        if matched:
            embedded_url = bool(self.EMBEDDED_URL_CREDS.search(git_config_body))
            return [
                Verdict(
                    severity="critical",
                    # A remote URL carrying `user:pass@` cannot be anything but
                    # a credential. A bare `token =` or `password =` line also
                    # matches a placeholder or a commented-out example.
                    confidence=0.95 if embedded_url else 0.75,
                    discriminator="git-config-credentials",
                    title=f"Git config contains credentials: {ctx.host}",
                    description=("Remote URL with embedded token/password found in .git/config"),
                    evidence=(
                        "Credential pattern found in .git/config (redacted). "
                        f"Accessible paths: {', '.join(accessible_git)}"
                    ),
                    reasoning=(
                        "a remote URL with embedded user:password was found in .git/config"
                        if embedded_url
                        else "a `token`/`password` assignment matched, which a placeholder "
                        "or commented-out example also satisfies"
                    ),
                    signals={
                        "patterns": matched,
                        "embedded_url_credentials": embedded_url,
                        "accessible_paths": accessible_git,
                    },
                    raw_data={"accessible_paths": accessible_git},
                    evidence_ids=evidence_ids,
                )
            ]

        recoverable = len(accessible_git) >= 3
        if looks_like_git:
            # The config parsed as a git config, so these really are repository
            # files. Short of certain because "recoverable" also needs the
            # objects to be fetchable, which this check never tried.
            confidence = 0.9
            why = ".git/config contains git config syntax, so these are repository files"
        elif len(html_bodies) == len(accessible_git):
            # Every "accessible" path returned an HTML page. This is what a
            # catch-all route looks like, and a repository it is probably not.
            confidence = 0.4
            why = (
                f"all {len(accessible_git)} path(s) returned HTML and .git/config has no "
                "git config syntax — the signature of a catch-all route, not a repository"
            )
        else:
            confidence = 0.7
            why = (
                "paths returned 200 but .git/config shows no git config syntax to confirm "
                "a repository"
            )

        return [
            Verdict(
                severity="critical" if recoverable else "high",
                confidence=confidence,
                discriminator="git-exposed",
                title=f"Git repository exposed: {ctx.host}",
                description=(
                    f"{len(accessible_git)} git metadata files accessible — "
                    f"{'full source code likely recoverable' if recoverable else 'partial exposure'}"
                ),
                evidence=f"Accessible: {', '.join(accessible_git)}",
                reasoning=why,
                signals={
                    "accessible_paths": accessible_git,
                    "git_config_syntax": looks_like_git,
                    "html_bodies": html_bodies,
                },
                raw_data={"accessible_paths": accessible_git},
                evidence_ids=evidence_ids,
            )
        ]

    @staticmethod
    def _get_accessible_paths(service: Service, context: dict) -> list[str]:
        """Get accessible paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            return paths_data[paths_key].get("accessible", [])
        # Also check top-level for backwards compat
        if paths_key in context:
            return context[paths_key].get("accessible", [])
        return []


def _path_of(exchange: Exchange) -> str:
    """The path this exchange asked for, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"


def _served(exchange: Exchange | None) -> bool:
    """True when the path returned 200 — the original `not error and == 200`."""
    return exchange is not None and exchange.error is None and exchange.response_status == 200


def _looks_like_html(body: str) -> bool:
    """True when a body is an HTML document rather than VCS metadata.

    Not a judgement about the target: it is how the grader tells "this path is
    served" from "every path is served", which is the difference between an
    exposed repository and a catch-all route.
    """
    head = body[:512].lower()
    return "<html" in head or "<!doctype html" in head
