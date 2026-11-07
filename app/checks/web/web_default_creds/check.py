"""
app/checks/web/default_creds.py - Default Credentials on Admin Panels

When path_probe finds admin panels returning 200 with login forms,
tests a small set of default credential pairs.

GATED: Requires checks.intrusive_web = true (opt-in).

**Probe/grade.** `check_service()` fetches each admin path,
and — where the page carries a login form — POSTs the default credential pairs,
recording the GET and every POST it made; `grade()` re-reads those exchanges and
decides what happened. The credential POSTs stay in the probe because they are
side effects a grader must never perform, and the probe still stops at the first
pair that looked accepted, reading that off the exchange it just recorded (§6.2)
so the stop and the verdict agree.

One candidate per admin path. The login-form GET is the primary exchange; the
credential attempts ride on the same candidate, their `username`/`password`
recorded in each POST's request body so the grader can name the pair that worked
without the probe carrying it separately.

**Every judgement here is a heuristic over a response body, and the confidences
say how much each rests on.**

- `default-creds` — "login succeeded" — is inferred from a success word
  (`dashboard`, `welcome`, `logout`) appearing and no failure word: a login page
  that simply says "Welcome, please log in" satisfies it. When a 3xx redirect
  backs the guess it is stronger (0.7) than a bare content match (0.55).
- `no-auth` — "admin panel, no login" — rests on an admin word in the body with
  no password field, which a public docs page describing an admin panel also
  shows (0.6).
- `login-form` — creds tested and rejected — is the sure one: a password field
  was present and six pairs came back failing (0.9).
"""

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig

REDIRECT_CODES = (301, 302, 303)


class DefaultCredsCheck(ServiceIteratingCheck):
    """Test discovered admin panels for default credentials."""

    name = "web_default_creds"
    description = "Test admin panels for default credentials and unauthenticated access"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["default_creds_observations"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Admin panels with default credentials supersede all AI-specific observations on the same host"
    references = ["OWASP WSTG-ATHN-02", "CWE-798", "CWE-1392"]
    techniques = ["default credential testing", "authentication bypass"]

    # Admin paths to test (only those found by path_probe with login forms)
    ADMIN_PATTERNS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/console",
        "/dashboard",
        "/manager",
        "/wp-admin",
        "/panel",
    ]

    # Default credential pairs to test (kept minimal to avoid lockout)
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
    ]

    # Patterns indicating a login form
    LOGIN_FORM_PATTERNS = [
        re.compile(r'<input[^>]+type\s*=\s*["\']password["\']', re.I),
        re.compile(r"<form[^>]+login", re.I),
        re.compile(r"<form[^>]+auth", re.I),
    ]

    # Patterns indicating successful login
    LOGIN_SUCCESS_PATTERNS = [
        re.compile(r"dashboard", re.I),
        re.compile(r"welcome", re.I),
        re.compile(r"logged\s*in", re.I),
        re.compile(r"logout", re.I),
    ]

    # Patterns indicating failed login
    LOGIN_FAILURE_PATTERNS = [
        re.compile(r"invalid\s*(credentials|password|login)", re.I),
        re.compile(r"incorrect\s*(password|login)", re.I),
        re.compile(r"authentication\s*failed", re.I),
        re.compile(r"login\s*failed", re.I),
        re.compile(r"wrong\s*password", re.I),
    ]

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, try the pairs, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # Gate: intrusive_web must be enabled
        if not self._is_intrusive_allowed():
            result.outputs["default_creds_skipped"] = True
            return result

        accessible = self._get_accessible_paths(service, context)
        admin_paths = [
            p
            for p in accessible
            if any(
                a in p.lower() for a in ["/admin", "/console", "/dashboard", "/manager", "/panel"]
            )
        ]

        if not admin_paths:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in admin_paths:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"admin-{_slug(path)}",
                        target=service,
                        target_url=url,
                    )
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                    # Only POST credentials when the page shows a login form —
                    # the same gate as before, read off the recorded GET.
                    has_login = any(p.search(resp.body) for p in self.LOGIN_FORM_PATTERNS)
                    if has_login:
                        await self._try_credentials(client, service, url, candidate, scan_id)

                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _try_credentials(
        self,
        client: AsyncHttpClient,
        service: Service,
        url: str,
        candidate,
        scan_id: str,
    ) -> None:
        """POST each default pair, recording the attempt, until one looks accepted.

        The stop-at-first-success is the original's, kept because probing on
        after a working login is a request this check never made. Whether an
        attempt succeeded is read back off the exchange just recorded, so the
        probe and `grade()` reach the same conclusion from the same bytes.
        """
        for username, password in self.DEFAULT_CREDS:
            await self._rate_limit()
            resp = await client.post(
                url,
                data=f"username={username}&password={password}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.error:
                continue

            exchange = exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=service.host,
                method="POST",
                request_body=f"username={username}&password={password}",
            )
            candidate.attach(exchange)

            if self._attempt_succeeded(exchange):
                break

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded login attempts. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one admin path. At most one verdict."""
        exchanges = list(evidence)
        if not exchanges:
            return []

        primary = exchanges[0]
        if not _served(primary):
            return []

        path = _path_of(primary)
        url = primary.request_url or ""
        body = primary.response_body or ""
        attempts = [e for e in exchanges[1:] if (e.request_method or "").upper() == "POST"]

        has_login = any(p.search(body) for p in self.LOGIN_FORM_PATTERNS)

        # ── No login form: is this an unauthenticated admin panel? ──
        if not has_login:
            if self._looks_like_admin_content(body):
                return [
                    Verdict(
                        severity="critical",
                        # "Admin panel with no auth" rests on an admin word in
                        # the body and the absence of a password field. A public
                        # page that documents an admin panel shows both.
                        confidence=0.6,
                        discriminator=f"no-auth-{_slug(path)}",
                        title=f"Admin panel requires no authentication: {ctx.host}{path}",
                        description=f"Admin panel at {path} is accessible without any login",
                        evidence=fmt_status_evidence(url, 200, body[:200]),
                        reasoning=(
                            "the 200 body contains admin-panel wording and no password "
                            "field; a page merely describing an admin panel matches too"
                        ),
                        signals={"path": path},
                        evidence_ids=[primary.id],
                    )
                ]
            return []

        # ── Login form present: did any recorded attempt look accepted? ──
        accepted = next((e for e in attempts if self._attempt_succeeded(e)), None)
        if accepted is not None:
            username, password = _creds_of(accepted)
            cred_display = f"{username}/{password}" if password else f"{username}/(empty)"
            redirect = accepted.response_status in REDIRECT_CODES
            return [
                Verdict(
                    severity="critical",
                    # Success is inferred, never confirmed: a success word and no
                    # failure word, or a 3xx. A redirect is the stronger tell;
                    # a bare content match is weak, because a re-served login
                    # page saying "Welcome" satisfies it.
                    confidence=0.7 if redirect else 0.55,
                    discriminator=f"default-creds-{_slug(path)}",
                    title=(f"Default credentials accepted: {cred_display} at {ctx.host}{path}"),
                    description=f"Login with default credentials succeeded at {path}",
                    evidence=f"POST {url} with {cred_display} -> login appears successful",
                    reasoning=(
                        f"the response to {cred_display} was a {accepted.response_status} "
                        "redirect with no failure text"
                        if redirect
                        else f"the response to {cred_display} contained a success word and "
                        "no failure word — inferred, not confirmed"
                    ),
                    signals={
                        "path": path,
                        "username": username,
                        "via_redirect": redirect,
                    },
                    raw_data={"path": path, "username": username},
                    evidence_ids=[primary.id, accepted.id],
                )
            ]

        return [
            Verdict(
                severity="high",
                # The sure one: a password field was present and every default
                # pair came back failing. Short of certain only because a WAF or
                # rate-limiter could mask a real acceptance behind a failure body.
                confidence=0.9,
                discriminator=f"login-form-{_slug(path)}",
                title=f"Login form detected: {ctx.host}{path}",
                description=(f"Admin login form found at {path} — default credentials rejected"),
                evidence=(
                    f"Login form at {url}, {len(self.DEFAULT_CREDS)} credential pairs "
                    "tested and rejected"
                ),
                reasoning=(
                    f"a login form was present and {len(attempts)} default pair(s) were "
                    "tested, none of which looked accepted"
                ),
                signals={"path": path, "pairs_tested": len(attempts)},
                evidence_ids=[primary.id],
            )
        ]

    def _attempt_succeeded(self, exchange: Exchange) -> bool:
        """Whether one recorded login POST looks accepted.

        The original success rule, read off the exchange: a success pattern with
        no failure pattern, or a 3xx redirect with no failure pattern.
        """
        if exchange.error is not None:
            return False
        body = exchange.response_body or ""
        has_failure = any(p.search(body) for p in self.LOGIN_FAILURE_PATTERNS)
        if has_failure:
            return False
        if any(p.search(body) for p in self.LOGIN_SUCCESS_PATTERNS):
            return True
        return exchange.response_status in REDIRECT_CODES

    @staticmethod
    def _looks_like_admin_content(body: str) -> bool:
        """Check if page content looks like an admin panel (not just a redirect or error)."""
        admin_indicators = [
            "dashboard",
            "admin panel",
            "configuration",
            "settings",
            "manage",
            "users",
        ]
        body_lower = body.lower()
        return any(ind in body_lower for ind in admin_indicators)

    @staticmethod
    def _is_intrusive_allowed() -> bool:
        """Check if intrusive web checks are enabled in preferences."""
        try:
            from app.preferences import get_preferences

            return get_preferences().checks.intrusive_web
        except Exception:
            return False

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


def _path_of(exchange: Exchange) -> str:
    """The admin path this attempt targeted, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"


def _served(exchange: Exchange) -> bool:
    """True when the admin path returned 200 with a body."""
    return (
        exchange.error is None and exchange.response_status == 200 and bool(exchange.response_body)
    )


def _creds_of(exchange: Exchange) -> tuple[str, str]:
    """The username/password an attempt POSTed, read back off its request body."""
    parsed = parse_qs(exchange.request_body or "")
    username = (parsed.get("username") or [""])[0]
    password = (parsed.get("password") or [""])[0]
    return username, password


def _slug(path: str) -> str:
    """The per-path discriminator suffix, unchanged from the original."""
    return path.replace("/", "-").strip("-")
