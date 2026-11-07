"""
app/checks/web/config_exposure.py - Exposed Configuration File Analysis

When path_probe finds .env, config.json, etc. returning 200,
this check fetches and parses for secrets (API keys, DB creds, etc.).
Secret values are NEVER stored — only redacted evidence.

**Probe/grade.** `check_service()` resolves which config
paths to try — from `path_probe`'s output, or a short fallback list — fetches
each, records it, and judges nothing; `grade()` re-reads the recorded bodies and
decides what was exposed.

**Where the confidence goes.** Both judgements here are `high` or `critical`,
and `config-accessible` rests on nothing more than a 200 with a body. A
single-page app answers 200 with its index page for `/.env`, which is exactly
this check's shape of false positive — and it lands on `high`. So `grade()` asks
whether the body is the *format the path implies*: an HTML document at `/.env`
is a catch-all route and carries 0.4; a `/config.json` whose body is not JSON
carries 0.5; anything else 0.85. `secrets` splits on which pattern matched — a
named key like `OPENAI_API_KEY` is 0.95, while the catch-all `GENERIC_SECRET`
pattern (any `*KEY`/`*TOKEN` assignment with a 20-character value) is 0.7,
because a placeholder such as `your-api-key-goes-here-xxxxxx` satisfies it.

Severity is unchanged in every case, and secret *values* are still never
recorded — only the pattern names.

#### One incidental cleanup

When `path_probe` had found no config paths, `_probe_config_paths()` fetched the
four fallback paths to see which returned 200, and then the main loop fetched
each of them again under the same condition. The paths are now fetched once, by
the main loop, which is also what puts them in the record exactly once.
"""

import re
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json

#: Tried when `path_probe` produced nothing to go on.
FALLBACK_CONFIG_PATHS = ["/.env", "/config.json", "/config.yaml", "/settings.json"]


class ConfigExposureCheck(ServiceIteratingCheck):
    """Analyze accessible configuration files for exposed secrets."""

    name = "web_config_exposure"
    description = "Parse accessible config files (.env, config.json, etc.) for secrets"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["config_observations"]
    service_types = ["http", "html", "api"]

    reason = "An accessible .env with API keys is game over — no need to probe for prompt leakage when you have the key"
    references = ["OWASP WSTG-CONF-05", "CWE-200", "CWE-540"]
    techniques = ["configuration analysis", "secret detection"]

    # Config file paths to check (if path_probe found them accessible)
    CONFIG_PATHS = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.development",
        "/config.json",
        "/config.yaml",
        "/config.yml",
        "/config.toml",
        "/settings.json",
        "/settings.yaml",
        "/appsettings.json",
        "/application.properties",
        "/application.yml",
        "/.aws/credentials",
        "/wp-config.php",
    ]

    # Secret patterns: (name, regex, severity)
    SECRET_PATTERNS = [
        # LLM provider keys
        (
            "OPENAI_API_KEY",
            re.compile(r"(?:OPENAI_API_KEY|openai[_-]?key)\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        (
            "ANTHROPIC_API_KEY",
            re.compile(r"(?:ANTHROPIC_API_KEY|anthropic[_-]?key)\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        (
            "HUGGINGFACE_TOKEN",
            re.compile(r"(?:HUGGING_?FACE[_-]?TOKEN|HF_TOKEN)\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        # Cloud credentials
        (
            "AWS_SECRET_ACCESS_KEY",
            re.compile(r"AWS_SECRET_ACCESS_KEY\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        ("AWS_ACCESS_KEY_ID", re.compile(r"AWS_ACCESS_KEY_ID\s*[=:]\s*\S+", re.I), "critical"),
        (
            "AZURE_KEY",
            re.compile(r"(?:AZURE[_-]?(?:KEY|SECRET|TOKEN))\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        (
            "GCP_KEY",
            re.compile(
                r"(?:GOOGLE[_-]?(?:API[_-]?KEY|APPLICATION[_-]?CREDENTIALS))\s*[=:]\s*\S+", re.I
            ),
            "critical",
        ),
        # Database credentials
        (
            "DATABASE_URL",
            re.compile(r"(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        (
            "DB_PASSWORD",
            re.compile(r"(?:DB_PASS(?:WORD)?|DATABASE_PASS(?:WORD)?)\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        # Secrets / tokens
        (
            "JWT_SECRET",
            re.compile(r"(?:JWT_SECRET|SESSION_SECRET|SECRET_KEY|APP_SECRET)\s*[=:]\s*\S+", re.I),
            "critical",
        ),
        ("PRIVATE_KEY", re.compile(r"(?:PRIVATE_KEY|RSA_KEY)\s*[=:]\s*\S+", re.I), "critical"),
        # Generic long secret values (KEY=<20+ chars>)
        (
            "GENERIC_SECRET",
            re.compile(
                r"[A-Z_]{3,}(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*[=:]\s*\S{20,}", re.I
            ),
            "high",
        ),
    ]

    #: The one pattern that names no particular secret. It matches any
    #: `*KEY`/`*TOKEN`/`*PASSWORD` assignment with a 20-character value, which a
    #: committed placeholder also satisfies. Grading input only.
    GENERIC_PATTERN_NAME = "GENERIC_SECRET"

    # ══ Probe ════════════════════════════════════════════════════════
    # Fetch, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        accessible = self._get_accessible_paths(service, context)
        config_paths = [
            p
            for p in accessible
            if any(p.endswith(c.lstrip("/")) or p == c for c in self.CONFIG_PATHS)
        ]

        # Nothing upstream to go on: try the common config paths directly. They
        # are fetched by the loop below, once, rather than probed first and then
        # fetched again.
        if not config_paths:
            config_paths = list(FALLBACK_CONFIG_PATHS)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in config_paths:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    # One candidate per config file: each observation named its
                    # own target_url, which lives on the candidate. `grade()`
                    # replaces the discriminator with the one it earns.
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"config-{path.replace('/', '-').strip('-')}",
                        target=service,
                        target_url=url,
                    )
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )
                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read one recorded config file. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one accessible config file. At most one verdict."""
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        body = exchange.response_body or ""
        if not body:
            return []

        path = _path_of(exchange)
        url = exchange.request_url or ""
        slug = path.replace("/", "-").strip("-")
        secrets_found = self._scan_for_secrets(body)

        if secrets_found:
            # Group by severity
            secret_names = [s[0] for s in secrets_found]
            max_severity = "critical" if any(s[2] == "critical" for s in secrets_found) else "high"
            named = [n for n in secret_names if n != self.GENERIC_PATTERN_NAME]

            return [
                Verdict(
                    severity=max_severity,
                    # A named key (`OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`) is
                    # an assignment to a variable whose purpose is not in doubt.
                    # `GENERIC_SECRET` alone is any `*KEY`/`*TOKEN` assignment
                    # with a 20-character value, which a committed placeholder
                    # like `your-api-key-goes-here-xxxxxx` also satisfies.
                    confidence=0.95 if named else 0.7,
                    discriminator=f"secrets-{slug}",
                    title=(f"Configuration file contains secrets: {path} at {ctx.host}"),
                    description=(f"{len(secrets_found)} secret pattern(s) detected in {path}"),
                    evidence=(f"Secrets detected (redacted): {', '.join(secret_names[:10])}"),
                    reasoning=(
                        f"named secret pattern(s) matched: {', '.join(named)}"
                        if named
                        else "only the generic *KEY/*TOKEN pattern matched, which a "
                        "committed placeholder value also satisfies"
                    ),
                    signals={
                        "path": path,
                        "secret_types": secret_names,
                        "named_patterns": named,
                        "count": len(secrets_found),
                    },
                    raw_data={
                        "path": path,
                        "secret_types": secret_names,
                        "count": len(secrets_found),
                    },
                    evidence_ids=[exchange.id],
                )
            ]

        # No secrets: the claim is just that the file is reachable — which is
        # precisely where a catch-all route masquerades as an exposed config.
        confidence, why = _format_confidence(path, body)

        return [
            Verdict(
                severity="high",
                confidence=confidence,
                discriminator=f"config-accessible-{slug}",
                title=f"Configuration file accessible: {path} at {ctx.host}",
                description=(
                    f"Config file {path} is publicly accessible (no secrets detected "
                    "but internal config exposed)"
                ),
                evidence=(f"GET {url} -> 200 ({len(body)} bytes, no secret patterns matched)"),
                reasoning=why,
                signals={"path": path, "bytes": len(body)},
                evidence_ids=[exchange.id],
            )
        ]

    def _scan_for_secrets(self, content: str) -> list[tuple[str, str, str]]:
        """Scan content for secret patterns. Returns list of (name, match, severity)."""
        found = []
        seen_names = set()
        for name, pattern, severity in self.SECRET_PATTERNS:
            if name in seen_names:
                continue
            match = pattern.search(content)
            if match:
                found.append((name, match.group(0)[:30] + "...", severity))
                seen_names.add(name)
        return found

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
    """The path this config file was fetched from, read back off the record."""
    return urlparse(exchange.request_url or "").path or "/"


def _format_confidence(path: str, body: str) -> tuple[float, str]:
    """How much a 200-with-a-body establishes that a config file is exposed.

    The question is whether the body is the format the path implies. It is not a
    judgement about the target — it is how the grader tells an exposed file from
    a catch-all route that answers every path with the same page.
    """
    head = body[:512].lower()
    if "<html" in head or "<!doctype html" in head:
        return 0.4, (
            f"{path} returned 200 but the body is an HTML document, which a config file "
            "is not — the signature of a catch-all route rather than an exposure"
        )
    if path.lower().endswith(".json") and safe_json(body) is None:
        return 0.5, (
            f"{path} returned 200 but the body does not parse as JSON, so it is probably "
            "not the config file the path names"
        )
    return 0.85, (
        f"{path} returned 200 with {len(body)} bytes in a plausible format; no secret "
        "pattern matched, so the exposure is of internal configuration rather than keys"
    )
