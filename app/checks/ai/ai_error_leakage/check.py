"""
app/checks/ai/ai_error_leakage/check.py - AI Error Leakage Check

Test for information disclosure in AI error responses.

**Probe/grade.** The probe sends seven malformed payloads
to provoke error responses and records each; `grade()` re-reads the error bodies
and returns up to four independent verdicts — stack traces, internal paths,
leaked tool names, and leaked config — each its own discriminator and
confidence. `_reading()` is the one parser both halves call (§0.12), because
`error_leaks` is an output other checks consume. This is the header pilot's
shape (one candidate, several judgements) applied to error bodies.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_error_evidence
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

STACK_TRACE_INDICATORS = ["traceback", "at line", 'file "', "exception in", "error at"]
PY_PATH_RE = re.compile(r"/[a-zA-Z0-9_/.-]+\.py")
QUOTED_IDENT_RE = re.compile(r"['\"]([a-z_]+)['\"]")
TOOL_CONTEXT_KEYWORDS = ["tools", "available_tools", "function"]
CONFIG_PATTERNS = ["model", "temperature", "max_tokens", "api_key", "endpoint", "base_url"]


class AIErrorLeakageCheck(BaseCheck):
    """Check for information leakage in AI error responses."""

    name = "ai_error_leakage"
    description = "Test for sensitive information disclosure in AI error responses"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["error_leaks"]

    sequential = True

    reason = "Error messages often reveal internal paths, tool names, and configuration details"
    references = ["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure", "CWE-209"]
    techniques = ["error triggering", "information gathering", "debug mode detection"]

    ERROR_PAYLOADS = [
        {},
        {"message": None},
        {"messages": "not_an_array"},
        {"messages": [{"role": "invalid"}]},
        {"model": "nonexistent-model-xyz"},
        {"max_tokens": -1},
        {"temperature": 999},
    ]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))

            try:
                candidate = self.create_candidate(host=service.host, target=service, target_url=url)
                await self._provoke(url, candidate, scan_id)
                result.candidates.append(candidate)

                result.outputs["error_leaks"] = self._reading(candidate.exchanges)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _provoke(self, url: str, candidate: Candidate, scan_id: str) -> None:
        """Send each malformed payload, recording every error response."""
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for payload in self.ERROR_PAYLOADS:
                await self._rate_limit()
                resp = await client.post(url, json=payload, headers=JSON_HEADERS)
                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=candidate.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=payload,
                    )
                )

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Up to four independent verdicts over the recorded error bodies."""
        exchanges = list(evidence)
        leaked = self._reading(exchanges)
        url = ctx.target_url or (ctx.target.url if ctx.target else "")
        ids = evidence.ids()
        error_bodies = self._error_count(exchanges)

        verdicts: list[Verdict] = []

        if leaked["stack_traces"]:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # A stack-trace indicator is a strong, specific signal —
                    # `traceback` and `exception in` do not appear in a normal
                    # JSON error envelope. Slightly under 1.0 because `file "`
                    # can match a benign message quoting a filename.
                    confidence=0.85,
                    discriminator="stack-trace",
                    title="Stack trace in error response",
                    description="Error responses contain stack traces revealing internal code paths",
                    evidence="Stack trace indicators found in error responses",
                    reasoning=(
                        "an error body matched a stack-trace marker (traceback / exception in / "
                        'file "...") that a structured JSON error does not contain'
                    ),
                    signals={"indicators": True},
                    references=["CWE-209"],
                    evidence_ids=ids,
                )
            )

        if leaked["paths"]:
            verdicts.append(
                Verdict(
                    severity="low",
                    # A `.py` path is an unambiguous shape; the only doubt is
                    # whether it is internal or a library path already public.
                    confidence=0.9,
                    discriminator="internal-paths",
                    title=f"Internal paths leaked ({len(leaked['paths'])})",
                    description="Error messages reveal internal file paths",
                    evidence=fmt_error_evidence(url, ", ".join(leaked["paths"][:5])),
                    reasoning=(
                        f"{len(leaked['paths'])} filesystem path(s) ending in .py appeared in "
                        "error bodies; the regex shape is unambiguous"
                    ),
                    signals={"paths": leaked["paths"]},
                    evidence_ids=ids,
                )
            )

        if leaked["tools"]:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # snake_case identifiers quoted inside a tool-context body:
                    # good, but the quoted-identifier regex also catches ordinary
                    # snake_case keys in a JSON error, so not conclusive.
                    confidence=0.7,
                    discriminator="tools-leaked",
                    title=f"Tools leaked in errors ({len(leaked['tools'])})",
                    description="Error messages reveal available tool/function names",
                    evidence=f"Tools: {', '.join(leaked['tools'][:5])}",
                    reasoning=(
                        "the error body mentions tools/functions and contains snake_case "
                        "identifiers; some may be ordinary JSON keys rather than tool names"
                    ),
                    signals={"tools": leaked["tools"]},
                    raw_data={"tools": leaked["tools"]},
                    evidence_ids=ids,
                )
            )

        if leaked["config"]:
            verdicts.append(
                Verdict(
                    severity="low",
                    # This is the weakest signal in the check: it substring-matches
                    # six ordinary parameter words, and an error that says
                    # "unknown model" or "temperature must be <= 2" is echoing the
                    # request, not leaking config. Confidence scales with how many
                    # distinct words appeared.
                    confidence=self._config_confidence(leaked["config"]),
                    discriminator="config-leaked",
                    title="Configuration leaked in errors",
                    description="Error messages reveal configuration parameters",
                    evidence=f"Config hints: {', '.join(leaked['config'])}",
                    reasoning=(
                        f"{len(leaked['config'])} config-parameter word(s) appeared in error "
                        "bodies; these words also appear in a validation error that merely names "
                        "the field the client sent, so this is a weak signal"
                    ),
                    signals={"config": leaked["config"], "error_bodies": error_bodies},
                    evidence_ids=ids,
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """The `error_leaks` dict, read off recorded error responses.

        Only 4xx/5xx bodies are read, as before. Sets are sorted rather than
        `list(set(...))` so the output is stable across identical runs.
        """
        leaked: dict[str, Any] = {"paths": [], "tools": [], "stack_traces": False, "config": []}
        paths: set[str] = set()
        tools: set[str] = set()
        config: set[str] = set()

        for exchange in exchanges:
            if exchange.error or (exchange.response_status or 0) < 400:
                continue

            body = (exchange.response_body or "").lower()

            if any(ind in body for ind in STACK_TRACE_INDICATORS):
                leaked["stack_traces"] = True

            paths.update(PY_PATH_RE.findall(body))

            if any(kw in body for kw in TOOL_CONTEXT_KEYWORDS):
                tools.update(t for t in QUOTED_IDENT_RE.findall(body) if "_" in t)

            for pattern in CONFIG_PATTERNS:
                if pattern in body:
                    config.add(pattern)

        leaked["paths"] = sorted(paths)
        leaked["tools"] = sorted(tools)
        leaked["config"] = sorted(config)
        return leaked

    def _error_count(self, exchanges: list[Exchange]) -> int:
        return sum(1 for e in exchanges if not e.error and (e.response_status or 0) >= 400)

    def _config_confidence(self, config: list[str]) -> float:
        """More distinct config words is marginally better evidence, but this
        signal is weak throughout — an echoed field name is not a leak."""
        if len(config) >= 4:
            return 0.5
        if len(config) >= 2:
            return 0.4
        return 0.3
