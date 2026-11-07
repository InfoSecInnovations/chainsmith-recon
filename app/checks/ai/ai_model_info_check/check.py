"""
app/checks/ai/ai_model_info_check/check.py - Model Information Disclosure

Discover endpoints that expose model information, versions, and configuration.

**Probe/grade.** The probe GETs each candidate path and
records it; `grade()` re-reads one recorded response, decides whether it
discloses model information, and places the severity. The path is read back off
`Exchange.request_url` (§0.13), and one candidate is emitted per path because
each observation names its own `target_url`.

**The hashed observation id is preserved.** This check used
`make_observation_id_hashed(name, host, "info-endpoint", path)` rather than a
plain discriminator, because seventeen paths on one host would otherwise
collide on one id. The grading stage builds ids with `make_observation_id`, so
the digest is reproduced *inside* the discriminator — `info-endpoint-<4 hex>` —
which makes both spellings land on the same id. Same approach as
`web_path_probe`.
"""

import hashlib
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.datafiles import load_data
from app.lib.evidence_fmt import fmt_endpoint_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json


class ModelInfoCheck(ServiceIteratingCheck):
    """Check for model information disclosure endpoints."""

    name = "ai_model_info_check"
    description = "Discover endpoints that expose model information and configuration"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["model_info"]
    service_types = ["ai", "api"]

    reason = "Model info endpoints reveal architecture, version, and configuration details useful for targeted attacks"
    references = ["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure"]
    techniques = ["API enumeration", "model fingerprinting", "configuration discovery"]

    # Shipped list: app/data/endpoints/model_info_paths.yaml (operator-editable).
    # This inline copy is the fallback if missing.
    _FALLBACK_MODEL_PATHS = [
        "/v1/models",
        "/models",
        "/model/info",
        "/model-info",
        "/api/models",
        "/api/v1/models",
        "/api/tags",
        "/api/show",
        "/internal/model-admin",
        "/debug/model",
        "/admin/models",
        "/health",
        "/version",
        "/info",
        "/config",
        "/api/config",
        "/settings",
    ]
    MODEL_PATHS = load_data("endpoints/model_info_paths.yaml", _FALLBACK_MODEL_PATHS)

    SENSITIVE_FIELDS = [
        "api_key",
        "secret",
        "token",
        "password",
        "credential",
        "system_prompt",
        "base_prompt",
        "instruction",
        "internal",
        "private",
        "cost",
        "billing",
    ]

    HIGH_SEVERITY_PATH_KEYWORDS = ["internal", "admin", "debug"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        probed: list[Exchange] = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.MODEL_PATHS:
                    url = service.with_path(path)
                    resp = await client.get(url)

                    exchange = exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host
                    )
                    probed.append(exchange)

                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=_discriminator(self.name, service.host, path),
                        target=service,
                        target_url=url,
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # `model_info_{port}` is the last disclosing path's details, which is
        # what the original produced — it assigned the output inside the loop,
        # so the final iteration won. Preserved rather than tidied: a check
        # migration is not the place to change an output's meaning.
        for exchange in probed:
            if self._discloses(exchange):
                result.outputs[f"model_info_{service.port}"] = self._model_details(exchange)

        return result

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one recorded model-info response.

        The whole ladder from before the split, unchanged: `medium` by default,
        `high` if the path name says internal/admin/debug, `high` if the body
        carries anything from `SENSITIVE_FIELDS`.
        """
        exchange = next(iter(evidence.completed()), None)
        if exchange is None or not self._discloses(exchange):
            return []

        path = urlparse(exchange.request_url).path or "/"
        url = exchange.request_url or ""
        body = exchange.response_body or ""
        status = exchange.response_status

        severity = "medium"
        if any(kw in path.lower() for kw in self.HIGH_SEVERITY_PATH_KEYWORDS):
            severity = "high"

        sensitive_found: list[str] = []
        details = self._model_details(exchange)
        data = safe_json(body)
        if data is not None:
            body_str = str(data).lower()
            for field in self.SENSITIVE_FIELDS:
                if field in body_str:
                    sensitive_found.append(field)
                    severity = "high"

        text = fmt_endpoint_evidence(url, status)
        if sensitive_found:
            text += f" | Sensitive fields: {', '.join(sensitive_found)}"
        if details.get("model_id"):
            text += f" | Model: {details['model_id']}"

        confidence, why = self._confidence_for(path, data, details, sensitive_found)

        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=_discriminator(ctx.check_name, ctx.host, path),
                title=f"Model info endpoint: {path}",
                description="Endpoint exposes model information and configuration",
                evidence=text,
                reasoning=why,
                signals={
                    "path": path,
                    "sensitive_fields": sensitive_found,
                    "model_id": details.get("model_id", ""),
                    "parsed_json": data is not None,
                },
                references=["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure"],
                raw_data={
                    "model_details": details,
                    "sensitive_fields": sensitive_found,
                    "response_preview": body[:500],
                },
                evidence_ids=[exchange.id],
            )
        ]

    # ── Shared readings ──────────────────────────────────────────────

    def _discloses(self, exchange: Exchange) -> bool:
        """The original gate: a 200 and no transport error. Nothing else."""
        return not exchange.error and exchange.response_status == 200

    def _model_details(self, exchange: Exchange) -> dict:
        """The `model_details` dict, parsed off a recorded body."""
        details: dict[str, Any] = {}
        data = safe_json(exchange.response_body or "")
        if data is None:
            return details

        if isinstance(data, dict):
            details = {
                "models": data.get("data", data.get("models", [])),
                "model_id": data.get("model_id", data.get("model", "")),
                "version": data.get("version", ""),
                "max_tokens": data.get("max_tokens", data.get("max_model_len", "")),
                "context_length": data.get("context_length", ""),
            }
        elif isinstance(data, list):
            details["models"] = data
        return details

    def _confidence_for(
        self,
        path: str,
        data: Any,
        details: dict,
        sensitive_found: list[str],
    ) -> tuple[float, str]:
        """How sure the disclosure claim is, and why it is not 1.0.

        Two independent weaknesses, and the sensitive-field scan is the louder
        one. It lowercases `str(data)` — the whole parsed structure, keys and
        values together — and asks whether any of twelve words appears
        anywhere in it. `token` matches `max_tokens`; `cost` matches
        `costa_rica`; `instruction` matches an `instruction_format` field
        describing a prompt template rather than containing one. Every one of
        those escalates the severity to `high`, so a verdict resting only on
        that scan says how thin it is.

        The second is the path list. `/health`, `/version` and `/info` are
        generic endpoints on any service, and a 200 there is not model
        disclosure at all unless something model-shaped came back — which is
        what `model_details` is read for.
        """
        model_shaped = bool(
            details.get("model_id") or details.get("models") or details.get("context_length")
        )
        generic_path = path.lower().rstrip("/").split("/")[-1] in ("health", "version", "info")
        weak_hits = [
            f for f in sensitive_found if f in ("token", "cost", "instruction", "internal")
        ]

        if data is None:
            return 0.3, (
                "the body is not JSON, so nothing was parsed — the 200 alone is all this rests on"
            )
        if sensitive_found and weak_hits == sensitive_found:
            return 0.4, (
                f"the only sensitive-field hits are {', '.join(weak_hits)}, matched as substrings "
                "anywhere in the stringified body — `token` also matches `max_tokens`, `cost` "
                "matches a field name, and each of them escalated this to high"
            )
        if sensitive_found and model_shaped:
            return 0.9, (
                f"model fields and {len(sensitive_found)} sensitive field name(s) in one parsed "
                "JSON response"
            )
        if model_shaped:
            return 0.85, "the parsed response carries model identity or capacity fields"
        if generic_path:
            return 0.35, (
                f"HTTP 200 with JSON on {path}, a generic endpoint any service exposes, and "
                "nothing model-shaped in the body"
            )
        return 0.6, ("JSON came back on a model-info path but carried no recognisable model fields")


def _discriminator(check_name: str, host: str, path: str) -> str:
    """`info-endpoint` plus the digest `make_observation_id_hashed` appends.

    Reproduced here rather than called, because the grading stage builds ids
    with `make_observation_id` — putting the digest in the discriminator makes
    the two spellings land on the same id, which is what keeps this check's
    observation ids stable across the migration.
    """
    payload = f"{check_name}:{host}:info-endpoint:{path}"
    return f"info-endpoint-{hashlib.sha256(payload.encode()).hexdigest()[:4]}"
