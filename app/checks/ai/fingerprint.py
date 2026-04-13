"""
app/checks/ai/fingerprint.py - AI Framework Fingerprinting

Identify the AI/ML framework powering a service.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation
from app.lib.parsing import extract_headers_dict


class AIFrameworkFingerprintCheck(ServiceIteratingCheck):
    """Fingerprint AI/ML frameworks from response characteristics."""

    name = "ai_framework_fingerprint"
    description = "Identify AI framework (vLLM, Ollama, LangChain, etc.) from responses"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["ai_framework"]
    service_types = ["ai", "api"]

    timeout_seconds = 30.0

    reason = "Knowing the AI framework enables targeted attacks against known vulnerabilities"
    references = ["MITRE ATLAS - ML Supply Chain Compromise"]
    techniques = ["fingerprinting", "technology identification", "version detection"]

    FRAMEWORK_SIGNATURES = {
        "vllm": {
            "headers": ["x-vllm", "vllm"],
            "body_patterns": [r"vllm", r"vllm_version"],
            "endpoints": ["/v1/models", "/v1/completions"],
            "error_patterns": [r"vLLM", r"AsyncLLMEngine"],
        },
        "ollama": {
            "headers": ["x-ollama"],
            "body_patterns": [r"ollama", r"modelfile"],
            "endpoints": ["/api/generate", "/api/tags", "/api/show"],
            "error_patterns": [r"ollama", r"Modelfile"],
        },
        "langserve": {
            "headers": ["x-langserve"],
            "body_patterns": [r"langserve", r"langchain"],
            "endpoints": ["/invoke", "/stream", "/batch", "/input_schema"],
            "error_patterns": [r"LangServe", r"LangChain", r"RunnableSequence"],
        },
        "huggingface_tgi": {
            "headers": ["x-inference-time"],
            "body_patterns": [r"text-generation-inference", r"generated_text"],
            "endpoints": ["/generate", "/generate_stream", "/info"],
            "error_patterns": [r"TGI", r"text-generation-inference"],
        },
        "triton": {
            "headers": ["x-triton"],
            "body_patterns": [r"triton", r"nvidia"],
            "endpoints": ["/v2/models", "/v2/health"],
            "error_patterns": [r"Triton", r"NVIDIA"],
        },
        "openai_compatible": {
            "headers": [],
            "body_patterns": [r'"object":\s*"(chat\.completion|list)"'],
            "endpoints": ["/v1/chat/completions", "/v1/models"],
            "error_patterns": [r"invalid_api_key", r"invalid_request_error"],
        },
        "fastapi_ml": {
            "headers": [],
            "body_patterns": [r"fastapi", r"starlette"],
            "endpoints": ["/docs", "/openapi.json", "/predict"],
            "error_patterns": [r"FastAPI", r"RequestValidationError"],
        },
        "gradio": {
            "headers": [],
            "body_patterns": [r"gradio", r"__gradio"],
            "endpoints": ["/api/predict", "/queue/join"],
            "error_patterns": [r"gradio", r"Gradio"],
        },
        "streamlit": {
            "headers": ["x-streamlit"],
            "body_patterns": [r"streamlit", r"_stcore"],
            "endpoints": ["/_stcore/health", "/_stcore/stream"],
            "error_patterns": [r"streamlit", r"Streamlit"],
        },
    }

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                evidence = await self._gather_evidence(client, service)

            confidence_scores = {}

            for framework, sigs in self.FRAMEWORK_SIGNATURES.items():
                score = 0
                matches = []

                for header_pattern in sigs["headers"]:
                    if any(header_pattern.lower() in h for h in evidence["headers"]):
                        score += 3
                        matches.append(f"header: {header_pattern}")

                for pattern in sigs["body_patterns"]:
                    if re.search(pattern, evidence["body"], re.I):
                        score += 2
                        matches.append(f"body: {pattern}")

                for endpoint in sigs["endpoints"]:
                    if endpoint in evidence["accessible_endpoints"]:
                        score += 2
                        matches.append(f"endpoint: {endpoint}")

                for pattern in sigs["error_patterns"]:
                    if re.search(pattern, evidence["errors"], re.I):
                        score += 2
                        matches.append(f"error: {pattern}")

                if score > 0:
                    confidence_scores[framework] = {"score": score, "matches": matches}

            if confidence_scores:
                best = max(confidence_scores, key=lambda k: confidence_scores[k]["score"])
                best_score = confidence_scores[best]["score"]

                if best_score >= 3:
                    confidence = (
                        "high" if best_score >= 6 else "medium" if best_score >= 4 else "low"
                    )

                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"AI framework identified: {best}",
                            description=f"Service appears to be running {best} ({confidence} confidence)",
                            severity="medium",
                            evidence=f"Matches: {', '.join(confidence_scores[best]['matches'][:5])}",
                            host=service.host,
                            discriminator=f"framework-{best}",
                            target=service,
                            raw_data={
                                "framework": best,
                                "confidence": confidence,
                                "score": best_score,
                                "all_scores": confidence_scores,
                            },
                        )
                    )

                    result.outputs[f"ai_framework_{service.port}"] = {
                        "framework": best,
                        "confidence": confidence,
                        "all_detected": list(confidence_scores.keys()),
                    }

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _gather_evidence(self, client: AsyncHttpClient, service: Service) -> dict:
        evidence = {"headers": [], "body": "", "accessible_endpoints": [], "errors": ""}

        resp = await client.get(service.url)
        if not resp.error:
            evidence["headers"] = list(extract_headers_dict(resp.headers).keys())
            evidence["body"] = resp.body[:5000]

        test_endpoints = [
            "/v1/models",
            "/api/tags",
            "/info",
            "/health",
            "/docs",
            "/invoke",
            "/generate",
            "/_stcore/health",
            "/v2/health",
        ]
        for endpoint in test_endpoints:
            resp = await client.get(service.with_path(endpoint))
            if not resp.error and resp.status_code < 500:
                evidence["accessible_endpoints"].append(endpoint)
                evidence["body"] += resp.body[:1000]

        err_resp = await client.post(
            service.url,
            json={"invalid": "request"},
            headers={"Content-Type": "application/json"},
        )
        if not err_resp.error and err_resp.status_code >= 400:
            evidence["errors"] = err_resp.body[:2000]

        return evidence
