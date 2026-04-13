"""
Service Probing Checks

Deep inspection of discovered services to determine type and gather fingerprints.
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig


class ServiceProbeCheck(ServiceIteratingCheck):
    """
    Probe discovered services to determine their type.

    Performs deep inspection:
    - HTTP vs HTTPS detection
    - Content type analysis
    - Header fingerprinting
    - AI/ML service detection
    """

    name = "service_probe"
    description = "Probe services to determine type and gather initial fingerprints"

    conditions = [
        CheckCondition("services", "truthy"),
    ]

    produces = ["services", "services_probed"]  # Enriches existing services

    timeout_seconds = 60.0
    sequential = True
    delay_between_targets = 0.2

    # Educational
    reason = "Understanding service types guides which checks to run next"
    references = ["OWASP WSTG-INFO-02"]
    techniques = ["service fingerprinting", "banner grabbing", "HTTP fingerprinting"]

    # Headers that indicate AI/ML services
    AI_HEADERS = ["x-model", "x-inference", "x-llm", "x-ai-", "x-ml-"]

    AI_POWERED_BY = [
        "vllm",
        "ollama",
        "tgi",
        "triton",
        "inference",
        "mlflow",
        "huggingface",
        "transformers",
        "langchain",
        "langserve",
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        # Signal to downstream discovery checks that classification has run,
        # so they don't race ahead and see service_type="unknown".
        result.outputs["services_probed"] = True

        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{service.host}:{service.port}"

            try:
                async with AsyncHttpClient(
                    HttpConfig(timeout_seconds=10.0, verify_ssl=False)
                ) as client:
                    response = await client.get(url)

                    # Check if request actually succeeded (HTTP client returns error in response, not exception)
                    if response.error:
                        result.errors.append(f"{url}: {response.error}")
                        continue

                    # Connection succeeded — now safe to update service
                    service.scheme = scheme
                    service.url = url

                    headers = dict(response.headers)
                    content_type = headers.get("content-type", "").lower()

                    # Store headers in metadata for later checks
                    service.metadata["headers"] = headers
                    service.metadata["status_code"] = response.status_code
                    service.metadata["content_type"] = content_type

                    # Determine service type
                    service.service_type = self._classify_service(
                        headers, content_type, response.body[:2000]
                    )

                    # Create observations for interesting discoveries
                    observations = self._analyze_response(service, headers, response)
                    result.observations.extend(observations)

                    result.services.append(service)
                    return result

            except Exception as e:
                result.errors.append(f"{url}: {e}")
                continue

        # Couldn't connect via HTTP(S) — preserve original scheme/url
        service.service_type = "tcp"
        result.services.append(service)
        return result

    def _classify_service(self, headers: dict, content_type: str, body: str) -> str:
        """Classify service type based on response characteristics."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()

        # Check for AI/ML indicators first
        for header in self.AI_HEADERS:
            if any(header in k for k in headers_lower):
                return "ai"

        powered_by = headers_lower.get("x-powered-by", "")
        server = headers_lower.get("server", "")

        for ai_tech in self.AI_POWERED_BY:
            if ai_tech in powered_by or ai_tech in server:
                return "ai"

        # Check body for AI indicators
        ai_body_indicators = [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "chatbot",
            "llm",
            "inference",
            "model",
            "/api/generate",
        ]
        if any(ind in body_lower for ind in ai_body_indicators):
            return "ai"

        # Check content type
        if "text/html" in content_type:
            return "html"
        elif "application/json" in content_type:
            # Could be API or AI - look for more clues
            if any(kw in body_lower for kw in ["openapi", "swagger"]):
                return "api"
            return "api"

        return "http"

    def _analyze_response(self, service: Service, headers: dict, response) -> list:
        """Extract observations from initial response."""
        observations = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Server header
        if "server" in headers_lower:
            server_value = headers_lower["server"]
            # Check if version info is present
            if any(c.isdigit() for c in server_value):
                observations.append(
                    self.create_observation(
                        title=f"Server version disclosed: {server_value}",
                        description="Server header reveals version information that could aid targeted attacks",
                        severity="low",
                        evidence=f"Server: {server_value}",
                        target=service,
                        references=["CWE-200"],
                    )
                )

        # X-Powered-By
        if "x-powered-by" in headers_lower:
            value = headers_lower["x-powered-by"]
            severity = "low"

            # Higher severity for AI/ML tech disclosure
            if any(ai in value.lower() for ai in self.AI_POWERED_BY):
                severity = "medium"

            observations.append(
                self.create_observation(
                    title=f"Technology disclosed: {value}",
                    description="X-Powered-By header reveals technology stack",
                    severity=severity,
                    evidence=f"X-Powered-By: {value}",
                    target=service,
                    references=["CWE-200"],
                )
            )

        # Custom headers (potential info leaks)
        standard_headers = {
            "x-powered-by",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "x-request-id",
            "x-correlation-id",
            "x-cache",
            "x-cache-hits",
            "x-served-by",
        }

        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower.startswith("x-") and key_lower not in standard_headers:
                severity = "info"
                if any(
                    s in key_lower for s in ["model", "token", "key", "secret", "internal", "debug"]
                ):
                    severity = "medium"

                observations.append(
                    self.create_observation(
                        title=f"Custom header: {key}",
                        description="Custom header may leak internal information",
                        severity=severity,
                        evidence=f"{key}: {value[:100]}",
                        target=service,
                    )
                )

        return observations
