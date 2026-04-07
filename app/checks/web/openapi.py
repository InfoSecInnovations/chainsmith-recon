"""
app/checks/web/openapi.py - OpenAPI/Swagger Discovery

Find and analyze exposed API documentation.
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation
from app.lib.parsing import extract_headers_dict, extract_paths_from_openapi, safe_json


class OpenAPICheck(ServiceIteratingCheck):
    """Discover and analyze OpenAPI/Swagger documentation."""

    name = "openapi_discovery"
    description = "Find exposed API documentation and extract endpoint information"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["api_endpoints", "openapi_specs"]
    service_types = ["http", "api", "ai"]

    timeout_seconds = 30.0

    reason = "OpenAPI docs reveal all API endpoints, parameters, auth mechanisms, and data models"
    references = ["OWASP API Security Top 10", "OWASP API1:2023", "OpenAPI Specification"]
    techniques = ["API enumeration", "documentation discovery"]

    OPENAPI_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/v1/openapi.json",
        "/docs/openapi.json",
        "/api-docs",
        "/swagger",
        "/docs",
        "/redoc",
        "/api/docs",
        "/api/v1/docs",
        "/swagger-ui.html",
    ]

    SENSITIVE_PATH_KEYWORDS = ["admin", "internal", "debug", "config", "user", "auth"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.OPENAPI_PATHS:
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200:
                        continue

                    headers_lower = extract_headers_dict(resp.headers)
                    content_type = headers_lower.get("content-type", "")

                    if "json" in content_type:
                        spec = safe_json(resp.body)
                        if spec and isinstance(spec, dict):
                            if "openapi" in spec or "swagger" in spec or "paths" in spec:
                                endpoints = extract_paths_from_openapi(spec)

                                security_schemes = list(
                                    spec.get("components", {}).get("securitySchemes", {}).keys()
                                ) or list(spec.get("securityDefinitions", {}).keys())

                                sensitive = [
                                    e
                                    for e in endpoints
                                    if any(kw in e.lower() for kw in self.SENSITIVE_PATH_KEYWORDS)
                                ]

                                severity = "high" if sensitive else "medium"
                                endpoint_preview = ", ".join(endpoints[:5])
                                if len(endpoints) > 5:
                                    endpoint_preview += "..."

                                result.observations.append(
                                    build_observation(
                                        check_name=self.name,
                                        title=f"OpenAPI documentation exposed ({len(endpoints)} endpoints)",
                                        description="API documentation reveals endpoint structure and attack surface",
                                        severity=severity,
                                        evidence=f"Spec at {path} | Endpoints include: {endpoint_preview}",
                                        host=service.host,
                                        discriminator="spec-exposed",
                                        target=service,
                                        target_url=url,
                                        raw_data={
                                            "endpoints": endpoints,
                                            "sensitive_endpoints": sensitive,
                                            "security_schemes": security_schemes,
                                            "spec_path": path,
                                        },
                                        references=["OWASP API1:2023"],
                                    )
                                )

                                result.outputs[f"openapi_{service.port}"] = {
                                    "url": url,
                                    "endpoints": endpoints,
                                    "spec": spec,
                                }
                                return result  # First spec found wins

                    elif "html" in content_type:
                        body_lower = resp.body.lower()
                        if any(kw in body_lower for kw in ["swagger", "openapi", "redoc"]):
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"API documentation UI at {path}",
                                    description="Interactive API documentation is accessible",
                                    severity="low",
                                    evidence=f"Swagger/OpenAPI UI found at {path}",
                                    host=service.host,
                                    discriminator=f"ui-{path.strip('/').replace('/', '-')}",
                                    target=service,
                                    target_url=url,
                                )
                            )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result
