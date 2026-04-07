"""
app/checks/web/config_exposure.py - Exposed Configuration File Analysis

When path_probe finds .env, config.json, etc. returning 200,
this check fetches and parses for secrets (API keys, DB creds, etc.).
Secret values are NEVER stored — only redacted evidence.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig


class ConfigExposureCheck(ServiceIteratingCheck):
    """Analyze accessible configuration files for exposed secrets."""

    name = "config_exposure"
    description = "Parse accessible config files (.env, config.json, etc.) for secrets"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["config_observations"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

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

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        accessible = self._get_accessible_paths(service, context)
        config_paths = [
            p
            for p in accessible
            if any(p.endswith(c.lstrip("/")) or p == c for c in self.CONFIG_PATHS)
        ]

        if not config_paths:
            # Also try probing common config paths directly
            config_paths = await self._probe_config_paths(service)

        if not config_paths:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in config_paths:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    secrets_found = self._scan_for_secrets(resp.body)

                    if secrets_found:
                        # Group by severity
                        secret_names = [s[0] for s in secrets_found]
                        max_severity = (
                            "critical" if any(s[2] == "critical" for s in secrets_found) else "high"
                        )

                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Configuration file contains secrets: {path} at {service.host}",
                                description=f"{len(secrets_found)} secret pattern(s) detected in {path}",
                                severity=max_severity,
                                evidence=f"Secrets detected (redacted): {', '.join(secret_names[:10])}",
                                host=service.host,
                                discriminator=f"secrets-{path.replace('/', '-').strip('-')}",
                                target=service,
                                target_url=url,
                                raw_data={
                                    "path": path,
                                    "secret_types": secret_names,
                                    "count": len(secrets_found),
                                },
                            )
                        )
                    else:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Configuration file accessible: {path} at {service.host}",
                                description=f"Config file {path} is publicly accessible (no secrets detected but internal config exposed)",
                                severity="high",
                                evidence=f"GET {url} -> 200 ({len(resp.body)} bytes, no secret patterns matched)",
                                host=service.host,
                                discriminator=f"config-accessible-{path.replace('/', '-').strip('-')}",
                                target=service,
                                target_url=url,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

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

    async def _probe_config_paths(self, service: Service) -> list[str]:
        """Probe common config paths if path_probe didn't cover them."""
        accessible = []
        cfg = HttpConfig(timeout_seconds=5.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in ["/.env", "/config.json", "/config.yaml", "/settings.json"]:
                    resp = await client.get(service.with_path(path))
                    if not resp.error and resp.status_code == 200:
                        accessible.append(path)
        except Exception:
            pass
        return accessible

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
