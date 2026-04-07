"""
app/checks/web/directory_listing.py - Directory Listing Detection

Checks for enabled directory listing (autoindex) on discovered paths.
Detects Apache, nginx, IIS, and Python SimpleHTTPServer signatures.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.evidence import fmt_status_evidence
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig


class DirectoryListingCheck(ServiceIteratingCheck):
    """Detect enabled directory listing on HTTP services."""

    name = "directory_listing"
    description = "Check for enabled directory listing (autoindex) on discovered paths"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["directory_listing_observations"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Directory listing exposes the full filesystem structure including model files, training data, and configs"
    references = ["OWASP WSTG-CONF-04", "CWE-548"]
    techniques = ["directory listing detection", "information disclosure"]

    # Patterns that indicate directory listing is enabled
    LISTING_PATTERNS = [
        re.compile(r"Index of /", re.I),
        re.compile(r"Directory listing for /", re.I),
        re.compile(r"<title>\s*Directory listing", re.I),
        re.compile(r"\[To Parent Directory\]", re.I),  # IIS
        re.compile(r"<h1>Directory Listing</h1>", re.I),
        re.compile(r"SimpleHTTP", re.I),  # Python SimpleHTTPServer
    ]

    # Sensitive file extensions in listings
    SENSITIVE_EXTENSIONS = [
        ".py",
        ".env",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".conf",
        ".cfg",
        ".key",
        ".pem",
        ".sql",
        ".db",
        ".sqlite",
        ".pt",
        ".onnx",
        ".safetensors",
        ".pkl",
        ".h5",  # Model files
        ".bak",
        ".old",
        ".backup",
    ]

    # Paths to check for directory listing
    PROBE_PATHS = ["/", "/static/", "/assets/", "/uploads/", "/data/", "/models/", "/backup/"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Combine probe paths with any paths from path_probe
        paths_to_check = list(self.PROBE_PATHS)
        accessible = self._get_accessible_paths(service, context)
        for p in accessible:
            if p.endswith("/") and p not in paths_to_check:
                paths_to_check.append(p)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in paths_to_check:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    if not self._is_directory_listing(resp.body):
                        continue

                    # Analyze what's visible in the listing
                    sensitive_files = self._find_sensitive_files(resp.body)
                    is_root = path == "/"

                    if is_root:
                        severity = "high"
                        title = f"Directory listing at root: {service.host}"
                    elif sensitive_files:
                        severity = "high"
                        title = f"Directory listing with sensitive files: {service.host}{path}"
                    else:
                        severity = "medium"
                        title = f"Directory listing enabled: {service.host}{path}"

                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=title,
                            description=f"Directory listing enabled at {path}"
                            + (
                                f" — sensitive files visible: {', '.join(sensitive_files[:5])}"
                                if sensitive_files
                                else ""
                            ),
                            severity=severity,
                            evidence=fmt_status_evidence(url, 200, resp.body[:300]),
                            host=service.host,
                            discriminator=f"listing-{path.replace('/', '-').strip('-') or 'root'}",
                            target=service,
                            target_url=url,
                            raw_data={
                                "path": path,
                                "sensitive_files": sensitive_files[:20],
                            },
                        )
                    )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    def _is_directory_listing(self, body: str) -> bool:
        """Check if response body contains directory listing signatures."""
        return any(p.search(body) for p in self.LISTING_PATTERNS)

    def _find_sensitive_files(self, body: str) -> list[str]:
        """Extract sensitive filenames from a directory listing."""
        sensitive = []
        # Look for href or filename patterns
        for ext in self.SENSITIVE_EXTENSIONS:
            matches = re.findall(rf'href="([^"]*{re.escape(ext)}[^"]*)"', body, re.I)
            sensitive.extend(matches)
        return list(dict.fromkeys(sensitive))[:20]  # Dedupe, cap at 20

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
