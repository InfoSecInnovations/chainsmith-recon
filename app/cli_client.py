"""
app/cli_client.py - HTTP client for CLI → API communication

Synchronous httpx wrapper around all Chainsmith API endpoints.
Returns raw dicts (parsed JSON).
"""

import time
from collections.abc import Callable

import httpx


class ChainsmithAPIError(Exception):
    """Raised when an API call returns an error status."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


class ChainsmithClient:
    """Synchronous HTTP client for the Chainsmith API."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)

    def close(self):
        self._client.close()

    def _request(self, method: str, path: str, **kwargs) -> dict:
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text
            try:
                body = resp.json()
                detail = body.get("detail", detail)
            except Exception:
                pass
            raise ChainsmithAPIError(resp.status_code, detail)
        return resp.json()

    def _request_raw(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make a request and return the raw response (for binary content like PDF)."""
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text
            try:
                body = resp.json()
                detail = body.get("detail", detail)
            except Exception:
                pass
            raise ChainsmithAPIError(resp.status_code, detail)
        return resp

    # ─── Health ───────────────────────────────────────────────

    def health(self) -> dict:
        return self._request("GET", "/health")

    # ─── Scope ────────────────────────────────────────────────

    def set_scope(
        self, target: str, exclude: list[str] = None, techniques: list[str] = None
    ) -> dict:
        return self._request(
            "POST",
            "/api/v1/scope",
            json={
                "target": target,
                "exclude": exclude or [],
                "techniques": techniques or [],
            },
        )

    def get_scope(self) -> dict:
        return self._request("GET", "/api/v1/scope")

    # ─── Settings ─────────────────────────────────────────────

    def update_settings(
        self,
        parallel: bool = False,
        rate_limit: float = 10.0,
        default_techniques: list[str] = None,
    ) -> dict:
        return self._request(
            "POST",
            "/api/v1/settings",
            json={
                "parallel": parallel,
                "rate_limit": rate_limit,
                "default_techniques": default_techniques or [],
            },
        )

    def get_settings(self) -> dict:
        return self._request("GET", "/api/v1/settings")

    # ─── Scan ─────────────────────────────────────────────────

    def start_scan(
        self,
        checks: list[str] = None,
        suites: list[str] = None,
        engagement_id: str = None,
        port_profile: str = None,
    ) -> dict:
        body: dict = {}
        if checks:
            body["checks"] = checks
        if suites:
            body["suites"] = suites
        if engagement_id:
            body["engagement_id"] = engagement_id
        if port_profile:
            body["port_profile"] = port_profile
        return self._request("POST", "/api/v1/scan", json=body if body else None)

    def get_scan_status(self) -> dict:
        return self._request("GET", "/api/v1/scan")

    def get_scan_checks(self) -> dict:
        return self._request("GET", "/api/v1/scan/checks")

    def poll_scan(
        self, interval: float = 1.0, callback: Callable[[dict], None] | None = None
    ) -> dict:
        """Poll GET /api/v1/scan until status is 'complete' or 'error'."""
        while True:
            status = self.get_scan_status()
            if callback:
                callback(status)
            if status.get("status") in ("complete", "error"):
                return status
            time.sleep(interval)

    # ─── Observations ─────────────────────────────────────────

    def get_observations(self) -> dict:
        return self._request("GET", "/api/v1/observations")

    # ─── Checks ───────────────────────────────────────────────

    def get_checks(self) -> dict:
        return self._request("GET", "/api/v1/checks")

    def get_check(self, name: str) -> dict:
        return self._request("GET", f"/api/v1/checks/{name}")

    # ─── Chains ───────────────────────────────────────────────

    def start_chain_analysis(self) -> dict:
        return self._request("POST", "/api/v1/chains/analyze")

    def retry_chain_analysis(self) -> dict:
        return self._request("POST", "/api/v1/chains/retry")

    def get_chains(self) -> dict:
        return self._request("GET", "/api/v1/chains")

    # ─── Scenarios ────────────────────────────────────────────

    def list_scenarios(self) -> dict:
        return self._request("GET", "/api/v1/scenarios")

    def load_scenario(self, name: str) -> dict:
        return self._request("POST", "/api/v1/scenarios/load", json={"name": name})

    def clear_scenario(self) -> dict:
        return self._request("POST", "/api/v1/scenarios/clear")

    def get_current_scenario(self) -> dict:
        return self._request("GET", "/api/v1/scenarios/current")

    # ─── Preferences ─────────────────────────────────────────

    def get_preferences(self) -> dict:
        return self._request("GET", "/api/v1/preferences")

    def update_preferences(self, updates: dict) -> dict:
        return self._request("PUT", "/api/v1/preferences", json=updates)

    # ─── Profiles ─────────────────────────────────────────────

    def list_profiles(self) -> dict:
        return self._request("GET", "/api/v1/profiles")

    def get_profile(self, name: str) -> dict:
        return self._request("GET", f"/api/v1/profiles/{name}")

    def create_profile(self, name: str, description: str = "", base: str | None = None) -> dict:
        body: dict = {"name": name, "description": description}
        if base:
            body["base"] = base
        return self._request("POST", "/api/v1/profiles", json=body)

    def delete_profile(self, name: str) -> dict:
        return self._request("DELETE", f"/api/v1/profiles/{name}")

    def activate_profile(self, name: str) -> dict:
        return self._request("PUT", f"/api/v1/profiles/{name}/activate")

    def reset_profile(self, name: str) -> dict:
        return self._request("POST", f"/api/v1/profiles/{name}/reset")

    def resolve_profile(self, name: str) -> dict:
        return self._request("GET", f"/api/v1/profiles/{name}/resolve")

    # ─── Scan History ────────────────────────────────────────

    def list_scans(
        self, target: str = None, status: str = None, engagement_id: str = None, limit: int = 50
    ) -> dict:
        params = {"limit": limit}
        if target:
            params["target"] = target
        if status:
            params["status"] = status
        if engagement_id:
            params["engagement_id"] = engagement_id
        return self._request("GET", "/api/v1/scans", params=params)

    def get_scan_detail(self, scan_id: str) -> dict:
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def get_scan_observations(self, scan_id: str) -> dict:
        return self._request("GET", f"/api/v1/scans/{scan_id}/observations")

    def delete_scan_by_id(self, scan_id: str) -> dict:
        return self._request("DELETE", f"/api/v1/scans/{scan_id}")

    def compare_scans(self, scan_a: str, scan_b: str) -> dict:
        return self._request("GET", f"/api/v1/scans/{scan_a}/compare/{scan_b}")

    # ─── Engagements ─────────────────────────────────────────

    def list_engagements(self) -> dict:
        return self._request("GET", "/api/v1/engagements")

    def create_engagement(
        self, name: str, target_domain: str, description: str = None, client_name: str = None
    ) -> dict:
        body = {"name": name, "target_domain": target_domain}
        if description:
            body["description"] = description
        if client_name:
            body["client_name"] = client_name
        return self._request("POST", "/api/v1/engagements", json=body)

    def get_engagement(self, engagement_id: str) -> dict:
        return self._request("GET", f"/api/v1/engagements/{engagement_id}")

    def delete_engagement(self, engagement_id: str) -> dict:
        return self._request("DELETE", f"/api/v1/engagements/{engagement_id}")

    def get_engagement_scans(self, engagement_id: str) -> dict:
        return self._request("GET", f"/api/v1/engagements/{engagement_id}/scans")

    def get_engagement_trend(self, engagement_id: str) -> dict:
        return self._request("GET", f"/api/v1/engagements/{engagement_id}/trend")

    def get_target_trend(self, target_domain: str) -> dict:
        return self._request("GET", f"/api/v1/targets/{target_domain}/trend")

    # ─── Observation Overrides ────────────────────────────────

    def set_observation_override(self, fingerprint: str, status: str, reason: str = None) -> dict:
        body = {"status": status}
        if reason:
            body["reason"] = reason
        return self._request("PUT", f"/api/v1/observations/{fingerprint}/override", json=body)

    def remove_observation_override(self, fingerprint: str) -> dict:
        return self._request("DELETE", f"/api/v1/observations/{fingerprint}/override")

    def list_observation_overrides(self, status: str = None) -> dict:
        params = {}
        if status:
            params["status"] = status
        return self._request("GET", "/api/v1/observations/overrides", params=params)

    # ─── Reports ─────────────────────────────────────────────

    def _report_request(self, path: str, payload: dict, fmt: str) -> dict:
        """Request a report. For PDF, returns raw bytes in content field."""
        if fmt == "pdf":
            resp = self._request_raw("POST", path, json=payload)
            disp = resp.headers.get("content-disposition", "")
            filename = "report.pdf"
            if 'filename="' in disp:
                filename = disp.split('filename="')[1].rstrip('"')
            return {"content": resp.content, "filename": filename, "format": "pdf"}
        return self._request("POST", path, json=payload)

    def generate_technical_report(self, scan_id: str, fmt: str = "md") -> dict:
        return self._report_request(
            "/api/v1/reports/technical", {"scan_id": scan_id, "format": fmt}, fmt
        )

    def generate_delta_report(self, scan_a_id: str, scan_b_id: str, fmt: str = "md") -> dict:
        return self._report_request(
            "/api/v1/reports/delta",
            {"scan_a_id": scan_a_id, "scan_b_id": scan_b_id, "format": fmt},
            fmt,
        )

    def generate_executive_report(
        self, scan_id: str, fmt: str = "md", engagement_id: str = None
    ) -> dict:
        payload = {"scan_id": scan_id, "format": fmt}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        return self._report_request("/api/v1/reports/executive", payload, fmt)

    def generate_compliance_report(
        self, scan_id: str, fmt: str = "md", engagement_id: str = None
    ) -> dict:
        payload = {"scan_id": scan_id, "format": fmt}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        return self._report_request("/api/v1/reports/compliance", payload, fmt)

    def generate_trend_report(
        self, fmt: str = "md", engagement_id: str = None, target: str = None
    ) -> dict:
        payload = {"format": fmt}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        if target:
            payload["target"] = target
        return self._report_request("/api/v1/reports/trend", payload, fmt)

    # ─── Export ───────────────────────────────────────────────

    def export_report(self) -> dict:
        return self._request("POST", "/api/v1/export")

    # ─── Reset ────────────────────────────────────────────────

    def reset(self) -> dict:
        return self._request("POST", "/api/v1/reset")
