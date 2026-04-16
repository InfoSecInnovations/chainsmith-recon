"""
tests/test_preferences_api.py - Tests for preferences and profiles REST API endpoints
"""

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def prefs_env(tmp_path, monkeypatch):
    """Set up isolated preferences environment."""
    prefs_path = tmp_path / "preferences.yaml"
    monkeypatch.setenv("CHAINSMITH_PREFERENCES_PATH", str(prefs_path))

    import app.preferences as prefs_module

    prefs_module._profile_store = None

    yield prefs_path

    prefs_module._profile_store = None


@pytest.fixture
def client(prefs_env, monkeypatch):
    """Create test client with mocked static files."""
    from unittest.mock import MagicMock

    import fastapi.staticfiles

    def mock_init(self, *args, **kwargs):
        pass

    monkeypatch.setattr(fastapi.staticfiles.StaticFiles, "__init__", mock_init)
    monkeypatch.setattr(fastapi.staticfiles.StaticFiles, "__call__", MagicMock())

    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


class TestPreferencesEndpoints:
    def test_get_preferences(self, client):
        response = client.get("/api/v1/preferences")
        assert response.status_code == 200
        data = response.json()
        assert data["active_profile"] == "default"
        assert data["preferences"]["network"]["timeout_seconds"] == 30.0

    def test_update_preferences(self, client):
        response = client.put("/api/v1/preferences", json={"network": {"timeout_seconds": 99.0}})
        assert response.status_code == 200
        assert response.json()["preferences"]["network"]["timeout_seconds"] == 99.0


class TestProfilesList:
    def test_list_profiles(self, client):
        response = client.get("/api/v1/profiles")
        assert response.status_code == 200
        names = [p["name"] for p in response.json()["profiles"]]
        assert "default" in names
        assert "aggressive" in names
        assert "stealth" in names

    def test_get_profile(self, client):
        response = client.get("/api/v1/profiles/aggressive")
        assert response.status_code == 200
        prefs = response.json()["resolved_preferences"]
        assert prefs["network"]["timeout_seconds"] == 120.0

    def test_get_profile_not_found(self, client):
        response = client.get("/api/v1/profiles/nonexistent")
        assert response.status_code == 404


class TestProfileCreate:
    def test_create_profile(self, client):
        response = client.post(
            "/api/v1/profiles",
            json={
                "name": "test-profile",
                "description": "Test",
                "overrides": {"network": {"timeout_seconds": 77.0}},
            },
        )
        assert response.status_code == 200
        assert response.json()["created"] is True

    def test_create_from_base(self, client):
        response = client.post(
            "/api/v1/profiles", json={"name": "my-aggressive", "base": "aggressive"}
        )
        assert response.status_code == 200

        response = client.get("/api/v1/profiles/my-aggressive")
        assert response.json()["resolved_preferences"]["network"]["timeout_seconds"] == 120.0

    def test_create_invalid_name(self, client):
        response = client.post("/api/v1/profiles", json={"name": "has spaces"})
        assert response.status_code == 400


class TestProfileUpdate:
    def test_update_profile(self, client):
        client.post("/api/v1/profiles", json={"name": "updatable"})
        response = client.put("/api/v1/profiles/updatable", json={"description": "Updated"})
        assert response.status_code == 200
        assert response.json()["profile"]["description"] == "Updated"

    def test_update_not_found(self, client):
        response = client.put("/api/v1/profiles/nonexistent", json={"description": "x"})
        assert response.status_code == 404


class TestProfileDelete:
    def test_delete_user_profile(self, client):
        client.post("/api/v1/profiles", json={"name": "to-delete"})
        response = client.delete("/api/v1/profiles/to-delete")
        assert response.status_code == 200
        assert response.json()["deleted"] is True

    def test_delete_builtin_resets(self, client):
        client.put(
            "/api/v1/profiles/aggressive",
            json={"overrides": {"network": {"timeout_seconds": 999.0}}},
        )
        response = client.delete("/api/v1/profiles/aggressive")
        assert response.status_code == 200
        assert response.json()["reset"] is True

    def test_delete_not_found(self, client):
        response = client.delete("/api/v1/profiles/nonexistent")
        assert response.status_code == 404


class TestProfileActivate:
    def test_activate_profile(self, client):
        response = client.put("/api/v1/profiles/aggressive/activate")
        assert response.status_code == 200
        assert response.json()["active_profile"] == "aggressive"

    def test_activate_not_found(self, client):
        response = client.put("/api/v1/profiles/nonexistent/activate")
        assert response.status_code == 404


class TestProfileReset:
    def test_reset_profile(self, client):
        client.put(
            "/api/v1/profiles/stealth",
            json={"overrides": {"rate_limiting": {"requests_per_second": 99.0}}},
        )
        response = client.post("/api/v1/profiles/stealth/reset")
        assert response.status_code == 200

    def test_reset_not_found(self, client):
        response = client.post("/api/v1/profiles/nonexistent/reset")
        assert response.status_code == 404


class TestProfileResolve:
    def test_resolve_without_activating(self, client):
        response = client.get("/api/v1/profiles/stealth/resolve")
        assert response.status_code == 200
        assert response.json()["preferences"]["rate_limiting"]["requests_per_second"] == 1.0

        # Active unchanged
        response = client.get("/api/v1/preferences")
        assert response.json()["active_profile"] == "default"

    def test_resolve_not_found(self, client):
        response = client.get("/api/v1/profiles/nonexistent/resolve")
        assert response.status_code == 404
