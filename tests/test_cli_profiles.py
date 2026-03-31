"""
tests/test_cli_profiles.py - Tests for CLI profile commands

All tests mock at the ChainsmithClient level — no direct preference imports.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from app.cli import cli
from app.cli_client import ChainsmithAPIError


@pytest.fixture
def runner():
    """CLI runner."""
    return CliRunner()


def _mock_client():
    """Create a mock ChainsmithClient."""
    client = MagicMock()
    client.health.return_value = {"status": "healthy"}
    return client


def _patch_client(client):
    return patch("app.cli._get_client", return_value=client)


class TestProfileList:
    def test_list_profiles(self, runner):
        client = _mock_client()
        client.list_profiles.return_value = {
            "profiles": [
                {"name": "default", "description": "Default settings", "active": True, "built_in": True},
                {"name": "aggressive", "description": "Fast scanning", "active": False, "built_in": True},
                {"name": "stealth", "description": "Slow and quiet", "active": False, "built_in": True},
            ],
            "count": 3,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "list"])
            assert result.exit_code == 0
            assert "default" in result.output
            assert "aggressive" in result.output
            assert "stealth" in result.output
            assert "active" in result.output

    def test_list_profiles_json(self, runner):
        client = _mock_client()
        client.list_profiles.return_value = {
            "profiles": [
                {"name": "default", "active": True, "built_in": True, "description": ""},
            ],
            "count": 1,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "list", "--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert isinstance(data, list)
            names = [p["name"] for p in data]
            assert "default" in names


class TestProfileShow:
    def test_show_profile(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {
                "name": "aggressive",
                "description": "Fast scanning",
                "built_in": True,
                "active": False,
                "overrides": {
                    "network": {"timeout_seconds": 120},
                },
            },
            "resolved_preferences": {
                "network": {"timeout_seconds": 120},
            },
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "show", "aggressive"])
            assert result.exit_code == 0
            assert "aggressive" in result.output
            assert "timeout_seconds" in result.output
            assert "120" in result.output

    def test_show_profile_resolved(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {
                "name": "aggressive",
                "description": "Fast scanning",
                "built_in": True,
                "active": False,
                "overrides": {},
            },
            "resolved_preferences": {
                "network": {"timeout_seconds": 120},
                "rate_limiting": {"requests_per_second": 50},
            },
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "show", "aggressive", "--resolved"])
            assert result.exit_code == 0
            assert "Resolved Preferences" in result.output

    def test_show_profile_not_found(self, runner):
        client = _mock_client()
        client.get_profile.side_effect = ChainsmithAPIError(404, "Profile 'nonexistent' not found")

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "show", "nonexistent"])
            assert result.exit_code == 1
            assert "not found" in result.output


class TestProfileCreate:
    def test_create_profile(self, runner):
        client = _mock_client()
        client.create_profile.return_value = {
            "created": True,
            "profile": {"name": "test-profile"},
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "create", "test-profile"])
            assert result.exit_code == 0
            assert "Created profile" in result.output

    def test_create_profile_with_base(self, runner):
        client = _mock_client()
        client.create_profile.return_value = {
            "created": True,
            "profile": {"name": "my-aggressive"},
        }

        with _patch_client(client):
            result = runner.invoke(cli, [
                "prefs", "profile", "create", "my-aggressive",
                "--base", "aggressive",
                "-d", "My aggressive variant",
            ])
            assert result.exit_code == 0
            assert "Based on: aggressive" in result.output

    def test_create_profile_invalid_name(self, runner):
        client = _mock_client()
        client.create_profile.side_effect = ChainsmithAPIError(
            400, "Invalid profile name"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "create", "has spaces"])
            assert result.exit_code == 1

    def test_create_profile_duplicate(self, runner):
        client = _mock_client()
        client.create_profile.side_effect = ChainsmithAPIError(
            400, "Profile 'dup-test' already exists"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "create", "dup-test"])
            assert result.exit_code == 1
            assert "already exists" in result.output


class TestProfileActivate:
    def test_activate_profile(self, runner):
        client = _mock_client()
        client.activate_profile.return_value = {
            "activated": True,
            "active_profile": "aggressive",
            "preferences": {
                "network": {"timeout_seconds": 120, "max_concurrent_requests": 20},
                "rate_limiting": {"requests_per_second": 50},
                "advanced": {"waf_evasion": False},
            },
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "activate", "aggressive"])
            assert result.exit_code == 0
            assert "Activated" in result.output

    def test_activate_not_found(self, runner):
        client = _mock_client()
        client.activate_profile.side_effect = ChainsmithAPIError(
            404, "Profile 'nonexistent' not found"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "activate", "nonexistent"])
            assert result.exit_code == 1
            assert "not found" in result.output


class TestProfileDelete:
    def test_delete_user_profile(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {"name": "to-delete", "built_in": False},
            "resolved_preferences": {},
        }
        client.get_preferences.return_value = {
            "active_profile": "default",
            "preferences": {},
        }
        client.delete_profile.return_value = {
            "deleted": True,
            "reset": False,
            "name": "to-delete",
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "delete", "to-delete", "-y"])
            assert result.exit_code == 0
            assert "Deleted" in result.output

    def test_delete_builtin_resets(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {"name": "aggressive", "built_in": True},
            "resolved_preferences": {},
        }
        client.get_preferences.return_value = {
            "active_profile": "default",
            "preferences": {},
        }
        client.delete_profile.return_value = {
            "deleted": False,
            "reset": True,
            "name": "aggressive",
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "delete", "aggressive", "-y"])
            assert result.exit_code == 0
            assert "Reset" in result.output

    def test_delete_not_found(self, runner):
        client = _mock_client()
        client.get_profile.side_effect = ChainsmithAPIError(
            404, "Profile 'nonexistent' not found"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "delete", "nonexistent", "-y"])
            assert result.exit_code == 1

    def test_delete_active_fails(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {"name": "will-activate", "built_in": False},
            "resolved_preferences": {},
        }
        client.get_preferences.return_value = {
            "active_profile": "will-activate",
            "preferences": {},
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "delete", "will-activate", "-y"])
            assert result.exit_code == 1
            assert "active" in result.output.lower()


class TestProfileReset:
    def test_reset_profile(self, runner):
        client = _mock_client()
        client.reset_profile.return_value = {
            "reset": True,
            "profile": {"name": "aggressive"},
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "reset", "aggressive", "-y"])
            assert result.exit_code == 0
            assert "Reset" in result.output

    def test_reset_not_found(self, runner):
        client = _mock_client()
        client.reset_profile.side_effect = ChainsmithAPIError(
            404, "Profile 'nonexistent' not found"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "reset", "nonexistent", "-y"])
            assert result.exit_code == 1


class TestProfileCopy:
    def test_copy_profile(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {"name": "aggressive", "built_in": True},
            "resolved_preferences": {"network": {"timeout_seconds": 120}},
        }
        client.create_profile.return_value = {
            "created": True,
            "profile": {"name": "my-copy"},
        }

        with _patch_client(client):
            result = runner.invoke(cli, [
                "prefs", "profile", "copy", "aggressive", "my-copy",
            ])
            assert result.exit_code == 0
            assert "Created profile 'my-copy'" in result.output

    def test_copy_source_not_found(self, runner):
        client = _mock_client()
        client.get_profile.side_effect = ChainsmithAPIError(
            404, "Profile 'nonexistent' not found"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "copy", "nonexistent", "new"])
            assert result.exit_code == 1

    def test_copy_dest_exists(self, runner):
        client = _mock_client()
        client.get_profile.return_value = {
            "profile": {"name": "aggressive"},
            "resolved_preferences": {},
        }
        client.create_profile.side_effect = ChainsmithAPIError(
            400, "Profile 'stealth' already exists"
        )

        with _patch_client(client):
            result = runner.invoke(cli, ["prefs", "profile", "copy", "aggressive", "stealth"])
            assert result.exit_code == 1
            assert "already exists" in result.output
