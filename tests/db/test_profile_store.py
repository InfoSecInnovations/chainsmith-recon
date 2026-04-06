"""
tests/test_profile_store.py - Tests for ProfileStore and file I/O

Tests cover:
  - ProfileStore CRUD operations
  - File persistence (YAML/JSON)
  - Legacy API compatibility
"""

from pathlib import Path

import pytest

from app.preferences import (
    BUILTIN_PROFILES,
    Preferences,
    ProfileStore,
    load_preferences,
    load_profile_store,
    save_preferences,
    save_profile_store,
)


pytestmark = pytest.mark.integration

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def temp_prefs_path(tmp_path: Path) -> Path:
    """Temporary preferences file path."""
    return tmp_path / "preferences.yaml"


# ═══════════════════════════════════════════════════════════════════════════════
# ProfileStore Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestProfileStore:
    """Tests for ProfileStore management."""

    def test_store_has_builtin_profiles(self):
        """Test that new store has built-in profiles."""
        store = ProfileStore()
        assert "default" in store.profiles
        assert "aggressive" in store.profiles
        assert store.profiles["default"].built_in is True

    def test_store_list_profiles(self):
        """Test listing profiles."""
        store = ProfileStore()
        profiles = store.list_profiles()
        names = [p["name"] for p in profiles]
        assert "default" in names
        assert "aggressive" in names

    def test_store_create_profile(self):
        """Test creating a new profile."""
        store = ProfileStore()
        profile = store.create_profile(
            name="my-profile",
            description="My custom profile",
            overrides={"network": {"timeout_seconds": 55.0}},
        )
        assert profile.name == "my-profile"
        assert "my-profile" in store.profiles

    def test_store_create_profile_from_base(self):
        """Test creating profile based on another profile."""
        store = ProfileStore()
        profile = store.create_profile(name="my-aggressive", base="aggressive")
        prefs = profile.resolve()
        assert prefs.network.max_concurrent_requests == 20  # from aggressive

    def test_store_create_profile_name_validation(self):
        """Test profile name validation."""
        store = ProfileStore()
        with pytest.raises(ValueError, match="cannot be empty"):
            store.create_profile("")
        with pytest.raises(ValueError, match="can only contain"):
            store.create_profile("my profile")

    def test_store_update_profile(self):
        """Test updating a profile."""
        store = ProfileStore()
        store.create_profile("editable", description="Original")
        updated = store.update_profile("editable", description="Updated")
        assert updated.description == "Updated"

    def test_store_delete_user_profile(self):
        """Test deleting a user profile."""
        store = ProfileStore()
        store.create_profile("deletable")
        result = store.delete_profile("deletable")
        assert result is True
        assert "deletable" not in store.profiles

    def test_store_delete_builtin_profile_resets(self):
        """Test that deleting a built-in profile resets it."""
        store = ProfileStore()
        store.update_profile("aggressive", overrides={"network": {"timeout_seconds": 999.0}})
        store.delete_profile("aggressive")
        assert "aggressive" in store.profiles
        original = BUILTIN_PROFILES["aggressive"]
        assert store.profiles["aggressive"].overrides == original.overrides

    def test_store_delete_active_profile_fails(self):
        """Test that deleting the active profile fails."""
        store = ProfileStore()
        store.create_profile("to-delete")
        store.activate_profile("to-delete")
        with pytest.raises(ValueError, match="Cannot delete the active profile"):
            store.delete_profile("to-delete")

    def test_store_activate_profile(self):
        """Test activating a profile."""
        store = ProfileStore()
        store.activate_profile("aggressive")
        assert store.active_profile == "aggressive"

    def test_store_activate_nonexistent_fails(self):
        """Test activating a nonexistent profile fails."""
        store = ProfileStore()
        with pytest.raises(ValueError, match="does not exist"):
            store.activate_profile("nonexistent")

    def test_store_reset_profile(self):
        """Test resetting a profile."""
        store = ProfileStore()
        store.update_profile("stealth", overrides={"network": {"timeout_seconds": 1.0}})
        store.reset_profile("stealth")
        original = BUILTIN_PROFILES["stealth"]
        assert store.profiles["stealth"].overrides == original.overrides

    def test_store_to_dict_only_user_profiles(self):
        """Test that to_dict only includes user/modified profiles."""
        store = ProfileStore()
        store.create_profile("custom")
        data = store.to_dict()
        assert "custom" in data["profiles"]
        assert "default" not in data["profiles"]

    def test_store_from_dict(self):
        """Test loading store from dict."""
        data = {
            "active_profile": "custom",
            "profiles": {"custom": {"description": "Custom", "overrides": {}}},
        }
        store = ProfileStore.from_dict(data)
        assert "custom" in store.profiles
        assert "default" in store.profiles  # built-in still present
        assert store.active_profile == "custom"


# ═══════════════════════════════════════════════════════════════════════════════
# File I/O Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFileIO:
    """Tests for file I/O operations."""

    def test_save_and_load_yaml(self, temp_prefs_path: Path):
        """Test saving and loading as YAML."""
        store = ProfileStore()
        store.create_profile("saved-profile", description="Saved")
        store.activate_profile("saved-profile")

        result = save_profile_store(store, temp_prefs_path)
        assert result is True

        loaded = load_profile_store(temp_prefs_path)
        assert loaded.active_profile == "saved-profile"
        assert "saved-profile" in loaded.profiles

    def test_save_and_load_json(self, tmp_path: Path):
        """Test saving and loading as JSON."""
        json_path = tmp_path / "preferences.json"
        store = ProfileStore()
        store.create_profile("json-profile")

        save_profile_store(store, json_path)
        loaded = load_profile_store(json_path)
        assert "json-profile" in loaded.profiles

    def test_load_nonexistent_file(self, tmp_path: Path):
        """Test loading from nonexistent file returns defaults."""
        nonexistent = tmp_path / "does_not_exist.yaml"
        store = load_profile_store(nonexistent)
        assert "default" in store.profiles

    def test_legacy_load_preferences(self, temp_prefs_path: Path):
        """Test legacy load_preferences function."""
        store = ProfileStore()
        store.activate_profile("aggressive")
        save_profile_store(store, temp_prefs_path)

        prefs = load_preferences(temp_prefs_path)
        assert prefs.network.timeout_seconds == 120.0

    def test_legacy_save_preferences(self, temp_prefs_path: Path):
        """Test legacy save_preferences function."""
        store = ProfileStore()
        save_profile_store(store, temp_prefs_path)

        prefs = Preferences()
        prefs.network.timeout_seconds = 88.0
        save_preferences(prefs, temp_prefs_path)

        loaded = load_profile_store(temp_prefs_path)
        resolved = loaded.get_active_preferences()
        assert resolved.network.timeout_seconds == 88.0
