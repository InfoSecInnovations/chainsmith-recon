"""
tests/test_preferences.py - Tests for preferences and profile system
"""

import json
import pytest
from pathlib import Path

from app.preferences import (
    Preferences, Profile, ProfileStore, BUILTIN_PROFILES,
    load_profile_store, save_profile_store, load_preferences, save_preferences,
    _calculate_overrides, _deep_merge,
    get_value, set_value, reset_value, _validate_and_convert,
    get_profile_store, get_preferences, set_preference, reset_preference,
    reset_all_preferences, get_check_override,
    list_profiles, get_profile, get_active_profile_name,
    create_profile, update_profile, delete_profile,
    activate_profile, reset_profile, resolve_profile,
)


@pytest.fixture
def temp_prefs_path(tmp_path: Path) -> Path:
    return tmp_path / "preferences.yaml"


@pytest.fixture
def temp_prefs_env(tmp_path: Path, monkeypatch):
    prefs_path = tmp_path / "preferences.yaml"
    monkeypatch.setenv("CHAINSMITH_PREFERENCES_PATH", str(prefs_path))
    import app.preferences as prefs_module
    prefs_module._profile_store = None
    yield prefs_path
    prefs_module._profile_store = None


@pytest.fixture
def default_prefs() -> Preferences:
    return Preferences()


@pytest.fixture
def custom_prefs() -> Preferences:
    prefs = Preferences()
    prefs.network.timeout_seconds = 60.0
    prefs.network.max_concurrent_requests = 20
    prefs.rate_limiting.requests_per_second = 5.0
    prefs.checks.on_critical = "stop"
    prefs.advanced.waf_evasion = True
    prefs.check_overrides = {"mcp_discovery": {"timeout_seconds": 120}}
    return prefs


@pytest.fixture
def sample_profile() -> Profile:
    return Profile(
        name="test-profile",
        description="A test profile",
        overrides={"network": {"timeout_seconds": 45.0}, "rate_limiting": {"requests_per_second": 2.0}},
        built_in=False,
    )


class TestPreferencesDataclass:
    def test_default_values(self, default_prefs):
        assert default_prefs.network.timeout_seconds == 30.0
        assert default_prefs.network.max_concurrent_requests == 10
        assert default_prefs.rate_limiting.requests_per_second == 10.0
        assert default_prefs.checks.on_critical == "annotate"
        assert default_prefs.advanced.waf_evasion is False

    def test_to_dict(self, default_prefs):
        d = default_prefs.to_dict()
        assert "network" in d and "rate_limiting" in d
        assert d["network"]["timeout_seconds"] == 30.0

    def test_from_dict_full(self, custom_prefs):
        d = custom_prefs.to_dict()
        restored = Preferences.from_dict(d)
        assert restored.network.timeout_seconds == 60.0
        assert restored.check_overrides == {"mcp_discovery": {"timeout_seconds": 120}}

    def test_from_dict_partial(self):
        prefs = Preferences.from_dict({"network": {"timeout_seconds": 99.0}})
        assert prefs.network.timeout_seconds == 99.0
        assert prefs.network.max_concurrent_requests == 10

    def test_copy(self, custom_prefs):
        copy = custom_prefs.copy()
        copy.network.timeout_seconds = 999.0
        assert custom_prefs.network.timeout_seconds == 60.0


class TestProfile:
    def test_profile_creation(self, sample_profile):
        assert sample_profile.name == "test-profile"
        assert sample_profile.built_in is False

    def test_profile_resolve_empty(self):
        profile = Profile(name="empty", overrides={})
        prefs = profile.resolve()
        assert prefs.to_dict() == Preferences().to_dict()

    def test_profile_resolve_with_overrides(self, sample_profile):
        prefs = sample_profile.resolve()
        assert prefs.network.timeout_seconds == 45.0
        assert prefs.network.max_concurrent_requests == 10


class TestBuiltinProfiles:
    def test_builtin_profiles_exist(self):
        assert "default" in BUILTIN_PROFILES
        assert "aggressive" in BUILTIN_PROFILES
        assert "stealth" in BUILTIN_PROFILES

    def test_aggressive_profile(self):
        prefs = BUILTIN_PROFILES["aggressive"].resolve()
        assert prefs.network.timeout_seconds == 120.0
        assert prefs.advanced.waf_evasion is True

    def test_stealth_profile(self):
        prefs = BUILTIN_PROFILES["stealth"].resolve()
        assert prefs.rate_limiting.requests_per_second == 1.0
        assert prefs.rate_limiting.respect_robots_txt is True


class TestProfileStore:
    def test_store_has_builtins(self):
        store = ProfileStore()
        assert "default" in store.profiles
        assert "aggressive" in store.profiles

    def test_store_create_profile(self):
        store = ProfileStore()
        profile = store.create_profile("my-profile", description="Test")
        assert profile.name == "my-profile"
        assert "my-profile" in store.profiles

    def test_store_create_from_base(self):
        store = ProfileStore()
        profile = store.create_profile("my-aggressive", base="aggressive")
        prefs = profile.resolve()
        assert prefs.network.max_concurrent_requests == 20

    def test_store_name_validation(self):
        store = ProfileStore()
        with pytest.raises(ValueError):
            store.create_profile("")
        with pytest.raises(ValueError):
            store.create_profile("has spaces")

    def test_store_update_profile(self):
        store = ProfileStore()
        store.create_profile("editable")
        store.update_profile("editable", description="Updated")
        assert store.profiles["editable"].description == "Updated"

    def test_store_delete_user_profile(self):
        store = ProfileStore()
        store.create_profile("deletable")
        store.delete_profile("deletable")
        assert "deletable" not in store.profiles

    def test_store_delete_builtin_resets(self):
        store = ProfileStore()
        store.update_profile("aggressive", overrides={"network": {"timeout_seconds": 999.0}})
        store.delete_profile("aggressive")
        assert store.profiles["aggressive"].overrides == BUILTIN_PROFILES["aggressive"].overrides

    def test_store_activate_profile(self):
        store = ProfileStore()
        store.activate_profile("aggressive")
        assert store.active_profile == "aggressive"

    def test_store_list_profiles(self):
        store = ProfileStore()
        profiles = store.list_profiles()
        names = [p["name"] for p in profiles]
        assert "default" in names


class TestFileIO:
    def test_save_and_load(self, temp_prefs_path):
        store = ProfileStore()
        store.create_profile("saved-profile")
        save_profile_store(store, temp_prefs_path)
        
        loaded = load_profile_store(temp_prefs_path)
        assert "saved-profile" in loaded.profiles

    def test_load_nonexistent(self, tmp_path):
        store = load_profile_store(tmp_path / "nonexistent.yaml")
        assert "default" in store.profiles

    def test_legacy_load_preferences(self, temp_prefs_path):
        store = ProfileStore()
        store.activate_profile("aggressive")
        save_profile_store(store, temp_prefs_path)
        
        prefs = load_preferences(temp_prefs_path)
        assert prefs.network.timeout_seconds == 120.0


class TestPreferenceAccess:
    def test_get_value(self, custom_prefs):
        assert get_value(custom_prefs, "network.timeout_seconds") == 60.0

    def test_set_value(self, default_prefs):
        set_value(default_prefs, "network.timeout_seconds", 99.0)
        assert default_prefs.network.timeout_seconds == 99.0

    def test_reset_value(self, custom_prefs):
        reset_value(custom_prefs, "network.timeout_seconds")
        assert custom_prefs.network.timeout_seconds == 30.0


class TestModuleLevelAPI:
    def test_get_preferences(self, temp_prefs_env):
        prefs = get_preferences()
        assert prefs.network.timeout_seconds == 30.0

    def test_set_preference(self, temp_prefs_env):
        set_preference("network.timeout_seconds", 77.0)
        prefs = get_preferences(reload=True)
        assert prefs.network.timeout_seconds == 77.0

    def test_activate_profile(self, temp_prefs_env):
        activate_profile("aggressive")
        assert get_active_profile_name() == "aggressive"

    def test_create_and_delete_profile(self, temp_prefs_env):
        create_profile("test-new")
        assert get_profile("test-new") is not None
        delete_profile("test-new")
        assert get_profile("test-new") is None

    def test_resolve_profile(self, temp_prefs_env):
        prefs = resolve_profile("stealth")
        assert prefs.rate_limiting.requests_per_second == 1.0
        assert get_active_profile_name() == "default"


class TestUtilityFunctions:
    def test_deep_merge(self):
        base = {"a": 1, "b": {"x": 10}}
        updates = {"a": 2, "b": {"y": 20}}
        result = _deep_merge(base, updates)
        assert result == {"a": 2, "b": {"x": 10, "y": 20}}

    def test_calculate_overrides(self, custom_prefs):
        overrides = _calculate_overrides(Preferences(), custom_prefs)
        assert overrides["network"]["timeout_seconds"] == 60.0
        assert "mcp_discovery" in overrides["check_overrides"]
