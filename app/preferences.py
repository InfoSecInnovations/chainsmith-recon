"""
app/preferences.py - User Preferences System with Profile Support

Manages user preferences stored in ~/.chainsmith/preferences.yaml

Preference categories:
  - network: timeout, concurrency, proxy, SSL verification
  - rate_limiting: requests per second, delays
  - checks: global check behavior
  - proof_of_scope: scan window + scope requirements
  - check_overrides: per-check configuration

Profile system:
  - Profiles are named preference sets that inherit from 'default'
  - Built-in profiles: default, aggressive, stealth
  - User can create, edit, and delete custom profiles
  - Active profile is persisted and used by CLI/UI

Usage:
    from app.preferences import get_preferences, set_preference, reset_preference
    from app.preferences import get_profile, list_profiles, create_profile

    # Get active profile's preferences
    prefs = get_preferences()
    print(prefs.network.timeout_seconds)

    # Work with profiles
    profiles = list_profiles()
    create_profile("my-custom", base="aggressive")
    activate_profile("my-custom")
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

# Optional YAML support
try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# Preference Dataclasses
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class NetworkPreferences:
    """Network behavior preferences."""

    timeout_seconds: float = 30.0
    max_concurrent_requests: int = 10
    user_agent: str = "Chainsmith/1.0"
    verify_ssl: bool = False
    proxy: str | None = None


@dataclass
class RateLimitingPreferences:
    """Rate limiting and politeness preferences."""

    requests_per_second: float = 10.0
    delay_between_hosts: float = 0.5
    respect_robots_txt: bool = False


@dataclass
class CheckPreferences:
    """Global check behavior preferences."""

    skip_disabled: bool = True
    on_critical: str = "annotate"  # annotate, skip_downstream, stop
    on_critical_overrides: dict[str, str] = field(default_factory=dict)  # per-suite overrides
    intrusive_web: bool = False  # gate WebDAV, credential testing checks
    verification_level: str = "none"  # none, sample, all


@dataclass
class ProofOfScopePreferences:
    """Proof of scope preferences."""

    traffic_logging: bool = True
    log_violations: bool = True
    require_scan_window: bool = True


@dataclass
class LLMPreferences:
    """LLM feature preferences."""

    enabled: bool = True
    provider: str | None = None  # None = auto-detect; "openai", "anthropic", "litellm", "none"
    chain_analysis: bool = True
    verification: bool = True


@dataclass
class AdvancedPreferences:
    """Advanced preferences (hidden by default)."""

    payload_mutation: bool = True
    timing_analysis: bool = True
    cache_responses: bool = True
    max_observation_evidence_bytes: int = 10000
    waf_evasion: bool = False


@dataclass
class Preferences:
    """
    Root preferences container.

    All preferences have sensible defaults. User overrides are merged on top.
    """

    network: NetworkPreferences = field(default_factory=NetworkPreferences)
    rate_limiting: RateLimitingPreferences = field(default_factory=RateLimitingPreferences)
    checks: CheckPreferences = field(default_factory=CheckPreferences)
    llm: LLMPreferences = field(default_factory=LLMPreferences)
    proof_of_scope: ProofOfScopePreferences = field(default_factory=ProofOfScopePreferences)
    advanced: AdvancedPreferences = field(default_factory=AdvancedPreferences)
    check_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    operator_assist: dict[str, Any] | None = None  # {"mode": "guided"} or None

    @property
    def guided_mode_enabled(self) -> bool:
        """Return True if Guided Mode is active."""
        if self.operator_assist is None:
            return False
        return self.operator_assist.get("mode") == "guided"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "network": asdict(self.network),
            "rate_limiting": asdict(self.rate_limiting),
            "checks": asdict(self.checks),
            "llm": asdict(self.llm),
            "proof_of_scope": asdict(self.proof_of_scope),
            "advanced": asdict(self.advanced),
            "check_overrides": self.check_overrides,
            "operator_assist": deepcopy(self.operator_assist) if self.operator_assist else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Preferences:
        """Create from dictionary, filling in defaults for missing values."""
        prefs = cls()

        if "network" in data and isinstance(data["network"], dict):
            for key, value in data["network"].items():
                if hasattr(prefs.network, key):
                    setattr(prefs.network, key, value)

        if "rate_limiting" in data and isinstance(data["rate_limiting"], dict):
            for key, value in data["rate_limiting"].items():
                if hasattr(prefs.rate_limiting, key):
                    setattr(prefs.rate_limiting, key, value)

        if "checks" in data and isinstance(data["checks"], dict):
            for key, value in data["checks"].items():
                # Migrate legacy on_critical_<suite> fields to on_critical_overrides dict
                if key.startswith("on_critical_") and key != "on_critical_overrides":
                    suite = key[len("on_critical_") :]
                    if value is not None:
                        prefs.checks.on_critical_overrides[suite] = value
                elif hasattr(prefs.checks, key):
                    setattr(prefs.checks, key, value)

        if "llm" in data and isinstance(data["llm"], dict):
            for key, value in data["llm"].items():
                if hasattr(prefs.llm, key):
                    setattr(prefs.llm, key, value)

        if "proof_of_scope" in data and isinstance(data["proof_of_scope"], dict):
            for key, value in data["proof_of_scope"].items():
                if hasattr(prefs.proof_of_scope, key):
                    setattr(prefs.proof_of_scope, key, value)

        if "advanced" in data and isinstance(data["advanced"], dict):
            for key, value in data["advanced"].items():
                if hasattr(prefs.advanced, key):
                    setattr(prefs.advanced, key, value)

        if "check_overrides" in data and isinstance(data["check_overrides"], dict):
            prefs.check_overrides = deepcopy(data["check_overrides"])

        if "operator_assist" in data and isinstance(data["operator_assist"], dict):
            prefs.operator_assist = deepcopy(data["operator_assist"])

        return prefs

    def copy(self) -> Preferences:
        """Create a deep copy of this Preferences instance."""
        return Preferences.from_dict(self.to_dict())


# ═══════════════════════════════════════════════════════════════════════════════
# Profile System
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class Profile:
    """
    A named set of preference overrides.

    Profiles store only the differences from the default profile.
    When resolved, they produce a complete Preferences object by
    merging their overrides onto the default.

    Attributes:
        name: Unique profile identifier (lowercase, hyphens allowed)
        description: Human-readable description
        overrides: Dict of preference overrides (sparse - only non-default values)
        built_in: Whether this is a built-in profile (default, aggressive, stealth)
    """

    name: str
    description: str = ""
    overrides: dict[str, Any] = field(default_factory=dict)
    built_in: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "overrides": deepcopy(self.overrides),
            "built_in": self.built_in,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Profile:
        """Create from dictionary."""
        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            overrides=deepcopy(data.get("overrides", {})),
            built_in=data.get("built_in", False),
        )

    def resolve(self, base: Preferences | None = None) -> Preferences:
        """
        Resolve this profile to a complete Preferences object.

        Merges overrides onto the base preferences (default if not specified).

        Args:
            base: Base preferences to merge onto. Uses defaults if None.

        Returns:
            Complete Preferences object with overrides applied.
        """
        if base is None:
            base = Preferences()

        # Start with a copy of base
        result = base.copy()

        # Apply overrides
        for section_key, section_value in self.overrides.items():
            if section_key == "check_overrides" and isinstance(section_value, dict):
                # Merge check_overrides
                for check_name, check_opts in section_value.items():
                    if check_name not in result.check_overrides:
                        result.check_overrides[check_name] = {}
                    result.check_overrides[check_name].update(check_opts)
            elif hasattr(result, section_key) and isinstance(section_value, dict):
                # Merge section overrides
                section_obj = getattr(result, section_key)
                for key, value in section_value.items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)

        return result


# Built-in profile definitions (stored in code, not YAML)
BUILTIN_PROFILES: dict[str, Profile] = {
    "default": Profile(
        name="default",
        description="Balanced settings for general reconnaissance",
        overrides={},  # No overrides - this IS the default
        built_in=True,
    ),
    "aggressive": Profile(
        name="aggressive",
        description="High timeouts, parallel execution, WAF evasion, intrusive checks enabled",
        overrides={
            "network": {
                "timeout_seconds": 120.0,
                "max_concurrent_requests": 20,
            },
            "checks": {
                "intrusive_web": True,
            },
            "advanced": {
                "waf_evasion": True,
            },
        },
        built_in=True,
    ),
    "stealth": Profile(
        name="stealth",
        description="Low rate limits, respects robots.txt, longer delays between requests",
        overrides={
            "network": {
                "timeout_seconds": 60.0,
            },
            "rate_limiting": {
                "requests_per_second": 1.0,
                "delay_between_hosts": 2.0,
                "respect_robots_txt": True,
            },
        },
        built_in=True,
    ),
    "training": Profile(
        name="training",
        description="Guided Mode enabled — learning the tool or onboarding new team members",
        overrides={
            "operator_assist": {"mode": "guided"},
        },
        built_in=True,
    ),
    "first-scan": Profile(
        name="first-scan",
        description="Guided Mode enabled — first time running against a new target type",
        overrides={
            "operator_assist": {"mode": "guided"},
        },
        built_in=True,
    ),
}


@dataclass
class ProfileStore:
    """
    Container for all profiles and active profile selection.

    Manages both built-in and user-defined profiles.
    """

    active_profile: str = "default"
    profiles: dict[str, Profile] = field(default_factory=dict)

    def __post_init__(self):
        """Ensure built-in profiles are always present."""
        for name, profile in BUILTIN_PROFILES.items():
            if name not in self.profiles:
                self.profiles[name] = deepcopy(profile)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        # Only serialize user profiles (non-built-in) and their overrides
        user_profiles = {}
        for name, profile in self.profiles.items():
            if not profile.built_in:
                user_profiles[name] = {
                    "description": profile.description,
                    "overrides": profile.overrides,
                }
            elif (
                profile.built_in
                and profile.overrides != BUILTIN_PROFILES.get(name, Profile(name=name)).overrides
            ):
                # Built-in profile has been modified - save the modifications
                user_profiles[name] = {
                    "description": profile.description,
                    "overrides": profile.overrides,
                    "_modified_builtin": True,
                }

        return {
            "active_profile": self.active_profile,
            "profiles": user_profiles,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ProfileStore:
        """Create from dictionary, merging with built-in profiles."""
        store = cls()

        # Set active profile
        store.active_profile = data.get("active_profile", "default")

        # Load user profiles
        profiles_data = data.get("profiles", {})
        for name, profile_data in profiles_data.items():
            if name in BUILTIN_PROFILES:
                # User has modified a built-in profile
                builtin = deepcopy(BUILTIN_PROFILES[name])
                builtin.description = profile_data.get("description", builtin.description)
                builtin.overrides = deepcopy(profile_data.get("overrides", builtin.overrides))
                store.profiles[name] = builtin
            else:
                # User-defined profile
                store.profiles[name] = Profile(
                    name=name,
                    description=profile_data.get("description", ""),
                    overrides=deepcopy(profile_data.get("overrides", {})),
                    built_in=False,
                )

        # Validate active profile exists
        if store.active_profile not in store.profiles:
            store.active_profile = "default"

        return store

    def get_profile(self, name: str) -> Profile | None:
        """Get a profile by name."""
        return self.profiles.get(name)

    def get_active_profile(self) -> Profile:
        """Get the currently active profile."""
        return self.profiles.get(self.active_profile, self.profiles["default"])

    def get_active_preferences(self) -> Preferences:
        """Resolve the active profile to Preferences."""
        profile = self.get_active_profile()
        return profile.resolve()

    def list_profiles(self) -> list[dict]:
        """List all profiles with metadata."""
        result = []
        for name, profile in sorted(self.profiles.items()):
            result.append(
                {
                    "name": name,
                    "description": profile.description,
                    "built_in": profile.built_in,
                    "active": name == self.active_profile,
                }
            )
        return result

    def create_profile(
        self,
        name: str,
        description: str = "",
        base: str | None = None,
        overrides: dict | None = None,
    ) -> Profile:
        """
        Create a new user profile.

        Args:
            name: Profile name (must be unique, lowercase with hyphens)
            description: Human-readable description
            base: Name of profile to copy from (default: "default")
            overrides: Additional overrides to apply

        Returns:
            The created Profile

        Raises:
            ValueError: If name is invalid or already exists
        """
        # Validate name
        name = name.lower().strip()
        if not name:
            raise ValueError("Profile name cannot be empty")
        if not all(c.isalnum() or c == "-" for c in name):
            raise ValueError("Profile name can only contain letters, numbers, and hyphens")
        if name in self.profiles:
            raise ValueError(f"Profile '{name}' already exists")

        # Start with base profile's overrides
        base_profile = self.profiles.get(base or "default", self.profiles["default"])
        new_overrides = deepcopy(base_profile.overrides)

        # Merge additional overrides
        if overrides:
            new_overrides = _deep_merge(new_overrides, overrides)

        profile = Profile(
            name=name,
            description=description,
            overrides=new_overrides,
            built_in=False,
        )
        self.profiles[name] = profile
        return profile

    def update_profile(
        self,
        name: str,
        description: str | None = None,
        overrides: dict | None = None,
        merge: bool = True,
    ) -> Profile:
        """
        Update an existing profile.

        Args:
            name: Profile name to update
            description: New description (None to keep existing)
            overrides: New overrides (None to keep existing)
            merge: If True, merge overrides; if False, replace entirely

        Returns:
            The updated Profile

        Raises:
            ValueError: If profile doesn't exist
        """
        if name not in self.profiles:
            raise ValueError(f"Profile '{name}' does not exist")

        profile = self.profiles[name]

        if description is not None:
            profile.description = description

        if overrides is not None:
            if merge:
                profile.overrides = _deep_merge(profile.overrides, overrides)
            else:
                profile.overrides = deepcopy(overrides)

        return profile

    def delete_profile(self, name: str) -> bool:
        """
        Delete a user profile.

        Built-in profiles cannot be deleted, but can be reset to defaults.

        Args:
            name: Profile name to delete

        Returns:
            True if deleted, False if profile didn't exist

        Raises:
            ValueError: If trying to delete the active profile
        """
        if name not in self.profiles:
            return False

        profile = self.profiles[name]

        if profile.built_in:
            # Reset built-in profile to defaults instead of deleting
            self.profiles[name] = deepcopy(BUILTIN_PROFILES[name])
            return True

        if name == self.active_profile:
            raise ValueError("Cannot delete the active profile. Switch to another profile first.")

        del self.profiles[name]
        return True

    def activate_profile(self, name: str) -> None:
        """
        Set a profile as active.

        Args:
            name: Profile name to activate

        Raises:
            ValueError: If profile doesn't exist
        """
        if name not in self.profiles:
            raise ValueError(f"Profile '{name}' does not exist")

        self.active_profile = name

    def reset_profile(self, name: str) -> Profile:
        """
        Reset a profile to its default state.

        For built-in profiles, restores the original settings.
        For user profiles, clears all overrides.

        Args:
            name: Profile name to reset

        Returns:
            The reset Profile

        Raises:
            ValueError: If profile doesn't exist
        """
        if name not in self.profiles:
            raise ValueError(f"Profile '{name}' does not exist")

        profile = self.profiles[name]

        if profile.built_in and name in BUILTIN_PROFILES:
            # Restore built-in profile
            self.profiles[name] = deepcopy(BUILTIN_PROFILES[name])
        else:
            # Clear user profile overrides
            profile.overrides = {}

        return self.profiles[name]


def _deep_merge(base: dict, updates: dict) -> dict:
    """
    Deep merge two dictionaries.

    Updates are applied on top of base. Nested dicts are merged recursively.
    """
    result = deepcopy(base)

    for key, value in updates.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Preference Metadata (for CLI/UI)
# ═══════════════════════════════════════════════════════════════════════════════


# Metadata about each preference for CLI help and validation
PREFERENCE_METADATA = {
    "network.timeout_seconds": {
        "type": "float",
        "description": "HTTP request timeout in seconds",
        "min": 1.0,
        "max": 300.0,
        "advanced": False,
    },
    "network.max_concurrent_requests": {
        "type": "int",
        "description": "Maximum concurrent HTTP requests",
        "min": 1,
        "max": 100,
        "advanced": False,
    },
    "network.user_agent": {
        "type": "str",
        "description": "User-Agent header for HTTP requests",
        "advanced": False,
    },
    "network.verify_ssl": {
        "type": "bool",
        "description": "Verify SSL certificates",
        "advanced": False,
    },
    "network.proxy": {
        "type": "str",
        "description": "HTTP proxy URL (e.g., http://127.0.0.1:8080)",
        "advanced": False,
    },
    "rate_limiting.requests_per_second": {
        "type": "float",
        "description": "Maximum requests per second",
        "min": 0.1,
        "max": 100.0,
        "advanced": False,
    },
    "rate_limiting.delay_between_hosts": {
        "type": "float",
        "description": "Delay between hosts in seconds",
        "min": 0.0,
        "max": 60.0,
        "advanced": False,
    },
    "rate_limiting.respect_robots_txt": {
        "type": "bool",
        "description": "Honor robots.txt crawl delays",
        "advanced": False,
    },
    "checks.skip_disabled": {
        "type": "bool",
        "description": "Skip checks marked as disabled",
        "advanced": False,
    },
    "checks.on_critical": {
        "type": "str",
        "description": "Behavior when critical observation discovered (annotate, skip_downstream, stop)",
        "choices": ["annotate", "skip_downstream", "stop"],
        "advanced": False,
    },
    "checks.on_critical_overrides": {
        "type": "dict",
        "description": "Per-suite on_critical overrides, e.g. {web: stop, ai: skip_downstream}",
        "advanced": True,
    },
    "checks.intrusive_web": {
        "type": "bool",
        "description": "Enable intrusive web checks (WebDAV probing, credential testing)",
        "advanced": False,
    },
    "checks.verification_level": {
        "type": "str",
        "description": "Observation verification level (none, sample, all)",
        "choices": ["none", "sample", "all"],
        "advanced": False,
    },
    "proof_of_scope.traffic_logging": {
        "type": "bool",
        "description": "Log all HTTP traffic for proof of scope",
        "advanced": False,
    },
    "proof_of_scope.log_violations": {
        "type": "bool",
        "description": "Log scope violations",
        "advanced": False,
    },
    "proof_of_scope.require_scan_window": {
        "type": "bool",
        "description": "Require scan window to be set",
        "advanced": False,
    },
    "llm.enabled": {
        "type": "bool",
        "description": "Enable LLM-powered features (chain analysis, verification)",
        "advanced": False,
    },
    "llm.provider": {
        "type": "str",
        "description": "LLM provider override (openai, anthropic, litellm, none)",
        "choices": ["openai", "anthropic", "litellm", "none"],
        "advanced": False,
    },
    "llm.chain_analysis": {
        "type": "bool",
        "description": "Enable LLM-based attack chain discovery",
        "advanced": False,
    },
    "llm.verification": {
        "type": "bool",
        "description": "Enable LLM-based observation verification",
        "advanced": False,
    },
    "advanced.payload_mutation": {
        "type": "bool",
        "description": "Try payload variations during checks",
        "advanced": True,
    },
    "advanced.timing_analysis": {
        "type": "bool",
        "description": "Detect timing-based vulnerabilities",
        "advanced": True,
    },
    "advanced.cache_responses": {
        "type": "bool",
        "description": "Cache HTTP responses during scan",
        "advanced": True,
    },
    "advanced.max_observation_evidence_bytes": {
        "type": "int",
        "description": "Maximum evidence bytes per observation",
        "min": 100,
        "max": 1000000,
        "advanced": True,
    },
    "advanced.waf_evasion": {
        "type": "bool",
        "description": "Enable WAF evasion techniques",
        "advanced": True,
    },
}


def get_preference_metadata(key: str) -> dict | None:
    """Get metadata for a preference key."""
    return PREFERENCE_METADATA.get(key)


def list_preferences(include_advanced: bool = False) -> list[str]:
    """List all preference keys."""
    keys = []
    for key, meta in PREFERENCE_METADATA.items():
        if not meta.get("advanced", False) or include_advanced:
            keys.append(key)
    return sorted(keys)


# ═══════════════════════════════════════════════════════════════════════════════
# File I/O
# ═══════════════════════════════════════════════════════════════════════════════


def _default_preferences_path() -> Path:
    """Return path to user preferences file."""
    if env := os.environ.get("CHAINSMITH_PREFERENCES_PATH"):
        return Path(env)
    return Path.home() / ".chainsmith" / "preferences.yaml"


def _ensure_preferences_dir(path: Path) -> None:
    """Ensure the preferences directory exists."""
    path.parent.mkdir(parents=True, exist_ok=True)


def load_profile_store(path: Path | None = None) -> ProfileStore:
    """
    Load the profile store from file.

    Returns a fresh ProfileStore with built-in profiles if file doesn't exist.
    """
    path = path or _default_preferences_path()

    if not path.exists():
        return ProfileStore()

    try:
        with open(path) as f:
            if path.suffix in (".yaml", ".yml") and _YAML_AVAILABLE:
                data = _yaml.safe_load(f) or {}
            else:
                data = json.load(f)

        if not isinstance(data, dict):
            return ProfileStore()

        return ProfileStore.from_dict(data)

    except Exception:
        # Return defaults on any error
        return ProfileStore()


def save_profile_store(store: ProfileStore, path: Path | None = None) -> bool:
    """
    Save the profile store to file.

    Returns True on success, False on failure.
    """
    path = path or _default_preferences_path()

    try:
        _ensure_preferences_dir(path)

        data = store.to_dict()

        with open(path, "w") as f:
            if path.suffix in (".yaml", ".yml") and _YAML_AVAILABLE:
                _yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            else:
                json.dump(data, f, indent=2)

        return True

    except Exception:
        return False


# Legacy compatibility: load_preferences and save_preferences
def load_preferences(path: Path | None = None) -> Preferences:
    """
    Load preferences from file.

    Returns the active profile's resolved preferences.
    For legacy compatibility.
    """
    store = load_profile_store(path)
    return store.get_active_preferences()


def save_preferences(prefs: Preferences, path: Path | None = None) -> bool:
    """
    Save preferences to the active profile.

    For legacy compatibility. Updates the active profile's overrides
    based on differences from default.
    """
    store = load_profile_store(path)

    # Calculate overrides (differences from default)
    default_prefs = Preferences()
    overrides = _calculate_overrides(default_prefs, prefs)

    # Update active profile
    active = store.get_active_profile()
    active.overrides = overrides

    return save_profile_store(store, path)


def _calculate_overrides(default: Preferences, current: Preferences) -> dict:
    """Calculate the overrides dict representing differences from default."""
    overrides = {}

    # Compare each section
    for section_name in ["network", "rate_limiting", "checks", "proof_of_scope", "advanced"]:
        default_section = getattr(default, section_name)
        current_section = getattr(current, section_name)

        section_overrides = {}
        for f in fields(default_section):
            default_value = getattr(default_section, f.name)
            current_value = getattr(current_section, f.name)
            if current_value != default_value:
                section_overrides[f.name] = current_value

        if section_overrides:
            overrides[section_name] = section_overrides

    # Include check_overrides if present
    if current.check_overrides:
        overrides["check_overrides"] = deepcopy(current.check_overrides)

    # Include operator_assist if set
    if current.operator_assist:
        overrides["operator_assist"] = deepcopy(current.operator_assist)

    return overrides


# ═══════════════════════════════════════════════════════════════════════════════
# Preference Access API
# ═══════════════════════════════════════════════════════════════════════════════


def get_value(prefs: Preferences, key: str) -> Any:
    """
    Get a preference value by dotted key.

    Examples:
        get_value(prefs, "network.timeout_seconds") -> 30.0
        get_value(prefs, "check_overrides.mcp_discovery.timeout_seconds") -> 60
    """
    parts = key.split(".")

    if len(parts) < 2:
        raise ValueError(f"Invalid preference key: {key}")

    section = parts[0]

    # Handle check_overrides specially
    if section == "check_overrides":
        if len(parts) < 3:
            # Return entire override dict for a check
            check_name = parts[1]
            return prefs.check_overrides.get(check_name, {})
        else:
            check_name = parts[1]
            override_key = ".".join(parts[2:])
            check_overrides = prefs.check_overrides.get(check_name, {})
            return check_overrides.get(override_key)

    # Standard section.key access
    section_obj = getattr(prefs, section, None)
    if section_obj is None:
        raise ValueError(f"Unknown preference section: {section}")

    attr_name = parts[1]
    if not hasattr(section_obj, attr_name):
        raise ValueError(f"Unknown preference: {key}")

    return getattr(section_obj, attr_name)


def set_value(prefs: Preferences, key: str, value: Any) -> None:
    """
    Set a preference value by dotted key.

    Validates type if metadata exists.
    """
    parts = key.split(".")

    if len(parts) < 2:
        raise ValueError(f"Invalid preference key: {key}")

    section = parts[0]

    # Handle check_overrides specially
    if section == "check_overrides":
        if len(parts) < 3:
            raise ValueError("check_overrides requires format: check_overrides.<check>.<option>")

        check_name = parts[1]
        override_key = ".".join(parts[2:])

        if check_name not in prefs.check_overrides:
            prefs.check_overrides[check_name] = {}

        prefs.check_overrides[check_name][override_key] = value
        return

    # Validate against metadata
    meta = get_preference_metadata(key)
    if meta:
        value = _validate_and_convert(value, meta, key)

    # Set value
    section_obj = getattr(prefs, section, None)
    if section_obj is None:
        raise ValueError(f"Unknown preference section: {section}")

    attr_name = parts[1]
    if not hasattr(section_obj, attr_name):
        raise ValueError(f"Unknown preference: {key}")

    setattr(section_obj, attr_name, value)


def reset_value(prefs: Preferences, key: str) -> None:
    """
    Reset a preference to its default value.
    """
    parts = key.split(".")

    if len(parts) < 2:
        raise ValueError(f"Invalid preference key: {key}")

    section = parts[0]

    # Handle check_overrides specially
    if section == "check_overrides":
        if len(parts) == 2:
            # Reset all overrides for a check
            check_name = parts[1]
            prefs.check_overrides.pop(check_name, None)
        elif len(parts) >= 3:
            # Reset specific override
            check_name = parts[1]
            override_key = ".".join(parts[2:])
            if check_name in prefs.check_overrides:
                prefs.check_overrides[check_name].pop(override_key, None)
        return

    # Get default value
    defaults = Preferences()
    default_section = getattr(defaults, section, None)
    if default_section is None:
        raise ValueError(f"Unknown preference section: {section}")

    attr_name = parts[1]
    if not hasattr(default_section, attr_name):
        raise ValueError(f"Unknown preference: {key}")

    default_value = getattr(default_section, attr_name)

    # Set to default
    section_obj = getattr(prefs, section, None)
    setattr(section_obj, attr_name, default_value)


def _validate_and_convert(value: Any, meta: dict, key: str) -> Any:
    """Validate and convert a value according to metadata."""
    expected_type = meta.get("type", "str")

    # Type conversion
    if expected_type == "bool":
        if isinstance(value, str):
            if value.lower() in ("true", "1", "yes", "on"):
                value = True
            elif value.lower() in ("false", "0", "no", "off"):
                value = False
            else:
                raise ValueError(f"{key}: expected boolean, got '{value}'")
        value = bool(value)

    elif expected_type == "int":
        try:
            value = int(value)
        except (ValueError, TypeError) as err:
            raise ValueError(f"{key}: expected integer, got '{value}'") from err

    elif expected_type == "float":
        try:
            value = float(value)
        except (ValueError, TypeError) as err:
            raise ValueError(f"{key}: expected number, got '{value}'") from err

    elif expected_type == "str":
        value = str(value) if value is not None else None

    # Range validation
    if "min" in meta and value is not None and value < meta["min"]:
        raise ValueError(f"{key}: value {value} below minimum {meta['min']}")

    if "max" in meta and value is not None and value > meta["max"]:
        raise ValueError(f"{key}: value {value} above maximum {meta['max']}")

    # Choice validation
    if "choices" in meta and value not in meta["choices"]:
        raise ValueError(f"{key}: must be one of {meta['choices']}, got '{value}'")

    return value


# ═══════════════════════════════════════════════════════════════════════════════
# Module-level Singleton
# ═══════════════════════════════════════════════════════════════════════════════


_profile_store: ProfileStore | None = None


def get_profile_store(reload: bool = False) -> ProfileStore:
    """
    Get the cached ProfileStore instance.

    Loads from file on first call.
    """
    global _profile_store

    if _profile_store is None or reload:
        _profile_store = load_profile_store()

    return _profile_store


def get_preferences(reload: bool = False) -> Preferences:
    """
    Get the active profile's resolved preferences.

    This is the main entry point for code that needs preferences.
    """
    store = get_profile_store(reload)
    return store.get_active_preferences()


def set_preference(key: str, value: Any, save: bool = True) -> None:
    """
    Set a preference value in the active profile.

    Args:
        key: Dotted preference key (e.g., "network.timeout_seconds")
        value: Value to set
        save: If True, save to file immediately
    """
    store = get_profile_store()
    prefs = store.get_active_preferences()
    set_value(prefs, key, value)

    # Update the active profile's overrides
    active = store.get_active_profile()
    default_prefs = Preferences()
    active.overrides = _calculate_overrides(default_prefs, prefs)

    if save:
        save_profile_store(store)


def reset_preference(key: str, save: bool = True) -> None:
    """
    Reset a preference to default in the active profile.

    Args:
        key: Dotted preference key
        save: If True, save to file immediately
    """
    store = get_profile_store()
    prefs = store.get_active_preferences()
    reset_value(prefs, key)

    # Update the active profile's overrides
    active = store.get_active_profile()
    default_prefs = Preferences()
    active.overrides = _calculate_overrides(default_prefs, prefs)

    if save:
        save_profile_store(store)


def reset_all_preferences(save: bool = True) -> None:
    """
    Reset active profile to defaults (clears all overrides).
    """
    store = get_profile_store()
    store.reset_profile(store.active_profile)

    if save:
        save_profile_store(store)


def get_check_override(check_name: str, option: str, default: Any = None) -> Any:
    """
    Get a check-specific override value.

    Convenience function for checks to read their overrides.

    Args:
        check_name: Name of the check (e.g., "mcp_discovery")
        option: Option name (e.g., "timeout_seconds")
        default: Default value if not set

    Returns:
        Override value or default
    """
    prefs = get_preferences()
    overrides = prefs.check_overrides.get(check_name, {})
    return overrides.get(option, default)


# ═══════════════════════════════════════════════════════════════════════════════
# Profile Management API (convenience wrappers)
# ═══════════════════════════════════════════════════════════════════════════════


def list_profiles() -> list[dict]:
    """List all available profiles."""
    store = get_profile_store()
    return store.list_profiles()


def get_profile(name: str) -> Profile | None:
    """Get a profile by name."""
    store = get_profile_store()
    return store.get_profile(name)


def get_active_profile_name() -> str:
    """Get the name of the active profile."""
    store = get_profile_store()
    return store.active_profile


def create_profile(
    name: str,
    description: str = "",
    base: str | None = None,
    overrides: dict | None = None,
    save: bool = True,
) -> Profile:
    """
    Create a new profile.

    Args:
        name: Profile name
        description: Human-readable description
        base: Name of profile to copy from (default: "default")
        overrides: Additional overrides to apply
        save: If True, save to file immediately

    Returns:
        The created Profile
    """
    store = get_profile_store()
    profile = store.create_profile(name, description, base, overrides)

    if save:
        save_profile_store(store)

    return profile


def update_profile(
    name: str,
    description: str | None = None,
    overrides: dict | None = None,
    merge: bool = True,
    save: bool = True,
) -> Profile:
    """
    Update an existing profile.

    Args:
        name: Profile name to update
        description: New description (None to keep existing)
        overrides: New overrides (None to keep existing)
        merge: If True, merge overrides; if False, replace entirely
        save: If True, save to file immediately

    Returns:
        The updated Profile
    """
    store = get_profile_store()
    profile = store.update_profile(name, description, overrides, merge)

    if save:
        save_profile_store(store)

    return profile


def delete_profile(name: str, save: bool = True) -> bool:
    """
    Delete a profile.

    Args:
        name: Profile name to delete
        save: If True, save to file immediately

    Returns:
        True if deleted/reset
    """
    store = get_profile_store()
    result = store.delete_profile(name)

    if save and result:
        save_profile_store(store)

    return result


def activate_profile(name: str, save: bool = True) -> None:
    """
    Set a profile as active.

    Args:
        name: Profile name to activate
        save: If True, save to file immediately
    """
    store = get_profile_store()
    store.activate_profile(name)

    if save:
        save_profile_store(store)


def reset_profile(name: str, save: bool = True) -> Profile:
    """
    Reset a profile to its default state.

    Args:
        name: Profile name to reset
        save: If True, save to file immediately

    Returns:
        The reset Profile
    """
    store = get_profile_store()
    profile = store.reset_profile(name)

    if save:
        save_profile_store(store)

    return profile


def is_guided_mode(reload: bool = False) -> bool:
    """Check if Guided Mode is currently active.

    Convenience function for agents and UI components.
    """
    return get_preferences(reload).guided_mode_enabled


def set_guided_mode(enabled: bool, save: bool = True) -> None:
    """Toggle Guided Mode on or off in the active profile.

    Args:
        enabled: True to enable, False to disable
        save: If True, persist to file immediately
    """
    store = get_profile_store()
    active = store.get_active_profile()

    if enabled:
        if "operator_assist" not in active.overrides:
            active.overrides["operator_assist"] = {}
        active.overrides["operator_assist"]["mode"] = "guided"
    else:
        active.overrides.pop("operator_assist", None)

    if save:
        save_profile_store(store)


VALID_ON_CRITICAL_VALUES = ("annotate", "skip_downstream", "stop")
SUITES_WITH_ON_CRITICAL = ("network", "web", "ai", "mcp", "agent", "rag", "cag")


def resolve_on_critical(prefs: Preferences, suite: str) -> str:
    """
    Resolve the on_critical behavior for a given suite.

    Per-suite override wins if set, otherwise falls back to global.

    Args:
        prefs: Resolved preferences
        suite: Suite name (e.g., "web", "ai")

    Returns:
        One of: "annotate", "skip_downstream", "stop"
    """
    suite_value = prefs.checks.on_critical_overrides.get(suite)
    if suite_value is not None and suite_value in VALID_ON_CRITICAL_VALUES:
        return suite_value
    return prefs.checks.on_critical


def resolve_profile(name: str) -> Preferences:
    """
    Resolve a profile to a complete Preferences object.

    Useful for Web UI to get preferences for a specific profile
    without changing the global active profile.

    Args:
        name: Profile name to resolve

    Returns:
        Complete Preferences object

    Raises:
        ValueError: If profile doesn't exist
    """
    store = get_profile_store()
    profile = store.get_profile(name)

    if profile is None:
        raise ValueError(f"Profile '{name}' does not exist")

    return profile.resolve()
