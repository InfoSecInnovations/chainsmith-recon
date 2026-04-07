"""
app/customizations.py - User Severity Override System

Manages severity overrides stored in ~/.chainsmith/customizations/:
  - severity_overrides.yaml: pre-run policy overrides (check-level, check+title-level)
  - scan_overrides/<scan_id>.yaml: post-run per-scan adjustments

Core principle: the DB stores raw observations as checks produced them.
Overrides are applied as a read-time layer. Original severity is always preserved.

Usage:
    from app.customizations import apply_pre_run_override, apply_scan_overrides

    # Pre-run: mutate observation dict before persistence
    apply_pre_run_override(observation_dict)

    # Post-run: apply overrides when reading observations from DB
    observations = apply_scan_overrides(observations, scan_id)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from app.lib.observations import validate_severity

try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Directory Management
# ═══════════════════════════════════════════════════════════════════════════════


def _customizations_dir() -> Path:
    """Return ~/.chainsmith/customizations/, creating it on first access."""
    d = Path.home() / ".chainsmith" / "customizations"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _scan_overrides_dir() -> Path:
    """Return ~/.chainsmith/customizations/scan_overrides/, creating it on first access."""
    d = _customizations_dir() / "scan_overrides"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _severity_overrides_path() -> Path:
    """Return path to the pre-run severity overrides YAML."""
    return _customizations_dir() / "severity_overrides.yaml"


def _scan_override_path(scan_id: str) -> Path:
    """Return path to a scan-specific override YAML."""
    return _scan_overrides_dir() / f"{scan_id}.yaml"


# ═══════════════════════════════════════════════════════════════════════════════
# YAML Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _read_yaml(path: Path) -> dict:
    """Read a YAML file, returning empty dict if missing or empty."""
    if not path.exists():
        return {}
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — cannot read %s", path)
        return {}
    with open(path) as f:
        return _yaml.safe_load(f) or {}


def _write_yaml(path: Path, data: dict) -> None:
    """Write a dict to a YAML file."""
    if not _YAML_AVAILABLE:
        raise RuntimeError("PyYAML is required for customizations but is not installed")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        _yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


# ═══════════════════════════════════════════════════════════════════════════════
# Pre-Run Severity Overrides
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class SeverityOverrideConfig:
    """Parsed pre-run severity override configuration."""

    check_level: dict[str, str] = field(default_factory=dict)
    check_title_level: dict[str, dict[str, str]] = field(default_factory=dict)


_cached_config: SeverityOverrideConfig | None = None


def load_severity_overrides() -> SeverityOverrideConfig:
    """
    Load pre-run severity overrides from YAML. Cached after first read.

    Returns empty config if file doesn't exist (no overrides).
    """
    global _cached_config
    if _cached_config is not None:
        return _cached_config

    data = _read_yaml(_severity_overrides_path())
    config = SeverityOverrideConfig()

    raw_check = data.get("check_level", {})
    if isinstance(raw_check, dict):
        for check_name, sev in raw_check.items():
            try:
                config.check_level[str(check_name)] = validate_severity(str(sev))
            except ValueError:
                logger.warning(
                    "Ignoring invalid severity '%s' for check '%s' in severity_overrides.yaml",
                    sev,
                    check_name,
                )

    raw_title = data.get("check_title_level", {})
    if isinstance(raw_title, dict):
        for check_name, titles in raw_title.items():
            if not isinstance(titles, dict):
                continue
            check_name = str(check_name)
            config.check_title_level[check_name] = {}
            for title, sev in titles.items():
                try:
                    config.check_title_level[check_name][str(title)] = validate_severity(str(sev))
                except ValueError:
                    logger.warning(
                        "Ignoring invalid severity '%s' for check '%s' title '%s'",
                        sev,
                        check_name,
                        title,
                    )

    _cached_config = config
    logger.info(
        "Loaded severity overrides: %d check-level, %d check+title-level",
        len(config.check_level),
        sum(len(v) for v in config.check_title_level.values()),
    )
    return config


def reload_severity_overrides() -> SeverityOverrideConfig:
    """Force reload of pre-run severity overrides from disk."""
    global _cached_config
    _cached_config = None
    return load_severity_overrides()


def get_severity_overrides_raw() -> dict:
    """Return the raw YAML content for API consumption."""
    return _read_yaml(_severity_overrides_path())


def save_severity_overrides_raw(data: dict) -> None:
    """Write pre-run severity overrides and reload cache."""
    _write_yaml(_severity_overrides_path(), data)
    reload_severity_overrides()


def set_check_level_override(check_name: str, severity: str) -> dict:
    """Set or update a check-level severity override."""
    severity = validate_severity(severity)
    data = _read_yaml(_severity_overrides_path())
    if "check_level" not in data:
        data["check_level"] = {}
    data["check_level"][check_name] = severity
    _write_yaml(_severity_overrides_path(), data)
    reload_severity_overrides()
    return {"check_name": check_name, "severity": severity}


def remove_check_level_override(check_name: str) -> bool:
    """Remove a check-level override. Returns True if it existed."""
    data = _read_yaml(_severity_overrides_path())
    check_level = data.get("check_level", {})
    if check_name not in check_level:
        return False
    del check_level[check_name]
    data["check_level"] = check_level
    _write_yaml(_severity_overrides_path(), data)
    reload_severity_overrides()
    return True


def set_check_title_override(check_name: str, title: str, severity: str) -> dict:
    """Set or update a check+title severity override."""
    severity = validate_severity(severity)
    data = _read_yaml(_severity_overrides_path())
    if "check_title_level" not in data:
        data["check_title_level"] = {}
    if check_name not in data["check_title_level"]:
        data["check_title_level"][check_name] = {}
    data["check_title_level"][check_name][title] = severity
    _write_yaml(_severity_overrides_path(), data)
    reload_severity_overrides()
    return {"check_name": check_name, "title": title, "severity": severity}


def remove_check_title_override(check_name: str, title: str) -> bool:
    """Remove a check+title override. Returns True if it existed."""
    data = _read_yaml(_severity_overrides_path())
    title_level = data.get("check_title_level", {})
    check_titles = title_level.get(check_name, {})
    if title not in check_titles:
        return False
    del check_titles[title]
    if not check_titles:
        del title_level[check_name]
    data["check_title_level"] = title_level
    _write_yaml(_severity_overrides_path(), data)
    reload_severity_overrides()
    return True


def apply_pre_run_override(observation_dict: dict) -> dict:
    """
    Apply pre-run severity overrides to a observation dict.

    Precedence: check+title > check-level > original.
    Stores original_severity in raw_data for audit trail.

    Args:
        observation_dict: Mutable observation dict (modified in place)

    Returns:
        The same dict (for chaining convenience)
    """
    config = load_severity_overrides()
    if not config.check_level and not config.check_title_level:
        return observation_dict

    check_name = observation_dict.get("check_name", "")
    title = observation_dict.get("title", "")
    original = observation_dict.get("severity", "info")

    new_severity = _resolve_override(
        check_name, title, config.check_level, config.check_title_level
    )

    if new_severity and new_severity != original:
        observation_dict["severity"] = new_severity
        raw = observation_dict.get("raw_data") or {}
        raw["original_severity"] = original
        raw["severity_override_source"] = "pre_run"
        observation_dict["raw_data"] = raw
        logger.debug(
            "Pre-run override: %s / %s: %s -> %s",
            check_name,
            title,
            original,
            new_severity,
        )

    return observation_dict


# ═══════════════════════════════════════════════════════════════════════════════
# Post-Run (Scan) Severity Overrides
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ScanOverrideRule:
    """A single scan-level severity override rule."""

    scope: dict[str, str]  # {check_name, title} — any subset
    severity: str
    reason: str | None = None


def load_scan_overrides(scan_id: str) -> list[ScanOverrideRule]:
    """Load override rules for a specific scan."""
    data = _read_yaml(_scan_override_path(scan_id))
    rules = []
    for entry in data.get("overrides", []):
        if not isinstance(entry, dict):
            continue
        scope = entry.get("scope", {})
        sev = entry.get("severity", "")
        try:
            sev = validate_severity(sev)
        except ValueError:
            logger.warning("Ignoring invalid severity '%s' in scan override %s", sev, scan_id)
            continue
        rules.append(
            ScanOverrideRule(
                scope=scope,
                severity=sev,
                reason=entry.get("reason"),
            )
        )
    return rules


def save_scan_overrides(scan_id: str, overrides: list[dict]) -> None:
    """
    Write scan override rules to YAML.

    Args:
        scan_id: The scan identifier
        overrides: List of override dicts [{scope, severity, reason}, ...]
    """
    path = _scan_override_path(scan_id)
    if not overrides:
        # Remove the file if no overrides remain
        if path.exists():
            path.unlink()
        return
    _write_yaml(path, {"overrides": overrides})


def get_scan_overrides_raw(scan_id: str) -> dict:
    """Return the raw scan overrides for API consumption."""
    return _read_yaml(_scan_override_path(scan_id))


def add_scan_override(scan_id: str, scope: dict, severity: str, reason: str | None = None) -> dict:
    """
    Add or update a scan-specific severity override.

    If an override with the same scope already exists, it is replaced.
    """
    severity = validate_severity(severity)
    data = _read_yaml(_scan_override_path(scan_id))
    overrides = data.get("overrides", [])

    # Replace existing override with same scope
    overrides = [o for o in overrides if o.get("scope") != scope]
    entry = {"scope": scope, "severity": severity}
    if reason:
        entry["reason"] = reason
    overrides.append(entry)

    save_scan_overrides(scan_id, overrides)
    return entry


def remove_scan_override(scan_id: str, scope: dict) -> bool:
    """Remove a scan override matching the given scope. Returns True if found."""
    data = _read_yaml(_scan_override_path(scan_id))
    overrides = data.get("overrides", [])
    before = len(overrides)
    overrides = [o for o in overrides if o.get("scope") != scope]
    if len(overrides) == before:
        return False
    save_scan_overrides(scan_id, overrides)
    return True


def apply_scan_overrides(observations: list[dict], scan_id: str) -> list[dict]:
    """
    Apply scan-specific severity overrides to a list of observation dicts.

    Overrides are matched by scope (narrowest wins):
      1. {check_name, title} — both must match
      2. {title} — title must match
      3. {check_name} — check_name must match

    Adds original_severity, severity_override_reason, and override_source
    to each overridden observation.

    Args:
        observations: List of observation dicts (modified in place)
        scan_id: The scan to load overrides for

    Returns:
        The same list (for chaining convenience)
    """
    rules = load_scan_overrides(scan_id)
    if not rules:
        return observations

    # Pre-sort rules by specificity: most specific first
    # Specificity = number of non-empty scope keys
    sorted_rules = sorted(rules, key=lambda r: -len(r.scope))

    for observation in observations:
        check_name = observation.get("check_name", "")
        title = observation.get("title", "")
        original = observation.get("severity", "info")

        matched_rule = _match_scan_rule(check_name, title, sorted_rules)
        if matched_rule and matched_rule.severity != original:
            observation["severity"] = matched_rule.severity
            observation["original_severity"] = original
            observation["severity_override_reason"] = matched_rule.reason
            observation["override_source"] = "post_run"

    return observations


def preview_scan_override(
    observations: list[dict],
    scope: dict,
    new_severity: str,
) -> list[dict]:
    """
    Dry-run: return observations that would be affected by an override without persisting.

    Returns list of affected observation summaries with before/after severity.
    """
    new_severity = validate_severity(new_severity)
    affected = []
    for f in observations:
        if _scope_matches(f, scope):
            affected.append(
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "check_name": f.get("check_name"),
                    "host": f.get("host"),
                    "current_severity": f.get("severity", "info"),
                    "new_severity": new_severity,
                }
            )
    return affected


# ═══════════════════════════════════════════════════════════════════════════════
# Shared Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _resolve_override(
    check_name: str,
    title: str,
    check_level: dict[str, str],
    title_level: dict[str, dict[str, str]],
) -> str | None:
    """
    Resolve which severity override applies (if any).

    Precedence: check+title > check-level.
    """
    # Check title-level first (higher precedence)
    title_overrides = title_level.get(check_name, {})
    if title in title_overrides:
        return title_overrides[title]

    # Fall back to check-level
    if check_name in check_level:
        return check_level[check_name]

    return None


def _match_scan_rule(
    check_name: str,
    title: str,
    sorted_rules: list[ScanOverrideRule],
) -> ScanOverrideRule | None:
    """Find the most specific matching scan override rule."""
    for rule in sorted_rules:
        if _scope_matches_values(check_name, title, rule.scope):
            return rule
    return None


def _scope_matches(observation: dict, scope: dict) -> bool:
    """Check if an observation matches a scope dict."""
    return _scope_matches_values(
        observation.get("check_name", ""),
        observation.get("title", ""),
        scope,
    )


def _scope_matches_values(check_name: str, title: str, scope: dict) -> bool:
    """Check if check_name/title values match a scope dict."""
    scope_check = scope.get("check_name")
    scope_title = scope.get("title")

    if scope_check and scope_title:
        return check_name == scope_check and title == scope_title
    if scope_title:
        return title == scope_title
    if scope_check:
        return check_name == scope_check
    return False
