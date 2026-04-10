"""
Framework tag parsing and YAML definition loader.

Each compliance framework (OWASP, MITRE ATLAS, CWE, etc.) is defined by a
YAML file in the ``definitions/`` directory.  The loader auto-discovers all
YAML files at import time and compiles their regex patterns for fast matching.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFINITIONS_DIR = Path(__file__).parent / "definitions"


@dataclass(frozen=True)
class FrameworkTag:
    """A single framework reference parsed from a check's reference string."""

    framework: str  # e.g. "MITRE ATLAS"
    short_label: str  # e.g. "ATLAS"
    tag_id: str  # e.g. "AML.T0054"
    url: str  # full link to reference page
    badge_color: str  # hex color


@dataclass
class FrameworkDefinition:
    """In-memory representation of one YAML definition file."""

    name: str
    short_label: str
    pattern: re.Pattern
    url_template: str
    badge_color: str
    id_prefix: str = ""  # prepended to captured group for display tag_id

    def match(self, reference: str) -> FrameworkTag | None:
        m = self.pattern.search(reference)
        if not m:
            return None
        raw_id = m.group(1)
        tag_id = f"{self.id_prefix}{raw_id}"
        return FrameworkTag(
            framework=self.name,
            short_label=self.short_label,
            tag_id=tag_id,
            url=self.url_template.replace("{id}", raw_id),
            badge_color=self.badge_color,
        )


def _load_definitions() -> list[FrameworkDefinition]:
    """Load all YAML files from the definitions directory."""
    defs: list[FrameworkDefinition] = []
    if not DEFINITIONS_DIR.is_dir():
        return defs
    for path in sorted(DEFINITIONS_DIR.glob("*.yaml")):
        if path.stem.endswith("-controls"):
            continue  # skip control catalog files
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "pattern" not in data:
            continue
        defs.append(
            FrameworkDefinition(
                name=data["name"],
                short_label=data["short_label"],
                pattern=re.compile(data["pattern"]),
                url_template=data["url_template"],
                badge_color=data["badge_color"],
                id_prefix=data.get("id_prefix", ""),
            )
        )
    return defs


# Loaded once at import time.
_DEFINITIONS: list[FrameworkDefinition] = _load_definitions()


def parse_all(references: list[str]) -> list[dict]:
    """Match reference strings against all loaded framework definitions.

    Returns a list of dicts (JSON-serialisable) with keys:
    framework, short_label, tag_id, url, badge_color.
    """
    tags: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for ref in references:
        for defn in _DEFINITIONS:
            tag = defn.match(ref)
            if tag and (tag.framework, tag.tag_id) not in seen:
                seen.add((tag.framework, tag.tag_id))
                tags.append(
                    {
                        "framework": tag.framework,
                        "short_label": tag.short_label,
                        "tag_id": tag.tag_id,
                        "url": tag.url,
                        "badge_color": tag.badge_color,
                    }
                )
    return tags
