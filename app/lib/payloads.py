"""
app/lib/payloads.py - Injection Payload Library

Load and query injection payloads for reconnaissance checks.

Usage:
    from app.lib.payloads import PayloadLibrary

    library = PayloadLibrary()

    # Get payloads by category
    goal_payloads = library.get_category("goal_injection")

    # Get payloads by technique
    jailbreak_payloads = library.get_by_technique("jailbreak")

    # Get payloads by severity
    critical_payloads = library.get_by_severity("critical")

    # Get specific payload
    payload = library.get_payload("goal_injection", "system_prompt_leak")
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Payload:
    """A single injection payload."""

    id: str
    name: str
    payload: str
    success_indicators: list[str]
    severity: str
    technique: str
    category: str
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "payload": self.payload,
            "success_indicators": self.success_indicators,
            "severity": self.severity,
            "technique": self.technique,
            "category": self.category,
            "note": self.note,
        }


class PayloadLibrary:
    """
    Load and query injection payloads.

    Payloads are organized by category:
    - goal_injection: Direct agent goal hijacking
    - indirect_injection: RAG/document-based injection
    - jailbreak: Constraint bypass and roleplay attacks
    - information_extraction: System info extraction
    - delimiter_escape: Format and delimiter exploitation
    - authority_bypass: Privilege escalation attempts
    - context_manipulation: Context window attacks
    - mcp_specific: MCP tool-calling attacks
    - cache_specific: CAG cache attacks
    """

    DEFAULT_PATH = Path(__file__).parent.parent / "data" / "injection_payloads.json"

    def __init__(self, path: Path | None = None):
        self.path = path or self.DEFAULT_PATH
        self._data: dict = {}
        self._payloads: dict[str, dict[str, Payload]] = {}
        self._load()

    def _load(self):
        """Load payloads from JSON file."""
        try:
            with open(self.path) as f:
                self._data = json.load(f)
            self._index_payloads()
        except FileNotFoundError:
            self._data = {"meta": {}}
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid payload file: {e}") from e

    def _index_payloads(self):
        """Index payloads by category and ID."""
        for category, category_data in self._data.items():
            if category == "meta":
                continue

            if not isinstance(category_data, dict):
                continue

            payloads = category_data.get("payloads", [])
            self._payloads[category] = {}

            for p in payloads:
                payload = Payload(
                    id=p.get("id", ""),
                    name=p.get("name", ""),
                    payload=p.get("payload", ""),
                    success_indicators=p.get("success_indicators", []),
                    severity=p.get("severity", "medium"),
                    technique=p.get("technique", "unknown"),
                    category=category,
                    note=p.get("note"),
                )
                self._payloads[category][payload.id] = payload

    @property
    def categories(self) -> list[str]:
        """Get all available categories."""
        return list(self._payloads.keys())

    @property
    def meta(self) -> dict:
        """Get library metadata."""
        return self._data.get("meta", {})

    def get_category(self, category: str) -> list[Payload]:
        """Get all payloads in a category."""
        return list(self._payloads.get(category, {}).values())

    def get_payload(self, category: str, payload_id: str) -> Payload | None:
        """Get a specific payload by category and ID."""
        return self._payloads.get(category, {}).get(payload_id)

    def get_by_technique(self, technique: str) -> list[Payload]:
        """Get all payloads using a specific technique."""
        results = []
        for category_payloads in self._payloads.values():
            for payload in category_payloads.values():
                if payload.technique == technique:
                    results.append(payload)
        return results

    def get_by_severity(self, severity: str) -> list[Payload]:
        """Get all payloads of a specific severity."""
        results = []
        for category_payloads in self._payloads.values():
            for payload in category_payloads.values():
                if payload.severity == severity:
                    results.append(payload)
        return results

    def get_all(self) -> list[Payload]:
        """Get all payloads."""
        results = []
        for category_payloads in self._payloads.values():
            results.extend(category_payloads.values())
        return results

    def search(self, query: str) -> list[Payload]:
        """Search payloads by name, ID, or payload content."""
        query_lower = query.lower()
        results = []
        for category_payloads in self._payloads.values():
            for payload in category_payloads.values():
                if (
                    query_lower in payload.id.lower()
                    or query_lower in payload.name.lower()
                    or query_lower in payload.payload.lower()
                ):
                    results.append(payload)
        return results

    def get_for_check(self, check_type: str) -> list[Payload]:
        """
        Get payloads appropriate for a specific check type.

        Args:
            check_type: One of "agent", "rag", "mcp", "cag", "llm"

        Returns:
            List of relevant payloads
        """
        mapping = {
            "agent": ["goal_injection", "jailbreak", "information_extraction"],
            "rag": ["indirect_injection", "delimiter_escape", "context_manipulation"],
            "mcp": ["mcp_specific", "information_extraction", "authority_bypass"],
            "cag": ["cache_specific", "context_manipulation"],
            "llm": ["jailbreak", "information_extraction", "authority_bypass"],
        }

        categories = mapping.get(check_type, [])
        results = []
        for category in categories:
            results.extend(self.get_category(category))
        return results

    def count(self) -> dict[str, int]:
        """Get payload counts by category."""
        return {category: len(payloads) for category, payloads in self._payloads.items()}

    def stats(self) -> dict:
        """Get library statistics."""
        all_payloads = self.get_all()

        severity_counts = {}
        technique_counts = {}

        for p in all_payloads:
            severity_counts[p.severity] = severity_counts.get(p.severity, 0) + 1
            technique_counts[p.technique] = technique_counts.get(p.technique, 0) + 1

        return {
            "total_payloads": len(all_payloads),
            "categories": len(self._payloads),
            "by_category": self.count(),
            "by_severity": severity_counts,
            "by_technique": technique_counts,
        }


# Singleton instance for convenience
_library: PayloadLibrary | None = None


def get_payload_library() -> PayloadLibrary:
    """Get the singleton payload library instance."""
    global _library
    if _library is None:
        _library = PayloadLibrary()
    return _library


def get_payloads(category: str) -> list[Payload]:
    """Convenience function to get payloads by category."""
    return get_payload_library().get_category(category)


def get_payloads_for_check(check_type: str) -> list[Payload]:
    """Convenience function to get payloads for a check type."""
    return get_payload_library().get_for_check(check_type)
