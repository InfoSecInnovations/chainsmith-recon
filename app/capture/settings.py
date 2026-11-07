"""
app/capture/settings.py - What gets captured.

Defaults are conservative on volume and generous on the corpus that matters:

  * **Observation-linked exchanges by default.** `network_port_scan` and
    `network_dns_enumeration` can emit thousands, and their evidence is not what
    makes grading possible.

  * **The AI, MCP, agent, RAG, and CAG suites always capture in full**, whatever
    the flag says. That corpus is the entire point of phase 58, and a partial
    one would not support it.

  * **Non-HTTP protocols are opt-in.** A `dns` or `tcp` row is cheap to write and
    rarely what a grader reads. The `protocol` column exists so that turning
    them on is a config change rather than a schema change.

  * **Completed pairs only.** A failed probe is usually target flakiness. But a
    refused connection, or a timeout that appears consistently under one
    specific payload, is occasionally the whole finding — hence
    `capture_failures` as a toggle rather than a hard rule.

Capture is **off by default while 57.2 is scaffolding**: nothing writes evidence
until the producers are wired and the growth number from §9 is measured. Turning
it on is `enabled: true`, one flag, once the corpus is understood.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from app.capture.models import MAX_BODY_BYTES
from app.capture.protocols import DEFAULT_PROTOCOLS

#: Suites whose evidence is the reason phase 58 exists. Always captured in full.
ALWAYS_FULL_CAPTURE_SUITES: frozenset[str] = frozenset({"ai", "mcp", "agent", "rag", "cag"})


@dataclass(frozen=True)
class CaptureSettings:
    """Scan-level capture posture."""

    #: Master switch. Off while 57.2 is scaffolding — see the module docstring.
    enabled: bool = False

    #: Which protocols to record. HTTP and LLM by default; the rest opt-in.
    protocols: frozenset[str] = field(default_factory=lambda: DEFAULT_PROTOCOLS)

    #: Record every exchange, not only observation-linked ones.
    full_capture: bool = False

    #: Record probes that never completed, with `error` set and no response.
    capture_failures: bool = False

    #: Per-body size cap in bytes; larger bodies are truncated and flagged.
    max_body_bytes: int = MAX_BODY_BYTES

    @classmethod
    def from_request(
        cls,
        enabled: bool = False,
        protocols: list[str] | None = None,
        full_capture: bool = False,
        capture_failures: bool = False,
        max_body_bytes: int | None = None,
    ) -> CaptureSettings:
        """
        Build a posture from what a scan request asked for (57.2 item 4).

        An empty `protocols` list means "the defaults" rather than "nothing":
        an operator who turns capture on and names no protocol wants HTTP and
        LLM, which is what the corpus is for. Naming none explicitly and
        meaning it is `enabled: false`.
        """
        return cls(
            enabled=enabled,
            protocols=frozenset(protocols) if protocols else DEFAULT_PROTOCOLS,
            full_capture=full_capture,
            capture_failures=capture_failures,
            max_body_bytes=max_body_bytes or MAX_BODY_BYTES,
        )

    def captures(self, protocol: str) -> bool:
        """Is this protocol being recorded?"""
        return protocol in self.protocols

    def with_protocols(self, *protocols: str) -> CaptureSettings:
        """A copy recording exactly these protocols."""
        return replace(self, protocols=frozenset(protocols))

    def always_full(self, suite: str) -> bool:
        """Does this suite bypass a narrower per-check policy?"""
        return suite in ALWAYS_FULL_CAPTURE_SUITES

    def effective_policy(self, policy: str, suite: str) -> str:
        """
        The policy actually applied to one check (57.2, D-20).

        `full_capture` is the scan-level override an operator reaches for when
        they want everything regardless of what the check authors chose, and
        the AI suites are exempt from narrowing in either direction: that corpus
        is the entire point of phase 58, and a partial one would not support it.
        """
        if self.full_capture or self.always_full(suite):
            return "all"
        return policy


# ── Process-wide settings ────────────────────────────────────────

_settings: CaptureSettings | None = None


def get_settings() -> CaptureSettings:
    global _settings
    if _settings is None:
        _settings = CaptureSettings()
    return _settings


def set_settings(settings: CaptureSettings) -> CaptureSettings:
    """Install the capture posture. Called at scan launch, and by tests."""
    global _settings
    _settings = settings
    return settings


def reset_settings() -> None:
    """Restore defaults. For tests."""
    global _settings
    _settings = None
