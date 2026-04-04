"""
app/scan_advisor.py - Post-Scan Advisor (Phase 20)

Optional, rule-based advisor that analyzes completed scan results and
recommends follow-up actions. Disabled by default. Never runs checks —
only recommends.

Phase 1: Post-scan analysis only.
- Gap analysis: checks that could have run with better inputs
- Partial results: checks that errored or timed out
- Follow-up suggestions: deeper checks based on what was found
- Coverage cross-reference: suites with zero or low coverage

Usage:
    from app.scan_advisor import ScanAdvisor

    advisor = ScanAdvisor(launcher, all_checks)
    recommendations = advisor.analyze()
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Data Model ───────────────────────────────────────────────────


@dataclass
class ScanAdvisorRecommendation:
    """A single recommendation from the advisor."""

    check_name: str
    reason: str
    context_injection: dict = field(default_factory=dict)
    confidence: str = "medium"  # high, medium, low
    category: str = "gap_analysis"  # gap_analysis, config_suggestion, context_seed, speculative

    def to_dict(self) -> dict:
        return {
            "check_name": self.check_name,
            "reason": self.reason,
            "context_injection": self.context_injection,
            "confidence": self.confidence,
            "category": self.category,
        }


# ── Configuration ────────────────────────────────────────────────


@dataclass
class ScanAdvisorConfig:
    """Advisor configuration. Disabled by default."""

    enabled: bool = False
    mode: str = "post_scan"  # post_scan only for Phase 1
    auto_seed_urls: bool = False  # allow advisor to suggest context injection
    require_approval: bool = True  # user must approve each recommendation


# ── Follow-up rules ──────────────────────────────────────────────
# Maps check names to follow-up suggestions when they produce findings.
# Each entry: (suggested_check, reason, confidence)

FOLLOW_UP_RULES: list[dict] = [
    {
        "trigger_check": "port_scan",
        "trigger_condition": "findings",
        "suggest": "service_probe",
        "reason": "Port scan found open ports — service probing can identify what's running.",
        "confidence": "high",
    },
    {
        "trigger_check": "llm_endpoint_discovery",
        "trigger_condition": "findings",
        "suggest": "prompt_leakage",
        "reason": "LLM endpoints discovered — prompt leakage testing can extract system prompts.",
        "confidence": "high",
    },
    {
        "trigger_check": "mcp_discovery",
        "trigger_condition": "findings",
        "suggest": "mcp_tool_enumeration",
        "reason": "MCP servers found — enumerating available tools reveals attack surface.",
        "confidence": "high",
    },
    {
        "trigger_check": "agent_discovery",
        "trigger_condition": "findings",
        "suggest": "agent_goal_injection",
        "reason": "Agent endpoints found — goal injection testing can reveal control weaknesses.",
        "confidence": "medium",
    },
    {
        "trigger_check": "rag_discovery",
        "trigger_condition": "findings",
        "suggest": "rag_indirect_injection",
        "reason": "RAG endpoints found — indirect injection can manipulate retrieval results.",
        "confidence": "medium",
    },
    {
        "trigger_check": "header_analysis",
        "trigger_condition": "findings",
        "suggest": "cors_check",
        "reason": "Header issues found — CORS misconfig often accompanies missing security headers.",
        "confidence": "medium",
    },
    {
        "trigger_check": "default_creds",
        "trigger_condition": "findings",
        "suggest": "debug_endpoints",
        "reason": "Default credentials found — debug endpoints are likely exposed too.",
        "confidence": "high",
    },
    {
        "trigger_check": "tls_analysis",
        "trigger_condition": "findings",
        "suggest": "hsts_preload",
        "reason": "TLS issues found — HSTS preload status should be verified.",
        "confidence": "medium",
    },
    {
        "trigger_check": "openapi_check",
        "trigger_condition": "findings",
        "suggest": "mass_assignment",
        "reason": "OpenAPI spec found — mass assignment testing on documented endpoints.",
        "confidence": "medium",
    },
    {
        "trigger_check": "content_filter",
        "trigger_condition": "findings",
        "suggest": "jailbreak_testing",
        "reason": "Content filter weaknesses detected — jailbreak testing may bypass them entirely.",
        "confidence": "high",
    },
]

# ── Suite coverage expectations ──────────────────────────────────
# Minimum checks expected per suite for reasonable coverage.

SUITE_COVERAGE_THRESHOLDS: dict[str, int] = {
    "network": 3,
    "web": 4,
    "ai": 2,
    "mcp": 1,
    "agent": 1,
    "rag": 1,
    "cag": 1,
}


# ── Advisor Engine ───────────────────────────────────────────────


class ScanAdvisor:
    """
    Rule-based post-scan advisor.

    Consumes the completed state of a CheckLauncher and the full check
    registry to produce recommendations. Does not execute anything.
    """

    def __init__(
        self,
        completed: set[str],
        failed: set[str],
        skipped: set[str],
        all_check_names: set[str],
        context: dict[str, Any],
        findings: list[dict],
        check_metadata: dict[str, dict],
        config: ScanAdvisorConfig | None = None,
    ):
        """
        Args:
            completed: Names of checks that ran successfully.
            failed: Names of checks that errored.
            skipped: Names of checks skipped (on_critical or other).
            all_check_names: Names of ALL checks in the registry.
            context: Final context dict after scan.
            findings: All findings produced.
            check_metadata: Per-check metadata (conditions, produces, suite).
            config: Advisor configuration.
        """
        self.completed = completed
        self.failed = failed
        self.skipped = skipped
        self.all_check_names = all_check_names
        self.context = context
        self.findings = findings
        self.check_metadata = check_metadata
        self.config = config or ScanAdvisorConfig()

    def analyze(self) -> list[ScanAdvisorRecommendation]:
        """Run all post-scan analysis rules. Returns recommendations."""
        if not self.config.enabled:
            logger.debug("Scan advisor is disabled — skipping analysis")
            return []

        logger.info("Scan advisor: running post-scan analysis")
        recommendations: list[ScanAdvisorRecommendation] = []

        recommendations.extend(self._analyze_gaps())
        recommendations.extend(self._analyze_partial_results())
        recommendations.extend(self._analyze_follow_ups())
        recommendations.extend(self._analyze_coverage())

        # Deduplicate by check_name (keep first / highest confidence)
        seen = set()
        deduped = []
        for rec in recommendations:
            if rec.check_name not in seen:
                seen.add(rec.check_name)
                deduped.append(rec)

        logger.info(f"Scan advisor: {len(deduped)} recommendations")
        return deduped

    # ── Gap Analysis ─────────────────────────────────────────────

    def _analyze_gaps(self) -> list[ScanAdvisorRecommendation]:
        """
        Identify checks that didn't run because conditions weren't met,
        but COULD run if the operator provided missing context data.
        """
        recs = []
        ran = self.completed | self.failed | self.skipped
        never_ran = self.all_check_names - ran

        for name in sorted(never_ran):
            meta = self.check_metadata.get(name)
            if not meta:
                continue

            conditions = meta.get("conditions", [])
            if not conditions:
                continue

            # Figure out which conditions were unmet
            missing_keys = []
            for cond_str in conditions:
                # Condition strings look like "services truthy" or "target_hosts truthy"
                parts = cond_str.split()
                if len(parts) >= 2:
                    key = parts[0]
                    if not self.context.get(key):
                        missing_keys.append(key)

            if missing_keys:
                recs.append(
                    ScanAdvisorRecommendation(
                        check_name=name,
                        reason=(
                            f"Check '{name}' could not run — missing context: "
                            f"{', '.join(missing_keys)}. "
                            f"Providing this data manually would enable the check."
                        ),
                        context_injection=dict.fromkeys(missing_keys),
                        confidence="medium",
                        category="gap_analysis",
                    )
                )

        return recs

    # ── Partial Results ──────────────────────────────────────────

    def _analyze_partial_results(self) -> list[ScanAdvisorRecommendation]:
        """Flag checks that failed or were skipped."""
        recs = []

        for name in sorted(self.failed):
            recs.append(
                ScanAdvisorRecommendation(
                    check_name=name,
                    reason=(
                        f"Check '{name}' failed during execution. "
                        f"Re-running with adjusted configuration or timeout may succeed."
                    ),
                    confidence="medium",
                    category="gap_analysis",
                )
            )

        for name in sorted(self.skipped):
            recs.append(
                ScanAdvisorRecommendation(
                    check_name=name,
                    reason=(
                        f"Check '{name}' was skipped due to on_critical policy. "
                        f"Running it separately may reveal additional findings on the affected hosts."
                    ),
                    confidence="low",
                    category="gap_analysis",
                )
            )

        return recs

    # ── Follow-Up Suggestions ────────────────────────────────────

    def _analyze_follow_ups(self) -> list[ScanAdvisorRecommendation]:
        """
        If certain checks produced findings, suggest deeper follow-up
        checks that weren't already run.
        """
        recs = []
        ran = self.completed | self.failed | self.skipped

        # Build set of checks that produced findings
        checks_with_findings = {f.get("check_name") for f in self.findings if f.get("check_name")}

        for rule in FOLLOW_UP_RULES:
            trigger = rule["trigger_check"]
            suggest = rule["suggest"]

            # Only fire if the trigger check ran AND produced findings
            if trigger not in checks_with_findings:
                continue

            # Only suggest if the follow-up didn't already run
            if suggest in ran:
                continue

            # Only suggest if the follow-up exists in the registry
            if suggest not in self.all_check_names:
                continue

            recs.append(
                ScanAdvisorRecommendation(
                    check_name=suggest,
                    reason=rule["reason"],
                    confidence=rule["confidence"],
                    category="gap_analysis",
                )
            )

        return recs

    # ── Coverage Cross-Reference ─────────────────────────────────

    def _analyze_coverage(self) -> list[ScanAdvisorRecommendation]:
        """
        Check if any suite has zero or very low coverage relative to
        the number of checks available for that suite.
        """
        from app.check_resolver import infer_suite

        recs = []

        # Count how many checks ran per suite
        suite_ran: dict[str, int] = {}
        suite_total: dict[str, int] = {}

        for name in self.all_check_names:
            suite = infer_suite(name)
            suite_total[suite] = suite_total.get(suite, 0) + 1

        for name in self.completed:
            suite = infer_suite(name)
            suite_ran[suite] = suite_ran.get(suite, 0) + 1

        for suite, threshold in SUITE_COVERAGE_THRESHOLDS.items():
            total = suite_total.get(suite, 0)
            ran = suite_ran.get(suite, 0)

            if total == 0:
                continue

            if ran == 0:
                recs.append(
                    ScanAdvisorRecommendation(
                        check_name=f"{suite}_suite",
                        reason=(
                            f"No checks ran from the '{suite}' suite "
                            f"({total} available). Consider running the "
                            f"'{suite}' suite to identify {suite}-specific issues."
                        ),
                        confidence="low",
                        category="config_suggestion",
                    )
                )
            elif ran < threshold and ran < total:
                recs.append(
                    ScanAdvisorRecommendation(
                        check_name=f"{suite}_suite",
                        reason=(
                            f"Only {ran}/{total} checks ran from the '{suite}' suite "
                            f"(threshold: {threshold}). Coverage may be incomplete."
                        ),
                        confidence="low",
                        category="config_suggestion",
                    )
                )

        return recs


# ── Factory helper ───────────────────────────────────────────────


def build_advisor_from_launcher(
    launcher,
    all_checks: list,
    config: ScanAdvisorConfig | None = None,
) -> ScanAdvisor:
    """
    Build a ScanAdvisor from a completed CheckLauncher and the full
    check registry.

    Args:
        launcher: A CheckLauncher that has finished run_all().
        all_checks: Full list of check instances from get_real_checks().
        config: Optional advisor config override.
    """
    from app.engine.scanner import get_check_info

    all_check_names = {c.name for c in all_checks}
    check_metadata = {c.name: get_check_info(c) for c in all_checks}

    return ScanAdvisor(
        completed=set(launcher.completed),
        failed=set(launcher.failed),
        skipped=set(launcher.skipped),
        all_check_names=all_check_names,
        context=dict(launcher.context),
        findings=list(launcher.findings),
        check_metadata=check_metadata,
        config=config,
    )
