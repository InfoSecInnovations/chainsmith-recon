"""
app/advisors/scan_planner_advisor.py - Pre-Scan Planning Advisor (Phase 41)

Rule-based advisor that analyzes the current scope, target characteristics,
and available checks to produce planning recommendations BEFORE the operator
starts scanning.

Responsibilities:
- Scope completeness: flag missing exclusions, suggest common patterns
- Check selection guidance: recommend suites based on target characteristics
- Scan readiness: verify scope, proof-of-scope, prerequisites
- Target analysis: identify target characteristics and suggest strategies

This advisor never modifies scope or executes checks. It recommends —
the operator decides.

Usage:
    from app.advisors.scan_planner_advisor import ScanPlannerAdvisor

    advisor = ScanPlannerAdvisor(scope, available_checks, check_metadata, proof_config)
    recommendations = advisor.analyze()
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from app.models import ScopeDefinition

logger = logging.getLogger(__name__)


# ── Data Model ───────────────────────────────────────────────────


@dataclass
class ScanPlannerRecommendation:
    """A single pre-scan planning recommendation."""

    category: str  # scope_completeness, check_selection, readiness, target_analysis
    reason: str
    suggestion: str  # actionable recommendation
    confidence: str = "medium"  # high, medium, low
    auto_fixable: bool = False  # can the system apply this automatically?
    fix_action: dict = field(default_factory=dict)  # e.g., {"add_exclusion": "cdn.example.com"}

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "reason": self.reason,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "auto_fixable": self.auto_fixable,
            "fix_action": self.fix_action if self.fix_action else None,
        }


# ── Known CDN / third-party patterns ────────────────────────────
# Domains that commonly appear in scope but are third-party infrastructure.

KNOWN_THIRD_PARTY_PATTERNS: list[str] = [
    "cdn.",
    "cloudfront.net",
    "cloudflare.",
    "akamai.",
    "fastly.",
    "googleapis.com",
    "googleusercontent.com",
    "amazonaws.com",
    "azurewebsites.net",
    "azureedge.net",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "firebase.",
    "herokuapp.com",
    "netlify.app",
    "vercel.app",
    "pages.dev",
]

# ── AI-related check name patterns ───────────────────────────────

AI_CHECK_PATTERNS: list[str] = [
    "llm_",
    "prompt_",
    "ai_",
    "mcp_",
    "agent_",
    "rag_",
    "cag_",
    "jailbreak",
    "content_filter",
]


# ── Advisor Engine ───────────────────────────────────────────────


class ScanPlannerAdvisor:
    """
    Rule-based pre-scan planning advisor.

    Analyzes scope definition, available checks, and configuration
    to produce recommendations before the operator starts scanning.
    Does not execute anything or modify scope.
    """

    def __init__(
        self,
        scope: ScopeDefinition,
        available_checks: set[str],
        check_metadata: dict[str, dict],
        proof_of_scope_config: dict[str, Any],
    ):
        """
        Args:
            scope: Current scope definition (domains, exclusions, etc.).
            available_checks: Names of all available checks in the registry.
            check_metadata: Per-check metadata (suite, conditions, etc.).
            proof_of_scope_config: Proof-of-scope configuration dict.
        """
        self.scope = scope
        self.available_checks = available_checks
        self.check_metadata = check_metadata
        self.proof_of_scope_config = proof_of_scope_config

    def analyze(self) -> list[ScanPlannerRecommendation]:
        """Run all pre-scan planning rules. Returns recommendations."""
        logger.info("Scan planner: running pre-scan analysis")
        recommendations: list[ScanPlannerRecommendation] = []

        recommendations.extend(self._check_no_exclusions())
        recommendations.extend(self._check_third_party_in_scope())
        recommendations.extend(self._check_proof_of_scope())
        recommendations.extend(self._check_ai_suite_suggestion())
        recommendations.extend(self._check_scan_window())
        recommendations.extend(self._check_single_domain_broad_ports())

        logger.info(f"Scan planner: {len(recommendations)} recommendations")
        return recommendations

    # ── Rule: No exclusions defined ──────────────────────────────

    def _check_no_exclusions(self) -> list[ScanPlannerRecommendation]:
        """Flag when no out-of-scope domains are defined."""
        if self.scope.out_of_scope_domains:
            return []

        if not self.scope.in_scope_domains:
            return []

        return [
            ScanPlannerRecommendation(
                category="scope_completeness",
                reason="No exclusions defined in scope.",
                suggestion=(
                    "Consider adding out-of-scope domains to prevent scanning "
                    "third-party infrastructure, shared services, or login portals "
                    "that shouldn't be tested."
                ),
                confidence="medium",
            )
        ]

    # ── Rule: Known CDN / third-party in scope ───────────────────

    def _check_third_party_in_scope(self) -> list[ScanPlannerRecommendation]:
        """Flag in-scope domains that match known CDN/third-party patterns."""
        recs = []
        for domain in self.scope.in_scope_domains:
            domain_lower = domain.lower()
            for pattern in KNOWN_THIRD_PARTY_PATTERNS:
                if pattern in domain_lower:
                    # Check it's not already excluded
                    already_excluded = any(
                        pattern in exc.lower() for exc in self.scope.out_of_scope_domains
                    )
                    if not already_excluded:
                        recs.append(
                            ScanPlannerRecommendation(
                                category="scope_completeness",
                                reason=(
                                    f"Domain '{domain}' matches known third-party "
                                    f"pattern '{pattern}'. Scanning third-party "
                                    f"infrastructure may be out of scope."
                                ),
                                suggestion=f"Consider excluding '{domain}' unless explicitly authorized.",
                                confidence="high",
                                auto_fixable=True,
                                fix_action={"add_exclusion": domain},
                            )
                        )
                    break  # Only flag once per domain
        return recs

    # ── Rule: No proof-of-scope configured ───────────────────────

    def _check_proof_of_scope(self) -> list[ScanPlannerRecommendation]:
        """Flag when proof-of-scope is not configured for external targets."""
        pos_enabled = self.proof_of_scope_config.get("enabled", False)
        if pos_enabled:
            return []

        if not self.scope.in_scope_domains:
            return []

        return [
            ScanPlannerRecommendation(
                category="readiness",
                reason="Proof-of-scope is not configured.",
                suggestion=(
                    "For external targets, consider configuring proof-of-scope "
                    "(DNS TXT record, meta tag, or file-based verification) to "
                    "confirm authorization before scanning."
                ),
                confidence="medium",
            )
        ]

    # ── Rule: AI suite suggestion ────────────────────────────────

    def _check_ai_suite_suggestion(self) -> list[ScanPlannerRecommendation]:
        """
        Suggest AI suite checks when API-related checks are available
        but no AI-specific checks appear to be selected.
        """
        # Find all AI-related checks available
        ai_checks = set()
        for name in self.available_checks:
            name_lower = name.lower()
            if any(pattern in name_lower for pattern in AI_CHECK_PATTERNS):
                ai_checks.add(name)

        if not ai_checks:
            return []

        # Check metadata for suite info
        ai_suite_checks = set()
        for name, meta in self.check_metadata.items():
            suite = meta.get("suite", "")
            if suite in ("ai", "mcp", "agent", "rag", "cag"):
                ai_suite_checks.add(name)

        if not ai_suite_checks:
            return []

        # Look for API-related keywords in scope domains that suggest AI targets
        api_hints = ["api.", "api-", "chat.", "ai.", "llm.", "openai.", "model."]
        has_api_hint = any(
            any(hint in d.lower() for hint in api_hints) for d in self.scope.in_scope_domains
        )

        if has_api_hint:
            return [
                ScanPlannerRecommendation(
                    category="check_selection",
                    reason=(
                        "Target domains suggest AI/API endpoints. "
                        f"{len(ai_suite_checks)} AI-related checks are available."
                    ),
                    suggestion=(
                        "Consider enabling the AI, MCP, or agent suites to test "
                        "for prompt injection, jailbreaks, and model-specific vulnerabilities."
                    ),
                    confidence="medium",
                )
            ]

        return []

    # ── Rule: Scan window not set ────────────────────────────────

    def _check_scan_window(self) -> list[ScanPlannerRecommendation]:
        """Flag when no time window is defined for the scan."""
        if self.scope.time_window:
            return []

        if not self.scope.in_scope_domains:
            return []

        return [
            ScanPlannerRecommendation(
                category="readiness",
                reason="No scan time window defined.",
                suggestion=(
                    "Consider setting a time window for the scan to "
                    "document the authorized testing period."
                ),
                confidence="low",
            )
        ]

    # ── Rule: Single domain, broad port range ────────────────────

    def _check_single_domain_broad_ports(self) -> list[ScanPlannerRecommendation]:
        """Flag when there's a single domain with all-ports profile."""
        if len(self.scope.in_scope_domains) != 1:
            return []

        # Check if ports include a very broad range
        if self.scope.in_scope_ports and len(self.scope.in_scope_ports) > 1000:
            return [
                ScanPlannerRecommendation(
                    category="target_analysis",
                    reason=(
                        "Single target domain with a broad port range "
                        f"({len(self.scope.in_scope_ports)} ports)."
                    ),
                    suggestion=(
                        "A broad port scan on a single domain will be slow. "
                        "Consider using a focused port profile (web, ai) unless "
                        "full port coverage is required."
                    ),
                    confidence="low",
                )
            ]

        return []
