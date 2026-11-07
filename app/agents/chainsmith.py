"""
Chainsmith Agent

Maintains, curates, and validates an organization's check ecosystem.
Guides operators on crafting custom checks and attack chain patterns.
Builds attack chains from verified observations.

Chainsmith is not in the scan pipeline — it manages the pipeline itself.

Capabilities:
- Graph validation (dead checks, orphaned outputs, shadow conflicts, cycles)
- Attack chain pattern validation (broken references, unreachable patterns)
- Attack chain building from verified observations
- Content-aware analysis (semantic overlap, coverage gaps — LLM-powered)
- Guided customization (scaffold new checks, impact analysis for disabling)

All operations are advisory. Chainsmith never blocks scans.
Persistence: database via ChainsmithRepository.
"""

import hashlib
import inspect
import json
import logging
import os
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

import yaml

from app.checks.base import BaseCheck
from app.config import ATTACK_PATTERNS_PATH
from app.lib.llm import get_llm_client
from app.models import (
    AgentEvent,
    AttackChain,
    ComponentType,
    EventImportance,
    EventType,
    Observation,
    ObservationStatus,
)

logger = logging.getLogger(__name__)

# Seed keys injected by scanner.py before any checks run
SEED_CONTEXT_KEYS = frozenset(
    {
        "base_domain",
        "scope_domains",
        "excluded_domains",
        "services",
        "port_profile",
    }
)

CUSTOM_DIR = os.path.join(os.path.dirname(__file__), "..", "checks", "custom")
COMMUNITY_DIRS = ["network", "web", "ai", "mcp", "agent", "rag", "cag"]


# ═══════════════════════════════════════════════════════════════════════════════
# Validation result models
# ═══════════════════════════════════════════════════════════════════════════════


class ValidationIssue:
    """A single issue found during validation."""

    def __init__(
        self,
        category: str,
        severity: str,
        message: str,
        check_name: str | None = None,
        suggestion: str | None = None,
    ):
        self.category = category
        self.severity = severity
        self.message = message
        self.check_name = check_name
        self.suggestion = suggestion

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "check_name": self.check_name,
            "suggestion": self.suggestion,
        }

    def __repr__(self) -> str:
        return f"[{self.severity.upper()}] {self.category}: {self.message}"


class ValidationResult:
    """Aggregate result of a full validation run."""

    def __init__(self):
        self.issues: list[ValidationIssue] = []
        self.checks_analyzed: int = 0
        self.patterns_analyzed: int = 0
        self.timestamp: str = datetime.now(UTC).isoformat()

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def healthy(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        if not self.issues:
            return (
                f"Check graph is healthy. {self.checks_analyzed} checks analyzed, "
                f"{self.patterns_analyzed} chain patterns validated. No issues found."
            )
        lines = [
            f"Validation complete: {self.checks_analyzed} checks, "
            f"{self.patterns_analyzed} patterns. "
            f"Found {len(self.errors)} error(s), {len(self.warnings)} warning(s)."
        ]
        for i, issue in enumerate(self.issues, 1):
            prefix = "ERROR" if issue.severity == "error" else "WARN"
            lines.append(f"  {i}. [{prefix}] {issue.message}")
            if issue.suggestion:
                lines.append(f"     Suggestion: {issue.suggestion}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "healthy": self.healthy,
            "checks_analyzed": self.checks_analyzed,
            "patterns_analyzed": self.patterns_analyzed,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "issues": [i.to_dict() for i in self.issues],
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Chainsmith Agent
# ═══════════════════════════════════════════════════════════════════════════════


class ChainsmithAgent:
    """Chainsmith — check ecosystem manager and chain builder.

    Validates and curates the check ecosystem, guides custom check and
    chain pattern creation, and builds attack chains from observations.
    Runs on operator demand only — not in the scan pipeline.
    """

    def __init__(
        self,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
        llm_client=None,
    ):
        self.event_callback = event_callback
        self.llm_client = llm_client
        self.chains: list[AttackChain] = []
        self.attack_patterns = self._load_patterns()
        self.client = get_llm_client()

    def _load_patterns(self) -> list[dict]:
        """Load attack patterns from knowledge base."""
        try:
            with open(ATTACK_PATTERNS_PATH) as f:
                data = json.load(f)
                return data.get("patterns", [])
        except (FileNotFoundError, OSError, json.JSONDecodeError, KeyError):
            return []

    async def emit(self, event: AgentEvent):
        if self.event_callback:
            await self.event_callback(event)

    # ═══════════════════════════════════════════════════════════════
    # Validation
    # ═══════════════════════════════════════════════════════════════

    async def validate(self, checks: list[BaseCheck] | None = None) -> ValidationResult:
        """Run full validation: graph + chain patterns.

        If checks is None, loads all checks via check_resolver.
        """
        await self.emit(
            AgentEvent(
                event_type=EventType.CHAINSMITH_VALIDATION_START,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message="Starting check ecosystem validation...",
            )
        )

        if checks is None:
            from app.check_resolver import get_real_checks

            checks = get_real_checks()

        result = ValidationResult()
        result.checks_analyzed = len(checks)

        self._validate_graph(checks, result)
        self._validate_chain_patterns(checks, result)
        self._validate_custom_check_health(result)

        await self.emit(
            AgentEvent(
                event_type=EventType.CHAINSMITH_VALIDATION_COMPLETE,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=result.summary(),
                details=result.to_dict(),
            )
        )

        for issue in result.issues:
            await self.emit(
                AgentEvent(
                    event_type=EventType.CHAINSMITH_ISSUE_FOUND,
                    agent=ComponentType.CHAINSMITH,
                    importance=(
                        EventImportance.HIGH
                        if issue.severity == "error"
                        else EventImportance.MEDIUM
                    ),
                    message=f"[{issue.category}] {issue.message}",
                    details=issue.to_dict(),
                )
            )

        return result

    async def analyze_content(self, checks: list[BaseCheck] | None = None) -> str:
        """Content-aware analysis using LLM.

        Reads check implementations and reasons about semantic overlap,
        coverage gaps, and condition adequacy. Falls back to metadata-only
        validation if no LLM client is available.
        """
        if self.llm_client is None:
            return (
                "Content-aware analysis requires an LLM client. "
                "Run metadata-only validation with `validate` instead."
            )

        if checks is None:
            from app.check_resolver import get_real_checks

            checks = get_real_checks()

        check_summaries = []
        for check in checks:
            summary = self._extract_check_summary(check)
            if summary:
                check_summaries.append(summary)

        if not check_summaries:
            return "No check implementations could be read for analysis."

        prompt = self._build_content_analysis_prompt(check_summaries)

        response = await self.llm_client.chat(
            prompt=prompt,
            system=(
                "You are a security check ecosystem analyst. You review check "
                "implementations for a security reconnaissance tool and identify: "
                "semantic overlap between checks (confidence threshold: 0.7+), "
                "coverage gaps in the check set, and conditions that are looser "
                "or tighter than what the code actually needs. Be specific and "
                "actionable. Reference check names directly."
            ),
            temperature=0.2,
            max_tokens=2000,
        )

        if not response.success:
            return f"Content analysis failed: {response.error}. Use `validate` for metadata-only validation."

        return response.content

    async def suggest_disable_impact(
        self, check_names: list[str], all_checks: list[BaseCheck] | None = None
    ) -> str:
        """Show what breaks if the given checks are disabled."""
        if all_checks is None:
            from app.check_resolver import get_real_checks

            all_checks = get_real_checks()

        check_map = {c.name: c for c in all_checks}
        disabled = set(check_names)

        produces_map: dict[str, str] = {}
        for check in all_checks:
            if check.name not in disabled:
                for key in check.produces:
                    produces_map[key] = check.name

        broken = []
        for check in all_checks:
            if check.name in disabled:
                continue
            for cond in check.conditions:
                if (
                    cond.output_name not in produces_map
                    and cond.output_name not in SEED_CONTEXT_KEYS
                ):
                    for d_name in disabled:
                        d_check = check_map.get(d_name)
                        if d_check and cond.output_name in d_check.produces:
                            broken.append((check.name, cond.output_name, d_name))

        from app.engine.chains import CHAIN_PATTERNS

        broken_patterns = []
        for pattern in CHAIN_PATTERNS:
            for req in pattern.get("required_observations", []):
                if req.get("check_name") in disabled:
                    broken_patterns.append((pattern["name"], req["check_name"]))

        if not broken and not broken_patterns:
            return (
                f"Disabling {', '.join(check_names)} has no downstream impact. "
                "No other checks depend on their outputs and no chain patterns reference them."
            )

        lines = [f"Impact of disabling {', '.join(check_names)}:\n"]

        if broken:
            lines.append("**Broken dependencies:**")
            for check_name, key, disabled_by in broken:
                lines.append(
                    f"  - `{check_name}` needs `{key}` (produced by disabled `{disabled_by}`)"
                )
            lines.append("")

        if broken_patterns:
            lines.append("**Broken chain patterns:**")
            for pattern_name, ref_check in broken_patterns:
                lines.append(
                    f"  - Pattern `{pattern_name}` references disabled `{ref_check}` — will never trigger"
                )
            lines.append("")

        lines.append("Disable those too, or provide alternative context?")
        return "\n".join(lines)

    async def diff_upstream(self) -> str:
        """Diff community checks against the last known state.

        Retrieves the last upstream_diff result from the DB to compare
        hashes. If no prior result exists, records the current baseline.
        """
        current_hash = self._hash_community_checks()

        # Try to load last known hash from DB
        last_hash = None
        try:
            from app.db.repositories import ChainsmithRepository

            last_result = await ChainsmithRepository().get_validation()
            if last_result and last_result.get("result"):
                last_hash = last_result["result"].get("community_hash")
        except (ImportError, KeyError, AttributeError):
            pass

        if last_hash is None:
            await self.emit(
                AgentEvent(
                    event_type=EventType.CHAINSMITH_UPSTREAM_DIFF,
                    agent=ComponentType.CHAINSMITH,
                    importance=EventImportance.LOW,
                    message="First sync — community check baseline recorded.",
                )
            )
            return "First sync — community check hash recorded as baseline. Run again after pulling upstream changes."

        if current_hash == last_hash:
            return "Community checks unchanged since last sync."

        await self.emit(
            AgentEvent(
                event_type=EventType.CHAINSMITH_UPSTREAM_DIFF,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.HIGH,
                message=f"Community checks changed (hash {last_hash[:8]}→{current_hash[:8]}). Run validation to check for conflicts.",
            )
        )

        return (
            f"Community checks have changed since last sync "
            f"(hash {last_hash[:8]}→{current_hash[:8]}). "
            "Run `validate` to check for conflicts with custom checks."
        )

    # ═══════════════════════════════════════════════════════════════
    # Custom Check Scaffolding
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _custom_check_name(name: str) -> str:
        """Normalize an operator-supplied name to a ``custom_<slug>`` check name.

        Custom checks are uniformly suite-prefixed (56.7) under the ``custom``
        suite, so the slug always starts with ``custom_``. Double underscores
        are collapsed (forbidden in component names — they are the env delimiter).
        """
        slug = name.strip().lower().replace(" ", "_").replace("-", "_")
        while "__" in slug:
            slug = slug.replace("__", "_")
        slug = slug.strip("_")
        if not slug.startswith("custom_"):
            slug = f"custom_{slug}"
        return slug

    async def scaffold_check(
        self,
        name: str,
        description: str,
        suite: str,
        conditions: list[dict] | None = None,
        produces: list[str] | None = None,
        service_types: list[str] | None = None,
        intrusive: bool = False,
    ) -> dict:
        """Generate a folder-shape custom check scaffold (preview — no disk write).

        Custom checks are discovered exactly like core checks (C9): the scaffold
        is a component folder ``app/checks/custom/custom_<name>/`` carrying a
        ``contract.yaml`` (name ``custom_<name>``, suite ``custom``), ``check.py``,
        ``config.yaml`` and a re-export ``__init__.py``. There is no registry and
        no registration step — ``write_check`` drops the folder and the loader
        finds it. The ``suite`` argument records the operator's functional intent
        (persisted as metadata by the engine); the discovered suite is ``custom``.

        Returns {"path": <folder>, "files": {filename: content}, "check_name":
        str, "class_name": str, "registered": False}.
        """
        check_name = self._custom_check_name(name)
        class_name = "".join(word.capitalize() for word in check_name.split("_")) + "Check"
        folder = os.path.join(CUSTOM_DIR, check_name)

        if os.path.exists(folder):
            return {
                "path": folder,
                "files": None,
                "registered": False,
                "error": f"Custom check folder already exists: {folder}",
            }

        files = self._render_check_folder(
            check_name=check_name,
            class_name=class_name,
            description=description,
            suite=suite,
            conditions=conditions,
            produces=produces,
            service_types=service_types,
            intrusive=intrusive,
        )

        await self.emit(
            AgentEvent(
                event_type=EventType.CHAINSMITH_CUSTOM_CHECK_CREATED,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=f"Scaffolded custom check: {check_name} ({class_name})",
                details={"path": folder, "class": class_name, "suite": suite},
            )
        )

        return {
            "path": folder,
            "files": files,
            "check_name": check_name,
            "class_name": class_name,
            "registered": False,
            "message": (
                f"Scaffold generated for {class_name} ({check_name}). Review the "
                f"files, then write them with write_check — the loader "
                f"auto-discovers the folder, no registration needed."
            ),
        }

    def _render_check_folder(
        self,
        *,
        check_name: str,
        class_name: str,
        description: str,
        suite: str,
        conditions: list[dict] | None,
        produces: list[str] | None,
        service_types: list[str] | None,
        intrusive: bool,
    ) -> dict[str, str]:
        """Render the four files of a folder-shape custom check as a dict.

        Pure (no I/O) so it backs both the preview and the on-disk write. The
        ``contract.yaml`` is dumped from a dict so it always parses back into a
        ``CheckContract`` and passes ``verify_contracts``.
        """
        depends_on: list[dict] = []
        cond_lines: list[str] = []
        for c in conditions or []:
            op = c.get("operator", "truthy")
            entry: dict = {"output_name": c["output_name"], "operator": op}
            val = c.get("value")
            if val is not None:
                entry["value"] = val
                cond_lines.append(f'        CheckCondition("{c["output_name"]}", "{op}", {val!r}),')
            else:
                cond_lines.append(f'        CheckCondition("{c["output_name"]}", "{op}"),')
            depends_on.append(entry)

        contract = {
            "id": str(uuid.uuid4()),
            "name": check_name,
            "type": "check",
            "description": description,
            "entry": f"check.py:{class_name}",
            "suite": "custom",
            "depends_on": depends_on,
            "produces": list(produces or []),
            "intrusive": intrusive,
            "service_types": list(service_types or []),
            "parallel_safe": False,
            "outputs": {"observations": ["Observation"]},
            "side_effects": ["none"],
            "techniques": [],
            "references": [],
            "reason": f"Custom check scaffolded by Chainsmith (functional intent: {suite}).",
        }
        contract_yaml = yaml.safe_dump(contract, sort_keys=False, default_flow_style=False)

        produces_str = ", ".join(f'"{p}"' for p in (produces or []))
        service_types_str = ", ".join(f'"{s}"' for s in (service_types or []))
        cond_body = (
            "\n".join(cond_lines)
            if cond_lines
            else "        # No conditions — runs unconditionally"
        )

        check_py = f'''"""
Custom check: {description}

Generated by Chainsmith on {datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}.
Functional-suite intent: {suite}. Discovered under the `custom` suite.
Review and implement before use.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult


class {class_name}(BaseCheck):
    name = "{check_name}"
    description = "{description}"

    conditions = [
{cond_body}
    ]

    produces = [{produces_str}]
    service_types = [{service_types_str}]
    intrusive = {intrusive}

    async def run(self, context: dict[str, Any]) -> CheckResult:
        """Implement check logic here.

        Args:
            context: Shared context dict with outputs from prior checks.
                     Access services via context.get("services", []).

        Returns:
            CheckResult with observations and outputs.
        """
        # TODO: Implement check logic
        return CheckResult(
            success=True,
            check_name=self.name,
            observations=[],
            services=[],
            outputs={{}},
            errors=[],
        )
'''

        config_yaml = (
            "enabled: true\n"
            "on_critical: annotate\n"
            "defaults:\n"
            "  timeout_seconds: 30.0\n"
            "  requests_per_second: 10.0\n"
            "  retry_count: 1\n"
            "  delay_between_targets: 0.2\n"
        )

        init_py = (
            '"""Re-export the entry class so the loader and importers resolve the '
            'same class object (identity-preserving, §3.1)."""\n\n'
            f"from app.checks.custom.{check_name}.check import {class_name}\n\n"
            f'__all__ = ["{class_name}"]\n'
        )

        return {
            "contract.yaml": contract_yaml,
            "check.py": check_py,
            "config.yaml": config_yaml,
            "__init__.py": init_py,
        }

    async def write_check(
        self,
        name: str,
        description: str,
        suite: str,
        conditions: list[dict] | None = None,
        produces: list[str] | None = None,
        service_types: list[str] | None = None,
        intrusive: bool = False,
    ) -> dict:
        """Scaffold and write a folder-shape custom check to disk.

        No registration step: the loader auto-discovers the new folder on the
        next check load (C9 — the CUSTOM_CHECK_REGISTRY path is gone).
        """
        result = await self.scaffold_check(
            name=name,
            description=description,
            suite=suite,
            conditions=conditions,
            produces=produces,
            service_types=service_types,
            intrusive=intrusive,
        )

        if result.get("error"):
            return result

        folder = result["path"]
        os.makedirs(folder, exist_ok=True)
        for filename, content in result["files"].items():
            with open(os.path.join(folder, filename), "w", encoding="utf-8") as f:
                f.write(content)

        result["registered"] = True
        result["message"] = (
            f"Custom check {result['class_name']} written to {folder}. "
            f"It is auto-discovered on the next check load — no registration needed."
        )

        await self.emit(
            AgentEvent(
                event_type=EventType.CHAINSMITH_FIX_APPLIED,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=f"Created custom check folder: {result['class_name']} ({result['path']})",
            )
        )

        return result

    # ═══════════════════════════════════════════════════════════════
    # Chain Building
    # ═══════════════════════════════════════════════════════════════

    async def build_chains(self, observations: list[Observation]) -> list[AttackChain]:
        """Build attack chains from verified observations."""
        self.chains = []

        verified = [f for f in observations if f.status == ObservationStatus.VERIFIED]

        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_START,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=f"Analyzing {len(verified)} verified observations for attack chains...",
            )
        )

        if len(verified) < 2:
            await self.emit(
                AgentEvent(
                    event_type=EventType.AGENT_COMPLETE,
                    agent=ComponentType.CHAINSMITH,
                    importance=EventImportance.LOW,
                    message="Not enough observations for chain analysis (need 2+)",
                )
            )
            return []

        self._build_chains_from_patterns(verified)

        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_COMPLETE,
                agent=ComponentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=f"Found {len(self.chains)} attack chain(s)",
            )
        )

        return self.chains

    def _build_chains_from_patterns(self, observations: list[Observation]):
        """Build chains using pattern matching."""
        observation_keywords = {}
        for f in observations:
            text = f"{f.title} {f.description} {f.evidence_summary or ''}".lower()
            keywords = set()

            kw_list = [
                # Web / Network
                "header",
                "server",
                "version",
                "disclosure",
                "api",
                "endpoint",
                "cors",
                "error",
                "debug",
                "config",
                "admin",
                "internal",
                "openapi",
                "swagger",
                "robots",
                "path",
                "auth",
                "credential",
                "default",
                "login",
                "password",
                "ssrf",
                "url",
                "callback",
                "webhook",
                "mass",
                "assignment",
                "schema",
                # AI / LLM
                "chatbot",
                "tool",
                "prompt",
                "injection",
                "model",
                "llm",
                "chat",
                "completion",
                "filter",
                "jailbreak",
                "streaming",
                "bypass",
                "content",
                "guardrail",
                "rate",
                "limit",
                "token",
                "cost",
                "exhaustion",
                "expensive",
                "system",
                # RAG
                "rag",
                "retrieval",
                "vector",
                "embedding",
                "corpus",
                "ingestion",
                "upload",
                "document",
                "collection",
                "chroma",
                "qdrant",
                "pinecone",
                "weaviate",
                # CAG
                "cache",
                "cag",
                "leakage",
                "cross-user",
                "isolation",
                "shared",
                "poisoning",
                "warming",
                "persistence",
                "stale",
                # MCP
                "mcp",
                "shadow",
                "resource",
                "traversal",
                "template",
                "invocation",
                "enumeration",
                # Agent
                "agent",
                "goal",
                "orchestration",
                "autonomous",
                "memory",
                "extraction",
                "multi-agent",
                "cross",
                "trust",
                "chain",
                "loop",
                "context",
                "overflow",
            ]
            for kw in kw_list:
                if kw in text:
                    keywords.add(kw)

            observation_keywords[f.id] = keywords

        for pattern in self.attack_patterns:
            indicators = set(pattern.get("indicators", []))
            matching = []

            for f in observations:
                if observation_keywords.get(f.id, set()) & indicators:
                    matching.append(f)

            if len(matching) >= 2:
                chain = AttackChain(
                    id=f"CHAIN-{len(self.chains) + 1:03d}",
                    title=pattern.get("name", "Attack Chain"),
                    observation_ids=[f.id for f in matching],
                    impact_statement=pattern.get("impact", "Multiple observations increase risk."),
                    attack_steps=pattern.get("steps", []),
                    combined_severity="high" if len(matching) > 3 else "medium",
                    confidence=0.7,
                    identified_at=datetime.now(UTC),
                )
                self.chains.append(chain)

    # ═══════════════════════════════════════════════════════════════
    # Graph Validation (internal)
    # ═══════════════════════════════════════════════════════════════

    def _validate_graph(self, checks: list[BaseCheck], result: ValidationResult):
        """Validate the check dependency graph."""
        produces_map: dict[str, list[str]] = defaultdict(list)
        consumes_map: dict[str, list[str]] = defaultdict(list)
        all_produced: set[str] = set()
        all_consumed: set[str] = set()

        for check in checks:
            for key in check.produces:
                produces_map[key].append(check.name)
                all_produced.add(key)
            for cond in check.conditions:
                consumes_map[cond.output_name].append(check.name)
                all_consumed.add(cond.output_name)

        # Dead checks
        for key in all_consumed:
            if key not in all_produced and key not in SEED_CONTEXT_KEYS:
                for consumer in consumes_map[key]:
                    result.issues.append(
                        ValidationIssue(
                            category="dead_check",
                            severity="error",
                            message=(
                                f"`{consumer}` requires `{key}` but no check produces it "
                                "and it's not a seed key."
                            ),
                            check_name=consumer,
                            suggestion=f"Check if `{key}` was renamed or if the producing check is disabled.",
                        )
                    )

        # Orphaned outputs
        for key in all_produced:
            if key not in all_consumed:
                for producer in produces_map[key]:
                    result.issues.append(
                        ValidationIssue(
                            category="orphaned_output",
                            severity="info",
                            message=f"`{producer}` produces `{key}` but nothing consumes it.",
                            check_name=producer,
                        )
                    )

        # Shadow conflicts
        for key, producers in produces_map.items():
            if len(producers) > 1:
                result.issues.append(
                    ValidationIssue(
                        category="shadow_conflict",
                        severity="warning",
                        message=(
                            f"Multiple checks produce `{key}`: {', '.join(producers)}. "
                            "Later execution silently overwrites earlier values."
                        ),
                        suggestion="Ensure this is intentional, or rename one of the output keys.",
                    )
                )

        # Circular dependencies
        cycles = self._detect_cycles(checks)
        for cycle in cycles:
            result.issues.append(
                ValidationIssue(
                    category="circular_dependency",
                    severity="error",
                    message=f"Circular dependency detected: {' -> '.join(cycle)}",
                    suggestion="Break the cycle by removing or loosening a condition.",
                )
            )

    def _detect_cycles(self, checks: list[BaseCheck]) -> list[list[str]]:
        """Detect circular dependencies using DFS coloring."""
        produces_to_check: dict[str, list[str]] = defaultdict(list)
        for check in checks:
            for key in check.produces:
                produces_to_check[key].append(check.name)

        deps: dict[str, set[str]] = defaultdict(set)
        for check in checks:
            for cond in check.conditions:
                for producer in produces_to_check.get(cond.output_name, []):
                    if producer != check.name:
                        deps[check.name].add(producer)

        WHITE, GRAY, BLACK = 0, 1, 2
        color = {c.name: WHITE for c in checks}
        cycles = []
        path = []

        def dfs(node: str):
            color[node] = GRAY
            path.append(node)
            for dep in deps.get(node, set()):
                if color.get(dep) == GRAY:
                    idx = path.index(dep)
                    cycles.append(path[idx:] + [dep])
                elif color.get(dep) == WHITE:
                    dfs(dep)
            path.pop()
            color[node] = BLACK

        for check in checks:
            if color[check.name] == WHITE:
                dfs(check.name)

        return cycles

    # ═══════════════════════════════════════════════════════════════
    # Chain Pattern Validation (internal)
    # ═══════════════════════════════════════════════════════════════

    def _validate_chain_patterns(self, checks: list[BaseCheck], result: ValidationResult):
        """Cross-reference chain patterns against the active check registry."""
        from app.engine.chains import CHAIN_PATTERNS

        check_names = {c.name for c in checks}
        result.patterns_analyzed = len(CHAIN_PATTERNS)

        for pattern in CHAIN_PATTERNS:
            pattern_name = pattern.get("name", "unnamed")
            for req in pattern.get("required_observations", []):
                ref_check = req.get("check_name")
                if ref_check and ref_check not in check_names:
                    result.issues.append(
                        ValidationIssue(
                            category="broken_pattern",
                            severity="error",
                            message=(
                                f"Chain pattern `{pattern_name}` references check "
                                f"`{ref_check}` which doesn't exist or is disabled."
                            ),
                            suggestion=(
                                f"Add the `{ref_check}` check, rename the pattern reference, "
                                "or remove the pattern."
                            ),
                        )
                    )

    # ═══════════════════════════════════════════════════════════════
    # Custom Check Health (internal)
    # ═══════════════════════════════════════════════════════════════

    def _validate_custom_check_health(self, result: ValidationResult):
        """Validate custom checks via the canonical contract validator (C9).

        The legacy ``CUSTOM_CHECK_REGISTRY`` is gone; custom checks are folder-shape
        components under ``app/checks/custom/``, discovered like any core check.
        Run the same ``verify_contracts`` gate the loader / CI / ``dev
        verify-contracts`` apply, and fold any violations into the result so
        ``validate`` still surfaces broken custom checks — now from the single
        source of truth instead of a parallel hand-rolled check.
        """
        from app.component_loader import verify_contracts

        for violation in verify_contracts(Path(CUSTOM_DIR), "check"):
            result.issues.append(
                ValidationIssue(
                    category="invalid_custom_check",
                    severity="error",
                    message=f"{violation.code}: {violation.message}",
                    check_name=violation.path.name,
                    suggestion="Run `chainsmith dev verify-contracts` for the full report.",
                )
            )

    # ═══════════════════════════════════════════════════════════════
    # Content-Aware Helpers (internal)
    # ═══════════════════════════════════════════════════════════════

    def _extract_check_summary(self, check: BaseCheck) -> dict | None:
        """Extract a summary of a check's implementation for LLM analysis."""
        try:
            source_file = inspect.getfile(check.__class__)
            with open(source_file) as f:
                source = f.read()

            return {
                "name": check.name,
                "description": check.description,
                "conditions": [str(c) for c in check.conditions],
                "produces": check.produces,
                "service_types": check.service_types,
                "intrusive": check.intrusive,
                "source_preview": source[:2000],
            }
        except (TypeError, OSError):
            return None

    def _build_content_analysis_prompt(self, summaries: list[dict]) -> str:
        """Build the LLM prompt for content-aware analysis."""
        check_descriptions = []
        for s in summaries[:50]:
            desc = (
                f"**{s['name']}**: {s['description']}\n"
                f"  Conditions: {', '.join(s['conditions']) or 'none'}\n"
                f"  Produces: {', '.join(s['produces']) or 'nothing'}\n"
                f"  Service types: {', '.join(s['service_types']) or 'all'}\n"
                f"  Intrusive: {s['intrusive']}\n"
                f"  Source preview:\n```python\n{s['source_preview'][:500]}\n```\n"
            )
            check_descriptions.append(desc)

        return (
            "Analyze the following security checks for:\n"
            "1. **Semantic overlap** (confidence >= 0.7): two checks probing the same "
            "endpoints or inspecting the same data for the same purpose\n"
            "2. **Coverage gaps**: known attack surfaces with no corresponding check\n"
            "3. **Condition adequacy**: declared conditions vs. actual runtime filtering\n\n"
            "Checks:\n\n" + "\n---\n".join(check_descriptions) + "\n\n"
            "Report findings with specific check names. Be concise."
        )

    # ═══════════════════════════════════════════════════════════════
    # Community Check Hashing
    # ═══════════════════════════════════════════════════════════════

    def _hash_community_checks(self) -> str:
        """Compute a hash of all community check files for diff detection."""
        hasher = hashlib.sha256()
        checks_dir = os.path.join(os.path.dirname(__file__), "..", "checks")
        for suite_dir in sorted(COMMUNITY_DIRS):
            suite_path = os.path.join(checks_dir, suite_dir)
            if not os.path.isdir(suite_path):
                continue
            for fname in sorted(os.listdir(suite_path)):
                if fname.endswith(".py"):
                    fpath = os.path.join(suite_path, fname)
                    try:
                        with open(fpath, "rb") as f:
                            hasher.update(f.read())
                    except OSError:
                        continue
        return hasher.hexdigest()

    # ═══════════════════════════════════════════════════════════════
    # Chat Interface
    # ═══════════════════════════════════════════════════════════════

    async def handle_message(self, text: str) -> str:
        """Handle a conversational message from the operator.

        Parses intent and dispatches to the appropriate capability.
        """
        text_lower = text.lower().strip()

        # Validate / health check
        if any(kw in text_lower for kw in ["validate", "health", "check graph", "audit"]):
            result = await self.validate()
            return result.summary()

        # Disable impact
        if "disable" in text_lower:
            from app.check_resolver import get_real_checks

            all_checks = get_real_checks()
            check_names = {c.name for c in all_checks}
            mentioned = [name for name in check_names if name in text_lower]
            if mentioned:
                return await self.suggest_disable_impact(mentioned, all_checks)
            suites = ["mcp", "agent", "rag", "cag", "ai", "web", "network"]
            mentioned_suites = [s for s in suites if s in text_lower]
            if mentioned_suites:
                from app.check_resolver import infer_suite

                suite_checks = [
                    c.name for c in all_checks if infer_suite(c.name) in mentioned_suites
                ]
                if suite_checks:
                    return await self.suggest_disable_impact(suite_checks, all_checks)
            return "Which checks would you like to disable? Name specific checks or suites."

        # Upstream diff
        if any(kw in text_lower for kw in ["upstream", "diff", "sync", "update", "changed"]):
            return await self.diff_upstream()

        # Content analysis
        if any(kw in text_lower for kw in ["content", "semantic", "overlap", "coverage", "gap"]):
            return await self.analyze_content()

        # Add / scaffold check
        if any(kw in text_lower for kw in ["add check", "new check", "create check", "scaffold"]):
            return (
                "I can scaffold a new custom check. Tell me:\n"
                "- **Name**: What should the check be called?\n"
                "- **Description**: What does it look for?\n"
                "- **Suite**: Which suite does it belong to? (network, web, ai, mcp, agent, rag, cag)\n"
                "- **Conditions**: What context keys does it need? (e.g., `services` truthy)\n"
                "- **Produces**: What output keys will it add to context?\n\n"
                "Or describe what you want in plain language and I'll ask clarifying questions."
            )

        # Default
        return (
            "I'm Chainsmith — your check ecosystem manager. I can help with:\n\n"
            '- **"Validate"** — Check dependency graph and chain patterns for issues\n'
            '- **"Disable [checks/suite]"** — Show what breaks if you disable checks\n'
            '- **"Upstream diff"** — Check if community checks changed since last sync\n'
            '- **"Content analysis"** — LLM-powered semantic overlap and coverage gaps\n'
            '- **"Add check"** — Scaffold a new custom check\n\n'
            "What would you like to do?"
        )
