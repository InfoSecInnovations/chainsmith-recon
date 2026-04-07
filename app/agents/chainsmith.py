"""
Chainsmith Agent

Handles scoping conversations and builds attack chains from verified observations.
Conversational flow that prompts for missing scope information.
"""

import json
import re
from collections.abc import Awaitable, Callable
from datetime import datetime

from app.config import ATTACK_PATTERNS_PATH
from app.lib.llm import get_llm_client
from app.models import (
    AgentEvent,
    AgentType,
    AttackChain,
    EventImportance,
    EventType,
    Observation,
    ObservationStatus,
    ScopeDefinition,
)


class ChainsmithAgent:
    """Chainsmith agent for scoping and chain building."""

    def __init__(self, event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None):
        self.event_callback = event_callback
        self.scope: ScopeDefinition | None = None
        self.chains: list[AttackChain] = []
        self.attack_patterns = self._load_patterns()

        # Scope data collected
        self.target: str | None = None
        self.exclusions: list[str] = []
        self.timeframe: str | None = None

        # Track what's been set
        self.scope_status = {
            "targets": False,
            "exclusions": False,
            "timeframe": False,
            "techniques": True,  # Always true - we use safe defaults
        }

        self.client = get_llm_client()

    def _load_patterns(self) -> list[dict]:
        """Load attack patterns from knowledge base."""
        try:
            with open(ATTACK_PATTERNS_PATH) as f:
                data = json.load(f)
                return data.get("patterns", [])
        except Exception:
            return []

    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)

    def get_scope_status(self) -> dict:
        """Get current scope status for LED indicators."""
        return self.scope_status.copy()

    # ─── Scoping Methods ───────────────────────────────────────

    async def start_scoping(self) -> dict:
        """Start the scoping conversation."""
        self.target = None
        self.exclusions = []
        self.timeframe = None
        self.scope_status = {
            "targets": False,
            "exclusions": False,
            "timeframe": False,
            "techniques": True,
        }

        response = """Welcome! Let's define your assessment scope.

I need the following information:
• **Target** (required) - Domain to test, e.g., *.fakobanko.local
• **Exclusions** - Domains to skip, e.g., vpn.fakobanko.local
• **Timeframe** - Testing window, e.g., "business hours" or "no restrictions"

What is your target domain?"""

        return {
            "response": response,
            "scope_complete": False,
            "scope": None,
            "scope_status": self.scope_status,
        }

    async def continue_scoping(self, user_message: str) -> dict:
        """Process user message and continue scoping conversation."""
        msg = user_message.strip()
        msg_lower = msg.lower()

        # Parse the message for scope info
        self._extract_scope_info(msg)

        # Check if user wants to proceed
        wants_to_go = any(
            word in msg_lower for word in ["go", "launch", "start", "proceed", "done", "ready"]
        )

        # Check if user wants defaults
        any(phrase in msg_lower for phrase in ["default", "use default", "skip", "none"])

        # If user wants to go or use defaults, check what we have
        if wants_to_go:
            if not self.target:
                return self._respond(
                    "I still need a target domain before we can proceed. What domain should I test?"
                )

            # Apply defaults for missing optional fields
            if not self.scope_status["exclusions"]:
                self.exclusions = []
                self.scope_status["exclusions"] = True

            if not self.scope_status["timeframe"]:
                self.timeframe = "No restrictions"
                self.scope_status["timeframe"] = True

            return self._finalize_scope()

        # If user explicitly says "none" or "no exclusions" for exclusions
        if not self.scope_status["exclusions"] and self.scope_status["targets"]:
            if any(phrase in msg_lower for phrase in ["no exclu", "none", "no domains", "nothing"]):
                self.exclusions = []
                self.scope_status["exclusions"] = True

        # Build response based on what's missing
        return self._build_response()

    def _extract_scope_info(self, msg: str):
        """Extract scope information from message."""
        msg.lower()

        # Domain regex
        domain_pattern = r"(\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*"

        # Process line by line
        for line in msg.split("\n"):
            line = line.strip()
            if not line:
                continue

            line_lower = line.lower()

            # Find domains in this line
            re.findall(domain_pattern, line, re.IGNORECASE)
            # Get full matches
            full_domains = re.findall(
                r"(\*\.[a-zA-Z0-9][-a-zA-Z0-9.]*|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*)",
                line,
            )

            # Determine context
            is_exclusion = any(
                w in line_lower
                for w in [
                    "exclude",
                    "skip",
                    "avoid",
                    "except",
                    "out of scope",
                    "don't test",
                    "not ",
                ]
            )
            is_target = any(w in line_lower for w in ["target", "scope", "test", "scan"]) or (
                not is_exclusion and not self.target
            )

            for domain in full_domains:
                domain = domain.strip(".,;:")
                if len(domain) < 4:
                    continue

                if is_exclusion:
                    if domain not in self.exclusions:
                        self.exclusions.append(domain)
                    self.scope_status["exclusions"] = True
                elif is_target or not self.target:
                    self.target = domain
                    self.scope_status["targets"] = True

            # Check for timeframe
            time_indicators = [
                "hour",
                "time",
                "until",
                "before",
                "after",
                "restrict",
                "window",
                "anytime",
                "no restrict",
                "24/7",
            ]
            if any(ind in line_lower for ind in time_indicators):
                self.timeframe = line
                self.scope_status["timeframe"] = True

    def _build_response(self) -> dict:
        """Build response prompting for missing info."""
        parts = []

        # Acknowledge what we got
        if self.scope_status["targets"] and self.target:
            parts.append(f"✓ Target: {self.target}")

        if self.scope_status["exclusions"]:
            if self.exclusions:
                parts.append(f"✓ Exclusions: {', '.join(self.exclusions)}")
            else:
                parts.append("✓ Exclusions: None")

        if self.scope_status["timeframe"] and self.timeframe:
            parts.append(f"✓ Timeframe: {self.timeframe}")

        # Build acknowledgment
        if parts:
            ack = "Got it!\n" + "\n".join(parts) + "\n\n"
        else:
            ack = ""

        # Ask for what's missing
        if not self.scope_status["targets"]:
            prompt = "What is your target domain? (e.g., *.fakobanko.local)"
        elif not self.scope_status["exclusions"]:
            prompt = "Any domains to exclude? (e.g., 'exclude vpn.fakobanko.local' or 'none')"
        elif not self.scope_status["timeframe"]:
            prompt = (
                "Any timeframe restrictions? (e.g., 'business hours only' or 'no restrictions')"
            )
        else:
            prompt = "All set! Say 'go' to launch the assessment."

        return {
            "response": ack + prompt,
            "scope_complete": False,
            "scope": None,
            "scope_status": self.scope_status,
        }

    def _respond(self, message: str) -> dict:
        """Create a response dict."""
        return {
            "response": message,
            "scope_complete": False,
            "scope": None,
            "scope_status": self.scope_status,
        }

    def _finalize_scope(self) -> dict:
        """Finalize and return the scope."""
        self.scope = ScopeDefinition(
            in_scope_domains=[self.target] if self.target else [],
            out_of_scope_domains=self.exclusions,
            in_scope_ports=[80, 443, 8080, 8081, 8082, 8083],
            allowed_techniques=[
                "port_scan",
                "header_grab",
                "robots_fetch",
                "directory_enum",
                "chatbot_probe",
                "error_trigger",
            ],
            forbidden_techniques=[
                "dos",
                "data_exfiltration",
                "credential_stuffing",
                "sql_injection",
                "brute_force",
            ],
            notes=self.timeframe,
            defined_at=datetime.utcnow(),
        )

        # All LEDs on
        self.scope_status = {
            "targets": True,
            "exclusions": True,
            "timeframe": True,
            "techniques": True,
        }

        summary = f"""Scope confirmed!

**Target:** {self.target}
**Exclusions:** {", ".join(self.exclusions) if self.exclusions else "None"}
**Timeframe:** {self.timeframe or "No restrictions"}
**Techniques:** Safe reconnaissance only (no DoS, no data exfiltration)

Ready to launch. Click the Launch button to begin."""

        return {
            "response": summary,
            "scope_complete": True,
            "scope": self.scope,
            "scope_status": self.scope_status,
        }

    # ─── Chain Building Methods ────────────────────────────────

    async def build_chains(self, observations: list[Observation]) -> list[AttackChain]:
        """Build attack chains from verified observations."""
        self.chains = []

        verified = [f for f in observations if f.status == ObservationStatus.VERIFIED]

        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_START,
                agent=AgentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=f"Analyzing {len(verified)} verified observations for attack chains...",
            )
        )

        if len(verified) < 2:
            await self.emit(
                AgentEvent(
                    event_type=EventType.AGENT_COMPLETE,
                    agent=AgentType.CHAINSMITH,
                    importance=EventImportance.LOW,
                    message="Not enough observations for chain analysis (need 2+)",
                )
            )
            return []

        # Pattern-based chain building
        self._build_chains_from_patterns(verified)

        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_COMPLETE,
                agent=AgentType.CHAINSMITH,
                importance=EventImportance.MEDIUM,
                message=f"Found {len(self.chains)} attack chain(s)",
            )
        )

        return self.chains

    def _build_chains_from_patterns(self, observations: list[Observation]):
        """Build chains using pattern matching."""
        # Extract keywords from each observation
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

        # Match against patterns
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
                    identified_at=datetime.utcnow(),
                )
                self.chains.append(chain)
