"""
Verifier Agent

Validates Scout's observations, catches hallucinations, assigns confidence scores.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime

from openai import AsyncOpenAI

from app.config import LITELLM_BASE_URL, LITELLM_MODEL_VERIFIER
from app.models import (
    AgentEvent,
    ComponentType,
    EventImportance,
    EventType,
    EvidenceQuality,
    Observation,
    ObservationStatus,
)
from app.tools import verify_cve, verify_endpoint_exists, verify_version_claim

VERIFIER_SYSTEM_PROMPT = """You are Verifier, an AI agent that validates reconnaissance observations.

Your job is to fact-check observations and catch errors, hallucinations, or overstated claims.

VALIDATION RULES:
1. For CVE claims: Use verify_cve to check if the CVE exists
2. For version claims: Use verify_version with the raw evidence
3. For endpoint claims: Use verify_endpoint with the ACTUAL base URL and path
4. For port/header observations: These are usually factual - verify based on evidence quality

VERIFICATION APPROACH:
- If evidence clearly supports the claim → VERIFIED
- If CVE doesn't exist in database → HALLUCINATION
- If version doesn't match evidence → REJECTED
- If endpoint doesn't exist → REJECTED
- If claim is reasonable but unverifiable → VERIFIED with lower confidence

EVIDENCE QUALITY:
When submitting a verdict, classify the evidence quality:
- "direct_observation": Your own tool confirmed the claim (endpoint returned 200, CVE exists in NVD)
- "inferred": Evidence is consistent but not conclusive (version string in header matches known-vulnerable range, but no direct probe)
- "claimed_no_proof": The observation was reported with no verifiable evidence attached

SUBMIT VERDICTS:
For each observation, call submit_verdict with:
- observation_id: The ID (e.g., "F-001")
- status: "verified", "rejected", or "hallucination"
- confidence: 0.0 to 1.0
- evidence_quality: "direct_observation", "inferred", or "claimed_no_proof"
- reasoning: Rich explanation including specifics from your verification.
  Good: "CVE-2021-41773 exists in NVD. Published 2021-10-05, CVSS 7.5. Affects Apache 2.4.49-2.4.50. Claimed version (2.4.49) falls within the affected range."
  Bad: "CVE confirmed in NVD"

Be practical. Port scan results showing open ports are factual data. Header disclosures are factual if the evidence shows the header. Focus hallucination detection on CVEs and overstated claims."""

VERIFIER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "verify_cve",
            "description": "Check if a CVE exists in the database",
            "parameters": {
                "type": "object",
                "properties": {"cve_id": {"type": "string", "description": "CVE ID to verify"}},
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_version",
            "description": "Verify a version claim against evidence",
            "parameters": {
                "type": "object",
                "properties": {
                    "software": {"type": "string"},
                    "claimed_version": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["software", "claimed_version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_endpoint",
            "description": "Check if an endpoint exists",
            "parameters": {
                "type": "object",
                "properties": {"base_url": {"type": "string"}, "endpoint": {"type": "string"}},
                "required": ["base_url", "endpoint"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_verdict",
            "description": "Submit verification verdict for an observation",
            "parameters": {
                "type": "object",
                "properties": {
                    "observation_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["verified", "rejected", "hallucination"]},
                    "confidence": {"type": "number"},
                    "evidence_quality": {
                        "type": "string",
                        "enum": ["direct_observation", "inferred", "claimed_no_proof"],
                        "description": "Quality of evidence supporting the verdict",
                    },
                    "reasoning": {"type": "string"},
                },
                "required": [
                    "observation_id",
                    "status",
                    "confidence",
                    "evidence_quality",
                    "reasoning",
                ],
            },
        },
    },
]


class VerifierAgent:
    """Verifier agent for validating observations."""

    def __init__(self, event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None):
        self.event_callback = event_callback
        self.verdicts: dict[str, dict] = {}
        self.is_running = False

        # Progress tracking
        self.observations_processed = 0
        self.total_observations = 0

        self.client = AsyncOpenAI(base_url=LITELLM_BASE_URL, api_key="not-needed")

    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)

    async def verify_observations(self, observations: list[Observation]) -> list[Observation]:
        """Verify a list of observations."""
        self.is_running = True
        self.observations_processed = 0

        pending = [f for f in observations if f.status == ObservationStatus.PENDING]
        self.total_observations = len(pending)

        await self.emit(
            AgentEvent(
                event_type=EventType.AGENT_START,
                agent=ComponentType.VERIFIER,
                importance=EventImportance.MEDIUM,
                message=f"Verifier starting validation of {self.total_observations} observations...",
                details={"total_observations": self.total_observations, "phase": "verification"},
            )
        )

        if not pending:
            await self.emit(
                AgentEvent(
                    event_type=EventType.AGENT_COMPLETE,
                    agent=ComponentType.VERIFIER,
                    importance=EventImportance.LOW,
                    message="No observations to verify",
                )
            )
            return observations

        # Build prompt with observations
        observations_text = "\n".join(
            [
                f"- [{f.id}] {f.title}\n  Severity: {f.severity.value}\n  Evidence: {f.evidence_summary or 'None provided'}"
                for f in pending
            ]
        )

        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Verify these {len(pending)} observations. Call submit_verdict for EACH one:\n\n{observations_text}",
            },
        ]

        iteration = 0
        max_iterations = 20

        try:
            while self.is_running and iteration < max_iterations:
                iteration += 1

                # Progress update
                await self.emit(
                    AgentEvent(
                        event_type=EventType.INFO,
                        agent=ComponentType.VERIFIER,
                        importance=EventImportance.LOW,
                        message=f"Verifier iteration {iteration}, {self.observations_processed}/{self.total_observations} processed",
                        details={
                            "iteration": iteration,
                            "processed": self.observations_processed,
                            "total": self.total_observations,
                        },
                    )
                )

                response = await self.client.chat.completions.create(
                    model=LITELLM_MODEL_VERIFIER,
                    messages=messages,
                    tools=VERIFIER_TOOLS,
                    tool_choice="auto",
                    max_tokens=2048,
                )

                msg = response.choices[0].message

                if msg.tool_calls:
                    messages.append(msg)

                    for tc in msg.tool_calls:
                        result = await self._execute_tool(tc, observations)
                        messages.append(
                            {"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)}
                        )
                else:
                    # Check if we've processed all observations
                    if self.observations_processed >= self.total_observations:
                        break
                    # If not done, prompt to continue
                    if msg.content:
                        await self.emit(
                            AgentEvent(
                                event_type=EventType.INFO,
                                agent=ComponentType.VERIFIER,
                                importance=EventImportance.LOW,
                                message=f"Verifier note: {msg.content[:100]}...",
                            )
                        )
                    break

                await asyncio.sleep(0.1)

            # Apply verdicts to observations
            verified_count = 0
            rejected_count = 0
            hallucination_count = 0

            for f in observations:
                if f.id in self.verdicts:
                    v = self.verdicts[f.id]
                    f.status = ObservationStatus(v["status"])
                    f.confidence = v["confidence"]
                    f.verification_notes = v["reasoning"]
                    f.evidence_quality = EvidenceQuality(v["evidence_quality"])
                    f.verified_by = ComponentType.VERIFIER
                    f.verified_at = datetime.utcnow()

                    if f.status == ObservationStatus.VERIFIED:
                        verified_count += 1
                    elif f.status == ObservationStatus.REJECTED:
                        rejected_count += 1
                    elif f.status == ObservationStatus.HALLUCINATION:
                        hallucination_count += 1

            await self.emit(
                AgentEvent(
                    event_type=EventType.AGENT_COMPLETE,
                    agent=ComponentType.VERIFIER,
                    importance=EventImportance.MEDIUM,
                    message=f"Verification complete: {verified_count} verified, {rejected_count} rejected, {hallucination_count} hallucinations caught",
                    details={
                        "verified": verified_count,
                        "rejected": rejected_count,
                        "hallucinations": hallucination_count,
                        "total_processed": self.observations_processed,
                    },
                )
            )

        except Exception as e:
            await self.emit(
                AgentEvent(
                    event_type=EventType.ERROR,
                    agent=ComponentType.VERIFIER,
                    importance=EventImportance.HIGH,
                    message=f"Verifier error: {str(e)}",
                )
            )

        self.is_running = False
        return observations

    async def _execute_tool(self, tool_call, observations: list[Observation]) -> dict:
        """Execute a verification tool."""
        name = tool_call.function.name
        args = json.loads(tool_call.function.arguments)

        await self.emit(
            AgentEvent(
                event_type=EventType.TOOL_CALL,
                agent=ComponentType.VERIFIER,
                importance=EventImportance.LOW,
                message=f"Verifier executing: {name}",
                details={"tool": name},
            )
        )

        try:
            if name == "verify_cve":
                cve_id = args["cve_id"]
                result = await verify_cve(cve_id)

                await self.emit(
                    AgentEvent(
                        event_type=EventType.TOOL_RESULT,
                        agent=ComponentType.VERIFIER,
                        importance=EventImportance.LOW,
                        message=f"CVE check: {cve_id} - {'exists' if result.get('exists') else 'NOT FOUND'}",
                        details=result,
                    )
                )

                if result.get("is_hallucination"):
                    await self.emit(
                        AgentEvent(
                            event_type=EventType.HALLUCINATION_CAUGHT,
                            agent=ComponentType.VERIFIER,
                            importance=EventImportance.HIGH,
                            message=f"HALLUCINATION: {cve_id} does not exist in NVD",
                            details=result,
                        )
                    )

                return result

            elif name == "verify_version":
                result = await verify_version_claim(
                    args["software"], args["claimed_version"], args.get("evidence")
                )

                await self.emit(
                    AgentEvent(
                        event_type=EventType.TOOL_RESULT,
                        agent=ComponentType.VERIFIER,
                        importance=EventImportance.LOW,
                        message=f"Version check: {args['software']} {args['claimed_version']} - {'confirmed' if result.get('confirmed') else 'unconfirmed'}",
                        details=result,
                    )
                )

                return result

            elif name == "verify_endpoint":
                result = await verify_endpoint_exists(args["base_url"], args["endpoint"])

                status = result.get("status_code", "unknown")
                await self.emit(
                    AgentEvent(
                        event_type=EventType.TOOL_RESULT,
                        agent=ComponentType.VERIFIER,
                        importance=EventImportance.LOW,
                        message=f"Endpoint check: {args['endpoint']} - status {status}",
                        details=result,
                    )
                )

                return result

            elif name == "submit_verdict":
                observation_id = args["observation_id"]
                status = args["status"]
                confidence = args["confidence"]
                evidence_quality = args.get("evidence_quality", "claimed_no_proof")
                reasoning = args["reasoning"]

                self.verdicts[observation_id] = {
                    "status": status,
                    "confidence": confidence,
                    "evidence_quality": evidence_quality,
                    "reasoning": reasoning,
                }
                self.observations_processed += 1

                # Find the observation for context
                observation = next((f for f in observations if f.id == observation_id), None)
                observation_title = observation.title if observation else observation_id

                # Emit appropriate event based on verdict
                if status == "hallucination":
                    await self.emit(
                        AgentEvent(
                            event_type=EventType.HALLUCINATION_CAUGHT,
                            agent=ComponentType.VERIFIER,
                            importance=EventImportance.HIGH,
                            message=f"HALLUCINATION CAUGHT [{observation_id}]: {reasoning[:80]}",
                            observation_id=observation_id,
                            details={
                                "confidence": confidence,
                                "observation_title": observation_title,
                            },
                        )
                    )
                elif status == "verified":
                    await self.emit(
                        AgentEvent(
                            event_type=EventType.OBSERVATION_VERIFIED,
                            agent=ComponentType.VERIFIER,
                            importance=EventImportance.MEDIUM,
                            message=f"VERIFIED [{observation_id}]: {observation_title}",
                            observation_id=observation_id,
                            details={"confidence": confidence, "reasoning": reasoning[:100]},
                        )
                    )
                else:  # rejected
                    await self.emit(
                        AgentEvent(
                            event_type=EventType.OBSERVATION_REJECTED,
                            agent=ComponentType.VERIFIER,
                            importance=EventImportance.LOW,
                            message=f"REJECTED [{observation_id}]: {reasoning[:80]}",
                            observation_id=observation_id,
                            details={"confidence": confidence},
                        )
                    )

                return {
                    "status": "recorded",
                    "observation_id": observation_id,
                    "progress": f"{self.observations_processed}/{self.total_observations}",
                }

            return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            await self.emit(
                AgentEvent(
                    event_type=EventType.ERROR,
                    agent=ComponentType.VERIFIER,
                    importance=EventImportance.LOW,
                    message=f"Tool {name} failed: {str(e)[:50]}",
                )
            )
            return {"error": str(e)}

    def stop(self):
        """Stop the agent."""
        self.is_running = False
