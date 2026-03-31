"""
Verifier Agent

Validates Scout's findings, catches hallucinations, assigns confidence scores.
"""

import json
import asyncio
from datetime import datetime
from typing import Optional, Callable, Awaitable
from openai import AsyncOpenAI

from app.config import LITELLM_BASE_URL, LITELLM_MODEL_VERIFIER
from app.models import (
    Finding, FindingStatus, AgentType,
    AgentEvent, EventType, EventImportance
)
from app.tools import verify_cve, verify_version_claim, verify_endpoint_exists


VERIFIER_SYSTEM_PROMPT = """You are Verifier, an AI agent that validates reconnaissance findings.

Your job is to fact-check Scout's findings and catch errors, hallucinations, or overstated claims.

VALIDATION RULES:
1. For CVE claims: Use verify_cve to check if the CVE exists
2. For version claims: Use verify_version with the raw evidence 
3. For endpoint claims: Use verify_endpoint with the ACTUAL base URL and path
4. For port/header findings: These are usually factual - verify based on evidence quality

IMPORTANT BASE URLS FOR THIS ENGAGEMENT:
- Web service: http://sec536-lab-fakobanko-web:8082
- Chat service: http://sec536-lab-fakobanko-chat:8081  
- API service: http://sec536-lab-fakobanko-api:8080

VERIFICATION APPROACH:
- If evidence clearly supports the claim → VERIFIED
- If CVE doesn't exist in database → HALLUCINATION
- If version doesn't match evidence → REJECTED
- If endpoint doesn't exist → REJECTED
- If claim is reasonable but unverifiable → VERIFIED with lower confidence

SUBMIT VERDICTS:
For each finding, call submit_verdict with:
- finding_id: The ID (e.g., "F-001")
- status: "verified", "rejected", or "hallucination"  
- confidence: 0.0 to 1.0
- reasoning: Brief explanation

Be practical. Port scan results showing open ports are factual observations. Header disclosures are factual if the evidence shows the header. Focus hallucination detection on CVEs and overstated claims."""

VERIFIER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "verify_cve",
            "description": "Check if a CVE exists in the database",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE ID to verify"}
                },
                "required": ["cve_id"]
            }
        }
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
                    "evidence": {"type": "string"}
                },
                "required": ["software", "claimed_version"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_endpoint",
            "description": "Check if an endpoint exists",
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "endpoint": {"type": "string"}
                },
                "required": ["base_url", "endpoint"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_verdict",
            "description": "Submit verification verdict for a finding",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["verified", "rejected", "hallucination"]},
                    "confidence": {"type": "number"},
                    "reasoning": {"type": "string"}
                },
                "required": ["finding_id", "status", "confidence", "reasoning"]
            }
        }
    }
]


class VerifierAgent:
    """Verifier agent for validating findings."""
    
    def __init__(
        self,
        event_callback: Optional[Callable[[AgentEvent], Awaitable[None]]] = None
    ):
        self.event_callback = event_callback
        self.verdicts: dict[str, dict] = {}
        self.is_running = False
        
        # Progress tracking
        self.findings_processed = 0
        self.total_findings = 0
        
        self.client = AsyncOpenAI(
            base_url=LITELLM_BASE_URL,
            api_key="not-needed"
        )
    
    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)
    
    async def verify_findings(self, findings: list[Finding]) -> list[Finding]:
        """Verify a list of findings."""
        self.is_running = True
        self.findings_processed = 0
        
        pending = [f for f in findings if f.status == FindingStatus.PENDING]
        self.total_findings = len(pending)
        
        await self.emit(AgentEvent(
            event_type=EventType.AGENT_START,
            agent=AgentType.VERIFIER,
            importance=EventImportance.MEDIUM,
            message=f"Verifier starting validation of {self.total_findings} findings...",
            details={"total_findings": self.total_findings, "phase": "verification"}
        ))
        
        if not pending:
            await self.emit(AgentEvent(
                event_type=EventType.AGENT_COMPLETE,
                agent=AgentType.VERIFIER,
                importance=EventImportance.LOW,
                message="No findings to verify"
            ))
            return findings
        
        # Build prompt with findings
        findings_text = "\n".join([
            f"- [{f.id}] {f.title}\n  Severity: {f.severity.value}\n  Evidence: {f.evidence_summary or 'None provided'}"
            for f in pending
        ])
        
        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
            {"role": "user", "content": f"Verify these {len(pending)} findings. Call submit_verdict for EACH one:\n\n{findings_text}"}
        ]
        
        iteration = 0
        max_iterations = 20
        
        try:
            while self.is_running and iteration < max_iterations:
                iteration += 1
                
                # Progress update
                await self.emit(AgentEvent(
                    event_type=EventType.INFO,
                    agent=AgentType.VERIFIER,
                    importance=EventImportance.LOW,
                    message=f"Verifier iteration {iteration}, {self.findings_processed}/{self.total_findings} processed",
                    details={
                        "iteration": iteration,
                        "processed": self.findings_processed,
                        "total": self.total_findings
                    }
                ))
                
                response = await self.client.chat.completions.create(
                    model=LITELLM_MODEL_VERIFIER,
                    messages=messages,
                    tools=VERIFIER_TOOLS,
                    tool_choice="auto",
                    max_tokens=2048
                )
                
                msg = response.choices[0].message
                
                if msg.tool_calls:
                    messages.append(msg)
                    
                    for tc in msg.tool_calls:
                        result = await self._execute_tool(tc, findings)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": json.dumps(result)
                        })
                else:
                    # Check if we've processed all findings
                    if self.findings_processed >= self.total_findings:
                        break
                    # If not done, prompt to continue
                    if msg.content:
                        await self.emit(AgentEvent(
                            event_type=EventType.INFO,
                            agent=AgentType.VERIFIER,
                            importance=EventImportance.LOW,
                            message=f"Verifier note: {msg.content[:100]}..."
                        ))
                    break
                
                await asyncio.sleep(0.1)
            
            # Apply verdicts to findings
            verified_count = 0
            rejected_count = 0
            hallucination_count = 0
            
            for f in findings:
                if f.id in self.verdicts:
                    v = self.verdicts[f.id]
                    f.status = FindingStatus(v["status"])
                    f.confidence = v["confidence"]
                    f.verification_notes = v["reasoning"]
                    f.verified_by = AgentType.VERIFIER
                    f.verified_at = datetime.utcnow()
                    
                    if f.status == FindingStatus.VERIFIED:
                        verified_count += 1
                    elif f.status == FindingStatus.REJECTED:
                        rejected_count += 1
                    elif f.status == FindingStatus.HALLUCINATION:
                        hallucination_count += 1
            
            await self.emit(AgentEvent(
                event_type=EventType.AGENT_COMPLETE,
                agent=AgentType.VERIFIER,
                importance=EventImportance.MEDIUM,
                message=f"Verification complete: {verified_count} verified, {rejected_count} rejected, {hallucination_count} hallucinations caught",
                details={
                    "verified": verified_count,
                    "rejected": rejected_count,
                    "hallucinations": hallucination_count,
                    "total_processed": self.findings_processed
                }
            ))
            
        except Exception as e:
            await self.emit(AgentEvent(
                event_type=EventType.ERROR,
                agent=AgentType.VERIFIER,
                importance=EventImportance.HIGH,
                message=f"Verifier error: {str(e)}"
            ))
        
        self.is_running = False
        return findings
    
    async def _execute_tool(self, tool_call, findings: list[Finding]) -> dict:
        """Execute a verification tool."""
        name = tool_call.function.name
        args = json.loads(tool_call.function.arguments)
        
        await self.emit(AgentEvent(
            event_type=EventType.TOOL_CALL,
            agent=AgentType.VERIFIER,
            importance=EventImportance.LOW,
            message=f"Verifier executing: {name}",
            details={"tool": name}
        ))
        
        try:
            if name == "verify_cve":
                cve_id = args["cve_id"]
                result = await verify_cve(cve_id)
                
                await self.emit(AgentEvent(
                    event_type=EventType.TOOL_RESULT,
                    agent=AgentType.VERIFIER,
                    importance=EventImportance.LOW,
                    message=f"CVE check: {cve_id} - {'exists' if result.get('exists') else 'NOT FOUND'}",
                    details=result
                ))
                
                if result.get("is_hallucination"):
                    await self.emit(AgentEvent(
                        event_type=EventType.HALLUCINATION_CAUGHT,
                        agent=AgentType.VERIFIER,
                        importance=EventImportance.HIGH,
                        message=f"HALLUCINATION: {cve_id} does not exist in NVD",
                        details=result
                    ))
                
                return result
                
            elif name == "verify_version":
                result = await verify_version_claim(
                    args["software"],
                    args["claimed_version"],
                    args.get("evidence")
                )
                
                await self.emit(AgentEvent(
                    event_type=EventType.TOOL_RESULT,
                    agent=AgentType.VERIFIER,
                    importance=EventImportance.LOW,
                    message=f"Version check: {args['software']} {args['claimed_version']} - {'confirmed' if result.get('confirmed') else 'unconfirmed'}",
                    details=result
                ))
                
                return result
                
            elif name == "verify_endpoint":
                result = await verify_endpoint_exists(
                    args["base_url"],
                    args["endpoint"]
                )
                
                status = result.get("status_code", "unknown")
                await self.emit(AgentEvent(
                    event_type=EventType.TOOL_RESULT,
                    agent=AgentType.VERIFIER,
                    importance=EventImportance.LOW,
                    message=f"Endpoint check: {args['endpoint']} - status {status}",
                    details=result
                ))
                
                return result
                
            elif name == "submit_verdict":
                finding_id = args["finding_id"]
                status = args["status"]
                confidence = args["confidence"]
                reasoning = args["reasoning"]
                
                self.verdicts[finding_id] = {
                    "status": status,
                    "confidence": confidence,
                    "reasoning": reasoning
                }
                self.findings_processed += 1
                
                # Find the finding for context
                finding = next((f for f in findings if f.id == finding_id), None)
                finding_title = finding.title if finding else finding_id
                
                # Emit appropriate event based on verdict
                if status == "hallucination":
                    await self.emit(AgentEvent(
                        event_type=EventType.HALLUCINATION_CAUGHT,
                        agent=AgentType.VERIFIER,
                        importance=EventImportance.HIGH,
                        message=f"HALLUCINATION CAUGHT [{finding_id}]: {reasoning[:80]}",
                        finding_id=finding_id,
                        details={"confidence": confidence, "finding_title": finding_title}
                    ))
                elif status == "verified":
                    await self.emit(AgentEvent(
                        event_type=EventType.FINDING_VERIFIED,
                        agent=AgentType.VERIFIER,
                        importance=EventImportance.MEDIUM,
                        message=f"VERIFIED [{finding_id}]: {finding_title}",
                        finding_id=finding_id,
                        details={"confidence": confidence, "reasoning": reasoning[:100]}
                    ))
                else:  # rejected
                    await self.emit(AgentEvent(
                        event_type=EventType.FINDING_REJECTED,
                        agent=AgentType.VERIFIER,
                        importance=EventImportance.LOW,
                        message=f"REJECTED [{finding_id}]: {reasoning[:80]}",
                        finding_id=finding_id,
                        details={"confidence": confidence}
                    ))
                
                return {
                    "status": "recorded",
                    "finding_id": finding_id,
                    "progress": f"{self.findings_processed}/{self.total_findings}"
                }
            
            return {"error": f"Unknown tool: {name}"}
            
        except Exception as e:
            await self.emit(AgentEvent(
                event_type=EventType.ERROR,
                agent=AgentType.VERIFIER,
                importance=EventImportance.LOW,
                message=f"Tool {name} failed: {str(e)[:50]}"
            ))
            return {"error": str(e)}
    
    def stop(self):
        """Stop the agent."""
        self.is_running = False
