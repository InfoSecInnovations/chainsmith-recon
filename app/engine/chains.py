"""
app/engine/chains.py - Attack Chain Detection

Two-pass chain analysis:
1. Rule-based pattern matching against known attack patterns
2. LLM-based discovery of novel chains
"""

import json
import logging
from typing import Optional, TYPE_CHECKING

from app.lib.llm import get_llm_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger(__name__)


# ─── Attack Chain Patterns ────────────────────────────────────

CHAIN_PATTERNS = [
    {
        "name": "api_documentation_recon",
        "title": "API Documentation Intelligence Gathering",
        "description": "Exposed API documentation combined with endpoint discovery reveals full attack surface",
        "severity": "medium",
        "required_findings": [
            {"check_name": "openapi_discovery"},
            {"check_name": "path_probe", "title_contains": "openapi"}
        ],
        "exploitation_steps": [
            "Access the exposed OpenAPI/Swagger documentation",
            "Enumerate all available endpoints and their parameters",
            "Identify authentication requirements for each endpoint",
            "Map out data models and potential injection points",
            "Use documentation to craft targeted API attacks"
        ]
    },
    {
        "name": "technology_stack_fingerprint",
        "title": "Technology Stack Identification",
        "description": "Version disclosure enables targeted vulnerability research",
        "severity": "medium",
        "required_findings": [
            {"check_name": "service_probe", "title_contains": "Technology"},
            {"check_name": "service_probe", "title_contains": "Server"}
        ],
        "exploitation_steps": [
            "Note the disclosed technology versions (e.g., vLLM/0.4.1)",
            "Search CVE databases for known vulnerabilities",
            "Check for default credentials or configurations",
            "Research technology-specific attack techniques",
            "Prepare targeted exploits based on version information"
        ]
    },
    {
        "name": "security_header_weakness",
        "title": "Client-Side Attack Surface",
        "description": "Missing security headers enable client-side attacks",
        "severity": "low",
        "required_findings": [
            {"check_name": "header_analysis", "title_contains": "Missing security headers"}
        ],
        "exploitation_steps": [
            "Note missing headers (CSP, X-Frame-Options, etc.)",
            "Test for XSS vulnerabilities without CSP protection",
            "Attempt clickjacking attacks without frame protection",
            "Check for MIME-sniffing vulnerabilities",
            "Craft client-side attack payloads"
        ]
    },
    {
        "name": "protected_admin_interface",
        "title": "Protected Administrative Interface",
        "description": "Admin interface exists but is protected - potential authorization bypass target",
        "severity": "medium",
        "required_findings": [
            {"check_name": "path_probe", "title_contains": "Protected path", "title_contains_2": "admin"}
        ],
        "exploitation_steps": [
            "Note the protected admin path location",
            "Test for authorization bypass techniques",
            "Check for parameter manipulation to access admin functions",
            "Look for alternative paths to admin functionality",
            "Test for IDOR vulnerabilities in admin endpoints"
        ]
    },
    {
        "name": "debug_endpoint_exposure",
        "title": "Debug Endpoint Information Leakage",
        "description": "Debug endpoints may leak sensitive configuration or allow manipulation",
        "severity": "high",
        "required_findings": [
            {"check_name": "openapi_discovery", "evidence_contains": "debug"}
        ],
        "exploitation_steps": [
            "Access discovered debug endpoints",
            "Extract configuration information",
            "Look for sensitive data in debug output",
            "Test for debug functionality that modifies state",
            "Check for ability to enable verbose error messages"
        ]
    },
    {
        "name": "multi_service_attack_surface",
        "title": "Multi-Service Architecture Reconnaissance",
        "description": "Multiple services discovered increases attack surface complexity",
        "severity": "medium",
        "required_findings": [
            {"check_name": "dns_enumeration", "count_gte": 2}
        ],
        "exploitation_steps": [
            "Map relationships between discovered services",
            "Identify internal communication patterns",
            "Look for services with weaker security postures",
            "Test for SSRF between services",
            "Check for trust relationships that can be exploited"
        ]
    },
    {
        "name": "ai_service_prompt_injection",
        "title": "AI/ML Service Prompt Injection Surface",
        "description": "Chat/AI endpoints combined with API documentation suggest prompt injection opportunities",
        "severity": "high",
        "required_findings": [
            {"check_name": "llm_endpoint_discovery"},
            {"check_name": "openapi_discovery"}
        ],
        "exploitation_steps": [
            "Identify chat/completion endpoints from API documentation",
            "Test for prompt injection vulnerabilities",
            "Attempt to extract system prompts",
            "Try to bypass content filters",
            "Test for indirect prompt injection via other data sources"
        ]
    },
    {
        "name": "ai_model_reconnaissance",
        "title": "AI Model Information Disclosure",
        "description": "Model information endpoints reveal architecture details for targeted attacks",
        "severity": "medium",
        "required_findings": [
            {"check_name": "model_info_check"},
            {"check_name": "ai_framework_fingerprint"}
        ],
        "exploitation_steps": [
            "Extract model version and architecture details",
            "Research known vulnerabilities for identified framework",
            "Identify model-specific attack techniques",
            "Use model info to craft targeted prompts",
            "Check for model configuration weaknesses"
        ]
    },
    {
        "name": "ai_error_exploitation",
        "title": "AI Service Error-Based Reconnaissance",
        "description": "Error messages from AI service reveal internal structure and tools",
        "severity": "high",
        "required_findings": [
            {"check_name": "ai_error_leakage", "title_contains": "tool"},
        ],
        "exploitation_steps": [
            "Analyze leaked tool names from error messages",
            "Map internal API structure from path disclosures",
            "Use stack traces to identify code paths",
            "Craft inputs that trigger informative errors",
            "Target discovered tools for abuse"
        ]
    },
    {
        "name": "embedding_data_extraction",
        "title": "Embedding Endpoint Data Exposure",
        "description": "Embedding endpoints may enable training data extraction or inference attacks",
        "severity": "medium",
        "required_findings": [
            {"check_name": "embedding_endpoint_discovery"}
        ],
        "exploitation_steps": [
            "Test embedding endpoint for membership inference",
            "Attempt to extract training data patterns",
            "Check for embedding inversion possibilities",
            "Test rate limits on embedding generation",
            "Look for sensitive data in embedding responses"
        ]
    }
]


# ─── Chain Analysis ───────────────────────────────────────────

async def run_chain_analysis(state: "AppState"):
    """
    Run two-pass chain analysis: rule-based then LLM.
    
    Updates state.chains and state.chain_status.
    """
    try:
        logger.info("Starting chain analysis...")
        
        # Pass 1: Rule-based pattern matching
        rule_chains = detect_rule_based_chains(state)
        logger.info(f"Rule-based analysis found {len(rule_chains)} chains")
        
        for chain in rule_chains:
            state.chains.append(chain)
        
        # Pass 2: LLM-based analysis
        llm_chains = await detect_llm_chains(state)
        logger.info(f"LLM analysis found {len(llm_chains)} additional chains")
        
        for chain in llm_chains:
            # Check if this overlaps with a rule-based chain
            overlapping = find_overlapping_chain(chain, rule_chains)
            if overlapping:
                # Merge: update the rule-based chain with LLM insights
                overlapping["source"] = "both"
                overlapping["llm_reasoning"] = chain.get("llm_reasoning")
                if chain.get("exploitation_steps"):
                    overlapping["exploitation_steps"].extend(chain["exploitation_steps"])
            else:
                state.chains.append(chain)
        
        state.chain_status = "complete"
        logger.info(f"Chain analysis complete. {len(state.chains)} total chains.")
        
    except Exception as e:
        logger.exception(f"Chain analysis error: {e}")
        state.chain_status = "error"
        state.chain_error = str(e)


def detect_rule_based_chains(state: "AppState") -> list[dict]:
    """Detect chains using predefined patterns."""
    chains = []
    chain_counter = 0
    
    for pattern in CHAIN_PATTERNS:
        matching_findings = match_pattern(pattern, state.findings)
        
        if matching_findings:
            chain_counter += 1
            chains.append({
                "id": f"C-{chain_counter:03d}",
                "title": pattern["title"],
                "description": pattern["description"],
                "severity": pattern["severity"],
                "finding_ids": [f["id"] for f in matching_findings],
                "exploitation_steps": pattern["exploitation_steps"],
                "source": "rule-based",
                "pattern_name": pattern["name"],
                "llm_reasoning": None
            })
    
    return chains


def match_pattern(pattern: dict, findings: list[dict]) -> list[dict]:
    """Check if findings match a pattern's requirements."""
    matched_findings = []
    
    for req in pattern["required_findings"]:
        matching = []
        
        for finding in findings:
            # Check check_name match
            if req.get("check_name") and finding.get("check_name") != req["check_name"]:
                continue
            
            # Check title_contains
            if req.get("title_contains"):
                if req["title_contains"].lower() not in finding.get("title", "").lower():
                    continue
            
            # Check title_contains_2 (secondary filter)
            if req.get("title_contains_2"):
                if req["title_contains_2"].lower() not in finding.get("title", "").lower():
                    continue
            
            # Check evidence_contains
            if req.get("evidence_contains"):
                if req["evidence_contains"].lower() not in finding.get("evidence", "").lower():
                    continue
            
            # Check count_gte (minimum count of findings)
            if req.get("count_gte"):
                count = len([f for f in findings if f.get("check_name") == req["check_name"]])
                if count < req["count_gte"]:
                    continue
            
            matching.append(finding)
        
        if not matching:
            return []  # Pattern not fully matched
        
        matched_findings.extend(matching)
    
    # Deduplicate
    seen_ids = set()
    unique_findings = []
    for f in matched_findings:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            unique_findings.append(f)
    
    return unique_findings


async def detect_llm_chains(state: "AppState") -> list[dict]:
    """Use LLM to discover additional attack chains."""
    chains = []
    
    # Check if LLM is available
    llm_client = get_llm_client()
    if not llm_client.is_available():
        logger.info("LLM not configured - skipping AI chain analysis")
        return chains
    
    # Prepare findings summary for LLM
    findings_summary = []
    for f in state.findings:
        findings_summary.append({
            "id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "check": f.get("check_name"),
            "target": f.get("target_url"),
            "evidence": f.get("evidence", "")[:200]  # Truncate evidence
        })
    
    prompt = f"""You are a penetration testing expert analyzing reconnaissance findings for attack chain opportunities.

Target: {state.target}

Findings discovered:
{format_findings_for_llm(findings_summary)}

Analyze these findings and identify potential ATTACK CHAINS - combinations of findings that together enable a more severe attack than any single finding alone.

For each chain you identify, provide:
1. A descriptive title
2. Which finding IDs are involved
3. The combined severity (low/medium/high/critical)
4. Step-by-step exploitation instructions
5. Your reasoning for why these findings combine into a chain

Respond in JSON format:
{{
    "chains": [
        {{
            "title": "Chain title",
            "finding_ids": ["F-001", "F-002"],
            "severity": "high",
            "exploitation_steps": ["Step 1", "Step 2"],
            "reasoning": "Why these findings combine..."
        }}
    ]
}}

Only include chains that represent genuine combined attack opportunities. If no additional chains beyond obvious single-finding attacks exist, return an empty chains array."""

    response = await llm_client.chat(prompt)
    
    if response.success:
        # Parse JSON from response
        llm_chains = parse_llm_response(response.content)
        
        # Convert to our chain format
        chain_counter = len(state.chains) + 1
        for lc in llm_chains:
            chains.append({
                "id": f"C-{chain_counter:03d}",
                "title": lc.get("title", "LLM-discovered chain"),
                "description": lc.get("reasoning", ""),
                "severity": lc.get("severity", "medium"),
                "finding_ids": lc.get("finding_ids", []),
                "exploitation_steps": lc.get("exploitation_steps", []),
                "source": "llm",
                "pattern_name": None,
                "llm_reasoning": lc.get("reasoning")
            })
            chain_counter += 1
        
        logger.info(f"LLM chain analysis found {len(chains)} chains (provider: {llm_client.provider_name})")
    else:
        logger.warning(f"LLM chain analysis failed: {response.error}")
    
    return chains


def format_findings_for_llm(findings: list[dict]) -> str:
    """Format findings for LLM prompt."""
    lines = []
    for f in findings:
        lines.append(f"- {f['id']}: [{f['severity'].upper()}] {f['title']}")
        lines.append(f"  Check: {f['check']}, Target: {f['target']}")
        if f['evidence']:
            lines.append(f"  Evidence: {f['evidence'][:100]}...")
        lines.append("")
    return "\n".join(lines)


def parse_llm_response(content: str) -> list[dict]:
    """Parse LLM JSON response, handling potential formatting issues."""
    # Try to extract JSON from the response
    try:
        # First, try direct parse
        data = json.loads(content)
        return data.get("chains", [])
    except json.JSONDecodeError:
        pass
    
    # Try to find JSON block in response
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(content[start:end])
            return data.get("chains", [])
    except json.JSONDecodeError:
        pass
    
    logger.warning("Could not parse LLM response as JSON")
    return []


def find_overlapping_chain(new_chain: dict, existing_chains: list[dict]) -> Optional[dict]:
    """Find if a chain overlaps significantly with existing chains."""
    new_ids = set(new_chain.get("finding_ids", []))
    
    for existing in existing_chains:
        existing_ids = set(existing.get("finding_ids", []))
        
        # Check for >50% overlap
        overlap = len(new_ids & existing_ids)
        if overlap > 0 and overlap >= len(new_ids) * 0.5:
            return existing
    
    return None
