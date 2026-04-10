"""
Researcher Agent

LLM-powered enrichment agent that gathers external context about findings.
Consults NVD, ExploitDB, vendor advisories, and version-vulnerability databases
to produce structured ResearchEnrichment records.

Supports offline mode for air-gapped deployments where external lookups
return cached/bundled data or graceful "not available" responses.
"""

import json
import logging
from collections.abc import Awaitable, Callable

from app.lib.llm import LLMClient
from app.models import (
    AdvisoryInfo,
    AgentEvent,
    ComponentType,
    CVEDetail,
    EventImportance,
    EventType,
    ExploitInfo,
    Observation,
    ResearchEnrichment,
)

logger = logging.getLogger(__name__)

# ─── System Prompt ──────────────────────────────────────────────

RESEARCHER_SYSTEM_PROMPT = """\
You are Researcher, an AI agent that enriches security observations with external context.

Your job is to gather detailed information about CVEs, software versions, known exploits,
and vendor advisories related to each observation. You decide what lookups are most valuable
and interpret the results.

AVAILABLE TOOLS:
1. lookup_cve — Get CVE details (description, CVSS, affected versions, references)
2. lookup_exploit_db — Check for public exploits
3. fetch_vendor_advisory — Retrieve vendor security bulletins
4. enrich_version_info — Find known vulnerabilities for a product/version

APPROACH:
- For observations referencing a CVE: always look it up for full details
- For version disclosures: check what vulnerabilities affect that version
- For any finding: check if public exploits exist
- Use your judgment about which lookups are most valuable for each observation

SUBMIT ENRICHMENT:
For each observation, call submit_enrichment with your structured findings.
Include all data sources you consulted (even if they returned no results).

Be thorough but practical. Not every observation needs all four lookups."""

RESEARCHER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_cve",
            "description": "Fetch CVE details from NVD (description, CVSS, affected versions, references)",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2021-41773)"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_exploit_db",
            "description": "Check ExploitDB for public exploits related to a CVE",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE ID to search for"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_vendor_advisory",
            "description": "Retrieve a vendor security advisory by URL",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Advisory URL"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_version_info",
            "description": "Find known vulnerabilities for a specific product/version",
            "parameters": {
                "type": "object",
                "properties": {
                    "product": {"type": "string", "description": "Software product name"},
                    "version": {"type": "string", "description": "Version string"},
                },
                "required": ["product", "version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_enrichment",
            "description": "Submit structured enrichment data for an observation",
            "parameters": {
                "type": "object",
                "properties": {
                    "observation_id": {"type": "string"},
                    "cve_details": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "cve_id": {"type": "string"},
                                "description": {"type": "string"},
                                "cvss_score": {"type": "number"},
                                "severity": {"type": "string"},
                                "published_date": {"type": "string"},
                                "affected_versions": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "references": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                        },
                    },
                    "exploit_availability": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": {"type": "string"},
                                "url": {"type": "string"},
                                "description": {"type": "string"},
                                "verified": {"type": "boolean"},
                            },
                        },
                    },
                    "vendor_advisories": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "url": {"type": "string"},
                                "summary": {"type": "string"},
                                "date": {"type": "string"},
                                "vendor": {"type": "string"},
                            },
                        },
                    },
                    "version_vulnerabilities": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "data_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["observation_id", "data_sources"],
            },
        },
    },
]


# ─── Tool Implementations ──────────────────────────────────────

# Known CVE data (simulated — production would hit NVD API)
_CVE_DATABASE = {
    "CVE-2021-41773": {
        "description": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published_date": "2021-10-05",
        "affected_versions": ["2.4.49"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://httpd.apache.org/security/vulnerabilities_24.html",
        ],
    },
    "CVE-2023-44487": {
        "description": "HTTP/2 Rapid Reset Attack allowing denial of service",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published_date": "2023-10-10",
        "affected_versions": ["nginx <1.25.3", "apache <2.4.58"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    },
    "CVE-2024-21626": {
        "description": "runc container escape via leaked file descriptor",
        "cvss_score": 8.6,
        "severity": "HIGH",
        "published_date": "2024-01-31",
        "affected_versions": ["runc <1.1.12"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21626"],
    },
    "CVE-2024-3094": {
        "description": "XZ Utils backdoor in liblzma",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "published_date": "2024-03-29",
        "affected_versions": ["xz-utils 5.6.0", "xz-utils 5.6.1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
    },
}

_EXPLOIT_DATABASE = {
    "CVE-2021-41773": [
        {
            "source": "exploitdb",
            "url": "https://www.exploit-db.com/exploits/50383",
            "description": "Apache HTTP Server 2.4.49 - Path Traversal & RCE",
            "verified": True,
        }
    ],
    "CVE-2024-3094": [
        {
            "source": "github",
            "url": "https://github.com/amlweems/xzbot",
            "description": "XZ backdoor analysis and PoC",
            "verified": False,
        }
    ],
}


async def _lookup_cve(cve_id: str, offline: bool = False) -> dict:
    """Look up CVE details. Uses local DB; production would hit NVD API."""
    cve_id = cve_id.upper().strip()

    if offline:
        if cve_id in _CVE_DATABASE:
            return {"found": True, "offline_mode": True, **_CVE_DATABASE[cve_id]}
        return {
            "found": False,
            "offline_mode": True,
            "message": f"{cve_id} not in bundled database. Online lookup unavailable.",
        }

    # In production, this would be an async HTTP call to NVD API
    if cve_id in _CVE_DATABASE:
        return {"found": True, **_CVE_DATABASE[cve_id]}
    return {"found": False, "message": f"{cve_id} not found. Recommend manual NVD check."}


async def _lookup_exploit_db(cve_id: str, offline: bool = False) -> dict:
    """Check ExploitDB for public exploits."""
    cve_id = cve_id.upper().strip()

    if offline:
        if cve_id in _EXPLOIT_DATABASE:
            return {"found": True, "offline_mode": True, "exploits": _EXPLOIT_DATABASE[cve_id]}
        return {"found": False, "offline_mode": True, "exploits": []}

    if cve_id in _EXPLOIT_DATABASE:
        return {"found": True, "exploits": _EXPLOIT_DATABASE[cve_id]}
    return {"found": False, "exploits": []}


async def _fetch_vendor_advisory(url: str, offline: bool = False) -> dict:
    """Fetch vendor advisory content."""
    if offline:
        return {
            "fetched": False,
            "offline_mode": True,
            "message": "Vendor advisory fetch unavailable in offline mode.",
        }

    # In production: async HTTP fetch + parse
    return {
        "fetched": False,
        "message": f"Advisory fetch from {url} not yet implemented for live sources.",
    }


async def _enrich_version_info(product: str, version: str, offline: bool = False) -> dict:
    """Find known vulnerabilities for a product/version."""
    product_lower = product.lower()
    matches = []

    for cve_id, data in _CVE_DATABASE.items():
        for affected in data.get("affected_versions", []):
            if product_lower in affected.lower() or version in affected:
                matches.append(
                    {
                        "cve_id": cve_id,
                        "description": data["description"],
                        "cvss_score": data["cvss_score"],
                        "severity": data["severity"],
                    }
                )

    return {
        "product": product,
        "version": version,
        "vulnerabilities_found": len(matches),
        "vulnerabilities": matches,
        "offline_mode": offline,
    }


# ─── Agent ──────────────────────────────────────────────────────


class ResearcherAgent:
    """Enriches observations with external vulnerability context.

    Uses LLM reasoning to decide which lookups are most valuable and
    interprets results into structured ResearchEnrichment records.
    """

    def __init__(
        self,
        client: LLMClient,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
        offline_mode: bool = False,
    ):
        self.client = client
        self.event_callback = event_callback
        self.offline_mode = offline_mode
        self.enrichments: dict[str, ResearchEnrichment] = {}
        self.is_running = False

    async def emit(self, event: AgentEvent):
        if self.event_callback:
            await self.event_callback(event)

    async def enrich_observations(
        self, observations: list[Observation]
    ) -> dict[str, ResearchEnrichment]:
        """Enrich a list of observations with external context.

        Returns a dict mapping observation_id -> ResearchEnrichment.
        """
        self.is_running = True
        self.enrichments = {}

        await self.emit(
            AgentEvent(
                event_type=EventType.RESEARCH_REQUESTED,
                agent=ComponentType.RESEARCHER,
                importance=EventImportance.MEDIUM,
                message=f"Researcher starting enrichment of {len(observations)} observations"
                + (" (offline mode)" if self.offline_mode else ""),
                details={"total": len(observations), "offline_mode": self.offline_mode},
            )
        )

        if not observations:
            await self.emit(
                AgentEvent(
                    event_type=EventType.RESEARCH_COMPLETE,
                    agent=ComponentType.RESEARCHER,
                    importance=EventImportance.LOW,
                    message="No observations to enrich",
                )
            )
            self.is_running = False
            return self.enrichments

        observations_text = "\n".join(
            [
                f"- [{o.id}] {o.title}\n"
                f"  Severity: {o.severity.value}\n"
                f"  Evidence: {o.evidence_summary or 'None'}\n"
                f"  References: {', '.join(o.references) if o.references else 'None'}"
                for o in observations
            ]
        )

        messages = [
            {"role": "system", "content": RESEARCHER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Enrich these {len(observations)} observations with external context. "
                    f"Call submit_enrichment for EACH one:\n\n{observations_text}"
                ),
            },
        ]

        if not self.client.is_available():
            logger.warning("LLM not available — skipping research enrichment")
            self.is_running = False
            return self.enrichments

        iteration = 0
        max_iterations = 20
        processed = 0

        try:
            while self.is_running and iteration < max_iterations:
                iteration += 1

                response = await self.client.chat(
                    prompt=json.dumps(messages),
                    system=RESEARCHER_SYSTEM_PROMPT,
                    temperature=0.2,
                    max_tokens=4096,
                )

                if not response.success:
                    logger.warning("Researcher LLM call failed: %s", response.error)
                    break

                # Parse tool calls from response
                tool_calls = self._extract_tool_calls(response.content)

                if not tool_calls:
                    break

                for tc_name, tc_args in tool_calls:
                    result = await self._execute_tool(tc_name, tc_args)
                    if tc_name == "submit_enrichment":
                        processed += 1
                    messages.append(
                        {
                            "role": "assistant",
                            "content": f"Called {tc_name}, result: {json.dumps(result)}",
                        }
                    )

                if processed >= len(observations):
                    break

            await self.emit(
                AgentEvent(
                    event_type=EventType.RESEARCH_COMPLETE,
                    agent=ComponentType.RESEARCHER,
                    importance=EventImportance.MEDIUM,
                    message=f"Research complete: {len(self.enrichments)} observations enriched",
                    details={"enriched": len(self.enrichments), "total": len(observations)},
                )
            )

        except Exception as e:
            logger.exception("Researcher error")
            await self.emit(
                AgentEvent(
                    event_type=EventType.ERROR,
                    agent=ComponentType.RESEARCHER,
                    importance=EventImportance.HIGH,
                    message=f"Researcher error: {str(e)[:100]}",
                )
            )

        self.is_running = False
        return self.enrichments

    def _extract_tool_calls(self, content: str) -> list[tuple[str, dict]]:
        """Extract tool calls from LLM response content.

        Handles both native tool calling (via the LLM client) and
        text-based function call patterns.
        """
        calls = []

        # Try parsing as JSON tool calls
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "tool_calls" in data:
                for tc in data["tool_calls"]:
                    calls.append((tc["name"], tc.get("arguments", {})))
                return calls
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        # Look for function call patterns in text
        import re

        pattern = r"(\w+)\s*\(\s*(\{[^}]*\})\s*\)"
        for match in re.finditer(pattern, content):
            name = match.group(1)
            try:
                args = json.loads(match.group(2))
                if name in (
                    "lookup_cve",
                    "lookup_exploit_db",
                    "fetch_vendor_advisory",
                    "enrich_version_info",
                    "submit_enrichment",
                ):
                    calls.append((name, args))
            except json.JSONDecodeError:
                continue

        return calls

    async def _execute_tool(self, name: str, args: dict) -> dict:
        """Execute a research tool."""
        await self.emit(
            AgentEvent(
                event_type=EventType.TOOL_CALL,
                agent=ComponentType.RESEARCHER,
                importance=EventImportance.LOW,
                message=f"Researcher executing: {name}",
                details={"tool": name},
            )
        )

        try:
            if name == "lookup_cve":
                return await _lookup_cve(args["cve_id"], self.offline_mode)

            elif name == "lookup_exploit_db":
                return await _lookup_exploit_db(args["cve_id"], self.offline_mode)

            elif name == "fetch_vendor_advisory":
                return await _fetch_vendor_advisory(args["url"], self.offline_mode)

            elif name == "enrich_version_info":
                return await _enrich_version_info(
                    args["product"], args["version"], self.offline_mode
                )

            elif name == "submit_enrichment":
                return self._handle_submit_enrichment(args)

            return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            logger.warning("Researcher tool %s failed: %s", name, e)
            return {"error": str(e)}

    def _handle_submit_enrichment(self, args: dict) -> dict:
        """Process a submit_enrichment call and store the result."""
        observation_id = args["observation_id"]

        enrichment = ResearchEnrichment(
            observation_id=observation_id,
            cve_details=[CVEDetail(**cve) for cve in args.get("cve_details", [])],
            exploit_availability=[
                ExploitInfo(**exp) for exp in args.get("exploit_availability", [])
            ],
            vendor_advisories=[AdvisoryInfo(**adv) for adv in args.get("vendor_advisories", [])],
            version_vulnerabilities=args.get("version_vulnerabilities", []),
            data_sources=args.get("data_sources", []),
            offline_mode=self.offline_mode,
        )

        self.enrichments[observation_id] = enrichment

        return {
            "status": "recorded",
            "observation_id": observation_id,
            "cve_count": len(enrichment.cve_details),
            "exploit_count": len(enrichment.exploit_availability),
        }

    def stop(self):
        """Stop the agent."""
        self.is_running = False
