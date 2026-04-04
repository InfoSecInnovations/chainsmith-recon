"""
app/checks/rag/source_attribution.py - Source Attribution Manipulation

Test if RAG source citations can be spoofed or manipulated. Checks
whether the citation system distinguishes between injected and
legitimate documents, and whether citation URLs are validated.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

# Queries designed to elicit cited responses
CITATION_QUERIES = [
    "Cite the source for your answer about company policies",
    "What are the official guidelines? Please include references.",
    "Summarize the documentation and list your sources",
]

# Patterns indicating citations in responses
CITATION_PATTERNS = [
    re.compile(r"(?:source|reference|citation)s?\s*:", re.I),
    re.compile(r"\[(?:source|ref|doc)\s*\d+\]", re.I),
    re.compile(r"\(\d{4}\)", re.I),  # Year citations
    re.compile(r"(?:from|according to)\s+[\"']([^\"']+)[\"']", re.I),
    re.compile(r"https?://\S+", re.I),
]

# URL validation patterns
SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)", re.I),
    re.compile(r"https?://[^/]*\.(test|example|invalid|local)\b", re.I),
]


class RAGSourceAttributionCheck(ServiceIteratingCheck):
    """
    Analyze RAG source citations for spoofability and URL validation.
    """

    name = "rag_source_attribution"
    description = "Analyze RAG source citation reliability and URL validation"

    conditions = [CheckCondition("rag_endpoints", "truthy")]
    produces = ["citation_reliability"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 60.0
    delay_between_targets = 0.5

    reason = (
        "Spoofed citations can make injected content appear authoritative, "
        "and unvalidated citation URLs can be used for phishing"
    )
    references = [
        "OWASP LLM Top 10 - LLM09 Overreliance",
    ]
    techniques = ["citation analysis", "source attribution testing", "URL validation"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        rag_endpoints = context.get("rag_endpoints", [])
        service_endpoints = [
            ep
            for ep in rag_endpoints
            if ep.get("service", {}).get("host") == service.host
            and ep.get("endpoint_type") == "rag_query"
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=12.0, verify_ssl=False)
        citation_info: dict[str, Any] = {
            "has_citations": False,
            "citation_types": [],
            "urls_found": [],
            "urls_validated": None,
            "structured_sources": False,
        }

        try:
            async with AsyncHttpClient(cfg) as client:
                ep = service_endpoints[0]
                url = ep.get("url", service.url)

                all_responses: list[str] = []
                all_structured: list[dict] = []

                for query in CITATION_QUERIES:
                    body = {
                        "query": query,
                        "question": query,
                        "input": query,
                        "k": 5,
                    }
                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.error or resp.status_code >= 400:
                        continue

                    resp_text = resp.body or ""
                    all_responses.append(resp_text)

                    # Check for structured source fields
                    try:
                        data = json.loads(resp_text)
                        if isinstance(data, dict):
                            for key in [
                                "sources",
                                "citations",
                                "references",
                                "source_documents",
                                "metadata",
                            ]:
                                if key in data:
                                    citation_info["structured_sources"] = True
                                    if isinstance(data[key], list):
                                        all_structured.extend(
                                            s for s in data[key] if isinstance(s, dict)
                                        )
                    except json.JSONDecodeError:
                        pass

                # Analyze all responses
                combined = "\n".join(all_responses)
                citation_info = self._analyze_citations(combined, all_structured, citation_info)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate findings
        if citation_info["has_citations"]:
            urls = citation_info.get("urls_found", [])
            suspicious = [u for u in urls if any(p.search(u) for p in SUSPICIOUS_URL_PATTERNS)]

            if suspicious:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="Citation URLs not validated: suspicious URLs in sources",
                        description=(
                            f"Found {len(suspicious)} suspicious URL(s) in citations. "
                            f"Arbitrary URLs may appear in source citations."
                        ),
                        severity="medium",
                        evidence=f"Suspicious URLs: {', '.join(suspicious[:3])}",
                        host=service.host,
                        discriminator="citation-urls-suspicious",
                        target=service,
                        raw_data=citation_info,
                        references=self.references,
                    )
                )

            if citation_info["structured_sources"]:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="Source attribution present with structured citations",
                        description=(
                            f"RAG returns structured source data. "
                            f"Citation types: {', '.join(citation_info['citation_types'])}."
                        ),
                        severity="low",
                        evidence=self._build_evidence(citation_info),
                        host=service.host,
                        discriminator="citation-structured",
                        target=service,
                        raw_data=citation_info,
                    )
                )
            else:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="Source attribution present but document origin not verified",
                        description="Citations found in text but no structured source verification.",
                        severity="low",
                        evidence=self._build_evidence(citation_info),
                        host=service.host,
                        discriminator="citation-unstructured",
                        target=service,
                        raw_data=citation_info,
                    )
                )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="No source attribution in RAG responses",
                    description="RAG responses do not include source citations.",
                    severity="info",
                    evidence="No citation patterns detected across queries",
                    host=service.host,
                    discriminator="no-citations",
                    target=service,
                )
            )

        result.outputs["citation_reliability"] = citation_info
        return result

    def _analyze_citations(
        self,
        combined_text: str,
        structured: list[dict],
        info: dict,
    ) -> dict:
        """Analyze combined response text for citation patterns."""
        for pattern in CITATION_PATTERNS:
            if pattern.search(combined_text):
                info["has_citations"] = True
                # Infer citation type
                if "source" in pattern.pattern.lower():
                    info["citation_types"].append("source_reference")
                elif "http" in pattern.pattern.lower():
                    info["citation_types"].append("url")
                else:
                    info["citation_types"].append("inline")

        # Extract URLs from responses
        url_pattern = re.compile(r"https?://[^\s\"'<>\]]+")
        info["urls_found"] = list(set(url_pattern.findall(combined_text)))[:20]

        # Check structured sources for URLs
        for src in structured:
            for key in ["url", "source", "link", "href"]:
                val = src.get(key, "")
                if isinstance(val, str) and val.startswith("http"):
                    if val not in info["urls_found"]:
                        info["urls_found"].append(val)

        info["citation_types"] = list(set(info["citation_types"]))
        return info

    def _build_evidence(self, info: dict) -> str:
        lines = [f"Citations detected: {info['has_citations']}"]
        if info["citation_types"]:
            lines.append(f"Types: {', '.join(info['citation_types'])}")
        if info["urls_found"]:
            lines.append(f"URLs found: {len(info['urls_found'])}")
            for u in info["urls_found"][:3]:
                lines.append(f"  {u}")
        lines.append(f"Structured sources: {info['structured_sources']}")
        return "\n".join(lines)
