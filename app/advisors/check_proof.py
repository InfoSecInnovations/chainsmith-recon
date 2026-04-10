"""
CheckProofAdvisor

Deterministic advisor that generates templated reproduction steps for verified
findings. Maps check types to YAML proof command templates and populates them
from observation metadata.

No LLM calls — output is entirely rule-based and deterministic.
"""

import logging
import re
from pathlib import Path

import yaml

from app.models import (
    EvidenceChecklistItem,
    EvidenceQuality,
    Observation,
    ObservationStatus,
    ProofGuidance,
    ProofStep,
    ResearchEnrichment,
)

logger = logging.getLogger(__name__)

# Default templates directory
_TEMPLATES_DIR = Path(__file__).parent.parent / "data" / "proof_templates"


def _load_templates(template_dir: Path | None = None) -> dict[str, dict]:
    """Load all YAML proof templates from the templates directory.

    Returns a dict mapping check_type -> template data.
    """
    directory = template_dir or _TEMPLATES_DIR
    templates = {}

    if not directory.exists():
        logger.warning("Proof templates directory not found: %s", directory)
        return templates

    for path in directory.glob("*.yaml"):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict) and "check_type" in data:
                templates[data["check_type"]] = data
        except Exception as e:
            logger.warning("Failed to load proof template %s: %s", path, e)

    logger.info("Loaded %d proof templates from %s", len(templates), directory)
    return templates


def _interpolate(template_str: str, context: dict[str, str]) -> str:
    """Interpolate {placeholders} in a template string with context values.

    Unknown placeholders are left as-is (e.g., {unknown_field}).
    """

    def replacer(match):
        key = match.group(1)
        return context.get(key, match.group(0))

    return re.sub(r"\{(\w+)\}", replacer, template_str)


def _build_context(
    observation: Observation, enrichment: ResearchEnrichment | None
) -> dict[str, str]:
    """Build the interpolation context from an observation and optional enrichment."""
    ctx: dict[str, str] = {
        "target_url": observation.target_url or "",
        "host": observation.target_service or "",
        "finding_id": observation.id,
        "finding_title": observation.title,
        "severity": observation.severity.value,
    }

    # Extract common fields from raw_evidence
    if observation.raw_evidence:
        re_data = observation.raw_evidence
        if re_data.headers:
            ctx["header_name"] = next(iter(re_data.headers), "")
            server = re_data.headers.get("server", re_data.headers.get("Server", ""))
            if server:
                ctx["server_header"] = server
        if re_data.status_code is not None:
            ctx["status_code"] = str(re_data.status_code)
        if re_data.body:
            ctx["response_body"] = re_data.body[:200]

    # Extract from evidence_summary
    if observation.evidence_summary:
        ctx["evidence"] = observation.evidence_summary

    # Extract version info from title/description
    version_match = re.search(
        r"(\d+\.\d+(?:\.\d+)*)", observation.title + " " + observation.description
    )
    if version_match:
        ctx["version"] = version_match.group(1)

    # Extract CVE IDs from references
    cve_ids = [ref for ref in observation.references if ref.startswith("CVE-")]
    if cve_ids:
        ctx["cve_id"] = cve_ids[0]

    # Extract endpoint path
    if observation.target_url:
        from urllib.parse import urlparse

        parsed = urlparse(observation.target_url)
        ctx["endpoint_path"] = parsed.path or "/"
        ctx["port"] = str(parsed.port) if parsed.port else ""
        ctx["host"] = parsed.hostname or ctx.get("host", "")

    # Enrich from Researcher data
    if enrichment:
        if enrichment.cve_details:
            cve = enrichment.cve_details[0]
            ctx.setdefault("cve_id", cve.cve_id)
            ctx["cvss_score"] = str(cve.cvss_score) if cve.cvss_score else ""
            ctx["cve_description"] = cve.description
            if cve.affected_versions:
                ctx["affected_versions"] = ", ".join(cve.affected_versions)
            if cve.published_date:
                ctx["published_date"] = cve.published_date

    return ctx


def _match_template(observation: Observation, templates: dict[str, dict]) -> dict:
    """Find the best matching template for an observation.

    Matches on check_name first, then falls back to observation_type patterns,
    then to the default template.
    """
    # Direct match on check_name / observation_type
    check_name = observation.observation_type.lower().replace(" ", "_")

    # Try exact match
    if check_name in templates:
        return templates[check_name]

    # Try partial matches
    for template_type, template in templates.items():
        if template_type == "default":
            continue
        if template_type in check_name or check_name in template_type:
            return template

    # Pattern-based matching
    title_lower = observation.title.lower()
    desc_lower = observation.description.lower()
    combined = title_lower + " " + desc_lower

    if any(kw in combined for kw in ["header", "x-frame", "hsts", "csp", "cors"]):
        if "header_analysis" in templates:
            return templates["header_analysis"]

    if any(kw in combined for kw in ["version", "disclosure", "banner", "server header"]):
        if "version_disclosure" in templates:
            return templates["version_disclosure"]

    if any(kw in combined for kw in ["cve-", "vulnerability", "vulnerable version"]):
        if "cve_match" in templates:
            return templates["cve_match"]

    if any(kw in combined for kw in ["endpoint", "api", "admin", "path", "directory"]):
        if "endpoint_discovery" in templates:
            return templates["endpoint_discovery"]

    if any(kw in combined for kw in ["port", "open port", "service"]):
        if "port_scan" in templates:
            return templates["port_scan"]

    if any(kw in combined for kw in ["prompt", "injection", "llm", "chatbot", "ai"]):
        if "ai_prompt_injection" in templates:
            return templates["ai_prompt_injection"]

    if any(kw in combined for kw in ["robots", "sitemap"]):
        if "robots_sitemap" in templates:
            return templates["robots_sitemap"]

    return templates.get("default", {})


class CheckProofAdvisor:
    """Deterministic advisor that generates proof guidance for verified findings.

    Loads YAML proof templates and populates them from observation metadata.
    No LLM calls — entirely rule-based.
    """

    def __init__(self, template_dir: Path | None = None):
        self.templates = _load_templates(template_dir)

    def generate_guidance(
        self,
        observation: Observation,
        enrichment: ResearchEnrichment | None = None,
    ) -> ProofGuidance:
        """Generate proof guidance for a single observation.

        Args:
            observation: The verified observation to generate guidance for.
            enrichment: Optional Researcher enrichment data.

        Returns:
            ProofGuidance with reproduction steps, evidence checklist, etc.
        """
        template = _match_template(observation, self.templates)
        context = _build_context(observation, enrichment)

        # Build proof steps from template
        proof_steps = []
        for step_data in template.get("proof_steps", []):
            proof_steps.append(
                ProofStep(
                    tool=step_data.get("tool", "manual"),
                    command=_interpolate(step_data.get("command", ""), context),
                    expected_output=_interpolate(step_data.get("expected_output", ""), context),
                    screenshot_worthy=step_data.get("screenshot_worthy", False),
                )
            )

        # Build evidence checklist
        evidence_checklist = [
            EvidenceChecklistItem(description=item, captured=False)
            for item in template.get("evidence_checklist", [])
        ]

        # Build severity rationale
        severity_rationale = self._build_severity_rationale(observation, enrichment, context)

        # Build false positive indicators
        false_positive_indicators = self._build_fp_indicators(observation, context)

        # Common mistakes from template
        common_mistakes = template.get("common_mistakes", [])

        return ProofGuidance(
            finding_id=observation.id,
            finding_title=observation.title,
            verification_status=observation.status.value,
            evidence_quality=observation.evidence_quality.value
            if observation.evidence_quality
            else None,
            proof_steps=proof_steps,
            evidence_checklist=evidence_checklist,
            severity_rationale=severity_rationale,
            false_positive_indicators=false_positive_indicators,
            common_mistakes=common_mistakes,
        )

    def generate_batch(
        self,
        observations: list[Observation],
        enrichments: dict[str, ResearchEnrichment] | None = None,
    ) -> list[ProofGuidance]:
        """Generate proof guidance for multiple observations.

        Only processes verified observations.
        """
        results = []
        enrichments = enrichments or {}

        for obs in observations:
            if obs.status != ObservationStatus.VERIFIED:
                continue
            enrichment = enrichments.get(obs.id)
            results.append(self.generate_guidance(obs, enrichment))

        return results

    def _build_severity_rationale(
        self,
        observation: Observation,
        enrichment: ResearchEnrichment | None,
        context: dict[str, str],
    ) -> str:
        """Build a severity rationale from observation and enrichment data."""
        parts = [f"Rated {observation.severity.value.upper()}."]

        if observation.evidence_quality:
            quality_desc = {
                EvidenceQuality.DIRECT_OBSERVATION: "directly confirmed by tool verification",
                EvidenceQuality.INFERRED: "inferred from available evidence (not directly confirmed)",
                EvidenceQuality.CLAIMED_NO_PROOF: "claimed without verifiable proof",
            }
            parts.append(
                f"Evidence was {quality_desc.get(observation.evidence_quality, 'unknown')}."
            )

        if enrichment and enrichment.cve_details:
            cve = enrichment.cve_details[0]
            if cve.cvss_score is not None:
                parts.append(f"CVSS score: {cve.cvss_score}.")
            if enrichment.exploit_availability:
                parts.append(f"{len(enrichment.exploit_availability)} public exploit(s) known.")

        if observation.verification_notes:
            parts.append(f"Verifier notes: {observation.verification_notes[:200]}")

        return " ".join(parts)

    def _build_fp_indicators(self, observation: Observation, context: dict[str, str]) -> list[str]:
        """Build false positive indicators based on observation type."""
        indicators = []
        title_lower = observation.title.lower()

        if "header" in title_lower:
            indicators.append(
                "Header is present but not detected due to case sensitivity or encoding"
            )
            indicators.append("CDN or WAF adds the header after the check captured the response")

        if "version" in title_lower:
            indicators.append("Reported version is a facade/decoy configured by the administrator")
            indicators.append(
                "Backported security patches fix the vulnerability without changing version number"
            )

        if "cve" in title_lower or context.get("cve_id"):
            indicators.append("CVE is disputed or rejected in NVD")
            indicators.append(
                "Vendor has applied a backported patch that doesn't change the version string"
            )
            indicators.append("Configuration or environment makes the vulnerability unexploitable")

        if "endpoint" in title_lower:
            indicators.append(
                "Endpoint returns a generic response regardless of path (catch-all handler)"
            )
            indicators.append("Endpoint requires authentication that was not tested")

        if "prompt" in title_lower or "injection" in title_lower:
            indicators.append(
                "AI response is non-deterministic and the behavior doesn't reproduce consistently"
            )
            indicators.append("Guardrails were temporarily disabled during testing")

        if not indicators:
            indicators.append("The target has been patched or reconfigured since the scan")
            indicators.append("Network conditions differ between scan and manual verification")

        return indicators
