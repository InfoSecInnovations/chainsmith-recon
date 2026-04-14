"""
CVE Verification Tool

Verifies CVE claims against known databases (simulated for lab).
Used by the Verifier agent to catch hallucinated CVEs.
"""

import re

from app.lib.timeutils import iso_utc, now_utc
from app.models import RawEvidence

# Known real CVEs (subset for demo purposes)
# In production, this would hit NVD API
KNOWN_CVES = {
    "CVE-2023-44487": {
        "description": "HTTP/2 Rapid Reset Attack",
        "affected": ["nginx", "apache", "various"],
        "severity": "HIGH",
        "cvss": 7.5,
    },
    "CVE-2024-21626": {
        "description": "runc container escape",
        "affected": ["runc", "docker", "kubernetes"],
        "severity": "HIGH",
        "cvss": 8.6,
    },
    "CVE-2023-36884": {
        "description": "Microsoft Office and Windows HTML RCE",
        "affected": ["microsoft office", "windows"],
        "severity": "HIGH",
        "cvss": 8.3,
    },
    "CVE-2024-3094": {
        "description": "XZ Utils backdoor",
        "affected": ["xz-utils", "liblzma"],
        "severity": "CRITICAL",
        "cvss": 10.0,
    },
}

# Known fake CVEs that Scout might hallucinate
KNOWN_HALLUCINATED_CVES = [
    "CVE-2024-31847",  # Fake vLLM RCE
    "CVE-2024-28193",  # Fake FastAPI auth bypass
    "CVE-2023-99999",  # Fake embedding extraction
    "CVE-2024-50001",  # Fake Nova prompt injection
]


def validate_cve_format(cve_id: str) -> bool:
    """Check if CVE ID follows valid format."""
    pattern = r"^CVE-\d{4}-\d{4,}$"
    return bool(re.match(pattern, cve_id.upper()))


async def verify_cve(cve_id: str) -> dict:
    """
    Verify if a CVE exists and get its details.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)

    Returns:
        Dictionary with verification results
    """
    cve_id = cve_id.upper().strip()

    results = {
        "cve_id": cve_id,
        "timestamp": iso_utc(),
        "valid_format": False,
        "exists": False,
        "is_hallucination": False,
        "details": None,
        "verification_source": "local_db",  # Would be "NVD" in production
        "confidence": 0.0,
        "reason": None,
    }

    # Check format
    if not validate_cve_format(cve_id):
        results["reason"] = f"Invalid CVE format: {cve_id}"
        return results

    results["valid_format"] = True

    # Check if it's a known hallucination
    if cve_id in KNOWN_HALLUCINATED_CVES:
        results["is_hallucination"] = True
        results["reason"] = (
            f"CVE {cve_id} does not exist in NVD. This appears to be a hallucinated CVE."
        )
        results["confidence"] = 0.95
        return results

    # Check if it's a known real CVE
    if cve_id in KNOWN_CVES:
        results["exists"] = True
        results["details"] = KNOWN_CVES[cve_id]
        results["confidence"] = 1.0
        results["reason"] = f"CVE {cve_id} verified in database"
        return results

    # For unknown CVEs, we'd normally hit NVD API
    # For the lab, we return uncertain status
    results["reason"] = (
        f"CVE {cve_id} not found in local database. Recommend manual verification via NVD."
    )
    results["confidence"] = 0.3

    return results


async def verify_version_claim(
    software: str, claimed_version: str, actual_evidence: str | None = None
) -> dict:
    """
    Verify a version detection claim.

    Args:
        software: Software name
        claimed_version: Version Scout claims to have detected
        actual_evidence: Raw evidence (e.g., header value)

    Returns:
        Dictionary with verification results
    """
    results = {
        "software": software,
        "claimed_version": claimed_version,
        "actual_evidence": actual_evidence,
        "timestamp": iso_utc(),
        "verified": False,
        "mismatch": False,
        "reason": None,
        "confidence": 0.0,
    }

    if actual_evidence:
        # Check if claimed version appears in evidence
        if claimed_version.lower() in actual_evidence.lower():
            results["verified"] = True
            results["confidence"] = 0.9
            results["reason"] = f"Version {claimed_version} confirmed in raw evidence"
        else:
            results["mismatch"] = True
            results["confidence"] = 0.85
            results["reason"] = (
                f"Claimed version {claimed_version} not found in evidence. Evidence shows: {actual_evidence[:100]}"
            )
    else:
        results["reason"] = "No raw evidence provided for verification"
        results["confidence"] = 0.2

    return results


async def verify_endpoint_exists(base_url: str, endpoint: str, timeout: float = 10.0) -> dict:
    """
    Verify that an endpoint actually exists.

    Args:
        base_url: Base URL of the target
        endpoint: Endpoint path to verify
        timeout: Request timeout

    Returns:
        Dictionary with verification results
    """
    import httpx

    full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"

    results = {
        "base_url": base_url,
        "endpoint": endpoint,
        "full_url": full_url,
        "timestamp": iso_utc(),
        "exists": False,
        "status_code": None,
        "reason": None,
        "confidence": 0.0,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            # Try HEAD first, then GET
            response = await client.head(full_url)

            results["status_code"] = response.status_code

            if response.status_code < 400:
                results["exists"] = True
                results["confidence"] = 0.95
                results["reason"] = f"Endpoint returned {response.status_code}"
            elif response.status_code == 404:
                results["exists"] = False
                results["confidence"] = 0.9
                results["reason"] = "Endpoint returned 404 Not Found"
            elif response.status_code == 403:
                results["exists"] = True  # Exists but forbidden
                results["confidence"] = 0.85
                results["reason"] = "Endpoint exists but returns 403 Forbidden"
            else:
                results["confidence"] = 0.5
                results["reason"] = f"Uncertain - endpoint returned {response.status_code}"

    except Exception as e:
        results["reason"] = f"Verification failed: {str(e)}"
        results["confidence"] = 0.1

    return results


def create_verify_cve_evidence(cve_id: str, results: dict) -> RawEvidence:
    """Create evidence record for CVE verification."""
    return RawEvidence(
        tool_name="verify_cve",
        timestamp=now_utc(),
        request={"cve_id": cve_id},
        response=results,
    )
