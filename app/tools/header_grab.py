"""
HTTP Header Grab Tool

Fetches and analyzes HTTP headers from target URLs.
"""

from datetime import datetime

import httpx

from app.models import RawEvidence


async def grab_headers(
    url: str, method: str = "HEAD", follow_redirects: bool = False, timeout: float = 10.0
) -> dict:
    """
    Fetch HTTP headers from a URL.

    Args:
        url: Target URL
        method: HTTP method (HEAD or GET)
        follow_redirects: Whether to follow redirects
        timeout: Request timeout

    Returns:
        Dictionary with header analysis
    """
    results = {
        "url": url,
        "method": method,
        "timestamp": datetime.utcnow().isoformat(),
        "success": False,
        "status_code": None,
        "headers": {},
        "interesting_headers": [],
        "security_headers": {},
        "redirect_location": None,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,  # Allow self-signed certs
        ) as client:
            if method.upper() == "HEAD":
                response = await client.head(url)
            else:
                response = await client.get(url)

            results["success"] = True
            results["status_code"] = response.status_code
            results["headers"] = dict(response.headers)

            # Check for redirect
            if response.status_code in [301, 302, 303, 307, 308]:
                results["redirect_location"] = response.headers.get("location")

            # Analyze interesting headers
            interesting = []

            # Server identification
            if "server" in response.headers:
                interesting.append(
                    {
                        "header": "Server",
                        "value": response.headers["server"],
                        "significance": "Server software identification",
                    }
                )

            # X-Powered-By
            if "x-powered-by" in response.headers:
                interesting.append(
                    {
                        "header": "X-Powered-By",
                        "value": response.headers["x-powered-by"],
                        "significance": "Technology stack disclosure",
                    }
                )

            # Custom headers (X-*)
            for key, value in response.headers.items():
                key_lower = key.lower()
                if key_lower.startswith("x-") and key_lower not in [
                    "x-powered-by",
                    "x-content-type-options",
                    "x-frame-options",
                    "x-xss-protection",
                ]:
                    interesting.append(
                        {
                            "header": key,
                            "value": value,
                            "significance": "Custom header - potential information leak",
                        }
                    )

            results["interesting_headers"] = interesting

            # Security headers check
            security_headers = {
                "x-content-type-options": response.headers.get("x-content-type-options"),
                "x-frame-options": response.headers.get("x-frame-options"),
                "x-xss-protection": response.headers.get("x-xss-protection"),
                "strict-transport-security": response.headers.get("strict-transport-security"),
                "content-security-policy": response.headers.get("content-security-policy"),
                "access-control-allow-origin": response.headers.get("access-control-allow-origin"),
                "access-control-allow-credentials": response.headers.get(
                    "access-control-allow-credentials"
                ),
            }
            results["security_headers"] = {
                k: v for k, v in security_headers.items() if v is not None
            }

            # Flag dangerous CORS config
            if security_headers["access-control-allow-origin"] == "*":
                if security_headers.get("access-control-allow-credentials") == "true":
                    interesting.append(
                        {
                            "header": "CORS",
                            "value": "Allow-Origin: * with credentials",
                            "significance": "CRITICAL: Dangerous CORS misconfiguration",
                        }
                    )

    except httpx.TimeoutException:
        results["error"] = "Connection timeout"
    except httpx.ConnectError as e:
        results["error"] = f"Connection failed: {str(e)}"
    except Exception as e:
        results["error"] = f"Error: {str(e)}"

    return results


def create_header_grab_evidence(url: str, results: dict) -> RawEvidence:
    """Create evidence record for header grab."""
    return RawEvidence(
        tool_name="header_grab",
        timestamp=datetime.utcnow(),
        request={"url": url, "method": results.get("method", "HEAD")},
        response=results,
        headers=results.get("headers"),
        status_code=results.get("status_code"),
    )
