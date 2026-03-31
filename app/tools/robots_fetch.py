"""
Robots.txt Fetch Tool

Retrieves and parses robots.txt files from target URLs.
"""

from datetime import datetime
from urllib.parse import urljoin, urlparse
import httpx

from app.models import RawEvidence


async def fetch_robots(
    base_url: str,
    timeout: float = 10.0
) -> dict:
    """
    Fetch and parse robots.txt from a URL.
    
    Args:
        base_url: Base URL of the target
        timeout: Request timeout
    
    Returns:
        Dictionary with robots.txt analysis
    """
    # Ensure we're hitting the robots.txt at the root
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    
    results = {
        "url": robots_url,
        "base_url": base_url,
        "timestamp": datetime.utcnow().isoformat(),
        "success": False,
        "status_code": None,
        "content": None,
        "disallowed_paths": [],
        "allowed_paths": [],
        "sitemaps": [],
        "interesting_paths": [],
        "user_agents": [],
        "error": None,
    }
    
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.get(robots_url)
            
            results["status_code"] = response.status_code
            
            if response.status_code == 200:
                results["success"] = True
                results["content"] = response.text
                
                # Parse robots.txt
                current_agent = "*"
                
                for line in response.text.split("\n"):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    
                    # Parse directives
                    if ":" in line:
                        directive, value = line.split(":", 1)
                        directive = directive.strip().lower()
                        value = value.strip()
                        
                        if directive == "user-agent":
                            current_agent = value
                            if value not in results["user_agents"]:
                                results["user_agents"].append(value)
                        
                        elif directive == "disallow":
                            if value:
                                results["disallowed_paths"].append({
                                    "path": value,
                                    "user_agent": current_agent
                                })
                                
                                # Check for interesting paths
                                interesting_keywords = [
                                    "admin", "internal", "api", "debug", 
                                    "config", "backup", "private", "secret",
                                    "model", "ml", "ai", "data"
                                ]
                                if any(kw in value.lower() for kw in interesting_keywords):
                                    results["interesting_paths"].append({
                                        "path": value,
                                        "reason": "Potentially sensitive path in Disallow",
                                        "full_url": urljoin(base_url, value)
                                    })
                        
                        elif directive == "allow":
                            if value:
                                results["allowed_paths"].append({
                                    "path": value,
                                    "user_agent": current_agent
                                })
                        
                        elif directive == "sitemap":
                            results["sitemaps"].append(value)
            
            elif response.status_code == 404:
                results["error"] = "robots.txt not found (404)"
            else:
                results["error"] = f"Unexpected status code: {response.status_code}"
                
    except httpx.TimeoutException:
        results["error"] = "Connection timeout"
    except httpx.ConnectError as e:
        results["error"] = f"Connection failed: {str(e)}"
    except Exception as e:
        results["error"] = f"Error: {str(e)}"
    
    return results


def create_robots_fetch_evidence(base_url: str, results: dict) -> RawEvidence:
    """Create evidence record for robots.txt fetch."""
    return RawEvidence(
        tool_name="robots_fetch",
        timestamp=datetime.utcnow(),
        request={"base_url": base_url},
        response=results,
        body=results.get("content"),
        status_code=results.get("status_code"),
    )
