"""
Chatbot Probe Tool

Probes AI chatbots to extract information about their capabilities and configuration.
"""

from datetime import datetime
from typing import Optional
import httpx
import json

from app.models import RawEvidence


async def probe_chatbot(
    chat_url: str,
    message: str,
    timeout: float = 30.0,
    extract_headers: bool = True
) -> dict:
    """
    Send a probe message to a chatbot and analyze the response.
    
    Args:
        chat_url: Chatbot API endpoint
        message: Message to send
        timeout: Request timeout
        extract_headers: Whether to extract response headers
    
    Returns:
        Dictionary with probe results
    """
    results = {
        "url": chat_url,
        "probe_message": message,
        "timestamp": datetime.utcnow().isoformat(),
        "success": False,
        "status_code": None,
        "response_body": None,
        "response_headers": {},
        "tools_mentioned": [],
        "model_hints": [],
        "error_info": None,
        "response_time_ms": None,
    }
    
    # Ensure we're hitting the chat endpoint
    if not chat_url.endswith("/chat"):
        chat_url = chat_url.rstrip("/") + "/chat"
    
    try:
        start_time = datetime.utcnow()
        
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.post(
                chat_url,
                json={"message": message},
                headers={"Content-Type": "application/json"}
            )
            
            end_time = datetime.utcnow()
            results["response_time_ms"] = (end_time - start_time).total_seconds() * 1000
            
            results["status_code"] = response.status_code
            
            if extract_headers:
                results["response_headers"] = dict(response.headers)
            
            try:
                body = response.json()
                results["response_body"] = body
                results["success"] = True
                
                # Analyze response for interesting info
                body_str = json.dumps(body).lower()
                
                # Look for tool mentions
                common_tools = [
                    "get_account", "get_balance", "get_transaction",
                    "lookup", "search", "fetch", "report",
                    "internal", "admin", "debug"
                ]
                for tool in common_tools:
                    if tool in body_str:
                        results["tools_mentioned"].append(tool)
                
                # Look for model hints
                model_keywords = [
                    "gpt", "claude", "nova", "llama", "mistral",
                    "bedrock", "openai", "anthropic", "amazon"
                ]
                for model in model_keywords:
                    if model in body_str:
                        results["model_hints"].append(model)
                
            except json.JSONDecodeError:
                results["response_body"] = response.text
                results["success"] = response.status_code < 400
                
    except httpx.TimeoutException:
        results["error_info"] = {"type": "timeout", "message": "Request timed out"}
    except httpx.ConnectError as e:
        results["error_info"] = {"type": "connection", "message": str(e)}
    except Exception as e:
        results["error_info"] = {"type": "unknown", "message": str(e)}
    
    return results


async def trigger_error(
    chat_url: str,
    timeout: float = 15.0
) -> dict:
    """
    Attempt to trigger an error response from the chatbot.
    
    Sends malformed requests to try to get verbose error messages.
    
    Args:
        chat_url: Chatbot API endpoint
        timeout: Request timeout
    
    Returns:
        Dictionary with error analysis
    """
    results = {
        "url": chat_url,
        "timestamp": datetime.utcnow().isoformat(),
        "error_responses": [],
        "tools_leaked": [],
        "config_leaked": [],
    }
    
    if not chat_url.endswith("/chat"):
        chat_url = chat_url.rstrip("/") + "/chat"
    
    # Different malformed requests to try
    test_cases = [
        {"name": "empty_body", "data": {}},
        {"name": "null_message", "data": {"message": None}},
        {"name": "array_message", "data": {"message": [1, 2, 3]}},
        {"name": "very_long", "data": {"message": "A" * 50000}},
        {"name": "unicode_bomb", "data": {"message": "\u0000" * 100}},
        {"name": "nested_object", "data": {"message": {"nested": {"deep": "value"}}}},
    ]
    
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        for test in test_cases:
            try:
                response = await client.post(
                    chat_url,
                    json=test["data"],
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code >= 400:
                    try:
                        error_body = response.json()
                    except:
                        error_body = response.text
                    
                    error_record = {
                        "test_name": test["name"],
                        "status_code": response.status_code,
                        "response": error_body,
                        "headers": dict(response.headers)
                    }
                    
                    results["error_responses"].append(error_record)
                    
                    # Check for tool leaks
                    error_str = json.dumps(error_body) if isinstance(error_body, dict) else str(error_body)
                    error_lower = error_str.lower()
                    
                    # Look for tool names in error
                    if "available_tools" in error_lower or "tools" in error_lower:
                        if isinstance(error_body, dict):
                            debug_info = error_body.get("debug_info", {})
                            if "available_tools" in debug_info:
                                results["tools_leaked"] = debug_info["available_tools"]
                    
                    # Look for config leaks
                    config_keywords = ["model", "temperature", "max_tokens", "api_key", "endpoint"]
                    for kw in config_keywords:
                        if kw in error_lower:
                            results["config_leaked"].append(kw)
                    
            except Exception as e:
                results["error_responses"].append({
                    "test_name": test["name"],
                    "error": str(e)
                })
    
    return results


def create_chatbot_probe_evidence(chat_url: str, results: dict) -> RawEvidence:
    """Create evidence record for chatbot probe."""
    return RawEvidence(
        tool_name="probe_chatbot",
        timestamp=datetime.utcnow(),
        request={"url": chat_url, "message": results.get("probe_message")},
        response=results,
        headers=results.get("response_headers"),
        status_code=results.get("status_code"),
        response_time_ms=results.get("response_time_ms"),
    )
