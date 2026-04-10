"""
Demo-Domain Helpdesk Tools

Legitimate and "mistakenly exposed" tools for the IT helpdesk AI chatbot.
"""

import random
from datetime import datetime

from demo_domain.config import is_finding_active

# ─── Fake Data ───────────────────────────────────────────────────

TICKETS = {
    "TKT-1001": {
        "id": "TKT-1001",
        "status": "open",
        "subject": "VPN not connecting",
        "priority": "high",
        "owner": "USR-002",
        "created": "2026-03-01",
        "description": "VPN client shows 'connection timed out' after domain migration.",
        "assigned_to": "Tier 1 - IT Ops",
    },
    "TKT-1002": {
        "id": "TKT-1002",
        "status": "resolved",
        "subject": "Password reset",
        "priority": "low",
        "owner": "USR-001",
        "created": "2026-03-02",
        "description": "User forgot domain password after PTO.",
        "assigned_to": "Tier 1 - IT Ops",
    },
    "TKT-1003": {
        "id": "TKT-1003",
        "status": "in_progress",
        "subject": "Laptop won't boot",
        "priority": "high",
        "owner": "USR-002",
        "created": "2026-03-03",
        "description": "Dell Latitude 7440 stuck on BIOS splash screen.",
        "assigned_to": "Tier 2 - Desktop Eng",
    },
    "TKT-1004": {
        "id": "TKT-1004",
        "status": "open",
        "subject": "Email sync issue",
        "priority": "medium",
        "owner": "USR-001",
        "created": "2026-03-04",
        "description": "Outlook not syncing on mobile device since Exchange update.",
        "assigned_to": "Tier 1 - IT Ops",
    },
}

KB_ARTICLES = [
    {
        "id": "KB-001",
        "title": "How to Reset Your Domain Password",
        "summary": "Step-by-step guide to resetting your Active Directory password via the self-service portal.",
        "tags": ["password", "reset", "AD", "self-service"],
    },
    {
        "id": "KB-002",
        "title": "VPN Troubleshooting Guide",
        "summary": "Common VPN connection issues and resolution steps for GlobalProtect.",
        "tags": ["vpn", "globalprotect", "network", "connection"],
    },
    {
        "id": "KB-003",
        "title": "Setting Up MFA",
        "summary": "How to enrol in multi-factor authentication using Microsoft Authenticator.",
        "tags": ["mfa", "2fa", "security", "authenticator"],
    },
    {
        "id": "KB-004",
        "title": "Requesting New Software",
        "summary": "Process for requesting software installations through the IT portal.",
        "tags": ["software", "install", "request", "approval"],
    },
    {
        "id": "KB-005",
        "title": "Outlook Mobile Setup",
        "summary": "Configure Outlook on iOS and Android for corporate email.",
        "tags": ["outlook", "email", "mobile", "exchange"],
    },
]

EMPLOYEES = {
    "alice@corp.internal": {
        "id": "USR-001",
        "name": "Alice Morgan",
        "email": "alice@corp.internal",
        "department": "Engineering",
        "title": "SRE",
        "manager": "Dan Reyes",
        "phone": "x4501",
        "active": True,
    },
    "bob@corp.internal": {
        "id": "USR-002",
        "name": "Bob Nguyen",
        "email": "bob@corp.internal",
        "department": "IT Operations",
        "title": "Sysadmin",
        "manager": "Dan Reyes",
        "phone": "x4502",
        "active": True,
    },
    "carol@corp.internal": {
        "id": "USR-003",
        "name": "Carol Davis",
        "email": "carol@corp.internal",
        "department": "Security",
        "title": "SOC Analyst",
        "manager": "Eve Collins",
        "phone": "x4503",
        "active": True,
    },
    "dan@corp.internal": {
        "id": "USR-004",
        "name": "Dan Reyes",
        "email": "dan@corp.internal",
        "department": "IT Operations",
        "title": "IT Manager",
        "manager": "CTO",
        "phone": "x4504",
        "active": True,
    },
}

INTERNAL_DOCS = {
    "runbooks/vpn-troubleshoot.md": {
        "title": "VPN Troubleshooting Runbook",
        "content": "## VPN Troubleshooting\n1. Check GlobalProtect service\n2. Verify DNS 10.0.4.1\n3. Restart PanGPS service\n4. Escalate to NetOps if unresolved.",
        "classification": "INTERNAL",
    },
    "runbooks/password-reset.md": {
        "title": "Password Reset Procedure",
        "content": "## Password Reset\n1. Verify user identity via employee ID\n2. Reset in AD admin console\n3. Set temp password: TempPass + last4 of employee ID\n4. Force change on next login.",
        "classification": "INTERNAL",
    },
    "policies/acceptable-use.md": {
        "title": "Acceptable Use Policy",
        "content": "## Acceptable Use\nCorporate IT resources are for business use. Personal use is permitted within reason.",
        "classification": "PUBLIC",
    },
}

SERVICES_STATUS = {
    "email": {"name": "Email / Exchange", "status": "operational", "uptime": "99.98%"},
    "vpn": {"name": "VPN (GlobalProtect)", "status": "degraded", "uptime": "97.2%", "note": "Intermittent timeouts on east-coast gateway"},
    "active_directory": {"name": "Active Directory", "status": "operational", "uptime": "99.99%"},
    "ticketing": {"name": "Ticket System", "status": "operational", "uptime": "99.95%"},
    "chat_assistant": {"name": "AI Chat Assistant", "status": "operational", "uptime": "99.5%"},
    "file_share": {"name": "File Shares (SMB)", "status": "operational", "uptime": "99.97%"},
}


# ─── Legitimate Tools (Always Available) ─────────────────────────


def get_ticket(ticket_id: str) -> dict:
    """Look up a support ticket by ID."""
    ticket_id = ticket_id.upper()
    if ticket_id in TICKETS:
        return {"ticket": TICKETS[ticket_id], "found": True}
    return {"found": False, "message": f"Ticket {ticket_id} not found"}


def search_kb(query: str) -> dict:
    """Search knowledge base articles by keyword."""
    query_lower = query.lower()
    results = []
    for article in KB_ARTICLES:
        if (
            query_lower in article["title"].lower()
            or query_lower in article["summary"].lower()
            or any(query_lower in tag for tag in article["tags"])
        ):
            results.append(article)

    return {
        "results": results,
        "total": len(results),
        "query": query,
    }


def check_service_status() -> dict:
    """Check the status of all IT services."""
    return get_service_status()


def create_ticket(subject: str, description: str, priority: str = "medium") -> dict:
    """Create a new support ticket."""
    ticket_id = f"TKT-{random.randint(2000, 9999)}"
    ticket = {
        "id": ticket_id,
        "status": "open",
        "subject": subject,
        "description": description,
        "priority": priority,
        "owner": "current-user",
        "created": datetime.utcnow().strftime("%Y-%m-%d"),
        "assigned_to": "Tier 1 - IT Ops",
    }
    TICKETS[ticket_id] = ticket
    return {"created": True, "ticket": ticket}


# ─── Sensitive / Mistakenly Exposed Tools ────────────────────────


def lookup_employee(email: str) -> dict:
    """
    SHOULD NOT BE EXPOSED - Internal employee directory lookup.
    Allows employee enumeration.
    """
    if not is_finding_active("tool_schema_exposed"):
        return {"error": "Tool not available"}

    email_lower = email.lower()
    if email_lower in EMPLOYEES:
        return {"found": True, "employee": EMPLOYEES[email_lower]}
    return {"found": False, "message": f"No employee found with email: {email}"}


def escalate_ticket(ticket_id: str, user_id: str, reason: str = "") -> dict:
    """
    SHOULD NOT BE EXPOSED - Escalate ticket without human-in-the-loop.
    Executes immediately with no confirmation step.
    """
    if not is_finding_active("agent_tool_abuse"):
        return {"error": "Tool not available"}

    ticket_id = ticket_id.upper()
    confirmation = f"ESC-{random.randint(100000, 999999)}"

    return {
        "escalated": True,
        "ticket_id": ticket_id,
        "escalated_by": user_id,
        "reason": reason or "Automated escalation",
        "confirmation": confirmation,
        "assigned_to": "Tier 2 - On-Call",
        "escalation_contact": "tier2-oncall@corp.internal",
        "_warning": "No HITL verification performed",
    }


def fetch_internal_doc(path: str) -> dict:
    """
    SHOULD NOT BE EXPOSED - Internal document retrieval with path traversal risk.
    """
    if not is_finding_active("tool_schema_exposed"):
        return {"error": "Tool not available"}

    if path in INTERNAL_DOCS:
        doc = INTERNAL_DOCS[path]
        return {
            "status": "success",
            "document": doc,
            "base_path": "/var/data/helpdesk/docs/",
            "full_path": f"/var/data/helpdesk/docs/{path}",
        }
    return {
        "status": "error",
        "message": f"Document not found: {path}",
        "searched_path": f"/var/data/helpdesk/docs/{path}",
        "available_directories": ["runbooks/", "policies/", "internal/", "config/"],
    }


# ─── Aliases used by agent.py MCP layer ──────────────────────────

# agent.py maps MCP tool names to these via execute_tool:
#   get_ticket   -> get_ticket_status  (alias)
#   search_kb    -> get_kb_article     (alias)
#   lookup_user  -> lookup_employee    (alias)


def get_ticket_status(ticket_id: str = "", **kwargs) -> dict:
    """Alias used by the agent MCP layer."""
    return get_ticket(ticket_id)


def get_kb_article(query: str = "", **kwargs) -> dict:
    """Alias used by the agent MCP layer."""
    return search_kb(query)


def lookup_user(email: str = "", **kwargs) -> dict:
    """Alias used by the agent MCP layer."""
    return lookup_employee(email)


# ─── Tool Registry ──────────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "name": "get_ticket",
        "function": {
            "name": "get_ticket",
            "description": "Look up a support ticket by its ID (e.g. TKT-1001)",
            "parameters": {
                "type": "object",
                "properties": {
                    "ticket_id": {"type": "string", "description": "Ticket ID"},
                },
                "required": ["ticket_id"],
            },
        },
    },
    {
        "type": "function",
        "name": "search_kb",
        "function": {
            "name": "search_kb",
            "description": "Search knowledge base articles by keyword",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "name": "check_service_status",
        "function": {
            "name": "check_service_status",
            "description": "Check the current status of all IT services",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "name": "create_ticket",
        "function": {
            "name": "create_ticket",
            "description": "Create a new support ticket",
            "parameters": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string", "description": "Ticket subject"},
                    "description": {"type": "string", "description": "Detailed description of the issue"},
                    "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Ticket priority"},
                },
                "required": ["subject", "description"],
            },
        },
    },
]

SENSITIVE_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "name": "lookup_employee",
        "function": {
            "name": "lookup_employee",
            "description": "Look up an employee record by email address",
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {"type": "string", "description": "Employee email address"},
                },
                "required": ["email"],
            },
        },
    },
    {
        "type": "function",
        "name": "escalate_ticket",
        "function": {
            "name": "escalate_ticket",
            "description": "Escalate a ticket to Tier 2 on-call. Executes immediately without confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ticket_id": {"type": "string", "description": "Ticket ID to escalate"},
                    "user_id": {"type": "string", "description": "Requesting user ID"},
                    "reason": {"type": "string", "description": "Reason for escalation"},
                },
                "required": ["ticket_id", "user_id"],
            },
        },
    },
    {
        "type": "function",
        "name": "fetch_internal_doc",
        "function": {
            "name": "fetch_internal_doc",
            "description": "Retrieve an internal document by path",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Document path"},
                },
                "required": ["path"],
            },
        },
    },
]


def get_active_tools() -> list[dict]:
    """Get list of tool definitions that should be active for this session."""
    tools = list(TOOL_DEFINITIONS)

    # Add sensitive tools if their finding is active
    if is_finding_active("tool_schema_exposed"):
        tools.append(SENSITIVE_TOOL_DEFINITIONS[0])  # lookup_employee
        tools.append(SENSITIVE_TOOL_DEFINITIONS[2])  # fetch_internal_doc
    if is_finding_active("agent_tool_abuse"):
        tools.append(SENSITIVE_TOOL_DEFINITIONS[1])  # escalate_ticket

    return tools


def execute_tool(tool_name: str, arguments: dict) -> dict:
    """Execute a tool by name with given arguments."""
    tool_map = {
        "get_ticket": get_ticket,
        "search_kb": search_kb,
        "check_service_status": check_service_status,
        "create_ticket": create_ticket,
        "lookup_employee": lookup_employee,
        "escalate_ticket": escalate_ticket,
        "fetch_internal_doc": fetch_internal_doc,
        # Aliases used by agent.py MCP layer
        "get_ticket_status": get_ticket_status,
        "get_kb_article": get_kb_article,
        "lookup_user": lookup_user,
    }

    if tool_name not in tool_map:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        return tool_map[tool_name](**arguments)
    except Exception as e:
        return {"error": str(e), "tool": tool_name, "arguments": arguments}


def get_service_status() -> dict:
    """Return current service health data."""
    return {
        "services": SERVICES_STATUS,
        "overall": "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "note": "VPN gateway experiencing intermittent issues",
    }
