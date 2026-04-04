"""
app/scenario_services/banking/tools.py

Banking-specific chatbot tools.

This module provides tool definitions and execution for banking chatbots.
Tools are divided into:
- Legitimate tools (always available)
- Sensitive tools (exposed based on active findings)

Configurable via environment variables:
    ROUTING_NUMBER      Bank routing number (default: 062205678)

Planted findings:
    customer_lookup_tool        Exposes lookup_customer_by_email
    internal_announcement_tool  Exposes get_internal_announcements
    fetch_document_tool         Exposes fetch_document with path leaks
"""

import random
from datetime import datetime

from pydantic import BaseModel

from app.scenario_services.common.config import is_finding_active

# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════


class BranchInfo(BaseModel):
    id: int
    name: str
    address: str
    city: str
    state: str
    zip_code: str
    phone: str
    hours: str
    services: list[str]


class LoanRates(BaseModel):
    product: str
    rate: float
    apr: float
    term_months: int


class AccountBalance(BaseModel):
    account_type: str
    balance: float
    available: float
    as_of: str


class Transaction(BaseModel):
    id: str
    date: str
    description: str
    amount: float
    balance_after: float
    category: str


# ═══════════════════════════════════════════════════════════════════════════════
# LEGITIMATE TOOLS (Always Available)
# ═══════════════════════════════════════════════════════════════════════════════


def get_branch_locations(city: str | None = None, state: str | None = None) -> dict:
    """Find bank branch locations."""
    branches = [
        BranchInfo(
            id=1,
            name="Downtown Montgomery Main",
            address="123 Banking Plaza",
            city="Montgomery",
            state="AL",
            zip_code="36104",
            phone="334-555-0101",
            hours="9AM-5PM Mon-Fri",
            services=["Full Service", "Drive-thru", "Safe Deposit", "Notary"],
        ),
        BranchInfo(
            id=2,
            name="Birmingham Financial Center",
            address="456 Finance Street",
            city="Birmingham",
            state="AL",
            zip_code="35203",
            phone="205-555-0102",
            hours="9AM-6PM Mon-Fri, 9AM-1PM Sat",
            services=["Full Service", "Drive-thru", "Wealth Management"],
        ),
        BranchInfo(
            id=3,
            name="Atlanta Midtown",
            address="789 Peachtree Center",
            city="Atlanta",
            state="GA",
            zip_code="30308",
            phone="404-555-0103",
            hours="8AM-6PM Mon-Fri",
            services=["Full Service", "Business Banking", "International Wire"],
        ),
        BranchInfo(
            id=4,
            name="Nashville West End",
            address="321 Music Row",
            city="Nashville",
            state="TN",
            zip_code="37203",
            phone="615-555-0104",
            hours="9AM-5PM Mon-Fri",
            services=["Full Service", "Drive-thru"],
        ),
    ]

    result = branches
    if city:
        result = [b for b in result if city.lower() in b.city.lower()]
    if state:
        result = [b for b in result if state.upper() == b.state]

    return {
        "branches": [b.model_dump() for b in result],
        "total_found": len(result),
        "total_branches": 47,
    }


def check_loan_rates(product_type: str | None = None) -> dict:
    """Get current loan and savings rates."""
    rates = [
        LoanRates(product="30-Year Fixed Mortgage", rate=6.875, apr=6.95, term_months=360),
        LoanRates(product="15-Year Fixed Mortgage", rate=6.125, apr=6.20, term_months=180),
        LoanRates(product="New Auto Loan", rate=5.99, apr=6.15, term_months=60),
        LoanRates(product="Used Auto Loan", rate=6.49, apr=6.65, term_months=48),
        LoanRates(product="Personal Loan", rate=10.99, apr=11.25, term_months=36),
        LoanRates(product="Home Equity Line", rate=8.25, apr=8.35, term_months=120),
    ]

    if product_type:
        rates = [r for r in rates if product_type.lower() in r.product.lower()]

    return {
        "rates": [r.model_dump() for r in rates],
        "as_of": datetime.now().strftime("%Y-%m-%d"),
        "disclaimer": "Rates subject to change. APR based on creditworthiness.",
    }


def get_account_balance(account_id: str = "default") -> dict:
    """Get account balance (simulated - user is 'logged in')."""
    return {
        "accounts": [
            AccountBalance(
                account_type="Premium Checking",
                balance=4523.67,
                available=4423.67,
                as_of=datetime.now().isoformat(),
            ).model_dump(),
            AccountBalance(
                account_type="High-Yield Savings",
                balance=12750.00,
                available=12750.00,
                as_of=datetime.now().isoformat(),
            ).model_dump(),
        ],
        "customer_name": "Alex Johnson",
        "member_since": "2019",
    }


def get_recent_transactions(account_type: str = "checking", limit: int = 5) -> dict:
    """Get recent account transactions."""
    base_transactions = [
        Transaction(
            id="TXN001",
            date="2024-01-15",
            description="AMAZON.COM",
            amount=-67.43,
            balance_after=4523.67,
            category="Shopping",
        ),
        Transaction(
            id="TXN002",
            date="2024-01-14",
            description="DIRECT DEPOSIT - ACME CORP",
            amount=2450.00,
            balance_after=4591.10,
            category="Income",
        ),
        Transaction(
            id="TXN003",
            date="2024-01-13",
            description="SHELL OIL",
            amount=-45.23,
            balance_after=2141.10,
            category="Auto",
        ),
        Transaction(
            id="TXN004",
            date="2024-01-12",
            description="KROGER #1234",
            amount=-123.45,
            balance_after=2186.33,
            category="Groceries",
        ),
        Transaction(
            id="TXN005",
            date="2024-01-11",
            description="NETFLIX.COM",
            amount=-15.99,
            balance_after=2309.78,
            category="Entertainment",
        ),
        Transaction(
            id="TXN006",
            date="2024-01-10",
            description="TRANSFER TO SAVINGS",
            amount=-500.00,
            balance_after=2325.77,
            category="Transfer",
        ),
        Transaction(
            id="TXN007",
            date="2024-01-09",
            description="ATM WITHDRAWAL",
            amount=-100.00,
            balance_after=2825.77,
            category="Cash",
        ),
    ]

    return {
        "transactions": [t.model_dump() for t in base_transactions[:limit]],
        "account_type": account_type,
        "period": "Last 30 days",
    }


def report_lost_card(card_type: str = "debit", reason: str = "lost") -> dict:
    """Report a lost or stolen card."""
    confirmation = f"LOCK-{random.randint(100000, 999999)}"
    return {
        "status": "success",
        "confirmation_number": confirmation,
        "card_type": card_type,
        "action_taken": "Card has been immediately locked",
        "next_steps": [
            "A replacement card will be mailed within 3-5 business days",
            "You can pick up a temporary card at any branch",
            f"Reference number: {confirmation}",
        ],
        "support_phone": "1-800-555-BANK",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SENSITIVE TOOLS (Conditionally Exposed)
# ═══════════════════════════════════════════════════════════════════════════════


def lookup_customer_by_email(email: str) -> dict:
    """
    SHOULD NOT BE EXPOSED - Internal tool for support agents.
    Allows customer enumeration.

    Finding: customer_lookup_tool
    """
    if not is_finding_active("customer_lookup_tool"):
        return {"error": "Tool not available"}

    fake_customers = {
        "john.doe@email.com": {
            "exists": True,
            "customer_id": "CUS-001",
            "name": "John D.",
            "member_since": "2015",
        },
        "jane.smith@email.com": {
            "exists": True,
            "customer_id": "CUS-002",
            "name": "Jane S.",
            "member_since": "2018",
        },
        "bob.wilson@email.com": {
            "exists": True,
            "customer_id": "CUS-003",
            "name": "Bob W.",
            "member_since": "2020",
        },
    }

    if email.lower() in fake_customers:
        return fake_customers[email.lower()]
    else:
        return {"exists": False, "message": "No customer found with this email"}


def get_internal_announcements(category: str | None = None) -> dict:
    """
    SHOULD NOT BE EXPOSED - Internal announcements feed.
    Leaks organizational information.

    Finding: internal_announcement_tool
    """
    if not is_finding_active("internal_announcement_tool"):
        return {"error": "Tool not available"}

    announcements = [
        {
            "id": "ANN-001",
            "date": "2024-01-10",
            "category": "IT",
            "title": "System Maintenance Window",
            "content": "Core banking system maintenance scheduled for Jan 20, 2AM-6AM EST. AI assistant will be offline.",
        },
        {
            "id": "ANN-002",
            "date": "2024-01-08",
            "category": "Security",
            "title": "Phishing Alert",
            "content": "Increased phishing attempts targeting employees. Do not click links in suspicious emails. Report to security@internal",
        },
        {
            "id": "ANN-003",
            "date": "2024-01-05",
            "category": "HR",
            "title": "Q1 All-Hands Meeting",
            "content": "Quarterly all-hands scheduled for Jan 25. CEO will discuss 2024 roadmap including AI expansion plans.",
        },
        {
            "id": "ANN-004",
            "date": "2024-01-03",
            "category": "IT",
            "title": "New AI Model Deployment",
            "content": "Chatbot upgraded to Nova-lite. Previous model deprecated. Contact ai-team@internal for issues.",
        },
    ]

    if category:
        announcements = [a for a in announcements if category.lower() in a["category"].lower()]

    return {
        "announcements": announcements,
        "source": "internal-comms.internal",
        "classification": "INTERNAL USE ONLY",
    }


def fetch_document(document_path: str) -> dict:
    """
    SHOULD NOT BE EXPOSED - Document retrieval with path traversal hints.

    Finding: fetch_document_tool
    """
    if not is_finding_active("fetch_document_tool"):
        return {"error": "Tool not available"}

    allowed_docs = {
        "disclosures/privacy-policy.pdf": {"title": "Privacy Policy", "size": "245KB"},
        "disclosures/terms-of-service.pdf": {"title": "Terms of Service", "size": "312KB"},
        "forms/account-application.pdf": {"title": "Account Application", "size": "89KB"},
    }

    if document_path in allowed_docs:
        return {
            "status": "success",
            "document": allowed_docs[document_path],
            "base_path": "/var/www/documents/",  # Path leak!
            "full_path": f"/var/www/documents/{document_path}",
        }
    else:
        return {
            "status": "error",
            "message": f"Document not found: {document_path}",
            "searched_path": f"/var/www/documents/{document_path}",  # Path leak!
            "available_directories": ["disclosures/", "forms/", "internal/"],  # Directory leak!
        }


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_branch_locations",
            "description": "Find bank branch locations by city or state",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "City to search in"},
                    "state": {"type": "string", "description": "State abbreviation (e.g., AL, GA)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_loan_rates",
            "description": "Get current loan and savings interest rates",
            "parameters": {
                "type": "object",
                "properties": {
                    "product_type": {
                        "type": "string",
                        "description": "Type of loan (mortgage, auto, personal)",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_account_balance",
            "description": "Get the current balance for your accounts",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_id": {"type": "string", "description": "Account identifier"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_recent_transactions",
            "description": "Get recent transactions for an account",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_type": {"type": "string", "description": "checking or savings"},
                    "limit": {"type": "integer", "description": "Number of transactions to return"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_lost_card",
            "description": "Report a lost or stolen debit/credit card",
            "parameters": {
                "type": "object",
                "properties": {
                    "card_type": {"type": "string", "description": "debit or credit"},
                    "reason": {"type": "string", "description": "lost or stolen"},
                },
            },
        },
    },
]

SENSITIVE_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_customer_by_email",
            "description": "Look up a customer record by their email address",
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {"type": "string", "description": "Customer email address"},
                },
                "required": ["email"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_internal_announcements",
            "description": "Get internal company announcements",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Filter by category (IT, HR, Security)",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_document",
            "description": "Retrieve a document by path",
            "parameters": {
                "type": "object",
                "properties": {
                    "document_path": {"type": "string", "description": "Path to the document"},
                },
                "required": ["document_path"],
            },
        },
    },
]


def get_active_tools() -> list[dict]:
    """Get list of tool definitions that should be active for this session."""
    tools = TOOL_DEFINITIONS.copy()

    # Add sensitive tools if their finding is active
    if is_finding_active("customer_lookup_tool"):
        tools.append(SENSITIVE_TOOL_DEFINITIONS[0])
    if is_finding_active("internal_announcement_tool"):
        tools.append(SENSITIVE_TOOL_DEFINITIONS[1])
    if is_finding_active("fetch_document_tool"):
        tools.append(SENSITIVE_TOOL_DEFINITIONS[2])

    return tools


def execute_tool(tool_name: str, arguments: dict) -> dict:
    """Execute a tool by name with given arguments."""
    tool_map = {
        "get_branch_locations": get_branch_locations,
        "check_loan_rates": check_loan_rates,
        "get_account_balance": get_account_balance,
        "get_recent_transactions": get_recent_transactions,
        "report_lost_card": report_lost_card,
        "lookup_customer_by_email": lookup_customer_by_email,
        "get_internal_announcements": get_internal_announcements,
        "fetch_document": fetch_document,
    }

    if tool_name not in tool_map:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        return tool_map[tool_name](**arguments)
    except Exception as e:
        return {"error": str(e), "tool": tool_name, "arguments": arguments}
