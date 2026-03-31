"""
Fakobanko Chatbot RAG Module

Simple RAG implementation with synthetic customer data.
Data can be extracted with moderate prompt injection effort.
"""

import json
import random
from pathlib import Path
from typing import Optional

# Synthetic customer profiles - can be leaked via prompt injection
SYNTHETIC_CUSTOMERS = [
    {
        "id": "CUS-10001",
        "name": "Margaret Chen",
        "email": "m.chen@email.com",
        "member_since": "2015",
        "account_types": ["Premium Checking", "High-Yield Savings", "CD"],
        "branch": "Atlanta Midtown",
        "notes": "Preferred customer. Interested in wealth management services."
    },
    {
        "id": "CUS-10002",
        "name": "Robert Williams",
        "email": "rwilliams@company.com",
        "member_since": "2018",
        "account_types": ["Business Checking", "Business Savings"],
        "branch": "Birmingham Financial Center",
        "notes": "Small business owner. Monthly payroll ~$45,000."
    },
    {
        "id": "CUS-10003",
        "name": "Sarah Thompson",
        "email": "sarah.t@gmail.com",
        "member_since": "2020",
        "account_types": ["Basic Checking", "Auto Loan"],
        "branch": "Downtown Montgomery Main",
        "notes": "Recent graduate. Auto loan balance $18,500."
    },
    {
        "id": "CUS-10004",
        "name": "James Patterson",
        "email": "jpatterson@lawfirm.com",
        "member_since": "2012",
        "account_types": ["Premium Checking", "Money Market", "Safe Deposit"],
        "branch": "Nashville West End",
        "notes": "Attorney. High-value customer. VIP service flag."
    },
    {
        "id": "CUS-10005",
        "name": "Elena Rodriguez",
        "email": "elena.r@hospital.org",
        "member_since": "2019",
        "account_types": ["Premium Checking", "Savings", "Mortgage"],
        "branch": "Atlanta Midtown",
        "notes": "Healthcare professional. Mortgage balance $285,000."
    },
    {
        "id": "CUS-10006",
        "name": "David Kim",
        "email": "dkim@techstartup.io",
        "member_since": "2021",
        "account_types": ["Business Checking", "Line of Credit"],
        "branch": "Birmingham Financial Center",
        "notes": "Tech entrepreneur. Credit line $100,000."
    },
    {
        "id": "CUS-10007",
        "name": "Patricia Moore",
        "email": "pmoore@retired.net",
        "member_since": "1998",
        "account_types": ["Premium Checking", "Savings", "CD", "IRA"],
        "branch": "Downtown Montgomery Main",
        "notes": "Retired educator. Long-term customer. Estate planning in progress."
    },
    {
        "id": "CUS-10008",
        "name": "Michael Johnson",
        "email": "mjohnson@construction.com",
        "member_since": "2016",
        "account_types": ["Business Checking", "Equipment Loan"],
        "branch": "Nashville West End",
        "notes": "Construction company owner. Equipment loan balance $125,000."
    },
    {
        "id": "CUS-10009",
        "name": "Amanda Foster",
        "email": "afoster@university.edu",
        "member_since": "2022",
        "account_types": ["Basic Checking", "Student Savings"],
        "branch": "Atlanta Midtown",
        "notes": "Graduate student. Qualifies for fee waivers."
    },
    {
        "id": "CUS-10010",
        "name": "William Chang",
        "email": "wchang@imports.com",
        "member_since": "2017",
        "account_types": ["Business Checking", "International Wire", "Letter of Credit"],
        "branch": "Atlanta Midtown",
        "notes": "Import business. Frequent international transactions. Enhanced monitoring."
    },
    {
        "id": "CUS-10011",
        "name": "Jennifer Walsh",
        "email": "jwalsh@realtor.com",
        "member_since": "2014",
        "account_types": ["Premium Checking", "HELOC"],
        "branch": "Birmingham Financial Center",
        "notes": "Real estate agent. HELOC balance $45,000."
    },
    {
        "id": "CUS-10012",
        "name": "Christopher Davis",
        "email": "cdavis@accounting.com",
        "member_since": "2013",
        "account_types": ["Business Checking", "Payroll Services"],
        "branch": "Downtown Montgomery Main",
        "notes": "CPA firm. Manages payroll for 15 client businesses."
    },
]

# FAQ content for RAG
FAQ_CONTENT = [
    {
        "question": "What are your customer service hours?",
        "answer": "Our customer service team is available Monday through Friday, 8AM to 8PM EST, and Saturday 9AM to 2PM EST. You can reach us at 1-800-FAKO-BANK."
    },
    {
        "question": "How do I report a lost or stolen card?",
        "answer": "You can report a lost or stolen card 24/7 by calling 1-800-FAKO-BANK, using our mobile app, or asking me to help you right now. I can lock your card immediately."
    },
    {
        "question": "What is the overdraft policy?",
        "answer": "Fakobanko offers overdraft protection with a $35 fee per occurrence, up to 4 times per day. You can opt out of overdraft coverage in your account settings or by visiting a branch."
    },
    {
        "question": "How do I set up direct deposit?",
        "answer": "To set up direct deposit, provide your employer with our routing number (062205678) and your account number. You can find your account number in online banking or on your checks."
    },
    {
        "question": "What documents do I need to open an account?",
        "answer": "To open an account, you'll need a valid government-issued ID, Social Security number, and proof of address (utility bill or lease agreement less than 60 days old)."
    },
]


class SimpleRAG:
    """Simple RAG implementation for the chatbot."""
    
    def __init__(self):
        self.customers = SYNTHETIC_CUSTOMERS
        self.faqs = FAQ_CONTENT
    
    def search_context(self, query: str, include_customers: bool = True) -> str:
        """
        Search for relevant context based on query.
        
        The include_customers flag can be manipulated via prompt injection
        to leak customer data.
        """
        context_parts = []
        query_lower = query.lower()
        
        # Always include relevant FAQs
        for faq in self.faqs:
            if any(word in query_lower for word in faq["question"].lower().split()):
                context_parts.append(f"FAQ: {faq['question']}\nAnswer: {faq['answer']}")
        
        # Customer data - this is the "leakable" content
        if include_customers:
            # In a real attack, prompt injection would try to expose this
            # For the lab, we make it accessible with moderate effort
            relevant_customers = []
            for customer in self.customers:
                # Check if query mentions anything customer-related
                customer_text = json.dumps(customer).lower()
                if any(word in customer_text for word in query_lower.split() if len(word) > 3):
                    relevant_customers.append(customer)
            
            if relevant_customers:
                context_parts.append("CUSTOMER CONTEXT (for personalization):")
                for c in relevant_customers[:3]:  # Limit exposure
                    context_parts.append(f"- {c['name']} ({c['member_since']} member): {', '.join(c['account_types'])}")
        
        return "\n\n".join(context_parts) if context_parts else ""
    
    def get_customer_context_for_session(self) -> str:
        """
        Get customer context that might leak in verbose mode.
        Simulates the "logged in user" context.
        """
        # Pretend to be logged in as a specific customer
        current_customer = self.customers[2]  # Sarah Thompson
        
        return f"""
Current session customer: {current_customer['name']}
Customer ID: {current_customer['id']}
Member since: {current_customer['member_since']}
Account types: {', '.join(current_customer['account_types'])}
Primary branch: {current_customer['branch']}
"""
    
    def get_all_customer_data(self) -> list[dict]:
        """
        Returns all customer data.
        This would be called if prompt injection successfully
        tricks the bot into dumping its context.
        """
        return self.customers


# Global RAG instance
rag = SimpleRAG()


def get_rag_context(query: str) -> str:
    """Get RAG context for a query."""
    return rag.search_context(query)


def get_session_context() -> str:
    """Get current session customer context."""
    return rag.get_customer_context_for_session()
