"""
Fakobanko Chatbot Service

AI-powered customer assistant.
This is a thin wrapper that imports from the original chatbot.py.
"""

# Import the app from the original location for backward compatibility
from fakobanko.chatbot import app

__all__ = ["app"]
