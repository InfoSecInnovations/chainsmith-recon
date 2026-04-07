"""
app/scenario_services/ai - AI infrastructure service templates.

Services:
- mcp_server: Model Context Protocol server
- agent: AI agent orchestration
- rag: Retrieval-Augmented Generation module
- vector_db: Vector database / embedding store
- ml_serving: ML model serving endpoint

These services simulate AI infrastructure components commonly found in
enterprise AI deployments, with configurable security observations.
"""

__all__ = [
    "mcp_server",
    "agent",
    "rag",
    "vector_db",
    "ml_serving",
]
