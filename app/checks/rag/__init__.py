"""
app/checks/rag - RAG Suite

Retrieval-Augmented Generation reconnaissance checks.
Audits retrieval pipelines for poisoning, indirect injection,
data leakage, and embedding attacks.

Implemented checks:
  rag_discovery             - Detect RAG endpoints and vector store backends
  rag_indirect_injection    - Test for indirect prompt injection vulnerabilities

Supported vector stores:
  - Chroma
  - Pinecone
  - Weaviate
  - Qdrant
  - Milvus
  - pgvector
  - FAISS

Backlog checks:
  rag_document_exfiltration - Probe whether stored documents can be extracted
  rag_source_attribution    - Test citation/source tracking accuracy
  rag_retrieval_poisoning   - Poison the retrieval corpus with crafted content
  rag_embedding_probe       - Fingerprint embedding model via similarity queries
  rag_chunking_abuse        - Exploit chunking boundaries to split injection payloads
  rag_metadata_leak         - Extract document metadata via crafted queries
  rag_context_overflow      - Overflow retrieval context to displace system prompt
  rag_reranker_manipulation - Manipulate reranker scores via adversarial content
  rag_multimodal_injection  - Inject via images or PDFs fed into multimodal RAG
  rag_query_reconstruction  - Reconstruct original queries from embedding distances

Chain patterns:
  rag_indirect_to_tool_call    - Indirect injection -> tool execution
  rag_poison_to_exfil          - Corpus poisoning -> data exfiltration via LLM
  rag_embedding_fingerprint    - Embedding probe -> model identification -> targeted attack
  rag_context_displacement     - Overflow -> system prompt displacement -> jailbreak
  rag_multimodal_pivot         - Multimodal injection -> text context poisoning

References:
  https://arxiv.org/abs/2402.16893  (Indirect Prompt Injection)
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://atlas.mitre.org/
"""

from app.checks.base import BaseCheck
from app.checks.rag.discovery import RAGDiscoveryCheck
from app.checks.rag.indirect_injection import RAGIndirectInjectionCheck

__all__ = [
    "RAGDiscoveryCheck",
    "RAGIndirectInjectionCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented RAG checks."""
    return [
        RAGDiscoveryCheck,
        RAGIndirectInjectionCheck,
    ]
