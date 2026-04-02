"""
app/checks/rag - RAG Suite

Retrieval-Augmented Generation reconnaissance checks.
Audits retrieval pipelines for poisoning, indirect injection,
data leakage, and embedding attacks.

Implemented checks:
  rag_discovery                - Detect RAG endpoints and vector store backends
  rag_indirect_injection       - Test for indirect prompt injection vulnerabilities
  rag_vector_store_access      - Probe vector store APIs for direct data access
  rag_auth_bypass              - Test vector store authentication bypass
  rag_collection_enumeration   - Enumerate collections and knowledge base structure
  rag_embedding_fingerprint    - Fingerprint the embedding model
  rag_document_exfiltration    - Probe for sensitive content extraction via queries
  rag_retrieval_manipulation   - Test client-side retrieval parameter override
  rag_source_attribution       - Analyze source citation reliability
  rag_cache_poisoning          - Detect RAG response caching
  rag_corpus_poisoning         - Test writable ingestion endpoints (corpus poisoning)
  rag_metadata_injection       - Test injection via document metadata fields
  rag_chunk_boundary           - Test chunk boundary exploitation
  rag_multimodal_injection     - Test injection via PDF metadata and filenames
  rag_fusion_reranker          - Detect re-ranking stages
  rag_cross_collection         - Test cross-collection retrieval isolation
  rag_adversarial_embedding    - Test adversarial queries exploiting embedding weaknesses

Supported vector stores:
  - Chroma
  - Pinecone
  - Weaviate
  - Qdrant
  - Milvus
  - pgvector
  - FAISS

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
from app.checks.rag.vector_store_access import RAGVectorStoreAccessCheck
from app.checks.rag.auth_bypass import RAGAuthBypassCheck
from app.checks.rag.collection_enumeration import RAGCollectionEnumerationCheck
from app.checks.rag.embedding_fingerprint import RAGEmbeddingFingerprintCheck
from app.checks.rag.document_exfiltration import RAGDocumentExfiltrationCheck
from app.checks.rag.retrieval_manipulation import RAGRetrievalManipulationCheck
from app.checks.rag.source_attribution import RAGSourceAttributionCheck
from app.checks.rag.cache_poisoning import RAGCachePoisoningCheck
from app.checks.rag.corpus_poisoning import RAGCorpusPoisoningCheck
from app.checks.rag.metadata_injection import RAGMetadataInjectionCheck
from app.checks.rag.chunk_boundary import RAGChunkBoundaryCheck
from app.checks.rag.multimodal_injection import RAGMultimodalInjectionCheck
from app.checks.rag.fusion_reranker import RAGFusionRerankerCheck
from app.checks.rag.cross_collection import RAGCrossCollectionCheck
from app.checks.rag.adversarial_embedding import RAGAdversarialEmbeddingCheck

__all__ = [
    "RAGDiscoveryCheck",
    "RAGIndirectInjectionCheck",
    "RAGVectorStoreAccessCheck",
    "RAGAuthBypassCheck",
    "RAGCollectionEnumerationCheck",
    "RAGEmbeddingFingerprintCheck",
    "RAGDocumentExfiltrationCheck",
    "RAGRetrievalManipulationCheck",
    "RAGSourceAttributionCheck",
    "RAGCachePoisoningCheck",
    "RAGCorpusPoisoningCheck",
    "RAGMetadataInjectionCheck",
    "RAGChunkBoundaryCheck",
    "RAGMultimodalInjectionCheck",
    "RAGFusionRerankerCheck",
    "RAGCrossCollectionCheck",
    "RAGAdversarialEmbeddingCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented RAG checks."""
    return [
        RAGDiscoveryCheck,
        RAGIndirectInjectionCheck,
        RAGVectorStoreAccessCheck,
        RAGAuthBypassCheck,
        RAGCollectionEnumerationCheck,
        RAGEmbeddingFingerprintCheck,
        RAGDocumentExfiltrationCheck,
        RAGRetrievalManipulationCheck,
        RAGSourceAttributionCheck,
        RAGCachePoisoningCheck,
        RAGCorpusPoisoningCheck,
        RAGMetadataInjectionCheck,
        RAGChunkBoundaryCheck,
        RAGMultimodalInjectionCheck,
        RAGFusionRerankerCheck,
        RAGCrossCollectionCheck,
        RAGAdversarialEmbeddingCheck,
    ]
