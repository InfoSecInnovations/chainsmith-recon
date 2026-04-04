# RAG Suite

Retrieval-Augmented Generation pipeline discovery, vector store analysis, and injection testing.
17 checks organized in 5 phases by dependency order.

---

## Phase 1 — Discovery (depends on services)

### rag_discovery

**Detect RAG pipeline endpoints and vector store backends.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `rag_endpoints`, `vector_stores` |

Probes common RAG paths (/query, /search, /retrieve, /ask, /chat, /rag, /documents, /knowledge, /embeddings, /invoke). Detects vector stores: Chroma, Pinecone, Weaviate, Qdrant, Milvus, pgvector, FAISS. Identifies RAG indicators in responses (sources, citations, chunks, similarity scores).

#### Findings

- **medium**: Vector store accessible (no auth)
- **medium**: RAG query endpoint found
- **info**: Vector store detected (auth required)

---

## Phase 2 — Vector Store Analysis (depends on vector_stores / rag_endpoints)

### rag_vector_store_access

**Probe vector store APIs for direct data access.**

| Property | Value |
|----------|-------|
| Conditions | `vector_stores is truthy` |
| Produces | `accessible_stores`, `vector_store_collections` |

Per-store probes for collection listing, document enumeration, arbitrary queries. Store-specific: Chroma (list_collections, dump_documents), Qdrant (collection_info, enumerate_points), Weaviate (full_schema, GraphQL), Pinecone (index_stats, list_vectors), Milvus (entity_query).

#### Findings

- **critical**: Full document dump or point enumeration accessible
- **high**: Arbitrary query/search/GraphQL accessible
- **medium**: Collection listing/info accessible
- **low**: Partial access or auth required but endpoint exists

---

### rag_auth_bypass

**Test vector store authentication bypass with default credentials.**

| Property | Value |
|----------|-------|
| Conditions | `vector_stores is truthy` |
| Produces | `auth_bypass_results` |

Tests per-store default credentials (Chroma: empty token; Qdrant: "qdrant", "default"; Weaviate: anonymous Bearer; Pinecone: empty key). Also tests IP-based bypass headers (X-Forwarded-For, X-Real-IP) and common auth headers. Intrusive check.

#### Findings

- **critical**: Vector store requires no authentication
- **high**: Default credential or common header bypasses auth
- **medium**: IP-based header bypass accepted
- **info**: Authentication properly enforced

---

### rag_collection_enumeration

**Enumerate vector store collections and knowledge base structure.**

| Property | Value |
|----------|-------|
| Conditions | `accessible_stores is truthy` |
| Produces | `knowledge_base_structure` |

Enumerates up to 10 collections per store with per-store methods. Flags sensitive collection names (hr, payroll, credential, password, secret, pii, customer, employee, financial, confidential, medical, hipaa, ssn).

#### Findings

- **high**: Large number of collections or documents with sensitive names
- **medium**: Collections detected without sensitive indicators
- **info**: Collections enumerated, no sensitive indicators

---

### rag_embedding_fingerprint

**Fingerprint the RAG embedding model via dimensionality and metadata.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `embedding_model` |

Probes embedding endpoints and vector store configs. Maps dimensions to models: 1536 = OpenAI ada-002, 3072 = text-embedding-3-large, 768 = BERT/RoBERTa, 384 = MiniLM, 1024 = Cohere/e5-large, etc.

#### Findings

- **low**: Embedding model identified with dimensions
- **info**: Model not identified

---

## Phase 3 — Read-Only Probing (depends on Phase 1-2)

### rag_indirect_injection

**Test RAG endpoints for indirect prompt injection vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `indirect_injection_results`, `vulnerable_rag_endpoints` |

Tests payloads: instruction_echo, context_extraction, delimiter_escape. Analyzes responses for instruction following, context leakage, role confusion, and delimiter escape patterns. Confidence-based scoring. Intrusive check.

#### Findings

- **high**: Indirect injection successful (confidence > 0.6)
- **medium**: Possible injection (confidence 0.3-0.6)
- **low**: Weak indicators (partial matches)

---

### rag_document_exfiltration

**Probe for sensitive content extraction via RAG queries.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `sensitive_content_categories` |

Two-phase approach: broad discovery queries then targeted sensitive queries (credentials, PII, API keys, infrastructure, financial). Detects email, phone, SSN, api_key, password, bearer_token, aws_key, private_key patterns. Also detects raw chunk metadata leakage. Intrusive check.

#### Findings

- **critical**: Credentials or PII detected in responses
- **high**: Internal infrastructure details detected
- **medium**: Raw document chunks with metadata
- **low**: No sensitive patterns detected

---

### rag_retrieval_manipulation

**Test for client-side retrieval parameter override.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `retrieval_control` |

Tests top_k parameter override with multiple names (top_k, k, n_results, limit, topK, num_results, max_results) and k values (1, 10, 50). Tests filter/where clause override with empty and null filters. Intrusive check.

#### Findings

- **high**: top_k parameter accepts client override
- **medium**: Filter/where clause parameters accepted from client
- **low**: top_k parameter bounded by server

---

### rag_source_attribution

**Analyze RAG source citation reliability and URL validation.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `citation_reliability` |

Submits citation-eliciting queries. Detects citation patterns (source references, year citations, URLs). Validates URLs against suspicious patterns (localhost, .test, .example, .local domains).

#### Findings

- **medium**: Suspicious URLs in citations (localhost, .example)
- **low**: Source attribution present (structured or unstructured)
- **info**: No source attribution in responses

---

### rag_cache_poisoning

**Detect RAG response caching and assess cache poisoning risk.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `rag_cache_behavior` |

Detects caching via cache headers, identical responses to repeated queries, and response timing analysis.

#### Findings

- **high**: Cache poisoning confirmed (caching + injection vulnerability + identical responses)
- **medium**: Caching detected with identical responses
- **low**: Cache headers present but responses vary
- **info**: No RAG-level caching detected

---

## Phase 4 — Write/Intrusive Probing (depends on Phase 2-3)

### rag_corpus_poisoning

**Test for writable document ingestion endpoints (corpus poisoning).**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `ingestion_endpoints` |

Probes ingestion paths (/documents, /ingest, /upload, /index, /add) and collection-scoped paths. Tries JSON and multipart upload formats with canary documents. Cleanup attempted after testing. Intrusive check.

#### Findings

- **critical**: Ingestion endpoint accepts unauthenticated writes
- **high**: Document ingestion accessible with write access (auth required)
- **medium**: Ingestion endpoint found but writes rejected

---

### rag_metadata_injection

**Test for injection via document metadata fields in RAG context.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `metadata_injection_results` |

Active test (with write capability): injects metadata with payloads and queries for retrieval. Passive test: analyzes existing responses for metadata field presence. Tests fields: source, author, title, category, permissions, tags, date, filename, url, description. Intrusive check.

#### Findings

- **high**: Metadata injection confirmed (LLM followed metadata instructions)
- **medium**: Metadata included in LLM context but not followed
- **info**: Metadata not accessible through RAG queries

---

### rag_chunk_boundary

**Test injection payload split across chunk boundaries.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` AND `ingestion_endpoints is truthy` |
| Produces | `chunk_boundary_results` |

Tests at multiple chunk sizes (256, 512, 1024 tokens). Splits injection payload across boundary with filler text. Injects document and queries to check if split payload reassembles in LLM context. Intrusive check.

#### Findings

- **high**: Chunk boundary bypass confirmed (split payload reassembled)
- **medium**: Both chunks retrieved but injection not confirmed
- **info**: Split payloads did not bypass filtering

---

### rag_multimodal_injection

**Test injection via PDF metadata, EXIF data, and filenames.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `multimodal_injection_results` |

Tests 3 vectors: PDF metadata injection (payload in Title field), crafted filename injection, and text file hidden instructions. Uploads via multipart and queries to detect processing. Intrusive check.

#### Findings

- **high**: Multimodal injection confirmed (indicator in response)
- **medium**: RAG accepts file uploads without content scanning
- **info**: RAG does not accept non-text inputs

---

## Phase 5 — Advanced (depends on Phase 3-4)

### rag_fusion_reranker

**Detect RAG re-ranking stages and injection amplification.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `reranker_info` |

Detects rerankers via response headers (x-reranker, x-fusion-score, x-cross-encoder). Analyzes score patterns with varying k values (1, 3, 10) to identify normalized scoring and high score spread.

#### Findings

- **low**: Re-ranking detected via headers
- **info**: Re-ranking inferred from score patterns or not detected

---

### rag_cross_collection

**Test cross-collection retrieval isolation.**

| Property | Value |
|----------|-------|
| Conditions | `knowledge_base_structure is truthy` |
| Produces | `cross_collection_results` |

Requires at least 2 collections. Tests isolation via direct vector store scoped queries and RAG query endpoint with collection parameter. Checks if one collection's query returns another's data.

#### Findings

- **critical**: Cross-collection retrieval confirmed (multiple violations)
- **high**: Single isolation violation
- **info**: Collection isolation enforced

---

### rag_adversarial_embedding

**Test adversarial queries that exploit embedding weaknesses.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `adversarial_embedding_results` |

Three keyword-based techniques (no GPU required): keyword stuffing (sensitive terms), semantic mismatch (public topic steered toward sensitive content), and embedding collision (special chars, template syntax). Compares baseline vs. adversarial retrieval results. Intrusive check.

#### Findings

- **high**: Adversarial embedding successful (>50% new docs)
- **medium**: Adversarial embedding effective but weaker
- **info**: Adversarial queries did not force unexpected retrieval
