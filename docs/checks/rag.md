# RAG Suite

Retrieval-Augmented Generation system discovery and testing.

## rag_discovery

**Discover RAG endpoints and vector stores.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `rag_endpoints`, `vector_stores` |

Detects vector stores and RAG query endpoints:

| Vector Store | Detection Method |
|--------------|------------------|
| Chroma | `/api/v1/collections` |
| Pinecone | Headers, `/query` |
| Weaviate | `/v1/schema` |
| Qdrant | `/collections` |
| Milvus | `/v1/vector` |
| pgvector | SQL patterns |
| FAISS | Error signatures |

### RAG Indicators

- Response fields: `sources`, `chunks`, `documents`, `context`
- Headers: `x-embedding-model`, `x-vector-store`

### Findings

- **medium**: Vector store accessible (no auth)
- **medium**: RAG query endpoint found
- **info**: Vector store detected

---

## rag_indirect_injection

**Test RAG systems for indirect prompt injection.**

| Property | Value |
|----------|-------|
| Conditions | `rag_endpoints is truthy` |
| Produces | `indirect_injection_results`, `vulnerable_rag_endpoints` |

Tests whether malicious content in retrieved documents can influence LLM behavior.

### Attack Vectors

1. **Instruction Following**: Injected instructions in documents
2. **Context Extraction**: Leak system prompts via retrieval
3. **Delimiter Escape**: Break out of document context
4. **Data Exfiltration**: Enumerate internal documents

### Confidence Scoring

Analyzes response patterns:

| Pattern | Weight |
|---------|--------|
| `instruction_following:` | +0.3 |
| `context_leakage:` | +0.3 |
| `delimiter_escape:` | +0.2 |
| Payload echoed | +0.2 |

### Findings

- **high**: Indirect injection successful (>0.6 confidence)
- **medium**: Possible injection (0.3-0.6)
- **low**: Weak indicators

### Example Output

```yaml
vulnerable_rag_endpoints:
  - endpoint:
      url: "http://rag.example.com/query"
    successful_tests:
      - payload_id: context_extraction
        confidence: 0.85
      - payload_id: delimiter_escape
        confidence: 0.68
```

### References

- [Indirect Prompt Injection (arXiv:2402.16893)](https://arxiv.org/abs/2402.16893)
- [OWASP LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
