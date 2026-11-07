"""
app/scenario_services/ai/ml_serving.py

ML model serving service template.

This service simulates an ML model serving endpoint (similar to vLLM, TGI, etc.)
with embeddings and completions APIs. It includes configurable security observations.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    ML_VERSION          Service version (default: 2.1.0)
    MODEL_ID            Model identifier (default: <brand>-llm-v2)

Planted observations:
    framework_fingerprint       X-Serving-Engine and X-Model-Backend headers
    model_version_leak          X-Model-Version header
    model_info_endpoint         /v1/models returns detailed model info
    model_config_exposed        /debug/config and training config visible
    embedding_endpoint_exposed  Embedding endpoint with debug info
    no_rate_limit               No rate limiting on embeddings
    bulk_query_allowed          Bulk embedding queries allowed
    no_session_isolation        Semantic cache serves one session's answers to another
    cache_timing_leak           Semantic cache hits are measurably faster than misses

Also serves an ungated semantic cache (lab backport 2d): GET/POST /semantic-cache,
GET /cache/stats. See the SEMANTIC CACHE section.

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.ai.ml_serving:app
      --host 0.0.0.0 --port 8084
    environment:
      - BRAND_NAME=Fakobanko
      - MODEL_ID=fakobanko-llm-v2
"""

import asyncio
import os
import random
import re
import time
from collections import OrderedDict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.scenario_services.common.config import (
    get_brand_name,
    get_or_create_session,
    is_observation_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

ML_VERSION = os.getenv("ML_VERSION", "2.1.0")


def _get_model_id() -> str:
    if model_id := os.getenv("MODEL_ID"):
        return model_id
    brand = get_brand_name().lower().replace(" ", "-")
    return f"{brand}-llm-v2"


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="ML Service",
    description="Internal ML model serving",
    version=ML_VERSION,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════


class EmbeddingRequest(BaseModel):
    text: str | list[str]
    model: str | None = None


class InferenceRequest(BaseModel):
    prompt: str
    max_tokens: int | None = 256
    temperature: float | None = 0.7


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active observations."""
    response = await call_next(request)

    # Observation: framework_fingerprint - leak serving infrastructure
    if is_observation_active("framework_fingerprint"):
        response.headers["X-Serving-Engine"] = "vLLM/0.4.1"
        response.headers["X-Model-Backend"] = "transformers"

    # Observation: model_version_leak - leak model version
    if is_observation_active("model_version_leak"):
        model_id = _get_model_id()
        response.headers["X-Model-Version"] = f"{model_id}-v2.3.1-ft"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/")
async def root():
    """Service info endpoint."""
    brand = get_brand_name()
    return {
        "service": f"{brand} ML Service",
        "version": ML_VERSION,
        "endpoints": ["/v1/models", "/v1/embeddings", "/v1/completions", "/semantic-cache"],
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "status": "healthy",
        "service": f"{brand}-ml",
        "session_id": session.session_id,
    }


@app.get("/v1/models")
async def list_models():
    """
    Model listing endpoint.

    Observation: model_info_endpoint
    When active, returns detailed model information.

    Observation: model_config_exposed
    When active, includes training configuration.
    """
    model_id = _get_model_id()
    brand = get_brand_name().lower().replace(" ", "-")

    models = [
        {
            "id": model_id,
            "object": "model",
            "owned_by": brand,
        }
    ]

    # Observation: model_info_endpoint - leak detailed model info
    if is_observation_active("model_info_endpoint"):
        models[0].update(
            {
                "architecture": "llama-7b-hf",
                "quantization": "awq-4bit",
                "max_context": 4096,
                "fine_tuned": True,
                "base_model": "meta-llama/Llama-2-7b-hf",
            }
        )

    # Observation: model_config_exposed - leak training config
    if is_observation_active("model_config_exposed"):
        models[0]["training_config"] = {
            "dataset": f"s3://{brand}-ml/training/customer-interactions-2024/",
            "epochs": 3,
            "learning_rate": 2e-5,
        }

    return {"data": models, "object": "list"}


@app.post("/v1/embeddings")
async def create_embedding(request: EmbeddingRequest):
    """
    Embedding endpoint.

    Observation: no_rate_limit
    When not active, limits to 10 texts per request.

    Observation: bulk_query_allowed
    When not active, prevents bulk queries.

    Observation: embedding_endpoint_exposed
    When active, includes debug info in response.
    """
    model_id = request.model or f"{_get_model_id()}-embed-v1"
    texts = request.text if isinstance(request.text, list) else [request.text]

    # Check rate limiting
    if not is_observation_active("no_rate_limit") and len(texts) > 10:
        raise HTTPException(429, "Rate limit exceeded: max 10 texts per request")

    # Check bulk query
    if not is_observation_active("bulk_query_allowed") and len(texts) > 1:
        raise HTTPException(400, "Bulk queries not allowed")

    # Generate fake embeddings (384-dimensional)
    embeddings = [[random.uniform(-1, 1) for _ in range(384)] for _ in texts]

    response = {
        "embeddings": embeddings,
        "model": model_id,
        "usage": {
            "prompt_tokens": sum(len(t.split()) for t in texts),
            "total_tokens": sum(len(t.split()) for t in texts),
        },
    }

    # Observation: embedding_endpoint_exposed - include debug info
    if is_observation_active("embedding_endpoint_exposed"):
        response["_debug"] = {
            "model_path": f"/models/{_get_model_id()}-embed-v1",
            "dimension": 384,
            "normalize": True,
        }

    return response


@app.post("/v1/completions")
async def create_completion(request: InferenceRequest):
    """Completion endpoint."""
    model_id = _get_model_id()

    return {
        "id": "cmpl-" + os.urandom(8).hex(),
        "object": "text_completion",
        "model": model_id,
        "choices": [
            {
                "text": "I'm a simulated ML model response.",
                "index": 0,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": len(request.prompt.split()),
            "completion_tokens": 8,
            "total_tokens": len(request.prompt.split()) + 8,
        },
    }


@app.get("/debug/config")
async def debug_config():
    """
    Debug config endpoint.

    Observation: model_config_exposed
    Only available when this observation is active.
    """
    if not is_observation_active("model_config_exposed"):
        raise HTTPException(404, "Not found")

    model_id = _get_model_id()
    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "model_id": model_id,
        "serving_config": {
            "gpu_memory_utilization": 0.9,
            "tensor_parallel_size": 1,
            "max_num_seqs": 256,
        },
        "inference_config": {
            "temperature": 0.7,
            "top_p": 0.9,
            "max_tokens": 2048,
        },
        "endpoints": {
            "internal_metrics": f"http://ml.{brand}.local:9090/metrics",
            "model_store": f"s3://{brand}-ml/models/",
        },
    }


@app.get("/metrics")
async def metrics():
    """
    Prometheus-style metrics endpoint.

    Observation: model_config_exposed
    Only available when this observation is active.
    """
    if not is_observation_active("model_config_exposed"):
        raise HTTPException(404, "Not found")

    model_id = _get_model_id()

    # Return fake Prometheus metrics
    metrics_text = f"""# HELP ml_requests_total Total number of requests
# TYPE ml_requests_total counter
ml_requests_total{{model="{model_id}",endpoint="completions"}} 12453
ml_requests_total{{model="{model_id}",endpoint="embeddings"}} 45231

# HELP ml_inference_seconds Inference latency
# TYPE ml_inference_seconds histogram
ml_inference_seconds_bucket{{model="{model_id}",le="0.1"}} 8234
ml_inference_seconds_bucket{{model="{model_id}",le="0.5"}} 11456
ml_inference_seconds_bucket{{model="{model_id}",le="1.0"}} 12100
ml_inference_seconds_bucket{{model="{model_id}",le="+Inf"}} 12453

# HELP ml_gpu_memory_bytes GPU memory usage
# TYPE ml_gpu_memory_bytes gauge
ml_gpu_memory_bytes{{device="0"}} 15032385536
"""

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(metrics_text, media_type="text/plain")


# ═══════════════════════════════════════════════════════════════════════════════
# SEMANTIC CACHE (CAG)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Lab backport 2d: a small token-overlap "semantic" cache in front of the
# completion model, so the CAG suite has something real to probe. Phase 46 asked
# for a separate container; this lives on `ml` instead (alias
# `cache.fakobanko.local`), as the lab did.
#
#   Ungated (discoverable on every session):
#     GET  /semantic-cache   cache info, `X-Semantic-Cache` header
#     GET  /cache/stats      entry count, hit rate, ttl
#     POST /semantic-cache   {input, query} -> cached or freshly "generated" answer
#
#   Planted observations:
#     no_session_isolation   lookups ignore `X-Session-Id`, so one session's
#                            cached answer is served to another
#     cache_timing_leak      hits return immediately while misses take the
#                            "generation" time; when inactive, hits are padded
#                            to the same latency

CACHE_SIMILARITY_THRESHOLD = 0.5
CACHE_MAX_ENTRIES = 500
CACHE_TTL_SECONDS = 3600
_GENERATION_SECONDS = 0.25
_SHARED_SESSION = "shared"

_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "do",
        "does",
        "for",
        "from",
        "how",
        "i",
        "in",
        "is",
        "it",
        "me",
        "my",
        "of",
        "on",
        "or",
        "our",
        "please",
        "tell",
        "the",
        "this",
        "to",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "with",
        "you",
        "your",
    ]
)


def _tokens(text: str) -> frozenset[str]:
    return frozenset(t for t in re.findall(r"[a-z0-9_]+", text.lower()) if t not in _STOPWORDS)


def _similarity(a: frozenset[str], b: frozenset[str]) -> float:
    """Overlap coefficient: shared tokens over the smaller set.

    Deliberately loose, as real semantic caches tuned for hit rate are. A short
    query that shares one keyword with a cached prompt can hit.
    """
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


class CacheQuery(BaseModel):
    input: str | None = None
    query: str | None = None


# key -> {"session": str, "prompt": str, "tokens": frozenset, "response": str, "created": float}
_cache: OrderedDict[str, dict] = OrderedDict()
_cache_stats = {"hits": 0, "misses": 0}


def _seed_cache() -> None:
    """Public banking FAQ answers, visible to every session."""
    brand = get_brand_name()
    for prompt, answer in [
        ("What are your branch opening hours?", "Branches open 9am to 5pm, Monday to Friday."),
        ("How do I reset my online banking password?", "Use 'Forgot password' on the login page."),
        ("What is the daily ATM withdrawal limit?", "The standard daily ATM limit is $500."),
        (f"Does {brand} charge for international transfers?", "International wires cost $25."),
    ]:
        _store(_SHARED_SESSION, prompt, answer)


def _store(session: str, prompt: str, response: str) -> None:
    key = f"{session}:{prompt}"
    _cache[key] = {
        "session": session,
        "prompt": prompt,
        "tokens": _tokens(prompt),
        "response": response,
        "created": time.time(),
    }
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX_ENTRIES:
        _cache.popitem(last=False)


def _lookup(session: str, prompt: str) -> tuple[dict | None, float]:
    """Best cached entry for `prompt` that this session may see."""
    cross_session = is_observation_active("no_session_isolation")
    wanted = _tokens(prompt)
    now = time.time()
    best, best_score = None, 0.0
    for entry in _cache.values():
        if now - entry["created"] > CACHE_TTL_SECONDS:
            continue
        if not cross_session and entry["session"] not in (session, _SHARED_SESSION):
            continue
        score = _similarity(wanted, entry["tokens"])
        if score > best_score:
            best, best_score = entry, score
    if best is not None and best_score >= CACHE_SIMILARITY_THRESHOLD:
        return best, best_score
    return None, best_score


def _cache_info() -> dict:
    total = _cache_stats["hits"] + _cache_stats["misses"]
    return {
        "cache_type": "semantic_cache",
        "backend": "in-memory embedding_match",
        "entries": len(_cache),
        "cache_hit_rate": round(_cache_stats["hits"] / total, 3) if total else 0.0,
        "similarity_threshold": CACHE_SIMILARITY_THRESHOLD,
        "ttl": CACHE_TTL_SECONDS,
    }


_seed_cache()


@app.get("/semantic-cache")
async def semantic_cache_info():
    """Cache description. Ungated, so `cag_discovery` always finds the cache."""
    return JSONResponse(_cache_info(), headers={"X-Semantic-Cache": "enabled"})


@app.get("/cache/stats")
async def cache_stats():
    """Entry count and hit rate. Ungated."""
    return {**_cache_info(), "hits": _cache_stats["hits"], "misses": _cache_stats["misses"]}


@app.post("/semantic-cache")
async def semantic_cache_query(
    body: CacheQuery,
    x_session_id: str | None = Header(default=None),
):
    """Answer from the cache when a similar prompt is cached, else "generate" and store."""
    session = x_session_id or "anonymous"
    prompt = " ".join(p for p in (body.input, body.query) if p).strip()
    if not prompt:
        raise HTTPException(422, "input or query is required")

    started = time.monotonic()
    entry, score = _lookup(session, prompt)

    if entry is not None:
        _cache_stats["hits"] += 1
        if not is_observation_active("cache_timing_leak"):
            # Constant-time: pad a hit to the generation latency.
            await asyncio.sleep(max(0.0, _GENERATION_SECONDS - (time.monotonic() - started)))
        payload = {
            "cached": True,
            "cache_hit": True,
            "response": entry["response"],
            "similarity_score": round(score, 3),
            "cache_age": int(time.time() - entry["created"]),
        }
        if is_observation_active("no_session_isolation"):
            payload["session_id"] = entry["session"]  # whose answer this was
        status = "HIT"
    else:
        _cache_stats["misses"] += 1
        await asyncio.sleep(_GENERATION_SECONDS)  # the "model" generating
        answer = f"Noted. You said: {body.input or body.query}"
        _store(session, prompt, answer)
        payload = {
            "cached": False,
            "cache_hit": False,
            "response": answer,
            "similarity_score": round(score, 3),
        }
        status = "MISS"

    return JSONResponse(
        payload,
        headers={"X-Cache": status, "X-Semantic-Cache": status.lower(), "X-Session-Id": session},
    )
