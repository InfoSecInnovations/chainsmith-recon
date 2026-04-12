"""
Fakobanko ML Model Serving Service

Simulates an ML model serving endpoint with planted findings.
"""

import os
import random

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from fakobanko.config import get_or_create_session, is_observation_active

app = FastAPI(
    title="Fakobanko ML Service",
    description="Internal ML model serving",
    version="2.1.0",
)


# ─── Models ────────────────────────────────────────────────────


class EmbeddingRequest(BaseModel):
    text: str | list[str]
    model: str | None = "fakobanko-embed-v1"


class EmbeddingResponse(BaseModel):
    embeddings: list[list[float]]
    model: str
    usage: dict


class InferenceRequest(BaseModel):
    prompt: str
    max_tokens: int | None = 256
    temperature: float | None = 0.7


# ─── Middleware ────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)

    # Framework fingerprinting finding
    if is_observation_active("framework_fingerprint"):
        response.headers["X-Serving-Engine"] = "vLLM/0.4.1"
        response.headers["X-Model-Backend"] = "transformers"

    if is_observation_active("model_version_leak"):
        response.headers["X-Model-Version"] = "fakobanko-llm-v2.3.1-ft"

    return response


# ─── Endpoints ─────────────────────────────────────────────────


@app.get("/")
async def root():
    return {
        "service": "Fakobanko ML Service",
        "version": "2.1.0",
        "endpoints": ["/v1/models", "/v1/embeddings", "/v1/completions"],
    }


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "fakobanko-ml", "session_id": session.session_id}


@app.get("/v1/models")
async def list_models():
    """Model listing endpoint - may leak info."""
    models = [{"id": "fakobanko-llm-v2", "object": "model", "owned_by": "fakobanko"}]

    if is_observation_active("model_info_endpoint"):
        # Leak additional model details
        models[0].update(
            {
                "architecture": "llama-7b-hf",
                "quantization": "awq-4bit",
                "max_context": 4096,
                "fine_tuned": True,
                "base_model": "meta-llama/Llama-2-7b-hf",
            }
        )

    if is_observation_active("model_config_exposed"):
        models[0]["training_config"] = {
            "dataset": "s3://fakobanko-ml/training/customer-interactions-2024/",
            "epochs": 3,
            "learning_rate": 2e-5,
        }

    return {"data": models, "object": "list"}


@app.post("/v1/embeddings")
async def create_embedding(request: EmbeddingRequest):
    """Embedding endpoint - may allow bulk queries."""

    texts = request.text if isinstance(request.text, list) else [request.text]

    # Check rate limiting finding
    if not is_observation_active("no_rate_limit") and len(texts) > 10:
        raise HTTPException(429, "Rate limit exceeded: max 10 texts per request")

    if not is_observation_active("bulk_query_allowed") and len(texts) > 1:
        raise HTTPException(400, "Bulk queries not allowed")

    # Generate fake embeddings
    embeddings = [[random.uniform(-1, 1) for _ in range(384)] for _ in texts]

    response = {
        "embeddings": embeddings,
        "model": request.model,
        "usage": {
            "prompt_tokens": sum(len(t.split()) for t in texts),
            "total_tokens": sum(len(t.split()) for t in texts),
        },
    }

    if is_observation_active("embedding_endpoint_exposed"):
        response["_debug"] = {
            "model_path": "/models/fakobanko-embed-v1",
            "dimension": 384,
            "normalize": True,
        }

    return response


@app.post("/v1/completions")
async def create_completion(request: InferenceRequest):
    """Completion endpoint."""

    return {
        "id": "cmpl-" + os.urandom(8).hex(),
        "object": "text_completion",
        "model": "fakobanko-llm-v2",
        "choices": [
            {"text": "I'm a simulated ML model response.", "index": 0, "finish_reason": "stop"}
        ],
        "usage": {
            "prompt_tokens": len(request.prompt.split()),
            "completion_tokens": 8,
            "total_tokens": len(request.prompt.split()) + 8,
        },
    }


@app.get("/debug/config")
async def debug_config():
    """Debug config endpoint - only if finding active."""
    if not is_observation_active("model_config_exposed"):
        raise HTTPException(404, "Not found")

    return {
        "model_id": "fakobanko-llm-v2",
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
            "internal_metrics": "http://ml.fakobanko.local:9090/metrics",
            "model_store": "s3://fakobanko-ml/models/",
        },
    }
