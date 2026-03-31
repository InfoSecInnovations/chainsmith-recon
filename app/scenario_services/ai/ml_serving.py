"""
app/scenario_services/ai/ml_serving.py

ML model serving service template.

This service simulates an ML model serving endpoint (similar to vLLM, TGI, etc.)
with embeddings and completions APIs. It includes configurable security findings.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    ML_VERSION          Service version (default: 2.1.0)
    MODEL_ID            Model identifier (default: <brand>-llm-v2)

Planted findings:
    framework_fingerprint       X-Serving-Engine and X-Model-Backend headers
    model_version_leak          X-Model-Version header
    model_info_endpoint         /v1/models returns detailed model info
    model_config_exposed        /debug/config and training config visible
    embedding_endpoint_exposed  Embedding endpoint with debug info
    no_rate_limit               No rate limiting on embeddings
    bulk_query_allowed          Bulk embedding queries allowed

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.ai.ml_serving:app
      --host 0.0.0.0 --port 8084
    environment:
      - BRAND_NAME=Fakobanko
      - MODEL_ID=fakobanko-llm-v2
"""

import os
import random
from typing import Optional, Union

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

from app.scenario_services.common.config import (
    SERVICE_NAME,
    is_finding_active,
    get_or_create_session,
    get_brand_name,
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
    text: Union[str, list[str]]
    model: Optional[str] = None


class InferenceRequest(BaseModel):
    prompt: str
    max_tokens: Optional[int] = 256
    temperature: Optional[float] = 0.7


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active findings."""
    response = await call_next(request)

    # Finding: framework_fingerprint - leak serving infrastructure
    if is_finding_active("framework_fingerprint"):
        response.headers["X-Serving-Engine"] = "vLLM/0.4.1"
        response.headers["X-Model-Backend"] = "transformers"

    # Finding: model_version_leak - leak model version
    if is_finding_active("model_version_leak"):
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
        "endpoints": ["/v1/models", "/v1/embeddings", "/v1/completions"],
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
    
    Finding: model_info_endpoint
    When active, returns detailed model information.
    
    Finding: model_config_exposed
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

    # Finding: model_info_endpoint - leak detailed model info
    if is_finding_active("model_info_endpoint"):
        models[0].update({
            "architecture": "llama-7b-hf",
            "quantization": "awq-4bit",
            "max_context": 4096,
            "fine_tuned": True,
            "base_model": "meta-llama/Llama-2-7b-hf",
        })

    # Finding: model_config_exposed - leak training config
    if is_finding_active("model_config_exposed"):
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
    
    Finding: no_rate_limit
    When not active, limits to 10 texts per request.
    
    Finding: bulk_query_allowed
    When not active, prevents bulk queries.
    
    Finding: embedding_endpoint_exposed
    When active, includes debug info in response.
    """
    model_id = request.model or f"{_get_model_id()}-embed-v1"
    texts = request.text if isinstance(request.text, list) else [request.text]

    # Check rate limiting
    if not is_finding_active("no_rate_limit") and len(texts) > 10:
        raise HTTPException(429, "Rate limit exceeded: max 10 texts per request")

    # Check bulk query
    if not is_finding_active("bulk_query_allowed") and len(texts) > 1:
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

    # Finding: embedding_endpoint_exposed - include debug info
    if is_finding_active("embedding_endpoint_exposed"):
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
    
    Finding: model_config_exposed
    Only available when this finding is active.
    """
    if not is_finding_active("model_config_exposed"):
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
    
    Finding: model_config_exposed
    Only available when this finding is active.
    """
    if not is_finding_active("model_config_exposed"):
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
