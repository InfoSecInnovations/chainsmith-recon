"""
scenarios/_template/services/extra.py

Optional service example (profile-activated).

Enable with: ./range/start-range.sh my-scenario --profile extra
"""

from fastapi import FastAPI

app = FastAPI(
    title="Template Extra Service",
    description="Optional profile-activated service",
    version="1.0.0",
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {
        "service": "extra",
        "message": "This is an optional service activated via --profile extra",
    }
