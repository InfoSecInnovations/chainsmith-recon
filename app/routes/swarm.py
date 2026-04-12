"""
app/routes/swarm.py - Swarm coordinator API endpoints.

Agent-facing endpoints (register, heartbeat, task polling, result submission)
require API key auth. Status endpoint is public (read-only).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Response

from app.swarm.auth import (
    create_api_key,
    list_api_keys,
    require_swarm_auth,
    revoke_api_key,
)
from app.swarm.coordinator import get_coordinator
from app.swarm.models import (
    CoordinatorStatus,
    HeartbeatRequest,
    KeyCreateRequest,
    RegisterRequest,
    RegisterResponse,
    TaskFailPayload,
    TaskPayload,
    TaskResultPayload,
    TaskStartRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/swarm", tags=["swarm"])


# ── Agent registration ───────────────────────────────────────────


@router.post("/register", response_model=RegisterResponse)
async def register_agent(
    body: RegisterRequest,
    key_id: str = Depends(require_swarm_auth),
):
    """Register a new swarm agent."""
    coordinator = get_coordinator()
    try:
        agent = coordinator.register_agent(
            name=body.name,
            api_key_name=key_id,
            capabilities=body.capabilities,
            max_concurrent=body.max_concurrent,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e

    return RegisterResponse(
        agent_id=agent.agent_id,
        config={"heartbeat_interval": 30},
    )


@router.delete("/agents/{agent_id}", status_code=204)
async def deregister_agent(
    agent_id: str,
    key_id: str = Depends(require_swarm_auth),
):
    """Deregister a swarm agent."""
    coordinator = get_coordinator()
    if not coordinator.deregister_agent(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    return Response(status_code=204)


# ── Heartbeat ────────────────────────────────────────────────────


@router.post("/heartbeat", status_code=200)
async def heartbeat(
    body: HeartbeatRequest,
    key_id: str = Depends(require_swarm_auth),
):
    """Agent heartbeat."""
    coordinator = get_coordinator()
    if not coordinator.heartbeat(body.agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"ok": True}


# ── Task polling & lifecycle ─────────────────────────────────────


@router.get("/tasks/next")
async def get_next_task(
    agent_id: str,
    key_id: str = Depends(require_swarm_auth),
):
    """Poll for the next available task. Returns 204 if nothing ready."""
    coordinator = get_coordinator()

    if agent_id not in coordinator.agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    task = coordinator.get_next_task(agent_id)
    if task is None:
        # Nothing available -- agent should poll again later
        if not coordinator.is_running:
            return {"done": True}
        return Response(status_code=204)

    return TaskPayload.from_swarm_task(task).model_dump()


@router.post("/tasks/{task_id}/start", status_code=200)
async def start_task(
    task_id: str,
    body: TaskStartRequest,
    key_id: str = Depends(require_swarm_auth),
):
    """Mark task as in-progress."""
    coordinator = get_coordinator()
    if not coordinator.start_task(task_id, body.agent_id):
        raise HTTPException(status_code=404, detail="Task not found or not assigned to this agent")
    return {"ok": True}


@router.post("/tasks/{task_id}/result", status_code=200)
async def submit_result(
    task_id: str,
    body: TaskResultPayload,
    key_id: str = Depends(require_swarm_auth),
):
    """Submit check results (observations). This is how observations flow back."""
    coordinator = get_coordinator()
    if not await coordinator.complete_task(task_id, body):
        raise HTTPException(status_code=404, detail="Task not found or not assigned to this agent")
    return {"ok": True}


@router.post("/tasks/{task_id}/fail", status_code=200)
async def fail_task(
    task_id: str,
    body: TaskFailPayload,
    key_id: str = Depends(require_swarm_auth),
):
    """Report check failure."""
    coordinator = get_coordinator()
    if not coordinator.fail_task(task_id, body.agent_id, body.error):
        raise HTTPException(status_code=404, detail="Task not found")
    return {"ok": True}


# ── Status (public) ──────────────────────────────────────────────


@router.get("/status", response_model=CoordinatorStatus)
async def coordinator_status():
    """Coordinator status -- no auth required."""
    return get_coordinator().get_status()


@router.get("/agents")
async def list_agents(key_id: str = Depends(require_swarm_auth)):
    """List connected agents."""
    return get_coordinator().list_agents()


# ── Key management ───────────────────────────────────────────────


@router.post("/keys", status_code=201)
async def create_key(body: KeyCreateRequest, key_id: str = Depends(require_swarm_auth)):
    """Create a new swarm API key. Requires existing auth."""
    new_key_id, raw_key = await create_api_key(body.name)
    return {"key_id": new_key_id, "name": body.name, "raw_key": raw_key}


@router.get("/keys")
async def get_keys():
    """List all swarm API keys (metadata only)."""
    return await list_api_keys()


@router.delete("/keys/{key_id}", status_code=204)
async def delete_key(key_id: str):
    """Revoke a swarm API key."""
    if not await revoke_api_key(key_id):
        raise HTTPException(status_code=404, detail="Key not found")
    return Response(status_code=204)
