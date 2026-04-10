"""
app/routes/chat.py - Operator Chat Routes (Phase 35)

Endpoints:
- POST /api/v1/chat/message   Send operator message
- GET  /api/v1/chat/stream    SSE stream for agent responses
- GET  /api/v1/chat/history   Chat history (cursor-paginated)
- POST /api/v1/chat/clear     Clear chat for session
- GET  /api/v1/chat/export    Export engagement chat as JSON
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.engine.chat import chat_dispatcher, chat_repo, sse_manager
from app.state import state

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Request/Response Models ─────────────────────────────────────


class ChatMessageRequest(BaseModel):
    text: str
    agent: str | None = None  # Optional: route directly to a specific agent
    ui_context: dict | None = None
    scan_id: str | None = None  # Optional: scope context to a specific scan


class ClearChatRequest(BaseModel):
    session_id: str | None = None


# ─── POST /api/v1/chat/message ───────────────────────────────────


@router.post("/api/v1/chat/message")
async def send_chat_message(req: ChatMessageRequest):
    """Send an operator message.

    If `agent` is specified, routes directly to that agent. Otherwise,
    routes through PromptRouter for automatic classification.
    """
    if not req.text or not req.text.strip():
        raise HTTPException(400, "Message text is required.")

    session_id = state.session_id
    engagement_id = state.engagement_id

    response = await chat_dispatcher.handle_operator_message(
        session_id=session_id,
        text=req.text.strip(),
        ui_context=req.ui_context,
        engagement_id=engagement_id,
        target_agent=req.agent,
        scan_id=req.scan_id,
    )

    return response


# ─── GET /api/v1/chat/stream ─────────────────────────────────────


@router.get("/api/v1/chat/stream")
async def chat_stream(request: Request):
    """SSE stream for agent responses and events.

    Opens a persistent connection that pushes chat_response, agent_event,
    redirect, and typing events to the browser.
    """
    session_id = state.session_id
    queue = sse_manager.connect(session_id)

    async def event_generator():
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                    event_type = payload["event"]
                    data = json.dumps(payload["data"])
                    yield f"event: {event_type}\ndata: {data}\n\n"
                except TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            sse_manager.disconnect(session_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ─── GET /api/v1/chat/history ────────────────────────────────────


@router.get("/api/v1/chat/history")
async def get_chat_history(
    session: str | None = Query(None),
    engagement: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    before: str | None = Query(None),
):
    """Get chat history with cursor-based pagination.

    If engagement is set, returns messages across all sessions in that
    engagement. Otherwise scoped to session_id.
    """
    session_id = session or state.session_id
    engagement_id = engagement or state.engagement_id

    messages = await chat_repo.get_history(
        session_id=session_id,
        engagement_id=engagement_id,
        limit=limit,
        before=before,
    )

    return {"messages": messages, "has_more": len(messages) == limit}


# ─── POST /api/v1/chat/clear ─────────────────────────────────────


@router.post("/api/v1/chat/clear")
async def clear_chat(req: ClearChatRequest):
    """Clear chat history for a session.

    Messages are marked as cleared in the DB (retained for audit)
    but excluded from future history queries. Also clears Coach
    session memory to prevent anchor/recency bias.
    """
    session_id = req.session_id or state.session_id
    count = await chat_repo.clear_session(session_id)
    # Clear Coach memory when chat is cleared
    chat_dispatcher.clear_coach_memory()
    return {"cleared": count, "session_id": session_id}


# ─── GET /api/v1/chat/export ─────────────────────────────────────


@router.get("/api/v1/chat/export")
async def export_engagement_chat(
    engagement_id: str = Query(..., alias="engagement"),
):
    """Export all chat messages for an engagement as JSON."""
    messages = await chat_repo.export_engagement_chat(engagement_id)
    if not messages:
        raise HTTPException(404, "No chat messages found for this engagement.")

    return {
        "engagement_id": engagement_id,
        "exported_at": datetime.now(UTC).isoformat(),
        "messages": messages,
    }
