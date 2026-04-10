"""
demo_domain.services.www

IT helpdesk landing page.

Planted findings:
    version_disclosure       X-Powered-By and Server headers leak stack versions
    missing_security_headers No CSP, no X-Frame-Options, no HSTS
    robots_sensitive_paths   robots.txt discloses /internal and /admin paths
    verbose_errors           Full stack traces in 500 responses
    unauthed_docs            /openapi.json and /docs exposed (FastAPI default)
    cookie_security_missing  Session cookies without Secure/HttpOnly flags
    config_exposure          .env file accessible at /.env
"""

import traceback

from demo_domain.config import (
    VERBOSE_ERRORS,
    get_or_create_session,
    is_finding_active,
    reset_session,
)
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(
    title="HelpDesk Portal",
    description="IT support portal",
    version="2.4.1",
    # /docs and /openapi.json intentionally left enabled — unauthed_docs finding
)


# ── Header middleware ─────────────────────────────────────────────


@app.middleware("http")
async def add_response_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as exc:
        if VERBOSE_ERRORS:
            return JSONResponse(
                status_code=500,
                content={
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                    "service": "demo-domain-web",
                    "path": str(request.url.path),
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    # version_disclosure finding — leak stack details
    if is_finding_active("version_disclosure"):
        response.headers["X-Powered-By"] = "FastAPI/0.111.0 Python/3.11.9"
        response.headers["Server"] = "uvicorn/0.29.0"
        response.headers["X-App-Version"] = "helpdesk-portal/2.4.1"
        response.headers["X-Internal-Build"] = "build-20260228-a3f1c"

    # missing_security_headers finding — deliberately absent:
    # Content-Security-Policy, X-Frame-Options, Strict-Transport-Security,
    # X-Content-Type-Options, Referrer-Policy

    # cookie_security_missing finding — session cookie without Secure/HttpOnly
    if is_finding_active("cookie_security_missing"):
        response.set_cookie(
            key="helpdesk_session",
            value=get_or_create_session().session_id,
            # Intentionally missing: secure=True, httponly=True, samesite="strict"
        )

    return response


# ── Routes ────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index():
    """Main helpdesk landing page."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IT Help Desk</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; color: #333; }
        .header { background: #1a1a2e; color: white; padding: 16px 32px;
                  display: flex; align-items: center; gap: 12px; }
        .header h1 { font-size: 20px; font-weight: 600; }
        .header .subtitle { font-size: 13px; opacity: 0.6; }
        .container { max-width: 960px; margin: 40px auto; padding: 0 24px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
        .card { background: white; border-radius: 8px; padding: 24px;
                border: 1px solid #e0e0e0; cursor: pointer; transition: box-shadow 0.15s; }
        .card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .card-icon { font-size: 32px; margin-bottom: 12px; }
        .card-title { font-size: 16px; font-weight: 600; margin-bottom: 6px; }
        .card-desc { font-size: 13px; color: #666; line-height: 1.5; }
        .status-bar { background: white; border: 1px solid #e0e0e0; border-radius: 8px;
                      padding: 16px 24px; margin-bottom: 24px;
                      display: flex; align-items: center; gap: 10px; font-size: 14px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #4ade80; }
        .status-dot.degraded { background: #fbbf24; }
        .chat-fab { position: fixed; bottom: 32px; right: 32px;
                    background: #1a1a2e; color: white; border: none;
                    border-radius: 50px; padding: 14px 24px; font-size: 15px;
                    cursor: pointer; box-shadow: 0 4px 16px rgba(0,0,0,0.2); }
        .chat-fab:hover { background: #16213e; }
        h2 { font-size: 22px; margin-bottom: 20px; }
        .footer { text-align: center; padding: 40px; font-size: 12px; color: #999; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>IT Help Desk</h1>
            <div class="subtitle">Internal Support Portal</div>
        </div>
    </div>
    <div class="container">
        <div class="status-bar">
            <div class="status-dot degraded"></div>
            <span>VPN intermittent — all other services operational</span>
            <a href="/status" style="margin-left:auto;font-size:13px;color:#1a1a2e;">View status →</a>
        </div>
        <h2>How can we help?</h2>
        <div class="grid">
            <div class="card" onclick="location.href='/chat'">
                <div class="card-icon">💬</div>
                <div class="card-title">Chat with Support</div>
                <div class="card-desc">Talk to our AI assistant for instant help with common issues.</div>
            </div>
            <div class="card" onclick="location.href='/tickets'">
                <div class="card-icon">🎫</div>
                <div class="card-title">My Tickets</div>
                <div class="card-desc">View and track your open support requests.</div>
            </div>
            <div class="card" onclick="location.href='/kb'">
                <div class="card-icon">📖</div>
                <div class="card-title">Knowledge Base</div>
                <div class="card-desc">Self-service guides for common IT tasks.</div>
            </div>
            <div class="card" onclick="location.href='/status'">
                <div class="card-icon">🟢</div>
                <div class="card-title">Service Status</div>
                <div class="card-desc">Real-time status of all IT services and systems.</div>
            </div>
        </div>
    </div>
    <button class="chat-fab" onclick="location.href='/chat'">💬 Chat with IT Support</button>
    <div class="footer">IT Help Desk Portal — Internal Use Only</div>
</body>
</html>"""


@app.get("/chat", response_class=HTMLResponse)
async def chat_ui():
    """Chatbot UI — thin wrapper around the chat API."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IT Support Chat</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; height: 100vh; display: flex; flex-direction: column; }
        .header { background: #1a1a2e; color: white; padding: 14px 24px;
                  display: flex; align-items: center; gap: 10px; }
        .header h1 { font-size: 17px; }
        .header .back { margin-right: auto; color: rgba(255,255,255,0.6);
                        text-decoration: none; font-size: 13px; }
        .messages { flex: 1; overflow-y: auto; padding: 24px;
                    display: flex; flex-direction: column; gap: 12px; }
        .msg { max-width: 75%; padding: 12px 16px; border-radius: 12px;
               font-size: 14px; line-height: 1.5; }
        .msg.user { background: #1a1a2e; color: white; align-self: flex-end;
                    border-bottom-right-radius: 4px; }
        .msg.bot  { background: white; border: 1px solid #e0e0e0;
                    align-self: flex-start; border-bottom-left-radius: 4px; }
        .msg.bot .name { font-size: 11px; color: #999; margin-bottom: 4px; }
        .input-row { padding: 16px 24px; background: white;
                     border-top: 1px solid #e0e0e0;
                     display: flex; gap: 10px; }
        .input-row input { flex: 1; padding: 10px 14px; border: 1px solid #ddd;
                           border-radius: 6px; font-size: 14px; outline: none; }
        .input-row input:focus { border-color: #1a1a2e; }
        .input-row button { padding: 10px 20px; background: #1a1a2e; color: white;
                            border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }
        .thinking { color: #999; font-style: italic; font-size: 13px; }
    </style>
</head>
<body>
    <div class="header">
        <a href="/" class="back">← Back</a>
        <h1>IT Support Assistant</h1>
    </div>
    <div class="messages" id="messages">
        <div class="msg bot">
            <div class="name">IT Support Assistant</div>
            Hi! I'm the IT Help Desk assistant. I can help you with tickets, system status,
            and common IT issues. How can I help you today?
        </div>
    </div>
    <div class="input-row">
        <input type="text" id="input" placeholder="Type your message..." autocomplete="off">
        <button onclick="send()">Send</button>
    </div>
    <script>
        const CHAT_URL = 'http://localhost:8201';
        let conversationId = null;

        document.getElementById('input').addEventListener('keydown', e => {
            if (e.key === 'Enter') send();
        });

        async function send() {
            const input = document.getElementById('input');
            const text = input.value.trim();
            if (!text) return;
            input.value = '';

            appendMsg('user', text);
            const thinking = appendMsg('bot', '<span class="thinking">Thinking...</span>', true);

            try {
                const res = await fetch(`${CHAT_URL}/v1/chat`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text, conversation_id: conversationId }),
                });
                const data = await res.json();
                conversationId = data.conversation_id;
                thinking.innerHTML = '<div class="name">IT Support Assistant</div>' +
                    escapeHtml(data.response);
            } catch (e) {
                thinking.innerHTML = '<div class="name">IT Support Assistant</div>' +
                    'Sorry, I encountered an error. Please try again.';
            }
        }

        function appendMsg(role, html, raw = false) {
            const div = document.createElement('div');
            div.className = 'msg ' + role;
            div.innerHTML = raw ? html : escapeHtml(html);
            document.getElementById('messages').appendChild(div);
            div.scrollIntoView();
            return div;
        }

        function escapeHtml(s) {
            return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                .replace(/>/g,'&gt;').replace(/\n/g,'<br>');
        }
    </script>
</body>
</html>"""


@app.get("/status")
async def service_status():
    """Public service status page."""
    from demo_domain.tools import get_service_status

    return get_service_status()


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    """robots_sensitive_paths finding — discloses internal paths."""
    if is_finding_active("robots_sensitive_paths"):
        return (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /internal\n"
            "Disallow: /internal/session\n"
            "Disallow: /api/v1/users\n"
            "Disallow: /api/v1/admin\n"
            "Disallow: /_debug\n"
            "\n"
            "# AI assistant backend\n"
            "Disallow: /v1/chat\n"
            "Disallow: /v1/tools\n"
        )
    return "User-agent: *\nDisallow: /admin\n"


@app.get("/.env", response_class=PlainTextResponse)
async def env_file():
    """config_exposure finding — .env file accessible."""
    if not is_finding_active("config_exposure"):
        from fastapi import HTTPException

        raise HTTPException(404, "Not found")
    return (
        "# IT HelpDesk Configuration\n"
        "DATABASE_URL=sqlite:///data/helpdesk.db\n"
        "SESSION_SECRET=helpdesk-secret-2026-Q1\n"
        "LLM_API_KEY=sk-demo-key-not-real-but-looks-like-it\n"
        "INTERNAL_API_URL=http://demo-domain-api:8202\n"
        "AGENT_URL=http://demo-domain-agent:8203\n"
        "RAG_URL=http://demo-domain-rag:8204\n"
        "CACHE_URL=http://demo-domain-cache:8205\n"
        "ADMIN_PASSWORD=helpdesk-admin-2026\n"
    )


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "demo-domain-web",
        "session_id": session.session_id,
    }


@app.post("/internal/session/reset")
async def session_reset():
    """
    In-place session reset — re-randomizes findings, clears memory.
    Called by target.sh reset via HTTP.
    """
    session = reset_session()
    return {
        "reset": True,
        "session_id": session.session_id,
        "active_findings": session.active_findings,
        "created_at": session.created_at,
    }


@app.get("/_debug")
async def debug_info(request: Request):
    """
    robots_sensitive_paths / verbose_errors finding.
    Exposed debug endpoint — leaks environment and request info.
    """
    if not is_finding_active("verbose_errors"):
        from fastapi import HTTPException

        raise HTTPException(404, "Not found")
    import os

    return {
        "service": "demo-domain-web",
        "python_path": os.environ.get("PYTHONPATH"),
        "app_module": os.environ.get("APP_MODULE"),
        "session_id": get_or_create_session().session_id,
        "request_headers": dict(request.headers),
        "active_findings": get_or_create_session().active_findings,
    }
