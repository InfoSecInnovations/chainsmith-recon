"""
demo_domain.services.docs

Internal documentation portal — API reference, tool schemas,
and IT runbooks.

Planted findings:
    directory_listing        Directory index enabled, exposes file structure
    version_disclosure       Response headers leak service versions
    unauthed_docs            Documentation accessible without authentication
"""

import traceback as tb

from demo_domain.config import VERBOSE_ERRORS, get_or_create_session, is_finding_active
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(
    title="Documentation Portal",
    description="Internal API and tool documentation",
    version="1.0.3",
)


# ── Middleware ────────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as exc:
        if VERBOSE_ERRORS:
            return JSONResponse(
                status_code=500,
                content={
                    "error": str(exc),
                    "traceback": tb.format_exc(),
                    "service": "demo-domain-docs",
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    # version_disclosure finding — leak versions in headers
    if is_finding_active("version_disclosure"):
        response.headers["X-Powered-By"] = "FastAPI/0.111.0 Python/3.11.9"
        response.headers["Server"] = "uvicorn/0.29.0"
        response.headers["X-Docs-Version"] = "docs-portal/1.0.3"
        response.headers["X-Internal-Build"] = "build-20260401-d8e2a"

    return response


# ── Shared styles ────────────────────────────────────────────────

_STYLES = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f5f5f5; color: #333; }
    .header { background: #1a1a2e; color: white; padding: 16px 32px;
              display: flex; align-items: center; gap: 12px; }
    .header h1 { font-size: 20px; font-weight: 600; }
    .header .subtitle { font-size: 13px; opacity: 0.6; }
    .header nav { margin-left: auto; display: flex; gap: 16px; }
    .header nav a { color: rgba(255,255,255,0.7); text-decoration: none; font-size: 14px; }
    .header nav a:hover { color: white; }
    .container { max-width: 960px; margin: 32px auto; padding: 0 24px; }
    .card { background: white; border-radius: 8px; padding: 24px;
            border: 1px solid #e0e0e0; margin-bottom: 16px; }
    .card h2 { font-size: 18px; margin-bottom: 8px; }
    .card p { font-size: 14px; color: #666; line-height: 1.6; }
    .card a { color: #1a1a2e; text-decoration: none; font-weight: 500; }
    .card a:hover { text-decoration: underline; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px;
           font-family: 'Fira Code', monospace; font-size: 13px; }
    pre { background: #1a1a2e; color: #e0e0e0; padding: 16px; border-radius: 6px;
          overflow-x: auto; font-size: 13px; line-height: 1.5; margin: 12px 0; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0; }
    th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #e0e0e0;
             font-size: 14px; }
    th { background: #f9f9f9; font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 11px; font-weight: 600; }
    .badge.get { background: #e8f5e9; color: #2e7d32; }
    .badge.post { background: #e3f2fd; color: #1565c0; }
    .badge.delete { background: #fce4ec; color: #c62828; }
    .dir-listing { list-style: none; }
    .dir-listing li { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
    .dir-listing li a { color: #1a1a2e; text-decoration: none; }
    .dir-listing li a:hover { text-decoration: underline; }
    .dir-icon { margin-right: 8px; }
    .footer { text-align: center; padding: 32px; font-size: 12px; color: #999; }
    .warning { background: #fff3e0; border-left: 4px solid #ff9800;
               padding: 12px 16px; margin: 16px 0; border-radius: 4px;
               font-size: 13px; color: #e65100; }
"""


def _nav():
    return """
    <nav>
        <a href="/">Index</a>
        <a href="/api-reference">API Reference</a>
        <a href="/tools-reference">Tools</a>
        <a href="/runbooks">Runbooks</a>
    </nav>"""


def _auth_gate(request: Request):
    """Check auth unless unauthed_docs finding is active."""
    if not is_finding_active("unauthed_docs"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")


# ── Documentation index ──────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    directory_listing finding — directory index exposes file structure.
    unauthed_docs finding — accessible without authentication.
    """
    _auth_gate(request)

    # directory_listing finding — show file/directory structure
    if is_finding_active("directory_listing"):
        directory_section = """
        <div class="card">
            <h2>Directory Index</h2>
            <ul class="dir-listing">
                <li><span class="dir-icon">📁</span><a href="/api-reference">api-reference/</a></li>
                <li><span class="dir-icon">📁</span><a href="/tools-reference">tools-reference/</a></li>
                <li><span class="dir-icon">📁</span><a href="/runbooks">runbooks/</a></li>
                <li><span class="dir-icon">📄</span><a href="/openapi.json">openapi.json</a></li>
                <li><span class="dir-icon">📄</span>deployment.yaml</li>
                <li><span class="dir-icon">📄</span>docker-compose.yml</li>
                <li><span class="dir-icon">📄</span>.env.example</li>
                <li><span class="dir-icon">📁</span>internal/</li>
                <li><span class="dir-icon">📁</span>admin/</li>
            </ul>
        </div>"""
    else:
        directory_section = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documentation Portal</title>
    <style>{_STYLES}</style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Documentation Portal</h1>
            <div class="subtitle">Internal API &amp; Tool Documentation</div>
        </div>
        {_nav()}
    </div>
    <div class="container">
        <div class="warning">
            INTERNAL USE ONLY — This documentation contains sensitive architecture details.
            Do not share outside the organization.
        </div>

        <div class="card">
            <h2>IT Help Desk Platform</h2>
            <p>Documentation for the internal IT Help Desk platform, including API endpoints,
               AI assistant tool schemas, and operational runbooks.</p>
        </div>

        <div class="card">
            <h2>Quick Links</h2>
            <p>
                <a href="/api-reference">API Reference</a> — REST API endpoints for the helpdesk backend<br>
                <a href="/tools-reference">Tool Schemas</a> — AI assistant tool definitions and parameters<br>
                <a href="/runbooks">Runbooks</a> — IT operations runbooks and procedures
            </p>
        </div>

        {directory_section}

        <div class="card">
            <h2>Service Architecture</h2>
            <table>
                <tr><th>Service</th><th>Port</th><th>Description</th></tr>
                <tr><td>Web Portal</td><td>8200</td><td>IT Help Desk landing page</td></tr>
                <tr><td>Chat API</td><td>8201</td><td>AI-powered chat endpoint</td></tr>
                <tr><td>REST API</td><td>8202</td><td>Helpdesk backend API</td></tr>
                <tr><td>Agent</td><td>8203</td><td>Agentic orchestration / MCP</td></tr>
                <tr><td>Knowledge Base</td><td>8204</td><td>RAG service</td></tr>
                <tr><td>Cache</td><td>8205</td><td>Semantic response cache</td></tr>
                <tr><td>Docs</td><td>8206</td><td>This documentation portal</td></tr>
            </table>
        </div>
    </div>
    <div class="footer">Documentation Portal v1.0.3 — Internal Use Only</div>
</body>
</html>"""


# ── API Reference ────────────────────────────────────────────────


@app.get("/api-reference", response_class=HTMLResponse)
async def api_reference(request: Request):
    """API reference docs — unauthed_docs finding."""
    _auth_gate(request)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Reference — Documentation Portal</title>
    <style>{_STYLES}</style>
</head>
<body>
    <div class="header">
        <div>
            <h1>API Reference</h1>
            <div class="subtitle">REST API Endpoints</div>
        </div>
        {_nav()}
    </div>
    <div class="container">
        <div class="card">
            <h2>Authentication</h2>
            <p>All authenticated endpoints require a Bearer token in the Authorization header:</p>
            <pre>Authorization: Bearer &lt;token&gt;</pre>
            <p>Demo tokens for testing:</p>
            <table>
                <tr><th>Token</th><th>User</th><th>Role</th></tr>
                <tr><td><code>demo-token-alice</code></td><td>Alice Morgan (USR-001)</td><td>User</td></tr>
                <tr><td><code>demo-token-bob</code></td><td>Bob Nguyen (USR-002)</td><td>User</td></tr>
                <tr><td><code>demo-token-admin</code></td><td>Admin (USR-ADM)</td><td>Admin</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Helpdesk API (port 8202)</h2>
            <table>
                <tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/api/v1/status</code></td><td>No</td><td>Service status</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/api/v1/users</code></td><td>Yes*</td><td>List all users</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/api/v1/users/{{id}}</code></td><td>Yes*</td><td>Get user by ID</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/api/v1/tickets</code></td><td>Yes</td><td>List tickets</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/api/v1/tickets/{{id}}</code></td><td>Yes</td><td>Get ticket by ID</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/api/v1/tickets</code></td><td>Yes</td><td>Create ticket</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/api/v1/embeddings</code></td><td>No</td><td>Generate embeddings</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/api/v1/admin/config</code></td><td>Yes</td><td>Admin configuration</td></tr>
            </table>
            <p style="margin-top:8px;font-size:12px;color:#999;">* Auth may be bypassed in some configurations</p>
        </div>

        <div class="card">
            <h2>Chat API (port 8201)</h2>
            <table>
                <tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/v1/chat</code></td><td>No</td><td>Send chat message</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/v1/chat/completions</code></td><td>No</td><td>OpenAI-compat endpoint</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/v1/tools</code></td><td>No*</td><td>List tool schemas</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/v1/models</code></td><td>No</td><td>List available models</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Agent / MCP (port 8203)</h2>
            <table>
                <tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/mcp</code></td><td>No</td><td>MCP JSON-RPC endpoint</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/mcp/sse</code></td><td>No</td><td>MCP SSE stream</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/.well-known/mcp</code></td><td>No</td><td>MCP discovery</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/memory</code></td><td>No</td><td>Agent memory store</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/agent/execute</code></td><td>No</td><td>Execute agent goal</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/agent/relay</code></td><td>No</td><td>Inter-agent relay</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Knowledge Base (port 8204)</h2>
            <table>
                <tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/v1/search</code></td><td>Yes*</td><td>Search knowledge base</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/v1/collections</code></td><td>Yes*</td><td>List collections</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/v1/ingest</code></td><td>Yes</td><td>Ingest document</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/v1/documents/{{id}}</code></td><td>Yes*</td><td>Retrieve document</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Cache (port 8205)</h2>
            <table>
                <tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/v1/cache/lookup</code></td><td>No</td><td>Cache lookup</td></tr>
                <tr><td><span class="badge post">POST</span></td><td><code>/v1/cache/store</code></td><td>Yes*</td><td>Store cache entry</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/v1/cache/stats</code></td><td>Yes*</td><td>Cache statistics</td></tr>
                <tr><td><span class="badge delete">DELETE</span></td><td><code>/v1/cache/invalidate</code></td><td>Yes</td><td>Invalidate entries</td></tr>
                <tr><td><span class="badge get">GET</span></td><td><code>/v1/cache/entries</code></td><td>Yes*</td><td>List cache entries</td></tr>
            </table>
        </div>
    </div>
    <div class="footer">Documentation Portal v1.0.3 — Internal Use Only</div>
</body>
</html>"""


# ── Tools Reference ──────────────────────────────────────────────


@app.get("/tools-reference", response_class=HTMLResponse)
async def tools_reference(request: Request):
    """Tool schemas and documentation — unauthed_docs finding."""
    _auth_gate(request)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tools Reference — Documentation Portal</title>
    <style>{_STYLES}</style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Tools Reference</h1>
            <div class="subtitle">AI Assistant Tool Schemas</div>
        </div>
        {_nav()}
    </div>
    <div class="container">
        <div class="warning">
            These tool schemas are used by the AI assistant. Exposing them publicly
            may allow prompt injection or tool abuse.
        </div>

        <div class="card">
            <h2>get_ticket_status</h2>
            <p>Retrieve a support ticket by ID.</p>
            <pre>{{
  "name": "get_ticket_status",
  "input_schema": {{
    "type": "object",
    "properties": {{
      "ticket_id": {{ "type": "string", "description": "Ticket ID (e.g. TKT-1001)" }}
    }},
    "required": ["ticket_id"]
  }}
}}</pre>
        </div>

        <div class="card">
            <h2>get_kb_article</h2>
            <p>Search the knowledge base for articles matching a query.</p>
            <pre>{{
  "name": "get_kb_article",
  "input_schema": {{
    "type": "object",
    "properties": {{
      "query": {{ "type": "string", "description": "Search query" }}
    }},
    "required": ["query"]
  }}
}}</pre>
        </div>

        <div class="card">
            <h2>create_ticket</h2>
            <p>Create a new support ticket.</p>
            <pre>{{
  "name": "create_ticket",
  "input_schema": {{
    "type": "object",
    "properties": {{
      "subject": {{ "type": "string" }},
      "description": {{ "type": "string" }},
      "priority": {{ "type": "string", "enum": ["low", "medium", "high", "critical"] }}
    }},
    "required": ["subject", "description"]
  }}
}}</pre>
        </div>

        <div class="card">
            <h2>get_service_status</h2>
            <p>Get real-time status of all IT services.</p>
            <pre>{{
  "name": "get_service_status",
  "input_schema": {{
    "type": "object",
    "properties": {{}},
    "required": []
  }}
}}</pre>
        </div>

        <div class="card">
            <h2>escalate_ticket</h2>
            <p>Escalate a ticket to Tier 2 on-call. Executes immediately without confirmation.</p>
            <pre>{{
  "name": "escalate_ticket",
  "input_schema": {{
    "type": "object",
    "properties": {{
      "ticket_id": {{ "type": "string" }},
      "user_id": {{ "type": "string", "description": "Requesting user ID (unvalidated)" }},
      "reason": {{ "type": "string" }}
    }},
    "required": ["ticket_id", "user_id"]
  }}
}}</pre>
        </div>

        <div class="card">
            <h2>lookup_user</h2>
            <p>Look up employee record by email address.</p>
            <pre>{{
  "name": "lookup_user",
  "input_schema": {{
    "type": "object",
    "properties": {{
      "email": {{ "type": "string", "description": "Employee email address" }}
    }},
    "required": ["email"]
  }}
}}</pre>
        </div>

        <div class="card">
            <h2>MCP Configuration</h2>
            <p>The agent service exposes an MCP endpoint at <code>/mcp</code> supporting
               JSON-RPC 2.0. Available methods:</p>
            <table>
                <tr><th>Method</th><th>Description</th></tr>
                <tr><td><code>initialize</code></td><td>Initialize MCP session</td></tr>
                <tr><td><code>tools/list</code></td><td>List available tools</td></tr>
                <tr><td><code>tools/call</code></td><td>Execute a tool</td></tr>
                <tr><td><code>resources/list</code></td><td>List available resources</td></tr>
                <tr><td><code>resources/read</code></td><td>Read a resource</td></tr>
                <tr><td><code>prompts/list</code></td><td>List available prompts</td></tr>
                <tr><td><code>prompts/get</code></td><td>Get a prompt template</td></tr>
            </table>
        </div>
    </div>
    <div class="footer">Documentation Portal v1.0.3 — Internal Use Only</div>
</body>
</html>"""


# ── Runbooks ─────────────────────────────────────────────────────


@app.get("/runbooks", response_class=HTMLResponse)
async def runbooks(request: Request):
    """IT runbooks index — unauthed_docs finding."""
    _auth_gate(request)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Runbooks — Documentation Portal</title>
    <style>{_STYLES}</style>
</head>
<body>
    <div class="header">
        <div>
            <h1>IT Runbooks</h1>
            <div class="subtitle">Operational Procedures</div>
        </div>
        {_nav()}
    </div>
    <div class="container">
        <div class="card">
            <h2>VPN Troubleshooting</h2>
            <p><strong>Owner:</strong> Bob Nguyen (IT Operations)</p>
            <p>Steps for diagnosing and resolving VPN connectivity issues.</p>
            <pre>1. Verify VPN client version (minimum 4.2.1)
2. Check connectivity to vpn-gateway.corp.internal:443
3. Clear credential cache:
   $ vpncli disconnect &amp;&amp; vpncli clear-cache
4. Re-authenticate using SSO
5. Check firewall rules on 10.0.4.0/24 subnet
6. Escalate to Network Ops if unresolved

Gateway: 10.0.4.1 (primary), 10.0.4.2 (backup)
Contact: netops-oncall@corp.internal</pre>
        </div>

        <div class="card">
            <h2>Laptop Provisioning</h2>
            <p><strong>Owner:</strong> Bob Nguyen (IT Operations)</p>
            <p>Standard procedure for new hire laptop setup.</p>
            <pre>1. Image with corp-standard-2026Q1
2. Join to domain corp.internal
3. Install agent suite: EDR, DLP, VPN client
4. Enroll in MDM
5. Configure BitLocker (recovery key escrowed to AD)
6. Verify all agents reporting to console

Imaging server: imaging.corp.internal
Service account: svc-imaging</pre>
        </div>

        <div class="card">
            <h2>Incident Response</h2>
            <p><strong>Owner:</strong> Carol Davis (Security)</p>
            <p>Incident response playbook for security events.</p>
            <pre>1. CONTAIN — Isolate affected systems immediately
2. NOTIFY — SOC (soc-oncall@corp.internal) + CISO within 30 min
3. PRESERVE — Do not reboot or wipe; preserve evidence
4. ENGAGE — IR retainer (contract #IR-2026-042)
5. DOCUMENT — Timeline in JIRA project SEC

Escalation: CISO direct line x4401
SOC Slack: #soc-alerts</pre>
        </div>

        <div class="card">
            <h2>Service Restart Procedures</h2>
            <p><strong>Owner:</strong> Dan Reyes (IT Manager)</p>
            <p>Procedures for restarting helpdesk platform services.</p>
            <pre>Services run as containers via docker-compose.

Restart single service:
  $ docker-compose restart &lt;service-name&gt;

Full platform restart:
  $ docker-compose down &amp;&amp; docker-compose up -d

Service names: web, chat, api, agent, rag, cache, docs
Config: /opt/helpdesk/docker-compose.yml
State: /data/demo_session.json
Logs: /var/log/helpdesk/</pre>
        </div>
    </div>
    <div class="footer">Documentation Portal v1.0.3 — Internal Use Only</div>
</body>
</html>"""


# ── Health ───────────────────────────────────────────────────────


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "demo-domain-docs",
        "session_id": session.session_id,
    }
