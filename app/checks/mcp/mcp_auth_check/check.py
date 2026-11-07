"""
app/checks/mcp/auth_check.py - MCP Authentication & Authorization

Tests MCP server auth enforcement at multiple levels:
- No-auth access to tools/list and tool invocations
- Default/common API keys
- Auth scope (discovery vs tool invocation)
- Session reuse/fixation
- CORS cross-origin access

**Probe/grade.** Five independent tests run per server, and
each becomes its **own candidate** (one per (server, test)) carrying only that
test's exchanges. `grade()` never sees the candidate's discriminator (§0.16), so
it recognises which test it is looking at from the *shape* of the evidence — an
OPTIONS request is the CORS test, an `Mcp-Session-Id` request header is the
session-reuse test, an `Authorization`/`X-API-Key` header is the default-key
test, an `initialize` body alongside a plain `tools/list` is the scope test, and
a lone plain `tools/list` is the no-auth test. Isolating each test in its own
candidate is what keeps the two byte-identical plain `tools/list` requests (the
no-auth probe and the scope probe's second leg) from being confused (§0.15).

Each test's judgement is read back off its recorded request/response — the
method and `clientInfo` off the request body, the credential off the request
headers, the session id and CORS origin likewise — never from a value the probe
remembered.

**Fixed**: several discriminators embed a key value
(`default-key-<key>`), an unbounded set, so there is no `observations:` map and
`grade()` places the tier. Confidence is where the split pays: real tool data
returned without credentials is near-certain, while a 200 with no tool data, or
a status-code-only scope mismatch, or a session "reused" only across a changed
User-Agent within one process, each carry their own weakness.

References:
  https://modelcontextprotocol.io/specification
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Common default API keys to test
DEFAULT_KEYS = [
    "mcp-key",
    "default",
    "test",
    "admin",
    "mcp",
    "",
    "changeme",
    "password",
    "secret",
    "api-key",
]

_AUTH_HEADER_NAMES = ("authorization", "x-api-key", "api-key")


class MCPAuthCheck(BaseCheck):
    """
    Check MCP server authentication and authorization enforcement.

    Tests whether MCP servers require authentication at all levels:
    discovery, tool listing, and tool invocation. Also checks for
    default credentials, session reuse, and CORS misconfiguration.
    """

    name = "mcp_auth_check"
    description = "Check MCP server authentication and authorization enforcement"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_auth_status"]
    service_types = ["ai", "api", "http"]

    reason = "Local dev MCP servers often have no auth. Testing enforcement reveals unauthenticated tool access."
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
    ]
    techniques = ["authentication testing", "authorization bypass", "session analysis"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        auth_status = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            base_path = server.get("path", "")

            try:
                async with AsyncHttpClient(cfg) as client:
                    tests = {
                        "no_auth": await self._probe_no_auth(
                            client, server_url, base_path, host, scan_id
                        ),
                        "default_keys": await self._probe_default_keys(
                            client, server_url, base_path, host, scan_id
                        ),
                        "auth_scope": await self._probe_auth_scope(
                            client, server_url, base_path, host, scan_id
                        ),
                        "session_reuse": await self._probe_session_reuse(
                            client, server_url, base_path, host, scan_id
                        ),
                        "cors": await self._probe_cors(
                            client, server_url, base_path, host, scan_id
                        ),
                    }

                    server_tests = {}
                    for test_name, exchanges in tests.items():
                        if not exchanges:
                            continue
                        candidate = self.create_candidate(
                            host=host,
                            discriminator=f"authtest-{test_name}",
                            target_url=server_url,
                        )
                        for exchange in exchanges:
                            candidate.attach(exchange)
                        result.candidates.append(candidate)
                        server_tests[test_name] = self._summarise(test_name, exchanges)

                    auth_status.append({"url": server_url, "host": host, "tests": server_tests})

            except Exception as e:
                result.errors.append(f"{server_url}: {e}")

        if auth_status:
            result.outputs["mcp_auth_status"] = auth_status

        return result

    async def _post(
        self, client, url: str, payload: dict, headers: dict, scan_id: str, host: str
    ) -> Exchange:
        resp = await client.post(url, json=payload, headers=headers)
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=headers,
            request_json=payload,
        )

    async def _probe_no_auth(
        self, client, server_url: str, base_path: str, host: str, scan_id: str
    ) -> list[Exchange]:
        url = self._tools_url(server_url, base_path)
        ex = await self._post(
            client,
            url,
            {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            dict(JSON_HEADERS),
            scan_id,
            host,
        )
        return [ex]

    async def _probe_default_keys(
        self, client, server_url: str, base_path: str, host: str, scan_id: str
    ) -> list[Exchange]:
        url = self._tools_url(server_url, base_path)
        exchanges = []
        for key in DEFAULT_KEYS:
            for header_name in ("Authorization", "X-API-Key", "Api-Key"):
                auth_value = f"Bearer {key}" if header_name == "Authorization" and key else key
                headers = {**JSON_HEADERS, header_name: auth_value}
                exchanges.append(
                    await self._post(
                        client,
                        url,
                        {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                        headers,
                        scan_id,
                        host,
                    )
                )
        return exchanges

    async def _probe_auth_scope(
        self, client, server_url: str, base_path: str, host: str, scan_id: str
    ) -> list[Exchange]:
        init_url = self._build_url(server_url, base_path or "/mcp")
        init_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "chainsmith-recon", "version": "1.0"},
            },
            "id": 1,
        }
        init_ex = await self._post(
            client, init_url, init_payload, dict(JSON_HEADERS), scan_id, host
        )

        tools_url = self._tools_url(server_url, base_path)
        tools_ex = await self._post(
            client,
            tools_url,
            {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            dict(JSON_HEADERS),
            scan_id,
            host,
        )
        return [init_ex, tools_ex]

    async def _probe_session_reuse(
        self, client, server_url: str, base_path: str, host: str, scan_id: str
    ) -> list[Exchange]:
        init_url = self._build_url(server_url, base_path or "/mcp")
        init_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "chainsmith-session-a", "version": "1.0"},
            },
            "id": 1,
        }
        init_ex = await self._post(
            client, init_url, init_payload, dict(JSON_HEADERS), scan_id, host
        )

        session_id = self._header(init_ex.response_headers, "mcp-session-id")
        if init_ex.error or init_ex.response_status not in (200, 201) or not session_id:
            return [init_ex]

        tools_url = self._tools_url(server_url, base_path)
        reuse_headers = {
            **JSON_HEADERS,
            "Mcp-Session-Id": session_id,
            "User-Agent": "different-client/1.0",
        }
        reuse_ex = await self._post(
            client,
            tools_url,
            {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            reuse_headers,
            scan_id,
            host,
        )
        return [init_ex, reuse_ex]

    async def _probe_cors(
        self, client, server_url: str, base_path: str, host: str, scan_id: str
    ) -> list[Exchange]:
        url = self._build_url(server_url, base_path or "/mcp")
        headers = {
            "Origin": "https://evil.attacker.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        resp = await client.options(url, headers=headers)
        ex = exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="OPTIONS",
            request_headers=headers,
        )
        return [ex]

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        if not exchanges:
            return []
        test = self._classify_test(exchanges)
        grader = {
            "cors": self._grade_cors,
            "session_reuse": self._grade_session,
            "default_keys": self._grade_default_keys,
            "auth_scope": self._grade_scope,
            "no_auth": self._grade_no_auth,
        }[test]
        return grader(exchanges, ctx)

    def _classify_test(self, exchanges: list[Exchange]) -> str:
        """Which of the five tests this evidence set is, from its shape alone."""
        if any(e.request_method == "OPTIONS" for e in exchanges):
            return "cors"
        if any(self._header(e.request_headers, "mcp-session-id") for e in exchanges):
            return "session_reuse"
        if any(self._has_auth_header(e) for e in exchanges):
            return "default_keys"
        if any(self._method_of(e) == "initialize" for e in exchanges):
            return "auth_scope"
        return "no_auth"

    def _grade_no_auth(self, exchanges: list[Exchange], ctx: GradeContext) -> list[Verdict]:
        ex = exchanges[0]
        url = ex.request_url
        if ex.error:
            return []
        if ex.response_status == 200:
            if self._response_has_tools(ex.response_body):
                return [
                    Verdict(
                        severity="critical",
                        confidence=0.9,
                        discriminator="no-auth-tools",
                        title="MCP server requires no authentication: tools accessible without credentials",
                        description=(
                            "The MCP server responds to tools/list requests without any authentication. "
                            "An unauthenticated attacker can enumerate all available tools and their schemas."
                        ),
                        evidence=f"URL: {url}\nStatus: 200\nBody: {(ex.response_body or '')[:500]}",
                        reasoning=(
                            "real tool data returned to a request carrying no credentials is close to "
                            "conclusive; the only residue is a server that returns canned tool data on "
                            "every path regardless of the method"
                        ),
                        signals={"status": 200, "has_tools": True},
                        references=self.references,
                        raw_data={"url": url, "status": 200},
                        tier=ctx.tier,
                        evidence_ids=[ex.id],
                    )
                ]
            return [
                Verdict(
                    severity="high",
                    confidence=0.6,
                    discriminator="no-auth-endpoint",
                    title="MCP endpoint accessible without authentication",
                    description=(
                        "The MCP server responds to requests without authentication headers, "
                        "though the response may not contain tool data."
                    ),
                    evidence=f"URL: {url}\nStatus: 200",
                    reasoning=(
                        "a 200 with no tool payload is weaker than one with tools: a catch-all "
                        "route or SPA index answers 200 to any path without the MCP endpoint "
                        "actually being open"
                    ),
                    signals={"status": 200, "has_tools": False},
                    references=self.references,
                    raw_data={"url": url, "status": 200},
                    tier=ctx.tier,
                    evidence_ids=[ex.id],
                )
            ]
        if ex.response_status == 401:
            return [
                Verdict(
                    severity="info",
                    confidence=0.8,
                    discriminator="auth-enforced",
                    title="MCP server enforces authentication",
                    description="The MCP server correctly returns 401 for unauthenticated requests.",
                    evidence=f"URL: {url}\nStatus: 401",
                    reasoning=(
                        "an explicit 401 is the server itself demanding credentials; the small "
                        "residual is a 401 from a gateway in front of a path that has no MCP handler"
                    ),
                    signals={"status": 401},
                    references=self.references,
                    raw_data={"url": url, "status": 401},
                    tier=ctx.tier,
                    evidence_ids=[ex.id],
                )
            ]
        return []

    def _grade_default_keys(self, exchanges: list[Exchange], ctx: GradeContext) -> list[Verdict]:
        verdicts = []
        seen_keys = set()
        for ex in exchanges:
            if ex.error or ex.response_status != 200:
                continue
            if not self._response_has_tools(ex.response_body):
                continue
            header_name, raw_value = self._auth_header(ex)
            key = raw_value[len("Bearer ") :] if raw_value.startswith("Bearer ") else raw_value
            key_label = key or "(empty)"
            if key_label in seen_keys:
                continue
            seen_keys.add(key_label)
            verdicts.append(
                Verdict(
                    severity="medium",
                    confidence=0.75,
                    discriminator=f"default-key-{key or 'empty'}",
                    title=f"Default API key accepted: '{key_label}' grants MCP access",
                    description=(
                        f"The MCP server accepts the default key '{key_label}' via {header_name} "
                        "header, granting access to tool enumeration."
                    ),
                    evidence=f"Header: {header_name}: {raw_value}\nStatus: 200",
                    reasoning=(
                        "tool data returned with a known default credential is strong, but a "
                        "server that ignores the auth header entirely and serves tools to everyone "
                        "returns the same 200 — the no-auth test separates the two"
                    ),
                    signals={"header": header_name, "key": key},
                    references=self.references,
                    raw_data={"header": header_name, "key": key},
                    tier=ctx.tier,
                    evidence_ids=[ex.id],
                )
            )
        return verdicts

    def _grade_scope(self, exchanges: list[Exchange], ctx: GradeContext) -> list[Verdict]:
        init_ex = next((e for e in exchanges if self._method_of(e) == "initialize"), None)
        tools_ex = next((e for e in exchanges if self._method_of(e) == "tools/list"), None)
        if init_ex is None or tools_ex is None:
            return []
        init_requires_auth = not init_ex.error and init_ex.response_status == 401
        tools_requires_auth = not tools_ex.error and tools_ex.response_status == 401
        if init_requires_auth and not tools_requires_auth:
            return [
                Verdict(
                    severity="high",
                    confidence=0.7,
                    discriminator="auth-scope-mismatch",
                    title="Auth bypass: initialize requires auth but tools/list does not",
                    description=(
                        "The MCP server requires authentication for the initialize handshake "
                        "but allows unauthenticated access to tools/list. This inconsistency "
                        "allows attackers to enumerate tools without credentials."
                    ),
                    evidence=(
                        f"initialize: 401 at {init_ex.request_url}\n"
                        f"tools/list: {tools_ex.response_status} at {tools_ex.request_url}"
                    ),
                    reasoning=(
                        "the two paths differ in status, but that can reflect different routing "
                        "or handlers rather than a real scope gap — the tools/list side was not "
                        "confirmed to return actual tool data"
                    ),
                    signals={
                        "init_status": init_ex.response_status,
                        "tools_status": tools_ex.response_status,
                    },
                    references=self.references,
                    raw_data={
                        "init_status": init_ex.response_status,
                        "tools_status": tools_ex.response_status,
                    },
                    tier=ctx.tier,
                    evidence_ids=[init_ex.id, tools_ex.id],
                )
            ]
        return []

    def _grade_session(self, exchanges: list[Exchange], ctx: GradeContext) -> list[Verdict]:
        reuse_ex = next(
            (e for e in exchanges if self._header(e.request_headers, "mcp-session-id")), None
        )
        if reuse_ex is None:
            return []
        session_id = self._header(reuse_ex.request_headers, "mcp-session-id")
        if not reuse_ex.error and reuse_ex.response_status == 200:
            return [
                Verdict(
                    severity="high",
                    confidence=0.65,
                    discriminator="session-reuse",
                    title="Session reuse: MCP session ID accepted from different client context",
                    description=(
                        "The MCP server accepts a session ID obtained from one client context "
                        "when used by a different client. This enables session hijacking if an "
                        "attacker obtains a valid session ID."
                    ),
                    evidence=f"Session ID: {session_id}\nReuse status: 200",
                    reasoning=(
                        "the 'different client' is only a changed User-Agent from the same process "
                        "and IP; a server that binds sessions to network identity would still accept "
                        "this, so it overstates how portable the session really is"
                    ),
                    signals={"session_id": session_id, "reuse_status": 200},
                    references=self.references,
                    raw_data={"session_id": session_id, "reuse_status": 200},
                    tier=ctx.tier,
                    evidence_ids=[reuse_ex.id],
                )
            ]
        return []

    def _grade_cors(self, exchanges: list[Exchange], ctx: GradeContext) -> list[Verdict]:
        ex = exchanges[0]
        if ex.error:
            return []
        acao = self._header(ex.response_headers, "access-control-allow-origin")
        if acao in ("*", "https://evil.attacker.com"):
            confidence = 0.85 if acao == "*" else 0.7
            reasoning = (
                "an explicit `Access-Control-Allow-Origin: *` is the server declaring open CORS"
                if acao == "*"
                else "the server echoed the attacker Origin back, which is open CORS, but an echo "
                "can also come from a permissive proxy rather than the MCP app itself"
            )
            return [
                Verdict(
                    severity="high",
                    confidence=confidence,
                    discriminator="cors-open",
                    title="MCP endpoint allows cross-origin requests: browser-based MCP access possible",
                    description=(
                        f"The MCP endpoint returns Access-Control-Allow-Origin: {acao}, "
                        "allowing browser-based JavaScript from any origin to interact with "
                        "the MCP server. This enables cross-site MCP attacks."
                    ),
                    evidence=f"URL: {ex.request_url}\nAccess-Control-Allow-Origin: {acao}",
                    reasoning=reasoning,
                    signals={"acao": acao},
                    references=self.references,
                    raw_data={"acao": acao, "url": ex.request_url},
                    tier=ctx.tier,
                    evidence_ids=[ex.id],
                )
            ]
        return []

    # ── Shared readers ───────────────────────────────────────────────

    def _summarise(self, test_name: str, exchanges: list[Exchange]) -> dict:
        """Rebuild each test's result dict for `mcp_auth_status`, off the record."""
        if test_name == "no_auth":
            ex = exchanges[0]
            return {"accessible": not ex.error and ex.response_status == 200}
        if test_name == "default_keys":
            accepted = []
            for ex in exchanges:
                if (
                    not ex.error
                    and ex.response_status == 200
                    and self._response_has_tools(ex.response_body)
                ):
                    header_name, raw_value = self._auth_header(ex)
                    key = (
                        raw_value[len("Bearer ") :]
                        if raw_value.startswith("Bearer ")
                        else raw_value
                    )
                    accepted.append({"header": header_name, "key": key or "(empty)"})
            return {"accepted_keys": accepted}
        if test_name == "auth_scope":
            init_ex = next((e for e in exchanges if self._method_of(e) == "initialize"), None)
            tools_ex = next((e for e in exchanges if self._method_of(e) == "tools/list"), None)
            mismatch = bool(
                init_ex
                and tools_ex
                and init_ex.response_status == 401
                and tools_ex.response_status != 401
            )
            return {"scope_mismatch": mismatch}
        if test_name == "session_reuse":
            reuse_ex = next(
                (e for e in exchanges if self._header(e.request_headers, "mcp-session-id")), None
            )
            return {"session_reusable": bool(reuse_ex and reuse_ex.response_status == 200)}
        if test_name == "cors":
            acao = self._header(exchanges[0].response_headers, "access-control-allow-origin")
            return {"allows_any_origin": acao in ("*", "https://evil.attacker.com")}
        return {}

    def _has_auth_header(self, exchange: Exchange) -> bool:
        names = {k.lower() for k in (exchange.request_headers or {})}
        return bool(names & set(_AUTH_HEADER_NAMES))

    def _auth_header(self, exchange: Exchange) -> tuple[str, str]:
        for k, v in (exchange.request_headers or {}).items():
            if k.lower() in _AUTH_HEADER_NAMES:
                return k, v
        return "", ""

    @staticmethod
    def _header(headers: dict | None, name: str) -> str:
        for k, v in (headers or {}).items():
            if k.lower() == name.lower():
                return v
        return ""

    @staticmethod
    def _method_of(exchange: Exchange) -> str:
        try:
            return json.loads(exchange.request_body or "{}").get("method", "")
        except (json.JSONDecodeError, TypeError):
            return ""

    def _tools_url(self, server_url: str, base_path: str) -> str:
        tools_path = f"{base_path.rstrip('/')}/tools/list" if base_path else "/mcp/tools/list"
        return self._build_url(server_url, tools_path)

    def _build_url(self, server_url: str, path: str) -> str:
        """Build URL from server base and path."""
        base = server_url.rstrip("/")
        if path and not path.startswith("/"):
            path = f"/{path}"
        return f"{base}{path}" if path else base

    def _response_has_tools(self, body: str | None) -> bool:
        """Check if response body contains tool data."""
        if not body:
            return False
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                result = data.get("result", data)
                if isinstance(result, dict) and "tools" in result:
                    return bool(result["tools"])
                if isinstance(result, list) and len(result) > 0:
                    return any("name" in item for item in result if isinstance(item, dict))
            if isinstance(data, list) and len(data) > 0:
                return any("name" in item for item in data if isinstance(item, dict))
        except (json.JSONDecodeError, TypeError):
            pass
        return False
