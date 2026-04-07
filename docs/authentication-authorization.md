# Authentication & Authorization

Design guidance for securing Chainsmith across deployment scenarios.

## Problem Statement

Chainsmith has three distinct authentication needs with different trust
models and friction tolerances:

1. **Server/UI access** — Who can view observations, start scans, manage
   settings via the web UI or API.
2. **CLI-to-server authentication** — The CLI talks to the API server.
   Currently unauthenticated. Matters when the server is shared.
3. **Swarm agent authentication** — Distributed agents connecting to the
   coordinator. Implemented with API keys; mTLS planned for Phase 3 (see
   [swarm-architecture.md](swarm-architecture.md) for design,
   [swarm-usage.md](swarm-usage.md) for setup).

These need not use the same mechanism. A solo pentester on a laptop needs
zero friction. A shared team server needs basic access control. An
enterprise deployment needs to integrate with existing identity providers.

## Deployment Tiers

| Tier | Scenario | Auth mechanism | Friction |
|------|----------|----------------|----------|
| Local | Solo pentester, localhost | None or optional API key | Zero |
| Team | Shared server, small engagement team | Built-in token auth (JWT) | Low |
| Enterprise | Organization-wide, multi-team | OIDC provider (Keycloak, Okta, Azure AD, etc.) | Standard |

The system should default to **no auth** on localhost and require explicit
opt-in for authentication. Running `chainsmith serve` on 127.0.0.1 should
work exactly as it does today. Authentication activates when:

- Binding to a non-localhost address (`--host 0.0.0.0`)
- Explicitly enabled via config (`auth.enabled: true`)
- An OIDC provider is configured

## MVP: Built-in Token Authentication

The MVP auth system is self-contained — no external dependencies. Chainsmith
generates and validates its own JWTs using a local secret. User credentials
are stored alongside observations in the existing data layer.

### How It Works

```
┌──────────┐     POST /api/auth/login      ┌──────────────────┐
│  CLI /   │  ──────────────────────────>   │   Chainsmith     │
│  Browser │  <──────────────────────────   │   Server         │
│          │     { "token": "eyJ..." }      │                  │
│          │                                │  ┌────────────┐  │
│          │     GET /api/observations          │  │ User Store  │  │
│          │     Authorization: Bearer eyJ  │  │ (SQLite)    │  │
│          │  ──────────────────────────>   │  └────────────┘  │
│          │  <──────────────────────────   │  ┌────────────┐  │
│          │     { observations: [...] }        │  │ JWT Secret  │  │
└──────────┘                                │  │ (generated) │  │
                                            │  └────────────┘  │
                                            └──────────────────┘
```

### Token Lifecycle

1. User authenticates via `POST /api/auth/login` with username + password
2. Server validates credentials against local user store
3. Server returns a signed JWT containing: user ID, username, role, expiry
4. Client includes JWT in subsequent requests: `Authorization: Bearer <token>`
5. Server validates JWT signature and expiry on each request
6. Tokens expire after a configurable TTL (default: 24 hours)
7. Refresh via `POST /api/auth/refresh` with a valid (non-expired) token

### User Management

```bash
# Create the first admin user (interactive, prompts for password)
chainsmith auth create-user admin --role admin

# Create additional users
chainsmith auth create-user alice --role operator
chainsmith auth create-user bob --role viewer

# List users
chainsmith auth list-users

# Change password
chainsmith auth change-password alice

# Delete user
chainsmith auth delete-user bob

# Reset to no auth (removes all users, disables auth)
chainsmith auth reset --yes
```

### CLI Authentication

```bash
# Login (stores token in ~/.chainsmith/credentials)
chainsmith auth login
Username: admin
Password: ********
Authenticated. Token stored.

# Login non-interactively (for scripts/CI)
chainsmith auth login --username admin --password-stdin < secret.txt

# Check auth status
chainsmith auth status
Authenticated as: admin (role: admin)
Token expires: 2026-03-28T14:30:00Z

# Logout (removes stored token)
chainsmith auth logout
```

### Web UI Authentication

When auth is enabled, the web UI shows a login page before granting access.
The UI stores the JWT in a secure, httpOnly cookie (not localStorage) to
prevent XSS-based token theft.

Login flow:
1. User navigates to Chainsmith UI
2. Server returns login page (no observations data loaded)
3. User enters credentials
4. JavaScript sends POST /api/auth/login
5. Server sets httpOnly cookie with JWT
6. UI redirects to observations/scope page

### API Endpoints

```
POST   /api/auth/login           Authenticate, receive JWT
POST   /api/auth/refresh         Refresh token before expiry
POST   /api/auth/logout          Invalidate token (server-side)
GET    /api/auth/me              Current user info and role
POST   /api/auth/change-password Change own password
```

Admin-only:
```
GET    /api/auth/users           List all users
POST   /api/auth/users           Create user
DELETE /api/auth/users/{id}      Delete user
PUT    /api/auth/users/{id}/role Change user role
```

### Configuration

```yaml
# chainsmith.yaml
auth:
  enabled: false              # Default: no auth on localhost
  auto_enable_on_bind: true   # Auto-enable when binding to non-localhost
  jwt_secret: null            # Auto-generated on first user creation
  token_ttl_hours: 24         # JWT expiry
  max_failed_attempts: 5      # Lock account after N failures
  lockout_minutes: 15         # Lockout duration
```

```bash
# Environment variables
CHAINSMITH_AUTH_ENABLED=true
CHAINSMITH_JWT_SECRET=<secret>    # Override auto-generated secret
CHAINSMITH_TOKEN_TTL_HOURS=24
```

### Password Storage

- Passwords hashed with bcrypt (work factor 12)
- Stored in SQLite alongside observations data
- No plaintext passwords anywhere (config, logs, error messages)
- Password requirements: minimum 8 characters (no complexity rules —
  pentesters know about password security)

### Security Properties

- JWT signed with HS256 using a server-generated 256-bit secret
- Secret auto-generated on first user creation, stored in
  `~/.chainsmith/auth.key`
- Tokens are stateless (no server-side session store needed)
- Token revocation via server-side blacklist (for logout and user deletion)
- All auth endpoints rate-limited (5 attempts per minute per IP)
- Failed login attempts logged for audit trail

## Enterprise: OIDC Integration

For organizations with existing identity providers, Chainsmith supports
OIDC (OpenID Connect) as an authentication backend. This works with
Keycloak, Okta, Azure AD, Google Workspace, Auth0, and any OIDC-compliant
provider.

### How It Works

```
┌──────────┐                           ┌──────────────────┐
│  Browser  │  ── 1. Login click ──>   │   Chainsmith     │
│           │  <── 2. Redirect ──────  │   Server         │
│           │                          └────────┬─────────┘
│           │  ── 3. Authenticate ──>  ┌────────┴─────────┐
│           │  <── 4. Auth code ─────  │   OIDC Provider   │
│           │                          │  (Keycloak, Okta) │
│           │  ── 5. Code to server -> └──────────────────┘
│           │  <── 6. JWT (local) ───  Chainsmith exchanges
│           │                          code for OIDC token,
└──────────┘                           maps claims to role,
                                       issues local JWT
```

Chainsmith does NOT pass the OIDC token to the client. It exchanges the
OIDC token for claims (username, email, groups), maps those to a local
role, and issues its own JWT. This means:

- The OIDC provider handles authentication
- Chainsmith handles authorization (role mapping)
- Clients only deal with Chainsmith JWTs
- If the OIDC provider is unavailable after login, existing sessions
  continue to work

### Configuration

```yaml
# chainsmith.yaml
auth:
  enabled: true
  provider: oidc             # "local" (default) or "oidc"

  oidc:
    issuer_url: https://keycloak.example.com/realms/chainsmith
    client_id: chainsmith
    client_secret: <secret>
    scopes: ["openid", "profile", "email", "groups"]

    # Role mapping: OIDC group/claim -> Chainsmith role
    role_mapping:
      admin: ["chainsmith-admins"]
      operator: ["chainsmith-operators", "pentesters"]
      viewer: ["chainsmith-viewers", "security-team"]
      default_role: viewer    # Role when no group matches
```

```bash
# Environment variables
CHAINSMITH_AUTH_PROVIDER=oidc
CHAINSMITH_OIDC_ISSUER_URL=https://keycloak.example.com/realms/chainsmith
CHAINSMITH_OIDC_CLIENT_ID=chainsmith
CHAINSMITH_OIDC_CLIENT_SECRET=<secret>
```

### CLI with OIDC

```bash
# Browser-based login (opens browser for OIDC flow)
chainsmith auth login --oidc
Opening browser for authentication...
Authenticated as: alice@example.com (role: operator)
Token stored.

# Device code flow (for headless/SSH environments)
chainsmith auth login --oidc --device-code
Visit: https://keycloak.example.com/device
Enter code: ABCD-EFGH
Waiting for authentication...
Authenticated as: alice@example.com (role: operator)
```

### Keycloak Setup Guide

For teams choosing Keycloak specifically:

1. Create a realm: `chainsmith`
2. Create a client: `chainsmith` (confidential, standard flow)
3. Set redirect URI: `http://localhost:8000/api/auth/oidc/callback`
4. Create groups: `chainsmith-admins`, `chainsmith-operators`, `chainsmith-viewers`
5. Assign users to groups
6. Configure Chainsmith with the issuer URL, client ID, and secret

## Authorization: Role-Based Access Control

Regardless of authentication method (local JWT or OIDC), Chainsmith uses
the same RBAC model.

### Roles

| Role | Description |
|------|-------------|
| `viewer` | Read-only access to observations and reports |
| `operator` | Start/stop scans, manage scope, run analysis |
| `admin` | Full access including user management and settings |

### Permission Matrix

| Action | viewer | operator | admin |
|--------|--------|----------|-------|
| View observations | yes | yes | yes |
| Export reports | yes | yes | yes |
| View scan status | yes | yes | yes |
| View attack chains | yes | yes | yes |
| Start/stop scans | no | yes | yes |
| Set scope | no | yes | yes |
| Run chain analysis | no | yes | yes |
| Manage profiles/preferences | no | yes | yes |
| Load scenarios | no | yes | yes |
| Manage swarm agents | no | no | yes |
| Manage API keys | no | no | yes |
| Create/delete users | no | no | yes |
| Change settings | no | no | yes |
| View audit log | no | no | yes |
| Access /cache/clear, /reset | no | no | yes |

### API Enforcement

Every API route is annotated with a minimum required role. The auth
middleware checks:

1. Is auth enabled? If not, allow all requests (localhost default).
2. Is a valid JWT present? If not, return 401.
3. Does the JWT's role meet the minimum for this route? If not, return 403.

```python
# Example route decoration
@router.get("/api/observations")
@require_role("viewer")
async def get_observations():
    ...

@router.post("/api/scan/start")
@require_role("operator")
async def start_scan():
    ...

@router.post("/api/auth/users")
@require_role("admin")
async def create_user():
    ...
```

### Web UI Enforcement

The UI adapts based on role:

- **viewer**: Scan/scope controls hidden. Observations and visualizations
  visible. Export button visible.
- **operator**: Full scan controls visible. Settings drawer visible.
  User management hidden.
- **admin**: Everything visible including user management panel.

The UI reads the role from the JWT claims (client-side) for display
purposes, but all actual enforcement happens server-side. A modified
JWT with an upgraded role will fail server-side validation.

## Swarm Agent Authentication

Swarm agents use a separate auth mechanism from user auth (see
[swarm-architecture.md](swarm-architecture.md) for design and
[swarm-usage.md](swarm-usage.md) for setup instructions). The key
design decisions:

- **Agents authenticate with pre-shared API keys**, not user credentials
- **mTLS provides transport-level authentication** in production
- **Agent keys are managed by admins** via `chainsmith swarm generate-key`
- **Agent keys are scoped**: an agent key grants permission to execute
  assigned checks and submit results, nothing else
- **Agent keys cannot**: view other agents' results, access the UI, manage
  users, or modify scope

### How Agent Auth Relates to User Auth

| Concern | User Auth | Agent Auth |
|---------|-----------|------------|
| Identity | Username + password or OIDC | API key + optional mTLS |
| Trust model | Interactive human | Automated process |
| Credential storage | ~/.chainsmith/credentials | Agent config file |
| Scope of access | Role-based (viewer/operator/admin) | Fixed: execute + report |
| Session duration | 24 hours (JWT TTL) | Persistent (key-based) |
| Revocation | Logout / admin deletion | chainsmith swarm revoke-key |

Agent keys are stored in the same user store as user credentials but
flagged as service accounts. They appear in `chainsmith auth list-users`
with type "agent" for auditability.

## API Key Authentication

For programmatic access (CI/CD pipelines, scripts, integrations),
Chainsmith supports long-lived API keys as an alternative to
username/password login.

```bash
# Generate an API key (scoped to a role)
chainsmith auth create-api-key --name "ci-pipeline" --role viewer
API key created: cs_key_a1b2c3d4e5f6...
Store this key securely — it cannot be retrieved again.

# List API keys
chainsmith auth list-api-keys

# Revoke an API key
chainsmith auth revoke-api-key --name "ci-pipeline"
```

Usage:
```bash
# CLI
chainsmith --api-key cs_key_a1b2c3d4e5f6 scan example.com

# HTTP
curl -H "X-API-Key: cs_key_a1b2c3d4e5f6" http://localhost:8000/api/observations

# Environment variable
export CHAINSMITH_API_KEY=cs_key_a1b2c3d4e5f6
chainsmith scan example.com
```

API keys:
- Are hashed (bcrypt) before storage — the plaintext key is shown once
  at creation and cannot be retrieved
- Have a fixed role (cannot escalate)
- Can have optional expiry dates
- Are logged in the audit trail with the key name (not the key itself)
- Do not support refresh — if revoked, a new key must be created

## Audit Logging

When auth is enabled, all authenticated actions are logged:

```
2026-03-27T14:30:00Z [AUTH] user=admin action=login ip=192.168.1.5
2026-03-27T14:30:15Z [SCAN] user=admin action=start_scan target=example.com
2026-03-27T14:35:00Z [AUTH] user=bob action=login_failed ip=192.168.1.10 reason=invalid_password
2026-03-27T14:35:30Z [AUTH] user=bob action=account_locked ip=192.168.1.10 reason=max_attempts
2026-03-27T15:00:00Z [AGENT] key=dmz-scanner action=submit_results task=uuid-1234
2026-03-27T15:10:00Z [API] key=ci-pipeline action=export_observations format=sarif
```

Audit log stored in `~/.chainsmith/audit.log` (configurable path).
Retained for 90 days by default (configurable).

Admin-accessible via:
```bash
chainsmith auth audit-log [--since 2026-03-27] [--user admin] [--action login]
```

## Implementation Phases

### Phase 1: Built-in Token Auth (MVP)

- Local user store (SQLite)
- bcrypt password hashing
- JWT generation and validation
- CLI login/logout commands
- API middleware for role checking
- Web UI login page
- Auto-enable on non-localhost bind
- Basic audit logging

### Phase 2: API Keys and Polish

- Long-lived API key generation and revocation
- API key auth in CLI and HTTP
- Account lockout on failed attempts
- Password change CLI command
- Audit log CLI viewer
- Web UI role-based element visibility

### Phase 3: OIDC Integration

- OIDC discovery and authorization code flow
- Role mapping from OIDC groups/claims
- Browser-based CLI login (redirect flow)
- Device code flow for headless environments
- Token refresh via OIDC refresh tokens
- Keycloak setup documentation

### Phase 4: Advanced

- Multi-factor authentication (TOTP) for local auth
- Session management (list active sessions, force logout)
- IP allowlisting per user/role
- Temporary elevated access ("sudo mode" for operators)
- Integration with swarm agent key management

## Module Structure

```
app/
  auth/
    __init__.py
    middleware.py        # FastAPI middleware for JWT validation
    models.py            # User, APIKey, AuditEntry dataclasses
    jwt.py               # Token generation, validation, refresh
    store.py             # User/key storage (SQLite)
    oidc.py              # OIDC client (Phase 3)
    audit.py             # Audit logging
  routes/
    auth.py              # /api/auth/* endpoints
```

## Configuration Reference

### Full Configuration Example

```yaml
auth:
  # Core settings
  enabled: false                    # Enable authentication
  auto_enable_on_bind: true         # Auto-enable on non-localhost
  provider: local                   # "local" or "oidc"

  # JWT settings
  jwt_secret: null                  # Auto-generated if null
  token_ttl_hours: 24               # Token expiry
  refresh_ttl_hours: 168            # Refresh token expiry (7 days)

  # Security
  max_failed_attempts: 5            # Failed logins before lockout
  lockout_minutes: 15               # Lockout duration
  min_password_length: 8            # Minimum password length

  # OIDC settings (Phase 3)
  oidc:
    issuer_url: null
    client_id: null
    client_secret: null
    scopes: ["openid", "profile", "email", "groups"]
    role_mapping:
      admin: []
      operator: []
      viewer: []
      default_role: viewer

  # Audit
  audit:
    enabled: true
    log_path: ~/.chainsmith/audit.log
    retention_days: 90

  # API keys
  api_keys:
    max_per_user: 5                 # Maximum API keys per user
    default_expiry_days: null       # null = no expiry
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CHAINSMITH_AUTH_ENABLED` | Enable authentication | false |
| `CHAINSMITH_JWT_SECRET` | JWT signing secret | auto-generated |
| `CHAINSMITH_TOKEN_TTL_HOURS` | Token expiry | 24 |
| `CHAINSMITH_AUTH_PROVIDER` | Auth provider (local/oidc) | local |
| `CHAINSMITH_OIDC_ISSUER_URL` | OIDC issuer URL | - |
| `CHAINSMITH_OIDC_CLIENT_ID` | OIDC client ID | - |
| `CHAINSMITH_OIDC_CLIENT_SECRET` | OIDC client secret | - |
| `CHAINSMITH_API_KEY` | API key for CLI/scripts | - |
| `CHAINSMITH_AUDIT_LOG_PATH` | Audit log file path | ~/.chainsmith/audit.log |
