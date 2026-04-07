# Instance Authentication & NIST CUI Compliance

Plan for hardening Chainsmith's authentication and session management to
meet NIST 800-171 requirements for Controlled Unclassified Information (CUI).

This document builds on [authentication-authorization.md](authentication-authorization.md),
which defines the authentication mechanisms (JWT, OIDC, RBAC, swarm API keys).
This document covers the compliance posture, session management hardening, and
MFA roadmap.

## Problem Statement

Chainsmith stores security assessment data — findings with extracted evidence,
attack chains, engagement details, client metadata — that qualifies as CUI
under NIST 800-171. The existing auth design covers *mechanisms* (how users
authenticate) but not *compliance* (what controls are required, how sessions
are managed, what audit obligations exist).

This plan bridges that gap: which NIST 800-171 controls apply to Chainsmith,
how to implement them incrementally, and where the current design has gaps.

## NIST 800-171 Control Mapping

### 3.1 — Access Control (AC)

| Control | Requirement | Status | Approach |
|---------|-------------|--------|----------|
| 3.1.1 | Limit system access to authorized users | **Designed** | JWT auth with role enforcement; auto-enable on non-localhost bind |
| 3.1.2 | Limit system access to authorized transactions/functions | **Designed** | RBAC: viewer/operator/admin permission matrix |
| 3.1.3 | Control CUI flow in accordance with approved authorizations | **Gap** | Need data classification + export controls per role |
| 3.1.4 | Separate duties to reduce risk of malicious activity | **Partial** | Role separation exists; no separation between scan execution and finding modification |
| 3.1.5 | Employ principle of least privilege | **Designed** | Role-based; swarm agents scoped to execute+report only |
| 3.1.7 | Prevent non-privileged users from executing privileged functions | **Designed** | API middleware checks role per route |
| 3.1.8 | Limit unsuccessful login attempts | **Designed** | 5-attempt lockout, 15-minute cooldown |
| 3.1.10 | Use session lock after inactivity | **Gap** | No idle timeout or session lock implemented |
| 3.1.11 | Terminate sessions after defined conditions | **Gap** | JWT TTL exists (24h) but no idle timeout, no forced termination |

### 3.5 — Identification and Authentication (IA)

| Control | Requirement | Status | Approach |
|---------|-------------|--------|----------|
| 3.5.1 | Identify and authenticate users/devices/processes | **Designed** | Users: JWT; swarm agents: API keys; CLI: stored tokens |
| 3.5.2 | Authenticate devices connecting to the system | **Partial** | Swarm agents use API keys; mTLS planned but not implemented |
| 3.5.3 | Use multifactor authentication for network access | **Gap** | MFA not implemented; roadmap below |
| 3.5.4 | Employ replay-resistant authentication | **Designed** | JWT with expiry; refresh tokens time-bound |
| 3.5.7 | Enforce minimum password complexity | **Designed** | 8-char minimum; bcrypt work factor 12 |
| 3.5.8 | Prohibit password reuse for a defined number of generations | **Gap** | No password history tracked |
| 3.5.9 | Allow temporary passwords for initial login only | **Gap** | No forced-change-on-first-login mechanism |

### 3.3 — Audit and Accountability (AU)

| Control | Requirement | Status | Approach |
|---------|-------------|--------|----------|
| 3.3.1 | Create and retain audit records | **Designed** | Audit log in existing auth doc; 90-day retention |
| 3.3.2 | Ensure actions can be traced to individual users | **Designed** | JWT contains user ID; audit log captures user+action+IP |
| 3.3.4 | Alert on audit process failure | **Gap** | No alerting if audit log write fails |
| 3.3.5 | Correlate audit review/analysis/reporting | **Gap** | Audit log is flat file; no structured querying beyond grep |
| 3.3.8 | Protect audit information from unauthorized access | **Gap** | Audit log is a plaintext file; needs access controls |
| 3.3.9 | Limit audit log management to authorized individuals | **Partial** | CLI `audit-log` command is admin-only; file system permissions not enforced |

### 3.13 — System and Communications Protection (SC)

| Control | Requirement | Status | Approach |
|---------|-------------|--------|----------|
| 3.13.1 | Monitor/control communications at external boundaries | **Gap** | No TLS enforcement; Chainsmith serves HTTP by default |
| 3.13.8 | Implement cryptographic mechanisms to prevent unauthorized disclosure during transmission | **Gap** | TLS not enforced even when auth is enabled |
| 3.13.10 | Establish and manage cryptographic keys | **Partial** | JWT secret auto-generated; no formal key management |

## Session Management Requirements

The existing auth design uses stateless JWTs with a 24-hour TTL. NIST 800-171
requires more granular session controls. This means adding a server-side
session registry even though JWTs are structurally stateless.

### Session Tracking Table

```sql
CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,        -- UUID
    user_id         INTEGER NOT NULL,
    token_jti       TEXT NOT NULL UNIQUE,     -- JWT ID claim (links JWT to session)
    created_at      TIMESTAMP NOT NULL,
    last_activity   TIMESTAMP NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    is_locked       BOOLEAN DEFAULT FALSE,   -- Session locked (idle) vs terminated
    terminated_at   TIMESTAMP,               -- NULL if active
    terminated_by   TEXT,                     -- 'idle_timeout', 'admin', 'logout', 'max_sessions'
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Session Lifecycle

```
Login
  │
  ├─ Create session record
  ├─ Issue JWT with jti claim matching session.token_jti
  ├─ Record IP + user agent
  │
  ▼
Active Session
  │
  ├─ Each API request updates last_activity
  ├─ Middleware checks: session exists, not terminated, not locked, not idle-timed-out
  │
  ├─── Idle timeout reached ──► Session LOCKED (UI shows lock screen, re-auth required)
  ├─── Absolute timeout (24h) ─► Session TERMINATED
  ├─── Admin force-kill ───────► Session TERMINATED (terminated_by = 'admin')
  ├─── Max concurrent reached ─► Oldest session TERMINATED (terminated_by = 'max_sessions')
  └─── User logout ───────────► Session TERMINATED (terminated_by = 'logout')
```

### Configuration

```yaml
auth:
  session:
    idle_timeout_minutes: 30        # NIST CUI default; lock after 30 min inactivity
    absolute_timeout_hours: 24      # Matches existing JWT TTL
    max_concurrent_sessions: 3      # Per user; oldest killed when exceeded
    lock_on_idle: true              # Lock (re-auth) vs terminate on idle
    show_previous_login: true       # Display last login time/IP after auth
```

### Idle Timeout vs Session Lock

NIST 800-171 3.1.10 requires session lock, not session termination, on idle.
The distinction matters:

- **Session lock**: UI shows a lock overlay requiring password re-entry.
  The session remains valid on the server. User re-authenticates to resume.
  No data loss (unsaved UI state preserved if feasible).
- **Session terminate**: Session destroyed. User must fully re-login.
  Any unsaved state is lost.

Default behavior: **lock on idle** (30 min), **terminate on absolute timeout**
(24h). Configurable per deployment.

### Previous Login Notification

On successful authentication, the response includes:

```json
{
  "token": "eyJ...",
  "user": { "id": 1, "username": "admin", "role": "admin" },
  "previous_login": {
    "at": "2026-04-05T09:15:00Z",
    "ip": "192.168.1.5",
    "user_agent": "Mozilla/5.0..."
  }
}
```

This allows users to detect unauthorized access to their account. The UI
should display this prominently on login.

### Admin Session Management

Admins can view and kill active sessions:

```
GET    /api/auth/sessions              List all active sessions
GET    /api/auth/sessions/me           List own sessions
DELETE /api/auth/sessions/{id}         Force-terminate a session
DELETE /api/auth/sessions/user/{id}    Force-terminate all sessions for a user
```

CLI:
```bash
chainsmith auth sessions list
chainsmith auth sessions kill <session-id>
chainsmith auth sessions kill-user <username>
```

## Swarm Node Considerations

Swarm agents use API keys, not user sessions — they are not subject to
session idle timeout. However, swarm traffic carries CUI (findings, evidence,
task payloads) and has its own compliance requirements.

### Transport Security

| Deployment | Minimum | Recommended |
|------------|---------|-------------|
| Local (127.0.0.1) | None | None |
| LAN (trusted network) | TLS 1.2+ | TLS 1.3 |
| WAN / Cloud | TLS 1.3 | mTLS |

When `auth.enabled: true`, Chainsmith should **refuse** to start on a
non-localhost bind without TLS configured. This can be overridden with
`--allow-insecure` for lab environments, but must be a conscious decision.

```yaml
tls:
  enabled: false              # Auto-enabled with auth on non-localhost
  cert_path: null             # Path to TLS certificate
  key_path: null              # Path to TLS private key
  require_client_cert: false  # mTLS: require agent certificates
  min_version: "1.2"          # Minimum TLS version
```

### Agent Key Lifecycle

- **Generation**: Admin generates key via CLI or API
- **Distribution**: Out of band (secure channel to agent operator)
- **Rotation**: Configurable max age; CLI warns when keys approach expiry
- **Revocation**: Immediate via `chainsmith swarm revoke-key <name>`
- **Audit**: All agent actions logged with key name

Recommended rotation schedule for CUI environments: 90 days.

```yaml
swarm:
  key_max_age_days: 90          # Warn when key approaches this age
  key_expiry_enabled: false     # Hard expiry (reject expired keys)
```

### Agent Activity Audit

The existing audit log captures agent registration and result submission.
For CUI compliance, also log:

- Task assignment (which agent received which check for which target)
- Task payload contents summary (check name, target, not full evidence)
- Agent key age warnings
- Failed agent authentication attempts

## Password History & Temporary Passwords

### Password History (3.5.8)

Track last N password hashes to prevent reuse:

```sql
CREATE TABLE password_history (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    changed_at  TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

Configuration: `auth.password_history_count: 12` (NIST recommends
prohibiting reuse of last 12 passwords).

### Forced Change on First Login (3.5.9)

Users created by an admin receive a temporary password and a
`must_change_password` flag. On first login:

1. Authentication succeeds
2. Server returns a restricted JWT with `password_change_required: true`
3. Client is redirected to change-password flow
4. Only `POST /api/auth/change-password` is allowed with this token
5. After password change, a normal JWT is issued

## MFA Roadmap

MFA is a far-future feature but the design should accommodate it now.
No code changes are needed yet — this section documents the target design.

### Phase 3: TOTP (RFC 6238)

Default second factor. Works offline, no external dependencies.

```
Enrollment:
  1. User initiates MFA setup (CLI or UI)
  2. Server generates TOTP secret, returns QR code + recovery codes
  3. User scans QR code with authenticator app
  4. User enters verification code to confirm setup
  5. Server stores encrypted TOTP secret in user record

Login with MFA:
  1. User provides username + password → server validates
  2. Server returns 401 with `mfa_required: true` and a short-lived challenge token
  3. User provides TOTP code + challenge token
  4. Server validates TOTP code → issues full JWT
```

User table additions:
```sql
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret_encrypted TEXT;  -- AES-256-GCM encrypted TOTP secret
ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT;    -- JSON array of hashed recovery codes
```

### MFA Policy Configuration

```yaml
auth:
  mfa:
    enabled: false                  # Global MFA availability
    required_for_roles: []          # e.g., ["admin"] — require MFA for specific roles
    enforcement: optional           # "optional", "required", "role-based"
    recovery_code_count: 10         # Number of one-time recovery codes
    totp_issuer: "Chainsmith"       # Display name in authenticator apps
```

### Phase 4: WebAuthn / FIDO2 (Stretch)

Hardware security keys and biometric auth. Depends on browser-based
UI — not applicable to CLI-only usage without a device code flow.

Design considerations:
- WebAuthn requires a relying party ID (domain) — localhost
  complicates this
- CLI users would need a browser-based flow to register/use hardware keys
- Could pair with OIDC — let the IdP handle WebAuthn, Chainsmith
  consumes the assertion

## Implementation Phases

### Phase 1 — Session Hardening (Near-Term)

- [ ] Session tracking table (SQLite/PostgreSQL)
- [ ] Middleware: validate session exists and is active on every authed request
- [ ] Idle timeout enforcement (update `last_activity`, check on request)
- [ ] Concurrent session limit (terminate oldest when exceeded)
- [ ] TLS enforcement when auth is enabled on non-localhost
- [ ] Audit log: add session lifecycle events (create, lock, terminate)
- [ ] Previous login notification in auth response

### Phase 2 — Compliance Polish (Mid-Term)

- [ ] Session lock (UI lock screen with re-auth) vs session terminate distinction
- [ ] Admin session management API and CLI commands
- [ ] Password history tracking (prevent reuse of last 12)
- [ ] Temporary password / forced change on first login
- [ ] Structured audit log (JSON) with query API
- [ ] Audit log integrity protection (append-only, checksummed)
- [ ] NIST 800-171 self-assessment checklist

### Phase 3 — MFA (Future)

- [ ] TOTP enrollment and verification flow
- [ ] Recovery codes generation and redemption
- [ ] MFA policy configuration (per-role enforcement)
- [ ] CLI MFA flow (challenge-response)
- [ ] UI MFA enrollment page with QR code

### Phase 4 — Advanced (Far Future)

- [ ] WebAuthn / FIDO2 support
- [ ] Hardware key registration
- [ ] Adaptive authentication (risk-based MFA challenges)
- [ ] IP allowlisting per user/role
- [ ] Temporary elevated access ("sudo mode" for operators)

## Open Questions

1. **Session storage location**: Should the sessions table live in the main
   Chainsmith database alongside findings, or in a separate auth database?
   Colocating is simpler; separating isolates auth state from scan data.

2. **Session state across restarts**: If Chainsmith restarts, should all
   sessions be invalidated? For CUI, this might be desirable (forces
   re-auth). But it's disruptive for team deployments.

3. **Swarm agent idle timeout**: Should agents that haven't polled for tasks
   within a configurable window be automatically deregistered? Current design
   uses heartbeat monitoring — should this tie into the session framework or
   remain separate?

4. **FIPS 140-2 validated crypto**: NIST 800-171 references FIPS-validated
   cryptographic modules. Python's `hashlib` and `hmac` use OpenSSL, which
   has FIPS-validated builds, but the default Python distribution does not
   ship one. Is FIPS validation a hard requirement for target deployments?

5. **Audit log tamper resistance**: For CUI, audit logs should be protected
   from modification. Options: append-only file with HMAC chain,
   write-once storage, or external log shipping (syslog, SIEM). Which
   approach fits the deployment model?

6. **OIDC session synchronization**: When using OIDC, should Chainsmith's
   session lifetime be bound to the OIDC token lifetime? If the IdP revokes
   the user, Chainsmith's local JWT remains valid until expiry. Should there
   be periodic OIDC token introspection?
