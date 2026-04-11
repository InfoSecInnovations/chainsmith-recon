# Phase 32 — NIST 800-171 CUI Hardening for Scan Results and Reports

Captured 2026-04-08.

Status: Design — Open Questions Resolved

---

## Motivation

Chainsmith scan results contain detailed vulnerability intelligence:
target hostnames, exploit evidence, attack chains, raw HTTP responses,
and severity assessments. When Chainsmith is used against systems that
process, store, or transmit Controlled Unclassified Information (CUI),
the scan output itself becomes CUI — it is a detailed map of
exploitable weaknesses in CUI-handling infrastructure.

Today, Chainsmith has **zero protections** on this data:

- Reports served over HTTP with no authentication or authorization.
- Database stores observations, evidence, and raw data in plaintext.
- Scratch fallback writes unencrypted JSON to the local filesystem.
- No audit trail of who generated or accessed reports.
- No integrity verification (signatures, HMACs) on exported reports.
- No data retention or destruction controls.

This phase brings Chainsmith into alignment with the NIST SP 800-171
Rev 2 control families relevant to protecting scan output as CUI.

---

## Applicable NIST 800-171 Control Families

Not every family applies to a scanning tool. The table below maps
relevant controls to concrete Chainsmith changes.

| Family | ID Range | Relevance to Chainsmith |
|--------|----------|-------------------------|
| 3.1 Access Control | 3.1.1 – 3.1.22 | Who can generate/view/export reports |
| 3.3 Audit & Accountability | 3.3.1 – 3.3.2 | Log every report access and export |
| 3.5 Identification & Auth | 3.5.1 – 3.5.11 | Authenticate users before report access |
| 3.8 Media Protection | 3.8.1 – 3.8.9 | Protect exported report files, sanitize/destroy |
| 3.13 SC Protection | 3.13.1 – 3.13.16 | Encrypt CUI in transit and at rest |
| 3.14 SI Integrity | 3.14.1 – 3.14.7 | Detect tampering of stored/exported reports |

---

## Work Items

### 1. Encryption at Rest — Database (3.13.16)

**Problem:** SQLite database stores all observations, evidence, raw
data, and chain analyses in plaintext.

**Decision:** Column-level Fernet encryption on sensitive fields.

**Approach:**
- Use `cryptography.fernet` (AES-128-CBC + HMAC-SHA256) to encrypt
  sensitive columns: observation evidence, raw data, chain analysis
  content. Non-sensitive metadata (scan IDs, timestamps, severity
  levels, hostnames, fingerprints) remains in plaintext and queryable.
- Fernet is sufficient for CUI — both AES-128 and AES-256 are
  FIPS-approved algorithms, and CUI does not require AES-256.
- Encryption key sourced from environment variable
  (`CHAINSMITH_CUI_KEY`), consistent with existing `CHAINSMITH_*`
  env var convention. OS keychain via `keyring` library documented
  as an upgrade path for desktop/workstation use (see Future Work).
- Key never stored alongside the database file. In `cui_mode`,
  startup fails if no key is configured.
- Encrypted columns are not used as query predicates in the current
  codebase (observations are looked up by fingerprint, scan_id,
  severity, host), so the loss of SQL queryability on those fields
  has no practical impact.
- Implement an encrypted column type or mixin in the model layer
  that handles transparent encrypt-on-write / decrypt-on-read.

**Files touched:**
- `app/db/models.py` — encrypted column type or mixin on sensitive fields
- `app/config.py` — encryption key configuration, key validation

### 2. Encryption at Rest — Scratch Fallback (3.13.16, 3.8.3)

**Problem:** When the DB writer fails, observations are dumped as
plaintext JSON under `~/.chainsmith/scratch/<scan_id>/`.

**Decision:** Encrypt scratch files with the same Fernet key as item 1.

**Approach:**
- Encrypt scratch JSON files using Fernet with the same
  `CHAINSMITH_CUI_KEY` used for database column encryption.
- Set restrictive file permissions (0600) on creation.
- Add a `scratch import` CLI command that decrypts and replays
  scratch observations into the database.

**Files touched:**
- `app/db/writers.py` — encrypt on fallback write
- `app/cli.py` — `scratch import` subcommand

### 3. Encryption in Transit — TLS Enforcement (3.13.1, 3.13.8)

**Problem:** FastAPI dev server serves reports over plain HTTP.

**Proposed change:**
- Add TLS configuration to the launcher (cert/key path in config).
- When TLS is configured, redirect HTTP to HTTPS and set HSTS
  headers on all responses.
- Document recommended deployment behind a reverse proxy (nginx,
  Caddy) with TLS termination as the production path.
- Reject report generation requests over non-TLS connections when
  `cui_mode` is enabled (see item 10).

**Files touched:**
- `app/launcher.py` — uvicorn SSL kwargs
- `app/config.py` — TLS cert/key/cui_mode settings
- `app/middleware.py` (new or existing) — HSTS / redirect middleware

### 4. Authentication on Report Endpoints (3.5.1, 3.5.2, 3.1.1)

**Problem:** All five report endpoints (`/api/v1/reports/{type}`) are
unauthenticated. Anyone with network access can generate full
vulnerability reports.

**Decision:** Multi-user with individual accounts, extending the
existing swarm auth pattern.

**Approach:**
- Extend the existing `app/swarm/auth.py` pattern (API keys stored
  as SHA-256 hashes, Bearer token validation, FastAPI dependency
  injection) to a general-purpose auth system.
- New `User` and `ApiKey` models — each user gets individual API
  keys for audit attribution.
- Every report endpoint requires a valid token via `Authorization:
  Bearer <token>` header.
- CLI reads the token from config/environment.
- Per-user watermarking automatic in `cui_mode`: reports include
  `"Generated by {user} at {timestamp}"` in metadata/footer for
  leak attribution.
- Live observation stream endpoints (scan status, progress) are
  included in auth enforcement — no separate work item needed since
  TLS (item 3) covers transit encryption and auth gates access.

**Files touched:**
- `app/db/models.py` — `User`, `ApiKey` models
- `app/routes/auth.py` (new) — token issuance / validation
- `app/routes/scan_history.py` — dependency injection for auth
- `app/middleware.py` — global auth enforcement when cui_mode on
- `app/reports.py` — per-user watermark embedding

### 5. Role-Based Access Control (3.1.1, 3.1.2, 3.1.5)

**Problem:** No concept of least privilege — if you can reach the
API, you can do anything.

**Proposed change:**
- Define roles: `operator` (run scans, view own results), `analyst`
  (generate reports, view all results), `admin` (manage users,
  export, configure).
- Report generation restricted to `analyst` and above.
- Raw data / evidence export restricted to `admin`.
- Role stored on the User model; checked via FastAPI dependency.

**Consideration:** This is heavyweight for a single-user tool.
Consider a `cui_mode` flag that enables RBAC only when needed,
leaving the current open behavior as the default for non-CUI use.

**Files touched:**
- `app/db/models.py` — role field on User
- `app/routes/` — role-check dependencies on protected endpoints

### 6. Audit Logging (3.3.1, 3.3.2)

**Problem:** No record of who generated, viewed, or exported reports.

**Proposed change:**
- New `AuditLog` database table: timestamp, user_id, action
  (report_generated, report_exported, scan_started, data_deleted),
  resource_id, source_ip, detail.
- Log entries written on every report endpoint call, scan launch,
  and data deletion.
- Audit log itself is append-only (no UPDATE/DELETE allowed via the
  application layer).
- CLI command `chainsmith audit-log [--since DATE] [--user USER]`
  to review.
- Audit log entries are not encrypted (they contain no CUI — only
  action metadata) but are integrity-protected (see item 8).
- **Periodic export for anti-tampering:** configurable
  `audit_export_interval_days` setting (e.g., 30 days). In
  `cui_mode`, CLI warns on startup if the last export is older than
  the configured interval. `chainsmith audit-log export --format
  json` writes a signed export file (HMAC integrity, same approach
  as report signatures in item 7). The exported file includes the
  full hash chain so integrity can be independently verified outside
  Chainsmith. This ensures the audit trail survives database loss.
- Audit logs have a separate retention setting
  (`audit_retention_days`) since they typically need to be kept
  longer than scan data for compliance evidence.

**Files touched:**
- `app/db/models.py` — `AuditLog` model
- `app/db/repositories.py` — audit write helper
- `app/routes/scan_history.py` — emit audit events
- `app/cli.py` — `audit-log` subcommand, export and startup warning
- `app/config.py` — `audit_export_interval_days`, `audit_retention_days`

### 7. Report Integrity Signatures (3.14.1, 3.14.2)

**Problem:** Exported reports (PDF, JSON, SARIF, HTML) have no
integrity verification. A report could be silently altered after
export.

**Proposed change:**
- On report export, compute an HMAC-SHA256 over the report content
  using a signing key (derived from the encryption key or a separate
  signing key).
- Embed the HMAC in report metadata:
  - JSON/SARIF: top-level `"integrity"` field.
  - PDF: custom metadata property.
  - HTML: `<meta name="chainsmith-integrity">` tag.
  - Markdown: YAML frontmatter.
- CLI command `chainsmith verify-report <file>` to validate.
- Optionally support Ed25519 signatures for non-repudiation (Phase
  32b — requires key management beyond a shared secret).

**Files touched:**
- `app/reports.py` — HMAC computation and embedding per format
- `app/cli.py` — `verify-report` subcommand

### 8. Audit Log Integrity (3.3.1)

**Problem:** If the audit log can be silently modified, it loses
evidentiary value.

**Proposed change:**
- Each audit log entry includes an HMAC of its content + the
  previous entry's HMAC (hash chain), making tampering detectable.
- CLI `chainsmith audit-log --verify` walks the chain and flags
  breaks.

**Files touched:**
- `app/db/models.py` — `prev_hmac`, `entry_hmac` fields on AuditLog
- `app/db/repositories.py` — chain computation on insert
- `app/cli.py` — `--verify` flag

### 9. Data Retention and Sanitization (3.8.3, 3.8.5)

**Problem:** Scan data accumulates indefinitely with no mechanism to
purge old results or sanitize exported media.

**Proposed change:**
- Configurable retention policy: auto-archive scans older than N
  days, auto-delete after M days.
- `retention_days` defaults to `null` (no auto-purge). In
  `cui_mode`, this must be explicitly set — forces the operator to
  make a conscious decision about retention.
- `chainsmith purge --older-than 90d` CLI command for manual cleanup.
- Purge writes an audit log entry before deletion.
- Scratch directory cleanup included in purge.
- Document guidance for secure deletion of the SQLite file (e.g.,
  `shred` on Linux, Cipher /W on Windows).

**Files touched:**
- `app/config.py` — retention settings
- `app/db/repositories.py` — purge queries
- `app/cli.py` — `purge` subcommand

### 10. CUI Mode Toggle (meta-control)

**Problem:** Chainsmith is used in both casual and regulated
contexts. Enforcing all CUI controls by default would hurt usability
for non-regulated users.

**Proposed change:**
- Add a `cui_mode: bool` configuration flag (default: false).
- When `cui_mode` is true:
  - TLS required (item 3).
  - Authentication required (item 4).
  - RBAC enforced (item 5).
  - Audit logging enabled (item 6).
  - Report integrity signatures auto-appended (item 7).
  - Per-user watermarking auto-appended on reports (item 4).
  - Encryption at rest required — startup fails if no key is
    configured via `CHAINSMITH_CUI_KEY` (items 1-2).
  - Retention policy must be explicitly set (item 9).
  - Audit export interval must be set (item 6).
  - Swarm mode is blocked — startup rejects enabling both
    `cui_mode` and swarm until swarm CUI support is implemented
    (see Phase 33).
- When false, current behavior is preserved.
- `chainsmith config cui-mode enable` wizard walks through required
  settings.

**Files touched:**
- `app/config.py` — `cui_mode` flag
- `app/launcher.py` — startup validation when cui_mode is on
- `app/cli.py` — `config cui-mode` subcommand

### 11. Database Encryption Migration (3.13.16)

**Problem:** Enabling encryption at rest on an existing database
requires migrating existing plaintext data. Telling users to start
fresh means losing historical scan data and vulnerability trends.

**Decision:** Provide CLI migration commands.

**Approach:**
- `chainsmith db encrypt` — reads each row with sensitive columns,
  encrypts with the configured Fernet key, writes back. One-time
  batch operation with progress bar and `--dry-run` flag.
- `chainsmith db decrypt` — reverse operation for disabling CUI
  mode or migrating to a different encryption approach.
- Migration logic lives in `app/db/migration.py` (new), keeping
  `app/cli.py` thin (argument parsing only).

**Files touched:**
- `app/db/migration.py` (new) — batch encrypt/decrypt logic,
  progress tracking, dry-run support
- `app/cli.py` — `db encrypt` and `db decrypt` subcommands

---

## CUI Marking and Banner (3.1.3, 3.8.4)

Reports generated in `cui_mode` should carry appropriate CUI
markings per 32 CFR Part 2002:

- Header/footer banner: `CUI // SP-VULN` (Special Category:
  Vulnerability Information) or the appropriate CUI category
  designated by the organization.
- Page-level marking on PDF reports.
- JSON/SARIF: `"classification": "CUI"` metadata field.
- HTML: visible banner div at top of report.

The exact CUI category and dissemination controls depend on the
organization's CUI registry entry. Chainsmith should make the
banner text configurable (`cui_banner` in config).

---

## Suggested Implementation Order

| Phase | Items | Rationale |
|-------|-------|-----------|
| 32a | 10, 3, 4 | CUI mode toggle + TLS + auth — minimum viable protection |
| 32b | 1, 2, 11 | Encryption at rest + migration tooling — protects stored CUI |
| 32c | 6, 8 | Audit logging with integrity chain and export |
| 32d | 7 | Report integrity signatures |
| 32e | 5 | RBAC (only needed for multi-user deployments) |
| 32f | 9 | Retention and sanitization |

---

## Out of Scope

- FIPS 140-2 validated cryptographic modules (would require
  certified OpenSSL build — significant operational burden).
- Physical security controls (3.10.x) — outside software scope.
- Personnel security (3.9.x) — organizational policy, not code.
- Incident response procedures (3.6.x) — documented separately.
- Full FedRAMP/CMMC assessment — this phase addresses the technical
  controls only. Organizational policies, SSP documentation, and
  POA&M tracking are outside Chainsmith's scope.
- Swarm/distributed CUI hardening — deferred to Phase 33 (see
  below).

---

## Resolved Design Decisions

Resolved 2026-04-10.

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | Encryption engine | Column-level Fernet | Pure Python, no native deps, preserves PostgreSQL path. Encrypted fields are not used as query predicates. |
| 2 | Authentication model | Multi-user with individual accounts | Extends existing swarm auth pattern. Required for audit attribution (3.3.1). |
| 3 | Key management | Env var (`CHAINSMITH_CUI_KEY`) primary | Fits existing `CHAINSMITH_*` convention. OS keychain via `keyring` as upgrade path (see Future Work). |
| 4 | CUI category | Configurable, default `CUI // SP-VULN` | Correct default for vuln scanning output. Orgs override via `cui_banner` config. |
| 5 | FIPS mode | FIPS algorithms via standard libraries | AES-128 (Fernet) + HMAC-SHA256 are FIPS-approved. Full FIPS-validated builds are out of scope. |
| 6 | Report watermarking | Yes, automatic in `cui_mode` | Low effort, high value. `"Generated by {user} at {timestamp}"` in report metadata/footer. |
| 7 | Swarm CUI | Deferred to Phase 33 | Scope too large (mTLS, encrypted payloads, distributed audit). `cui_mode` + swarm blocked at startup until Phase 33. |
| 8 | Retention requirements | Configurable, no hardcoded minimum | Different CUI programs differ. `retention_days` required in `cui_mode`. Audit logs get separate `audit_retention_days`. Periodic signed export for anti-tampering. |
| 9 | Scope of "reports" | Covered by auth + TLS | Live stream protected by auth gate (item 4) and TLS (item 3). No separate work item. |
| 10 | Database migration | Provide `chainsmith db encrypt/decrypt` CLI | Avoids losing historical data. Logic in `app/db/migration.py`, CLI stays thin. |

---

## Phase 33 — Swarm CUI Hardening (Deferred)

Swarm/distributed mode transmits full observation data between
coordinator and agents. CUI hardening for swarm requires:

- Mutual TLS (mTLS) between coordinator and all agents.
- Encrypted task payloads (observations, evidence) in transit
  beyond what transport-level TLS provides.
- Agent identity verification and per-agent audit attribution.
- Distributed audit logging with chain integrity across nodes.
- Topology-aware key distribution.

This is a separate phase because the swarm feature is still in
active development and the scope is significantly larger than the
single-instance hardening in Phase 32. Until Phase 33 is complete,
`cui_mode` and swarm mode are mutually exclusive — startup
validation rejects enabling both.

---

## Future Work

- **OS keychain integration:** Support `keyring` library as an
  alternative to environment variables for `CHAINSMITH_CUI_KEY` on
  desktop/workstation deployments.
- **External KMS:** HashiCorp Vault, AWS KMS, Azure Key Vault
  integration for enterprise key management.
- **External auth:** Reverse proxy with client certs, SSO/OIDC
  integration for organizations with existing identity providers.
- **Ed25519 signatures:** Non-repudiation for report integrity
  (requires key management beyond a shared secret).
- **FIPS-validated builds:** Certified OpenSSL build for
  organizations that require FIPS 140-2 validated modules.
