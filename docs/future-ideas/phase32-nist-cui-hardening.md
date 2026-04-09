# Phase 32 — NIST 800-171 CUI Hardening for Scan Results and Reports

Captured 2026-04-08.

Status: Design / Open Questions

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

**Proposed change:**
- Integrate SQLCipher (or application-level column encryption via
  `cryptography.fernet`) for the observation and chain tables.
- Encryption key derived from a passphrase or pulled from an
  external secrets manager (environment variable, HashiCorp Vault,
  AWS KMS reference).
- Key never stored alongside the database file.

**Trade-offs:**
- SQLCipher requires a native library dependency (complicates
  cross-platform installs).
- Column-level Fernet encryption is pure Python but breaks SQL
  queries against encrypted fields (full-text search on evidence
  would require decryption).
- Performance impact on large scan histories needs benchmarking.

**Files touched:**
- `app/db/engine.py` — connection string / pragma changes
- `app/db/models.py` — encrypted column type or mixin
- `app/config.py` — encryption key configuration

### 2. Encryption at Rest — Scratch Fallback (3.13.16, 3.8.3)

**Problem:** When the DB writer fails, observations are dumped as
plaintext JSON under `~/.chainsmith/scratch/<scan_id>/`.

**Proposed change:**
- Encrypt scratch files using Fernet with the same key as item 1.
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

**Proposed change:**
- Implement token-based authentication (API key or JWT).
- API keys stored as salted hashes in the database (new `User` /
  `ApiKey` model).
- Every report endpoint requires a valid token via `Authorization:
  Bearer <token>` header.
- CLI prompts for or reads the token from config/environment.

**Open question:** Should this be a full user/role system, or is a
single shared API key sufficient for the initial implementation?
See questions section.

**Files touched:**
- `app/db/models.py` — `User`, `ApiKey` models
- `app/routes/auth.py` (new) — token issuance / validation
- `app/routes/scan_history.py` — dependency injection for auth
- `app/middleware.py` — global auth enforcement when cui_mode on

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

**Files touched:**
- `app/db/models.py` — `AuditLog` model
- `app/db/repositories.py` — audit write helper
- `app/routes/scan_history.py` — emit audit events
- `app/cli.py` — `audit-log` subcommand

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
  - Encryption at rest required — startup fails if no key is
    configured (items 1-2).
  - Retention policy must be set (item 9).
- When false, current behavior is preserved.
- `chainsmith config cui-mode enable` wizard walks through required
  settings.

**Files touched:**
- `app/config.py` — `cui_mode` flag
- `app/launcher.py` — startup validation when cui_mode is on
- `app/cli.py` — `config cui-mode` subcommand

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
| 32b | 1, 2 | Encryption at rest — protects stored CUI |
| 32c | 6, 8 | Audit logging with integrity chain |
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

---

## Open Questions

1. **Encryption engine:** SQLCipher (transparent, requires native
   dep) vs. application-level Fernet (pure Python, breaks SQL
   queries on encrypted columns)? A hybrid approach — SQLCipher for
   the full database when available, Fernet for specific columns as
   fallback — adds complexity. What's the preferred trade-off?

2. **Authentication model:** Single shared API key (simple, fits
   single-operator use) vs. multi-user with individual accounts
   (needed for audit attribution and RBAC)? The audit logging
   requirement (3.3.1) calls for individual accountability, which
   pushes toward per-user accounts. Is multi-user in scope for
   Chainsmith, or would external auth (reverse proxy with client
   certs, SSO) be preferred?

3. **Key management:** Where should the encryption/signing key live?
   Options: environment variable, config file with restrictive
   permissions, OS keychain (keyring library), or external KMS
   (Vault, AWS KMS). Each has different operational complexity.
   What deployment environments need to be supported?

4. **CUI category:** The default banner uses `CUI // SP-VULN`
   (vulnerability information). Is this the correct CUI category
   for your use case, or does the target organization designate a
   different category or dissemination control (e.g.,
   `CUI // SP-VULN // NOFORN`)?

5. **FIPS mode:** NIST 800-171 references FIPS-validated
   cryptography (3.13.11). Full FIPS compliance requires certified
   modules and adds significant complexity. Is "use of FIPS
   algorithms (AES-256, SHA-256, HMAC-SHA256) with standard
   libraries" acceptable, or is a FIPS-validated build required?

6. **Report watermarking:** Should exported reports include a
   per-user watermark (e.g., "Generated by [user] at [timestamp]")
   to support leak attribution? This is not required by 800-171 but
   is common in CUI-handling tools.

7. **Existing swarm/distributed mode:** The swarm capability
   transmits scan data between nodes. Does CUI hardening need to
   extend to swarm communications (mutual TLS, encrypted payloads)?
   If so, this becomes a significantly larger scope item.

8. **Retention requirements:** What is the minimum retention period
   for scan results and audit logs? Some CUI programs require 3
   years; others defer to the organization. This drives the default
   retention policy configuration.

9. **Scope of "reports":** Should CUI protections extend to the
   real-time observation stream (WebSocket/SSE during scanning), or
   only to generated report artifacts? The live stream contains the
   same sensitive data.

10. **Database migration path:** Enabling encryption at rest on an
    existing database requires a migration (decrypt-read,
    encrypt-write). Should Chainsmith provide a `chainsmith db
    encrypt` migration command, or is a fresh database acceptable
    when enabling CUI mode?
