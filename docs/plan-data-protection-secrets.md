# Data Protection & Secrets Management

Plan for encrypting Chainsmith's data at rest and establishing a secrets
management strategy for credentials and API keys.

This document complements [authentication-authorization.md](authentication-authorization.md)
(who can access data) and [plan-instance-auth-nist-cui.md](plan-instance-auth-nist-cui.md)
(session management and NIST compliance). This document covers *what happens
to the data itself* — classification, encryption, key management, and
credential storage.

## Problem Statement

Chainsmith stores security assessment data that qualifies as CUI:

- **Observation evidence** may contain extracted secrets, tokens, configuration
  snippets, and internal URLs from target systems
- **Attack chains** describe exploitable paths through target infrastructure
- **Engagement metadata** includes client names and scope details
- **Adjudication rationale** contains analyst reasoning about severity

All of this is currently stored as plaintext in SQLite (or PostgreSQL).
API keys for LLM providers sit in `.env` files or environment variables
with no encryption, rotation, or access auditing.

This plan defines a layered encryption strategy and a path from the current
`.env`-based approach to proper secrets management.

## Data Classification

| Classification | Data | Examples | Encryption Need |
|----------------|------|----------|-----------------|
| **Critical** | Extracted target secrets, credentials, API keys | `observations.evidence` containing tokens, `.env` API keys, engagement client PII | Column-level encryption with dedicated key |
| **High** | Assessment details that reveal target weaknesses | `observations.title`, `observations.severity`, `chains.*`, `adjudication_results.rationale` | Column-level encryption |
| **Standard** | Operational metadata | `check_log.*`, `scans.status`, `scans.started_at`, user preferences | Database-level encryption sufficient |
| **Public** | Check definitions, scenario templates, app config | Check metadata, built-in payloads, documentation | No encryption needed |

### Per-Table Classification

| Table | Critical Columns | High Columns | Standard Columns |
|-------|-----------------|--------------|------------------|
| `observations` | `evidence` | `title`, `severity`, `check_name` | `fingerprint`, `created_at` |
| `chains` | — | `title`, `severity`, `observation_ids` | `source`, `created_at` |
| `scans` | — | `target_domain` | `status`, `started_at`, `observations_count` |
| `engagements` | `client_name` | `target_domain`, `name` | `status`, `created_at` |
| `adjudication_results` | — | `rationale`, `adjudicated_severity` | `approach`, `original_severity` |
| `observation_overrides` | — | `reason` | `fingerprint`, `status` |
| `swarm_api_keys` | `key_hash` (already hashed) | — | `name`, `created_at` |

## Encryption Strategy — Layered Approach

### Layer 1: Database-Level Encryption (MVP)

Transparent encryption of the entire database file. Application code
requires no changes — encryption is handled at the storage layer.

**SQLite: SQLCipher**

SQLCipher replaces the standard SQLite library with AES-256-CBC encryption.
Every page of the database file is encrypted.

```python
# Connection with SQLCipher (via sqlcipher3 or pysqlcipher3)
import sqlcipher3

conn = sqlcipher3.connect("chainsmith.db")
conn.execute(f"PRAGMA key = '{master_key}'")
conn.execute("PRAGMA cipher_page_size = 4096")
conn.execute("PRAGMA kdf_iter = 256000")  # PBKDF2 iterations
```

Key derivation: PBKDF2-HMAC-SHA512 with 256,000 iterations from a master
passphrase or raw key.

```yaml
storage:
  encryption:
    enabled: true
    backend: sqlcipher         # sqlcipher | pgcrypto | filesystem
    key_source: file           # file | env | vault
    key_path: ~/.chainsmith/master.key
```

**PostgreSQL: TDE options**

| Approach | Mechanism | Pros | Cons |
|----------|-----------|------|------|
| pgcrypto extension | `pgp_sym_encrypt()` per column | Granular, no special build | Application changes needed, query overhead |
| PostgreSQL 16+ TDE | Cluster-level encryption | Transparent, no app changes | Requires special build, all-or-nothing |
| Filesystem encryption | LUKS / BitLocker / dm-crypt | Zero app changes | Doesn't protect against DB-level access |

Recommendation: Filesystem encryption as baseline for PostgreSQL, with
column-level encryption (Layer 2) for critical/high fields.

**Encrypting an existing plaintext database:**

```bash
# Convert existing SQLite DB to SQLCipher
chainsmith db encrypt --key-source file --key-path ~/.chainsmith/master.key
# Creates chainsmith.db.enc, validates, replaces original
# Original backed up to chainsmith.db.bak (user should secure or delete)
```

### Layer 2: Column-Level Encryption (Phase 2)

Application-level encryption of sensitive columns before database write.
Different keys for different classification levels.

**Key Hierarchy**

```
Master Key (file / vault / derived from passphrase)
│
├── KEK (Key Encryption Key) — encrypts the DEKs
│
├── DEK-critical ── AES-256-GCM
│   ├── observations.evidence
│   ├── engagements.client_name
│   └── (any future credential storage columns)
│
├── DEK-high ── AES-256-GCM
│   ├── observations.title, observations.severity, observations.check_name
│   ├── chains.title, chains.severity, chains.observation_ids
│   ├── adjudication_results.rationale
│   └── scans.target_domain
│
└── DEK-standard ── (covered by Layer 1 database encryption)
```

**How it works:**

1. On startup, Chainsmith loads the master key
2. Master key unwraps the KEK
3. KEK unwraps DEK-critical and DEK-high from a key table
4. DEKs are held in memory for the lifetime of the process
5. On write: `encrypted_value = AES-256-GCM(DEK, plaintext, nonce)`
6. On read: `plaintext = AES-256-GCM-decrypt(DEK, encrypted_value, nonce)`
7. Nonce stored alongside ciphertext (prepended or in separate column)

**Storage format for encrypted columns:**

```
[1-byte version][12-byte nonce][N-byte ciphertext][16-byte GCM tag]
```

Base64-encoded for TEXT columns. The version byte allows future algorithm
changes without a full re-encryption migration.

**ORM integration:**

```python
from app.db.encryption import EncryptedString, EncryptedText

class Observation(Base):
    __tablename__ = "observations"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    fingerprint = Column(String)                          # Standard — not encrypted
    title = Column(EncryptedString(key_tier="high"))      # High — encrypted with DEK-high
    severity = Column(String)                             # Queryable — not encrypted (see tradeoffs)
    evidence = Column(EncryptedText(key_tier="critical")) # Critical — encrypted with DEK-critical
    check_name = Column(String)                           # Queryable — not encrypted
```

**Tradeoff: encryption vs queryability.** Columns that appear in WHERE
clauses, ORDER BY, or GROUP BY cannot be encrypted without additional
mechanisms (blind indexes, deterministic encryption, or decrypt-then-filter).

Practical compromise for Phase 2:
- Encrypt `evidence`, `rationale`, `client_name` (long text, rarely filtered)
- Keep `severity`, `check_name`, `fingerprint` as plaintext (needed for queries)
- Encrypt `title` and `target_domain` only if query patterns allow it

### Layer 3: Per-Engagement Key Segregation (Phase 3 / Future)

Each engagement gets its own DEK. This enables:

- **Crypto-shredding**: Delete an engagement's key to irrecoverably destroy
  all its data without touching the database
- **Client data isolation**: Even if one engagement's key is compromised,
  other engagements remain protected
- **Compliance**: Some clients require that their data be independently
  deletable

```
Master Key
└── KEK
    ├── DEK-engagement-001
    ├── DEK-engagement-002
    └── DEK-engagement-003
```

Key table:

```sql
CREATE TABLE encryption_keys (
    id              TEXT PRIMARY KEY,
    key_tier        TEXT NOT NULL,       -- 'critical', 'high', 'engagement'
    engagement_id   INTEGER,            -- NULL for global keys
    wrapped_key     BLOB NOT NULL,      -- DEK encrypted with KEK
    algorithm       TEXT NOT NULL,       -- 'aes-256-gcm'
    created_at      TIMESTAMP NOT NULL,
    rotated_at      TIMESTAMP,
    retired_at      TIMESTAMP,          -- Non-null = key retired, data re-encrypted
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
```

## Secrets Management

### Current State (MVP — Acceptable)

```
.env file:
  OPENAI_API_KEY=sk-...
  ANTHROPIC_API_KEY=sk-ant-...
  LITELLM_BASE_URL=http://localhost:4000/v1

Environment variables read by app/lib/llm.py at startup.
```

No encryption, no rotation, no access audit. Functional for solo use.

### Phase 2: Encrypted Secrets Store

Chainsmith-managed encrypted file for credentials that don't belong in
plaintext `.env` files.

```
~/.chainsmith/secrets.enc
  Format: AES-256-GCM encrypted JSON
  Key: derived from master key (same as DB encryption)
```

CLI:
```bash
# Store a secret
chainsmith secrets set OPENAI_API_KEY
Enter value: ********
Secret stored.

# List secrets (names only, not values)
chainsmith secrets list
  OPENAI_API_KEY    (set 2026-03-15, last accessed 2026-04-06)
  ANTHROPIC_API_KEY (set 2026-03-15, last accessed 2026-04-01)

# Delete a secret
chainsmith secrets delete ANTHROPIC_API_KEY

# Export secrets to env vars (for scripts — prints to stdout)
chainsmith secrets export --format env
```

Resolution priority (updated):
1. Environment variables (always win — allows override)
2. Encrypted secrets store (`~/.chainsmith/secrets.enc`)
3. `.env` file (legacy fallback)
4. Auto-detection (existing behavior)

### Phase 3: External Vault Integration

For team/enterprise deployments, credentials live in a central vault.

```yaml
secrets:
  provider: vault              # env | file | vault
  vault:
    type: hashicorp            # hashicorp | aws_secrets_manager | azure_keyvault
    address: https://vault.internal:8200
    auth_method: token         # token | approle | kubernetes
    secret_path: secret/data/chainsmith
    token: ${VAULT_TOKEN}      # Or use approle for automated access
```

```python
class VaultStore(CredentialStore):
    """HashiCorp Vault backend."""

    async def get(self, name: str) -> str:
        # GET /v1/secret/data/chainsmith
        # Returns versioned KV secret
        ...

    async def set(self, name: str, value: str) -> None:
        # PUT /v1/secret/data/chainsmith
        ...
```

Vault integration also enables:
- **Dynamic database credentials**: Vault generates short-lived PostgreSQL
  credentials for Chainsmith, rotated automatically
- **Audit trail**: Vault logs every secret access
- **Centralized rotation**: Rotate keys in Vault, Chainsmith picks up
  changes on next access or via a watch/lease mechanism

## Key Management Challenges

These are hard problems. This section is honest about what's difficult
and where design decisions are still needed.

### Key Rotation

When a DEK is rotated:
1. Generate new DEK
2. Wrap new DEK with KEK, store in key table
3. Re-encrypt all data protected by old DEK with new DEK
4. Mark old DEK as retired
5. Verify re-encryption succeeded before deleting old DEK

For large databases, step 3 is expensive. Options:
- **Online rotation**: Background job re-encrypts rows incrementally.
  Reads check both old and new DEK until migration completes.
- **Offline rotation**: `chainsmith db rotate-keys` command. Requires
  downtime or read-only mode.
- **Lazy rotation**: Re-encrypt on read. Each row is decrypted with
  old key, re-encrypted with new key, written back. Eventually all
  rows migrate. Risk: incomplete migration if some rows are never read.

### Key Backup and Recovery

If the master key is lost, all encrypted data is irrecoverable. This is
by design (encryption is meaningless if the key can be trivially recovered),
but it demands clear backup procedures.

Options:
- **Key file backup**: User manually backs up `~/.chainsmith/master.key`
- **Key splitting (Shamir's Secret Sharing)**: Split master key into N
  shares, require M to reconstruct. Good for team deployments.
- **Key escrow**: Store master key (encrypted) with a trusted third party
  or organizational key custodian.

### Swarm Agent Key Distribution

Swarm agents need to decrypt task payloads (which may contain target info)
and encrypt results (which contain observations). Options:

| Approach | How | Pros | Cons |
|----------|-----|------|------|
| Coordinator decrypts/encrypts | Agent sees plaintext over TLS | Simple, no key distribution | Coordinator is bottleneck; data in transit (TLS-protected) |
| Per-task session keys | Coordinator wraps task DEK with agent's key | Key isolation per task | Complex; agent needs asymmetric key pair |
| Shared DEK | Agent receives DEK at registration | Simple reads/writes | Key compromise affects all agents |

Recommendation: Start with coordinator-side encryption (agents see plaintext
over mTLS). Move to per-task session keys if threat model requires it.

### Performance Impact

Column-level encryption adds overhead to every read and write:

| Operation | Estimated Overhead | Mitigation |
|-----------|-------------------|------------|
| Encrypt on write | ~0.1ms per field (AES-256-GCM is fast) | Negligible for individual writes |
| Decrypt on read | ~0.1ms per field | Bulk reads (listing observations) may be noticeable |
| Bulk scan persist (500 observations) | ~50-100ms additional | Acceptable; scan execution takes minutes |
| Key derivation on startup | ~200ms (PBKDF2, 256k iterations) | One-time cost |

Primary concern is bulk reads — listing/filtering observations requires
decrypting every returned row. Consider:
- Caching decrypted results in memory for active scans
- Pagination (already exists in the API)
- Keeping queryable fields unencrypted

### Search on Encrypted Data

Encrypted columns cannot be used in SQL WHERE, LIKE, or ORDER BY. Options:

| Approach | How | Tradeoff |
|----------|-----|----------|
| Don't encrypt queryable fields | `severity`, `check_name`, `fingerprint` stay plaintext | Leaks classification/categorization |
| Blind indexes | Store HMAC(key, value) alongside encrypted value; query on HMAC | Equality search only, no LIKE/range |
| Decrypt-then-filter | Load encrypted rows, decrypt in Python, filter in memory | Performance degrades with data size |
| Searchable encryption (SSE) | Academic schemes (OPE, ORE) | Complex, limited library support |

Recommendation for Phase 2: Keep queryable fields unencrypted. Encrypt
long-text evidence and rationale fields. Revisit with blind indexes if
the threat model demands encrypting titles/check names.

### Schema Migrations on Encrypted Columns

Alembic migrations that alter encrypted columns need special handling:
- Column type changes require decrypt → migrate → re-encrypt
- Adding encryption to existing plaintext columns requires a data migration
- Migration scripts must have access to the master key

```python
# Example: migration to encrypt observations.evidence
def upgrade():
    # Load encryption key
    from app.db.encryption import get_dek
    dek = get_dek("critical")

    # Read all plaintext evidence
    observations = op.get_bind().execute(text("SELECT id, evidence FROM observations"))
    for f in observations:
        encrypted = encrypt(dek, f.evidence)
        op.get_bind().execute(
            text("UPDATE observations SET evidence = :ev WHERE id = :id"),
            {"ev": encrypted, "id": f.id}
        )
```

## Implementation Phases

### Phase 1 — Database-Level Encryption (Near-Term)

- [ ] SQLCipher integration for SQLite backend
- [ ] Master key generation (`chainsmith db init-encryption`)
- [ ] Master key storage in `~/.chainsmith/master.key` (0600 permissions)
- [ ] `chainsmith db encrypt` command for existing databases
- [ ] PostgreSQL TDE documentation and setup guide
- [ ] Encrypted database backup (`chainsmith db backup --encrypted`)
- [ ] Startup check: refuse to open encrypted DB without key

### Phase 2 — Column-Level Encryption & Secrets Store (Mid-Term)

- [ ] `EncryptedString` / `EncryptedText` SQLAlchemy column types
- [ ] Key hierarchy: master key → KEK → DEK-critical, DEK-high
- [ ] `encryption_keys` table for DEK storage
- [ ] Encrypt critical columns: `observations.evidence`, `engagements.client_name`
- [ ] Encrypt high columns: `chains.title`, `adjudication_results.rationale`
- [ ] Encrypted secrets store (`~/.chainsmith/secrets.enc`)
- [ ] CLI: `chainsmith secrets set/list/delete/export`
- [ ] Key rotation tooling (`chainsmith db rotate-keys`)
- [ ] Data migration for existing plaintext data

### Phase 3 — Vault & Per-Engagement Keys (Future)

- [ ] External vault integration (HashiCorp Vault, AWS Secrets Manager)
- [ ] Per-engagement DEK segregation
- [ ] Crypto-shredding support (`chainsmith engagement destroy --crypto-shred`)
- [ ] Dynamic database credentials via Vault
- [ ] WebUI credential management
- [ ] Swarm agent key distribution (per-task session keys)
- [ ] Shamir's Secret Sharing for master key backup
- [ ] Key escrow for team deployments

## Open Questions

1. **SQLCipher vs filesystem encryption**: SQLCipher protects the DB file
   itself but adds a dependency (custom SQLite build). Filesystem encryption
   (BitLocker on Windows, LUKS on Linux) is transparent but doesn't protect
   against application-level access. Are both needed, or is one sufficient
   for the threat model?

2. **Search and filtering on encrypted columns**: The practical compromise
   (encrypt evidence/rationale, leave severity/check_name plaintext) leaks
   some information. Is this acceptable for CUI, or do we need blind
   indexes from the start?

3. **Swarm agent decryption**: Should agents ever hold DEKs, or should all
   encryption/decryption happen on the coordinator? Coordinator-side is
   simpler and avoids key distribution, but adds latency and makes the
   coordinator a single point of failure for decryption.

4. **FIPS 140-2 validated crypto**: Python's `cryptography` library uses
   OpenSSL, which has FIPS-validated builds. Should Chainsmith require a
   FIPS-validated OpenSSL? This affects packaging and deployment.

5. **Key escrow for team deployments**: When multiple team members access
   a shared Chainsmith instance, who holds the master key recovery
   material? Options: designated key custodian, Shamir splitting among
   team leads, or organizational HSM.

6. **Performance benchmarking**: Before committing to column-level
   encryption, need benchmarks on realistic data volumes. How many observations
   per scan? How large is typical evidence text? What's the acceptable
   latency for listing 1,000 observations with decryption?

7. **Schema migration strategy**: Encrypting existing plaintext columns is
   a one-way operation. Need a tested rollback plan (keep plaintext backup
   until encryption verified). How long should the plaintext backup be
   retained?
