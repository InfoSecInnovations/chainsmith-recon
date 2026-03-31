# Data Persistence Layer

Design guidance for adding persistent storage to Chainsmith. This is a
prerequisite for reporting, trend analysis, scan history, and engagement
management.

## Current State

Chainsmith 1.3.0 stores all scan data **entirely in-memory** via the
`AppState` class in `app/state.py`. When the server restarts, all
findings, chains, and check logs are lost.

### What Persists Today

| Data | Storage | Survives Restart |
|------|---------|-----------------|
| User preferences/profiles | `~/.chainsmith/preferences.yaml` | Yes |
| Traffic audit logs | `/data/traffic_log.jsonl` | Yes |
| Scope violation logs | `/data/violations_log.jsonl` | Yes |
| Compliance report (if generated) | `/data/compliance_report.json` | Yes |

### What Does NOT Persist

| Data | Storage | Survives Restart |
|------|---------|-----------------|
| Scan findings | `state.findings` (list in memory) | No |
| Attack chains | `state.chains` (list in memory) | No |
| Check execution log | `state.check_log` (list in memory) | No |
| Scan metadata (target, status, timing) | `state.*` fields | No |
| Verification results | `state.*` fields | No |
| Scope configuration | `state.scope` | No |
| Session ID | Generated on startup | No |

### Architectural Gaps

- `config.py` defines `db_path: Path = Path("/data/recon.sqlite")` but
  no database code exists
- No ORM or database library in dependencies (no SQLAlchemy, no sqlite3
  usage, no migrations)
- No concept of scan IDs for referencing past scans
- No engagement tracking (multiple scans for same target)
- The `/api/export` endpoint generates a point-in-time JSON report but
  it's not saved automatically and cannot be re-imported

## Design Goals

1. **Scan results survive server restarts** — the minimum viable improvement
2. **Scan history** — view and compare past scans for the same target
3. **Engagement management** — group scans into engagements with metadata
4. **Foundation for reporting** — stored data enables trend analysis,
   remediation tracking, and compliance reporting over time
5. **Backward compatibility** — existing in-memory workflow continues to
   work; persistence is additive, not a rewrite

## Storage Engine

### Recommendation: SQLite (MVP), PostgreSQL (team/enterprise)

**SQLite for local/solo deployments:**
- Zero configuration, no separate process
- Single file, easy to back up and transport
- Already referenced in config (`db_path`)
- Sufficient for single-user, single-server use
- File: `~/.chainsmith/chainsmith.db` (or `/data/recon.sqlite` in Docker)

**PostgreSQL for team/enterprise deployments:**
- Required when multiple Chainsmith instances share data
- Required for swarm coordinator with concurrent agent writes (see
  [swarm-usage.md](swarm-usage.md))
- Required for reporting dashboards that query data directly
- Connection string via config/env var

**Migration path:** Start with SQLite. Schema is the same. Switch to
PostgreSQL by changing the connection string. Use SQLAlchemy as the ORM
to abstract the backend.

### Dependencies to Add

```
sqlalchemy >= 2.0
alembic                  # Schema migrations
aiosqlite                # Async SQLite for FastAPI
asyncpg                  # Async PostgreSQL (optional, for enterprise)
```

## Database Schema

### Core Tables

```sql
-- Engagements: group scans for the same target/client
CREATE TABLE engagements (
    id              TEXT PRIMARY KEY,    -- UUID
    name            TEXT NOT NULL,       -- Human-readable name
    target_domain   TEXT NOT NULL,       -- Primary target
    description     TEXT,
    client_name     TEXT,                -- Optional client/org name
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL,
    status          TEXT DEFAULT 'active', -- active, completed, archived
    metadata        JSON                 -- Extensible key-value data
);

-- Scans: individual scan executions
CREATE TABLE scans (
    id              TEXT PRIMARY KEY,    -- UUID
    engagement_id   TEXT REFERENCES engagements(id),
    session_id      TEXT NOT NULL,       -- Maps to current AppState session_id
    target_domain   TEXT NOT NULL,
    status          TEXT NOT NULL,       -- running, complete, error, cancelled
    started_at      TIMESTAMP NOT NULL,
    completed_at    TIMESTAMP,
    duration_ms     INTEGER,
    checks_total    INTEGER,
    checks_completed INTEGER,
    checks_failed   INTEGER,
    findings_count  INTEGER,
    scope           JSON,               -- Scope config snapshot
    settings        JSON,               -- Scan settings snapshot
    profile_name    TEXT,                -- Active profile at scan time
    scenario_name   TEXT,                -- Scenario if used
    error_message   TEXT,
    metadata        JSON
);

-- Findings: individual vulnerability findings
CREATE TABLE findings (
    id              TEXT PRIMARY KEY,    -- Finding ID (from check)
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL,       -- critical, high, medium, low, info
    check_name      TEXT NOT NULL,
    suite           TEXT,                -- network, web, ai, mcp, agent, rag, cag
    target_url      TEXT,
    host            TEXT,
    evidence        TEXT,
    raw_data        JSON,
    references      JSON,               -- Array of reference URLs
    verification_status TEXT DEFAULT 'pending',
    confidence      REAL,
    created_at      TIMESTAMP NOT NULL,
    metadata        JSON,

    -- For deduplication across scans
    fingerprint     TEXT                 -- Hash of (check_name, host, title, key evidence)
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_host ON findings(host);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);

-- Attack chains
CREATE TABLE chains (
    id              TEXT PRIMARY KEY,    -- Chain ID
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL,
    source          TEXT NOT NULL,       -- rule-based, llm, both
    finding_ids     JSON,               -- Array of finding IDs in this chain
    created_at      TIMESTAMP NOT NULL,
    metadata        JSON
);

CREATE INDEX idx_chains_scan_id ON chains(scan_id);

-- Check execution log
CREATE TABLE check_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    check_name      TEXT NOT NULL,
    suite           TEXT,
    event           TEXT NOT NULL,       -- started, completed, failed, skipped
    findings_count  INTEGER DEFAULT 0,
    duration_ms     INTEGER,
    error_message   TEXT,
    timestamp       TIMESTAMP NOT NULL
);

CREATE INDEX idx_check_log_scan_id ON check_log(scan_id);
```

### Supporting Tables

```sql
-- Finding fingerprints for tracking across scans
-- (did this finding exist in the last scan? is it new? resolved?)
CREATE TABLE finding_status_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint     TEXT NOT NULL,       -- Finding fingerprint
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    status          TEXT NOT NULL,       -- new, recurring, resolved, regressed
    first_seen_scan TEXT REFERENCES scans(id),
    last_seen_scan  TEXT REFERENCES scans(id),
    created_at      TIMESTAMP NOT NULL
);

CREATE INDEX idx_fsh_fingerprint ON finding_status_history(fingerprint);

-- Scan comparisons (precomputed for performance)
CREATE TABLE scan_comparisons (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_a_id       TEXT NOT NULL REFERENCES scans(id),
    scan_b_id       TEXT NOT NULL REFERENCES scans(id),
    new_findings    INTEGER,             -- In B but not A
    resolved        INTEGER,             -- In A but not B
    recurring       INTEGER,             -- In both
    regressed       INTEGER,             -- Was resolved, now back
    created_at      TIMESTAMP NOT NULL,

    UNIQUE(scan_a_id, scan_b_id)
);
```

## Finding Fingerprinting

To track findings across scans (is this finding new, recurring, or
resolved?), each finding gets a deterministic fingerprint:

```python
fingerprint = sha256(
    check_name + "|" +
    host + "|" +
    title + "|" +
    key_evidence_normalized
).hexdigest()[:16]
```

The fingerprint is stable across scans for the same vulnerability on the
same host, even if the description or raw_data changes slightly. This
enables:

- **New finding detection:** fingerprint not in previous scan
- **Recurring finding:** fingerprint in both current and previous scan
- **Resolved finding:** fingerprint in previous scan but not current
- **Regressed finding:** was resolved, now back (appeared, disappeared,
  reappeared)

Key evidence normalization strips timestamps, request IDs, and other
volatile data that would change between scans.

## Data Access Layer

### Repository Pattern

```python
# app/db/repositories.py

class ScanRepository:
    async def create_scan(self, scan: Scan) -> Scan
    async def update_scan(self, scan_id: str, **updates) -> Scan
    async def get_scan(self, scan_id: str) -> Optional[Scan]
    async def list_scans(self, engagement_id: str = None,
                         target: str = None,
                         limit: int = 50) -> list[Scan]
    async def get_latest_scan(self, target: str) -> Optional[Scan]

class FindingRepository:
    async def bulk_create(self, scan_id: str, findings: list[dict]) -> int
    async def get_findings(self, scan_id: str,
                           severity: str = None,
                           host: str = None) -> list[Finding]
    async def get_findings_by_host(self, scan_id: str) -> dict
    async def get_finding(self, finding_id: str) -> Optional[Finding]

class ChainRepository:
    async def bulk_create(self, scan_id: str, chains: list[dict]) -> int
    async def get_chains(self, scan_id: str) -> list[Chain]

class EngagementRepository:
    async def create_engagement(self, **kwargs) -> Engagement
    async def list_engagements(self) -> list[Engagement]
    async def get_engagement(self, id: str) -> Optional[Engagement]
    async def get_engagement_scans(self, id: str) -> list[Scan]

class ComparisonRepository:
    async def compare_scans(self, scan_a: str, scan_b: str) -> ScanComparison
    async def get_finding_history(self, fingerprint: str) -> list[dict]
    async def get_trend_data(self, engagement_id: str) -> TrendData
```

### Integration with AppState

AppState continues to hold the active scan's in-memory data for real-time
UI updates (progress, live findings). The persistence layer writes to the
database at key lifecycle points:

```
Scan starts     -> INSERT into scans (status=running)
Check completes -> INSERT into check_log
                -> INSERT findings into findings table
Scan completes  -> UPDATE scans (status=complete, timing)
                -> INSERT chains
                -> Compute finding fingerprints
                -> Compare with previous scan (if exists)
                -> Generate finding_status_history entries
```

The in-memory AppState is NOT replaced. It remains the source of truth
for the active scan. The database is the source of truth for everything
historical.

## API Changes

### New Endpoints

```
# Scan history
GET    /api/scans                    List past scans (paginated)
GET    /api/scans/{id}               Get scan details
GET    /api/scans/{id}/findings      Get scan's findings
GET    /api/scans/{id}/chains        Get scan's chains
GET    /api/scans/{id}/log           Get scan's check execution log
GET    /api/scans/{id}/compare/{id2} Compare two scans
DELETE /api/scans/{id}               Delete a scan and its data

# Engagements
GET    /api/engagements              List engagements
POST   /api/engagements              Create engagement
GET    /api/engagements/{id}         Get engagement details
GET    /api/engagements/{id}/scans   List scans in engagement
GET    /api/engagements/{id}/trend   Trend data for engagement
PUT    /api/engagements/{id}         Update engagement
DELETE /api/engagements/{id}         Delete engagement and all scans

# Finding history
GET    /api/findings/{fingerprint}/history  Finding across scans
```

### Modified Endpoints

Existing endpoints continue to work against the active scan (backward
compatible). When a `scan_id` query parameter is provided, they read
from the database instead:

```
GET /api/findings                     -> Active scan (current behavior)
GET /api/findings?scan_id=abc-123     -> Historical scan from database
GET /api/chains                       -> Active scan
GET /api/chains?scan_id=abc-123       -> Historical scan
GET /api/findings-by-host             -> Active scan
GET /api/findings-by-host?scan_id=abc -> Historical scan
```

## CLI Changes

```bash
# Scan history
chainsmith scans list [--target example.com] [--limit 20]
chainsmith scans show <scan-id>
chainsmith scans compare <scan-id-a> <scan-id-b>
chainsmith scans delete <scan-id> [--yes]

# Engagements
chainsmith engagements list
chainsmith engagements create --name "Q1 Pentest" --target example.com
chainsmith engagements show <id>
chainsmith engagements delete <id> [--yes]

# Scan into engagement
chainsmith scan example.com --engagement <engagement-id>

# Export historical scan
chainsmith export --scan <scan-id> -f json -o report.json
```

## Web UI Changes

### Scan History Panel

Add a "History" section accessible from the nav or a new tab:

- List of past scans with: date, target, finding count by severity,
  duration, status
- Click to view historical findings in the same visualizations (icicle,
  host table, chains)
- Compare button: select two scans for side-by-side diff
- Filter by target, date range, engagement

### Finding Status Badges

When viewing current scan findings, show status relative to previous scan:

- **NEW** — This finding didn't exist in the last scan (green badge)
- **RECURRING** — This finding existed in the last scan too (neutral)
- **REGRESSED** — This finding was resolved but is back (red badge)

When viewing historical findings:
- **RESOLVED** — This finding no longer appears in the latest scan

## Migration Strategy

### Phase 1: Write-only persistence (non-breaking)

- Add SQLAlchemy + alembic to dependencies
- Create schema and initial migration
- At scan completion, write findings/chains/log to database
- All reads still come from AppState (no behavior change)
- Database is populated silently in the background
- If database write fails, scan still works (graceful degradation)

### Phase 2: Read from database for historical data

- Add /api/scans endpoints
- Add scan_id query parameter to existing endpoints
- Add scan history to CLI
- Add History panel to web UI
- Active scan reads still from AppState; historical from database

### Phase 3: Engagement management

- Add engagements table and API
- Add --engagement flag to scan command
- Add finding fingerprinting and status tracking
- Add scan comparison API and UI

### Phase 4: Full integration

- Trend analysis (requires engagement + history)
- Remediation tracking (requires finding fingerprinting)
- Compliance reporting over time (requires scan history)
- Database becomes authoritative for all data, AppState becomes
  a real-time cache for the active scan only

## Configuration

```yaml
# chainsmith.yaml
storage:
  backend: sqlite              # sqlite or postgresql
  sqlite:
    path: ~/.chainsmith/chainsmith.db
  postgresql:
    url: postgresql://user:pass@host:5432/chainsmith
  auto_persist: true           # Write scan results to DB automatically
  retention_days: 365          # Auto-delete scans older than this (0 = forever)
```

```bash
# Environment variables
CHAINSMITH_STORAGE_BACKEND=sqlite
CHAINSMITH_SQLITE_PATH=~/.chainsmith/chainsmith.db
CHAINSMITH_POSTGRESQL_URL=postgresql://...
CHAINSMITH_STORAGE_RETENTION_DAYS=365
```

## Module Structure

```
app/
  db/
    __init__.py
    engine.py               # SQLAlchemy engine setup, session management
    models.py               # ORM models (Scan, Finding, Chain, Engagement, etc.)
    repositories.py         # Data access layer (repository pattern)
    migrations/
      env.py                # Alembic configuration
      versions/
        001_initial.py      # Initial schema
```

## Data Volume Estimates

For capacity planning:

| Data | Per Scan | Retention | 1 Year (weekly scans) |
|------|----------|-----------|----------------------|
| Scan metadata | ~1 KB | Forever | ~52 KB |
| Findings | ~50-500 KB (50-500 findings × ~1 KB each) | Forever | ~13-26 MB |
| Chains | ~5-50 KB | Forever | ~1.3-2.6 MB |
| Check log | ~5-20 KB | 90 days | ~0.5-2 MB |
| Fingerprint history | ~10-100 KB | Forever | ~2.6-5.2 MB |

SQLite handles this easily. Even at 100 scans/year with 500 findings
each, the database would be under 100 MB.
