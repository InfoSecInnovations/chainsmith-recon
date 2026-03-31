# Working with Saved Scans

Chainsmith automatically saves every scan to a local database. This guide
covers how persistence works, how to browse and compare historical scans,
how to generate reports from them, and how to clean up old data.

## How Scans Are Saved

Persistence is **automatic** — no flags or extra steps required. When
`auto_persist` is enabled (the default), every scan is written to the
database at two points:

1. **Scan start** — a record is created with `status=running`, capturing
   the target domain, scope, settings, profile, and scenario.
2. **Scan completion** — findings, attack chains, and the check execution
   log are bulk-inserted, then the scan record is updated with final
   stats (duration, finding counts, status).

If the database write fails for any reason, the scan still completes
normally — persistence never blocks execution.

### What Gets Stored

| Data | Description |
|------|-------------|
| **Scan metadata** | Target, status, timing, check counts, profile/scenario, scope snapshot |
| **Findings** | Title, severity, check name, host, evidence, raw data, references |
| **Attack chains** | Linked findings with severity and source (rule-based/LLM/both) |
| **Check log** | Per-check events: started, completed, failed, skipped, with duration |
| **Finding fingerprints** | Stable SHA256 hash for tracking findings across scans |
| **Finding status history** | Whether each finding is new, recurring, resolved, or regressed |
| **Scan comparisons** | Precomputed diff between consecutive scans of the same target |

### Configuration

In `chainsmith.yaml`:

```yaml
storage:
  backend: sqlite              # sqlite or postgresql
  sqlite:
    path: ~/.chainsmith/chainsmith.db
  postgresql:
    url: postgresql://user:pass@host:5432/chainsmith
  auto_persist: true           # set false to disable persistence entirely
  retention_days: 365          # auto-delete scans older than this (0 = keep forever)
```

Environment variable overrides:

```bash
CHAINSMITH_STORAGE_BACKEND=sqlite
CHAINSMITH_SQLITE_PATH=~/.chainsmith/chainsmith.db
CHAINSMITH_POSTGRESQL_URL=postgresql://...
CHAINSMITH_STORAGE_RETENTION_DAYS=365
```

---

## Browsing Scan History

### CLI

```bash
# List all saved scans (most recent first)
chainsmith scans list

# Filter by target
chainsmith scans list --target example.com

# Limit results
chainsmith scans list --target example.com -n 5

# JSON output (for scripting)
chainsmith scans list --json

# View details of a specific scan
chainsmith scans show <scan-id>
chainsmith scans show <scan-id> --json
```

### API

```
GET /api/v1/scans?target=example.com&status=complete&limit=50&offset=0
GET /api/v1/scans/{scan_id}
GET /api/v1/scans/{scan_id}/findings?severity=high&host=api.example.com
GET /api/v1/scans/{scan_id}/findings/by-host
GET /api/v1/scans/{scan_id}/chains
GET /api/v1/scans/{scan_id}/log
```

All endpoints are also available without the `/v1` prefix
(e.g. `/api/scans`).

### Web UI

Open the **Findings** page to browse scan history interactively. You can
filter by severity and host, view finding status across scans, and manage
overrides.

---

## Comparing Scans

Chainsmith uses **finding fingerprints** — stable hashes of
`check_name | host | title | key_evidence` — to track the same finding
across scans. This enables four status categories:

| Status | Meaning |
|--------|---------|
| **new** | Finding appears in the current scan but not the previous one |
| **recurring** | Finding exists in both scans |
| **resolved** | Finding was in the previous scan but is gone now |
| **regressed** | Finding was previously resolved but has reappeared |

Comparisons are **check-aware**: only findings from checks that ran in
both scans are considered. A finding from a newly-added check won't be
falsely marked as "new" relative to an older scan that didn't run that
check.

### CLI

```bash
chainsmith scans compare <scan-a-id> <scan-b-id>
chainsmith scans compare <scan-a-id> <scan-b-id> --json
```

### API

```
GET /api/v1/scans/{scan_a_id}/compare/{scan_b_id}
```

Returns: `new_count`, `resolved_count`, `recurring_count`, plus the
actual finding lists and check-level comparison.

---

## Trend Analysis

View how findings evolve over time for a target domain.

### CLI

```bash
chainsmith scans trend --target example.com
chainsmith scans trend -t example.com --json
```

### API

```
GET /api/v1/targets/{domain}/trend?since=2025-01-01&until=2025-12-31&last_n=10
```

Filters are optional and combinable. Returns per-scan data points with
severity breakdowns, risk scores, and computed metrics (regression rate,
mean time to resolution).

### Web UI

Open the **Trend** page to view interactive charts of severity counts per
scan, regression rate, and MTTR over a date range.

---

## Finding History and Overrides

Track the lifecycle of a specific finding across all scans, and
optionally mark it as accepted risk or a false positive.

### View Finding History

```
GET /api/v1/findings/{fingerprint}/history
```

Returns the finding's status (new/recurring/resolved/regressed) in each
scan where it appeared, plus any active override.

### Set an Override

```
PUT /api/v1/findings/{fingerprint}/override
Body: {"status": "accepted" | "false_positive", "reason": "optional note"}
```

### Remove an Override

```
DELETE /api/v1/findings/{fingerprint}/override
```

### List All Overrides

```
GET /api/v1/findings/overrides?status=false_positive
```

---

## Generating Reports from Saved Scans

All report types work against historical scan data stored in the
database. Available formats: `md`, `json`, `html`, `pdf`, `sarif`.

### CLI

```bash
# Technical report (detailed findings)
chainsmith report technical --scan <scan-id> -f html -o report.html

# Executive summary
chainsmith report executive --scan <scan-id> -f pdf -o summary.pdf

# Compliance report
chainsmith report compliance --scan <scan-id> -f md

# Delta report (comparison between two scans)
chainsmith report delta --scan-a <id-a> --scan-b <id-b> -f html -o delta.html

# Trend report (across all scans for a target or engagement)
chainsmith report trend -t example.com -f html
```

### API

```
POST /api/v1/reports/technical     {"scan_id": "...", "format": "html"}
POST /api/v1/reports/executive     {"scan_id": "...", "format": "pdf"}
POST /api/v1/reports/compliance    {"scan_id": "...", "format": "md"}
POST /api/v1/reports/delta         {"scan_a_id": "...", "scan_b_id": "...", "format": "html"}
POST /api/v1/reports/trend         {"target": "example.com", "format": "html"}
POST /api/v1/reports/targeted      {"fingerprints": ["abc1...", "def2..."], "format": "md"}
```

The targeted export lets you cherry-pick specific findings by fingerprint
for a curated report.

PDF output requires the optional `xhtml2pdf` dependency. Check what
formats are available:

```
GET /api/v1/capabilities
```

---

## Engagements

Engagements group related scans for the same client or assessment.

### CLI

```bash
# Create an engagement
chainsmith engagements create --name "Q1 Pentest" --target example.com

# List engagements
chainsmith engagements list

# View engagement details and its scans
chainsmith engagements show <engagement-id>

# Run a scan linked to an engagement
chainsmith scan example.com --engagement <engagement-id>

# View engagement-level trend
chainsmith engagements trend <engagement-id>

# Delete engagement (scans are kept, just unlinked)
chainsmith engagements delete <engagement-id> --yes
```

### API

```
GET    /api/v1/engagements
POST   /api/v1/engagements
GET    /api/v1/engagements/{id}
GET    /api/v1/engagements/{id}/scans
GET    /api/v1/engagements/{id}/trend
PUT    /api/v1/engagements/{id}
DELETE /api/v1/engagements/{id}
```

Deleting an engagement does **not** delete its scans — they become
standalone historical records with `engagement_id` set to null.

---

## Deleting Scans

### CLI

```bash
# Delete with confirmation prompt
chainsmith scans delete <scan-id>

# Skip confirmation
chainsmith scans delete <scan-id> --yes
```

### API

```
DELETE /api/v1/scans/{scan_id}
```

Deletion is **cascading** — it removes the scan record and all associated
findings, chains, check log entries, finding status history, and scan
comparison records.

### Automatic Retention

Set `retention_days` in your storage config to automatically delete scans
older than the specified number of days. Set to `0` to keep scans
forever.

---

## Database Location

By default, Chainsmith stores data in an SQLite file at
`./data/chainsmith.db` (relative to the working directory). To back up
your scan history, copy this file. To start fresh, delete it — tables are
recreated automatically on startup.

For team deployments, switch to PostgreSQL by setting the `backend` and
`postgresql_url` config values. The schema is identical.
