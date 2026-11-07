# Performance Tuning Notes

Observations and guidance for keeping Chainsmith responsive as scan sizes
and usage patterns grow.


## DB Query Latency

The database is the source of truth for observation, chain, and adjudication
data. API routes read it through the repositories in `app/db/repositories.py`
(SQLAlchemy async sessions); live scan progress comes from the in-memory scan
session for each running scan.

**Expected impact for typical scans (< 500 observations):** Negligible.
SQLite is fast for read queries on indexed columns, and the `scan_id`
foreign key on `observations` is already indexed.

**Watch for:**
- Scans producing 1000+ observations. `GET /api/v1/observations` has no
  pagination today (it accepts `severity` and `host` filters but returns the
  full list).
- The `by-host` grouping endpoint does an in-Python group after fetching
  all observations. If this becomes slow, move grouping to a SQL
  `GROUP BY` query.
- Frequent polling of `GET /api/v1/scan` during scans. Progress fields
  (status, checks_completed, current_check) come from the scan session —
  no DB hit. If a count is ever served from the DB instead, that's a query
  per poll; prefer the in-memory `ObservationWriter` counter during active
  scans.

**Indexing:**
- `observations.scan_id` — already indexed (FK).
- `observations.severity` — consider adding if severity-filtered queries
  become common.
- `observations.host` — consider adding if by-host queries become slow.
- `observation_status_history.fingerprint` — already indexed.

**Monitoring approach:** Add timing to repository methods behind a debug
flag or structured logging, and compare runs on a scan with a known
observation count.


## ObservationWriter Batch Size

Default batch size: 10 observations per flush.

**Trade-offs:**
- Smaller batches (1-5): better durability (less data at risk on crash),
  more DB round-trips.
- Larger batches (20-50): fewer round-trips, more data at risk, higher
  memory during fast checks.
- Current choice (10): a crash loses at most 9 observations. Fast checks
  (port scan, header checks) that produce many observations in rapid
  succession stay efficient.

**Tuning:** If profiling shows DB writes are a bottleneck during scans,
increase batch size. If durability is paramount (e.g., long-running scans
against production), decrease it.


## SQLite Concurrency

SQLite uses file-level locking. With DB as source of truth:
- Concurrent reads are fine (multiple route handlers).
- Concurrent writes need care. During a scan, the `ObservationWriter`
  writes batches while routes may read. SQLite WAL mode (write-ahead
  logging) allows concurrent reads during writes — verify WAL is enabled.
- Concurrent scans (several sessions at once, or swarm) multiply writes. If SQLite becomes the
  bottleneck, consider PostgreSQL for multi-scan deployments.

**Check WAL mode:**
```sql
PRAGMA journal_mode;  -- should return "wal"
```

**If not enabled, set it:**
```sql
PRAGMA journal_mode=WAL;
```


## Progress Updates

Live scan progress is pushed over Server-Sent Events:
`GET /api/v1/scans/{scan_id}/stream` (or the unscoped alias
`GET /api/v1/scan/stream`). Each connection gets an initial snapshot, then
one event per scan state change, with a keepalive comment every 15 seconds.
`GET /api/v1/scan` remains available for polling clients; it reads the scan
session only — no DB hit. Keep it that way.

If future features add more data to progress events or the status response
(e.g., latest observation title), serve it from the session or an in-memory
cache updated by the writer, not from a DB query.
