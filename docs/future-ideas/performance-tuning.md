# Performance Tuning Notes

Observations and guidance for keeping Chainsmith responsive as scan sizes
and usage patterns grow.


## DB Query Latency After Phase 31

Phase 31 (DB as source of truth) replaces in-memory list reads with DB
queries for observation, chain, and adjudication data.

**Current state:** Routes read `state.observations` — a Python list, O(1)
access, zero I/O.

**After migration:** Routes query SQLite via SQLAlchemy async sessions.

**Expected impact for typical scans (< 500 observations):** Negligible.
SQLite is fast for read queries on indexed columns, and the `scan_id`
foreign key on `observations` is already indexed.

**Watch for:**
- Scans producing 1000+ observations. May need pagination on
  `GET /api/v1/observations` (currently returns full list).
- The `by-host` grouping endpoint does an in-Python group after fetching
  all observations. If this becomes slow, move grouping to a SQL
  `GROUP BY` query.
- Frequent polling of `GET /api/v1/scan` during scans. Progress fields
  (status, checks_completed, current_check) stay in state — no DB hit.
  But if `observations_count` is served from DB instead of state, that's
  a query per poll. Mitigation: serve count from `ObservationWriter.count`
  (in-memory counter) during active scans.

**Indexing:**
- `observations.scan_id` — already indexed (FK).
- `observations.severity` — consider adding if severity-filtered queries
  become common.
- `observations.host` — consider adding if by-host queries become slow.
- `observation_status_history.fingerprint` — already indexed.

**Monitoring approach:** Add timing to repository methods behind a debug
flag or structured logging. Compare before/after migration on a scan with
known observation count.


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
- True concurrent scans (swarm) will hammer writes. If SQLite becomes the
  bottleneck, consider PostgreSQL for multi-scan deployments.

**Check WAL mode:**
```sql
PRAGMA journal_mode;  -- should return "wal"
```

**If not enabled, set it:**
```sql
PRAGMA journal_mode=WAL;
```


## Progress Polling

`GET /api/v1/scan` is polled by the UI during scans (typically every 1-2
seconds). This endpoint reads only from state — no DB hit. Keep it that way.

If future features add more data to the poll response (e.g., latest
observation title), serve from an in-memory cache updated by the writer,
not from a DB query.
