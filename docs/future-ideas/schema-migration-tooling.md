# Future: Schema Migration Tooling

## Context

Phase 42 (Workstream B) removed Alembic and the runtime
`_sync_add_missing_columns()` auto-migrator. The ORM models via
`Base.metadata.create_all()` are now the single schema authority.

This is appropriate while the schema is still evolving and all databases
are disposable. Once users have data worth preserving across upgrades,
we need migration tooling.

## When to revisit

- When Chainsmith has users running persistent databases across versions
- When the schema has stabilized enough that migrations are incremental
  rather than structural

## Approach

Provide a standalone migration script (e.g., `tools/migrate_schema.py`)
that users run explicitly when upgrading. This is simpler than
maintaining an Alembic migration chain during rapid development. The
script would:

1. Detect the current schema version (via a `schema_version` table or
   column inspection)
2. Apply the necessary transforms (rename columns, add tables, backfill
   defaults)
3. Validate the result against the current ORM models

Alembic remains an option if the project reaches a point where
incremental migrations are the norm rather than the exception.
