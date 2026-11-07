"""
app/dev/ - Local source-tree authoring tools.

A *different category* from the operator CLI in `app/cli.py` (a thin HTTP
client). These commands are filesystem + AST + codemod tools that run
**serverless** — no `ChainsmithClient`, no HTTP — because a remote/Docker
server can't refactor the developer's local source tree.

`app/cli.py`'s `dev` group is thin Click wrappers importing this package; the
group is registered `hidden=True` (out of the operator `--help`, still runnable
in any checkout and in CI for `verify-contracts`).

Modules:
- `registry_diff.py` — capture/compare the live check registry (the migration safety anchor).
- `scaffold.py` — `new-check` component-folder generator.
- `migrate.py` — `migrate-check` / `migrate-suite` (flat file → component folder).
- `codemod.py` — AST import-path rewriting for moved modules.
"""
