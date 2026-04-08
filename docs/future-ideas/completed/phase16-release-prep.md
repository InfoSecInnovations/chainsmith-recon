# Phase 16: Release Prep

Remaining items from `prior-to-release.txt` (one directory above repo root) that
were not addressed during the initial commit.

Source: `../prior-to-release.txt`

Last verified: 2026-04-03

---

## Already Complete

- [x] Rotate Anthropic API key
- [x] Create root .gitignore
- [x] Clean build artifacts before first commit
- [x] Replace all "yourorg" placeholder URLs
- [x] Create .env.example
- [x] `.env` protected by `.gitignore` (not tracked)

---

## Remaining Work

All items completed.

### Wave 1 — Should do

| # | Item | Status | Details |
|---|------|--------|---------|
| 1 | Replace debug print statements with logging | **Done** | `scout.py`, `config.py`, `chain.py` — switched to `logging.getLogger(__name__)` |
| 2 | Remove `--reload` flag from Dockerfile CMD | **Skipped** | Kept — this is a dev image with volume-mounted code; `--reload` is intentional |
| 3 | Add CHANGELOG.md | **Done** | Created with Keep a Changelog format |
| 7 | Resolve TODO/FIXME comments | **Done** | Only `scanner.py:182` remained — reworded as placeholder docstring. AI check files had no TODOs. |

### Wave 2 — Nice to have

| # | Item | Status | Details |
|---|------|--------|---------|
| 4 | Add GitHub issue/PR templates | **Done** | Bug report, feature request, and PR template |
| 5 | Add SECURITY.md | **Done** | Responsible disclosure instructions |
| 6 | Add README badges | **Done** | License (Apache 2.0) and CI status badges |
