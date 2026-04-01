# Phase 16: Release Prep

Remaining items from `prior-to-release.txt` (one directory above repo root) that
were not addressed during the initial commit.

Source: `../prior-to-release.txt`

---

## Already Complete

- [x] Rotate Anthropic API key
- [x] Create root .gitignore
- [x] Clean build artifacts before first commit
- [x] Replace all "yourorg" placeholder URLs
- [x] Create .env.example

---

## Remaining Work

### Wave 1 — Should do

| # | Item | Details |
|---|------|---------|
| 1 | Replace debug print statements with logging | `app/agents/scout.py:152`, `app/preferences.py:25`, `app/scenario_services/common/config.py:145` |
| 2 | Remove `--reload` flag from Dockerfile CMD | Line 36 — dev-only flag, not appropriate for production image |
| 3 | Add CHANGELOG.md | Referenced in docs but does not exist |

### Wave 2 — Nice to have

| # | Item | Details |
|---|------|---------|
| 4 | Add GitHub issue/PR templates | `.github/ISSUE_TEMPLATE/` and `.github/PULL_REQUEST_TEMPLATE.md` |
| 5 | Add SECURITY.md | Responsible vulnerability disclosure instructions |
| 6 | Add README badges | License (Apache 2.0), CI status |
