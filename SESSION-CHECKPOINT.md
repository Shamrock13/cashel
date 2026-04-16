# Session Checkpoint — 2026-04-16

## What was accomplished

### Codebase audit + stale TASK file cleanup
- Confirmed blueprint decomp, SQLite, auth, RBAC all fully shipped on main
- Deleted TASK-auth.md, TASK-rbac-ui.md, TASK-sqlite.md, TASK-web-decomp.md (were implemented, never removed)

### Python 3.9 compat — fixed and shipped
- Root cause: 12 modules used `str | None` union syntax without `from __future__ import annotations`; fails at runtime on Python 3.9 (macOS system Python), including `activity_log.py` which caused all alert_engine tests to fail silently
- Fix: added the guard to all 12 affected modules; 234 tests now pass locally
- Committed to main

### Staging sync — 3 fix branches merged
- `cld/fix-session-key-multiworker`: gunicorn SECRET_KEY sharing across workers (session loss fix for Render)
- `cld/zen-matsumoto`: circular import fix (already had extensions.py but some blueprints still imported from web.py), Render WEB_CONCURRENCY respect, admin 403 suppression, viewer null-guards
- `cld/auth-fixes`: auth backend bug fixes from staging validation, RBAC header redesign, DOM listener guards

### CRITICAL CSS restore — fixed and shipped
- Root cause: resolving style.css conflict with `git checkout --theirs` pulled in auth-fixes' v1.4 snapshot, wiping `--critical`/`--finding-critical-*` CSS variables and `.sev-critical`/`.finding-critical`/`.rem-badge-critical` classes
- Fix: restored all 3 sets of CRITICAL CSS rules; both light and dark mode
- **Lesson:** when resolving against older branches, always grep for `--critical` (and any recent feature vars) after merge to catch regressions

### Staging → main merged (PR #78)
- All CI green; CRITICAL summary box rendering confirmed fixed in staging before merge

### Branch cleanup
- Removed 4 worktrees (dazzling-noyce, dreamy-hofstadter, priceless-golick, zen-matsumoto)
- Deleted all cld/ and claude/ local branches

---

## Current branch state

| Branch | State |
|--------|-------|
| `main` | Clean, v1.5.1, PR #78 merged |
| `staging` | In sync with main |
| `demo-main` | Demo infrastructure — leave untouched |
| `gemini-staging` | Separate tooling — leave untouched |

---

## Known local test quirk

26 auth tests fail locally: `hashlib.scrypt` unavailable in macOS Python 3.9. Not a code bug — CI uses Python 3.11 and is green. Use `/Users/dereklockovich/myenv/bin/pytest` for local runs.

---

## Next up (no active spec)

1. **LDAP/OIDC/TACACS+ auth** — `blueprints/auth.py` has a seed comment; no implementation. Natural enterprise auth expansion.
2. **Scheduled PDF delivery** — `scheduler_runner.py` runs audits but doesn't auto-export PDF and email the report.
3. **Compliance test coverage** — `compliance.py` (76K) partially covered; CIS/NIST/PCI/HIPAA need test expansion beyond SOC2/STIG.

---

## Workflow notes (reinforced this session)
- Always `git fetch --all` before comparing branches
- Feature branches cut from `staging`; never directly from `main`
- When taking `--theirs` on CSS/JS during merge conflict resolution, grep for recently-added feature vars afterward to catch version regressions
- `gemini-staging` and `demo-main` are off-limits unless explicitly instructed

---

## Previous session notes (2026-04-08)

### Viewer role JS crash — fixed and shipped
- **Root cause:** `findingsPagination` is inside `{% if role in ('admin', 'auditor') %}` — doesn't exist in viewer DOM. An IIFE at page-load called `.addEventListener` directly on null.
- **Fixes:** Wrapped IIFE in `if (paginationEl)`; `if (!el) return` guard in `renderPaginationBar`; gated `loadSettings()` to admin-only (was triggering a 403 console noise for all non-admin roles).
- **PRs:** #37, #38 → staging → main

### Render auto-deploy crash — fixed and shipped
- **Root cause 1 (primary):** `gunicorn.conf.py` read `GUNICORN_WORKERS` (default 2), not `WEB_CONCURRENCY`. Render sets `WEB_CONCURRENCY=1`; 2 workers on a 1-CPU instance during zero-downtime → OOM → gunicorn exit code 3.
- **Root cause 2:** Docker `HEALTHCHECK` hardcoded port 5000; Render runs on `PORT=10000`.
- **Root cause 3:** No `.dockerignore` — `.git/`, `.claude/` worktrees baked into every image.
- **Fix:** `workers = int(os.environ.get("WEB_CONCURRENCY") or os.environ.get("GUNICORN_WORKERS", "2"))`, HEALTHCHECK uses `${PORT:-5000}`, `.dockerignore` added.
- **PR:** #39 → staging → main

### mypy CI failure — fixed and shipped
- **Root cause:** `audit`, `history`, `reports`, `api_v1` blueprints all imported `limiter`/`csrf` back from `cashel.web` — circular import mypy couldn't resolve → `[has-type]` errors on `register_blueprint()` calls.
- **Fix:** New `src/cashel/extensions.py` with uninitialized `CSRFProtect` + `Limiter`. `web.py` calls `.init_app(app)`. All four blueprints import from `cashel.extensions` not `cashel.web`.
- **PR:** #42 → staging → main

### cashel-demo Render crash — fixed
- **Root cause:** `Dockerfile.demo` hardcoded `--workers 2` and `--bind 0.0.0.0:5000` in CMD, bypassing `gunicorn.conf.py` entirely — WEB_CONCURRENCY fix never applied.
- **Fix:** CMD updated to `gunicorn --config gunicorn.conf.py cashel.web:app`. Redundant standalone `pip install gunicorn` removed.
- **Committed directly to cashel-demo/main:** a422ed2

### Full v1.4.x stack promoted to production
- PR #40 (staging → main) squash-merged: bfef3c6
- Covers PRs #31–#42: blueprint decomp, SQLite, multi-user auth, all viewer/role fixes, Render infra, extensions.py, ruff/mypy CI clean

---

## Current branch state

| Branch | State |
|--------|-------|
| `main` | Production — bfef3c6, all v1.4.x work live |
| `staging` | In sync with main |
| `cld/zen-matsumoto` | Worktree from this session — safe to delete |
| `gemini-staging` | Leave untouched |

---

## Next up (Phase 1 — 3 items remain)

1. **OpenAPI/Swagger docs** at `/api/docs` — marked Next in PLAN.md; start here next session
2. **Auth event audit logging** — login attempts, failed keys, user/settings changes
3. **Production deployment guide** — Docker Compose + nginx/Traefik TLS examples

**Version bump** to v1.5.0 is due after the next batch ships to main (remember: 5 locations — pyproject.toml, export.py, index.html footer, index.html JSON metadata, index.html SARIF driver).

---

## Workflow notes (reinforced this session)
- Always `git fetch --all` before comparing branches or reporting commit state
- Check PR state with `gh pr list --state all` before referencing — never tell user to merge a PR without confirming it's still open
- Feature branches cut from `staging`; never directly from `main`
- `gemini-staging` is off-limits unless explicitly instructed
