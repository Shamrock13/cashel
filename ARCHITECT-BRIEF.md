**ARCHITECT-BRIEF.md**

# Step 1 — Complete CI Pipeline

## Context

`.github/workflows/ci.yml` already exists and covers: ruff lint, ruff format check, mypy, XML safety, dep-sync, and pytest. It runs on every PR and push to main. **Do not rewrite it.** Make targeted additions only.

## Decisions

- Secret scanning tool: **gitleaks** (action: `gitleaks/gitleaks-action@v2`). Free, no token required, well-maintained.
- pip-audit: separate workflow file (`pip-audit-nightly.yml`), runs on `schedule` cron + `workflow_dispatch`.
- Secret scan placement: new step in `ci.yml`, runs on `push` to main only (not PR — avoids noisy failures on forks).
- Fix the install step: remove `2>/dev/null` suppression; the `.[dev]` extras group already exists in `pyproject.toml`, so the fallback chain is unnecessary.

## Build Order

1. Fix the install step in `ci.yml` — remove `2>/dev/null || pip install -e . && pip install ruff mypy pytest`. Replace with: `pip install -e ".[dev]"`.
2. Add secret scan step to `ci.yml` — runs on push to main only. Use a job-level `if:` condition, not a step-level one, so it doesn't clutter PR runs. Simplest: add a second job `secret-scan` with `if: github.event_name == 'push'`.
3. Create `.github/workflows/pip-audit-nightly.yml` — runs nightly at 02:00 UTC and on `workflow_dispatch`. Steps: checkout → setup Python 3.11 → `pip install pip-audit` → `pip-audit -r requirements.txt`.

## Flags

- Flag: do NOT enable `GITLEAKS_LICENSE` or any paid gitleaks feature. Free tier only.
- Flag: pip-audit should scan `requirements.txt`, not the installed environment, so it runs without installing the full app.
- Flag: the `validate` job in `ci.yml` must be unchanged in name — other tooling may reference it.
- Flag: `test_cisco.py` is referenced in CLAUDE.md but does not exist in `tests/`. Do not create it — just note it in the review request as a known gap.

## Definition of Done

- [ ] `ci.yml` install step no longer suppresses errors
- [ ] `ci.yml` has a `secret-scan` job that runs gitleaks on push to main
- [ ] `.github/workflows/pip-audit-nightly.yml` exists and is valid YAML
- [ ] `ruff check src/ tests/` passes locally
- [ ] `pytest tests/ -v` passes locally
- [ ] Write `REVIEW-REQUEST.md` listing the two changed/created files and the known `test_cisco.py` gap
