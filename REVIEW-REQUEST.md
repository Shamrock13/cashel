**REVIEW-REQUEST.md**

# Step 1 — Complete CI Pipeline

**Ready for Review: YES**

---

## Files Changed

### `.github/workflows/ci.yml` (lines 22, 56–65)

- **Line 22** — Removed `2>/dev/null || pip install -e . && pip install ruff mypy pytest` from install step. The `.[dev]` extras group exists in `pyproject.toml`; the fallback chain and error suppression were unnecessary and could hide broken installs.
- **Lines 56–65** — Added `secret-scan` job using `gitleaks/gitleaks-action@v2`. Job-level `if: github.event_name == 'push'` confines it to pushes to main; PR runs are unaffected. `fetch-depth: 0` ensures full git history is available for scanning.

### `.github/workflows/pip-audit-nightly.yml` (new file)

- New workflow: runs `pip-audit -r requirements.txt` nightly at 02:00 UTC and on `workflow_dispatch`. Scans `requirements.txt` directly — no app install required.

---

## Open Questions / Uncertainties

None. Brief was unambiguous.

---

## Known Gaps (out of scope)

- `test_cisco.py` is referenced in CLAUDE.md ("Tests for both live in `tests/test_cisco.py`") but the file does not exist. Logged in BUILD-LOG. Recommend Architect adds to a future step.
