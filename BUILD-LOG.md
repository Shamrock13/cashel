**BUILD-LOG.md**

# Cashel — Build Log

---

## Step 1 — Complete CI Pipeline

**Status:** Review complete — awaiting deploy gate

**Files changed:**
- `.github/workflows/ci.yml` — fixed install step, added `secret-scan` job
- `.github/workflows/pip-audit-nightly.yml` — created

**Key decisions:**
- Used `gitleaks/gitleaks-action@v2` (free tier, no license token needed)
- Secret scan runs on push only via job-level `if: github.event_name == 'push'`; keeps PR runs clean
- pip-audit scans `requirements.txt` directly, no full app install needed
- `fetch-depth: 0` on secret-scan checkout so gitleaks can scan full history

**Known gaps logged:**
- `test_cisco.py` referenced in CLAUDE.md but does not exist in `tests/` — out of scope for this step
