**REVIEW-FEEDBACK.md**

# Review Feedback — Step 1

Date: 2026-04-02
Ready for Builder: YES

---

## Must Fix

None.

---

## Should Fix

- `ci.yml:63` — `gitleaks/gitleaks-action@v2` uses a mutable version tag. A supply chain attack against this action would compromise the security scanner itself. Recommend pinning to the current commit SHA (e.g. `gitleaks/gitleaks-action@SHA`). Check the current SHA at https://github.com/gitleaks/gitleaks-action/releases and pin with a comment: `# gitleaks/gitleaks-action@v2.x.x`. Under 5 minutes to fix.

---

## Escalate to Architect

None.

---

## Cleared

Both workflow files reviewed against the brief: install step corrected, `secret-scan` job is spec-compliant (job-level condition, full fetch depth, free-tier gitleaks, correct token), `pip-audit-nightly.yml` is correct (cron schedule, workflow_dispatch, requirements.txt scan). No drift, no missing items, no logic errors.
