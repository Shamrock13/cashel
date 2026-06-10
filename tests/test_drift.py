"""Tests for scheduled-audit drift detection (audit.regression events)."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.scheduler_runner import _dispatch_regression_event  # noqa: E402


_PREV = {
    "id": "base123",
    "findings": ["[HIGH] telnet enabled", "[MEDIUM] no logging"],
}


def _fire(previous, findings):
    with patch("cashel.webhooks.dispatch_event") as mock_dispatch:
        _dispatch_regression_event(
            previous,
            findings,
            audit_id="cur456",
            tag="edge",
            vendor="asa",
            host="10.0.0.1",
        )
    return mock_dispatch


def test_no_previous_audit_is_quiet():
    mock = _fire(None, ["[HIGH] anything"])
    mock.assert_not_called()


def test_unchanged_findings_are_quiet():
    mock = _fire(_PREV, list(_PREV["findings"]))
    mock.assert_not_called()


def test_new_medium_only_drift_is_quiet():
    findings = _PREV["findings"] + ["[MEDIUM] new minor thing"]
    mock = _fire(_PREV, findings)
    mock.assert_not_called()


def test_new_high_finding_fires_regression_event():
    findings = _PREV["findings"] + ["[HIGH] rdp open to any"]
    mock = _fire(_PREV, findings)
    mock.assert_called_once()
    event, payload = mock.call_args[0]
    assert event == "audit.regression"
    assert payload["audit_id"] == "cur456"
    assert payload["baseline_audit_id"] == "base123"
    assert payload["tag"] == "edge"
    assert payload["new_findings"] == ["[HIGH] rdp open to any"]
    assert payload["new_count"] == 1
    assert payload["resolved_count"] == 0
    assert payload["truncated"] is False


def test_resolved_findings_counted():
    findings = ["[MEDIUM] no logging", "[CRITICAL] any-any added"]
    mock = _fire(_PREV, findings)
    payload = mock.call_args[0][1]
    assert payload["resolved_count"] == 1  # telnet finding gone


def test_dispatch_errors_never_raise():
    with patch("cashel.webhooks.dispatch_event", side_effect=RuntimeError("boom")):
        _dispatch_regression_event(
            _PREV,
            _PREV["findings"] + ["[CRITICAL] x"],
            audit_id="a",
            tag="t",
            vendor="asa",
            host="h",
        )  # must not raise


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
