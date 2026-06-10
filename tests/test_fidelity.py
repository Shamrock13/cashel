"""Tests for the parser fidelity registry."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cashel._vendor_helpers import ALL_VENDORS  # noqa: E402
from cashel.fidelity import VENDOR_FIDELITY, vendor_fidelity  # noqa: E402

_MATURITY = {"mature", "partial", "experimental"}
_ENRICHMENT = {"full", "partial"}


def test_registry_covers_every_dispatchable_vendor():
    # "cisco" is a UI alias resolved to asa/ftd before dispatch.
    expected = ALL_VENDORS - {"cisco"}
    assert set(VENDOR_FIDELITY) == expected


def test_registry_values_are_constrained():
    for vendor, record in VENDOR_FIDELITY.items():
        assert record["maturity"] in _MATURITY, vendor
        assert record["enrichment"] in _ENRICHMENT, vendor
        assert record["display"], vendor
        assert record["notes"], vendor


def test_vendor_fidelity_includes_key():
    record = vendor_fidelity("asa")
    assert record["vendor"] == "asa"
    assert record["maturity"] == "mature"


def test_vendor_fidelity_unknown_is_explicit():
    record = vendor_fidelity("netscreen")
    assert record["maturity"] == "unknown"
    assert record["enrichment"] == "unknown"


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
