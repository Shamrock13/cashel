"""Tests for alert_engine.py — threshold evaluation and dedup logic."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cashel.db as db_mod


def _tmp_db(fn):
    """Decorator: run test against an isolated temp database."""
    def wrapper(*args, **kwargs):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        orig_path = db_mod.DB_PATH
        orig_conn = getattr(db_mod._local, "conn", None)
        try:
            db_mod.DB_PATH = tmp
            db_mod._local.conn = None
            db_mod.init_db()
            return fn(*args, **kwargs)
        finally:
            conn = getattr(db_mod._local, "conn", None)
            if conn:
                conn.close()
            db_mod.DB_PATH = orig_path
            db_mod._local.conn = orig_conn
            try:
                os.unlink(tmp)
            except OSError:
                pass
    wrapper.__name__ = fn.__name__
    return wrapper


class TestAlertSchema(unittest.TestCase):
    @_tmp_db
    def test_alert_thresholds_table_exists(self):
        conn = db_mod.get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alert_thresholds'"
        ).fetchone()
        self.assertIsNotNone(row)

    @_tmp_db
    def test_alert_state_table_exists(self):
        conn = db_mod.get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alert_state'"
        ).fetchone()
        self.assertIsNotNone(row)


if __name__ == "__main__":
    unittest.main()
