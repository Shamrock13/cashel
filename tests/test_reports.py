"""Route tests for /remediation-plan and /demo/sample-report.pdf."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_client():
    import cashel.web as web_mod

    app = web_mod.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    return app.test_client()


def _ensure_user_exists():
    """Create a test user so has_users() returns True and the auth gate passes."""
    from cashel import user_store as us
    from cashel.user_store import UserValidationError

    try:
        us.create_user("testadmin", "TestPass123!", "admin")
    except UserValidationError:
        pass  # user already exists — fine


SAMPLE_PAYLOAD = {
    "findings": [
        {
            "severity": "HIGH",
            "category": "exposure",
            "message": "[HIGH] permit ip any any",
            "remediation": "Replace with specific rules.",
        }
    ],
    "vendor": "asa",
    "filename": "test.txt",
}

SAMPLE_SUMMARY = {"critical": 1, "high": 2, "medium": 3, "low": 0, "total": 6, "score": 51}


class TestRemediationPdfInline(unittest.TestCase):
    def setUp(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        # Isolated temp DB so tests pass regardless of execution order.
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self._tmp_db_path = f.name
        self._orig_db_path = db_mod.DB_PATH
        self._orig_db_conn = getattr(db_mod._local, "conn", None)
        db_mod.DB_PATH = self._tmp_db_path
        db_mod._local.conn = None
        db_mod.init_db()

        # Use an isolated temp settings file with auth disabled so routes are
        # reachable without a login session.
        self.tmp_dir = tempfile.mkdtemp()
        self._tmp_settings = os.path.join(self.tmp_dir, "settings.json")
        self._orig_settings_file = settings_mod.SETTINGS_FILE
        settings_mod.SETTINGS_FILE = self._tmp_settings

        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = self.tmp_dir

        self.client = _make_client()
        _ensure_user_exists()

    def tearDown(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        conn = getattr(db_mod._local, "conn", None)
        if conn:
            conn.close()
        db_mod.DB_PATH = self._orig_db_path
        db_mod._local.conn = self._orig_db_conn
        try:
            os.unlink(self._tmp_db_path)
        except OSError:
            pass

        settings_mod.SETTINGS_FILE = self._orig_settings_file

        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def test_pdf_inline_returns_pdf_content_type(self):
        resp = self.client.post(
            "/remediation-plan?fmt=pdf&inline=1",
            json=SAMPLE_PAYLOAD,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/pdf", resp.content_type)

    def test_pdf_inline_does_not_set_attachment_disposition(self):
        resp = self.client.post(
            "/remediation-plan?fmt=pdf&inline=1",
            json=SAMPLE_PAYLOAD,
        )
        cd = resp.headers.get("Content-Disposition", "")
        self.assertNotIn("attachment", cd)

    def test_pdf_attachment_still_works(self):
        """Default (no inline=1) must remain attachment for backward compat."""
        resp = self.client.post(
            "/remediation-plan?fmt=pdf",
            json=SAMPLE_PAYLOAD,
        )
        self.assertEqual(resp.status_code, 200)
        cd = resp.headers.get("Content-Disposition", "")
        self.assertIn("attachment", cd)


class TestReportViewer(unittest.TestCase):
    def setUp(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            self._tmp_db_path = f.name
        self._orig_db_path = db_mod.DB_PATH
        self._orig_db_conn = getattr(db_mod._local, "conn", None)
        db_mod.DB_PATH = self._tmp_db_path
        db_mod._local.conn = None
        db_mod.init_db()

        self.tmp_dir = tempfile.mkdtemp()
        self._tmp_settings = os.path.join(self.tmp_dir, "settings.json")
        self._orig_settings_file = settings_mod.SETTINGS_FILE
        settings_mod.SETTINGS_FILE = self._tmp_settings

        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = self.tmp_dir
        self.client = _make_client()
        _ensure_user_exists()

    def tearDown(self):
        import cashel.db as db_mod
        import cashel.settings as settings_mod

        conn = getattr(db_mod._local, "conn", None)
        if conn:
            conn.close()
        db_mod.DB_PATH = self._orig_db_path
        db_mod._local.conn = self._orig_db_conn
        try:
            os.unlink(self._tmp_db_path)
        except OSError:
            pass

        settings_mod.SETTINGS_FILE = self._orig_settings_file

        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder
        import cashel.blueprints.reports as r

        r.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def _write_report_with_sidecar(self):
        from cashel.reporter import generate_report, report_sidecar_path, write_report_sidecar

        path = os.path.join(self.tmp_dir, "cashel_report_test.pdf")
        findings = SAMPLE_PAYLOAD["findings"]
        generate_report(
            findings,
            "edge-fw.txt",
            "asa",
            "cis",
            output_path=path,
            summary=SAMPLE_SUMMARY,
        )
        sidecar = write_report_sidecar(
            path,
            findings=findings,
            filename="edge-fw.txt",
            vendor="asa",
            compliance="cis",
            summary=SAMPLE_SUMMARY,
            report_id="csh_test_123",
            generated_at="2026-05-01T12:56:00+00:00",
        )
        self.assertEqual(sidecar, report_sidecar_path(path))
        self.assertTrue(os.path.exists(sidecar))
        return path

    def test_report_viewer_returns_html_with_dynamic_data(self):
        self._write_report_with_sidecar()
        resp = self.client.get("/reports/cashel_report_test.pdf/view")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)
        body = resp.data.decode()
        self.assertIn("edge-fw.txt", body)
        self.assertIn("Cisco", body)
        self.assertIn("51", body)
        self.assertIn("permit ip any any", body)
        self.assertIn("csh_test_123", body)

    def test_report_viewer_falls_back_without_sidecar(self):
        path = os.path.join(self.tmp_dir, "legacy.pdf")
        with open(path, "wb") as fh:
            fh.write(b"%PDF-1.4\n")

        resp = self.client.get("/reports/legacy.pdf/view")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)
        body = resp.data.decode()
        self.assertIn("Limited report metadata", body)
        self.assertIn("legacy.pdf", body)


class TestDemoSampleReport(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self._orig_folder = os.environ.get("REPORTS_FOLDER")
        os.environ["REPORTS_FOLDER"] = self.tmp_dir
        import cashel.blueprints.audit as a

        a.REPORTS_FOLDER = self.tmp_dir
        self.client = _make_client()

    def tearDown(self):
        if self._orig_folder is None:
            os.environ.pop("REPORTS_FOLDER", None)
        else:
            os.environ["REPORTS_FOLDER"] = self._orig_folder
        import cashel.blueprints.audit as a

        a.REPORTS_FOLDER = (
            self._orig_folder
            if self._orig_folder is not None
            else "/tmp/cashel_reports"
        )

    def test_sample_report_returns_200(self):
        resp = self.client.get("/demo/sample-report.pdf")
        self.assertEqual(resp.status_code, 200)

    def test_sample_report_content_type_is_pdf(self):
        resp = self.client.get("/demo/sample-report.pdf")
        self.assertIn("application/pdf", resp.content_type)

    def test_sample_report_is_inline_not_attachment(self):
        resp = self.client.get("/demo/sample-report.pdf")
        cd = resp.headers.get("Content-Disposition", "")
        self.assertNotIn("attachment", cd)

    def test_sample_report_returns_non_empty_pdf(self):
        resp = self.client.get("/demo/sample-report.pdf")
        self.assertTrue(resp.data[:4] == b"%PDF")


class TestModalMarkup(unittest.TestCase):
    def test_webhook_and_remediation_modals_use_scoped_layouts(self):
        template_path = os.path.join(
            os.path.dirname(__file__), "..", "src", "cashel", "templates", "index.html"
        )
        with open(template_path, encoding="utf-8") as fh:
            body = fh.read()

        self.assertIn("modal webhook-modal", body)
        self.assertIn("event-picker", body)
        self.assertIn("modal remediation-modal", body)
        self.assertIn("rem-summary-bar", body)
        self.assertNotIn('class="modal remediation-modal" style=', body)
        self.assertNotIn('class="modal" style="max-width:520px"', body)
