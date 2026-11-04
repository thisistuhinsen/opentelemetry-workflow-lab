"""Small bounded CI diagnostics; these tests never invoke Docker."""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

PUBLIC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PUBLIC))
import ci_smoke  # noqa: E402


class FailureSummaryTests(unittest.TestCase):
    def test_detail_is_bounded_and_scrubs_common_sensitive_values(self):
        detail = ci_smoke.safe_failure_detail(
            "bad checkout for shopper@example.test card 4111111111111111 "
            "shop-11111111-1111-4111-8111-111111111111 "
            "token=secret-value Authorization: Bearer abc.def.ghi " + "x" * 400
        )
        self.assertLessEqual(len(detail), 240)
        self.assertNotIn("shopper@example.test", detail)
        self.assertNotIn("4111111111111111", detail)
        self.assertNotIn("11111111-1111-4111-8111-111111111111", detail)
        self.assertNotIn("secret-value", detail)
        self.assertNotIn("abc.def.ghi", detail)
        self.assertIn("[email]", detail)
        self.assertIn("[number]", detail)
        self.assertIn("[shopper]", detail)
        self.assertIn("[redacted]", detail)

    def test_failed_cli_emits_only_the_bounded_run_error_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            stderr = io.StringIO()

            def failed_cli(argv, *, stdout, **kwargs):
                stdout.write(b"raw output that must stay in the evidence log\n")
                ci_smoke.write_json(
                    campaign.evidence / "runs" / "run-1" / "run.json",
                    {
                        "command": "story",
                        "status": "failed",
                        "error": "Cart read for shopper@example.test returned 4111111111111111; "
                        "Authorization: Bearer abc.def.ghi",
                    },
                )
                return SimpleNamespace(returncode=1)

            with mock.patch.object(ci_smoke.subprocess, "run", side_effect=failed_cli):
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaisesRegex(RuntimeError, "Shop step failed"),
                ):
                    campaign.cli("story", "normal-checkout")

            output = stderr.getvalue()
            self.assertIn("Shop CI detail: phase=story status=failed", output)
            self.assertIn("Cart read for [email] returned [number]", output)
            self.assertNotIn("shopper@example.test", output)
            self.assertNotIn("4111111111111111", output)
            self.assertNotIn("abc.def.ghi", output)
            self.assertNotIn("raw output", output)

    def test_missing_run_directory_produces_no_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            self.assertEqual(campaign._new_failed_run_summary(set()), "")

    def test_oversized_run_record_produces_no_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            path = campaign.evidence / "runs" / "run-1" / "run.json"
            path.parent.mkdir(parents=True)
            path.write_text('{"command":"story","status":"failed","error":"' + "x" * 65537)
            self.assertEqual(campaign._new_failed_run_summary(set()), "")

    def test_malformed_run_record_produces_no_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            path = campaign.evidence / "runs" / "run-1" / "run.json"
            path.parent.mkdir(parents=True)
            path.write_text("not json")
            self.assertEqual(campaign._new_failed_run_summary(set()), "")

    def test_multiple_fresh_failed_run_records_produce_no_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            for name in ("run-1", "run-2"):
                ci_smoke.write_json(
                    campaign.evidence / "runs" / name / "run.json",
                    {"command": "story", "status": "failed", "error": "cart read failed"},
                )
            self.assertEqual(campaign._new_failed_run_summary(set()), "")


if __name__ == "__main__":
    unittest.main()
