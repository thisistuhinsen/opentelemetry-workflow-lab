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
                        "finished_at": "2026-11-04T00:00:01Z",
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

    def test_failed_agent_cli_includes_only_allowlisted_phase_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            stderr = io.StringIO()
            secret = "private fixture response and api key"

            def failed_cli(argv, *, stdout, **kwargs):
                ci_smoke.write_json(
                    campaign.evidence / "runs" / "run-agent" / "run.json",
                    {
                        "command": "agent-replay",
                        "status": "failed",
                        "finished_at": "2026-11-04T00:00:01Z",
                        "error": "A required command failed (exit 1).",
                        "commands": [{"status": "failed", "stderr_name": "001.stderr.log"}],
                        "result": {
                            "failure_stage": "fixture-endpoint",
                            "error_type": "HTTPError",
                            "runtime_guard_check": "vcr-record-mode",
                            "runtime_guard_error_type": "RuntimeError",
                            "prompt": secret,
                            "api_key": secret,
                        },
                    },
                )
                log_dir = campaign.evidence / "runs" / "run-agent" / "commands"
                log_dir.mkdir()
                (log_dir / "001.stderr.log").write_text(
                    "RuntimeError: cassette fixture endpoint failed\n", encoding="utf-8"
                )
                return SimpleNamespace(returncode=1)

            with mock.patch.object(ci_smoke.subprocess, "run", side_effect=failed_cli):
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaisesRegex(RuntimeError, "Shop step failed"),
                ):
                    campaign.cli("agent-replay")

            output = stderr.getvalue()
            self.assertIn(
                "cassette fixture endpoint failed agent_replay=",
                output,
            )
            self.assertIn(
                'agent_replay={"error_type":"HTTPError","failure_stage":"fixture-endpoint",'
                '"runtime_guard_check":"vcr-record-mode","runtime_guard_error_type":"RuntimeError"}',
                output,
            )
            self.assertNotIn(secret, output)
            self.assertNotIn("api_key", output)

    def test_agent_failure_uses_last_phase_if_result_record_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            run_path = campaign.evidence / "runs" / "run-agent" / "run.json"
            ci_smoke.write_json(
                run_path,
                {
                    "command": "agent-replay",
                    "status": "failed",
                    "finished_at": "2026-11-04T00:00:01Z",
                    "error": "Agent replay failed",
                    "events": [
                        {
                            "type": "phase",
                            "metadata": {"agent_replay_stage": "runtime-guard"},
                        },
                        {
                            "type": "phase",
                            "metadata": {"agent_replay_stage": {"untrusted": "ignored"}},
                        },
                    ],
                },
            )
            detail = campaign._new_failed_run_summary(set(), "agent-replay")
            self.assertIn('agent_replay={"last_observed_stage":"runtime-guard"}', detail)
            self.assertNotIn("untrusted", detail)

    def test_failed_cli_falls_back_to_redacted_command_log_when_run_records_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            stderr = io.StringIO()

            def failed_cli(argv, *, stdout, **kwargs):
                stdout.write(
                    b"raw response for shopper@example.test must not appear\n"
                    b"Traceback (most recent call last):\n"
                    b"ValueError: Cart read is unknown for shopper@example.test; "
                    b"token=secret-value Authorization: Bearer abc.def.ghi "
                    b"https://user:pass@example.test/path github_pat_12345678901234567890 "
                    b"\x1b[31mcolored\x1b[0m\n"
                )
                for run_id in ("run-a", "run-b"):
                    ci_smoke.write_json(
                        campaign.evidence / "runs" / run_id / "run.json",
                        {
                            "command": "story",
                            "status": "failed",
                            "finished_at": "2026-11-04T00:00:01Z",
                            "error": "ambiguous",
                        },
                    )
                return SimpleNamespace(returncode=1)

            with mock.patch.object(ci_smoke.subprocess, "run", side_effect=failed_cli):
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaisesRegex(RuntimeError, "Shop step failed"),
                ):
                    campaign.cli("story", "shared-cart-conflict")

            output = stderr.getvalue()
            self.assertIn("phase=story status=failed exit=1 exception=ValueError", output)
            self.assertIn("Cart read is unknown for [email]", output)
            self.assertIn("token=[redacted]", output)
            self.assertIn("Authorization=[redacted]", output)
            self.assertIn("https://[credentials]@example.test/path", output)
            self.assertIn("[credential]", output)
            self.assertIn("colored", output)
            for raw in (
                "shopper@example.test",
                "secret-value",
                "abc.def.ghi",
                "user:pass",
                "github_pat_12345678901234567890",
                "\x1b[31m",
                "raw response",
            ):
                self.assertNotIn(raw, output)

    def test_failed_cli_emits_phase_and_exit_when_log_has_no_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            stderr = io.StringIO()

            def failed_cli(argv, *, stdout, **kwargs):
                stdout.write(b"raw output remains in the evidence log\n")
                return SimpleNamespace(returncode=1)

            with mock.patch.object(ci_smoke.subprocess, "run", side_effect=failed_cli):
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaisesRegex(RuntimeError, "Shop step failed"),
                ):
                    campaign.cli("story", "shared-cart-conflict")

            output = stderr.getvalue()
            self.assertIn(
                "phase=story status=failed exit=1 error=terminal exception detail unavailable",
                output,
            )
            self.assertNotIn("raw output", output)

    def test_failed_cli_reads_only_the_shop_error_line_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            stderr = io.StringIO()

            def failed_cli(argv, *, stdout, **kwargs):
                stdout.write(
                    b"Shop could not complete this step: cart read failed for "
                    b"shopper@example.test; token=secret-value\n"
                    b"raw response body must not appear\n"
                )
                return SimpleNamespace(returncode=1)

            with mock.patch.object(ci_smoke.subprocess, "run", side_effect=failed_cli):
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaisesRegex(RuntimeError, "Shop step failed"),
                ):
                    campaign.cli("story", "shared-cart-conflict")

            output = stderr.getvalue()
            self.assertIn("phase=story status=failed exit=1", output)
            self.assertIn("cart read failed for [email]; token=[redacted]", output)
            self.assertNotIn("shopper@example.test", output)
            self.assertNotIn("secret-value", output)
            self.assertNotIn("raw response body", output)

    def test_failed_native_stderr_is_joined_to_the_primary_run_not_live_companion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = ci_smoke.Campaign(root / "state", root / "evidence")
            stderr = io.StringIO()

            def failed_cli(argv, *, stdout, **kwargs):
                primary = campaign.evidence / "runs" / "primary"
                commands = primary / "commands"
                commands.mkdir(parents=True)
                (commands / "001.stderr.log").write_text(
                    "TypeError: fetch failed; cause=Error: connect ECONNREFUSED "
                    "127.0.0.1:8080 for shopper@example.test\n",
                    encoding="utf-8",
                )
                ci_smoke.write_json(
                    primary / "run.json",
                    {
                        "command": "story",
                        "status": "failed",
                        "finished_at": "2026-11-04T00:00:01Z",
                        "error": "A required command failed (exit 127). Open stderr in the run viewer.",
                        "commands": [{"status": "failed", "stderr_name": "001.stderr.log"}],
                    },
                )
                ci_smoke.write_json(
                    campaign.evidence / "runs" / "companion" / "run.json",
                    {"command": "Live service logs", "status": "running"},
                )
                return SimpleNamespace(returncode=1)

            with mock.patch.object(ci_smoke.subprocess, "run", side_effect=failed_cli):
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaisesRegex(RuntimeError, "Shop step failed"),
                ):
                    campaign.cli("story", "shared-cart-conflict")

            output = stderr.getvalue()
            self.assertIn(
                "Shop CI detail: phase=story status=failed error=TypeError: fetch failed; "
                "cause=Error: connect ECONNREFUSED 127.0.0.1:8080 for [email]",
                output,
            )
            self.assertNotIn("shopper@example.test", output)
            self.assertNotIn("Open stderr in the run viewer", output)

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
                    {
                        "command": "story",
                        "status": "failed",
                        "finished_at": "2026-11-04T00:00:01Z",
                        "error": "cart read failed",
                    },
                )
            self.assertEqual(campaign._new_failed_run_summary(set()), "")


if __name__ == "__main__":
    unittest.main()
