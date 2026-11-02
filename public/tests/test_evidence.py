import json
import re
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from public.evidence import EvidenceRecorder


class EvidenceRecorderTests(unittest.TestCase):
    def test_finish_immediately_publishes_terminal_status(self):
        recorder = EvidenceRecorder(self.root, "quick command")
        recorder.phase("One quick step")
        recorder.finish("passed")
        page = recorder.index_path.read_text(encoding="utf-8")
        data = json.loads(
            re.search(r'<script id="evidence-data" type="application/json">(.*?)</script>', page, re.S)[1]
        )
        self.assertEqual(data["runs"][0]["status"], "passed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workflow-evidence-")
        self.root = Path(self.temp.name) / "evidence"

    def tearDown(self):
        self.temp.cleanup()

    def test_persists_run_after_external_state_is_removed(self):
        recorder = EvidenceRecorder(self.root, "docker compose up", "Checkout workflow")
        recorder.phase("Starting local services", status="running", service="collector")
        recorder.native(["docker", "compose", "up"], "ready\n", "", 0, 1.25)
        recorder.result({"status": "passed", "checks": 3})
        recorder.finish("completed")
        transient = self.root / "fake-docker-state"
        transient.mkdir()
        (transient / "state.json").write_text('{"running":true}', encoding="utf-8")
        shutil.rmtree(transient)

        run_dir = self.root / "runs" / recorder.run_id
        run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual("completed", run["status"])
        self.assertTrue((run_dir / "commands" / "001.stdout.log").is_file())
        self.assertEqual(
            {"checks": 3, "status": "passed"},
            json.loads((run_dir / "result.json").read_text(encoding="utf-8")),
        )
        self.assertTrue(recorder.index_path.is_file())

    def test_unique_runs_preserve_prior_run(self):
        first = EvidenceRecorder(self.root, "first", "First case")
        first.phase("done", status="completed")
        second = EvidenceRecorder(self.root, "second", "Second case")
        second.finish("failed", error="example failure")
        page = second.index_path.read_text(encoding="utf-8")
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertIn(first.run_id, page)
        self.assertIn(second.run_id, page)
        self.assertTrue((self.root / "runs" / first.run_id / "events.jsonl").is_file())

    def test_untrusted_content_is_not_interpreted_as_html(self):
        payload = '</script><img src=x onerror="alert(1)">'
        recorder = EvidenceRecorder(self.root, "run", payload)
        recorder.phase(payload)
        recorder.native(["echo", payload], payload, payload, 0, 0.1)
        recorder.result({"message": payload})
        page = recorder.index_path.read_text(encoding="utf-8")
        self.assertNotIn(payload, page)
        self.assertIn("\\u003c/script\\u003e", page)
        self.assertIn("Run JSON", page)

    def test_redacts_supplied_and_obvious_credentials(self):
        recorder = EvidenceRecorder(self.root, "run")
        recorder.set_redactions(["sample-private-value"])
        recorder.native(
            ["tool", "--token=sample-private-value"],
            "sample-private-value\nBearer abcdefghijklmnop\napi_key=hidden-value\nghp_1234567890abcdef",
            "",
            0,
            0.1,
        )
        saved = "\n".join(p.read_text(encoding="utf-8") for p in self.root.rglob("*") if p.is_file())
        self.assertNotIn("sample-private-value", saved)
        self.assertNotIn("abcdefghijklmnop", saved)
        self.assertNotIn("hidden-value", saved)
        self.assertNotIn("ghp_1234567890abcdef", saved)
        self.assertIn("[REDACTED]", saved)

    def test_local_links_are_relative_and_json_matches_run_files(self):
        recorder = EvidenceRecorder(self.root, "local command", "Story")
        recorder.native(["echo", "ok"], "ok", "", 0, 0.02)
        page = recorder.index_path.read_text(encoding="utf-8")
        self.assertIn('"run":"runs/', page)
        self.assertIn('"stdout":"runs/', page)
        self.assertNotIn("file://", page)
        manifest = json.loads((recorder.directory / "run.json").read_text(encoding="utf-8"))
        self.assertEqual("local command", manifest["command"])
        self.assertEqual(0, manifest["commands"][0]["exit_code"])

    def test_streaming_logs_are_visible_before_finish_and_preview_is_bounded(self):
        recorder = EvidenceRecorder(self.root, "long-running command", "Streaming case")
        command_id = recorder.begin_native(["worker", "--watch"])
        stdout_path = recorder.directory / "commands" / f"{command_id}.stdout.log"
        self.assertTrue(stdout_path.is_file())
        initial = recorder.index_path.read_text(encoding="utf-8")
        self.assertIn('"status":"running"', initial)

        # Allow the normal 500ms index throttle to elapse, as a real reader
        # thread would while the child process continues to emit output.
        time.sleep(0.51)
        chunk = "PREFIX_MARK" + ("x" * 9000) + "TAIL_MARK"
        recorder.append_native(command_id, stdout=chunk, stderr="warning\n")
        live_page = recorder.index_path.read_text(encoding="utf-8")
        self.assertIn("TAIL_MARK", live_page)
        self.assertIn("Showing final 8,000 characters", live_page)
        self.assertNotIn("PREFIX_MARK", live_page)
        self.assertLess(len(live_page), 40000)
        self.assertEqual(chunk, stdout_path.read_text(encoding="utf-8"))

        recorder.end_native(command_id, 0, 0.75)
        finished_page = recorder.index_path.read_text(encoding="utf-8")
        self.assertIn('"status":"completed"', finished_page)

    def test_artifacts_link_only_contained_files_and_directories(self):
        recorder = EvidenceRecorder(self.root, "workflow", "Artifact case")
        source = recorder.root / "inputs" / "rendered config.yaml"
        source.parent.mkdir()
        source.write_text("safe: true\n", encoding="utf-8")
        traces = recorder.root / "application traces"
        traces.mkdir()
        recorder.artifact("Rendered configuration", source)
        recorder.artifact("Application traces folder", traces)

        page = recorder.index_path.read_text(encoding="utf-8")
        manifest = json.loads((recorder.directory / "run.json").read_text(encoding="utf-8"))
        self.assertIn("Rendered configuration", page)
        self.assertIn("Application traces folder", page)
        self.assertEqual("inputs/rendered%20config.yaml", manifest["artifacts"][0]["href"])
        self.assertEqual("directory", manifest["artifacts"][1]["kind"])

        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("not in evidence root", encoding="utf-8")
        with self.assertRaises(ValueError):
            recorder.artifact("Outside file", outside)
        self.assertNotIn("Outside file", recorder.index_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
