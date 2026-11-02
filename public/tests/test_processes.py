import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from public import logwatch, processes
from public.evidence import EvidenceRecorder


class NativeProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workflow-processes-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def python(code):
        return [sys.executable, "-u", "-c", code]

    def test_stdout_and_stderr_are_durable_while_child_is_still_running(self):
        recorder = EvidenceRecorder(self.root / "evidence", "fake process", "Streaming test")
        code = (
            "import sys,time; print('stdout-first',flush=True); "
            "print('stderr-first',file=sys.stderr,flush=True); time.sleep(.8); "
            "print('stdout-final',flush=True)"
        )
        result = {}
        worker = threading.Thread(
            target=lambda: result.setdefault(
                "value", processes.run_native(self.python(code), recorder=recorder, timeout=30)
            )
        )
        worker.start()
        command_dir = recorder.directory / "commands"
        stdout_log = command_dir / "001.stdout.log"
        stderr_log = command_dir / "001.stderr.log"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if (
                stdout_log.exists()
                and stderr_log.exists()
                and "stdout-first" in stdout_log.read_text(encoding="utf-8")
                and "stderr-first" in stderr_log.read_text(encoding="utf-8")
            ):
                break
            time.sleep(0.03)
        was_running = worker.is_alive()
        stderr_text = stderr_log.read_text(encoding="utf-8") if stderr_log.exists() else ""
        worker.join(timeout=35)
        self.assertFalse(worker.is_alive())
        self.assertTrue(was_running, "child should still be running after first output is persisted")
        self.assertIn("stderr-first", stderr_text)
        self.assertIn("stdout-final", result["value"])
        self.assertIn("stdout-final", stdout_log.read_text(encoding="utf-8"))

    def test_nonzero_exit_is_reported_and_stderr_is_retained(self):
        recorder = EvidenceRecorder(self.root / "evidence", "failing fake process")
        with self.assertRaisesRegex(RuntimeError, "exit 7"):
            processes.run_native(
                self.python("import sys; print('failure detail',file=sys.stderr); sys.exit(7)"),
                recorder=recorder,
                timeout=30,
            )
        self.assertIn(
            "failure detail", (recorder.directory / "commands" / "001.stderr.log").read_text(encoding="utf-8")
        )
        manifest = json.loads((recorder.directory / "run.json").read_text(encoding="utf-8"))
        self.assertEqual("failed", manifest["commands"][0]["status"])

    def test_timeout_terminates_and_reaps_owned_child_tree(self):
        child_pid_file = self.root / "child.pid"
        code = (
            "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            f"open({str(child_pid_file)!r},'w').write(str(child.pid)); "
            "print('parent-started',flush=True); time.sleep(30)"
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            processes.run_native(self.python(code), timeout=15)
        self.assertTrue(child_pid_file.is_file())
        child_pid = int(child_pid_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self._pid_alive(child_pid):
            time.sleep(0.1)
        self.assertFalse(self._pid_alive(child_pid), "owned descendant survived timeout cleanup")

    @staticmethod
    def _pid_alive(pid):
        if os.name == "nt":
            try:
                value = subprocess.check_output(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-Command",
                        f"[bool](Get-Process -Id {pid} -ErrorAction SilentlyContinue)",
                    ],
                    text=True,
                    timeout=5,
                ).strip()
                return value.casefold() == "true"
            except subprocess.SubprocessError:
                return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def test_watcher_startup_handshake_and_cooperative_stop(self):
        directory = self.root / "run"
        directory.mkdir()
        state_file = directory / "state.json"
        state_file.write_text("{}", encoding="utf-8")
        evidence_root = self.root / "evidence"
        real_popen = subprocess.Popen
        child_process = {}

        def fake_logwatch_popen(argv, **kwargs):
            if len(argv) < 2 or Path(argv[1]).name != "logwatch.py":
                return real_popen(argv, **kwargs)
            script_path, state_path = argv[1], Path(argv[3])
            child_code = (
                "import os,pathlib,sys,time\n"
                "s=pathlib.Path(sys.argv[2])\n"
                "s.with_suffix('.ready').write_text(str(os.getpid())+' '+sys.argv[3])\n"
                "stop=s.with_suffix('.stop')\n"
                "while not stop.exists():\n time.sleep(.02)\n"
                "s.with_suffix('.stopped').write_text(str(os.getpid()))\n"
            )
            child_process["popen"] = real_popen(
                [sys.executable, "-c", child_code, str(script_path), str(state_path), str(argv[-1])], **kwargs
            )
            return child_process["popen"]

        original = processes.subprocess.Popen
        processes.subprocess.Popen = fake_logwatch_popen
        try:
            pid = processes.start_watcher({}, directory, evidence_root)
            self.assertTrue((directory / "state.ready").is_file())
            self.assertEqual(str(pid), (directory / "state.ready").read_text(encoding="utf-8").split()[0])
            self.assertIn(pid, processes._WATCHERS)
            self.assertTrue(processes.watcher_matches(pid, state_file))
            processes.stop_watcher({"log_pid": pid}, directory)
            self.assertTrue((directory / "state.stopped").is_file())
            self.assertIsNotNone(child_process["popen"].poll())
            self.assertIsNotNone(child_process["popen"].poll())
        finally:
            processes.subprocess.Popen = original
            process = child_process.get("popen")
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            processes._WATCHERS.clear()

    def test_watcher_stop_finishes_evidence_as_stopped(self):
        state_file = self.root / "state.json"
        evidence_root = self.root / "evidence"
        state_file.write_text(
            json.dumps(
                {
                    "story": "Fake lifecycle",
                    "project": "shop-abcdef123456",
                    "docker_context": "default",
                    "config": "fake-compose.yml",
                }
            ),
            encoding="utf-8",
        )
        original_argv = sys.argv
        original_runner = logwatch.run_native
        sys.argv = [
            "logwatch.py",
            "--state",
            str(state_file),
            "--evidence",
            str(evidence_root),
            "--handshake",
            "inert-test-handshake",
        ]
        logwatch.run_native = lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt())
        try:
            logwatch.main()
        finally:
            sys.argv = original_argv
            logwatch.run_native = original_runner
        runs = list((evidence_root / "runs").glob("*/run.json"))
        self.assertEqual(1, len(runs))
        self.assertEqual("stopped", json.loads(runs[0].read_text(encoding="utf-8"))["status"])
        self.assertTrue(state_file.with_suffix(".stopped").is_file())


if __name__ == "__main__":
    unittest.main()
