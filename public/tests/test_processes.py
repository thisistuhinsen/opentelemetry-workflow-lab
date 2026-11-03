import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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
        if sys.platform.startswith("linux"):
            try:
                fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
                if fields and fields[0] in {"Z", "X"}:
                    return False
            except FileNotFoundError:
                return False
            except OSError:
                pass
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
                "s.with_suffix('.stopped').write_text(str(os.getpid())+' '+sys.argv[3]+'\\n')\n"
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
        self.assertEqual(
            f"{os.getpid()} inert-test-handshake",
            state_file.with_suffix(".stopped").read_text(encoding="utf-8").strip(),
        )

    def _write_external_watcher_identity(self, directory, pid, token, *, evidence_root=None):
        directory.mkdir(parents=True, exist_ok=True)
        state_file = directory / "state.json"
        evidence_root = evidence_root or directory / "evidence with spaces"
        state_file.write_text(json.dumps({"evidence_root": str(evidence_root)}), encoding="utf-8")
        state_file.with_suffix(".ready").write_text(f"{pid} {token}", encoding="utf-8")
        argv = [
            sys.executable,
            str(Path(processes.__file__).with_name("logwatch.py")),
            "--state",
            str(state_file),
            "--evidence",
            str(evidence_root),
            "--handshake",
            token,
        ]
        return state_file, argv

    def test_macos_watcher_detection_uses_ps_and_preserves_paths_with_spaces(self):
        pid = 41237
        token = "a" * 32
        state_file, argv = self._write_external_watcher_identity(self.root / "run with spaces", pid, token)
        with patch.object(processes.sys, "platform", "darwin"), patch.object(
            processes.subprocess, "check_output", return_value=" ".join(argv)
        ) as check_output:
            self.assertTrue(processes.watcher_matches(pid, state_file))
        check_output.assert_called_once_with(
            ["ps", "-ww", "-p", str(pid), "-o", "command="], text=True, errors="replace", timeout=10
        )

    def test_reused_pid_with_different_handshake_is_not_owned(self):
        pid = 41238
        state_file, argv = self._write_external_watcher_identity(self.root / "run", pid, "b" * 32)
        observed = " ".join(argv[:-1] + ["c" * 32])
        with patch.object(processes.sys, "platform", "darwin"), patch.object(
            processes.subprocess, "check_output", return_value=observed
        ):
            self.assertFalse(processes.watcher_matches(pid, state_file))

    def test_stale_pid_without_a_live_proc_entry_is_not_owned(self):
        pid = 41239
        state_file, _ = self._write_external_watcher_identity(self.root / "stale run", pid, "9" * 32)
        original_read_bytes = Path.read_bytes

        def stale_proc_entry(path):
            if path == Path(f"/proc/{pid}/cmdline"):
                raise FileNotFoundError(path)
            return original_read_bytes(path)

        with patch.object(processes.sys, "platform", "linux"), patch.object(Path, "read_bytes", stale_proc_entry):
            self.assertFalse(processes.watcher_matches(pid, state_file))

    def test_windows_commandline_matching_keeps_windows_quoting(self):
        pid = 41246
        state_file, argv = self._write_external_watcher_identity(self.root / "windows run", pid, "8" * 32)
        command_line = subprocess.list2cmdline(argv)
        with patch.object(processes.subprocess, "check_output", return_value=command_line) as check_output:
            status, token = processes._external_watcher_identity(pid, state_file, "win32")
        self.assertEqual(("owned", "8" * 32), (status, token))
        check_output.assert_called_once_with(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"$process = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; "
                "if ($null -eq $process) { 'MISSING' } "
                "elseif ([string]::IsNullOrEmpty($process.CommandLine)) { 'UNREADABLE' } "
                "else { $process.CommandLine }",
            ],
            text=True,
            errors="replace",
            timeout=10,
        )

    def test_windows_unreadable_commandline_is_unknown_not_stopped(self):
        pid = 41247
        state_file, _ = self._write_external_watcher_identity(self.root / "windows run", pid, "7" * 32)
        with patch.object(processes.subprocess, "check_output", return_value="UNREADABLE"):
            self.assertEqual(("unknown", "7" * 32), processes._external_watcher_identity(pid, state_file, "win32"))

    def test_windows_missing_pid_is_stopped(self):
        pid = 41248
        state_file, _ = self._write_external_watcher_identity(self.root / "windows run", pid, "6" * 32)
        with patch.object(processes.subprocess, "check_output", return_value="MISSING"):
            self.assertEqual(("stopped", "6" * 32), processes._external_watcher_identity(pid, state_file, "win32"))

    def test_ready_marker_for_wrong_pid_is_not_owned_or_probed(self):
        state_file, _ = self._write_external_watcher_identity(self.root / "run", 41240, "d" * 32)
        with patch.object(processes.sys, "platform", "darwin"), patch.object(
            processes.subprocess, "check_output"
        ) as check_output:
            self.assertFalse(processes.watcher_matches(41241, state_file))
        check_output.assert_not_called()

    def test_oversized_pid_markers_fail_closed_without_integer_overflow(self):
        pid = 41249
        state_file, _ = self._write_external_watcher_identity(self.root / "oversized pid", pid, "5" * 32)
        oversized = "9" * 5000
        state_file.with_suffix(".ready").write_text(f"{oversized} {'5' * 32}", encoding="utf-8")
        state_file.with_suffix(".stopped").write_text(f"{oversized} {'5' * 32}", encoding="utf-8")
        self.assertIsNone(processes._ready_identity(state_file))
        self.assertFalse(processes._stopped_identity(state_file, pid, "5" * 32))
        self.assertFalse(processes.watcher_matches(pid, state_file))

    def test_stopped_tracked_watcher_does_not_match(self):
        process = type("ExitedProcess", (), {"pid": 41242, "poll": lambda self: 0})()
        processes._WATCHERS[process.pid] = process
        try:
            self.assertFalse(processes.watcher_matches(process.pid, self.root / "missing-state.json"))
        finally:
            processes._WATCHERS.pop(process.pid, None)

    def test_unreadable_watcher_identity_fails_closed_without_stop_signal(self):
        pid = 41243
        state_file, _ = self._write_external_watcher_identity(self.root / "run", pid, "e" * 32)
        with patch.object(processes.sys, "platform", "darwin"), patch.object(
            processes.subprocess, "check_output", side_effect=PermissionError("process listing denied")
        ), patch.object(processes, "_request_stop") as request_stop:
            with self.assertRaisesRegex(RuntimeError, "(?i)cannot verify.*watcher|watcher.*cannot verify"):
                processes.stop_watcher({"log_pid": pid}, state_file.parent)
        request_stop.assert_not_called()

    def test_start_refuses_to_replace_watcher_when_identity_readback_fails(self):
        pid = 41244
        directory = self.root / "run"
        state_file, _ = self._write_external_watcher_identity(directory, pid, "f" * 32)
        original_read_text = Path.read_text

        def fail_ready_read(path, *args, **kwargs):
            if path == state_file.with_suffix(".ready"):
                raise PermissionError("ready marker unreadable")
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", fail_ready_read), patch.object(processes.sys, "platform", "darwin"):
            with self.assertRaisesRegex(RuntimeError, "(?i)cannot verify.*watcher|watcher.*cannot verify"):
                processes.start_watcher({"log_pid": pid}, directory, self.root / "evidence")

    def test_terminal_marker_readback_failure_is_not_reported_as_clean_stop(self):
        pid = 41245
        state_file, _ = self._write_external_watcher_identity(self.root / "run", pid, "1" * 32)

        class ExitedProcess:
            returncode = None

            def poll(self):
                return None

            def wait(self, timeout):
                self.returncode = 0
                return 0

        process = ExitedProcess()
        process.pid = pid
        processes._WATCHERS[pid] = process
        try:
            with patch.object(processes, "_request_stop"), patch.object(processes, "_stopped_identity", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "terminal marker"):
                    processes.stop_watcher({"log_pid": pid}, state_file.parent)
        finally:
            processes._WATCHERS.pop(pid, None)


if __name__ == "__main__":
    unittest.main()
