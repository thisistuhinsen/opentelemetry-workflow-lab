"""Owned native commands and a bounded-lifetime service-log companion."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

_WATCHERS: dict[int, subprocess.Popen] = {}


def _terminate_owned_tree(process: subprocess.Popen) -> None:
    """Terminate only the process group/tree created for this Popen child."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_native(
    argv, source=None, *, recorder=None, timeout=900, capture_return=True, stop_file: Path | None = None
):
    """Run a child with concurrent output draining and optional cooperative stop.

    ``stop_file`` is polled while the process runs. Creating it raises
    KeyboardInterrupt only after this owned child tree has been terminated and
    reaped, allowing a watcher to persist a terminal status before exiting.
    """
    started = time.monotonic()
    command_id = recorder.begin_native(argv) if recorder is not None else None
    options = (
        {"start_new_session": True}
        if os.name != "nt"
        else {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
    )
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if source is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=dict(os.environ, PYTHONUNBUFFERED="1"),
        **options,
    )
    collected = {"stdout": [], "stderr": []}
    errors = []

    def read(stream, name):
        try:
            for line in iter(stream.readline, ""):
                if capture_return:
                    collected[name].append(line)
                if recorder is not None:
                    recorder.append_native(command_id, **{name: line})
        except Exception as error:
            errors.append(error)
        finally:
            stream.close()

    threads = [
        threading.Thread(target=read, args=(process.stdout, "stdout"), daemon=True),
        threading.Thread(target=read, args=(process.stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        if source is not None:
            try:
                process.stdin.write(source)
                process.stdin.close()
            except BrokenPipeError:
                pass
        deadline = None if timeout is None else started + timeout
        while process.poll() is None:
            if stop_file is not None and stop_file.exists():
                raise KeyboardInterrupt
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                process.wait(timeout=0.1 if remaining is None else min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        _terminate_owned_tree(process)
        raise
    finally:
        for thread in threads:
            thread.join(timeout=10)
        if any(thread.is_alive() for thread in threads):
            _terminate_owned_tree(process)
            for thread in threads:
                thread.join(timeout=2)
        if recorder is not None:
            recorder.end_native(
                command_id,
                process.returncode if process.returncode is not None else -1,
                time.monotonic() - started,
            )
    if errors:
        raise RuntimeError(
            "The evidence folder could not retain command output; no next action was started."
        ) from errors[0]
    if process.returncode and process.returncode != 0:
        raise RuntimeError(
            f"A required command failed (exit {process.returncode}). Open its stderr in the run viewer; no application request was retried."
        )
    return "".join(collected["stdout"])


def _ready_identity(state_file: Path):
    try:
        fields = state_file.with_suffix(".ready").read_text(encoding="utf-8").split()
    except OSError:
        return None
    if len(fields) != 2:
        return None
    pid = _parse_marker_pid(fields[0])
    if pid is None:
        return None
    token = fields[1]
    if len(token) != 32 or any(character not in "0123456789abcdef" for character in token):
        return None
    return pid, token


def _parse_marker_pid(value: str):
    if len(value) > 10 or not value.isascii() or not value.isdecimal():
        return None
    try:
        pid = int(value)
    except ValueError:
        return None
    return pid if pid > 0 else None


def _watcher_argv(state_file: Path, evidence_root: str, handshake: str):
    return [
        sys.executable,
        str(Path(__file__).with_name("logwatch.py")),
        "--state",
        str(state_file),
        "--evidence",
        evidence_root,
        "--handshake",
        handshake,
    ]


def _pid_is_running(pid: int):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return None
    except OSError:
        return None
    return True


def _external_watcher_identity(pid: int, state_file: Path, platform: str | None = None):
    """Return owned, stopped, mismatched, or unknown without signaling a PID."""
    platform = sys.platform if platform is None else platform
    marker = _ready_identity(state_file)
    if marker is None:
        return "unknown", None
    marker_pid, handshake = marker
    if marker_pid != pid:
        return "mismatched", handshake
    try:
        state = json.loads(state_file.read_bytes())
        evidence_root = state.get("evidence_root") if isinstance(state, dict) else None
        if not isinstance(evidence_root, str) or not evidence_root:
            return "unknown", handshake
    except (OSError, ValueError, TypeError):
        return "unknown", handshake

    expected = _watcher_argv(state_file, evidence_root, handshake)
    try:
        if platform == "win32":
            script = (
                f"$process = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; "
                "if ($null -eq $process) { 'MISSING' } "
                "elseif ([string]::IsNullOrEmpty($process.CommandLine)) { 'UNREADABLE' } "
                "else { $process.CommandLine }"
            )
            observed = subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-Command", script],
                text=True,
                errors="replace",
                timeout=10,
            ).strip()
            if observed == "MISSING":
                return "stopped", handshake
            if observed == "UNREADABLE" or not observed:
                return "unknown", handshake
            return ("owned" if observed == subprocess.list2cmdline(expected) else "mismatched"), handshake
        if platform == "darwin":
            try:
                observed = subprocess.check_output(
                    ["ps", "-ww", "-p", str(pid), "-o", "command="],
                    text=True,
                    errors="replace",
                    timeout=10,
                ).strip()
            except subprocess.CalledProcessError:
                running = _pid_is_running(pid)
                return ("mismatched" if running else "stopped" if running is False else "unknown"), handshake
            if not observed:
                running = _pid_is_running(pid)
                return ("mismatched" if running else "stopped" if running is False else "unknown"), handshake
            return ("owned" if observed == " ".join(expected) else "mismatched"), handshake
        if platform.startswith("linux"):
            try:
                observed = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
            except FileNotFoundError:
                return "stopped", handshake
            except OSError:
                return "unknown", handshake
            if not observed:
                return "unknown", handshake
            decoded = [argument.decode("utf-8", "replace") for argument in observed]
            return ("owned" if decoded == expected else "mismatched"), handshake
    except (OSError, subprocess.SubprocessError):
        return "unknown", handshake
    return "unknown", handshake


def _watcher_identity(pid, state_file: Path):
    if type(pid) is not int or pid <= 0:
        return "stopped", None
    tracked = _WATCHERS.get(pid)
    if tracked is not None:
        if tracked.pid != pid:
            return "mismatched", None
        try:
            running = tracked.poll() is None
        except Exception:
            return "unknown", None
        marker = _ready_identity(state_file)
        if not running:
            return "stopped", marker[1] if marker and marker[0] == pid else None
        if marker is None or marker[0] != pid:
            return "unknown", None
        return "owned", marker[1]
    status, handshake = _external_watcher_identity(pid, state_file)
    if status != "owned" and handshake and _stopped_identity(state_file, pid, handshake):
        return "stopped", handshake
    return status, handshake


def watcher_matches(pid, state_file):
    return _watcher_identity(pid, Path(state_file))[0] == "owned"


def _stopped_identity(state_file: Path, pid: int, handshake: str):
    try:
        fields = state_file.with_suffix(".stopped").read_text(encoding="utf-8").split()
    except OSError:
        return False
    return len(fields) == 2 and _parse_marker_pid(fields[0]) == pid and fields[1] == handshake


def _forget_watcher(process: subprocess.Popen) -> None:
    for pid, owned in list(_WATCHERS.items()):
        if owned is process:
            _WATCHERS.pop(pid, None)


def _control_paths(state_file: Path):
    return (
        state_file.with_suffix(".ready"),
        state_file.with_suffix(".stop"),
        state_file.with_suffix(".stopped"),
    )


def _request_stop(state_file: Path) -> None:
    _, stop_file, _ = _control_paths(state_file)
    stop_file.parent.mkdir(parents=True, exist_ok=True)
    stop_file.write_text("stop\n", encoding="utf-8")


def _watcher_diagnostics(directory: Path) -> str:
    parts = []
    for name in ("watcher.stdout.log", "watcher.stderr.log"):
        path = directory / name
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8", errors="replace")[-4000:]
            except OSError as error:
                content = f"<could not read {name}: {error}>"
            if content.strip():
                parts.append(f"{name}:\n{content}")
    return "\n".join(parts)


def start_watcher(state, directory, evidence_root):
    state_file = Path(directory) / "state.json"
    current = state.get("log_pid")
    current_status, _ = _watcher_identity(current, state_file)
    if current_status == "owned":
        ready, _, _ = _control_paths(state_file)
        if ready.is_file():
            return current
        raise RuntimeError("The existing service-log watcher has no startup handshake.")
    if current_status in {"unknown", "mismatched"}:
        raise RuntimeError("Cannot verify the existing service-log watcher; no replacement was started.")
    ready, stop_file, stopped = _control_paths(state_file)
    for path in (ready, stop_file, stopped):
        path.unlink(missing_ok=True)
    handshake = uuid.uuid4().hex
    diagnostics = Path(evidence_root) / "watchers" / handshake
    diagnostics.mkdir(parents=True, exist_ok=False)
    state["watcher_diagnostics"] = str(diagnostics)
    options = (
        {"start_new_session": True}
        if os.name != "nt"
        else {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
    )
    stdout_log = (diagnostics / "watcher.stdout.log").open("ab")
    stderr_log = (diagnostics / "watcher.stderr.log").open("ab")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("logwatch.py")),
                "--state",
                str(state_file),
                "--evidence",
                str(evidence_root),
                "--handshake",
                handshake,
            ],
            stdin=subprocess.DEVNULL,
            stdout=stdout_log,
            stderr=stderr_log,
            **options,
        )
    finally:
        stdout_log.close()
        stderr_log.close()
    _WATCHERS[process.pid] = process
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ready.is_file():
            try:
                marker_pid, marker_token = ready.read_text(encoding="utf-8").strip().split(maxsplit=1)
                ready_pid = int(marker_pid)
            except (OSError, ValueError):
                ready_pid = -1
                marker_token = ""
            # The freshly generated nonce binds the marker to this launch. It
            # avoids OS command-line formatting differences while the live
            # Popen handle remains the process we wait for and reap.
            if ready_pid == process.pid and process.poll() is None:
                if marker_token == handshake:
                    _WATCHERS[ready_pid] = process
                    return ready_pid
        if process.poll() is not None:
            _forget_watcher(process)
            detail = _watcher_diagnostics(diagnostics)
            raise RuntimeError(
                f"Service-log watcher exited before ready (Popen PID {process.pid}, exit {process.returncode}).\n{detail}"
            )
        time.sleep(0.05)
    _request_stop(state_file)
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise TimeoutError(
            "Service-log watcher did not stop after startup timeout; process remains owned and was not force-killed."
        )
    if not _stopped_identity(state_file, process.pid, handshake):
        _forget_watcher(process)
        raise RuntimeError("Service-log watcher exited without a verified terminal stop marker.")
    _forget_watcher(process)
    detail = _watcher_diagnostics(diagnostics)
    try:
        reported_pid = ready.read_text(encoding="utf-8").strip() if ready.is_file() else "missing"
    except OSError:
        reported_pid = "unreadable"
    raise TimeoutError(
        f"Service-log watcher did not complete its startup handshake "
        f"(Popen PID {process.pid}, ready PID {reported_pid}).\n{detail}"
    )


def stop_watcher(state, directory):
    pid = state.get("log_pid")
    if type(pid) is not int or pid <= 0:
        return
    state_file = Path(directory) / "state.json"
    identity, handshake = _watcher_identity(pid, state_file)
    if identity == "stopped":
        process = _WATCHERS.pop(pid, None)
        if process is not None:
            process.wait(timeout=10)
            _forget_watcher(process)
        return
    if identity != "owned" or handshake is None:
        raise RuntimeError("Cannot verify the service-log watcher; no unrelated PID was signaled.")
    _request_stop(state_file)
    process = _WATCHERS.get(pid)
    if process is not None:
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(
                "Service-log watcher did not acknowledge stop; it was not force-killed."
            ) from error
        finally:
            _forget_watcher(process)
        if process.returncode is None:
            raise RuntimeError("Could not reap the service-log watcher process.")
        if not _stopped_identity(state_file, pid, handshake):
            raise RuntimeError("Service-log watcher stopped without a verified terminal marker.")
        return
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        identity, _ = _watcher_identity(pid, state_file)
        if _stopped_identity(state_file, pid, handshake):
            return
        if identity in {"unknown", "mismatched"}:
            raise RuntimeError("Watcher identity became unprovable during cleanup; no other PID was signaled.")
        if identity == "stopped":
            raise RuntimeError("Service-log watcher exited without a verified terminal marker.")
        time.sleep(0.1)
    raise TimeoutError(
        "Service-log watcher did not stop after the cooperative signal; no unrelated PID was killed."
    )
