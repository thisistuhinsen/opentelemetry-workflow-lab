"""Keep service logs on the host while a sample shop is running."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:  # Package imports for tests; direct imports when invoked as a script.
    from . import shop
    from .evidence import EvidenceRecorder
    from .processes import run_native
except ImportError:
    import shop
    from evidence import EvidenceRecorder
    from processes import run_native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--handshake", required=True)
    args = parser.parse_args()
    state = json.loads(args.state.read_bytes())
    recorder = EvidenceRecorder(args.evidence, "Live service logs", state["story"])
    fixture = shop.synthetic_fixture()
    recorder.set_redactions([fixture["email"], fixture["creditCard"]["creditCardNumber"]])
    ready_file = args.state.with_suffix(".ready")
    stop_file = args.state.with_suffix(".stop")
    stopped_file = args.state.with_suffix(".stopped")
    try:
        recorder.phase("Following this shop's service logs; files are stored outside Docker.")
        ready_file.write_text(f"{os.getpid()} {args.handshake}", encoding="utf-8")
        run_native(
            shop.compose_args(state, ["logs", "--follow", "--timestamps", "--no-color"]),
            recorder=recorder,
            timeout=None,
            capture_return=False,
            stop_file=stop_file,
        )
        recorder.finish("passed")
    except KeyboardInterrupt:
        recorder.finish("stopped")
    except Exception as error:
        recorder.finish("failed", str(error))
        raise
    finally:
        stopped_file.write_text(str(os.getpid()), encoding="utf-8")


if __name__ == "__main__":
    main()
