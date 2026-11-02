"""Materialize pinned public source only. No Docker, builds or application actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from source_integrity import freeze_inventory, verify_source

PUBLIC = Path(__file__).resolve().parent
PACKAGE = PUBLIC.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(argv, check=True, capture_output=True, env=env)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-runtime", required=True, action="store_true")
    parser.add_argument("--variant", choices=("original", "mcp-session-id"), default="original")
    parser.add_argument("--destination", type=Path, default=PACKAGE / "external/workspace/opentelemetry-demo")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--materialize", action="store_true")
    parser.add_argument("--offline-archive-from", type=Path)
    parser.add_argument("--allow-network-clone", action="store_true")
    args = parser.parse_args(argv)
    if args.dry_run and args.materialize:
        parser.error("--dry-run and --materialize are mutually exclusive")
    if args.offline_archive_from and args.allow_network_clone:
        parser.error("choose one source acquisition mode")
    manifest = json.loads((PUBLIC / "source-manifest.json").read_bytes())
    variant = manifest["variants"][args.variant]
    for patch in variant["patches"]:
        if sha(PUBLIC / patch["file"]) != patch["sha256"]:
            raise ValueError("Public source patch hash mismatch")
    destination = args.destination.absolute()
    plan = {
        "mode": "SOURCE_ONLY",
        "runtime": "FORBIDDEN",
        "variant": args.variant,
        "upstream": manifest["upstream"]["url"],
        "source_commit": variant["base_commit"],
        "patch_sha256": [p["sha256"] for p in variant["patches"]],
        "destination": str(destination),
        "cold_reconstruction": "NOT_RUN",
    }
    if not args.materialize:
        print(json.dumps({**plan, "status": "DRY_RUN_NO_COMMANDS_DISPATCHED"}, indent=2))
        return 0
    if destination.exists():
        raise FileExistsError("Source destination already exists; never overwrite or reuse it")
    if any(
        destination.with_name(destination.name + suffix).exists()
        for suffix in (".source-receipt.json", ".source-inventory.json")
    ):
        raise FileExistsError("Source binding files already exist; choose a fresh source folder")
    if not args.offline_archive_from and not args.allow_network_clone:
        parser.error("Materialization requires --offline-archive-from or explicit --allow-network-clone")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if args.offline_archive_from:
        source = args.offline_archive_from.absolute()
        commit = (
            run(
                [
                    "git",
                    "-c",
                    "core.autocrlf=false",
                    "-c",
                    "core.eol=lf",
                    "-C",
                    str(source),
                    "rev-parse",
                    variant["base_commit"] + "^{commit}",
                ]
            )
            .stdout.decode()
            .strip()
        )
        if commit != variant["base_commit"]:
            raise ValueError("Local object store does not resolve the exact public source pin")
        with tempfile.TemporaryDirectory(prefix="source-archive-", dir=destination.parent) as temporary:
            archive = Path(temporary) / "source.tar"
            run(
                [
                    "git",
                    "-c",
                    "core.autocrlf=false",
                    "-c",
                    "core.eol=lf",
                    "-C",
                    str(source),
                    "archive",
                    "--format=tar",
                    "--output",
                    str(archive),
                    commit,
                ]
            )
            destination.mkdir()
            with tarfile.open(archive, "r") as members:
                members.extractall(destination, filter="data")
        run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "-C",
                str(destination),
                "init",
                "-b",
                "main",
            ]
        )
        acquisition = "OFFLINE_GIT_ARCHIVE_EXISTING_OBJECT_STORE_NOT_COLD_CLONE"
    else:
        run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "-c",
                "credential.helper=",
                "-c",
                "core.askPass=",
                "clone",
                "--no-checkout",
                manifest["upstream"]["url"],
                str(destination),
            ]
        )
        run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "-C",
                str(destination),
                "checkout",
                "--detach",
                variant["base_commit"],
            ]
        )
        actual = (
            run(
                [
                    "git",
                    "-c",
                    "core.autocrlf=false",
                    "-c",
                    "core.eol=lf",
                    "-C",
                    str(destination),
                    "rev-parse",
                    "HEAD",
                ]
            )
            .stdout.decode()
            .strip()
        )
        if actual != variant["base_commit"]:
            raise ValueError("Clone HEAD does not match the exact source pin")
        acquisition = "PUBLIC_UPSTREAM_EXACT_COMMIT_CLONE_SOURCE_ONLY"
    for patch in variant["patches"]:
        patch_path = (PUBLIC / patch["file"]).resolve()
        run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "-C",
                str(destination),
                "apply",
                "--check",
                str(patch_path),
            ]
        )
        run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "-C",
                str(destination),
                "apply",
                str(patch_path),
            ]
        )
        for name, expected in patch.get("expected_files", {}).items():
            if sha(destination / name) != expected:
                raise ValueError("Materialized public compatibility file hash mismatch")
    receipt = {
        **plan,
        "status": "SOURCE_MATERIALIZED_NO_RUNTIME",
        "source_acquisition": acquisition,
        "runtime_calls": 0,
        "build_calls": 0,
        "application_calls": 0,
        "source_manifest_sha256": sha(PUBLIC / "source-manifest.json"),
        **freeze_inventory(destination),
    }
    with (destination.parent / (destination.name + ".source-receipt.json")).open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(receipt, stream, indent=2)
    qualified = verify_source(destination, args.variant)
    print(json.dumps(qualified, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
