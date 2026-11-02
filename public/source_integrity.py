"""Canonical acquired-source inventory and fail-closed workspace reuse checks."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

PUBLIC = Path(__file__).resolve().parent
SCHEMA = "workflow-lab.source-inventory.v1"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Source integrity metadata has duplicate keys.")
        result[key] = value
    return result


def _read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Source integrity metadata must be an ordinary sibling file.")
    data = path.read_bytes()
    value = json.loads(data, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("Source integrity metadata must be a JSON object.")
    return value, _sha(data)


def _paths(workspace):
    workspace = Path(workspace).absolute()
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("Source workspace must be an ordinary directory.")
    return (
        workspace,
        workspace.with_name(workspace.name + ".source-receipt.json"),
        workspace.with_name(workspace.name + ".source-inventory.json"),
    )


def source_inventory(workspace):
    workspace, _, _ = _paths(workspace)
    root = workspace.resolve()
    entries = {}

    def visit(directory):
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = path.relative_to(workspace).as_posix()
            if relative == ".git":
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                try:
                    resolved = path.resolve(strict=False)
                except (OSError, RuntimeError) as error:
                    raise ValueError("Source contains an invalid symlink.") from error
                if not resolved.is_relative_to(root) or resolved.is_relative_to(root / ".git"):
                    raise ValueError("Source symlink escapes its workspace: " + relative)
                raw = os.fsencode(target)
                entries[relative] = {
                    "type": "symlink",
                    "target": target,
                    "bytes": len(raw),
                    "sha256": _sha(raw),
                }
            elif stat.S_ISDIR(mode):
                if not path.resolve().is_relative_to(root):
                    raise ValueError("Source directory redirects outside its workspace: " + relative)
                entries[relative] = {"type": "directory"}
                visit(path)
            elif stat.S_ISREG(mode):
                digest = hashlib.sha256()
                size = 0
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                        size += len(chunk)
                entries[relative] = {
                    "type": "file",
                    "bytes": size,
                    "sha256": digest.hexdigest(),
                    "executable": bool(mode & 0o111),
                }
            else:
                raise ValueError("Source contains an unsupported file type: " + relative)

    visit(workspace)
    return {"schema": SCHEMA, "entries": dict(sorted(entries.items()))}


def freeze_inventory(workspace):
    """Called only after independent acquisition/patch checks, never by reuse."""
    workspace, _, inventory_path = _paths(workspace)
    data = _canonical(source_inventory(workspace))
    with inventory_path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return {"source_inventory_file": inventory_path.name, "source_inventory_sha256": _sha(data)}


def verify_source(workspace, variant):
    workspace, receipt_path, inventory_path = _paths(workspace)
    try:
        receipt, receipt_sha = _read(receipt_path)
    except (OSError, ValueError) as error:
        raise ValueError("Source receipt unavailable; acquire a fresh source folder.") from error
    if not receipt.get("source_inventory_sha256") or not receipt.get("source_inventory_file"):
        raise ValueError("Source receipt has no inventory; acquire a fresh source folder.")
    manifest_bytes = (PUBLIC / "source-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes, object_pairs_hook=_unique)
    selected = manifest.get("variants", {}).get(variant)
    if (
        not selected
        or receipt.get("variant") != variant
        or receipt.get("source_commit") != selected["base_commit"]
    ):
        raise ValueError("Source receipt does not match the pinned source variant.")
    if receipt.get("status") != "SOURCE_MATERIALIZED_NO_RUNTIME" or receipt.get(
        "source_manifest_sha256"
    ) != _sha(manifest_bytes):
        raise ValueError("Source receipt does not match the current acquisition manifest.")
    if receipt.get("patch_sha256") != [patch["sha256"] for patch in selected["patches"]]:
        raise ValueError("Source receipt does not match the pinned public patches.")
    if receipt["source_inventory_file"] != inventory_path.name:
        raise ValueError("Source inventory must be the exact sibling file.")
    try:
        inventory, inventory_sha = _read(inventory_path)
    except (OSError, ValueError) as error:
        raise ValueError("Source inventory unavailable; acquire a fresh source folder.") from error
    if inventory_sha != receipt["source_inventory_sha256"] or inventory.get("schema") != SCHEMA:
        raise ValueError("Source inventory hash or schema mismatch.")
    if inventory != source_inventory(workspace):
        raise ValueError("Source workspace changed since acquisition; acquire a fresh source folder.")
    return {**receipt, "source_receipt_sha256": receipt_sha, "integrity_status": "SOURCE_INTEGRITY_VERIFIED"}
