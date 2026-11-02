"""Source inventory regressions using local synthetic files only."""

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PUBLIC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PUBLIC))
import bootstrap_source  # noqa: E402
import source_integrity as integrity  # noqa: E402


class SourceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "source"
        self.workspace.mkdir()
        for name in (
            "compose.yaml",
            ".env",
            "src/flagd/demo.flagd.json",
            "src/frontend-proxy/envoy.tmpl.yaml",
        ):
            path = self.workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("original " + name).encode())
        self.manifest = json.loads((PUBLIC / "source-manifest.json").read_bytes())

    def freeze(self, variant="original"):
        binding = integrity.freeze_inventory(self.workspace)
        receipt = {
            "status": "SOURCE_MATERIALIZED_NO_RUNTIME",
            "variant": variant,
            "source_commit": self.manifest["variants"][variant]["base_commit"],
            "patch_sha256": [patch["sha256"] for patch in self.manifest["variants"][variant]["patches"]],
            "source_manifest_sha256": hashlib.sha256(
                (PUBLIC / "source-manifest.json").read_bytes()
            ).hexdigest(),
            **binding,
        }
        self.receipt_path = self.workspace.with_name(self.workspace.name + ".source-receipt.json")
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        return receipt

    def test_unchanged_source_returns_qualified_receipt_and_hash(self):
        self.freeze()
        result = integrity.verify_source(self.workspace, "original")
        self.assertEqual(result["integrity_status"], "SOURCE_INTEGRITY_VERIFIED")
        self.assertEqual(
            result["source_receipt_sha256"], hashlib.sha256(self.receipt_path.read_bytes()).hexdigest()
        )
        self.assertFalse(
            any(path.name.endswith("source-inventory.json") for path in self.workspace.rglob("*"))
        )

    def test_mutated_compose_env_flags_and_proxy_rejected(self):
        self.freeze()
        for name in (
            "compose.yaml",
            ".env",
            "src/flagd/demo.flagd.json",
            "src/frontend-proxy/envoy.tmpl.yaml",
        ):
            with self.subTest(path=name):
                path = self.workspace / name
                original = path.read_bytes()
                path.write_bytes(b"mutated source")
                with self.assertRaises(ValueError):
                    integrity.verify_source(self.workspace, "original")
                path.write_bytes(original)

    def test_added_and_removed_files_rejected(self):
        self.freeze()
        extra = self.workspace / "new-input.json"
        extra.write_bytes(b"extra")
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")
        extra.unlink()
        (self.workspace / ".env").unlink()
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")

    def test_git_metadata_ignored_but_nested_git_is_source(self):
        self.freeze()
        (self.workspace / ".git").mkdir()
        (self.workspace / ".git" / "index").write_bytes(b"metadata")
        integrity.verify_source(self.workspace, "original")
        (self.workspace / "src" / ".git").mkdir()
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")

    def test_legacy_receipt_rejected_without_requalification(self):
        self.receipt_path = self.workspace.with_name(self.workspace.name + ".source-receipt.json")
        self.receipt_path.write_text(
            json.dumps({"source_commit": self.manifest["upstream"]["commit"], "variant": "original"})
        )
        with self.assertRaisesRegex(ValueError, "fresh source folder"):
            integrity.verify_source(self.workspace, "original")
        self.assertFalse(self.workspace.with_name(self.workspace.name + ".source-inventory.json").exists())

    def test_wrong_variant_pin_inventory_hash_or_path_rejected(self):
        original = self.freeze()
        for change in (
            {"variant": "mcp-session-id"},
            {"source_commit": "0" * 40},
            {"patch_sha256": ["0" * 64]},
            {"source_inventory_sha256": "0" * 64},
            {"source_inventory_file": "elsewhere.json"},
        ):
            with self.subTest(change=change):
                self.receipt_path.write_text(json.dumps({**original, **change}))
                with self.assertRaises(ValueError):
                    integrity.verify_source(self.workspace, "original")

    def symlink(self, path, target):
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest("Host does not permit inert symlinks: " + str(error))

    def test_internal_symlink_bound_and_file_type_change_rejected(self):
        link = self.workspace / "config-link"
        self.symlink(link, "compose.yaml")
        self.freeze()
        integrity.verify_source(self.workspace, "original")
        link.unlink()
        link.write_bytes((self.workspace / "compose.yaml").read_bytes())
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")

    def test_escaping_symlink_rejected_at_acquisition_and_reuse(self):
        outside = self.workspace.parent / "outside"
        outside.write_bytes(b"outside")
        link = self.workspace / "escape"
        self.symlink(link, "../outside")
        with self.assertRaises(ValueError):
            integrity.freeze_inventory(self.workspace)
        link.unlink()
        self.freeze()
        self.symlink(link, "../outside")
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")

    def test_inventory_byte_tamper_and_refreeze_rejected(self):
        self.freeze()
        path = self.workspace.with_name(self.workspace.name + ".source-inventory.json")
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")
        with self.assertRaises(FileExistsError):
            integrity.freeze_inventory(self.workspace)

    def test_missing_inventory_is_not_recreated(self):
        self.freeze()
        path = self.workspace.with_name(self.workspace.name + ".source-inventory.json")
        path.unlink()
        with self.assertRaisesRegex(ValueError, "fresh source folder"):
            integrity.verify_source(self.workspace, "original")
        self.assertFalse(path.exists())

    def test_bootstrap_public_path_freezes_and_verifies_inventory(self):
        destination = self.workspace.parent / "acquired"
        calls = []

        def run(argv):
            calls.append(argv)
            if "rev-parse" in argv:
                return mock.Mock(stdout=self.manifest["upstream"]["commit"].encode())
            if "archive" in argv:
                archive = Path(argv[argv.index("--output") + 1])
                with tarfile.open(archive, "w") as stream:
                    data = b"synthetic public-source fixture"
                    info = tarfile.TarInfo("compose.yaml")
                    info.size = len(data)
                    stream.addfile(info, io.BytesIO(data))
            return mock.Mock(stdout=b"")

        with mock.patch.object(bootstrap_source, "run", run), mock.patch("builtins.print"):
            result = bootstrap_source.main(
                [
                    "--no-runtime",
                    "--materialize",
                    "--destination",
                    str(destination),
                    "--offline-archive-from",
                    str(self.workspace),
                ]
            )
        self.assertEqual(result, 0)
        qualified = integrity.verify_source(destination, "original")
        self.assertEqual(qualified["integrity_status"], "SOURCE_INTEGRITY_VERIFIED")
        self.assertTrue(destination.with_name(destination.name + ".source-inventory.json").is_file())
        self.assertTrue(all(command[0] == "git" for command in calls))

    def test_metadata_redirect_and_malformed_object_rejected(self):
        original = self.freeze()
        self.receipt_path.write_text("[]")
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")
        self.receipt_path.write_text(json.dumps(original))
        inventory = self.workspace.with_name(self.workspace.name + ".source-inventory.json")
        data = inventory.read_bytes()
        outside = self.workspace.parent / "redirected-inventory"
        outside.write_bytes(data)
        inventory.unlink()
        self.symlink(inventory, outside.name)
        with self.assertRaises(ValueError):
            integrity.verify_source(self.workspace, "original")


if __name__ == "__main__":
    unittest.main()
