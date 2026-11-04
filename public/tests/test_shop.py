"""Inert command-boundary controls; never invokes Docker or an application."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PUBLIC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PUBLIC))


class ShopControls(unittest.TestCase):
    def test_setup_makes_only_public_mounted_flags_guest_readable(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state_fixture(shop, root)
            runner, http, _, _ = self.adapters(shop)
            fresh = root / "fresh"
            calls = []
            real_chmod = Path.chmod

            def chmod(path, mode, *args, **kwargs):
                calls.append((path, mode))
                return real_chmod(path, mode, *args, **kwargs)

            with mock.patch.object(Path, "chmod", new=chmod), contextlib.redirect_stdout(io.StringIO()):
                shop.main(
                    [
                        "--state-dir",
                        str(fresh),
                        "setup",
                        "--workspace",
                        state["workspace"],
                        "--images",
                        state["images_lock"],
                        "--context",
                        state["docker_context"],
                    ],
                    runner,
                    http,
                )
            self.assertIn((fresh / "flags/demo.flagd.json", 0o644), calls)
            self.assertIn((fresh / "flags", 0o755), calls)
            self.assertIn((fresh / "envoy.tmpl.yaml", 0o644), calls)
            self.assertIn((fresh / "state.json", 0o600), calls)
            if os.name != "nt":
                self.assertEqual((fresh / "flags/demo.flagd.json").stat().st_mode & 0o777, 0o644)
                self.assertEqual((fresh / "state.json").stat().st_mode & 0o777, 0o600)

    def module(self):
        spec = importlib.util.spec_from_file_location("sample_shop", PUBLIC / "shop.py")
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except FileNotFoundError:
            self.fail("The public native-Compose shop entrypoint is not implemented")
        return module

    def test_unqualified_lock_rejects_before_native_dispatch(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "images.json"
            lock.write_text(json.dumps({"status": "NOT_YET_QUALIFIED", "services": {}}))
            with self.assertRaises(ValueError):
                shop.load_image_lock(lock, "original")

    def test_render_removes_global_names_auto_traffic_and_builds(self):
        shop = self.module()
        services = {
            s: {
                "image": "mutable:tag",
                "container_name": s,
                "build": {"context": "."},
                "ports": ["8080:8080"],
                "depends_on": {"load-generator": {"condition": "service_started"}},
                "networks": ["default"],
            }
            for s in shop.CORE_SERVICES
        }
        services["load-generator"] = {"image": "load-generator:tag"}
        images = dict(shop.BASE_IMAGES)
        result = shop.scoped_config(
            {"services": services, "networks": {"default": {"name": "global"}}, "volumes": {}},
            images,
            "shop-0123456789ab",
            Path("/fixture/flags"),
            18080,
            18011,
        )
        self.assertNotIn("load-generator", result["services"])
        for name, service in result["services"].items():
            self.assertNotIn("build", service)
            self.assertNotIn("container_name", service)
            self.assertEqual(service["image"], images[name])
            self.assertNotIn("load-generator", service.get("depends_on", {}))
        self.assertEqual(result["networks"]["default"]["name"], "shop-0123456789ab_default")
        self.assertEqual(result["services"]["cart"]["ports"], [])
        self.assertEqual(
            result["services"]["mcp"]["environment"]["TRACELOOP_BASE_URL"], "http://otel-collector:4318"
        )
        self.assertTrue(result["networks"]["default"]["internal"])
        self.assertFalse(result["networks"]["edge"]["internal"])
        self.assertEqual(set(result["services"]["frontend-proxy"]["networks"]), {"default", "edge"})
        self.assertEqual(set(result["services"]["mcp"]["networks"]), {"default", "edge"})
        self.assertEqual(set(result["services"]["checkout"]["networks"]), {"default"})

    def test_stop_is_exact_project_and_preserves_data(self):
        shop = self.module()
        args = shop.compose_args(
            {
                "project": "shop-0123456789ab",
                "config": "/fixture/config.json",
                "docker_context": "captured-engine",
            },
            ["stop", "--timeout", "30"],
        )
        self.assertEqual(
            args[:6],
            ["docker", "--context", "captured-engine", "compose", "--project-name", "shop-0123456789ab"],
        )
        self.assertEqual(args[-3:], ["stop", "--timeout", "30"])
        self.assertNotIn("down", args)
        with self.assertRaises(ValueError):
            shop.compose_args(
                {"project": "unowned", "config": "/fixture/config.json", "docker_context": "captured-engine"},
                ["stop"],
            )

    def test_reset_refuses_unrecorded_subject_before_http(self):
        shop = self.module()
        calls = []
        with self.assertRaises(ValueError):
            shop.reset_subject(
                {"users": {}, "http_port": 18080},
                "shop-11111111-1111-4111-8111-111111111111",
                lambda *args: calls.append(args),
            )
        self.assertEqual(calls, [])

    def test_checkout_claim_is_one_use_and_fixture_never_persisted(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user = "shop-11111111-1111-4111-8111-111111111111"
            first = shop.claim_checkout(root, user)
            self.assertTrue(first.is_file())
            with self.assertRaises(FileExistsError):
                shop.claim_checkout(root, user)
            self.assertNotIn("creditCard", first.read_text())

    def test_every_compose_call_uses_captured_context(self):
        shop = self.module()
        args = shop.compose_args(
            {
                "project": "shop-0123456789ab",
                "config": "/fixture/config.json",
                "docker_context": "captured-engine",
            },
            ["stop", "--timeout", "30"],
        )
        self.assertEqual(
            args[:6],
            ["docker", "--context", "captured-engine", "compose", "--project-name", "shop-0123456789ab"],
        )

    def test_original_variant_cannot_use_local_derived_image(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "images.json"
            images = dict(shop.BASE_IMAGES)
            images["mcp"] = "sha256:" + "b" * 64
            path.write_text(
                json.dumps(
                    {
                        "status": "QUALIFIED",
                        "source_commit": shop.SOURCE_COMMIT,
                        "platform": "linux/amd64",
                        "source_variant": "original",
                        "services": images,
                    }
                )
            )
            with self.assertRaises(ValueError):
                shop.load_image_lock(path, "original")

    def test_health_failure_denies_story_before_seed(self):
        shop = self.module()
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.state_fixture(shop, root)

            def runner(args, source=None):
                calls.append(args)
                return "[]"

            with self.assertRaises(ValueError):
                shop.main(
                    [
                        "--state-dir",
                        str(root),
                        "story",
                        "--user-id",
                        "shop-11111111-1111-4111-8111-111111111111",
                    ],
                    runner,
                    lambda *args: self.fail("No HTTP mutation permitted"),
                )
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][-3:], ["ps", "--format", "json"])

    def test_reset_allowed_exact_subject_only(self):
        shop = self.module()
        calls = []
        user = "shop-11111111-1111-4111-8111-111111111111"

        def http(port, method, path, body=None):
            calls.append((method, path, body))
            return (204, None) if method == "DELETE" else (200, {"items": []})

        result = shop.reset_subject({"users": {user: {"status": "OBSERVED"}}, "http_port": 18080}, user, http)
        self.assertTrue(result["API_cart_readback_empty"])
        self.assertEqual(result["API_cart_readback_identity"], "NOT_ECHOED_FOR_EMPTY_CART")
        self.assertEqual(calls[0], ("DELETE", "/api/cart", {"userId": user}))
        self.assertEqual(calls[1][0], "GET")

    def test_reset_rejects_wrong_shopper_readback(self):
        shop = self.module()
        user = "shop-11111111-1111-4111-8111-111111111111"

        def http(port, method, path, body=None):
            if method == "DELETE":
                return 204, None
            return 200, {"userId": "shop-22222222-2222-4222-8222-222222222222", "items": []}

        with self.assertRaises(RuntimeError):
            shop.reset_subject({"users": {user: {"status": "OBSERVED"}}, "http_port": 18080}, user, http)

    def test_unknown_checkout_cannot_be_reset(self):
        shop = self.module()
        user = "shop-11111111-1111-4111-8111-111111111111"
        with self.assertRaises(ValueError):
            shop.reset_subject(
                {"users": {user: {"status": "UNKNOWN_AFTER_DISPATCH"}}, "http_port": 18080},
                user,
                lambda *args: self.fail("No mutation permitted"),
            )

    def test_malformed_after_cart_never_passes_as_empty_or_retries_checkout(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.state_fixture(shop, root)
            runner, http, natives, requests = self.adapters(shop)
            dispatched = False

            def malformed(port, method, path, body=None):
                nonlocal dispatched
                if dispatched and method == "GET" and path.startswith("/api/cart"):
                    return 200, {}
                result = http(port, method, path, body)
                if method == "POST" and path.startswith("/api/checkout"):
                    dispatched = True
                return result

            with self.assertRaises(ValueError):
                shop.main(["--state-dir", str(root), "story"], runner, malformed)
            state = json.loads((root / "state.json").read_bytes())
            self.assertEqual(state["users"][state["last_user"]]["status"], "UNKNOWN_AFTER_DISPATCH")
            self.assertEqual(
                len([x for x in requests if x[0] == "POST" and x[1].startswith("/api/checkout")]), 1
            )
            for malformed_cart in (
                {},
                None,
                {"items": None},
                {"items": [{"quantity": 1}]},
                {"items": [{"productId": "demo", "quantity": True}]},
            ):
                with self.assertRaises(ValueError):
                    shop.cart_items(malformed_cart)
            self.assertEqual(shop.cart_items({"items": []}), [])

    def test_empty_cart_identity_is_explicitly_not_echoed_but_wrong_owner_rejects(self):
        shop = self.module()
        user = "shop-11111111-1111-4111-8111-111111111111"
        self.assertEqual(shop.cart_identity_status({"items": []}, user), "NOT_ECHOED_FOR_EMPTY_CART")
        self.assertEqual(
            shop.cart_identity_status({"userId": user, "items": []}, user),
            "MATCHED_REQUESTED_SHOPPER",
        )
        with self.assertRaisesRegex(ValueError, "another or unknown"):
            shop.cart_identity_status(
                {"userId": "shop-22222222-2222-4222-8222-222222222222", "items": []}, user
            )
        with self.assertRaisesRegex(ValueError, "another or unknown"):
            shop.cart_identity_status({"userId": "", "items": [{"productId": "x", "quantity": 1}]}, user)

    def test_local_fixed_mcp_requires_all_public_derivation_pins(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "images.json"
            images = dict(shop.BASE_IMAGES)
            images["mcp"] = "sha256:" + "b" * 64
            proof = {
                "status": "LOCAL_PUBLIC_BUILD",
                "image_id": images["mcp"],
                "base_reference": "ghcr.io/open-telemetry/demo@sha256:8cea957d3930d9df7365c0d655835bf3d553d097eae80d4428dac40b29ef533c",
                "patch_sha256": "a92da937de411c9e81b79ec75fdb86147994d7740e3c8f772eea5ae75c9ff276",
                "patched_tools_sha256": "179d31d39921f933eaf498b932ba54d075db9f8213730675095cfe012a003273",
            }
            lock = {
                "status": "QUALIFIED",
                "source_commit": shop.SOURCE_COMMIT,
                "platform": "linux/amd64",
                "source_variant": "mcp-session-id",
                "services": images,
                "public_mcp_derivation": proof,
            }
            path.write_text(json.dumps(lock))
            self.assertEqual(shop.load_image_lock(path, "mcp-session-id"), images)
            proof["patch_sha256"] = "0" * 64
            path.write_text(json.dumps(lock))
            with self.assertRaises(ValueError):
                shop.load_image_lock(path, "mcp-session-id")

    def test_world_routing_and_config_drift_fail_before_native_or_http(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state_fixture(shop, root)
            shop.verify_world(state, root)
            for key, value in [
                ("http_port", 19080),
                ("mcp_port", 19011),
                ("project", "shop-abcdefabcdef"),
                ("story", "cart-failure"),
                ("docker_context", "other-engine"),
            ]:
                original = state[key]
                state[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    shop.start_owned(
                        state,
                        root,
                        lambda *args: self.fail("No native action allowed"),
                        lambda *args: self.fail("No HTTP action allowed"),
                    )
                state[key] = original
            for path in (
                root / "compose.json",
                root / "flags/demo.flagd.json",
                Path(state["workspace"]) / "src/flagd/demo.flagd.json",
            ):
                original = path.read_bytes()
                path.write_bytes(b"{}")
                with self.subTest(path=path), self.assertRaises(ValueError):
                    shop.start_owned(
                        state,
                        root,
                        lambda *args: self.fail("No native action allowed"),
                        lambda *args: self.fail("No HTTP action allowed"),
                    )
                path.write_bytes(original)

    def test_runtime_census_accepts_exact_images_and_rejects_changed_engine_image_or_missing_container(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state_fixture(shop, root)
            images = shop.load_image_lock(Path(state["images_lock"]), "original")
            names = list(images)
            ids = {name: "sha256:" + format(index + 1, "064x") for index, name in enumerate(names)}
            mode = "allowed"

            def runner(args):
                if "info" in args:
                    return "engine-changed" if mode == "engine" else "engine-one"
                if "image" in args:
                    return "\n".join(
                        json.dumps({"config_id": ids[name], "repo_digests": [images[name]]}) for name in names
                    )
                if "ps" in args:
                    return "\n".join(
                        format(index + 1, "064x") for index in range(len(names) - (mode == "missing"))
                    )
                rows = [
                    {
                        "container_id": format(index + 1, "064x"),
                        "service": name,
                        "configured_image": images[name],
                        "image_id": ids[name],
                        "running": True,
                        "oom_killed": False,
                    }
                    for index, name in enumerate(names)
                ]
                if mode == "image":
                    rows[0]["image_id"] = "sha256:" + "f" * 64
                return "\n".join(json.dumps(row) for row in rows)

            observed = shop.snapshot_runtime(state, root, runner)
            self.assertEqual(len(observed["containers"]), 18)
            self.assertEqual(state["engine_id"], "engine-one")
            shop.verify_world(state, root)
            for mode in ("engine", "image", "missing"):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    shop.snapshot_runtime(state, root, runner)

    def test_image_lock_requires_matching_source_platform_and_public_references(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "images.json"
            base = json.loads((PUBLIC / "runtime-images.lock.json").read_bytes())
            self.assertEqual(len(shop.load_image_lock(PUBLIC / "runtime-images.lock.json", "original")), 18)
            for key, value in [
                ("source_commit", "other"),
                ("platform", "other"),
                ("source_variant", "mcp-session-id"),
            ]:
                lock = {**base, key: value}
                path.write_text(json.dumps(lock))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    shop.load_image_lock(path, lock["source_variant"])
            base["services"]["cart"] = "ghcr.io/example/shop@sha256:" + "a" * 64
            path.write_text(json.dumps(base))
            with self.assertRaises(ValueError):
                shop.load_image_lock(path, "original")

    def test_stop_and_cleanup_refuse_target_drift_but_allow_stale_source(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state_fixture(shop, root)
            calls = []

            def runner(args, source=None):
                calls.append(args)
                return "engine-one" if "info" in args else ""

            source = Path(state["workspace"]) / "src/flagd/demo.flagd.json"
            source.write_bytes(b"changed stale source")
            shop.stop_owned(state, root, runner)
            self.assertTrue(any("stop" in args for args in calls))
            for key, value in [("docker_context", "other"), ("project", "shop-abcdefabcdef")]:
                old = state[key]
                state[key] = value
                calls.clear()
                with self.subTest(key=key), self.assertRaises(ValueError):
                    shop.stop_owned(state, root, runner)
                self.assertEqual(calls, [])
                state[key] = old
            calls.clear()
            with self.assertRaises(ValueError):
                shop.stop_owned(state, root, lambda args: calls.append(args) or "different-engine")
            self.assertEqual(len(calls), 1)
            self.assertIn("info", calls[0])

    def state_fixture(self, shop, root, *, story="normal-checkout"):
        images = dict(shop.BASE_IMAGES)
        lock = root / "images.json"
        shop.write_json(
            lock,
            {
                "status": "QUALIFIED",
                "source_commit": shop.SOURCE_COMMIT,
                "platform": "linux/amd64",
                "source_variant": "original",
                "services": images,
            },
        )
        workspace = root / "source"
        workspace.mkdir()
        template = workspace / "src/frontend-proxy/envoy.tmpl.yaml"
        template.parent.mkdir(parents=True, exist_ok=True)
        template.write_text(
            '                        - match: { prefix: "/" }\n                          route: { cluster: frontend }\n'
        )
        shop.write_json(
            workspace / "src/flagd/demo.flagd.json",
            {
                "flags": {
                    "cartFailure": {"defaultVariant": "off", "variants": {"off": 0, "100%": 1}},
                    "paymentUnreachable": {"defaultVariant": "off", "variants": {"off": False, "on": True}},
                }
            },
        )
        from source_integrity import freeze_inventory

        shop.write_json(
            root / "source.source-receipt.json",
            {
                "status": "SOURCE_MATERIALIZED_NO_RUNTIME",
                "source_commit": shop.SOURCE_COMMIT,
                "variant": "original",
                "patch_sha256": [],
                "source_manifest_sha256": hashlib.sha256(
                    (PUBLIC / "source-manifest.json").read_bytes()
                ).hexdigest(),
                **freeze_inventory(workspace),
            },
        )
        state = {
            "schema": "workflow-shop.v1",
            "project": "shop-0123456789ab",
            "config": str(root / "compose.json"),
            "docker_context": "captured-engine",
            "engine_id": "engine-one",
            "http_port": 18080,
            "mcp_port": 18011,
            "started": True,
            "story": story,
            "users": {},
            "source_variant": "original",
            "workspace": str(workspace),
            "images_lock": str(lock),
            "images_sha256": hashlib.sha256(json.dumps(images, sort_keys=True).encode()).hexdigest(),
        }
        shop.write_json(root / "compose.json", {"name": state["project"], "services": {}, "networks": {}})
        shop.write_json(root / "flags/demo.flagd.json", {"flags": {}})
        shop.prepare_envoy(workspace, root)
        shop.bind_world(state, root)
        shop.write_json(root / "state.json", state)
        return state

    def adapters(self, shop):
        native_calls = []
        http_calls = []
        carts = {}
        rendered = {
            "services": {
                s: {"image": "mutable:tag", "ports": [], "networks": ["default"]} for s in shop.CORE_SERVICES
            },
            "volumes": {},
        }

        def runner(args, source=None):
            native_calls.append(args)
            if "info" in args:
                return "engine-one"
            if args[-3:] == ["ps", "--format", "json"]:
                return json.dumps(
                    [{"Service": s, "State": "running", "Health": "healthy"} for s in shop.CORE_SERVICES]
                )
            if "config" in args and "--format" in args:
                return json.dumps(rendered)
            if "exec" in args:
                if source and 'call_tool("get_cart"' in source:
                    users = json.loads(source.split("users = ", 1)[1].splitlines()[0])
                    return json.dumps(
                        {
                            "initialized": True,
                            "tool_names": ["get_cart"],
                            "carts": [
                                {"user_id": user, "is_error": False, "items": carts.get(user, [])}
                                for user in users
                            ],
                        }
                    )
                return json.dumps({"ready": True})
            return ""

        def http(port, method, path, body=None):
            http_calls.append((method, path, body))
            if method == "GET" and path.startswith("/api/products"):
                return 200, [{"id": "demo-product"}, {"id": "other-product"}]
            if method == "POST" and path.startswith("/api/cart"):
                carts[body["userId"]] = [
                    {"productId": body["item"]["productId"], "quantity": body["item"]["quantity"]}
                ]
                return 200, {}
            if method == "POST" and path.startswith("/api/checkout"):
                carts[body["userId"]] = []
                return 200, {"orderId": "inert-order", "private": "MUST_NOT_BE_SAVED"}
            if method == "DELETE":
                carts[body["userId"]] = []
                return 204, None
            if method == "GET" and path.startswith("/api/cart"):
                user = path.split("sessionId=")[1].split("&")[0]
                items = carts.get(user, [])
                return 200, {"userId": user, "items": items} if items else {"items": []}
            raise AssertionError((method, path))

        return runner, http, native_calls, http_calls

    def test_public_story_generates_subject_fixture_and_saves_only_metadata(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.state_fixture(shop, root)
            runner, http, natives, requests = self.adapters(shop)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(shop.main(["--state-dir", str(root), "story"], runner, http), 0)
            state = json.loads((root / "state.json").read_bytes())
            self.assertEqual(len(state["users"]), 1)
            self.assertEqual(state["users"][state["last_user"]]["status"], "OBSERVED")
            result = json.loads((root / ("result-" + state["last_user"] + ".json")).read_bytes())
            self.assertEqual(result["checkout_attempt_count"], 1)
            self.assertEqual(result["project_id"], state["project"])
            self.assertEqual(result["synthetic_shopper_id"], state["last_user"])
            self.assertEqual(result["cart_before_identity_status"], "MATCHED_REQUESTED_SHOPPER")
            self.assertEqual(result["cart_after_identity_status"], "NOT_ECHOED_FOR_EMPTY_CART")
            self.assertEqual(
                len([x for x in requests if x[0] == "POST" and x[1].startswith("/api/checkout")]), 1
            )
            self.assertEqual(len([x for x in requests if x[0] == "POST" and x[1].startswith("/api/cart")]), 1)
            saved = "".join(p.read_text() for p in root.rglob("*") if p.is_file())
            for private in ("4111111111111111", "shopper@example.test", "MUST_NOT_BE_SAVED"):
                self.assertNotIn(private, saved)
                self.assertNotIn(private, output.getvalue())
            self.assertTrue(all(args[:3] == ["docker", "--context", "captured-engine"] for args in natives))

    def test_mcp_story_verifies_two_distinct_synthetic_shopper_carts(self):
        shop = ShopControls().module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.state_fixture(shop, root, story="mcp-session-id")
            runner, http, _, _ = self.adapters(shop)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(shop.main(["--state-dir", str(root), "story"], runner, http), 0)
            final_state = json.loads((shop.active_directory(root) / "state.json").read_bytes())
            result = json.loads(
                (shop.active_directory(root) / ("result-" + final_state["last_user"] + ".json")).read_bytes()
            )
            self.assertTrue(result["assessment"]["passed"])
            self.assertTrue(result["actor_isolation_verified"])
            self.assertEqual(len(result["HTTP_carts_by_synthetic_actor"]), 2)
            self.assertEqual(result["HTTP_carts_by_synthetic_actor"], result["MCP_carts_by_synthetic_actor"])
            self.assertNotEqual(*result["HTTP_carts_by_synthetic_actor"].values())

    def test_shared_cart_conflict_uses_separate_ordered_clients_and_keeps_raw_responses(self):
        shop = ShopControls().module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self.state_fixture(shop, root, story="shared-cart-conflict")
            carts = {}
            clients = []

            def http(port, method, path, body=None):
                if method == "GET" and path.startswith("/api/products"):
                    return 200, [{"id": "demo-product"}, {"id": "other-product"}]
                if method == "GET" and path.startswith("/api/cart"):
                    user = path.split("sessionId=")[1].split("&")[0]
                    items = carts.get(user, [])
                    return 200, {"userId": user, "items": items} if items else {"items": []}
                raise AssertionError((method, path))

            def runner(args, source=None):
                if "node" not in args:
                    return ""
                script = args[-1]
                user = json.loads(script.split("const userId = ", 1)[1].split(";", 1)[0])
                actor = "actor-A" if "actor-A" in script else "actor-B"
                clients.append((actor, user))
                if actor == "actor-A":
                    product = json.loads(script.split("const productId = ", 1)[1].split(";", 1)[0])
                    carts[user] = [{"productId": product, "quantity": 1}]
                    raw = json.dumps({"userId": user, "items": carts[user]})
                    return json.dumps(
                        {
                            "actor_label": actor,
                            "intent": "retain-added-item",
                            "status": 200,
                            "raw_response": raw,
                            "raw_response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                        }
                    )
                carts[user] = []
                delete_raw = ""
                read_raw = json.dumps({"items": []})
                return json.dumps(
                    {
                        "actor_label": actor,
                        "intent": "clear-shared-cart",
                        "delete": {
                            "status": 204,
                            "raw_response": delete_raw,
                            "raw_response_sha256": hashlib.sha256(delete_raw.encode()).hexdigest(),
                        },
                        "read": {
                            "status": 200,
                            "raw_response": read_raw,
                            "raw_response_sha256": hashlib.sha256(read_raw.encode()).hexdigest(),
                        },
                    }
                )

            with contextlib.redirect_stdout(io.StringIO()):
                outcome = shop.run_story(
                    state,
                    root,
                    "shop-11111111-1111-4111-8111-111111111111",
                    http=http,
                    runner=runner,
                )
            self.assertEqual([actor for actor, _ in clients], ["actor-A", "actor-B"])
            self.assertEqual(clients[0][1], clients[1][1])
            self.assertEqual(outcome["assessment"]["passed"], True)
            self.assertEqual(outcome["actor_intents"][0]["sequence"], 1)
            self.assertEqual(outcome["actor_intents"][1]["sequence"], 2)
            self.assertEqual(outcome["ordered_client_results"][1]["cart_after"], [])
            self.assertEqual(outcome["host_cart_after"], [])
            self.assertEqual(
                outcome["cart_identity_observations"],
                {
                    "empty_prestate": "NOT_ECHOED_FOR_EMPTY_CART",
                    "actor_a_nonempty_readback": "MATCHED_REQUESTED_SHOPPER",
                    "actor_b_empty_readback": "NOT_ECHOED_FOR_EMPTY_CART",
                    "host_empty_readback": "NOT_ECHOED_FOR_EMPTY_CART",
                },
            )
            self.assertEqual(
                hashlib.sha256(outcome["ordered_client_results"][0]["raw_response"].encode()).hexdigest(),
                outcome["ordered_client_results"][0]["raw_response_sha256"],
            )

    def test_shared_cart_client_failure_stays_unknown_and_cannot_reset(self):
        shop = ShopControls().module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self.state_fixture(shop, root, story="shared-cart-conflict")
            carts = {}

            def http(port, method, path, body=None):
                if method == "GET" and path.startswith("/api/products"):
                    return 200, [{"id": "demo-product"}, {"id": "other-product"}]
                if method == "GET" and path.startswith("/api/cart"):
                    shared_user = path.split("sessionId=")[1].split("&")[0]
                    return 200, {"userId": shared_user, "items": carts.get(shared_user, [])}
                raise AssertionError((method, path))

            def fail_second_client(args, source=None):
                if "node" not in args:
                    return ""
                script = args[-1]
                user = json.loads(script.split("const userId = ", 1)[1].split(";", 1)[0])
                if "actor-A" in script:
                    product = json.loads(script.split("const productId = ", 1)[1].split(";", 1)[0])
                    carts[user] = [{"productId": product, "quantity": 1}]
                    raw = json.dumps({"userId": user, "items": carts[user]})
                    return json.dumps(
                        {
                            "actor_label": "actor-A",
                            "intent": "retain-added-item",
                            "status": 200,
                            "raw_response": raw,
                            "raw_response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                        }
                    )
                raise RuntimeError("synthetic second-client disconnect after the first write")

            user = "shop-11111111-1111-4111-8111-111111111111"
            with self.assertRaises(RuntimeError):
                shop.run_story(state, root, user, http=http, runner=fail_second_client)
            failed = json.loads((root / "state.json").read_bytes())
            self.assertEqual(failed["users"][user]["status"], "UNKNOWN_AFTER_DISPATCH")
            with self.assertRaises(ValueError):
                shop.reset_subject(
                    failed, user, lambda *args: self.fail("Unknown shared state cannot reset.")
                )

    def test_incomplete_mcp_actor_comparison_stays_unknown_and_cannot_reset(self):
        for failure in ("runner", "malformed", "missing", "extra", "wrong"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                shop = ShopControls().module()
                root = Path(directory)
                state = self.state_fixture(shop, root, story="mcp-session-id")
                runner, http, _, _ = self.adapters(shop)

                def incomplete_runner(args, source=None):
                    if "exec" not in args or not (source and 'call_tool("get_cart"' in source):
                        return runner(args, source)
                    if failure == "runner":
                        raise RuntimeError("synthetic MCP transport failure")
                    if failure == "malformed":
                        return "not-json"
                    result = json.loads(runner(args, source))
                    if failure == "missing":
                        result["carts"].pop()
                    elif failure == "extra":
                        result["carts"].append(dict(result["carts"][0]))
                    elif failure == "wrong":
                        result["carts"][1]["user_id"] = "shop-00000000-0000-4000-8000-000000000000"
                    return json.dumps(result)

                with self.assertRaises((RuntimeError, ValueError)):
                    shop.run_story(
                        state,
                        root,
                        "shop-11111111-1111-4111-8111-111111111111",
                        http=http,
                        runner=incomplete_runner,
                    )
                failed_state = json.loads((root / "state.json").read_bytes())
                actors = failed_state["users"]
                self.assertEqual(len(actors), 2)
                self.assertTrue(all(value["status"] == "UNKNOWN_AFTER_DISPATCH" for value in actors.values()))
                calls_before_reset = []

                def no_reset(*args):
                    calls_before_reset.append(args)
                    raise AssertionError("An unknown MCP comparison must not dispatch reset.")

                for actor in actors:
                    with self.assertRaises(ValueError):
                        shop.reset_subject(failed_state, actor, no_reset)
                self.assertEqual(calls_before_reset, [])

    def test_public_replay_preserves_old_claim_and_uses_fresh_world_and_shopper(self):
        shop = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self.state_fixture(shop, root)
            old = "shop-11111111-1111-4111-8111-111111111111"
            claim = shop.claim_checkout(root / "checkout-claims", old)
            original = claim.read_bytes()
            state["users"][old] = {"status": "OBSERVED"}
            state["last_user"] = old
            shop.write_json(root / "state.json", state)
            runner, http, natives, requests = self.adapters(shop)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(shop.main(["--state-dir", str(root), "replay"], runner, http), 0)
            active = shop.active_directory(root)
            new = json.loads((active / "state.json").read_bytes())
            self.assertNotEqual(new["project"], state["project"])
            self.assertNotEqual(new["last_user"], old)
            self.assertEqual(claim.read_bytes(), original)
            posts = [x for x in requests if x[0] == "POST" and x[1].startswith("/api/checkout")]
            self.assertEqual(len(posts), 1)
            self.assertNotEqual(posts[0][2]["userId"], old)
            self.assertEqual([x for x in requests if x[0] == "DELETE"], [])
            self.assertTrue(all(args[:3] == ["docker", "--context", "captured-engine"] for args in natives))


if __name__ == "__main__":
    unittest.main()


class PublicMcpBuildControls(unittest.TestCase):
    def test_changed_public_source_refuses_before_docker(self):
        shop = ShopControls().module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source/src/shared/tools.py"
            source.parent.mkdir(parents=True)
            source.write_text("changed source\n")
            calls = []
            with self.assertRaises(ValueError):
                shop.build_public_mcp(
                    root / "state", root / "source", "sample-context", lambda args: calls.append(args)
                )
            self.assertEqual(calls, [])

    def test_build_uses_only_public_file_pinned_base_and_captured_context(self):
        shop = ShopControls().module()
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source/src/shared/tools.py"
            source.parent.mkdir(parents=True)
            data = b"# public source fixture\n"
            source.write_bytes(data)
            calls = []
            identity = "sha256:" + "b" * 64

            def runner(args):
                calls.append(args)
                if "build" in args:
                    Path(args[args.index("--iidfile") + 1]).write_text(identity + "\n")
                return identity + "\n" if "inspect" in args else ""

            with patch.object(shop, "MCP_TOOLS_SHA256", hashlib.sha256(data).hexdigest()):
                proof = shop.build_public_mcp(root / "state", root / "source", "sample-context", runner)
            self.assertEqual(proof["image_id"], identity)
            self.assertEqual(proof["base_reference"], shop.MCP_BASE_REFERENCE)
            self.assertTrue(all(args[:3] == ["docker", "--context", "sample-context"] for args in calls))
            build = next(args for args in calls if "build" in args)
            self.assertIn("none", build)
            context = Path(build[-1])
            self.assertEqual(
                {f.relative_to(context).as_posix() for f in context.rglob("*") if f.is_file()},
                {"Dockerfile", "src/shared/tools.py"},
            )
            self.assertEqual((context / "src/shared/tools.py").read_bytes(), data)


class StoryOutcomeControls(unittest.TestCase):
    def test_checkout_dispatch_is_exact_and_excludes_telemetry_posts(self):
        shop = ShopControls().module()
        self.assertTrue(shop.is_checkout_dispatch("POST", "/api/checkout?currencyCode=USD"))
        self.assertFalse(shop.is_checkout_dispatch("POST", "/v1/traces"))
        self.assertFalse(shop.is_checkout_dispatch("POST", "/api/checkout/telemetry"))
        self.assertFalse(shop.is_checkout_dispatch("GET", "/api/checkout"))

    def test_proxy_gives_cart_readback_an_explicit_timeout_before_catch_all(self):
        shop = ShopControls().module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src/frontend-proxy/envoy.tmpl.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                '                        - match: { prefix: "/" }\n                          route: { cluster: frontend }\n'
            )
            rendered = shop.prepare_envoy(root, root / "generated").read_text()
            cart = rendered.index('path: "/api/cart"')
            catch_all = rendered.index('prefix: "/"')
            self.assertLess(cart, catch_all)
            self.assertIn(f"timeout: {shop.PROFILE['proxy_read_seconds']}s", rendered[cart:catch_all])
            self.assertIn('path: "/api/checkout"', rendered)

    def test_failed_cart_read_cannot_look_like_an_empty_cart(self):
        shop = ShopControls().module()
        outcome = {
            "checkout_attempt_count": 1,
            "checkout_HTTP_status": 200,
            "order_response_present": True,
            "cart_HTTP_status": 503,
            "cart_before": [{"product_id": "demo", "quantity": 1}],
            "cart_after": [],
        }
        self.assertFalse(shop.assess_story("normal-checkout", outcome)["passed"])

    def test_unavailable_or_wrong_shopper_readback_stays_unknown_and_cannot_reset(self):
        for mode in ("unavailable", "wrong-shopper"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                controls = ShopControls()
                shop = controls.module()
                root = Path(temporary)
                controls.state_fixture(shop, root)
                runner, http, _, requests = controls.adapters(shop)
                checkout_dispatched = False

                def degraded_readback(port, method, path, body=None):
                    nonlocal checkout_dispatched
                    if checkout_dispatched and method == "GET" and path.startswith("/api/cart"):
                        if mode == "unavailable":
                            return 503, {}
                        return 200, {"userId": "shop-22222222-2222-4222-8222-222222222222", "items": []}
                    result = http(port, method, path, body)
                    if method == "POST" and path.startswith("/api/checkout"):
                        checkout_dispatched = True
                    return result

                with self.assertRaises(ValueError):
                    shop.main(["--state-dir", str(root), "story"], runner, degraded_readback)
                state = json.loads((root / "state.json").read_bytes())
                user = state["last_user"]
                self.assertEqual(state["users"][user]["status"], "UNKNOWN_AFTER_DISPATCH")
                self.assertEqual(
                    len([row for row in requests if row[0] == "POST" and row[1].startswith("/api/checkout")]),
                    1,
                )
                with self.assertRaises(ValueError):
                    shop.reset_subject(state, user, lambda *args: self.fail("Unknown readback cannot reset."))

    def test_green_retained_cart_fails_normal_but_demonstrates_selected_fault(self):
        shop = ShopControls().module()
        item = [{"product_id": "demo", "quantity": 1}]
        outcome = {
            "checkout_attempt_count": 1,
            "cart_HTTP_status": 200,
            "checkout_HTTP_status": 200,
            "order_response_present": True,
            "cart_before": item,
            "cart_after": item,
            "cart_before_identity_status": "MATCHED_REQUESTED_SHOPPER",
            "cart_after_identity_status": "MATCHED_REQUESTED_SHOPPER",
        }
        self.assertFalse(shop.assess_story("normal-checkout", outcome)["passed"])
        self.assertTrue(shop.assess_story("cart-failure", outcome)["passed"])
        outcome["checkout_HTTP_status"] = 504
        self.assertFalse(shop.assess_story("cart-failure", outcome)["passed"])

    def test_allowed_empty_cart_and_error_retention_controls(self):
        shop = ShopControls().module()
        item = [{"product_id": "demo", "quantity": 1}]
        self.assertTrue(
            shop.assess_story(
                "normal-checkout",
                {
                    "checkout_attempt_count": 1,
                    "cart_HTTP_status": 200,
                    "checkout_HTTP_status": 200,
                    "order_response_present": True,
                    "cart_before": item,
                    "cart_after": [],
                    "cart_before_identity_status": "MATCHED_REQUESTED_SHOPPER",
                    "cart_after_identity_status": "NOT_ECHOED_FOR_EMPTY_CART",
                },
            )["passed"]
        )
        self.assertTrue(
            shop.assess_story(
                "payment-unreachable",
                {
                    "checkout_attempt_count": 1,
                    "cart_HTTP_status": 200,
                    "checkout_HTTP_status": 500,
                    "order_response_present": False,
                    "cart_before": item,
                    "cart_after": item,
                    "cart_before_identity_status": "MATCHED_REQUESTED_SHOPPER",
                    "cart_after_identity_status": "MATCHED_REQUESTED_SHOPPER",
                },
            )["passed"]
        )
        self.assertFalse(
            shop.assess_story(
                "normal-checkout",
                {
                    "checkout_attempt_count": 1,
                    "cart_HTTP_status": 200,
                    "checkout_HTTP_status": 200,
                    "order_response_present": True,
                    "cart_before": [],
                    "cart_after": [],
                },
            )["passed"]
        )

    def test_checkout_cases_require_exactly_one_attempt_and_no_success_order(self):
        shop = ShopControls().module()
        item = [{"product_id": "demo", "quantity": 1}]
        base = {
            "checkout_attempt_count": 1,
            "cart_HTTP_status": 200,
            "checkout_HTTP_status": 500,
            "order_response_present": False,
            "cart_before": item,
            "cart_after": item,
        }
        self.assertTrue(shop.assess_story("payment-unreachable", base)["passed"])
        for attempts, order_response in ((0, False), (2, False), (True, False), (1, True)):
            with self.subTest(attempts=attempts, order_response=order_response):
                outcome = {
                    **base,
                    "checkout_attempt_count": attempts,
                    "order_response_present": order_response,
                }
                self.assertFalse(shop.assess_story("payment-unreachable", outcome)["passed"])


class NetworkSelectionControls(unittest.TestCase):
    def test_allocator_avoids_existing_ranges_without_deleting_networks(self):
        shop = ShopControls().module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "compose.json"
            shop.write_json(
                config,
                {
                    "services": {},
                    "networks": {"default": {"name": "shop-0123456789ab_default", "internal": True}},
                },
            )
            state = {"project": "shop-0123456789ab", "config": str(config), "docker_context": "captured"}
            calls = []

            def runner(args):
                calls.append(args)
                if "ls" in args:
                    return "a" * 12 + "\n"
                if "inspect" in args:
                    return '[{"Subnet":"10.240.0.0/16"}]\n'
                return "created"

            shop.reserve_network(state, root, runner)
            self.assertEqual(state["subnet"], "10.241.0.0/24")
            self.assertTrue(all(args[:3] == ["docker", "--context", "captured"] for args in calls))
            self.assertFalse(any("rm" in args or "prune" in args for args in calls))
            self.assertIn("--internal", calls[-1])
