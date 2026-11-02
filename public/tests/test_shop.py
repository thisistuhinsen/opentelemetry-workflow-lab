"""Inert command-boundary controls; never invokes Docker or an application."""

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

PUBLIC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PUBLIC))


class ShopControls(unittest.TestCase):
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
        self.assertEqual(calls[0], ("DELETE", "/api/cart", {"userId": user}))
        self.assertEqual(calls[1][0], "GET")

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

    def state_fixture(self, shop, root):
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
            "story": "normal-checkout",
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
                return json.dumps({"ready": True})
            return ""

        def http(port, method, path, body=None):
            http_calls.append((method, path, body))
            if method == "GET" and path.startswith("/api/products"):
                return 200, [{"id": "demo-product"}]
            if method == "POST" and path.startswith("/api/cart"):
                carts[body["userId"]] = [{"productId": "demo-product", "quantity": 1}]
                return 200, {}
            if method == "POST" and path.startswith("/api/checkout"):
                carts[body["userId"]] = []
                return 200, {"orderId": "inert-order", "private": "MUST_NOT_BE_SAVED"}
            if method == "DELETE":
                carts[body["userId"]] = []
                return 204, None
            if method == "GET" and path.startswith("/api/cart"):
                user = path.split("sessionId=")[1].split("&")[0]
                return 200, {"items": carts.get(user, [])}
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
            self.assertEqual(
                len([x for x in requests if x[0] == "POST" and x[1].startswith("/api/checkout")]), 1
            )
            self.assertEqual(len([x for x in requests if x[0] == "POST" and x[1].startswith("/api/cart")]), 1)
            saved = "".join(p.read_text() for p in root.rglob("*") if p.is_file())
            for private in ("4111111111111111", "shopper@example.test", "MUST_NOT_BE_SAVED"):
                self.assertNotIn(private, saved)
                self.assertNotIn(private, output.getvalue())
            self.assertTrue(all(args[:3] == ["docker", "--context", "captured-engine"] for args in natives))

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
    def test_failed_cart_read_cannot_look_like_an_empty_cart(self):
        shop = ShopControls().module()
        outcome = {
            "checkout_HTTP_status": 200,
            "order_response_present": True,
            "cart_HTTP_status": 503,
            "cart_before": [{"product_id": "demo", "quantity": 1}],
            "cart_after": [],
        }
        self.assertFalse(shop.assess_story("normal-checkout", outcome)["passed"])

    def test_green_retained_cart_fails_normal_but_demonstrates_selected_fault(self):
        shop = ShopControls().module()
        item = [{"product_id": "demo", "quantity": 1}]
        outcome = {
            "cart_HTTP_status": 200,
            "checkout_HTTP_status": 200,
            "order_response_present": True,
            "cart_before": item,
            "cart_after": item,
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
                    "cart_HTTP_status": 200,
                    "checkout_HTTP_status": 200,
                    "order_response_present": True,
                    "cart_before": item,
                    "cart_after": [],
                },
            )["passed"]
        )
        self.assertTrue(
            shop.assess_story(
                "payment-unreachable",
                {
                    "cart_HTTP_status": 200,
                    "checkout_HTTP_status": 500,
                    "order_response_present": False,
                    "cart_before": item,
                    "cart_after": item,
                },
            )["passed"]
        )
        self.assertFalse(
            shop.assess_story(
                "normal-checkout",
                {
                    "cart_HTTP_status": 200,
                    "checkout_HTTP_status": 200,
                    "order_response_present": True,
                    "cart_before": [],
                    "cart_after": [],
                },
            )["passed"]
        )


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
