"""Small source-first Astronomy Shop CLI using native Docker Compose."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .source_integrity import verify_source
except ImportError:
    from source_integrity import verify_source

PUBLIC = Path(__file__).resolve().parent
CORE_SERVICES = (
    "ad",
    "astronomy-db",
    "cart",
    "checkout",
    "currency",
    "email",
    "flagd",
    "frontend",
    "frontend-proxy",
    "image-provider",
    "mcp",
    "otel-collector",
    "payment",
    "product-catalog",
    "quote",
    "recommendation",
    "shipping",
    "valkey-cart",
)
FRONTEND_NODE = "/nodejs/bin/node"  # The pinned distroless image uses this entrypoint path.
AGENT_REPLAY_OVERLAY = PUBLIC / "agent-replay" / "sitecustomize.py"
AGENT_REPLAY_MODEL = "azure/gpt-5.5"
AGENT_REPLAY_CASSETTE = "azure_gpt-5.5_cassette.yaml"
AGENT_VCRPY_VERSION = "8.3.0"
AGENT_PATCH_VCR_SHA256 = "d1a5f645bfd4a0006cfbdcfe2af8a0a9ecb754a8570c1168727d74ff3ccf492d"
AGENT_CASSETTE_SHA256 = "40a69e2353678db7ea7cb69baf5c1626097315cd1c4cdf33d66bff6496506acd"
STORIES = json.loads((PUBLIC / "stories.json").read_bytes())["stories"]
PROFILE = json.loads((PUBLIC / "runtime-profile.json").read_bytes())
for _name, _story in STORIES.items():
    if (
        not re.fullmatch(r"[a-z][a-z0-9-]*", _name)
        or _story.get("action") not in ("checkout", "mcp-cart", "shared-cart")
        or _story.get("source_variant") not in ("original", "mcp-session-id")
    ):
        raise ValueError("Story catalog contains an unsupported name, action or source variant.")
_RECORDER = None
SOURCE_COMMIT = "2c4be61741536937f1486ecaf74f44dbfd15d707"
BASE_IMAGES = json.loads((PUBLIC / "runtime-images.lock.json").read_bytes())["services"]
APPLICATION_PROVENANCE = json.loads((PUBLIC / "images.lock.json").read_bytes())
if any(
    entry["source_commit"] != SOURCE_COMMIT
    or entry["platform"] != "linux/amd64"
    or BASE_IMAGES.get(entry["service"]) != entry["reference"]
    for entry in APPLICATION_PROVENANCE["images"]
) or {entry["service"] for entry in APPLICATION_PROVENANCE["images"]} != set(CORE_SERVICES) - {
    "flagd",
    "valkey-cart",
    "astronomy-db",
    "otel-collector",
}:
    raise ValueError("Shipped image references and upstream application provenance are inconsistent.")


def progress(message, **metadata):
    print(message, flush=True)
    if _RECORDER is not None:
        _RECORDER.phase(message, **metadata)


def assess_story(story, outcome):
    expected = STORIES[story]["expected"]
    before = outcome.get("cart_before", outcome.get("HTTP_cart", []))
    after = outcome.get("cart_after", outcome.get("MCP_cart", []))
    positive = (
        len(before) == 1
        and type(before[0].get("quantity")) is int
        and before[0]["quantity"] == 1
        and isinstance(before[0].get("product_id"), str)
        and bool(before[0]["product_id"])
    )
    code = outcome.get("checkout_HTTP_status", 0)
    one_checkout = (
        type(outcome.get("checkout_attempt_count")) is int and outcome["checkout_attempt_count"] == 1
    )
    if expected == "success-empty":
        passed = (
            one_checkout
            and positive
            and code == 200
            and outcome.get("order_response_present") is True
            and after == []
        )
    elif expected == "success-retained":
        passed = (
            one_checkout
            and positive
            and code == 200
            and outcome.get("order_response_present") is True
            and after == before
        )
    elif expected == "error-retained":
        passed = (
            one_checkout
            and positive
            and isinstance(code, int)
            and 400 <= code <= 599
            and not outcome.get("order_response_present")
            and after == before
        )
    elif expected == "matching-cart":
        passed = (
            positive
            and outcome.get("MCP_initialized") is True
            and outcome.get("tool_error") is False
            and outcome.get("MCP_stateful_mutation_verified") is True
            and outcome.get("projections_match") is True
            and outcome.get("actor_isolation_verified") is True
            and after == before
        )
    elif expected == "ordered-conflict":
        intents = outcome.get("actor_intents", [])
        client_results = outcome.get("ordered_client_results", [])
        passed = (
            before == []
            and len(intents) == 2
            and [row.get("sequence") for row in intents] == [1, 2]
            and [row.get("intent") for row in intents] == ["retain-added-item", "clear-shared-cart"]
            and intents[0].get("shared_user_id") == intents[1].get("shared_user_id")
            and len(client_results) == 2
            and [row.get("actor_label") for row in client_results] == ["actor-A", "actor-B"]
            and outcome.get("host_cart_after") == []
            and client_results[0].get("cart_after") == before + [client_results[0].get("added_item")]
            and client_results[1].get("delete_status") == 204
            and client_results[1].get("cart_after") == []
            and outcome.get("cart_HTTP_status") == 200
            and after == []
            and outcome.get("cart_identity_observations")
            == {
                "empty_prestate": "NOT_ECHOED_FOR_EMPTY_CART",
                "actor_a_nonempty_readback": "MATCHED_REQUESTED_SHOPPER",
                "actor_b_empty_readback": "NOT_ECHOED_FOR_EMPTY_CART",
                "host_empty_readback": "NOT_ECHOED_FOR_EMPTY_CART",
            }
            and outcome.get("actor_identity") == "HARNESS_LABELS_ONLY_NOT_APPLICATION_AUTHENTICATION"
            and outcome.get("concurrency_claim") == "SEQUENTIALLY_ORDERED_NOT_OVERLAP_TESTED"
        )

    elif expected == "overlap-diagnostic":
        clients = outcome.get("concurrent_client_results", [])
        intents = outcome.get("actor_intents", [])
        windows_valid = len(clients) == 2 and all(
            type(row.get("request_start_monotonic_ns")) is int
            and type(row.get("response_complete_monotonic_ns")) is int
            and 0 < row["request_start_monotonic_ns"] < row["response_complete_monotonic_ns"]
            for row in clients
        )
        overlap_observed = windows_valid and max(row["request_start_monotonic_ns"] for row in clients) < min(
            row["response_complete_monotonic_ns"] for row in clients
        )
        requested = [row.get("item") for row in clients]
        final_items = outcome.get("cart_after")
        final_is_supported = (
            isinstance(final_items, list)
            and all(isinstance(item, dict) and item in requested for item in final_items)
            and len({item.get("product_id") for item in final_items if isinstance(item, dict)})
            == len(final_items)
        )
        passed = (
            before == []
            and [row.get("actor_label") for row in clients] == ["actor-A", "actor-B"]
            and all(row.get("status") == 200 for row in clients)
            and all(
                row.get("client_response_identity_status")
                in ("MATCHED_REQUESTED_SHOPPER", "NOT_ECHOED_FOR_EMPTY_CART")
                and hashlib.sha256(row.get("raw_response", "").encode()).hexdigest()
                == row.get("raw_response_sha256")
                for row in clients
            )
            and len(intents) == 2
            and [row.get("actor_label") for row in intents] == ["actor-A", "actor-B"]
            and [row.get("sequence") for row in intents] == [1, 2]
            and all(row.get("shared_user_id") == outcome.get("synthetic_shopper_id") for row in intents)
            and windows_valid
            and final_is_supported
            and outcome.get("cart_HTTP_status") == 200
            and outcome.get("actor_identity") == "HARNESS_LABELS_ONLY_NOT_APPLICATION_AUTHENTICATION"
        )
        outcome["client_window_overlap_observed"] = bool(overlap_observed)
        outcome["overlap_diagnostic"] = "OBSERVED" if overlap_observed else "NOT_OBSERVED"
        outcome["overlap_definition"] = (
            "max(request_start_monotonic_ns) < min(response_complete_monotonic_ns)"
        )
    else:
        raise ValueError("Story expected outcome is unsupported.")
    passed = passed and outcome.get("cart_HTTP_status") == 200
    assessment = {"passed": bool(passed), "expected": expected, "description": STORIES[story]["description"]}
    if expected == "overlap-diagnostic":
        assessment["diagnostic_result"] = outcome.get("overlap_diagnostic", "UNKNOWN")
        assessment["client_window_overlap_observed"] = outcome.get("client_window_overlap_observed")
        assessment["service_handler_overlap_claim"] = "NOT_ESTABLISHED"
    return assessment


def is_checkout_dispatch(method, path):
    """Classify only the sample's business checkout POST, not telemetry exports."""
    return method.upper() == "POST" and urlsplit(path).path == "/api/checkout"


def prepare_envoy(workspace, directory):
    text = (workspace / "src/frontend-proxy/envoy.tmpl.yaml").read_text(encoding="utf-8")
    marker = '                        - match: { prefix: "/" }'
    if text.count(marker) != 1:
        raise ValueError("The pinned public proxy template has an unexpected route layout.")
    route = (
        '                        - match: { path: "/api/checkout" }\n'
        f"                          route: {{ cluster: frontend, timeout: {PROFILE['proxy_checkout_seconds']}s, idle_timeout: {PROFILE['proxy_idle_seconds']}s }}\n"
        '                        - match: { path: "/api/cart" }\n'
        f"                          route: {{ cluster: frontend, timeout: {PROFILE['proxy_read_seconds']}s, idle_timeout: {PROFILE['proxy_idle_seconds']}s }}\n"
    )
    target = directory / "envoy.tmpl.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text.replace(marker, route + marker, 1), encoding="utf-8", newline="\n")
    target.chmod(0o644)  # Public config consumed by the non-root proxy.
    return target


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def verify_bind_sources(config):
    for service in config["services"].values():
        for mount in service.get("volumes", []):
            if mount.get("type") != "bind":
                continue
            source = Path(mount["source"])
            if not source.exists():
                raise ValueError("A required public bind input is absent: " + str(source))
            if os.name != "nt":
                required = 0o005 if source.is_dir() else 0o004
                if source.stat().st_mode & required != required:
                    raise ValueError(
                        "A public bind input is not readable by its non-root container: " + str(source)
                    )


def native(argv, source=None):
    from processes import run_native

    return run_native(argv, source, recorder=_RECORDER, timeout=PROFILE["native_timeout_seconds"])


def load_image_lock(path, variant, *, allow_pending=False):
    lock = json.loads(path.read_bytes())
    accepted = {"QUALIFIED"} | ({"SUPPORT_QUALIFICATION_PENDING"} if allow_pending else set())
    if lock.get("status") not in accepted or lock.get("source_variant") != variant:
        raise ValueError("Image lock is not yet qualified for this source variant; runtime is disabled.")
    if lock.get("source_commit") != SOURCE_COMMIT or lock.get("platform") != "linux/amd64":
        raise ValueError("Image lock does not bind the supported source and platform.")
    images = lock.get("services", {})
    if set(images) != set(CORE_SERVICES):
        raise ValueError("Qualified lock must cover the exact public core service set.")
    for name, value in images.items():
        if not (name == "mcp" and variant == "mcp-session-id") and value != BASE_IMAGES[name]:
            raise ValueError(
                "Image lock changed a qualified upstream reference; this sample cannot qualify custom images."
            )
        if (
            not (name == "mcp" and variant == "mcp-session-id")
            and isinstance(value, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", value)
        ):
            continue
        proof = lock.get("public_mcp_derivation", {})
        if (
            name == "mcp"
            and variant == "mcp-session-id"
            and isinstance(value, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            and proof.get("status") == "LOCAL_PUBLIC_BUILD"
            and proof.get("image_id") == value
            and proof.get("base_reference")
            == "ghcr.io/open-telemetry/demo@sha256:8cea957d3930d9df7365c0d655835bf3d553d097eae80d4428dac40b29ef533c"
            and proof.get("patch_sha256")
            == "a92da937de411c9e81b79ec75fdb86147994d7740e3c8f772eea5ae75c9ff276"
            and proof.get("patched_tools_sha256")
            == "179d31d39921f933eaf498b932ba54d075db9f8213730675095cfe012a003273"
        ):
            continue
        raise ValueError(
            "Use immutable registry digests; only the explicitly qualified public MCP derivation may use a local immutable ID."
        )
    return images


MCP_BASE_REFERENCE = (
    "ghcr.io/open-telemetry/demo@sha256:8cea957d3930d9df7365c0d655835bf3d553d097eae80d4428dac40b29ef533c"
)
MCP_TOOLS_SHA256 = "179d31d39921f933eaf498b932ba54d075db9f8213730675095cfe012a003273"


def build_public_mcp(directory, workspace, context, runner=native):
    source = workspace / "src/shared/tools.py"
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != MCP_TOOLS_SHA256:
        raise ValueError(
            "The public MCP source does not match the shipped query correction; no build was started."
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context):
        raise ValueError("Docker context name is invalid.")
    build_context = directory / "mcp-image-inputs"
    build_context.mkdir(parents=True, exist_ok=True)
    recipe = (
        "FROM " + MCP_BASE_REFERENCE + "\nCOPY src/shared/tools.py /app/src/mcp_server/tools.py\n"
    ).encode()
    files = {"Dockerfile": recipe, "src/shared/tools.py": data}
    existing = list(build_context.rglob("*"))
    if any(f.is_symlink() for f in existing) or any(
        f.is_file() and f.relative_to(build_context).as_posix() not in files for f in existing
    ):
        raise ValueError("MCP build context contains an unexpected file; no build was started.")
    for name, contents in files.items():
        target = build_context / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != contents:
            raise ValueError("MCP build input changed; no build was started.")
        target.write_bytes(contents)
    image_file = directory / "mcp-image-id.txt"
    print("Preparing the public MCP cart-query correction...", flush=True)
    runner(["docker", "--context", context, "pull", "--platform", "linux/amd64", MCP_BASE_REFERENCE])
    runner(
        [
            "docker",
            "--context",
            context,
            "build",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--iidfile",
            str(image_file),
            str(build_context),
        ]
    )
    identity = image_file.read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise ValueError("Docker did not return an immutable MCP image identity.")
    observed = runner(
        ["docker", "--context", context, "image", "inspect", identity, "--format", "{{.Id}}"]
    ).strip()
    if observed != identity:
        raise ValueError("The built MCP image does not match its recorded identity.")
    proof = {
        "status": "LOCAL_PUBLIC_BUILD",
        "image_id": identity,
        "base_reference": MCP_BASE_REFERENCE,
        "patch_sha256": "a92da937de411c9e81b79ec75fdb86147994d7740e3c8f772eea5ae75c9ff276",
        "patched_tools_sha256": MCP_TOOLS_SHA256,
        "dockerfile_sha256": hashlib.sha256(recipe).hexdigest(),
    }
    write_json(directory / "mcp-build.json", proof)
    return proof


def compose_args(state, arguments):
    if not re.fullmatch(r"shop-[0-9a-f]{12}", state.get("project", "")):
        raise ValueError("Refusing a namespace not owned by this sample.")
    context = state.get("docker_context", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context):
        raise ValueError(
            "A captured Docker context is required; it is never reselected for later operations."
        )
    return [
        "docker",
        "--context",
        context,
        "compose",
        "--project-name",
        state["project"],
        "-f",
        state["config"],
        *arguments,
    ]


def apply_runtime_profile(config):
    for name, service in config["services"].items():
        service.pop("container_name", None)
        service.pop("profiles", None)
        service.get("deploy", {}).pop("placement", None)
        floor = PROFILE["memory_floor_mib"].get(name)
        if floor is not None:
            if type(floor) is not int or floor <= 0:
                raise ValueError("Runtime memory floors must be positive integer MiB values.")
            limits = service.setdefault("deploy", {}).setdefault("resources", {}).setdefault("limits", {})
            limits["memory"] = str(max(int(limits.get("memory", 0)), floor * 1024 * 1024))
        if name == "payment":
            # This is a local Compose lab: cloud metadata discovery has no
            # useful result and also runs in the image's instrumented Node
            # health-check child. Keep application tracing enabled.
            service.setdefault("environment", {})["OTEL_NODE_RESOURCE_DETECTORS"] = "env,host,os,process"
            if "healthcheck" in service:
                service["healthcheck"]["timeout"] = "15s"
    return config


def routing_binding(state):
    fields = (
        "project",
        "docker_context",
        "engine_id",
        "story",
        "source_variant",
        "http_port",
        "mcp_port",
        "config",
        "workspace",
        "images_lock",
        "base_images_lock",
        "evidence_root",
        "telemetry_directory",
        "agent_replay_enabled",
        "agent_replay_overlay",
        "agent_replay_cassette",
    )
    identity = json.dumps(
        {key: state.get(key) for key in fields}, sort_keys=True, separators=(",", ":")
    ).encode()
    return {"sha256": hashlib.sha256(identity).hexdigest(), "bytes": len(identity)}


def bound_inputs(state, directory):
    files = {
        "compose": Path(state["config"]),
        "flags": directory / "flags/demo.flagd.json",
        "proxy": directory / "envoy.tmpl.yaml",
        "collector": PUBLIC / "collector.yaml",
        "stories": PUBLIC / "stories.json",
        "profile": PUBLIC / "runtime-profile.json",
        "images": Path(state["images_lock"]),
        "provenance": PUBLIC / "images.lock.json",
    }
    if state.get("agent_replay_enabled") is True:
        files["agent_replay_overlay"] = Path(state["agent_replay_overlay"])
        files["agent_replay_cassette"] = Path(state["agent_replay_cassette"])
    result = {
        key: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
        for key, path in files.items()
    }
    result["routing"] = routing_binding(state)
    return result


def verify_control_target(state, directory, runner=native):
    compose_args(state, [])
    if state.get("input_bindings", {}).get("routing") != routing_binding(state):
        raise ValueError("Stop/cleanup target identity changed; no Docker mutation was dispatched.")
    config = Path(state["config"]).resolve()
    if config != (directory / "compose.json").resolve():
        raise ValueError("Stop/cleanup configuration escapes its recorded world.")
    data = config.read_bytes()
    expected = state["input_bindings"].get("compose")
    if expected != {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}:
        raise ValueError("Stop/cleanup configuration changed; no Docker mutation was dispatched.")
    rendered = json.loads(data)
    resources = [*rendered.get("volumes", {}).values(), *rendered.get("networks", {}).values()]
    if rendered.get("name") != state["project"] or any(
        value.get("external") or not str(value.get("name", "")).startswith(state["project"] + "_")
        for value in resources
    ):
        raise ValueError("Stop/cleanup resources escape their recorded namespace.")
    engine = runner(["docker", "--context", state["docker_context"], "info", "--format", "{{.ID}}"]).strip()
    if not state.get("engine_id") or engine != state["engine_id"]:
        raise ValueError("Stop/cleanup Docker engine changed or is unknown; no mutation was dispatched.")
    return rendered


def bind_world(state, directory):
    receipt = verify_source(Path(state["workspace"]), state["source_variant"])
    state["source_receipt_sha256"] = receipt["source_receipt_sha256"]
    state["input_bindings"] = bound_inputs(state, directory)


def verify_world(state, directory):
    receipt = verify_source(Path(state["workspace"]), state["source_variant"])
    if state.get("source_receipt_sha256") != receipt["source_receipt_sha256"] or state.get(
        "input_bindings"
    ) != bound_inputs(state, directory):
        raise ValueError(
            "Recorded source/configuration inputs changed; prepare a fresh shop. No case was dispatched."
        )
    return receipt


def snapshot_runtime(state, directory, runner=native):
    images = load_image_lock(Path(state["images_lock"]), state["source_variant"])
    context = ["docker", "--context", state["docker_context"]]
    engine = runner([*context, "info", "--format", "{{.ID}}"]).strip()
    if not engine or state.get("engine_id", engine) != engine:
        raise ValueError("The captured Docker context now resolves to a different or unknown engine.")
    names = list(images)
    inspected = [
        json.loads(line)
        for line in runner(
            [
                *context,
                "image",
                "inspect",
                *[images[name] for name in names],
                "--format",
                '{"config_id":{{json .Id}},"repo_digests":{{json .RepoDigests}}}',
            ]
        ).splitlines()
        if line.strip()
    ]
    if len(inspected) != len(names) or any(
        not re.fullmatch(r"sha256:[0-9a-f]{64}", record.get("config_id", "")) for record in inspected
    ):
        raise ValueError("Runtime image census is incomplete.")
    expected = {name: record["config_id"] for name, record in zip(names, inspected)}
    identifiers = runner(compose_args(state, ["ps", "--all", "--quiet", *CORE_SERVICES])).split()
    if len(identifiers) != len(CORE_SERVICES) or any(
        not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in identifiers
    ):
        raise ValueError("Runtime container census is incomplete.")
    template = '{"container_id":{{json .Id}},"image_id":{{json .Image}},"configured_image":{{json .Config.Image}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"running":{{json .State.Running}},"oom_killed":{{json .State.OOMKilled}}}'
    rows = [
        json.loads(line)
        for line in runner([*context, "inspect", *identifiers, "--format", template]).splitlines()
        if line.strip()
    ]
    if {row["service"] for row in rows} != set(CORE_SERVICES) or any(
        not row["running"]
        or row["oom_killed"]
        or row["image_id"] != expected[row["service"]]
        or row["configured_image"] != images[row["service"]]
        for row in rows
    ):
        raise ValueError("Actual containers do not match the selected public image closure.")
    state["engine_id"] = engine
    state["input_bindings"] = bound_inputs(state, directory)
    write_json(directory / "state.json", state)
    result = {
        "engine_id": engine,
        "docker_context": state["docker_context"],
        "project": state["project"],
        "containers": rows,
        "images": {name: record for name, record in zip(names, inspected)},
    }
    if _RECORDER is not None:
        path = _RECORDER.directory / "runtime-observed.json"
        write_json(path, result)
        _RECORDER.artifact("Observed engine, containers and image identities", path)
    return result


def snapshot_inputs(state, directory):
    if _RECORDER is None:
        return
    output = _RECORDER.directory / "inputs"
    output.mkdir(parents=True, exist_ok=True)
    files = {
        "compose.json": Path(state["config"]),
        "images.lock.json": Path(state["images_lock"]),
        "flags.json": directory / "flags/demo.flagd.json",
        "envoy.tmpl.yaml": directory / "envoy.tmpl.yaml",
        "source-manifest.json": PUBLIC / "source-manifest.json",
        "stories.json": PUBLIC / "stories.json",
        "runtime-profile.json": PUBLIC / "runtime-profile.json",
        "collector.yaml": PUBLIC / "collector.yaml",
        "source-inventory.json": Path(state["workspace"]).with_name(
            Path(state["workspace"]).name + ".source-inventory.json"
        ),
        "source-receipt.json": Path(state["workspace"]).parent
        / (Path(state["workspace"]).name + ".source-receipt.json"),
    }
    if state.get("agent_replay_enabled") is True:
        files["agent-replay-overlay.py"] = Path(state["agent_replay_overlay"])
        files["agent-replay-cassette.yaml"] = Path(state["agent_replay_cassette"])
    manifest = []
    for name, source in files.items():
        if not source.is_file():
            raise ValueError("A required run input is missing: " + name)
        destination = output / name
        shutil.copyfile(source, destination)
        manifest.append(
            {
                "file": name,
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                "bytes": destination.stat().st_size,
            }
        )
        _RECORDER.artifact(name, destination)
    write_json(
        output / "manifest.json",
        {"files": manifest, "source_commit": "2c4be61741536937f1486ecaf74f44dbfd15d707"},
    )
    tool_sources = [
        "shop.py",
        "bootstrap_source.py",
        "source_integrity.py",
        "processes.py",
        "logwatch.py",
        "evidence.py",
    ]
    write_json(
        output / "launcher-source-hashes.json",
        {"files": {name: hashlib.sha256((PUBLIC / name).read_bytes()).hexdigest() for name in tool_sources}},
    )
    _RECORDER.artifact("Run input manifest", output / "manifest.json")
    if state.get("telemetry_directory") and Path(state["telemetry_directory"]).exists():
        _RECORDER.artifact("Application traces folder", Path(state["telemetry_directory"]))


def scoped_config(
    rendered,
    images,
    project,
    flags,
    http_port,
    mcp_port,
    envoy_template=None,
    telemetry=None,
    *,
    agent_replay=False,
    agent_overlay=None,
):
    compose_args({"project": project, "config": "pending", "docker_context": "source-validation"}, [])
    if any(name not in rendered["services"] for name in CORE_SERVICES):
        raise ValueError("Pinned upstream render lacks a required core service.")
    services = {}
    for name in CORE_SERVICES:
        service = copy.deepcopy(rendered["services"][name])
        service.pop("build", None)
        service.pop("profiles", None)
        service.pop("container_name", None)
        service.get("deploy", {}).pop("placement", None)
        service["image"] = images[name]
        service["restart"] = "no"
        service["ports"] = []
        service["networks"] = {"default": None}
        depends = service.get("depends_on", {})
        service["depends_on"] = {key: value for key, value in depends.items() if key in CORE_SERVICES}
        env = service.get("environment", {})
        if isinstance(env, dict):
            service["environment"] = {
                key: value
                for key, value in env.items()
                if not key.startswith(("LLM_", "OPENAI_", "TRACELOOP_")) and key != "API_KEY"
            }
        service["platform"] = "linux/amd64"
        services[name] = service
    services["checkout"].setdefault("environment", {})["KAFKA_ADDR"] = ""
    services["mcp"].setdefault("environment", {})["TRACELOOP_BASE_URL"] = "http://otel-collector:4318"
    if envoy_template is not None:
        services["frontend-proxy"]["volumes"] = [
            {
                "type": "bind",
                "source": str(envoy_template.absolute()),
                "target": "/home/envoy/envoy.tmpl.yaml",
                "read_only": True,
            }
        ]
    services["frontend-proxy"]["ports"] = [
        {"target": 8080, "published": str(http_port), "host_ip": "127.0.0.1", "protocol": "tcp"}
    ]
    services["mcp"]["ports"] = [
        {"target": 8011, "published": str(mcp_port), "host_ip": "127.0.0.1", "protocol": "tcp"}
    ]
    # Docker cannot publish ports for containers attached exclusively to an
    # internal bridge. Only the two loopback entrypoints get a gateway network.
    for entrypoint in ("frontend-proxy", "mcp"):
        services[entrypoint]["networks"]["edge"] = None
    services["flagd"]["volumes"] = [
        {"type": "bind", "source": str(flags.absolute()), "target": "/etc/flagd", "read_only": True}
    ]
    services["otel-collector"]["volumes"] = [
        {
            "type": "bind",
            "source": str(PUBLIC / "collector.yaml"),
            "target": "/etc/otelcol/config.yaml",
            "read_only": True,
        }
    ]
    if telemetry is not None:
        services["otel-collector"]["volumes"].append(
            {"type": "bind", "source": str(telemetry.absolute()), "target": "/evidence", "read_only": False}
        )
    services["otel-collector"]["command"] = ["--config=/etc/otelcol/config.yaml"]
    networks = {
        "default": {"name": project + "_default", "driver": "bridge", "internal": True},
        "edge": {"name": project + "_edge", "driver": "bridge", "internal": False},
    }
    if agent_replay:
        if agent_overlay is None or "agent" not in rendered["services"]:
            raise ValueError("Replay-only agent setup requires the pinned upstream agent and safety overlay.")
        agent = copy.deepcopy(rendered["services"]["agent"])
        agent.pop("container_name", None)
        agent.get("deploy", {}).pop("placement", None)
        agent["restart"] = "no"
        agent["ports"] = []
        agent["platform"] = "linux/amd64"
        agent["networks"] = {"agent-replay": None}
        agent["depends_on"] = {
            name: dependency
            for name, dependency in agent.get("depends_on", {}).items()
            if name in CORE_SERVICES
        }
        upstream_environment = agent.get("environment", {})
        if not isinstance(upstream_environment, dict):
            raise ValueError("Pinned upstream agent environment is not a rendered mapping.")
        # Rebuild, do not inherit the source .env: only these local endpoints and
        # replay controls are needed, and unknown credential names must not leak.
        env = {
            "WORKFLOW_LAB_CASSETTE_REPLAY_ONLY": "1",
            "USE_VCR": "true",
            "VCR_MATCH_THRESHOLD": "1.0",
            "LLM_MODEL": AGENT_REPLAY_MODEL,
            "LLM_BASE_URL": "http://127.0.0.1:9/v1",
            "LLM_TLS_VERIFY": "true",
            "API_KEY": "sk-dummy",
            "OPENAI_API_KEY": "sk-dummy",
            "MCP_ENABLED": "True",
            "MCP_ENDPOINT": "mcp",
            "MCP_PORT": "8011",
            "AGENT_PORT": "8010",
            "GRAPH_RECURSION_LIMIT": "6",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel-collector:4318",
            "OTEL_EXPORTER_OTLP_INSECURE": "true",
            "OTEL_RESOURCE_ATTRIBUTES": "service.namespace=workflow-lab,service.criticality=low",
            "OTEL_SERVICE_NAME": "agent",
            "OTEL_PYTHON_SDK_INTERNAL_METRICS_ENABLED": "true",
            "TRACELOOP_BASE_URL": "http://otel-collector:4318",
            "FLAGD_HOST": "flagd",
            "FLAGD_PORT": "8013",
        }
        agent["environment"] = env
        volumes = agent.get("volumes", [])
        for volume in volumes:
            if isinstance(volume, dict) and volume.get("target") == "/app/fixtures":
                volume["read_only"] = True
        volumes.append(
            {
                "type": "bind",
                "source": str(Path(agent_overlay).absolute()),
                "target": "/app/sitecustomize.py",
                "read_only": True,
            }
        )
        agent["volumes"] = volumes
        services["agent"] = agent
        for service_name in ("mcp", "otel-collector", "flagd"):
            services[service_name]["networks"]["agent-replay"] = None
        networks["agent-replay"] = {
            "name": project + "_agent-replay",
            "driver": "bridge",
            "internal": True,
        }
    volumes = copy.deepcopy(rendered.get("volumes", {}))
    for name, volume in volumes.items():
        if volume.get("external"):
            raise ValueError("External volumes are outside the sample namespace.")
        volume["name"] = project + "_" + name
    return apply_runtime_profile(
        {
            "name": project,
            "services": services,
            "networks": networks,
            "volumes": volumes,
        }
    )


def request(port, method, path, body=None):
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=PROFILE["checkout_http_seconds"]
        if is_checkout_dispatch(method, path)
        else PROFILE["read_http_seconds"],
    )
    try:
        payload = None if body is None else json.dumps(body).encode()
        connection.request(method, path, body=payload, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("Demo response exceeds the bounded sample limit.")
        try:
            decoded = json.loads(raw) if raw else None
        except (ValueError, UnicodeError):
            decoded = {"non_json_response": True, "response_bytes": len(raw)}
        return response.status, decoded
    finally:
        connection.close()


def validate_user(user):
    if not re.fullmatch(r"shop-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", user):
        raise ValueError("Choose a fresh synthetic shopper ID: shop-<UUIDv4>.")


def reset_subject(state, user, http=request):
    validate_user(user)
    if user not in state["users"] or state["users"][user].get("status") != "OBSERVED":
        raise ValueError(
            "Only recorded, reconciled synthetic shoppers may be reset; uncertain checkout is not retried or reset automatically."
        )
    status, _ = http(state["http_port"], "DELETE", "/api/cart", {"userId": user})
    if status not in (200, 204):
        raise RuntimeError("Exact shopper cart reset failed; no retry was made.")
    read_status, cart = http(state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD")
    if read_status != 200:
        raise RuntimeError("Reset acknowledgement did not produce an API empty-cart readback; no retry.")
    try:
        empty = cart_items(cart, expected_user=user) == []
    except ValueError as error:
        raise RuntimeError(
            "Reset acknowledgement did not produce an API empty-cart readback; no retry."
        ) from error
    if not empty:
        raise RuntimeError("Reset acknowledgement did not produce an API empty-cart readback; no retry.")
    return {
        "synthetic_cart_reset_status": status,
        "API_cart_readback_empty": True,
        "API_cart_readback_identity": cart_identity_status(cart, user),
        "other_data_touched": False,
    }


def claim_checkout(directory, user):
    validate_user(user)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (user + ".claim")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"one checkout dispatch; never automatically retry\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def cart_identity_status(value, expected_user):
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError("Cart read has no valid items array; empty-cart observation is unknown.")
    if value.get("userId") == expected_user:
        return "MATCHED_REQUESTED_SHOPPER"
    if value.get("items") == [] and value.get("userId") in (None, ""):
        return "NOT_ECHOED_FOR_EMPTY_CART"
    raise ValueError("Cart read is for another or unknown synthetic shopper; observation is unknown.")


def cart_items(value, *, expected_user=None):
    result = []
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError("Cart read has no valid items array; empty-cart observation is unknown.")
    if expected_user is not None:
        cart_identity_status(value, expected_user)
    for item in value["items"]:
        if not isinstance(item, dict):
            raise ValueError("Cart item schema is invalid; cart observation is unknown.")
        product = item.get("productId", item.get("product_id"))
        quantity = item.get("quantity")
        if not isinstance(product, str) or not product or type(quantity) is not int or quantity <= 0:
            raise ValueError("Cart item identity or quantity is invalid; cart observation is unknown.")
        result.append({"product_id": product, "quantity": quantity})
    return result


class ValkeyPayloadError(ValueError):
    """A protobuf failure with a fixed code; byte_offset is the parser cursor."""

    def __init__(self, code, *, byte_offset=None, payload_bytes=None):
        self.code = code
        self.byte_offset = byte_offset
        self.payload_bytes = payload_bytes
        super().__init__(code)


def _proto_varint(data, offset, *, context):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValkeyPayloadError(
                "protobuf-" + context + "-truncated-varint",
                byte_offset=offset,
                payload_bytes=len(data),
            )
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            if value > 0xFFFFFFFFFFFFFFFF:
                raise ValkeyPayloadError("protobuf-" + context + "-varint-out-of-range")
            return value, offset
    raise ValkeyPayloadError("protobuf-" + context + "-overlong-varint")


def _proto_bytes(data, offset, *, context):
    size, offset = _proto_varint(data, offset, context=context)
    end = offset + size
    if end > len(data):
        raise ValkeyPayloadError("protobuf-" + context + "-truncated-field")
    return data[offset:end], end


def _decode_cart_item(data):
    product_id = None
    quantity = None
    offset = 0
    while offset < len(data):
        tag, offset = _proto_varint(data, offset, context="cart-item")
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2 and product_id is None:
            raw, offset = _proto_bytes(data, offset, context="cart-item")
            product_id = raw.decode("utf-8")
        elif field == 2 and wire == 0 and quantity is None:
            quantity, offset = _proto_varint(data, offset, context="cart-item")
        else:
            raise ValkeyPayloadError("protobuf-cart-item-unsupported-field")
    if not product_id or type(quantity) is not int or not 0 < quantity <= 0x7FFFFFFF:
        raise ValkeyPayloadError("protobuf-cart-item-incomplete-or-invalid")
    return {"product_id": product_id, "quantity": quantity}


def decode_valkey_cart(data):
    """Decode only the Cart/CartItem fields in the pinned upstream demo.proto."""
    if not isinstance(data, bytes) or len(data) > 1_048_576:
        raise ValkeyPayloadError("protobuf-absent-or-over-limit")
    user_id = ""
    items = []
    user_id_seen = False
    offset = 0
    while offset < len(data):
        tag, offset = _proto_varint(data, offset, context="cart")
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2 and not user_id_seen:
            raw, offset = _proto_bytes(data, offset, context="cart")
            user_id = raw.decode("utf-8")
            user_id_seen = True
        elif field == 2 and wire == 2:
            raw, offset = _proto_bytes(data, offset, context="cart")
            items.append(_decode_cart_item(raw))
        else:
            raise ValkeyPayloadError("protobuf-cart-unsupported-or-duplicate-field")
    if len({item["product_id"] for item in items}) != len(items):
        raise ValkeyPayloadError("protobuf-cart-duplicate-product-id")
    return {"user_id": user_id, "items": items}


def read_valkey_cart(state, user, runner=native):
    """Read one pinned cart hash through the captured Compose target; never write."""
    phase = "input-validation"
    try:
        validate_user(user)
        config_path = Path(state.get("config", ""))
        phase = "capture-binding"
        config_bytes = config_path.read_bytes()
        config_binding = {"sha256": hashlib.sha256(config_bytes).hexdigest(), "bytes": len(config_bytes)}
        recorded_bindings = state.get("input_bindings")
        if (
            state.get("source_variant") not in ("original", "mcp-session-id")
            or state.get("source_commit") != SOURCE_COMMIT
            or not re.fullmatch(r"shop-[0-9a-f]{12}", state.get("project", ""))
            or not isinstance(state.get("config"), str)
            or not config_path.is_file()
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", state.get("docker_context", ""))
            or not isinstance(state.get("engine_id"), str)
            or not state["engine_id"]
            or not isinstance(recorded_bindings, dict)
            or recorded_bindings.get("compose") != config_binding
            or recorded_bindings.get("routing") != routing_binding(state)
        ):
            return {"status": "UNKNOWN", "reason": "unsupported-source-binding"}
        phase = "engine-binding"
        engine = runner(
            ["docker", "--context", state["docker_context"], "info", "--format", "{{.ID}}"]
        ).strip()
        if engine != state["engine_id"]:
            return {"status": "UNKNOWN", "reason": "docker-engine-binding-changed"}
        phase = "container-read"
        quoted_user = shlex.quote(user)
        lua = (
            'local n=redis.call("HSTRLEN",KEYS[1],ARGV[1]); '
            'if n > 1048576 then return "OVERSIZE" end; '
            'local v=redis.call("HGET",KEYS[1],ARGV[1]); '
            'if not v then return "MISSING" end; '
            'local h=string.gsub(v,".",function(c) return string.format("%02x",string.byte(c)) end); '
            'return string.format("%010d",n) .. h'
        )
        script = (
            "set -e; "
            f"valkey-cli --raw EVAL {shlex.quote(lua)} 1 {quoted_user} cart "
            "| tr -d '\\n' | base64 | tr -d '\\n'; printf '\\n'"
        )
        output = runner(compose_args(state, ["exec", "-T", "valkey-cart", "sh", "-c", script]))
        rows = output.splitlines()
        if len(rows) != 1:
            return {"status": "UNKNOWN", "reason": "missing-or-malformed-valkey-readback"}
        if len(rows[0]) > 2_796_216:
            return {"status": "UNKNOWN", "reason": "valkey-readback-exceeds-sample-bound"}
        phase = "base64-decode"
        framed = base64.b64decode(rows[0], validate=True)
        if framed == b"OVERSIZE":
            return {"status": "UNKNOWN", "reason": "valkey-readback-exceeds-sample-bound"}
        if framed == b"MISSING":
            return {"status": "UNKNOWN", "reason": "missing-or-malformed-valkey-readback"}
        if len(framed) < 10 or not re.fullmatch(rb"[0-9]{10}", framed[:10]):
            return {"status": "UNKNOWN", "reason": "missing-or-malformed-valkey-readback"}
        expected_payload_bytes = int(framed[:10])
        encoded_payload = framed[10:]
        if expected_payload_bytes > 1_048_576 or len(encoded_payload) > 2_097_152:
            return {"status": "UNKNOWN", "reason": "valkey-readback-exceeds-sample-bound"}
        if len(encoded_payload) != expected_payload_bytes * 2:
            return {"status": "UNKNOWN", "reason": "valkey-payload-length-mismatch"}
        try:
            payload = bytes.fromhex(encoded_payload.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return {"status": "UNKNOWN", "reason": "valkey-payload-hex-decode-failed-or-invalid"}
        if len(payload) != expected_payload_bytes:
            return {"status": "UNKNOWN", "reason": "valkey-payload-length-mismatch"}
        phase = "protobuf-decode"
        cart = decode_valkey_cart(payload)
        phase = "payload-identity"
        if cart["user_id"] and cart["user_id"] != user:
            return {"status": "UNKNOWN", "reason": "valkey-payload-user-mismatch"}
        if cart["items"] and cart["user_id"] != user:
            return {"status": "UNKNOWN", "reason": "valkey-nonempty-cart-identity-unbound"}
        phase = "post-read-binding"
        return {
            "status": "OBSERVED",
            "key_user_id": user,
            "payload_user_id": cart["user_id"] or None,
            "identity_basis": "payload-user-id"
            if cart["user_id"]
            else "exact-valkey-hash-key-empty-payload-has-no-user-id",
            "items": cart["items"],
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "project_id": state["project"],
            "source_commit": state["source_commit"],
            "docker_context": state["docker_context"],
            "config_sha256": hashlib.sha256(Path(state["config"]).read_bytes()).hexdigest(),
        }
    except ValkeyPayloadError as error:
        observation = {"status": "UNKNOWN", "reason": "valkey-" + error.code}
        if error.byte_offset is not None and error.payload_bytes is not None:
            observation["failure_byte_offset"] = error.byte_offset
            observation["failure_payload_bytes"] = error.payload_bytes
        return observation
    except (OSError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError, binascii.Error):
        return {"status": "UNKNOWN", "reason": "valkey-" + phase + "-failed-or-invalid"}


def compare_valkey_cart(user, expected_items, observation):
    """Compare a direct store observation with one API projection without upgrading missing evidence."""
    if observation.get("status") != "OBSERVED" or observation.get("key_user_id") != user:
        return "UNKNOWN"
    if observation.get("items") != expected_items:
        return "CONTRADICTED"
    return "MATCHED_API_READBACK"


def verify_health(state, runner=native, http=request):
    raw = runner(compose_args(state, ["ps", "--format", "json"]))
    try:
        records = json.loads(raw)
        if isinstance(records, dict):
            records = [records]
    except json.JSONDecodeError:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    by_service = {x.get("Service"): x for x in records}
    unhealthy = [
        name
        for name in CORE_SERVICES
        if name not in by_service
        or by_service[name].get("State") != "running"
        or by_service[name].get("Health") not in (None, "", "healthy")
    ]
    if unhealthy:
        raise ValueError(
            "Core services are not ready: " + ", ".join(unhealthy) + ". No story mutation was dispatched."
        )
    status, products = http(state["http_port"], "GET", "/api/products?currencyCode=USD")
    if status != 200 or not isinstance(products, list) or not products:
        raise ValueError("Read-only catalogue health check failed; no story mutation was dispatched.")
    probe = """import asyncio,json
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
async def main():
 async with streamablehttp_client("http://127.0.0.1:8011/mcp") as (read,write,_):
  async with ClientSession(read,write) as session:
   await session.initialize()
   tools=await session.list_tools()
   print(json.dumps({"ready":"get_cart" in [x.name for x in tools.tools]}))
asyncio.run(main())
"""
    ready = json.loads(runner(compose_args(state, ["exec", "-T", "mcp", "python", "-"]), probe))
    if ready.get("ready") is not True:
        raise ValueError(
            "Read-only MCP initialize/list health check failed; no story mutation was dispatched."
        )
    return True


def wait_ready(state, runner=native, http=request, *, seconds=60, pause=time.sleep, clock=time.monotonic):
    deadline = clock() + seconds
    while True:
        try:
            return verify_health(state, runner, http)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            if clock() >= deadline:
                raise RuntimeError(
                    "The read-only startup check did not become ready; no story was dispatched."
                ) from error
            progress("Waiting for browser/API and MCP endpoints to become ready...", status="waiting")
            pause(2)


def run_shared_cart_conflict(state, directory, user, product, runner, http):
    """Run two separate sequential clients against one synthetic user/cart."""
    initial_status, initial = http(
        state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    if initial_status != 200 or cart_items(initial, expected_user=user):
        raise ValueError("Shared-cart conflict requires a verified empty prestate; no actor ran.")
    initial_identity = cart_identity_status(initial, user)
    second_product = product[1]
    if product[0] == second_product:
        raise ValueError("The catalogue did not provide distinct products for the conflict case.")

    actor_a_source = """const crypto = require('node:crypto');
const frontendOrigin = 'http://' + require('node:os').hostname() + ':' + process.env.PORT;
const userId = USER_ID;
const productId = PRODUCT_ID;
async function main() {
  const response = await fetch(frontendOrigin + '/api/cart?currencyCode=USD', {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({userId, item: {productId, quantity: 1}})
  });
  const raw = await response.text();
  process.stdout.write(JSON.stringify({actor_label: 'actor-A', intent: 'retain-added-item', status: response.status,
    raw_response: raw, raw_response_sha256: crypto.createHash('sha256').update(raw).digest('hex')}) + '\\n');
}
main().catch(error => {
  const cause = error && error.cause ? `; cause=${String(error.cause)}` : '';
  console.error(`${String(error)}${cause}`);
  process.exitCode = 1;
});
""".replace("USER_ID", json.dumps(user)).replace("PRODUCT_ID", json.dumps(product[0]))
    state["users"][user] = {"status": "DISPATCHED", "story": "shared-cart-conflict"}
    write_json(directory / "state.json", state)
    actor_a = json.loads(
        runner(compose_args(state, ["exec", "-T", "frontend", FRONTEND_NODE, "-e", actor_a_source]))
    )
    if (
        actor_a.get("status") != 200
        or actor_a.get("actor_label") != "actor-A"
        or actor_a.get("intent") != "retain-added-item"
        or hashlib.sha256(actor_a.get("raw_response", "").encode()).hexdigest()
        != actor_a.get("raw_response_sha256")
    ):
        raise RuntimeError("First shared-cart client result is missing or unbound; state is unknown.")
    actor_a_cart = json.loads(actor_a["raw_response"])
    added_items = cart_items(actor_a_cart, expected_user=user)
    actor_a_identity = cart_identity_status(actor_a_cart, user)
    expected_item = {"product_id": product[0], "quantity": 1}
    if added_items != [expected_item]:
        raise RuntimeError("First client did not observe its expected cart write; state is unknown.")

    actor_b_source = """const crypto = require('node:crypto');
const frontendOrigin = 'http://' + require('node:os').hostname() + ':' + process.env.PORT;
const userId = USER_ID;
async function record(response) {
  const raw = await response.text();
  return {status: response.status, raw_response: raw,
    raw_response_sha256: crypto.createHash('sha256').update(raw).digest('hex')};
}
async function main() {
  const deleted = await record(await fetch(frontendOrigin + '/api/cart', {
    method: 'DELETE', headers: {'content-type': 'application/json'}, body: JSON.stringify({userId})
  }));
  const read = await record(await fetch(frontendOrigin + '/api/cart?sessionId=' + encodeURIComponent(userId) + '&currencyCode=USD'));
  process.stdout.write(JSON.stringify({actor_label: 'actor-B', intent: 'clear-shared-cart', delete: deleted, read}) + '\\n');
}
main().catch(error => {
  const cause = error && error.cause ? `; cause=${String(error.cause)}` : '';
  console.error(`${String(error)}${cause}`);
  process.exitCode = 1;
});
""".replace("USER_ID", json.dumps(user))
    actor_b = json.loads(
        runner(compose_args(state, ["exec", "-T", "frontend", FRONTEND_NODE, "-e", actor_b_source]))
    )
    if actor_b.get("actor_label") != "actor-B" or actor_b.get("intent") != "clear-shared-cart":
        raise RuntimeError("Second shared-cart client identity is missing; state is unknown.")
    for record in (actor_b.get("delete", {}), actor_b.get("read", {})):
        if hashlib.sha256(record.get("raw_response", "").encode()).hexdigest() != record.get(
            "raw_response_sha256"
        ):
            raise RuntimeError("Second shared-cart client result is missing or unbound; state is unknown.")
    if actor_b.get("delete", {}).get("status") != 204 or actor_b.get("read", {}).get("status") != 200:
        raise RuntimeError("Second shared-cart client did not clear and read the cart; state is unknown.")
    actor_b_cart = json.loads(actor_b["read"]["raw_response"])
    client_b_items = cart_items(actor_b_cart, expected_user=user)
    actor_b_identity = cart_identity_status(actor_b_cart, user)
    observer_status, observer = http(
        state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    observed_items = cart_items(observer, expected_user=user) if observer_status == 200 else None
    observer_identity = cart_identity_status(observer, user) if observer_status == 200 else "UNKNOWN"
    return {
        "story": "shared-cart-conflict",
        "project_id": state["project"],
        "synthetic_shopper_id": user,
        "cart_before": [],
        "cart_after": client_b_items,
        "cart_HTTP_status": observer_status,
        "actor_intents": [
            {"sequence": 1, "actor_label": "actor-A", "intent": "retain-added-item", "shared_user_id": user},
            {"sequence": 2, "actor_label": "actor-B", "intent": "clear-shared-cart", "shared_user_id": user},
        ],
        "ordered_client_results": [
            {
                "actor_label": "actor-A",
                "added_item": expected_item,
                "cart_after": added_items,
                "raw_response": actor_a["raw_response"],
                "raw_response_sha256": actor_a["raw_response_sha256"],
            },
            {
                "actor_label": "actor-B",
                "delete_status": actor_b.get("delete", {}).get("status"),
                "cart_after": client_b_items,
                "delete_raw_response": actor_b["delete"]["raw_response"],
                "delete_raw_response_sha256": actor_b["delete"]["raw_response_sha256"],
                "read_raw_response": actor_b["read"]["raw_response"],
                "read_raw_response_sha256": actor_b["read"]["raw_response_sha256"],
            },
        ],
        "host_cart_after": observed_items,
        "cart_identity_observations": {
            "empty_prestate": initial_identity,
            "actor_a_nonempty_readback": actor_a_identity,
            "actor_b_empty_readback": actor_b_identity,
            "host_empty_readback": observer_identity,
        },
        "actor_identity": "HARNESS_LABELS_ONLY_NOT_APPLICATION_AUTHENTICATION",
        "concurrency_claim": "SEQUENTIALLY_ORDERED_NOT_OVERLAP_TESTED",
        "runtime_qualification": "OBSERVATION_ONLY_NO_PRODUCT_AUTH_OR_CONCURRENCY_CLAIM",
    }


def run_shared_cart_overlap(state, directory, user, products, runner, http):
    """Observe overlapping client request windows for two updates to one cart."""
    initial_status, initial = http(
        state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    if initial_status != 200 or cart_items(initial, expected_user=user):
        raise ValueError("Shared-cart overlap requires a verified empty prestate; no actor ran.")
    if len(products) < 2 or products[0] == products[1]:
        raise ValueError("The catalogue did not provide two distinct products for the overlap case.")

    def source(actor, product):
        return (
            """const crypto = require('node:crypto');
const frontendOrigin = 'http://' + require('node:os').hostname() + ':' + process.env.PORT;
const userId = USER_ID;
const productId = PRODUCT_ID;
async function main() {
  const request_start_monotonic_ns = String(process.hrtime.bigint());
  const response = await fetch(frontendOrigin + '/api/cart?currencyCode=USD', {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({userId, item: {productId, quantity: 1}})
  });
  const raw_response = await response.text();
  const response_complete_monotonic_ns = String(process.hrtime.bigint());
  process.stdout.write(JSON.stringify({actor_label: ACTOR, intent: 'add-distinct-item', status: response.status,
    request_start_monotonic_ns, response_complete_monotonic_ns, raw_response,
    raw_response_sha256: crypto.createHash('sha256').update(raw_response).digest('hex')}) + '\\n');
}
main().catch(error => {
  const cause = error && error.cause ? `; cause=${String(error.cause)}` : '';
  console.error(`${String(error)}${cause}`);
  process.exitCode = 1;
});
""".replace("USER_ID", json.dumps(user))
            .replace("PRODUCT_ID", json.dumps(product))
            .replace("ACTOR", json.dumps(actor))
        )

    sources = [source("actor-A", products[0]), source("actor-B", products[1])]
    state["users"][user] = {"status": "DISPATCHED", "story": "shared-cart-overlap-diagnostic"}
    write_json(directory / "state.json", state)
    commands = [
        compose_args(state, ["exec", "-T", "frontend", FRONTEND_NODE, "-e", script]) for script in sources
    ]
    # Separate Compose execs provide two independent client processes. The
    # monotonic request windows, not thread start order, determine overlap.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(runner, command) for command in commands]
        actor_results = [json.loads(future.result()) for future in futures]
    actor_results.sort(key=lambda row: row.get("actor_label", ""))
    if [row.get("actor_label") for row in actor_results] != ["actor-A", "actor-B"]:
        raise RuntimeError("Concurrent shared-cart client identity is missing; state is unknown.")
    for row in actor_results:
        for key in ("request_start_monotonic_ns", "response_complete_monotonic_ns"):
            value = row.get(key)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,20}", value):
                raise RuntimeError("Concurrent shared-cart timing is missing or malformed; state is unknown.")
            row[key] = int(value)
        if hashlib.sha256(row.get("raw_response", "").encode()).hexdigest() != row.get("raw_response_sha256"):
            raise RuntimeError("Concurrent shared-cart response is unbound; state is unknown.")
        if row.get("status") != 200:
            raise RuntimeError("A concurrent shared-cart update failed; state is unknown.")
        try:
            client_response = json.loads(row.get("raw_response", ""))
            row["client_response_items"] = cart_items(client_response, expected_user=user)
            row["client_response_identity_status"] = cart_identity_status(client_response, user)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(
                "Concurrent shared-cart client response is malformed or stale; state is unknown."
            ) from error
        if any(item["product_id"] not in products for item in row["client_response_items"]):
            raise RuntimeError(
                "Concurrent shared-cart response contains an unrequested item; state is unknown."
            )

    observer_status, observer = http(
        state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    observed_items = cart_items(observer, expected_user=user) if observer_status == 200 else None
    expected = [
        {"product_id": products[0], "quantity": 1},
        {"product_id": products[1], "quantity": 1},
    ]
    final_product_ids = (
        {row["product_id"] for row in observed_items} if isinstance(observed_items, list) else set()
    )
    return {
        "story": "shared-cart-overlap-diagnostic",
        "project_id": state["project"],
        "synthetic_shopper_id": user,
        "cart_before": [],
        "cart_after": observed_items,
        "cart_HTTP_status": observer_status,
        "actor_intents": [
            {
                "sequence": index + 1,
                "actor_label": row["actor_label"],
                "intent": "add-distinct-item",
                "shared_user_id": user,
                "request_start_monotonic_ns": row["request_start_monotonic_ns"],
            }
            for index, row in enumerate(
                sorted(actor_results, key=lambda item: item["request_start_monotonic_ns"])
            )
        ],
        "concurrent_client_results": [
            {
                **row,
                "item": expected[index],
            }
            for index, row in enumerate(actor_results)
        ],
        "final_cart_observation": (
            "BOTH_ITEMS_RETAINED"
            if final_product_ids == set(products)
            else "ONE_UPDATE_NOT_PRESENT"
            if isinstance(observed_items, list) and final_product_ids.issubset(set(products))
            else "UNKNOWN"
        ),
        "cart_identity_observation": cart_identity_status(observer, user)
        if observer_status == 200
        else "UNKNOWN",
        "actor_identity": "HARNESS_LABELS_ONLY_NOT_APPLICATION_AUTHENTICATION",
        "concurrency_claim": "CLIENT_WINDOWS_MEASURED_SERVER_HANDLER_OVERLAP_NOT_ESTABLISHED",
        "runtime_qualification": "OBSERVATION_ONLY_NO_SERVER_CONCURRENCY_OR_AUTHORIZATION_CLAIM",
    }


def run_story(state, directory, user, fixture=None, http=request, runner=native):
    validate_user(user)
    if user in state["users"]:
        raise ValueError(
            "Shopper was already used. Replay requires a new synthetic ID, never a checkout retry."
        )
    story = state["story"]
    if STORIES[story]["action"] == "checkout":
        person = synthetic_fixture() if fixture is None else json.loads(fixture.read_bytes())
        if _RECORDER is not None:
            _RECORDER.set_redactions(
                [str(person.get("email", "")), str(person.get("creditCard", {}).get("creditCardNumber", ""))]
            )
        if set(person) != {"email", "address", "creditCard", "userCurrency"}:
            raise ValueError(
                "Fixture requires only email/address/creditCard/userCurrency; do not include userId."
            )
    state["last_user"] = user
    state["users"][user] = {"status": "STARTED"}
    write_json(directory / "state.json", state)
    status, products = http(state["http_port"], "GET", "/api/products?currencyCode=USD")
    if status != 200 or not isinstance(products, list) or not products:
        raise RuntimeError("Catalogue read failed; no fixture was added.")
    product = products[0]["id"]
    if STORIES[story]["action"] == "shared-cart":
        try:
            if len(products) < 2:
                raise ValueError("The catalogue did not provide two products for the shared-cart conflict.")
            product_ids = [products[0]["id"], products[1]["id"]]
            if story == "shared-cart-overlap-diagnostic":
                outcome = run_shared_cart_overlap(state, directory, user, product_ids, runner, http)
            else:
                outcome = run_shared_cart_conflict(state, directory, user, product_ids, runner, http)
        except Exception:
            status = state["users"][user].get("status")
            state["users"][user] = {
                "status": "UNKNOWN_AFTER_DISPATCH" if status == "DISPATCHED" else "NOT_RUN",
                "story": story,
            }
            write_json(directory / "state.json", state)
            raise
        outcome["assessment"] = assess_story(story, outcome)
        state["users"][user] = {
            "status": "OBSERVED" if outcome["assessment"]["passed"] else "UNKNOWN_AFTER_DISPATCH",
            "story": story,
        }
        write_json(directory / "state.json", state)
        write_json(directory / ("result-" + user + ".json"), outcome)
        if _RECORDER is not None:
            _RECORDER.result(outcome)
        if not outcome["assessment"]["passed"]:
            if story == "shared-cart-overlap-diagnostic":
                raise RuntimeError(
                    "Shared-cart overlap diagnostic failed a recorded identity/window/final-state predicate."
                )
            raise RuntimeError("The shared-cart ordering result did not match its expected behavior.")
        progress("Case complete: " + STORIES[story]["title"] + " behaved as described.")
        return outcome
    state["users"][user] = {"status": "SEED_DISPATCHED"}
    write_json(directory / "state.json", state)
    status, _ = http(
        state["http_port"],
        "POST",
        "/api/cart?currencyCode=USD",
        {"userId": user, "item": {"productId": product, "quantity": 1}},
    )
    if status != 200:
        raise RuntimeError("Cart-add outcome is unsuccessful or unknown; no retry was made.")
    before_status, before = http(
        state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    if before_status != 200:
        raise RuntimeError("Cart prestate read failed; no checkout was dispatched.")
    other_user = None
    if STORIES[story]["action"] == "mcp-cart":
        other_user = "shop-" + str(uuid.uuid4())
        validate_user(other_user)
        state["users"][other_user] = {"status": "STARTED", "story": story}
        write_json(directory / "state.json", state)
        try:
            if len(products) < 2 or products[0].get("id") == products[1].get("id"):
                raise ValueError(
                    "The public catalogue does not provide two distinct products for the isolation check."
                )
            primary_status, primary = http(
                state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
            )
            if primary_status != 200:
                raise RuntimeError("First synthetic actor's HTTP readback failed; MCP comparison is unknown.")
            primary_items = cart_items(primary, expected_user=user)
            source = """import asyncio,json
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
users = USER_IDS
product_id = PRODUCT_ID
async def normalized(result):
 items=[]
 for content in result.content:
  if hasattr(content,"text"):
   try:
    value=json.loads(content.text)
    items=value.get("items",[]) if isinstance(value,dict) else []
   except (ValueError,AttributeError): pass
 return [{"product_id":x.get("productId",x.get("product_id")),"quantity":x.get("quantity")} for x in items]
async def main():
 async with streamablehttp_client("http://127.0.0.1:8011/mcp") as (read,write,_):
  async with ClientSession(read,write) as session:
   await session.initialize()
   tools=await session.list_tools()
   names=[x.name for x in tools.tools]
   if "add_to_cart" not in names or "get_cart" not in names: raise RuntimeError("required tools unavailable")
   mutation=await session.call_tool("add_to_cart",{"user_id":users[1],"product_id":product_id,"quantity":1})
   mutation_items=await normalized(mutation)
   carts=[]
   for user in users:
    result=await session.call_tool("get_cart",{"user_id":user})
    carts.append({"user_id":user,"is_error":result.isError,"items":await normalized(result)})
   print(json.dumps({"initialized":True,"tool_names":names,"mutation_is_error":mutation.isError,"mutation_items":mutation_items,"carts":carts}))
asyncio.run(main())
""".replace("USER_IDS", json.dumps([user, other_user])).replace("PRODUCT_ID", json.dumps(products[1]["id"]))
            result = json.loads(runner(compose_args(state, ["exec", "-T", "mcp", "python", "-"]), source))
            if len(result.get("carts", [])) != 2 or [entry.get("user_id") for entry in result["carts"]] != [
                user,
                other_user,
            ]:
                raise RuntimeError("MCP cart reads did not return both requested synthetic actors in order.")
            other_status, other = http(
                state["http_port"], "GET", "/api/cart?sessionId=" + other_user + "&currencyCode=USD"
            )
            if other_status != 200:
                raise RuntimeError("MCP-mutated shopper HTTP readback failed; state is unknown.")
            other_items = cart_items(other, expected_user=other_user)
            mcp_carts = {
                entry["user_id"]: entry["items"]
                for entry in result["carts"]
                if entry.get("is_error") is False
            }
            http_carts = {user: primary_items, other_user: other_items}
            normalized_mcp = {actor: cart_items({"items": items}) for actor, items in mcp_carts.items()}
            projections_match = normalized_mcp == http_carts and len(normalized_mcp) == 2
            stateful_mutation_verified = (
                result.get("mutation_is_error") is False
                and other_items == [{"product_id": products[1]["id"], "quantity": 1}]
                and normalized_mcp.get(other_user) == other_items
            )
            actor_isolation_verified = (
                user != other_user
                and bool(primary_items)
                and bool(other_items)
                and primary_items != other_items
                and projections_match
                and stateful_mutation_verified
            )
            outcome = {
                "story": story,
                "project_id": state["project"],
                "cart_HTTP_status": min(before_status, primary_status, other_status),
                "MCP_initialized": result["initialized"],
                "MCP_stateful_tool": "add_to_cart",
                "MCP_stateful_mutation_verified": stateful_mutation_verified,
                "MCP_stateful_mutation_is_error": result.get("mutation_is_error"),
                "tool_error": len(mcp_carts) != 2 or result.get("mutation_is_error") is not False,
                "HTTP_cart": primary_items,
                "MCP_cart": normalized_mcp.get(user, []),
                "HTTP_carts_by_synthetic_actor": http_carts,
                "MCP_carts_by_synthetic_actor": normalized_mcp,
                "HTTP_cart_identity_by_actor": {
                    user: cart_identity_status(primary, user),
                    other_user: cart_identity_status(other, other_user),
                },
                "actor_isolation_verified": actor_isolation_verified,
                "projections_match": projections_match,
                "runtime_qualification": "OBSERVATION_ONLY_NOT_INDEPENDENT_EFFECT_PROOF",
            }
        except Exception:
            for actor in (user, other_user):
                state["users"][actor] = {"status": "UNKNOWN_AFTER_DISPATCH", "story": story}
            write_json(directory / "state.json", state)
            raise
    else:
        claim_checkout(directory / "checkout-claims", user)
        state["users"][user] = {"status": "UNKNOWN_AFTER_DISPATCH"}
        write_json(directory / "state.json", state)
        checkout_attempt_count = 0

        def dispatch(method, path, body):
            nonlocal checkout_attempt_count
            if is_checkout_dispatch(method, path):
                checkout_attempt_count += 1
            return http(state["http_port"], method, path, body)

        status, response = dispatch("POST", "/api/checkout?currencyCode=USD", {"userId": user, **person})
        after_status, after = http(
            state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
        )
        outcome = {
            "story": story,
            "project_id": state["project"],
            "synthetic_shopper_id": user,
            "checkout_attempt_count": checkout_attempt_count,
            "checkout_HTTP_status": status,
            "order_response_present": isinstance(response, dict) and bool(response.get("orderId")),
            "order_id": response.get("orderId") if isinstance(response, dict) else None,
            "cart_HTTP_status": after_status,
            "cart_before": cart_items(before, expected_user=user),
            "cart_after": cart_items(after, expected_user=user),
            "cart_before_identity_status": cart_identity_status(before, user),
            "cart_after_identity_status": cart_identity_status(after, user),
            "runtime_qualification": "OBSERVATION_ONLY_NO_SETTLEMENT_OR_RETRY_SAFETY_CLAIM",
        }
    outcome["assessment"] = assess_story(story, outcome)
    # A successful transport and an HTTP 200 read do not establish that the
    # observed state matches the selected case. Keep stale-but-well-formed
    # responses unobserved when the case assessment fails.
    settled = outcome["assessment"]["passed"] is True
    state["users"][user] = {"status": "OBSERVED" if settled else "UNKNOWN_AFTER_DISPATCH", "story": story}
    if other_user is not None:
        state["users"][other_user] = {
            "status": "OBSERVED" if settled else "UNKNOWN_AFTER_DISPATCH",
            "story": story,
        }
    write_json(directory / "state.json", state)
    write_json(directory / ("result-" + user + ".json"), outcome)
    if _RECORDER is not None:
        _RECORDER.result(outcome)
    if not outcome["assessment"]["passed"]:
        raise RuntimeError(
            "The case did not match its expected behavior. Its result is preserved; no purchase was retried."
        )
    progress("Case complete: " + STORIES[story]["title"] + " behaved as described.")
    return outcome


def synthetic_fixture():
    # Fictional public-demo data only; never use a real card or real personal data.
    return {
        "email": "shopper@example.test",
        "address": {
            "streetAddress": "1 Demo Way",
            "city": "Example City",
            "state": "CA",
            "country": "United States",
            "zipCode": "00000",
        },
        "userCurrency": "USD",
        "creditCard": {
            "creditCardNumber": "4111111111111111",
            "creditCardCvv": 123,
            "creditCardExpirationYear": dt.datetime.now(dt.UTC).year + 2,
            "creditCardExpirationMonth": 12,
        },
    }


def active_directory(base):
    pointer = base / "active.json"
    if not pointer.exists():
        return base
    relative = json.loads(pointer.read_bytes()).get("world", "")
    if not re.fullmatch(r"worlds/[0-9a-f]{32}", relative):
        raise ValueError("Active shop pointer is malformed.")
    return base / relative


def reserve_network(state, directory, runner=native):
    config_path = Path(state["config"])
    config = apply_runtime_profile(json.loads(config_path.read_bytes()))
    write_json(config_path, config)
    pending = [(key, network) for key, network in config["networks"].items() if not network.get("ipam")]
    if not pending:
        return
    context = state["docker_context"]
    raw = runner(["docker", "--context", context, "network", "ls", "--quiet"])
    identifiers = raw.split()
    if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in identifiers):
        raise ValueError("Docker returned an invalid network census.")
    occupied = []
    if identifiers:
        details = runner(
            [
                "docker",
                "--context",
                context,
                "network",
                "inspect",
                *identifiers,
                "--format",
                "{{json .IPAM.Config}}",
            ]
        )
        for line in details.splitlines():
            for item in json.loads(line or "[]") or []:
                subnet = item.get("Subnet")
                if subnet:
                    occupied.append(ipaddress.ip_network(subnet, strict=False))
    for key, network in pending:
        selected = next(
            (
                candidate
                for candidate in ipaddress.ip_network("10.240.0.0/12").subnets(new_prefix=24)
                if not any(
                    candidate.version == existing.version and candidate.overlaps(existing)
                    for existing in occupied
                )
            ),
            None,
        )
        if selected is None:
            raise ValueError("No free sample subnet was found. Existing networks were not changed.")
        progress("Preparing the " + key + " network without changing existing projects...")
        runner(
            [
                "docker",
                "--context",
                context,
                "network",
                "create",
                "--driver",
                "bridge",
                *(["--internal"] if network.get("internal") else []),
                "--subnet",
                str(selected),
                "--label",
                "com.docker.compose.project=" + state["project"],
                "--label",
                "com.docker.compose.network=" + key,
                network["name"],
            ]
        )
        network["ipam"] = {"driver": "default", "config": [{"subnet": str(selected)}]}
        occupied.append(selected)
        write_json(config_path, config)
        state["subnet" if key == "default" else key + "_subnet"] = str(selected)
        write_json(directory / "state.json", state)


def start_owned(state, directory, runner, http):
    verify_world(state, directory)
    snapshot_inputs(state, directory)
    images = load_image_lock(Path(state["images_lock"]), state["source_variant"])
    if hashlib.sha256(json.dumps(images, sort_keys=True).encode()).hexdigest() != state["images_sha256"]:
        raise ValueError(
            "Image mapping changed. Prepare a new shop rather than silently changing its source world."
        )
    if not state.get("started"):
        reserve_network(state, directory, runner)
        bind_world(state, directory)
        write_json(directory / "state.json", state)
        snapshot_inputs(state, directory)
        print("Starting your isolated shop; first-time image downloads can take a while...")
        runner(
            compose_args(
                state,
                [
                    "up",
                    "-d",
                    "--wait",
                    "--wait-timeout",
                    str(PROFILE["startup_wait_seconds"]),
                    "--no-build",
                    "--pull",
                    "never" if images["mcp"].startswith("sha256:") else "missing",
                    *CORE_SERVICES,
                ],
            )
        )
        state["started"] = True
        write_json(directory / "state.json", state)
    if runner is native:
        wait_ready(state, runner, http)
        snapshot_runtime(state, directory, runner)
    else:
        verify_health(state, runner, http)
    progress("Shop ready at http://127.0.0.1:" + str(state["http_port"]))
    if runner is native:
        from processes import start_watcher

        try:
            state["log_pid"] = start_watcher(state, directory, Path(state["evidence_root"]))
        finally:
            write_json(directory / "state.json", state)
            if _RECORDER is not None and state.get("watcher_diagnostics"):
                _RECORDER.artifact("Log companion startup diagnostics", Path(state["watcher_diagnostics"]))
    if _RECORDER is not None:
        _RECORDER.result(
            {
                "story": state["story"],
                "app_url": "http://127.0.0.1:" + str(state["http_port"]),
                "project": state["project"],
                "images_lock": state["images_lock"],
                "workspace": state["workspace"],
            }
        )


def agent_replay_summary_path(state, directory, evidence_root=None):
    """Return a fresh summary path; recorded artifacts must live under evidence root."""
    filename = "agent-replay-result.json"
    if evidence_root is None:
        path = Path(directory) / filename
        if path.exists() or path.is_symlink():
            raise FileExistsError("Agent replay summary already exists; refusing to overwrite it.")
        return path

    project = state.get("project")
    if not isinstance(project, str) or not re.fullmatch(r"shop-[0-9a-f]{12}", project):
        raise ValueError("Agent replay project identity is invalid.")
    root = Path(evidence_root).expanduser().resolve()
    replay_root = root / "agent-replay"
    if replay_root.is_symlink():
        raise ValueError("Agent replay evidence folder must not be a symlink.")
    replay_root.mkdir(exist_ok=True)
    if not replay_root.resolve().is_relative_to(root):
        raise ValueError("Agent replay evidence folder escapes the evidence root.")
    parent = replay_root / project
    if parent.exists() or parent.is_symlink():
        raise FileExistsError("Agent replay evidence folder already exists; refusing to overwrite it.")
    parent.mkdir(exist_ok=False)
    path = parent / filename
    if not path.resolve().is_relative_to(root):
        raise ValueError("Agent replay summary escapes the evidence root.")
    return path


AGENT_REPLAY_STAGES = {
    "world-start",
    "isolation-config",
    "agent-start",
    "container-boundary",
    "runtime-guard",
    "fixture-endpoint",
    "agent-stop",
    "evidence-artifact",
}

AGENT_RUNTIME_GUARD_CHECKS = {
    "imports",
    "vcr-version",
    "vcr-record-mode",
    "replay-only-flag",
    "llm-base-url",
    "dummy-api-key",
    "dummy-openai-key",
    "overlay-digest",
    "guard-response",
}


def agent_replay_failure_message(outcome, last_stage):
    """Produce a safe failure line from fixed fields only; never include payloads."""
    diagnostic = {"status": "UNKNOWN"}
    failure_stage = outcome.get("failure_stage")
    if isinstance(failure_stage, str) and failure_stage in AGENT_REPLAY_STAGES:
        diagnostic["failure_stage"] = failure_stage
    elif isinstance(last_stage, str) and last_stage in AGENT_REPLAY_STAGES:
        diagnostic["last_observed_stage"] = last_stage
    for field in ("error_type", "cleanup_error_type"):
        error_type = outcome.get(field)
        if isinstance(error_type, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", error_type):
            diagnostic[field] = error_type
    cleanup_stage = outcome.get("cleanup_failure_stage")
    if cleanup_stage == "agent-stop":
        diagnostic["cleanup_failure_stage"] = cleanup_stage
    guard_check = outcome.get("runtime_guard_check")
    if isinstance(guard_check, str) and guard_check in AGENT_RUNTIME_GUARD_CHECKS:
        diagnostic["runtime_guard_check"] = guard_check
    guard_error_type = outcome.get("runtime_guard_error_type")
    if isinstance(guard_error_type, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", guard_error_type):
        diagnostic["runtime_guard_error_type"] = guard_error_type
    if type(outcome.get("agent_stopped")) is bool:
        diagnostic["agent_stopped"] = outcome["agent_stopped"]
    return (
        "Agent cassette replay is UNKNOWN; no external model call or retry was allowed; diagnostic="
        + json.dumps(diagnostic, sort_keys=True, separators=(",", ":"))
    )


def agent_runtime_guard_failure(guard, expected_overlay_sha256):
    """Return only a fixed guard check and exception class; never echo guard output."""
    if not isinstance(guard, dict):
        return {"runtime_guard_check": "guard-response"}
    if guard.get("status") != "PASS":
        check = guard.get("failed_check")
        error_type = guard.get("error_type")
        failure = {"runtime_guard_check": check if check in AGENT_RUNTIME_GUARD_CHECKS else "guard-response"}
        if isinstance(error_type, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", error_type):
            failure["runtime_guard_error_type"] = error_type
        return failure
    if guard.get("vcrpy") != AGENT_VCRPY_VERSION:
        return {"runtime_guard_check": "vcr-version"}
    if guard.get("record_mode") != "none":
        return {"runtime_guard_check": "vcr-record-mode"}
    if guard.get("overlay_sha256") != expected_overlay_sha256:
        return {"runtime_guard_check": "overlay-digest"}
    return None


def run_agent_replay(state, directory, runner=native, http=request):
    """Exercise one pinned cassette with a dummy key, loopback endpoint and internal network."""
    if state.get("agent_replay_enabled") is not True:
        raise ValueError("Prepare this world with setup --agent-replay before requesting fixture replay.")
    stage = "world-start"

    def mark_stage(value):
        nonlocal stage
        stage = value
        if _RECORDER is not None:
            _RECORDER.phase("Agent replay stage observed", status="running", agent_replay_stage=value)

    mark_stage(stage)
    verify_world(state, directory)
    overlay = Path(state["agent_replay_overlay"])
    cassette = Path(state["agent_replay_cassette"])
    result_path = agent_replay_summary_path(
        state,
        directory,
        _RECORDER.root if _RECORDER is not None else None,
    )
    outcome = {
        "schema": "workflow-lab.agent-replay.v1",
        "status": "UNKNOWN",
        "source_commit": state["source_commit"],
        "compose_project": state["project"],
        "docker_context": state["docker_context"],
        "model": AGENT_REPLAY_MODEL,
        "prompt": "Show all available products in the store.",
        "cassette_name": AGENT_REPLAY_CASSETTE,
        "cassette_sha256": hashlib.sha256(cassette.read_bytes()).hexdigest(),
        "overlay_sha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
        "vcrpy_version": AGENT_VCRPY_VERSION,
        "record_mode": "none",
        "match_threshold": "1.0",
        "model_base_url": "http://127.0.0.1:9/v1 (unreachable loopback only)",
        "api_key": "dummy sentinel only",
        "network_policy": "agent attached only to project internal agent-replay bridge",
        "runtime_scope": "FIXTURE REPLAY; no live inference or business mutation intended",
        "live_inference": False,
    }
    successful = False
    agent_may_exist = False
    container_id = None
    try:
        if not state.get("started"):
            start_owned(state, directory, runner, http)
        mark_stage("isolation-config")
        config = json.loads(Path(state["config"]).read_bytes())
        expected_network = state["project"] + "_agent-replay"
        agent_service = config.get("services", {}).get("agent", {})
        if (
            config.get("networks", {}).get("agent-replay", {}).get("internal") is not True
            or agent_service.get("networks") != {"agent-replay": None}
            or not any(
                isinstance(mount, dict)
                and mount.get("target") == "/app/sitecustomize.py"
                and Path(mount.get("source", "")).resolve() == overlay.resolve()
                and mount.get("read_only") is True
                for mount in agent_service.get("volumes", [])
            )
            or agent_service.get("environment", {}).get("LLM_BASE_URL") != "http://127.0.0.1:9/v1"
            or agent_service.get("environment", {}).get("API_KEY") != "sk-dummy"
            or agent_service.get("environment", {}).get("OPENAI_API_KEY") != "sk-dummy"
        ):
            raise ValueError("Replay-only isolation/configuration is absent; no agent prompt was sent.")
        agent_may_exist = True
        mark_stage("agent-start")
        runner(
            compose_args(
                state,
                ["up", "-d", "--build", "--wait", "--wait-timeout", "90", "agent"],
            )
        )
        container_id = runner(compose_args(state, ["ps", "--quiet", "agent"])).strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise RuntimeError("Agent container identity is unavailable; no prompt was sent.")
        mark_stage("container-boundary")
        inspect_prefix = ["docker", "--context", state["docker_context"], "inspect", container_id]
        mounts = json.loads(runner([*inspect_prefix, "--format", "{{json .Mounts}}"]))
        port_bindings = json.loads(runner([*inspect_prefix, "--format", "{{json .HostConfig.PortBindings}}"]))
        networks = json.loads(runner([*inspect_prefix, "--format", "{{json .NetworkSettings.Networks}}"]))
        overlay_mount = next(
            (
                mount
                for mount in mounts
                if mount.get("Destination") == "/app/sitecustomize.py"
                and Path(mount.get("Source", "")).resolve() == overlay.resolve()
            ),
            None,
        )
        fixture_mount = next((mount for mount in mounts if mount.get("Destination") == "/app/fixtures"), None)
        if (
            not overlay_mount
            or overlay_mount.get("RW") is not False
            or not fixture_mount
            or fixture_mount.get("RW") is not False
            or port_bindings not in (None, {})
            or set(networks) != {expected_network}
        ):
            raise RuntimeError("Agent mount, port, or network boundary is unproven; no prompt was sent.")
        internal = runner(
            [
                "docker",
                "--context",
                state["docker_context"],
                "network",
                "inspect",
                expected_network,
                "--format",
                "{{.Internal}}",
            ]
        ).strip()
        if internal.lower() != "true":
            raise RuntimeError("Agent replay network is not Docker-internal; no prompt was sent.")
        mark_stage("runtime-guard")
        verify_script = r"""import hashlib,json,os
check='imports'
try:
 import vcr
 from src.agents.patch_vcr import VCR
 check='vcr-version'
 if vcr.__version__ != '8.3.0': raise RuntimeError
 check='vcr-record-mode'
 if VCR.record_mode.value != 'none': raise RuntimeError
 check='replay-only-flag'
 if os.environ.get('WORKFLOW_LAB_CASSETTE_REPLAY_ONLY') != '1': raise RuntimeError
 check='llm-base-url'
 if os.environ.get('LLM_BASE_URL') != 'http://127.0.0.1:9/v1': raise RuntimeError
 check='dummy-api-key'
 if os.environ.get('API_KEY') != 'sk-dummy': raise RuntimeError
 check='dummy-openai-key'
 if os.environ.get('OPENAI_API_KEY') != 'sk-dummy': raise RuntimeError
 check='overlay-digest'
 digest=hashlib.sha256(open('/app/sitecustomize.py','rb').read()).hexdigest()
 print(json.dumps({'status':'PASS','vcrpy':vcr.__version__,'record_mode':VCR.record_mode.value,'overlay_sha256':digest}))
except Exception as error:
 print(json.dumps({'status':'UNKNOWN','failed_check':check,'error_type':type(error).__name__}))"""
        outcome["runtime_guard_check"] = "guard-response"
        guard = json.loads(
            runner(compose_args(state, ["exec", "-T", "agent", "python", "-c", verify_script]))
        )
        guard_failure = agent_runtime_guard_failure(guard, outcome["overlay_sha256"])
        if guard_failure:
            outcome.update(guard_failure)
            raise RuntimeError("Agent replay runtime guard is UNKNOWN; no prompt was sent.")
        mark_stage("fixture-endpoint")
        request_script = r"""import hashlib,json,urllib.request
body=json.dumps({'message':'Show all available products in the store.','history':[]}).encode()
request=urllib.request.Request('http://127.0.0.1:8010/prompt',data=body,headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=120) as response:
 status=response.status
 payload=json.load(response)
messages=payload.get('response',{}).get('messages',[])
if status != 200 or not isinstance(messages,list):
 raise RuntimeError('agent endpoint response contract is unknown')
tool_names=[]
answers=[]
for message in messages:
 if not isinstance(message,dict): continue
 for call in message.get('tool_calls',[]) or []:
  if isinstance(call,dict):
   name=call.get('name') or call.get('function',{}).get('name')
   if isinstance(name,str): tool_names.append(name)
 if message.get('type') == 'tool' and isinstance(message.get('name'),str): tool_names.append(message['name'])
 if message.get('type') in ('ai','assistant') and isinstance(message.get('content'),str): answers.append(message['content'])
answer=answers[-1] if answers else ''
if 'list_products' not in tool_names or not answer:
 raise RuntimeError('fixture replay did not produce its expected read-only tool turn and answer')
print(json.dumps({'http_status':status,'tool_names':sorted(set(tool_names)),'message_count':len(messages),'answer_chars':len(answer),'answer_sha256':hashlib.sha256(answer.encode()).hexdigest()}))"""
        replay = json.loads(
            runner(compose_args(state, ["exec", "-T", "agent", "python", "-c", request_script]))
        )
        if replay.get("http_status") != 200 or "list_products" not in replay.get("tool_names", []):
            raise RuntimeError(
                "The bounded agent endpoint replay did not satisfy its read-only cassette contract."
            )
        outcome.update(replay, status="FIXTURE_REPLAY", agent_container_id=container_id)
        successful = True
    except Exception as error:
        # Keep endpoint failures actionable without copying arbitrary service or
        # request text into the public result record.
        outcome["error_type"] = type(error).__name__
        outcome["failure_stage"] = stage
    finally:
        if agent_may_exist:
            try:
                mark_stage("agent-stop")
            except Exception:
                # A failure to write the phase marker must not skip stopping an
                # agent container that may already exist.
                outcome["status"] = "UNKNOWN"
                outcome["cleanup_error_type"] = "ReplayStageEvidenceUnconfirmed"
                outcome["cleanup_failure_stage"] = "agent-stop"
                successful = False
            try:
                runner(compose_args(state, ["stop", "--timeout", "10", "agent"]))
                stopped = (
                    runner(
                        [
                            "docker",
                            "--context",
                            state["docker_context"],
                            "inspect",
                            container_id,
                            "--format",
                            "{{.State.Running}}",
                        ]
                    )
                    .strip()
                    .lower()
                    if isinstance(container_id, str)
                    else "unknown"
                )
                outcome["agent_stopped"] = stopped == "false"
                if not outcome["agent_stopped"]:
                    successful = False
            except (OSError, RuntimeError, subprocess.SubprocessError):
                outcome["agent_stopped"] = False
                outcome["cleanup_error_type"] = "AgentStopUnconfirmed"
                successful = False
            if not outcome.get("agent_stopped"):
                outcome["cleanup_failure_stage"] = "agent-stop"
        outcome["completed_utc"] = dt.datetime.now(dt.UTC).isoformat()
        write_json(result_path, outcome)
        if _RECORDER is not None:
            _RECORDER.result(outcome)
            try:
                _RECORDER.artifact("Public agent cassette replay summary", result_path)
            except Exception as error:
                outcome.update(
                    status="UNKNOWN",
                    error_type=type(error).__name__,
                    failure_stage="evidence-artifact",
                )
                write_json(result_path, outcome)
                _RECORDER.result(outcome)
                successful = False
    if not successful or outcome.get("agent_stopped") is not True:
        raise RuntimeError(agent_replay_failure_message(outcome, stage))
    return outcome


def stop_owned(state, directory, runner):
    verify_control_target(state, directory, runner)
    if runner is native and _RECORDER is not None:
        try:
            runner(compose_args(state, ["logs", "--no-color", "--timestamps", "--tail", "500"]))
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            _RECORDER.phase(
                "Final service-log snapshot was unavailable; earlier host logs remain preserved.",
                status="unknown",
                error=str(error),
            )
    runner(compose_args(state, ["stop", "--timeout", "30"]))
    if runner is native:
        from processes import stop_watcher

        stop_watcher(state, directory)
    state.pop("log_pid", None)
    state["started"] = False
    write_json(directory / "state.json", state)
    print("Your shop is stopped; its data and previous attempt records are retained.")


def dispatch_main(argv=None, runner=native, http=request):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=PUBLIC.parent / ".shop")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--no-browser", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser(
        "setup", help="Prepare public source and render configuration; no app starts."
    )
    setup.add_argument("--workspace", type=Path)
    setup.add_argument("--images", type=Path)
    setup.add_argument("--story", choices=STORIES, default="normal-checkout")
    setup.add_argument(
        "--agent-replay",
        action="store_true",
        help="Prepare the optional public agent service with a playback-only VCR overlay; no external model endpoint.",
    )
    setup.add_argument("--context")
    setup.add_argument("--offline-archive-from", type=Path)
    setup.add_argument("--allow-network-clone", action="store_true")
    setup.add_argument("--http-port", type=int, default=8080)
    setup.add_argument("--mcp-port", type=int, default=8011)
    names = ("normal", *STORIES)
    for name in ("start", "story"):
        command = commands.add_parser(name)
        command.add_argument("name", nargs="?", choices=names)
        if name == "story":
            command.add_argument("--user-id")
            command.add_argument("--fixture", type=Path)
    for command in ("stop", "clean", "view", "cases", "agent-replay"):
        commands.add_parser(command)
    for name in ("reset", "replay"):
        command = commands.add_parser(name)
        command.add_argument("--user-id")
        if name == "replay":
            command.add_argument("--fixture", type=Path)
    args = parser.parse_args(argv)
    base = args.state_dir.absolute()
    if args.command == "cases":
        for name, story in STORIES.items():
            print(name + ": " + story["description"])
        return 0
    if args.command == "view":
        import webbrowser

        target = (
            _RECORDER.root if _RECORDER is not None else (args.evidence_dir or PUBLIC.parent / "evidence")
        ) / "index.html"
        if not args.no_browser and not os.environ.get("CI"):
            webbrowser.open(target.resolve().as_uri())
        print("Run viewer: " + str(target))
        return 0
    if args.command == "clean":
        clean_worlds(base, runner)
        return 0
    directory = active_directory(base)
    state_path = directory / "state.json"
    state = json.loads(state_path.read_bytes()) if state_path.exists() else None
    if state and state.get("removed"):
        state = None
    if args.command == "setup":
        if state is not None:
            raise ValueError("This shop is already prepared. Use start or story to select a story.")
        directory = base
        state_path = directory / "state.json"
        variant = STORIES[args.story]["source_variant"]
        image_path = (args.images or (PUBLIC / "runtime-images.lock.json")).absolute()
        images = load_image_lock(image_path, "original", allow_pending=True)
        workspace = (args.workspace or PUBLIC.parent / "external/workspace" / variant).absolute()
        if not workspace.exists():
            print("Preparing pinned public source only...")
            acquire = [
                sys.executable,
                str(PUBLIC / "bootstrap_source.py"),
                "--no-runtime",
                "--materialize",
                "--variant",
                variant,
                "--destination",
                str(workspace),
            ]
            acquire += (
                ["--offline-archive-from", str(args.offline_archive_from)]
                if args.offline_archive_from
                else ["--allow-network-clone"]
            )
            runner(acquire)
        verify_source(workspace, variant)
        if (
            not all(1 <= x <= 65535 for x in (args.http_port, args.mcp_port))
            or args.http_port == args.mcp_port
        ):
            raise ValueError("Choose two distinct valid loopback ports.")
        context = args.context or runner(["docker", "context", "show"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context):
            raise ValueError("Docker context name is invalid.")
        engine = runner(["docker", "--context", context, "info", "--format", "{{.ID}}"]).strip()
        if not engine:
            raise ValueError("Docker engine identity is unavailable; no application was started.")
        if variant == "mcp-session-id":
            proof = build_public_mcp(directory, workspace, context, runner)
            images["mcp"] = proof["image_id"]
            derived = json.loads(image_path.read_bytes())
            derived.update(
                status="QUALIFIED", source_variant=variant, services=images, public_mcp_derivation=proof
            )
            image_path = directory / "runtime-images.lock.json"
            write_json(image_path, derived)
        project = "shop-" + uuid.uuid4().hex[:12]
        print("Rendering your shop without starting services...")
        rendered = json.loads(
            runner(
                [
                    "docker",
                    "--context",
                    context,
                    "compose",
                    "--project-name",
                    project,
                    "--project-directory",
                    str(workspace),
                    "--env-file",
                    str(workspace / ".env"),
                    "-f",
                    str(workspace / "compose.yaml"),
                    "-f",
                    str(workspace / "compose.agent.yaml"),
                    "config",
                    "--no-consistency",
                    "--format",
                    "json",
                ]
            )
        )
        flags = json.loads((workspace / "src/flagd/demo.flagd.json").read_bytes())
        for key in ("cartFailure", "paymentUnreachable"):
            value = STORIES[args.story][key]
            if value not in flags["flags"][key].get("variants", {}):
                raise ValueError("Selected story requests an unsupported upstream flag variant.")
            flags["flags"][key]["defaultVariant"] = value
        if "emitRawPii" in flags["flags"]:
            flags["flags"]["emitRawPii"]["defaultVariant"] = "off"
        write_json(directory / "flags/demo.flagd.json", flags)
        (directory / "flags").chmod(0o755)
        (directory / "flags/demo.flagd.json").chmod(0o644)  # Synthetic public flags, not private state.
        envoy_template = prepare_envoy(workspace, directory)
        telemetry = (
            (_RECORDER.root / "telemetry" / project) if _RECORDER is not None else directory / "telemetry"
        )
        telemetry.mkdir(parents=True, exist_ok=True)
        telemetry.chmod(0o777)  # Only this new, synthetic-data exporter directory.
        agent_overlay = None
        agent_cassette = None
        if args.agent_replay:
            upstream_agent = workspace / "src/agent/src/agents/patch_vcr.py"
            agent_cassette = workspace / "src/agent/fixtures/vcr_cassettes" / AGENT_REPLAY_CASSETTE
            if not upstream_agent.is_file() or not agent_cassette.is_file():
                raise ValueError(
                    "Pinned public agent replay source or cassette is missing; no agent was started."
                )
            if hashlib.sha256(upstream_agent.read_bytes()).hexdigest() != AGENT_PATCH_VCR_SHA256:
                raise ValueError("Pinned upstream VCR source changed; replay overlay was not prepared.")
            if hashlib.sha256(agent_cassette.read_bytes()).hexdigest() != AGENT_CASSETTE_SHA256:
                raise ValueError("Pinned public cassette changed; replay was not prepared.")
            agent_overlay = directory / "agent-replay" / "sitecustomize.py"
            agent_overlay.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(AGENT_REPLAY_OVERLAY, agent_overlay)
            agent_overlay.chmod(0o644)
        write_json(
            directory / "compose.json",
            scoped_config(
                rendered,
                images,
                project,
                directory / "flags",
                args.http_port,
                args.mcp_port,
                envoy_template,
                telemetry,
                agent_replay=args.agent_replay,
                agent_overlay=agent_overlay,
            ),
        )
        verify_bind_sources(json.loads((directory / "compose.json").read_bytes()))
        runner(
            [
                "docker",
                "--context",
                context,
                "compose",
                "--project-name",
                project,
                "-f",
                str(directory / "compose.json"),
                "config",
                "--quiet",
            ]
        )
        state = {
            "engine_id": engine,
            "evidence_root": str(_RECORDER.root)
            if _RECORDER is not None
            else str(PUBLIC.parent / "evidence"),
            "schema": "workflow-shop.v1",
            "project": project,
            "config": str(directory / "compose.json"),
            "story": args.story,
            "source_variant": variant,
            "source_commit": SOURCE_COMMIT,
            "http_port": args.http_port,
            "mcp_port": args.mcp_port,
            "users": {},
            "started": False,
            "docker_context": context,
            "workspace": str(workspace),
            "telemetry_directory": str(telemetry),
            "images_lock": str(image_path),
            "base_images_lock": str((args.images or PUBLIC / "runtime-images.lock.json").absolute()),
            "images_sha256": hashlib.sha256(json.dumps(images, sort_keys=True).encode()).hexdigest(),
            "agent_replay_enabled": args.agent_replay,
            "agent_replay_overlay": str(agent_overlay) if agent_overlay else None,
            "agent_replay_cassette": str(agent_cassette) if agent_cassette else None,
        }
        bind_world(state, directory)
        write_json(state_path, state)
        print("Setup complete. No app was started. Next: shop start.")
        return 0
    requested = getattr(args, "name", None)
    if requested == "normal":
        requested = "normal-checkout"
    selected = requested or (state["story"] if state else "normal-checkout")
    if args.command in ("start", "story", "replay", "reset") and (
        state is None or requested and requested != state["story"] or args.command in ("replay", "reset")
    ):
        # Every explicit replay gets a fresh project and shopper. Never dispatch an old claim again.
        if args.command == "replay" and args.user_id and state and args.user_id in state["users"]:
            raise ValueError(
                "Replay requires a fresh synthetic shopper; old checkout intent is never retried."
            )
        relative = "worlds/" + uuid.uuid4().hex
        new_directory = base / relative
        setup_args = ["--state-dir", str(new_directory), "setup", "--story", selected]
        if state:
            setup_args += [
                "--context",
                state["docker_context"],
                "--http-port",
                str(state["http_port"]),
                "--mcp-port",
                str(state["mcp_port"]),
            ]
            if state["source_variant"] == STORIES[selected]["source_variant"]:
                setup_args += [
                    "--workspace",
                    state["workspace"],
                    "--images",
                    state.get("base_images_lock", str(PUBLIC / "runtime-images.lock.json")),
                ]
        main(setup_args, runner, http)
        if state:
            # Failed health must not prevent a fresh owned reset.
            # A new project is the replay boundary; prior attempts stay untouched.
            stop_owned(state, directory, runner)
        write_json(base / "active.json", {"world": relative})
        directory = new_directory
        state_path = directory / "state.json"
        state = json.loads(state_path.read_bytes())
        if args.command == "replay":
            print("Fresh replay prepared. Previous uncertain attempts and data remain preserved.")
    if state is None:
        if args.command == "stop":
            progress("There is no active shop to stop. Your evidence is retained.")
            return 0
        raise ValueError("No shop is prepared yet. Run shop start normal.")
    compose_args(state, [])
    if args.command == "start":
        start_owned(state, directory, runner, http)
    elif args.command == "stop":
        stop_owned(state, directory, runner)
    elif args.command == "agent-replay":
        print(json.dumps(run_agent_replay(state, directory, runner), indent=2))
    elif args.command == "reset":
        start_owned(state, directory, runner, http)
        progress("Reset complete: a clean shop is ready; previous attempts remain preserved.")
    else:
        start_owned(state, directory, runner, http)
        verify_health(state, runner, http)
        print(STORIES[state["story"]]["description"])
        user = args.user_id or "shop-" + str(uuid.uuid4())
        print(json.dumps(run_story(state, directory, user, args.fixture, http, runner), indent=2))
    return 0


def clean_worlds(base, runner=native):
    paths = [base / "state.json", *sorted((base / "worlds").glob("*/state.json"))]
    removed = 0
    for path in paths:
        if not path.is_file():
            continue
        directory = path.parent
        if not directory.resolve().is_relative_to(base.resolve()):
            raise ValueError("A shop record escapes the selected state folder.")
        state = json.loads(path.read_bytes())
        compose_args(state, [])
        if state.get("removed"):
            continue
        config = Path(state["config"]).resolve()
        if config != (directory / "compose.json").resolve():
            raise ValueError("Shop cleanup refused a configuration outside its recorded world.")
        rendered = json.loads(config.read_bytes())
        resources = [*rendered.get("volumes", {}).values(), *rendered.get("networks", {}).values()]
        if rendered.get("name") != state["project"] or any(
            v.get("external") or not str(v.get("name", "")).startswith(state["project"] + "_")
            for v in resources
        ):
            raise ValueError("Shop cleanup refused resources outside its own namespace.")
        stop_owned(state, directory, runner)
        verify_control_target(state, directory, runner)
        runner(compose_args(state, ["down", "--volumes", "--remove-orphans"]))
        state["removed"] = True
        write_json(path, state)
        removed += 1
    progress("Cleanup complete: " + str(removed) + " recorded shops removed. Host evidence is untouched.")


def main(argv=None, runner=native, http=request):
    global _RECORDER
    actual = list(sys.argv[1:] if argv is None else argv)
    outer = runner is native and _RECORDER is None and not any(x in actual for x in ("--help", "-h"))
    if outer:
        from evidence import EvidenceRecorder

        pre = argparse.ArgumentParser(add_help=False)
        pre.add_argument("--state-dir", type=Path, default=PUBLIC.parent / ".shop")
        pre.add_argument("--evidence-dir", type=Path)
        pre.add_argument("--no-browser", action="store_true")
        known, _ = pre.parse_known_args(actual)
        saved = {}
        try:
            saved = json.loads((active_directory(known.state_dir.absolute()) / "state.json").read_bytes())
        except (OSError, ValueError):
            pass
        folder = known.evidence_dir or Path(saved.get("evidence_root", PUBLIC.parent / "evidence"))
        story = next((x for x in actual if x in STORIES), saved.get("story", "normal-checkout"))
        command = next(
            (
                x
                for x in actual
                if x in ("setup", "start", "story", "reset", "replay", "stop", "clean", "view", "cases")
            ),
            "help",
        )
        _RECORDER = EvidenceRecorder(
            folder,
            command,
            STORIES.get(story, {}).get("title", story),
            open_browser=not known.no_browser and not os.environ.get("CI") and command != "cases",
        )
        fixture = synthetic_fixture()
        _RECORDER.set_redactions([fixture["email"], fixture["creditCard"]["creditCardNumber"]])
        _RECORDER.phase("Starting " + command + ". Evidence is stored on the host, outside Docker.")
    try:
        result = dispatch_main(actual, runner, http)
        if outer:
            _RECORDER.finish("passed" if result == 0 else "failed")
        return result
    except BaseException as error:
        if outer:
            _RECORDER.finish("failed", str(error))
        raise
    finally:
        if outer:
            print("Evidence: " + str(_RECORDER.index_path), flush=True)
            _RECORDER = None


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print("Shop could not complete this step: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
