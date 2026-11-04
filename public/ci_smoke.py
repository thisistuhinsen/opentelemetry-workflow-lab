"""Exercise the public case catalog through the launcher; retain host evidence.

This script is intended for an isolated Linux CI runner. It never prunes Docker
or removes resources directly: stop/clean use the launcher's recorded namespaces.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

PUBLIC = Path(__file__).resolve().parent
ROOT = PUBLIC.parent
if str(PUBLIC) not in sys.path:
    sys.path.insert(0, str(PUBLIC))
import shop as shop_app  # noqa: E402


def timestamp():
    return dt.datetime.now(dt.UTC).isoformat()


def safe_failure_detail(value, limit=240):
    """Bound and redact a single already-redacted CLI error for CI logs."""
    if not isinstance(value, str) or not value.strip():
        return "detail unavailable; inspect the retained evidence artifact"
    detail = " ".join(value.split())
    detail = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", detail)
    detail = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", detail)
    detail = re.sub(r"(?i)\b(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[credentials]@", detail)
    detail = re.sub(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", "[email]", detail)
    detail = re.sub(
        r"\bshop-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        "[shopper]",
        detail,
    )
    detail = re.sub(r"\bshop-[0-9a-f]{12}\b", "[project]", detail)
    detail = re.sub(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", "[number]", detail)
    detail = re.sub(
        r"(?i)\b(authorization|password|token|secret)\s*[:=]\s*(?:(?:bearer|basic)\s+)?\S+",
        r"\1=[redacted]",
        detail,
    )
    detail = re.sub(
        r"(?i)\b(?:gh[pousr]_|github_pat_|sk-|AIza|ya29\.)[A-Za-z0-9_.-]{16,}\b",
        "[credential]",
        detail,
    )
    detail = re.sub(r"\s+", " ", detail).strip()
    return detail[:limit]


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_binding(root, path):
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Evidence inventory refuses redirected files.")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": path.relative_to(root).as_posix(), "bytes": size, "sha256": digest.hexdigest()}


def closed_primary_inventory(evidence):
    """Freeze closed primary runs, never the live companion or shared viewer."""
    files, excluded = [], []
    for path in sorted((evidence / "runs").glob("*/run.json")):
        record = read_json(path)
        if (
            record.get("command") == "Live service logs"
            or record.get("status") == "running"
            or not record.get("finished_at")
        ):
            excluded.append(path.relative_to(evidence).as_posix())
            continue
        if any(command.get("status") == "running" for command in record.get("commands", [])):
            raise RuntimeError("A closed primary run still has an active native command.")
        # Include native logs and any captured input/result files in this closed
        # run; telemetry, index.html, and CI cleanup logs live outside it.
        files.extend(
            file_binding(evidence, item) for item in sorted(path.parent.rglob("*")) if item.is_file()
        )
    return {"files": files, "excluded_active_or_companion_runs": excluded}


def _unique_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate OTLP JSON field.")
        value[key] = item
    return value


def _otlp_attributes(rows):
    """Read a tiny allowlist of string/bool attributes; never copy arbitrary PII."""
    if not isinstance(rows, list):
        raise ValueError("Malformed OTLP span attributes.")
    values = {}
    allowed = {"user.id", "demo.order.id", "demo.payment.charged"}
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise ValueError("Malformed OTLP span attribute.")
        key = item["key"]
        if key not in allowed:
            continue
        if key in values:
            raise ValueError("Duplicate allowlisted OTLP span attribute.")
        value = item.get("value")
        if not isinstance(value, dict):
            raise ValueError("Malformed allowlisted OTLP span attribute value.")
        if key == "demo.payment.charged":
            if type(value.get("boolValue")) is not bool:
                raise ValueError("Malformed payment-charged OTLP attribute.")
            values[key] = value["boolValue"]
        else:
            text = value.get("stringValue")
            if not isinstance(text, str) or not text:
                raise ValueError("Malformed identity OTLP attribute.")
            values[key] = text
    return values


def parse_otlp_traces(path):
    """Validate actual file-exporter envelopes, not debug text or log records."""
    counts = {}
    checkout_error_users = set()
    boundary_spans = []
    lines = 0
    with path.open("r", encoding="utf-8", errors="strict") as stream:
        for line in stream:
            lines += 1
            record = json.loads(line, object_pairs_hook=_unique_json)
            resources = record.get("resourceSpans") if isinstance(record, dict) else None
            if not isinstance(resources, list) or not resources:
                raise ValueError("Missing nonempty OTLP resourceSpans.")
            for resource in resources:
                if not isinstance(resource, dict):
                    raise ValueError("Malformed OTLP resource.")
                metadata = resource.get("resource")
                if not isinstance(metadata, dict):
                    raise ValueError("Missing OTLP resource metadata.")
                attributes = metadata.get("attributes", [])
                if not isinstance(attributes, list) or any(not isinstance(item, dict) for item in attributes):
                    raise ValueError("Malformed OTLP resource attributes.")
                service_attributes = [item for item in attributes if item.get("key") == "service.name"]
                if len(service_attributes) != 1 or not isinstance(service_attributes[0].get("value"), dict):
                    raise ValueError("OTLP resource requires exactly one service.name attribute.")
                names = [service_attributes[0]["value"].get("stringValue")]
                if len(names) != 1 or not isinstance(names[0], str) or not names[0].strip():
                    raise ValueError("OTLP resource requires exactly one service.name.")
                scopes = resource.get("scopeSpans")
                if not isinstance(scopes, list) or not scopes:
                    raise ValueError("Missing nonempty OTLP scopeSpans.")
                for scope in scopes:
                    spans = scope.get("spans") if isinstance(scope, dict) else None
                    if not isinstance(spans, list) or not spans:
                        raise ValueError("Missing nonempty OTLP spans.")
                    for span in spans:
                        if (
                            not isinstance(span, dict)
                            or not isinstance(span.get("name"), str)
                            or not span["name"].strip()
                        ):
                            raise ValueError("Malformed OTLP span name.")
                        for key, length in (("traceId", 32), ("spanId", 16)):
                            identifier = span.get(key)
                            if (
                                not isinstance(identifier, str)
                                or not re.fullmatch(r"[0-9a-fA-F]{" + str(length) + "}", identifier)
                                or int(identifier, 16) == 0
                            ):
                                raise ValueError("Malformed OTLP span identity.")
                        start, end = span.get("startTimeUnixNano"), span.get("endTimeUnixNano")
                        if any(
                            type(value) not in (int, str) or not re.fullmatch(r"[0-9]+", str(value))
                            for value in (start, end)
                        ):
                            raise ValueError("Malformed OTLP span timestamps.")
                        if not 0 < int(start) <= int(end) < 2**64:
                            raise ValueError("Invalid OTLP span timestamp order.")
                        counts[names[0]] = counts.get(names[0], 0) + 1
                        safe_attributes = _otlp_attributes(span.get("attributes", []))
                        events = span.get("events", [])
                        if not isinstance(events, list) or any(
                            not isinstance(event, dict) or not isinstance(event.get("name"), str)
                            for event in events
                        ):
                            raise ValueError("Malformed OTLP span events.")
                        if names[0] in ("checkout", "payment", "email"):
                            boundary_spans.append(
                                {
                                    "service": names[0],
                                    "trace_id": span["traceId"].lower(),
                                    "email_send_span": names[0] == "email" and span["name"] == "send_email",
                                    "user_id": safe_attributes.get("user.id"),
                                    "order_id": safe_attributes.get("demo.order.id"),
                                    "payment_charged": safe_attributes.get("demo.payment.charged"),
                                }
                            )
                        if names[0] == "checkout":
                            status = span.get("status")
                            attributes = span.get("attributes", [])
                            matching_users = [
                                item.get("value", {}).get("stringValue")
                                for item in attributes
                                if isinstance(item, dict)
                                and item.get("key") == "user.id"
                                and isinstance(item.get("value"), dict)
                            ]
                            if (
                                isinstance(status, dict)
                                and type(status.get("code")) is int
                                and status["code"] == 2
                                and len(matching_users) == 1
                                and isinstance(matching_users[0], str)
                                and matching_users[0].strip()
                            ):
                                checkout_error_users.add(matching_users[0])
    if not lines or not counts:
        raise ValueError("No exported OTLP spans.")
    return {
        "observed_span_count": sum(counts.values()),
        "service_counts": dict(sorted(counts.items())),
        "checkout_error_user_ids": sorted(checkout_error_users),
        "boundary_spans": boundary_spans,
        "jsonl_lines": lines,
    }


def simulated_boundary_observation(trace_inventory, browser_result):
    """Join allowlisted demo spans to one browser order without claiming real-world effects."""
    user = browser_result.get("synthetic_shopper_id")
    order_id = browser_result.get("order_id")
    project = browser_result.get("project_id")
    if not all(isinstance(value, str) and value for value in (user, order_id, project)):
        return {"status": "UNKNOWN", "reason": "browser-order-binding-missing"}
    if (
        trace_inventory.get("project") != project
        or trace_inventory.get("status") != "OBSERVED_EXPORTED_SPANS"
    ):
        return {"status": "UNKNOWN", "reason": "trace-project-unavailable-or-invalid"}
    spans = trace_inventory.get("boundary_spans")
    if not isinstance(spans, list):
        return {"status": "UNKNOWN", "reason": "trace-boundary-spans-unavailable"}
    checkout = [
        span
        for span in spans
        if span.get("service") == "checkout"
        and span.get("user_id") == user
        and span.get("order_id") == order_id
    ]
    if len(checkout) != 1:
        return {"status": "UNKNOWN", "reason": "checkout-order-span-not-unique"}
    trace_id = checkout[0].get("trace_id")
    payment = [
        span
        for span in spans
        if span.get("service") == "payment"
        and span.get("trace_id") == trace_id
        and span.get("payment_charged") is True
    ]
    email = [
        span
        for span in spans
        if span.get("service") == "email"
        and span.get("trace_id") == trace_id
        and span.get("email_send_span") is True
        and span.get("order_id") == order_id
    ]
    return {
        "status": "OBSERVED" if len(payment) == 1 and len(email) == 1 else "UNKNOWN",
        "synthetic_shopper_id": user,
        "order_id": order_id,
        "trace_id": trace_id,
        "checkout_span_count": len(checkout),
        "payment_charged_span_count": len(payment),
        "email_order_span_count": len(email),
        "email_send_span_count": len(email),
        "basis": "ALLOWLISTED_PINNED_DEMO_OTEL_SERVICE_SPANS; NOT AN INDEPENDENT JOURNAL, SETTLEMENT, OR EMAIL-DELIVERY PROOF",
    }


def payment_story_observations(evidence, project, story_results):
    observations = []
    recorded_paths = set()
    for action in story_results:
        if action.get("story") != "payment-unreachable" or action.get("project_id") != project:
            continue
        run_relative = Path(action.get("run", ""))
        if run_relative.is_absolute() or not run_relative.parts or ".." in run_relative.parts:
            raise ValueError("Payment-unavailable action has an unsafe run reference.")
        run_path = evidence / run_relative
        result_path = run_path.parent / "result.json"
        run_file = file_binding(evidence, run_path)
        result_file = file_binding(evidence, result_path)
        if run_file["sha256"] != action.get("run_sha256") or result_file["sha256"] != action.get(
            "result_sha256"
        ):
            raise ValueError("Payment-unavailable action no longer matches its recorded result hashes.")
        recorded_paths.add(result_path.resolve())
        result = read_json(result_path)
        before = result.get("cart_before")
        after = result.get("cart_after")
        shopper = result.get("synthetic_shopper_id")
        item_is_single_demo_item = (
            isinstance(before, list)
            and len(before) == 1
            and isinstance(before[0], dict)
            and isinstance(before[0].get("product_id"), str)
            and bool(before[0]["product_id"])
            and type(before[0].get("quantity")) is int
            and before[0]["quantity"] == 1
        )
        valid = (
            isinstance(shopper, str)
            and re.fullmatch(
                r"shop-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", shopper
            )
            and result.get("project_id") == project
            and result.get("story") == "payment-unreachable"
            and action.get("synthetic_shopper_id") == shopper
            and type(action.get("checkout_attempt_count")) is int
            and action["checkout_attempt_count"] == 1
            and type(result.get("checkout_attempt_count")) is int
            and result["checkout_attempt_count"] == 1
            and type(result.get("checkout_HTTP_status")) is int
            and 400 <= result["checkout_HTTP_status"] <= 599
            and result.get("order_response_present") is False
            and type(result.get("cart_HTTP_status")) is int
            and result["cart_HTTP_status"] == 200
            and item_is_single_demo_item
            and before == after
            and result.get("assessment", {}).get("passed") is True
        )
        if not valid:
            raise ValueError(
                "Payment-unavailable result lacks the one-attempt, error, no-order and cart-readback contract."
            )
        observations.append({"synthetic_shopper_id": shopper})
    for path in sorted((evidence / "runs").glob("*/result.json")):
        result = read_json(path)
        if result.get("project_id") == project and result.get("story") == "payment-unreachable":
            if path.resolve() not in recorded_paths:
                raise ValueError("Payment-unavailable result is absent from the campaign's action record.")
    return observations


def telemetry_inventory(evidence, projects):
    records, files = [], []
    for context, project in projects:
        directory = evidence / "telemetry" / project
        path = directory / "traces.jsonl"
        row = {"project": project, "docker_context": context, "status": "UNKNOWN"}
        try:
            row.update(file_binding(evidence, path))
            row.update(parse_otlp_traces(path))
            row["status"] = "OBSERVED_EXPORTED_SPANS"
            campaign_path = evidence / "ci" / "campaign.json"
            campaign = read_json(campaign_path) if campaign_path.is_file() else {}
            browser_result = campaign.get("browser_checkout") if isinstance(campaign, dict) else None
            if isinstance(browser_result, dict) and browser_result.get("project_id") == project:
                boundary = simulated_boundary_observation(row, browser_result)
                row["browser_simulated_boundary_observation"] = boundary
                if boundary["status"] != "OBSERVED":
                    raise ValueError("Browser checkout lacks matching simulated payment/order/email spans.")
            story_results = campaign.get("story_results", [])
            if not isinstance(story_results, list):
                raise ValueError("Campaign story-results record is malformed.")
            payment_observations = payment_story_observations(evidence, project, story_results)
            checkout_error_users = set(row["checkout_error_user_ids"])
            row["payment_unavailable_observations"] = [
                {
                    "synthetic_shopper_id": item["synthetic_shopper_id"],
                    "direct_error_response_and_cart_readback": True,
                    "one_checkout_dispatch_recorded": True,
                    "matching_checkout_error_span_observed": item["synthetic_shopper_id"]
                    in checkout_error_users,
                    "basis": "synthetic API response and cart readback joined to a positive checkout OTel error span; no settlement claim",
                }
                for item in payment_observations
            ]
            if any(
                not item["matching_checkout_error_span_observed"]
                for item in row["payment_unavailable_observations"]
            ):
                raise ValueError("Payment-unavailable result has no matching positive checkout error span.")
            row["status"] = "OBSERVED_EXPORTED_SPANS"
        except (OSError, ValueError, TypeError, AttributeError, OverflowError):
            row["status"] = "UNKNOWN"
            row["error"] = "Missing or invalid trace/result binding; no telemetry qualification."
        records.append(row)
        if directory.exists():
            files.extend(
                file_binding(evidence, item) for item in sorted(directory.rglob("*")) if item.is_file()
            )
    return {
        "status": "PASS"
        if records and all(row["status"] == "OBSERVED_EXPORTED_SPANS" for row in records)
        else "NO_RECORDED_PROJECTS"
        if not records
        else "FAILED",
        "projects": records,
        "files": files,
        "basis": "stopped file-exporter JSONL; debug logs are not substitutes",
    }


def scan_runtime_privacy(evidence):
    """Inspect persisted bytes and JSON ASCII escapes, with no raw-value output."""
    needles = {"default_pan": b"4111111111111111", "default_email": b"shopper@example.test"}
    scanned, excluded, violations, errors = 0, [], [], []
    for path in sorted(evidence.rglob("*")):
        relative = path.relative_to(evidence)
        # Launcher source is represented by hashes, not copied bodies. No
        # directory name can exempt runtime bytes from the upload scan.
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(evidence.resolve()):
                raise ValueError("Redirected evidence")
            if not path.is_file():
                continue
            scanned += 1
            found = {
                label
                for label, needle in needles.items()
                if needle in relative.as_posix().encode("utf-8").lower()
            }
            carry = b""
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    combined = carry + chunk
                    normalized = re.sub(
                        rb"\\u00([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]), combined
                    ).lower()
                    found.update(label for label, needle in needles.items() if needle in normalized)
                    carry = combined[-256:]
            if found:
                violations.append({"path": relative.as_posix(), "sentinels": sorted(found)})
        except (OSError, ValueError):
            errors.append(relative.as_posix())
    return {
        "status": "PASS_DEFAULT_SENTINELS" if not violations and not errors else "FAILED",
        "scanned_files": scanned,
        "files_with_matches": len(violations),
        "violations": violations,
        "unreadable_or_redirected": errors,
        "excluded_tool_source_files": excluded,
        "scope": "default synthetic PAN/email in persisted bytes and JSON ASCII escapes; no general PII guarantee",
    }


def privacy_check(evidence):
    result = scan_runtime_privacy(evidence)
    write_json(evidence / "ci" / "privacy-final.json", result)
    summary = {
        "status": result["status"],
        "scanned_files": result["scanned_files"],
        "files_with_matches": result["files_with_matches"],
        "unreadable_files": len(result["unreadable_or_redirected"]),
        "excluded_tool_source_files": len(result["excluded_tool_source_files"]),
        "scope": "Default synthetic PAN/email sentinel scan only; not general PII certification.",
    }
    write_json(evidence / "ci" / "privacy-summary.json", summary)
    allowed = result["status"] == "PASS_DEFAULT_SENTINELS"
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
            stream.write("allowed=" + ("true" if allowed else "false") + "\n")
    return 0 if allowed else 1


def agent_vcr_self_test():
    """Prove the overlay forces VCR none and an HTTPX cassette miss is rejected."""
    import importlib.util

    try:
        import httpx
        import vcr
    except ImportError:
        print("Agent replay guard test requires pinned vcrpy and httpx packages.", file=sys.stderr)
        return 2
    overlay = PUBLIC / "agent-replay" / "sitecustomize.py"
    original_vcr = vcr.VCR
    prior_guard = os.environ.get("WORKFLOW_LAB_CASSETTE_REPLAY_ONLY")
    try:
        os.environ.pop("WORKFLOW_LAB_CASSETTE_REPLAY_ONLY", None)
        blocked_spec = importlib.util.spec_from_file_location(
            "workflow_lab_agent_replay_overlay_unset", overlay
        )
        if blocked_spec is None or blocked_spec.loader is None:
            raise RuntimeError("Replay overlay cannot be loaded for its unset-guard check.")
        blocked_module = importlib.util.module_from_spec(blocked_spec)
        try:
            blocked_spec.loader.exec_module(blocked_module)
        except RuntimeError as error:
            if str(error) != "The Workflow Lab agent overlay is valid only for explicit cassette replay.":
                raise
        else:
            raise RuntimeError("The replay overlay loaded without explicit replay authorization.")
        os.environ["WORKFLOW_LAB_CASSETTE_REPLAY_ONLY"] = "1"
        spec = importlib.util.spec_from_file_location("workflow_lab_agent_replay_overlay", overlay)
        if spec is None or spec.loader is None:
            raise RuntimeError("Replay overlay cannot be loaded.")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if vcr.VCR is original_vcr:
            raise RuntimeError("Replay overlay did not replace the upstream VCR constructor.")
        with tempfile.TemporaryDirectory() as temporary:
            cassette = Path(temporary) / "must-not-be-created.yaml"
            client_vcr = vcr.VCR(cassette_library_dir=temporary, record_mode="new_episodes")
            if client_vcr.record_mode.value != "none":
                raise RuntimeError("The replay overlay did not force record_mode=none.")

            async def cassette_miss():
                with client_vcr.use_cassette(cassette.name):
                    async with httpx.AsyncClient(timeout=2.0) as client:
                        await client.post(
                            "http://127.0.0.1:9/v1/chat/completions",
                            json={"model": "offline-test", "messages": [{"role": "user", "content": "miss"}]},
                        )

            try:
                asyncio.run(cassette_miss())
            except vcr.errors.CannotOverwriteExistingCassetteException:
                pass
            else:
                raise RuntimeError(
                    "An unmatched HTTPX request was not rejected by cassette playback-only mode."
                )
            if cassette.exists():
                raise RuntimeError("A cassette miss wrote a new episode.")
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "vcrpy_version": vcr.__version__,
                    "record_mode": "none",
                    "transport": "HTTPX async client",
                    "cassette_miss": "rejected before network response",
                    "cassette_created": False,
                }
            )
        )
        return 0
    except Exception as error:
        print(
            "Agent replay guard test failed: "
            + safe_failure_detail(type(error).__name__ + ": " + str(error)),
            file=sys.stderr,
        )
        return 1
    finally:
        vcr.VCR = original_vcr
        if prior_guard is None:
            os.environ.pop("WORKFLOW_LAB_CASSETTE_REPLAY_ONLY", None)
        else:
            os.environ["WORKFLOW_LAB_CASSETTE_REPLAY_ONLY"] = prior_guard


def verify_inventory(evidence, before):
    rows, changes = [], []
    for old in before["files"]:
        try:
            current = file_binding(evidence, evidence / old["path"])
        except (OSError, ValueError):
            current = {"path": old["path"], "status": "MISSING_OR_UNREADABLE"}
        rows.append(current)
        if current != old:
            changes.append(old["path"])
    return {"files": rows, "changed": changes, "unchanged": not changes}


def recorded_projects(base):
    projects = set()
    for path in [base / "state.json", *sorted((base / "worlds").glob("*/state.json"))]:
        if not path.exists():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
            raise ValueError("A recorded shop escapes its CI state folder.")
        record = read_json(path)
        context, project = record.get("docker_context", ""), record.get("project", "")
        if not re.fullmatch(r"shop-[0-9a-f]{12}", project) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context
        ):
            raise ValueError("Recorded cleanup requires an exact sample namespace and captured context.")
        projects.add((context, project))
    return sorted(projects)


def running_census(projects, run=subprocess.run):
    rows = []
    for context, project in projects:
        argv = [
            "docker",
            "--context",
            context,
            "ps",
            "--filter",
            "label=com.docker.compose.project=" + project,
            "--format",
            "{{.ID}}",
        ]
        result = run(argv, text=True, capture_output=True, check=False, timeout=30)
        ids = result.stdout.split()
        valid = result.returncode == 0 and all(re.fullmatch(r"[0-9a-f]{12,64}", item) for item in ids)
        rows.append(
            {
                "docker_context": context,
                "project": project,
                "argv": argv,
                "exit_code": result.returncode,
                "running_ids": ids if valid else None,
                "status": "ZERO" if valid and not ids else "NONZERO" if valid else "UNKNOWN",
            }
        )
    return {
        "scope": "recorded sample projects only",
        "projects": rows,
        "status": "ZERO"
        if rows and all(row["status"] == "ZERO" for row in rows)
        else "NO_RECORDED_PROJECTS"
        if not rows
        else "FAILED",
    }


def required_refs(lock):
    services = lock.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("The runtime image lock has no service references.")
    refs = sorted(set(services.values()))
    if not all(
        isinstance(ref, str) and re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", ref) for ref in refs
    ):
        raise ValueError("Cold inventory requires immutable registry image references.")
    return refs


def cold_status(rows):
    present = sum(row["status"] == "PRESENT" for row in rows)
    missing = sum(row["status"] == "ABSENT" for row in rows)
    if not rows or present + missing != len(rows):
        return "UNKNOWN"
    return (
        "REQUIRED_IMAGES_COLD"
        if not present
        else "REQUIRED_IMAGES_PARTIALLY_CACHED"
        if missing
        else "REQUIRED_IMAGES_CACHED"
    )


def cold_census(context, lock, destination, run=subprocess.run):
    """Inspect only required refs, before setup/start can pull or build anything."""
    record = {
        "schema": "workflow-lab.ci-image-census.v1",
        "started_utc": timestamp(),
        "docker_context": context,
        "scope": "required immutable images only; not a global engine census",
        "images": [],
        "status": "UNKNOWN",
    }
    try:
        for ref in required_refs(lock):
            result = run(
                ["docker", "--context", context, "image", "inspect", "--format", "{{.Id}}", ref],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", result.stdout.strip()):
                row = {"ref": ref, "status": "PRESENT", "config_id": result.stdout.strip()}
            elif result.returncode != 0 and "no such image" in result.stderr.lower():
                row = {"ref": ref, "status": "ABSENT"}
            else:
                raise RuntimeError("Required-image inspection failed; cold state is unknown.")
            record["images"].append(row)
        record["status"] = cold_status(record["images"])
        return record
    finally:
        record["completed_utc"] = timestamp()
        write_json(destination, record)


def active_state(base):
    directory = base
    if (base / "active.json").is_file():
        directory = base / read_json(base / "active.json")["world"]
    if not directory.resolve().is_relative_to(base.resolve()):
        raise ValueError("The active shop record escapes the selected CI folder.")
    return read_json(directory / "state.json")


def active_state_path(base):
    directory = base
    if (base / "active.json").is_file():
        directory = base / read_json(base / "active.json")["world"]
    if not directory.resolve().is_relative_to(base.resolve()):
        raise ValueError("The active shop record escapes the selected CI folder.")
    return directory / "state.json"


def assert_fresh(before, after, context, *, empty=False):
    if before["project"] == after["project"] or after["docker_context"] != context:
        raise RuntimeError("Reset/replay did not preserve context and create a fresh shop.")
    if empty and after.get("users"):
        raise RuntimeError("Reset unexpectedly recorded a shopper action.")
    if set(before.get("users", {})) & set(after.get("users", {})):
        raise RuntimeError("Replay reused a previous shopper.")


def verify_same_world_restart(before, after, user, status, payload, expected_cart):
    """Bind a restart readback to the same recorded project and synthetic shopper."""
    if (
        before.get("project") != after.get("project")
        or before.get("config") != after.get("config")
        or before.get("docker_context") != after.get("docker_context")
        or before.get("users", {}).get(user, {}).get("status") != "OBSERVED"
        or after.get("users", {}).get(user, {}).get("status") != "OBSERVED"
    ):
        raise RuntimeError("Same-world restart changed the recorded project, context, or settled shopper.")
    if status != 200:
        raise RuntimeError("Same-world restart readback is unavailable; persisted cart state is unknown.")
    items = shop_app.cart_items(payload, expected_user=user)
    if items != expected_cart:
        raise RuntimeError("Same-world restart changed or contradicted the recorded cart observation.")
    return {
        "project_unchanged": True,
        "synthetic_shopper_id": user,
        "cart_HTTP_status": status,
        "cart_identity_observation": shop_app.cart_identity_status(payload, user),
        "cart_after_restart": items,
        "matches_pre_restart_observation": True,
        "basis": "same recorded project and synthetic shopper; direct HTTP API readback after stop/start",
    }


def observe_store_for_result(state, result, *, runner=shop_app.native):
    """Join one API result to read-only Valkey observations in the same project."""
    if result.get("project_id") != state.get("project"):
        raise RuntimeError("Direct cart observation refused a result from another Compose project.")
    actors = result.get("HTTP_carts_by_synthetic_actor")
    if actors is None:
        user = result.get("synthetic_shopper_id")
        if not isinstance(user, str):
            raise RuntimeError("Direct cart observation has no bound synthetic shopper.")
        actors = {user: result.get("cart_after")}
    if not isinstance(actors, dict) or not actors:
        raise RuntimeError("Direct cart observation has no actor/cart mapping.")
    observations = {}
    for user, expected_items in actors.items():
        if not isinstance(expected_items, list):
            observations[user] = {"status": "UNKNOWN", "comparison": "UNKNOWN"}
            continue
        observed = shop_app.read_valkey_cart(state, user, runner)
        comparison = shop_app.compare_valkey_cart(user, expected_items, observed)
        observations[user] = {**observed, "comparison": comparison}
    comparisons = [row["comparison"] for row in observations.values()]
    status = (
        "CONTRADICTED"
        if "CONTRADICTED" in comparisons
        else "UNKNOWN"
        if any(value != "MATCHED_API_READBACK" for value in comparisons)
        else "MATCHED"
    )
    return {
        "status": status,
        "project_id": state["project"],
        "source_commit": state.get("source_commit"),
        "docker_context": state["docker_context"],
        "config_sha256": hashlib.sha256(Path(state["config"]).read_bytes()).hexdigest(),
        "actors": observations,
        "interpretation": "READ_ONLY_VALKEY_SNAPSHOT_JOINED_TO_HTTP_OR_MCP_PROJECTION; NOT_AUTHORIZATION_OR_RUNTIME_EFFECT_PROOF",
    }


def demote_unconfirmed_users(base, state, result):
    users = result.get("HTTP_carts_by_synthetic_actor")
    if not isinstance(users, dict):
        user = result.get("synthetic_shopper_id")
        users = {user: None} if isinstance(user, str) else {}
    for user in users:
        if user in state.get("users", {}):
            state["users"][user] = {
                "status": "UNKNOWN_AFTER_DISPATCH",
                "story": result.get("story", "unknown"),
            }
    write_json(active_state_path(base), state)


def catalog_status_matrix(summary, catalog, error=None):
    """Expose completed and deliberately-not-run stories after a fail-closed stop."""
    results = summary.get("story_results", [])
    counts = {
        story: sum(1 for row in results if isinstance(row, dict) and row.get("story") == story)
        for story in catalog
    }
    return [
        {
            "story": story,
            "completed_observations": counts[story],
            "status": "REPLAYED"
            if counts[story] >= 2
            else "OBSERVED_ONCE"
            if counts[story] == 1
            else "NOT_RUN",
            **({"blocker": error} if counts[story] < 2 and error else {}),
        }
        for story in catalog
    ]


def validate_agent_replay_result(run_record, result, *, expected_overlay_sha256):
    """Accept only a durable, pinned playback-only read-only agent result."""
    return (
        isinstance(run_record, dict)
        and run_record.get("status") == "passed"
        and isinstance(result, dict)
        and result.get("status") == "FIXTURE_REPLAY"
        and result.get("source_commit") == shop_app.SOURCE_COMMIT
        and result.get("model") == shop_app.AGENT_REPLAY_MODEL
        and result.get("prompt") == "Show all available products in the store."
        and result.get("cassette_sha256") == shop_app.AGENT_CASSETTE_SHA256
        and result.get("overlay_sha256") == expected_overlay_sha256
        and result.get("vcrpy_version") == shop_app.AGENT_VCRPY_VERSION
        and result.get("record_mode") == "none"
        and result.get("match_threshold") == "1.0"
        and result.get("tool_names") == ["list_products"]
        and result.get("agent_stopped") is True
        and result.get("live_inference") is False
    )


def browser_checkout_diagnostic(browser, valkey, comparison):
    """Return a bounded, identity-free diagnostic suitable for ordinary CI logs."""
    browser = browser if isinstance(browser, dict) else {}
    valkey = valkey if isinstance(valkey, dict) else {}
    before = browser.get("cart_before")
    after = browser.get("cart_after")
    return {
        "browser_status": browser.get("status", "UNKNOWN"),
        "checkout_request_count": browser.get("checkout_request_count"),
        "checkout_http_status": browser.get("checkout_HTTP_status"),
        "order_response_present": browser.get("order_response_present"),
        "cart_http_status": browser.get("cart_HTTP_status"),
        "cart_before_item_count": len(before) if isinstance(before, list) else None,
        "cart_after_item_count": len(after) if isinstance(after, list) else None,
        "valkey_status": valkey.get("status", "UNKNOWN"),
        "valkey_reason": valkey.get("reason"),
        "valkey_comparison": comparison,
    }


def run_browser_checkout(state, *, on_prepared, on_dispatch, browser_timeout_ms=30000):
    """Perform one real Chromium checkout with fictional data and loopback-only requests."""
    from playwright.sync_api import sync_playwright

    user = "shop-" + str(uuid.uuid4())
    shop_app.validate_user(user)
    status, products = shop_app.request(state["http_port"], "GET", "/api/products?currencyCode=USD")
    if status != 200 or not isinstance(products, list) or not products:
        raise RuntimeError("Browser checkout lacks a read-only catalogue; no browser attempt was made.")
    status, _ = shop_app.request(
        state["http_port"],
        "POST",
        "/api/cart?currencyCode=USD",
        {"userId": user, "item": {"productId": products[0]["id"], "quantity": 1}},
    )
    if status != 200:
        raise RuntimeError("Browser checkout cart preparation failed; no checkout was attempted.")
    before_status, before = shop_app.request(
        state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    before_items = shop_app.cart_items(before, expected_user=user) if before_status == 200 else None
    if before_items != [{"product_id": products[0]["id"], "quantity": 1}]:
        raise RuntimeError("Browser checkout prestate is not the requested single synthetic item.")
    on_prepared(user)

    fixture = shop_app.synthetic_fixture()
    if shop_app._RECORDER is not None:
        shop_app._RECORDER.set_redactions([fixture["email"], fixture["creditCard"]["creditCardNumber"]])
    session = json.dumps({"userId": user, "currencyCode": "USD"}, separators=(",", ":"))
    base_url = "http://127.0.0.1:" + str(state["http_port"])
    checkout_requests = []
    blocked_hosts = set()
    browser_result = {
        "story": "browser-normal-checkout",
        "project_id": state["project"],
        "synthetic_shopper_id": user,
        "status": "UNKNOWN",
    }
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context()
            context.add_init_script(
                "if (location.origin !== 'null') localStorage.setItem('session', "
                + json.dumps(session)
                + ");"
            )

            def route_request(route):
                parsed = urlsplit(route.request.url)
                if parsed.scheme not in ("http", "https") or parsed.hostname not in (
                    "127.0.0.1",
                    "localhost",
                ):
                    blocked_hosts.add(parsed.hostname or "non-http")
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", route_request)
            page = context.new_page()
            page.set_default_timeout(browser_timeout_ms)

            def on_request(request):
                parsed = urlsplit(request.url)
                if request.method == "POST" and parsed.path == "/api/checkout":
                    checkout_requests.append({"method": request.method, "path": parsed.path})
                    on_dispatch(user)

            page.on("request", on_request)
            page.goto(base_url + "/cart", wait_until="domcontentloaded")
            page.locator("#email").fill(fixture["email"])
            page.locator("#street_address").fill(fixture["address"]["streetAddress"])
            page.locator("#zip_code").fill(fixture["address"]["zipCode"])
            page.locator("#city").fill(fixture["address"]["city"])
            page.locator("#state").fill(fixture["address"]["state"])
            page.locator("#country").fill(fixture["address"]["country"])
            card_number = fixture["creditCard"]["creditCardNumber"]
            card_number = "-".join(card_number[index : index + 4] for index in range(0, 16, 4))
            page.locator("#credit_card_number").fill(card_number)
            page.locator("#credit_card_cvv").fill(str(fixture["creditCard"]["creditCardCvv"]))
            page.locator("#credit_card_expiration_month").select_option(
                str(fixture["creditCard"]["creditCardExpirationMonth"])
            )
            page.locator("#credit_card_expiration_year").select_option(
                str(fixture["creditCard"]["creditCardExpirationYear"])
            )
            with page.expect_response(
                lambda response: urlsplit(response.url).path == "/api/checkout", timeout=browser_timeout_ms
            ) as response_info:
                page.locator('[data-cy="checkout-place-order"]').click()
            response = response_info.value
            payload = response.json()
            order_present = isinstance(payload, dict) and bool(payload.get("orderId"))
            page.get_by_text("Your order is complete!", exact=True).wait_for()
            if (
                len(checkout_requests) != 1
                or response.status != 200
                or not order_present
                or not urlsplit(page.url).path.startswith("/cart/checkout/")
            ):
                raise RuntimeError(
                    "browser predicate failed: expected one checkout request, HTTP 200 order, and checkout receipt page"
                )
            after_status, after = shop_app.request(
                state["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
            )
            after_items = shop_app.cart_items(after, expected_user=user) if after_status == 200 else None
            browser_result.update(
                status="API_AND_BROWSER_OBSERVED" if after_items == [] else "UNKNOWN",
                checkout_request_count=len(checkout_requests),
                checkout_HTTP_status=response.status,
                order_response_present=order_present,
                order_id=payload.get("orderId") if order_present else None,
                cart_HTTP_status=after_status,
                cart_before=before_items,
                cart_after=after_items,
                blocked_external_hosts=sorted(blocked_hosts),
                basis="REAL_CHROMIUM_UI_AND_HTTP_RESPONSE; EFFECT_STATE_REQUIRES_INDEPENDENT_VALKEY_JOIN",
            )
            return browser_result
        except Exception as error:
            if checkout_requests:
                raise RuntimeError(
                    "Browser checkout failed after dispatch; outcome UNKNOWN, no retry was made."
                ) from error
            raise RuntimeError(
                "Browser checkout failed before dispatch; no checkout was attempted."
            ) from error
        finally:
            browser.close()


def observe_same_world_restart(campaign, result, before):
    user = result.get("synthetic_shopper_id")
    if not isinstance(user, str) or not user:
        raise RuntimeError("Restart observation has no recorded synthetic shopper; state is unknown.")
    campaign.cli("stop")
    campaign.cli("start")
    after = active_state(campaign.state)
    status, payload = shop_app.request(
        after["http_port"], "GET", "/api/cart?sessionId=" + user + "&currencyCode=USD"
    )
    return verify_same_world_restart(before, after, user, status, payload, result.get("cart_after"))


def semantic_outcome(result):
    """Keep stable behavior fields while excluding run, project, actor and time IDs."""
    story = result.get("story")
    assessment = result.get("assessment", {})
    common = {
        "story": story,
        "assessment_passed": assessment.get("passed"),
        "assessment_expected": assessment.get("expected"),
    }
    if story in ("normal-checkout", "cart-failure", "payment-unreachable"):
        before, after = result.get("cart_before"), result.get("cart_after")
        relation = "UNKNOWN"
        if isinstance(before, list) and isinstance(after, list):
            relation = "EMPTY" if not after else "UNCHANGED" if before == after else "CHANGED"
        return {
            **common,
            "checkout_attempt_count": result.get("checkout_attempt_count"),
            "checkout_status_class": _status_class(result.get("checkout_HTTP_status")),
            "order_response_present": result.get("order_response_present"),
            "cart_status_class": _status_class(result.get("cart_HTTP_status")),
            "cart_relation": relation,
            "cart_before": before,
            "cart_after": after,
            "cart_before_identity_status": result.get("cart_before_identity_status"),
            "cart_after_identity_status": result.get("cart_after_identity_status"),
        }
    if story == "mcp-session-id":
        return {
            **common,
            "http_cart_contents": sorted(
                json.dumps(cart, sort_keys=True)
                for cart in result.get("HTTP_carts_by_synthetic_actor", {}).values()
            ),
            "mcp_cart_contents": sorted(
                json.dumps(cart, sort_keys=True)
                for cart in result.get("MCP_carts_by_synthetic_actor", {}).values()
            ),
            "http_cart_identity_statuses": sorted(result.get("HTTP_cart_identity_by_actor", {}).values()),
            "actor_isolation_verified": result.get("actor_isolation_verified"),
            "projections_match": result.get("projections_match"),
            "tool_error": result.get("tool_error"),
        }
    if story == "shared-cart-conflict":
        actors = result.get("ordered_client_results", [])
        return {
            **common,
            "intents": [row.get("intent") for row in result.get("actor_intents", [])],
            "actor_cart_contents": [row.get("cart_after") for row in actors],
            "delete_status": actors[1].get("delete_status") if len(actors) == 2 else None,
            "final_cart_contents": result.get("cart_after"),
            "host_cart_contents": result.get("host_cart_after"),
            "cart_identity_observations": result.get("cart_identity_observations"),
        }
    if story == "shared-cart-overlap-diagnostic":
        return {
            **common,
            "diagnostic_completed": assessment.get("passed") is True,
            "service_handler_overlap_claim": "NOT_ESTABLISHED",
        }
    raise ValueError("No stable semantic comparison is defined for this story.")


def _status_class(value):
    if type(value) is not int:
        return "UNKNOWN"
    if 200 <= value <= 299:
        return "SUCCESS"
    if 400 <= value <= 499:
        return "CLIENT_ERROR"
    if 500 <= value <= 599:
        return "SERVER_ERROR"
    return "OTHER"


class Campaign:
    def __init__(self, state, evidence):
        self.state = state.resolve()
        self.evidence = evidence.resolve()
        if self.evidence.is_relative_to(self.state) or self.state.is_relative_to(self.evidence):
            raise ValueError("CI state and durable evidence must be separate folders.")
        self.receipts = self.evidence / "ci"
        self.receipts.mkdir(parents=True, exist_ok=True)
        self.sequence = len(list(self.receipts.glob("command-*.json")))

    def cli(self, *arguments):
        self.sequence += 1
        stem = "command-" + str(self.sequence).zfill(3)
        prior_runs = set((self.evidence / "runs").glob("*/run.json"))
        argv = [
            sys.executable,
            str(PUBLIC / "shop.py"),
            "--no-browser",
            "--state-dir",
            str(self.state),
            "--evidence-dir",
            str(self.evidence),
            *arguments,
        ]
        record = {"argv": argv, "started_utc": timestamp(), "exit_code": None, "log": stem + ".log"}
        start = time.monotonic()
        print("Shop CI: " + " ".join(arguments), flush=True)
        try:
            with (self.receipts / record["log"]).open("wb") as log:
                result = subprocess.run(
                    argv,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=False,
                    env={**os.environ, "CI": "true", "PYTHONUNBUFFERED": "1"},
                )
            record["exit_code"] = result.returncode
            if result.returncode:
                failed = self._new_failed_run_summary(prior_runs, arguments[0] if arguments else None)
                if not failed:
                    failed = self._command_log_failure_summary(
                        self.receipts / record["log"], arguments, result.returncode
                    )
                print("Shop CI detail: " + failed, file=sys.stderr, flush=True)
                raise RuntimeError("Shop step failed: " + " ".join(arguments) + "; inspect " + record["log"])
        finally:
            record.update(completed_utc=timestamp(), duration_seconds=time.monotonic() - start)
            write_json(self.receipts / (stem + ".json"), record)

    def _new_failed_run_summary(self, prior_runs, expected_command=None):
        runs = self.evidence / "runs"
        if not runs.is_dir():
            return ""
        fresh = sorted(set(runs.glob("*/run.json")) - prior_runs)
        primary = []
        for path in fresh:
            try:
                if (
                    path.is_symlink()
                    or not path.resolve().is_relative_to(self.evidence)
                    or not path.is_file()
                    or path.stat().st_size > 65536
                ):
                    continue
                run = read_json(path)
            except (OSError, ValueError, RuntimeError):
                continue
            command = run.get("command") if isinstance(run, dict) else None
            if (
                isinstance(command, str)
                and command in {"setup", "start", "story", "reset", "replay", "stop", "clean", "agent-replay"}
                and (expected_command is None or command == expected_command)
                and run.get("status") == "failed"
                and isinstance(run.get("finished_at"), str)
            ):
                primary.append((path, run))
        if len(primary) != 1:
            return ""
        path, run = primary[0]
        command = run["command"]
        detail = safe_failure_detail(run.get("error"))
        if isinstance(run.get("error"), str) and re.match(
            r"^A required command failed \(exit -?\d+\)\.", run["error"]
        ):
            stderr_detail = self._failed_native_stderr(path.parent, run.get("commands"))
            if stderr_detail:
                detail = stderr_detail
        return f"phase={command} status=failed error={detail}"

    def _failed_native_stderr(self, run_directory, commands):
        if not isinstance(commands, list):
            return ""
        failed = [row for row in commands if isinstance(row, dict) and row.get("status") == "failed"]
        if len(failed) != 1:
            return ""
        name = failed[0].get("stderr_name")
        if not isinstance(name, str) or not re.fullmatch(r"[0-9]{3}\.stderr\.log", name):
            return ""
        directory = run_directory / "commands"
        path = directory / name
        try:
            if (
                directory.is_symlink()
                or path.is_symlink()
                or not path.resolve().is_relative_to(directory.resolve())
                or not path.is_file()
            ):
                return ""
            with path.open("rb") as stream:
                size = path.stat().st_size
                stream.seek(max(0, size - 65536))
                tail = stream.read(65536).decode("utf-8", errors="replace")
        except (OSError, RuntimeError):
            return ""
        lines = [line.strip() for line in tail.splitlines() if line.strip()]
        return safe_failure_detail(lines[-1]) if lines else ""

    def _command_log_failure_summary(self, path, arguments, exit_code):
        """Summarize only the failed command's terminal exception line, never raw logs."""
        command = (
            arguments[0]
            if arguments
            and arguments[0]
            in {
                "setup",
                "start",
                "story",
                "reset",
                "replay",
                "stop",
                "clean",
                "agent-replay",
            }
            else "unknown"
        )
        summary = f"phase={command} status=failed exit={exit_code}"
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(self.receipts) or not path.is_file():
                return summary + " error=command log unavailable"
            with path.open("rb") as stream:
                size = path.stat().st_size
                stream.seek(max(0, size - 65536))
                tail = stream.read(65536).decode("utf-8", errors="replace")
        except (OSError, RuntimeError):
            return summary + " error=command log unavailable"

        lines = tail.splitlines()
        traceback_start = max(
            (
                index
                for index, line in enumerate(lines)
                if line.strip() == "Traceback (most recent call last):"
            ),
            default=-1,
        )
        if traceback_start < 0:
            cli_error_prefix = "Shop could not complete this step: "
            cli_errors = [line.strip() for line in lines if line.strip().startswith(cli_error_prefix)]
            if cli_errors:
                detail = safe_failure_detail(cli_errors[-1][len(cli_error_prefix) :])
                return f"{summary} error={detail}"
            return summary + " error=terminal exception detail unavailable"
        exception = None
        for line in reversed(lines[traceback_start + 1 :]):
            match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception))(?::\s*(.*))?\s*", line)
            if match:
                exception = match
                break
        if exception is None:
            return summary + " error=terminal exception detail unavailable"
        name = exception.group(1)
        detail = safe_failure_detail(exception.group(2) or "detail unavailable")
        return f"{summary} exception={name} error={detail}"

    def action(self, command, story):
        runs = self.evidence / "runs"
        prior = set(runs.glob("*/run.json"))
        self.cli(*command)
        new = {
            path
            for path in set(runs.glob("*/run.json")) - prior
            if read_json(path).get("command") == command[0]
        }
        # The live service-log companion is a separate recorder, not the CLI
        # result. Still reject missing or duplicate matching primary runs.
        if len(new) != 1:
            raise RuntimeError("The story did not produce exactly one durable CLI run.")
        run_path = new.pop()
        record = read_json(run_path)
        result_path = run_path.parent / "result.json"
        result = read_json(result_path)
        if (
            record.get("status") != "passed"
            or result.get("story") != story
            or result.get("assessment", {}).get("passed") is not True
        ):
            raise RuntimeError("The durable story assessment did not pass.")
        return {
            "story": story,
            "command": command,
            "run": str(run_path.relative_to(self.evidence)),
            "run_sha256": sha256(run_path),
            "result_sha256": sha256(result_path),
            "assessment": result["assessment"],
            "project_id": result.get("project_id"),
            "synthetic_shopper_id": result.get("synthetic_shopper_id"),
            "cart_after": result.get("cart_after"),
            "checkout_attempt_count": result.get("checkout_attempt_count"),
            "semantic_outcome": semantic_outcome(result),
        }

    def cleanup(self):
        failures = []
        attempt = "cleanup-" + str(len(list(self.receipts.glob("cleanup-*.json"))) + 1).zfill(3)
        before = None
        census = {"status": "UNKNOWN"}
        telemetry = {"status": "UNKNOWN"}
        projects = []
        try:
            projects = recorded_projects(self.state)
            self.cli("stop")
            before = closed_primary_inventory(self.evidence)
            telemetry = telemetry_inventory(self.evidence, projects)
            before["files"].extend(telemetry["files"])
            write_json(self.receipts / (attempt + "-before.json"), before)
            write_json(self.receipts / (attempt + "-telemetry.json"), telemetry)
            if telemetry["status"] not in ("PASS", "NO_RECORDED_PROJECTS"):
                failures.append("Every recorded project requires valid nonempty exported OTLP spans.")
        except (OSError, ValueError, RuntimeError) as error:
            failures.append(str(error))
        try:
            self.cli("clean")
        except (OSError, ValueError, RuntimeError) as error:
            failures.append(str(error))
        if before is not None:
            after = verify_inventory(self.evidence, before)
            write_json(self.receipts / (attempt + "-after.json"), after)
            if not after["unchanged"]:
                failures.append("Closed primary evidence changed during cleanup.")
        try:
            census = running_census(projects)
            if census["status"] not in ("ZERO", "NO_RECORDED_PROJECTS"):
                failures.append("Recorded shop running-container census was not zero.")
        except (OSError, subprocess.SubprocessError) as error:
            failures.append(str(error))
        privacy = scan_runtime_privacy(self.evidence)
        write_json(self.receipts / (attempt + "-privacy.json"), privacy)
        write_json(self.receipts / "privacy-final.json", privacy)
        if privacy["status"] != "PASS_DEFAULT_SENTINELS":
            failures.append("Persisted evidence failed the default synthetic PAN/email scan.")
        record = {
            "completed_utc": timestamp(),
            "status": "FAILED" if failures else "COMPLETED",
            "errors": failures,
            "evidence_retained": self.evidence.is_dir(),
            "scope": "recorded sample namespaces only",
            "primary_inventory_status": "UNCHANGED"
            if before is not None and not after["changed"]
            else "UNKNOWN_OR_CHANGED",
            "running_census": census,
            "telemetry_status": telemetry["status"],
            "privacy_status": privacy["status"],
        }
        write_json(self.receipts / (attempt + ".json"), record)
        write_json(self.receipts / "cleanup.json", record)
        return not failures


def self_test():
    """Run inert regressions; no Docker, network, or shop actions are executed."""
    import tempfile
    import unittest
    from unittest import mock

    module = sys.modules[__name__]

    class Controls(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory()
            self.addCleanup(self.temp.cleanup)
            self.base = Path(self.temp.name)
            self.campaign = Campaign(self.base / "state", self.base / "evidence")

        def primary(self, name="primary", command="story", passed=True):
            directory = self.campaign.evidence / "runs" / name
            write_json(
                directory / "run.json",
                {"command": command, "status": "passed", "finished_at": timestamp(), "commands": []},
            )
            write_json(
                directory / "result.json",
                {
                    "story": "normal-checkout",
                    "assessment": {"passed": passed, "expected": "success-empty"},
                    "checkout_attempt_count": 1,
                    "checkout_HTTP_status": 200,
                    "order_response_present": True,
                    "cart_HTTP_status": 200,
                    "cart_before": [{"product_id": "demo-product", "quantity": 1}],
                    "cart_after": [],
                },
            )
            return directory

        def test_semantic_repeatability_ignores_fresh_ids_but_detects_behavior_change(self):
            first = {
                "story": "normal-checkout",
                "project_id": "shop-aaaaaaaaaaaa",
                "synthetic_shopper_id": "shop-11111111-1111-4111-8111-111111111111",
                "started_utc": "first-time",
                "checkout_attempt_count": 1,
                "checkout_HTTP_status": 200,
                "order_response_present": True,
                "cart_HTTP_status": 200,
                "cart_before": [{"product_id": "demo-product", "quantity": 1}],
                "cart_after": [],
                "cart_before_identity_status": "MATCHED_REQUESTED_SHOPPER",
                "cart_after_identity_status": "NOT_ECHOED_FOR_EMPTY_CART",
                "assessment": {"passed": True, "expected": "success-empty"},
            }
            replay = {
                **first,
                "project_id": "shop-bbbbbbbbbbbb",
                "synthetic_shopper_id": "shop-22222222-2222-4222-8222-222222222222",
                "started_utc": "second-time",
            }
            self.assertEqual(semantic_outcome(first), semantic_outcome(replay))
            replay["cart_after"] = [{"product_id": "demo-product", "quantity": 1}]
            self.assertNotEqual(semantic_outcome(first), semantic_outcome(replay))

        def test_same_world_restart_rejects_project_drift_and_unavailable_or_wrong_readback(self):
            user = "shop-11111111-1111-4111-8111-111111111111"
            cart = [{"product_id": "demo-product", "quantity": 1}]
            before = {
                "project": "shop-0123456789ab",
                "config": "/fixture/compose.json",
                "docker_context": "default",
                "users": {user: {"status": "OBSERVED"}},
            }
            after = json.loads(json.dumps(before))
            payload = {"userId": user, "items": [{"productId": "demo-product", "quantity": 1}]}
            result = verify_same_world_restart(before, after, user, 200, payload, cart)
            self.assertTrue(result["project_unchanged"])
            self.assertTrue(result["matches_pre_restart_observation"])
            for changed_after, status, body in (
                ({**after, "project": "shop-aaaaaaaaaaaa"}, 200, payload),
                (after, 503, {}),
                (after, 200, {"userId": "shop-22222222-2222-4222-8222-222222222222", "items": cart}),
                (after, 200, {"userId": user, "items": []}),
            ):
                with self.subTest(project=changed_after["project"], status=status, body=body):
                    with self.assertRaises((RuntimeError, ValueError)):
                        verify_same_world_restart(before, changed_after, user, status, body, cart)

        def test_direct_valkey_join_is_bound_to_project_and_fails_closed(self):
            config = self.base / "compose.json"
            config.write_text("{}", encoding="utf-8")
            user_a = "shop-11111111-1111-4111-8111-111111111111"
            user_b = "shop-22222222-2222-4222-8222-222222222222"
            state = {
                "project": "shop-0123456789ab",
                "docker_context": "captured-engine",
                "engine_id": "engine-test",
                "config": str(config),
                "source_variant": "original",
                "source_commit": shop_app.SOURCE_COMMIT,
            }
            config_data = config.read_bytes()
            state["input_bindings"] = {
                "compose": {"sha256": sha256(config), "bytes": len(config_data)},
                "routing": shop_app.routing_binding(state),
            }
            result = {
                "project_id": state["project"],
                "HTTP_carts_by_synthetic_actor": {user_a: [], user_b: []},
            }

            def runner(args):
                return "engine-test" if "info" in args else "1\n\n"

            matched = observe_store_for_result(state, result, runner=runner)
            self.assertEqual(matched["status"], "MATCHED")
            self.assertEqual(set(matched["actors"]), {user_a, user_b})
            missing = observe_store_for_result(
                state, result, runner=lambda args: "engine-test" if "info" in args else "0\n\n"
            )
            self.assertEqual(missing["status"], "UNKNOWN")
            contradictory = observe_store_for_result(
                state,
                {
                    "project_id": state["project"],
                    "synthetic_shopper_id": user_a,
                    "cart_after": [{"product_id": "x", "quantity": 1}],
                },
                runner=runner,
            )
            self.assertEqual(contradictory["actors"][user_a]["comparison"], "CONTRADICTED")
            with self.assertRaises(RuntimeError):
                observe_store_for_result({**state, "project": "shop-aaaaaaaaaaaa"}, result, runner=runner)

        def test_browser_checkout_diagnostic_is_bounded_and_identity_free(self):
            shopper = "shop-11111111-1111-4111-8111-111111111111"
            order = "private-order-id"
            diagnostic = browser_checkout_diagnostic(
                {
                    "status": "API_AND_BROWSER_OBSERVED",
                    "synthetic_shopper_id": shopper,
                    "order_id": order,
                    "checkout_request_count": 1,
                    "checkout_HTTP_status": 200,
                    "order_response_present": True,
                    "cart_HTTP_status": 200,
                    "cart_before": [{"product_id": "demo-product", "quantity": 1}],
                    "cart_after": [],
                },
                {"status": "UNKNOWN", "reason": "engine identity mismatch", "actor_id": shopper},
                "UNKNOWN",
            )
            self.assertEqual(diagnostic["browser_status"], "API_AND_BROWSER_OBSERVED")
            self.assertEqual(diagnostic["valkey_status"], "UNKNOWN")
            self.assertEqual(diagnostic["cart_before_item_count"], 1)
            self.assertEqual(diagnostic["cart_after_item_count"], 0)
            encoded = json.dumps(diagnostic)
            self.assertNotIn(shopper, encoded)
            self.assertNotIn(order, encoded)
            self.assertNotIn("actor_id", diagnostic)

        def test_campaign_action_supplies_bound_cart_to_same_world_restart(self):
            user = "shop-11111111-1111-4111-8111-111111111111"
            cart = []
            state = {
                "project": "shop-0123456789ab",
                "config": "/fixture/compose.json",
                "docker_context": "default",
                "http_port": 18080,
                "users": {user: {"status": "OBSERVED"}},
            }
            self.campaign.state.mkdir(parents=True)
            write_json(self.campaign.state / "state.json", state)
            lifecycle_calls = []

            def fake_cli(*args):
                if args[0] == "story":
                    run = self.campaign.evidence / "runs" / "restart-source"
                    write_json(
                        run / "run.json",
                        {"command": "story", "status": "passed", "finished_at": timestamp(), "commands": []},
                    )
                    write_json(
                        run / "result.json",
                        {
                            "story": "shared-cart-conflict",
                            "assessment": {"passed": True, "expected": "ordered-conflict"},
                            "project_id": state["project"],
                            "synthetic_shopper_id": user,
                            "cart_after": cart,
                            "actor_intents": [
                                {"intent": "retain-added-item"},
                                {"intent": "clear-shared-cart"},
                            ],
                            "ordered_client_results": [
                                {"cart_after": [{"product_id": "demo-product", "quantity": 1}]},
                                {"cart_after": [], "delete_status": 204},
                            ],
                        },
                    )
                else:
                    lifecycle_calls.append(args[0])

            self.campaign.cli = fake_cli
            action = self.campaign.action(["story", "shared-cart-conflict"], "shared-cart-conflict")
            self.assertEqual(action["synthetic_shopper_id"], user)
            self.assertEqual(action["cart_after"], cart)
            payload = {"userId": user, "items": []}
            with mock.patch.object(shop_app, "request", return_value=(200, payload)):
                result = observe_same_world_restart(self.campaign, action, state)
            self.assertEqual(lifecycle_calls, ["stop", "start"])
            self.assertTrue(result["matches_pre_restart_observation"])

        def test_failed_campaign_exposes_completed_and_not_run_catalog_rows(self):
            summary = {
                "story_results": [
                    {"story": "normal-checkout"},
                    {"story": "normal-checkout"},
                    {"story": "cart-failure"},
                ]
            }
            rows = catalog_status_matrix(
                summary,
                ["normal-checkout", "cart-failure", "payment-unreachable"],
                "prior result UNKNOWN",
            )
            self.assertEqual([row["status"] for row in rows], ["REPLAYED", "OBSERVED_ONCE", "NOT_RUN"])
            self.assertEqual(rows[2]["blocker"], "prior result UNKNOWN")

        def test_agent_replay_result_requires_exact_pinned_playback_and_cleanup(self):
            overlay = Path(shop_app.AGENT_REPLAY_OVERLAY)
            overlay_hash = sha256(overlay)
            result = {
                "status": "FIXTURE_REPLAY",
                "source_commit": shop_app.SOURCE_COMMIT,
                "model": shop_app.AGENT_REPLAY_MODEL,
                "prompt": "Show all available products in the store.",
                "cassette_sha256": shop_app.AGENT_CASSETTE_SHA256,
                "overlay_sha256": overlay_hash,
                "vcrpy_version": shop_app.AGENT_VCRPY_VERSION,
                "record_mode": "none",
                "match_threshold": "1.0",
                "tool_names": ["list_products"],
                "agent_stopped": True,
                "live_inference": False,
            }
            self.assertTrue(
                validate_agent_replay_result(
                    {"status": "passed"}, result, expected_overlay_sha256=overlay_hash
                )
            )
            for field, value in (
                ("record_mode", "new_episodes"),
                ("cassette_sha256", "0" * 64),
                ("overlay_sha256", "0" * 64),
                ("tool_names", ["checkout"]),
                ("agent_stopped", False),
                ("live_inference", True),
            ):
                with self.subTest(field=field):
                    self.assertFalse(
                        validate_agent_replay_result(
                            {"status": "passed"},
                            {**result, field: value},
                            expected_overlay_sha256=overlay_hash,
                        )
                    )
            self.assertFalse(
                validate_agent_replay_result(
                    {"status": "failed"}, result, expected_overlay_sha256=overlay_hash
                )
            )

        def test_semantic_mcp_repeatability_ignores_actor_ids_not_cart_mismatch(self):
            first = {
                "story": "mcp-session-id",
                "HTTP_carts_by_synthetic_actor": {
                    "actor-one": [{"product_id": "item-a", "quantity": 1}],
                    "actor-two": [{"product_id": "item-b", "quantity": 1}],
                },
                "MCP_carts_by_synthetic_actor": {
                    "actor-one": [{"product_id": "item-a", "quantity": 1}],
                    "actor-two": [{"product_id": "item-b", "quantity": 1}],
                },
                "actor_isolation_verified": True,
                "projections_match": True,
                "tool_error": False,
                "HTTP_cart_identity_by_actor": {
                    "actor-one": "MATCHED_REQUESTED_SHOPPER",
                    "actor-two": "MATCHED_REQUESTED_SHOPPER",
                },
                "assessment": {"passed": True, "expected": "matching-cart"},
            }
            replay = json.loads(json.dumps(first))
            replay["HTTP_carts_by_synthetic_actor"] = {
                "fresh-one": [{"product_id": "item-b", "quantity": 1}],
                "fresh-two": [{"product_id": "item-a", "quantity": 1}],
            }
            replay["MCP_carts_by_synthetic_actor"] = {
                "fresh-one": [{"product_id": "item-b", "quantity": 1}],
                "fresh-two": [{"product_id": "item-a", "quantity": 1}],
            }
            self.assertEqual(semantic_outcome(first), semantic_outcome(replay))
            replay["MCP_carts_by_synthetic_actor"]["fresh-two"] = []
            self.assertNotEqual(semantic_outcome(first), semantic_outcome(replay))

        def test_identity_evidence_changes_stable_comparison(self):
            first = {
                "story": "normal-checkout",
                "checkout_attempt_count": 1,
                "checkout_HTTP_status": 200,
                "order_response_present": True,
                "cart_HTTP_status": 200,
                "cart_before": [{"product_id": "demo-product", "quantity": 1}],
                "cart_after": [],
                "cart_before_identity_status": "MATCHED_REQUESTED_SHOPPER",
                "cart_after_identity_status": "NOT_ECHOED_FOR_EMPTY_CART",
                "assessment": {"passed": True, "expected": "success-empty"},
            }
            replay = dict(first)
            self.assertEqual(semantic_outcome(first), semantic_outcome(replay))
            replay["cart_after_identity_status"] = "MATCHED_REQUESTED_SHOPPER"
            self.assertNotEqual(semantic_outcome(first), semantic_outcome(replay))

        def test_companion_coexists_with_one_matching_primary(self):
            def cli(*args):
                self.primary()
                self.primary("companion", "Live service logs")

            self.campaign.cli = cli
            self.assertEqual(
                self.campaign.action(["story", "normal-checkout"], "normal-checkout")["story"],
                "normal-checkout",
            )

        def test_duplicate_matching_primaries_reject(self):
            self.campaign.cli = lambda *args: (self.primary(), self.primary("duplicate"))
            with self.assertRaises(RuntimeError):
                self.campaign.action(["story", "normal-checkout"], "normal-checkout")

        def test_failed_assessment_is_not_promoted_by_companion(self):
            self.campaign.cli = lambda *args: (
                self.primary(passed=False),
                self.primary("companion", "Live service logs"),
            )
            with self.assertRaises(RuntimeError):
                self.campaign.action(["story", "normal-checkout"], "normal-checkout")

        def test_inventory_excludes_companion_and_detects_primary_change(self):
            primary = self.primary()
            command = primary / "commands" / "001.stdin.json"
            command.parent.mkdir()
            command.write_bytes(b'{"synthetic":true}')
            (primary / "commands" / "001.stdout.log").write_bytes(b"closed output")
            companion = self.primary("companion", "Live service logs")
            before = closed_primary_inventory(self.campaign.evidence)
            paths = {row["path"] for row in before["files"]}
            self.assertIn("runs/primary/commands/001.stdin.json", paths)
            self.assertFalse(any("companion" in path for path in paths))
            (companion / "result.json").write_bytes(b"still growing")
            self.assertTrue(verify_inventory(self.campaign.evidence, before)["unchanged"])
            command.write_bytes(b"changed input")
            self.assertFalse(verify_inventory(self.campaign.evidence, before)["unchanged"])

        def test_census_is_context_and_exact_project_scoped(self):
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")

            project = "shop-" + "a" * 12
            result = running_census([("captured-context", project)], run)
            self.assertEqual(result["status"], "ZERO")
            self.assertEqual(calls[0][:4], ["docker", "--context", "captured-context", "ps"])
            self.assertIn("label=com.docker.compose.project=" + project, calls[0])
            for code, output, expected in ((0, "a" * 12, "NONZERO"), (1, "", "UNKNOWN")):
                result = running_census(
                    [("captured-context", project)],
                    lambda *a, **k: subprocess.CompletedProcess(a, code, output, ""),
                )
                self.assertEqual(result["projects"][0]["status"], expected)

        def test_cleanup_stops_before_freeze_and_preserves_original_files(self):
            events = []
            self.primary()

            def cli(command):
                events.append(command)
                if command == "clean":
                    self.assertTrue(list(self.campaign.receipts.glob("cleanup-*-before.json")))

            self.campaign.cli = cli
            with mock.patch.object(module, "running_census", return_value={"status": "ZERO"}) as census:
                self.assertTrue(self.campaign.cleanup())
                self.assertEqual(census.call_count, 1)
            self.assertEqual(events, ["stop", "clean"])
            self.assertEqual(
                read_json(self.campaign.receipts / "cleanup.json")["primary_inventory_status"], "UNCHANGED"
            )

        def test_cleanup_changed_primary_or_running_container_fails(self):
            primary = self.primary()
            self.campaign.cli = lambda command: (
                (primary / "result.json").write_text("changed") if command == "clean" else None
            )
            with mock.patch.object(module, "running_census", return_value={"status": "FAILED"}):
                self.assertFalse(self.campaign.cleanup())
            record = read_json(self.campaign.receipts / "cleanup.json")
            self.assertEqual(record["status"], "FAILED")
            self.assertEqual(len(record["errors"]), 2)

        def test_invalid_recorded_namespace_rejects(self):
            write_json(
                self.campaign.state / "state.json", {"project": "unrelated", "docker_context": "captured"}
            )
            with self.assertRaises(ValueError):
                recorded_projects(self.campaign.state)

        def test_zero_exported_spans_cannot_pass_cleanup(self):
            project = "shop-" + "b" * 12
            write_json(self.campaign.state / "state.json", {"project": project, "docker_context": "captured"})
            traces = self.campaign.evidence / "telemetry" / project / "traces.jsonl"
            traces.parent.mkdir(parents=True)
            traces.write_bytes(b"")
            self.campaign.cli = lambda command: None
            with mock.patch.object(module, "running_census", return_value={"status": "ZERO"}):
                self.assertFalse(self.campaign.cleanup())

        def trace(self):
            project = "shop-" + "c" * 12
            write_json(self.campaign.state / "state.json", {"project": project, "docker_context": "captured"})
            span = {
                "name": "GET /api/products",
                "traceId": "1" * 32,
                "spanId": "2" * 16,
                "startTimeUnixNano": "100",
                "endTimeUnixNano": "200",
            }
            record = {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [{"key": "service.name", "value": {"stringValue": "frontend"}}]
                        },
                        "scopeSpans": [{"spans": [span]}],
                    }
                ]
            }
            path = self.campaign.evidence / "telemetry" / project / "traces.jsonl"
            write_json(path, record)
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            return path, record

        def test_actual_otlp_file_binds_span_service_count_and_hash(self):
            path, record = self.trace()
            path.write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n", encoding="utf-8")
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "PASS")
            row = result["projects"][0]
            self.assertEqual(row["observed_span_count"], 2)
            self.assertEqual(row["service_counts"], {"frontend": 2})
            self.assertEqual(row["sha256"], sha256(path))
            self.assertEqual(row["bytes"], path.stat().st_size)

        def test_otlp_boundary_join_uses_allowlisted_pinned_demo_fields_only(self):
            user = "shop-11111111-1111-4111-8111-111111111111"
            order = "22222222-2222-4222-8222-222222222222"
            trace_id = "a" * 32

            def span(name, attributes):
                return {
                    "name": name,
                    "traceId": trace_id,
                    "spanId": uuid.uuid4().hex[:16],
                    "startTimeUnixNano": "100",
                    "endTimeUnixNano": "200",
                    "attributes": attributes,
                }

            def string_attr(key, value):
                return {"key": key, "value": {"stringValue": value}}

            def service(name, spans):
                return {
                    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": name}}]},
                    "scopeSpans": [{"spans": spans}],
                }

            record = {
                "resourceSpans": [
                    service(
                        "checkout",
                        [
                            span(
                                "PlaceOrder",
                                [
                                    string_attr("user.id", user),
                                    string_attr("demo.order.id", order),
                                    string_attr("user.email", "sensitive@example.test"),
                                ],
                            )
                        ],
                    ),
                    service(
                        "payment",
                        [
                            span(
                                "Charge",
                                [{"key": "demo.payment.charged", "value": {"boolValue": True}}],
                            )
                        ],
                    ),
                    service("email", [span("send_email", [string_attr("demo.order.id", order)])]),
                ]
            }
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "traces.jsonl"
                path.write_text(json.dumps(record) + "\n", encoding="utf-8")
                inventory = parse_otlp_traces(path)
            self.assertNotIn("sensitive@example.test", json.dumps(inventory))
            observation = simulated_boundary_observation(
                {**inventory, "project": "shop-" + "d" * 12, "status": "OBSERVED_EXPORTED_SPANS"},
                {
                    "project_id": "shop-" + "d" * 12,
                    "synthetic_shopper_id": user,
                    "order_id": order,
                },
            )
            self.assertEqual(observation["status"], "OBSERVED")
            no_payment = json.loads(json.dumps(inventory))
            no_payment["boundary_spans"][1]["payment_charged"] = False
            self.assertEqual(
                simulated_boundary_observation(
                    {**no_payment, "project": "shop-" + "d" * 12, "status": "OBSERVED_EXPORTED_SPANS"},
                    {
                        "project_id": "shop-" + "d" * 12,
                        "synthetic_shopper_id": user,
                        "order_id": order,
                    },
                )["status"],
                "UNKNOWN",
            )

        def test_simulated_checkout_boundaries_require_same_trace_and_order(self):
            project = "shop-" + "d" * 12
            user = "shop-11111111-1111-4111-8111-111111111111"
            order = "22222222-2222-4222-8222-222222222222"
            trace_id = "a" * 32
            inventory = {
                "project": project,
                "status": "OBSERVED_EXPORTED_SPANS",
                "boundary_spans": [
                    {
                        "service": "checkout",
                        "trace_id": trace_id,
                        "email_send_span": False,
                        "user_id": user,
                        "order_id": order,
                        "payment_charged": None,
                        "charged_event": True,
                    },
                    {
                        "service": "payment",
                        "trace_id": trace_id,
                        "email_send_span": False,
                        "user_id": None,
                        "order_id": None,
                        "payment_charged": True,
                        "charged_event": False,
                    },
                    {
                        "service": "email",
                        "trace_id": trace_id,
                        "email_send_span": True,
                        "user_id": None,
                        "order_id": order,
                        "payment_charged": None,
                        "charged_event": False,
                    },
                ],
            }
            browser = {
                "project_id": project,
                "synthetic_shopper_id": user,
                "order_id": order,
            }
            observed = simulated_boundary_observation(inventory, browser)
            self.assertEqual(observed["status"], "OBSERVED")
            self.assertIn("NOT AN INDEPENDENT JOURNAL", observed["basis"])
            missing_payment = json.loads(json.dumps(inventory))
            missing_payment["boundary_spans"][1]["payment_charged"] = False
            self.assertEqual(simulated_boundary_observation(missing_payment, browser)["status"], "UNKNOWN")
            wrong_trace = json.loads(json.dumps(inventory))
            wrong_trace["boundary_spans"][2]["trace_id"] = "b" * 32
            self.assertEqual(simulated_boundary_observation(wrong_trace, browser)["status"], "UNKNOWN")
            wrong_order = json.loads(json.dumps(inventory))
            wrong_order["boundary_spans"][2]["order_id"] = "33333333-3333-4333-8333-333333333333"
            self.assertEqual(simulated_boundary_observation(wrong_order, browser)["status"], "UNKNOWN")
            self.assertNotIn("shopper@example.test", json.dumps(observed))
            self.assertNotIn("4111111111111111", json.dumps(observed))

        def payment_result(self, project, shopper, **changes):
            result = {
                "story": "payment-unreachable",
                "project_id": project,
                "synthetic_shopper_id": shopper,
                "checkout_attempt_count": 1,
                "checkout_HTTP_status": 500,
                "order_response_present": False,
                "cart_HTTP_status": 200,
                "cart_before": [{"product_id": "demo-product", "quantity": 1}],
                "cart_after": [{"product_id": "demo-product", "quantity": 1}],
                "assessment": {"passed": True},
            }
            result.update(changes)
            path = self.campaign.evidence / "runs" / "payment-run" / "result.json"
            path.parent.mkdir(parents=True)
            write_json(path, result)
            run_path = path.parent / "run.json"
            write_json(run_path, {"status": "passed", "command": "story"})
            action = {
                "story": "payment-unreachable",
                "command": ["story", "payment-unreachable"],
                "run": run_path.relative_to(self.campaign.evidence).as_posix(),
                "run_sha256": sha256(run_path),
                "result_sha256": sha256(path),
                "assessment": result["assessment"],
                "project_id": project,
                "synthetic_shopper_id": shopper,
                "checkout_attempt_count": result["checkout_attempt_count"],
            }
            write_json(self.campaign.evidence / "ci" / "campaign.json", {"story_results": [action]})
            return path

        def checkout_error_trace(self, path, record, shopper, *, status_code=2):
            span = {
                "name": "oteldemo.CheckoutService/PlaceOrder",
                "traceId": "3" * 32,
                "spanId": "4" * 16,
                "startTimeUnixNano": "300",
                "endTimeUnixNano": "400",
                "attributes": [{"key": "user.id", "value": {"stringValue": shopper}}],
                "status": {"code": status_code},
            }
            record["resourceSpans"].append(
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "checkout"}}]
                    },
                    "scopeSpans": [{"spans": [span]}],
                }
            )
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")

        def test_payment_unavailable_joins_direct_observation_to_positive_checkout_error_span(self):
            path, record = self.trace()
            project = "shop-" + "c" * 12
            shopper = "shop-11111111-1111-4111-8111-111111111111"
            self.payment_result(project, shopper)
            self.checkout_error_trace(path, record, shopper)
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "PASS")
            observation = result["projects"][0]["payment_unavailable_observations"][0]
            self.assertTrue(observation["direct_error_response_and_cart_readback"])
            self.assertTrue(observation["one_checkout_dispatch_recorded"])
            self.assertTrue(observation["matching_checkout_error_span_observed"])

        def test_missing_or_wrong_checkout_error_span_does_not_pass_payment_story(self):
            path, record = self.trace()
            project = "shop-" + "c" * 12
            shopper = "shop-11111111-1111-4111-8111-111111111111"
            self.payment_result(project, shopper)
            self.checkout_error_trace(path, record, "shop-22222222-2222-4222-8222-222222222222")
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["projects"][0]["status"], "UNKNOWN")

        def test_non_error_checkout_span_does_not_qualify_payment_story(self):
            path, record = self.trace()
            project = "shop-" + "c" * 12
            shopper = "shop-11111111-1111-4111-8111-111111111111"
            self.payment_result(project, shopper)
            self.checkout_error_trace(path, record, shopper, status_code=1)
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["projects"][0]["status"], "UNKNOWN")

        def test_inconsistent_payment_result_contract_is_unknown(self):
            path, record = self.trace()
            project = "shop-" + "c" * 12
            shopper = "shop-11111111-1111-4111-8111-111111111111"
            self.payment_result(project, shopper, checkout_attempt_count=2)
            self.checkout_error_trace(path, record, shopper)
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["projects"][0]["status"], "UNKNOWN")

        def test_payment_result_requires_campaign_hash_link_and_action_record(self):
            path, record = self.trace()
            project = "shop-" + "c" * 12
            shopper = "shop-11111111-1111-4111-8111-111111111111"
            self.payment_result(project, shopper)
            self.checkout_error_trace(path, record, shopper)
            campaign_path = self.campaign.evidence / "ci" / "campaign.json"
            campaign = read_json(campaign_path)
            campaign["story_results"][0]["result_sha256"] = "0" * 64
            write_json(campaign_path, campaign)
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["projects"][0]["status"], "UNKNOWN")

            campaign["story_results"] = []
            write_json(campaign_path, campaign)
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["projects"][0]["status"], "UNKNOWN")

        def test_debug_empty_malformed_and_invalid_span_lines_reject(self):
            path, record = self.trace()
            invalid_span = json.loads(json.dumps(record))
            invalid_span["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"] = "0" * 16
            missing_service = json.loads(json.dumps(record))
            missing_service["resourceSpans"][0]["resource"]["attributes"] = []
            for data in (
                b"",
                b"debug: Spans #1 service.name=frontend\n",
                b'{"resourceSpans":[]}\n',
                (json.dumps(record) + "\nnot-json\n").encode(),
                b"\xff\n",
                (json.dumps(invalid_span) + "\n").encode(),
                (json.dumps(missing_service) + "\n").encode(),
            ):
                with self.subTest(data=data[:30]):
                    path.write_bytes(data)
                    self.assertEqual(
                        telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))[
                            "status"
                        ],
                        "FAILED",
                    )

        def test_one_good_project_cannot_hide_another_empty_project(self):
            self.trace()
            project = "shop-" + "d" * 12
            write_json(
                self.campaign.state / "worlds" / "other" / "state.json",
                {"project": project, "docker_context": "captured"},
            )
            result = telemetry_inventory(self.campaign.evidence, recorded_projects(self.campaign.state))
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(len(result["projects"]), 2)

        def test_closed_telemetry_must_survive_cleanup_unchanged(self):
            path, _ = self.trace()
            self.campaign.cli = lambda command: None
            with mock.patch.object(module, "running_census", return_value={"status": "ZERO"}):
                self.assertTrue(self.campaign.cleanup())
            before = read_json(next(self.campaign.receipts.glob("cleanup-*-before.json")))
            self.assertIn(
                path.relative_to(self.campaign.evidence).as_posix(), {row["path"] for row in before["files"]}
            )
            self.campaign.cli = lambda command: path.write_bytes(b"changed") if command == "clean" else None
            with mock.patch.object(module, "running_census", return_value={"status": "ZERO"}):
                self.assertFalse(self.campaign.cleanup())

        def test_privacy_scans_logs_results_inputs_and_json_escapes(self):
            for relative, data in (
                ("runs/live/commands/out.log", b"4111111111111111"),
                ("runs/case/result.json", b"shopper@example.test"),
                ("runs/case/inputs/compose.json", b"4111111111111111"),
                ("telemetry/project/traces.jsonl", b"\\u0034" + b"111111111111111"),
            ):
                path = self.campaign.evidence / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            result = scan_runtime_privacy(self.campaign.evidence)
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["files_with_matches"], 4)
            self.assertNotIn("4111111111111111", json.dumps(result))

        def test_privacy_scans_even_source_named_paths(self):
            path = self.campaign.evidence / "runs" / "id" / "inputs" / "tool-source" / "shop.py"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"4111111111111111 shopper@example.test")
            self.assertEqual(scan_runtime_privacy(self.campaign.evidence)["status"], "FAILED")
            self.assertEqual(scan_runtime_privacy(self.campaign.evidence)["files_with_matches"], 1)
            log = self.campaign.evidence / "runtime.log"
            log.write_bytes(b"x" * (1024 * 1024 - 4) + b"4111111111111111")
            self.assertEqual(scan_runtime_privacy(self.campaign.evidence)["status"], "FAILED")

        def test_privacy_upload_output_is_fail_closed_and_summary_minimized(self):
            path = self.campaign.evidence / "runtime.log"
            path.write_bytes(b"shopper@example.test")
            output = self.base / "github-output"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                self.assertEqual(privacy_check(self.campaign.evidence), 1)
            self.assertEqual(output.read_text(), "allowed=false\n")
            summary = (self.campaign.receipts / "privacy-summary.json").read_bytes()
            self.assertNotIn(b"shopper@example.test", summary)
            self.assertNotIn(b"runtime.log", summary)

        def test_privacy_upload_allowed_only_after_clean_scan(self):
            (self.campaign.evidence / "runtime.log").write_bytes(
                b"synthetic runtime result, no forbidden values"
            )
            output = self.base / "github-output"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                self.assertEqual(privacy_check(self.campaign.evidence), 0)
            self.assertEqual(output.read_text(), "allowed=true\n")

        def test_redirected_runtime_evidence_cannot_pass_privacy(self):
            target = self.base / "outside.log"
            target.write_bytes(b"outside")
            try:
                (self.campaign.evidence / "redirect.log").symlink_to(target)
            except OSError as error:
                self.skipTest("Host cannot create inert symlink: " + str(error))
            self.assertEqual(scan_runtime_privacy(self.campaign.evidence)["status"], "FAILED")

    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
    )
    return 0 if result.wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=ROOT / ".ci-shop")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "evidence")
    parser.add_argument("--context", help="Pin a Docker context; otherwise capture it once before inventory.")
    parser.add_argument(
        "--cleanup", action="store_true", help="Only stop/clean recorded CI shops; retain evidence."
    )
    parser.add_argument(
        "--self-test", action="store_true", help="Run inert CI orchestration regressions only."
    )
    parser.add_argument(
        "--agent-vcr-self-test",
        action="store_true",
        help="Prove the pinned replay-only VCR overlay rejects an HTTPX cassette miss without network access.",
    )
    parser.add_argument(
        "--agent-replay",
        action="store_true",
        help="Include one pinned, replay-only public agent endpoint call in the Docker campaign.",
    )
    parser.add_argument(
        "--privacy-check",
        "--privacy-only",
        dest="privacy_check",
        action="store_true",
        help="Scan persisted evidence and emit fail-closed GitHub upload eligibility; no Docker.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.agent_vcr_self_test:
        return agent_vcr_self_test()
    if args.privacy_check:
        evidence = args.evidence_dir.resolve()
        if not evidence.is_dir():
            return 1
        return privacy_check(evidence)
    campaign = Campaign(args.state_dir, args.evidence_dir)
    if args.cleanup:
        return 0 if campaign.cleanup() else 1
    summary = {
        "schema": "workflow-lab.ci-campaign.v1",
        "started_utc": timestamp(),
        "status": "RUNNING",
        "story_results": [],
        "runtime_scope": "public sample observations only",
        "agent_replay": {"status": "PENDING" if args.agent_replay else "NOT_REQUESTED"},
    }
    success = False
    try:
        if (campaign.state / "state.json").exists() or (campaign.state / "active.json").exists():
            raise ValueError(
                "This CI state folder already contains a shop; do not replay an unfinished campaign."
            )
        catalog = read_json(PUBLIC / "stories.json")["stories"]
        if not catalog or any(not re.fullmatch(r"[a-z][a-z0-9-]*", name) for name in catalog):
            raise ValueError("The public story catalog is empty or malformed.")
        summary.update(
            stories=list(catalog),
            catalog_sha256=sha256(PUBLIC / "stories.json"),
            runtime_lock_sha256=sha256(PUBLIC / "runtime-images.lock.json"),
            disk_free_bytes=shutil.disk_usage(ROOT).free,
        )
        context = args.context
        if not context:
            context = subprocess.run(
                ["docker", "context", "show"], text=True, capture_output=True, check=True
            ).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context):
            raise ValueError("Docker context name is invalid.")
        summary["docker_context"] = context
        cold_census(
            context,
            read_json(PUBLIC / "runtime-images.lock.json"),
            campaign.receipts / "required-image-cold-census.json",
        )
        campaign.cli("setup", "--context", context, *(["--agent-replay"] if args.agent_replay else []))
        campaign.cli("start", next(iter(catalog)))

        def mark_browser_dispatch(user):
            state = active_state(campaign.state)
            if state.get("users", {}).get(user, {}).get("status") != "PREPARED_NO_CHECKOUT":
                raise RuntimeError("Browser checkout shopper is not in its single-use prepared state.")
            state["users"][user] = {"status": "UNKNOWN_AFTER_DISPATCH", "story": "browser-normal-checkout"}
            write_json(active_state_path(campaign.state), state)

        def mark_browser_prepared(user):
            state = active_state(campaign.state)
            if user in state.get("users", {}):
                raise RuntimeError("Browser checkout shopper was already used; no retry is allowed.")
            state.setdefault("users", {})[user] = {
                "status": "PREPARED_NO_CHECKOUT",
                "story": "browser-normal-checkout",
            }
            write_json(active_state_path(campaign.state), state)

        browser_result = run_browser_checkout(
            active_state(campaign.state), on_prepared=mark_browser_prepared, on_dispatch=mark_browser_dispatch
        )
        browser_state = active_state(campaign.state)
        browser_observation = shop_app.read_valkey_cart(browser_state, browser_result["synthetic_shopper_id"])
        browser_comparison = shop_app.compare_valkey_cart(
            browser_result["synthetic_shopper_id"], browser_result.get("cart_after"), browser_observation
        )
        browser_diagnostic = browser_checkout_diagnostic(
            browser_result, browser_observation, browser_comparison
        )
        summary["browser_checkout_diagnostic"] = browser_diagnostic
        print(
            "Shop CI browser-checkout-summary: " + json.dumps(browser_diagnostic, sort_keys=True), flush=True
        )
        browser_result["independent_valkey_observation"] = {
            **browser_observation,
            "comparison": browser_comparison,
        }
        if (
            browser_result.get("status") != "API_AND_BROWSER_OBSERVED"
            or browser_comparison != "MATCHED_API_READBACK"
        ):
            summary["browser_checkout"] = browser_result
            demote_unconfirmed_users(campaign.state, browser_state, browser_result)
            write_json(campaign.receipts / "campaign.json", summary)
            raise RuntimeError("Browser checkout or its independent Valkey join is unknown/contradicted.")
        browser_state["users"][browser_result["synthetic_shopper_id"]]["status"] = "OBSERVED"
        write_json(active_state_path(campaign.state), browser_state)
        summary["browser_checkout"] = browser_result
        write_json(campaign.receipts / "campaign.json", summary)

        for story in catalog:
            first = campaign.action(["story", story], story)
            story_state = active_state(campaign.state)
            run_path = campaign.evidence / first["run"]
            result = read_json(run_path.parent / "result.json")
            first["independent_valkey_observation"] = observe_store_for_result(story_state, result)
            summary["story_results"].append(first)
            write_json(campaign.receipts / "campaign.json", summary)
            if first["independent_valkey_observation"]["status"] != "MATCHED":
                demote_unconfirmed_users(campaign.state, story_state, result)
                raise RuntimeError(
                    "Independent Valkey state is missing, stale or contradicts the story projection."
                )
            previous = active_state(campaign.state)
            if story == "shared-cart-conflict":
                observation = observe_same_world_restart(campaign, first, previous)
                summary["same_world_restart_observation"] = observation
                previous = active_state(campaign.state)
            campaign.cli("reset")
            reset = active_state(campaign.state)
            assert_fresh(previous, reset, context, empty=True)
            replay_result = campaign.action(["replay"], story)
            summary["story_results"].append(replay_result)
            if first["semantic_outcome"] != replay_result["semantic_outcome"]:
                raise RuntimeError("Reset/replay changed stable story semantics across fresh identities.")
            replay = active_state(campaign.state)
            assert_fresh(reset, replay, context)
            if set(previous.get("users", {})) & set(replay.get("users", {})):
                raise RuntimeError("Explicit replay reused the first story shopper.")
            write_json(campaign.receipts / "campaign.json", summary)
        if args.agent_replay:
            summary["agent_replay"] = {"status": "RUNNING"}
            write_json(campaign.receipts / "campaign.json", summary)
            prior_runs = set((campaign.evidence / "runs").glob("*/run.json"))
            campaign.cli("agent-replay")
            new_runs = {
                path
                for path in set((campaign.evidence / "runs").glob("*/run.json")) - prior_runs
                if read_json(path).get("command") == "agent-replay"
            }
            if len(new_runs) != 1:
                raise RuntimeError("The agent fixture replay did not produce one durable command result.")
            run_path = new_runs.pop()
            agent_run = read_json(run_path)
            agent_result = read_json(run_path.parent / "result.json")
            if not validate_agent_replay_result(
                agent_run,
                agent_result,
                expected_overlay_sha256=sha256(shop_app.AGENT_REPLAY_OVERLAY),
            ):
                raise RuntimeError(
                    "The agent endpoint result did not prove the pinned read-only fixture replay."
                )
            summary["agent_replay"] = {
                "status": "FIXTURE_REPLAY",
                "run": str(run_path.relative_to(campaign.evidence)),
                "run_sha256": sha256(run_path),
                "result_sha256": sha256(run_path.parent / "result.json"),
                "source_commit": agent_result["source_commit"],
                "model": agent_result["model"],
                "cassette_sha256": agent_result["cassette_sha256"],
                "overlay_sha256": agent_result["overlay_sha256"],
                "vcrpy_version": agent_result["vcrpy_version"],
                "record_mode": agent_result["record_mode"],
                "match_threshold": agent_result["match_threshold"],
                "tool_names": agent_result["tool_names"],
                "agent_stopped": True,
                "live_inference": False,
            }
            write_json(campaign.receipts / "campaign.json", summary)
        success = True
    except Exception as error:
        summary["error"] = safe_failure_detail(str(error), limit=300)
        if summary.get("agent_replay", {}).get("status") == "RUNNING":
            summary["agent_replay"] = {
                "status": "UNKNOWN",
                "blocker": summary["error"],
            }
        elif summary.get("agent_replay", {}).get("status") == "PENDING":
            summary["agent_replay"] = {
                "status": "NOT_RUN",
                "blocker": summary["error"],
            }
        summary["catalog_status"] = catalog_status_matrix(
            summary, summary.get("stories", []), summary["error"]
        )
        print("Shop CI stopped: " + summary["error"], file=sys.stderr)
    finally:
        cleaned = campaign.cleanup()
        summary.update(
            status="PASSED" if success and cleaned else "FAILED",
            completed_utc=timestamp(),
            cleanup_completed=cleaned,
        )
        write_json(campaign.receipts / "campaign.json", summary)
    return 0 if success and cleaned else 1


if __name__ == "__main__":
    raise SystemExit(main())
