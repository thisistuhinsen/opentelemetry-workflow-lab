"""Exercise the public case catalog through the launcher; retain host evidence.

This script is intended for an isolated Linux CI runner. It never prunes Docker
or removes resources directly: stop/clean use the launcher's recorded namespaces.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

PUBLIC = Path(__file__).resolve().parent
ROOT = PUBLIC.parent


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


def parse_otlp_traces(path):
    """Validate actual file-exporter envelopes, not debug text or log records."""
    counts = {}
    checkout_error_users = set()
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
        "jsonl_lines": lines,
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
            campaign_path = evidence / "ci" / "campaign.json"
            campaign = read_json(campaign_path) if campaign_path.is_file() else {}
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


def assert_fresh(before, after, context, *, empty=False):
    if before["project"] == after["project"] or after["docker_context"] != context:
        raise RuntimeError("Reset/replay did not preserve context and create a fresh shop.")
    if empty and after.get("users"):
        raise RuntimeError("Reset unexpectedly recorded a shopper action.")
    if set(before.get("users", {})) & set(after.get("users", {})):
        raise RuntimeError("Replay reused a previous shopper.")


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
                and command in {"setup", "start", "story", "reset", "replay", "stop", "clean"}
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
        "--privacy-check",
        "--privacy-only",
        dest="privacy_check",
        action="store_true",
        help="Scan persisted evidence and emit fail-closed GitHub upload eligibility; no Docker.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
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
        campaign.cli("setup", "--context", context)
        campaign.cli("start", next(iter(catalog)))
        for story in catalog:
            first = campaign.action(["story", story], story)
            summary["story_results"].append(first)
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
        success = True
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
        print("Shop CI stopped: " + str(error), file=sys.stderr)
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
