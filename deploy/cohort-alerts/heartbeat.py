"""Send selected systemd service states to the external operational monitor."""

import argparse
import asyncio
import json
import re
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_STORAGE_METRIC = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}/available_bytes")
_LIFECYCLE_LABEL = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_HEX32 = re.compile(r"[0-9a-f]{64}")
_BOUNDED_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ERROR_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_PHASES = {
    "intake",
    "preparation",
    "requests",
    "reference_commit",
    "reference_reveal",
    "evaluation",
    "evidence",
    "certification",
    "complete",
    "revoked",
}


async def _read_journal(service, *, pattern, since, maximum_entries):
    """Bound both journal output and runtime; never forward journal text."""
    process = await asyncio.create_subprocess_exec(
        "journalctl",
        "-u",
        service,
        f"--since=-{since}",
        "-n",
        str(maximum_entries),
        "-r",
        "--no-pager",
        "-o",
        "json",
        "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID",
        f"--grep={pattern}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:

        async def bounded_output():
            data = bytearray()
            while len(data) <= 65536:
                chunk = await process.stdout.read(min(8192, 65537 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            return data

        data = await asyncio.wait_for(bounded_output(), timeout=5)
        if len(data) > 65536:
            raise ValueError("journal_output_too_large")
        if await asyncio.wait_for(process.wait(), timeout=5):
            raise ValueError("journal_unavailable")
        return data.decode("utf-8")
    finally:
        if process.returncode is None:
            process.kill()
        # Drain the bounded pipe after killing an oversized producer; waiting
        # without draining a paused asyncio pipe can leave the child unreaped.
        await process.communicate()


async def read_journal(service):
    return await _read_journal(
        service,
        pattern="umi-standing-chain-observation/1",
        since="10min",
        maximum_entries=100,
    )


async def read_successor_journal(service):
    # A healthy successor can spend many minutes verifying retained history.
    # Keep the freshness window above that expected reconciliation time while
    # still detecting a prolonged hold well before chain activity expires.
    return await _read_journal(
        service,
        pattern="umi-successor-host-status/1",
        since="45min",
        maximum_entries=1000,
    )


async def read_delivery_journal(service):
    # Include the initial systemd messages so a new invocation with no completed
    # pass is distinguishable from an unavailable journal. Raw text stays local.
    return await _read_journal(service, pattern="", since="45min", maximum_entries=100)


def delivery_healthy(service, invocation_id):
    """Return a current invocation's delivery outcome, or None before its first pass."""
    try:
        lines = asyncio.run(read_delivery_journal(service)).splitlines()
        for line in lines:
            entry = json.loads(line)
            if entry.get("_SYSTEMD_INVOCATION_ID") != invocation_id:
                continue
            try:
                message = json.loads(entry.get("MESSAGE", ""))
            except (ValueError, TypeError):
                continue
            if not isinstance(message, dict):
                continue
            status = message.get("status")
            if status not in {
                "artifact_delivery_current",
                "artifact_delivery_pending",
                "artifact_delivery_retry",
            }:
                continue
            failed = message.get("failed_source_trees", 0)
            if type(failed) is not int or failed < 0:
                raise ValueError("invalid delivery report")
            # Missing not-yet-produced inputs are normal during an open cohort.
            return status != "artifact_delivery_retry" and failed == 0
        return None
    except (OSError, ValueError, TypeError, AttributeError, asyncio.TimeoutError) as error:
        raise RuntimeError("delivery_status_unavailable") from error


async def read_lifecycle_journal(service, cohort):
    return await _read_journal(
        service,
        pattern=(f'"cohort_sha256":"{cohort}".*"schema":"umi-cohort-lifecycle-observation/1"'),
        since="25h",
        maximum_entries=1,
    )


def standing_progress(service):
    missing = {service + "/finalized_block": None, service + "/weight_update_block": None}
    try:
        lines = asyncio.run(read_journal(service)).splitlines()
        for line in lines:
            entry = json.loads(line)
            message = json.loads(entry.get("MESSAGE", ""))
            if (
                not isinstance(message, dict)
                or message.get("schema") != "umi-standing-chain-observation/1"
            ):
                continue
            block, updated = message.get("block_number"), message.get("weight_update_block")
            if (
                type(block) is not int
                or type(updated) is not int
                or not 0 <= updated <= block < 2**53
            ):
                return missing
            return {service + "/finalized_block": block, service + "/weight_update_block": updated}
    except (OSError, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
        pass
    return missing


def successor_healthy(service, invocation_id):
    try:
        lines = asyncio.run(read_successor_journal(service)).splitlines()
        for line in lines:
            entry = json.loads(line)
            message = json.loads(entry.get("MESSAGE", ""))
            if (
                not isinstance(message, dict)
                or message.get("schema") != "umi-successor-host-status/1"
                or entry.get("_SYSTEMD_INVOCATION_ID") != invocation_id
            ):
                continue
            status = message.get("status")
            reason = message.get("reason")
            return status in {"worker_started", "worker_healthy"} or (status, reason) in {
                ("started", "successor_worker_started"),
                ("healthy", "successor_worker_healthy"),
                ("healthy", "current_worker_healthy"),
                ("healthy", "future_directive_staged"),
                ("healthy", "future_stage_failed"),
            }
    except (OSError, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
        pass
    return False


def lifecycle_status(service, cohort):
    try:
        lines = asyncio.run(read_lifecycle_journal(service, cohort)).splitlines()
        for line in lines:
            entry = json.loads(line)
            message = json.loads(entry.get("MESSAGE", ""))
            if not isinstance(message, dict) or message.get("cohort_sha256") != cohort:
                continue
            keys = {
                "schema",
                "cohort_sha256",
                "plan_sequence",
                "phase",
                "sequence",
                "target_block",
                "stage",
                "status",
                "progress_completion",
                "progress_observed_at_block",
                "unavailable_blocks",
                "expected_round_sha256",
                "error_type",
            }
            if (
                set(message) != keys
                or message.get("schema") != "umi-cohort-lifecycle-observation/1"
                or _HEX32.fullmatch(cohort) is None
                or type(message.get("plan_sequence")) is not int
                or not 1 <= message["plan_sequence"] < 2**53
                or message.get("phase") not in _PHASES
                or type(message.get("sequence")) is not int
                or not 0 <= message["sequence"] < 2**53
                or (
                    message.get("target_block") is not None
                    and (
                        type(message["target_block"]) is not int
                        or not 0 <= message["target_block"] < 2**53
                    )
                )
                or _BOUNDED_NAME.fullmatch(message.get("stage", "")) is None
                or _BOUNDED_NAME.fullmatch(message.get("status", "")) is None
                or message.get("progress_completion") not in {None, "pending", "complete"}
                or any(
                    value is not None and (type(value) is not int or not 0 <= value < 2**53)
                    for value in (
                        message.get("progress_observed_at_block"),
                        message.get("unavailable_blocks"),
                    )
                )
                or (
                    message.get("progress_completion") is None
                    and (
                        message.get("progress_observed_at_block") is not None
                        or message.get("unavailable_blocks") is not None
                    )
                )
                or (
                    message.get("progress_completion") is not None
                    and (
                        message.get("progress_observed_at_block") is None
                        or message.get("unavailable_blocks") is None
                    )
                )
                or (
                    message.get("error_type") is not None
                    and _ERROR_NAME.fullmatch(message["error_type"]) is None
                )
                or (
                    message.get("expected_round_sha256") is not None
                    and _HEX32.fullmatch(message["expected_round_sha256"]) is None
                )
            ):
                return None
            return {key: message[key] for key in keys if key != "schema"}
    except (OSError, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
        pass
    return None


def public_round_index(raw_url):
    url = urllib.parse.urlsplit(raw_url)
    if (
        url.scheme != "https"
        or url.path != "/v1/competition/rounds/index"
        or url.query
        or url.fragment
        or url.username
    ):
        raise ValueError("invalid public round index URL")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    request = urllib.request.Request(
        raw_url + "?limit=20", headers={"User-Agent": "umi-cohort-monitor/1"}
    )
    with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError("public round index unavailable")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid public round index")
    items = value.get("items")
    if (
        value.get("schema") != "umi-competition-round-index/1"
        or not isinstance(items, list)
        or len(items) > 20
    ):
        raise ValueError("invalid public round index")
    if not items:
        return 0, set()
    result, sequences = set(), []
    for item in items:
        sequence = item.get("sequence") if isinstance(item, dict) else None
        round_sha256 = item.get("round_sha256") if isinstance(item, dict) else None
        if (
            type(sequence) is not int
            or not 1 <= sequence < 2**53
            or not isinstance(round_sha256, str)
            or _HEX32.fullmatch(round_sha256) is None
        ):
            raise ValueError("invalid public round item")
        result.add(round_sha256)
        sequences.append(sequence)
    if sequences != sorted(set(sequences), reverse=True):
        raise ValueError("public round index is not ordered")
    return sequences[0], result


def heartbeat(
    services,
    standing_services=(),
    successor_services=(),
    storage_paths=None,
    lifecycle_cohorts=None,
    public_round_index_url=None,
    delivery_services=(),
):
    if not services or len(services) > 20 or len(set(services)) != len(services):
        raise ValueError("invalid services")
    if (
        len(standing_services) > 10
        or len(set(standing_services)) != len(standing_services)
        or not set(standing_services) <= set(services)
    ):
        raise ValueError("invalid standing services")
    if (
        len(successor_services) > 10
        or len(set(successor_services)) != len(successor_services)
        or not set(successor_services) <= set(services)
    ):
        raise ValueError("invalid successor services")
    if (
        len(delivery_services) > 10
        or len(set(delivery_services)) != len(delivery_services)
        or not set(delivery_services) <= set(services)
    ):
        raise ValueError("invalid delivery services")
    storage_paths = {} if storage_paths is None else storage_paths
    lifecycle_cohorts = {} if lifecycle_cohorts is None else lifecycle_cohorts
    if (
        not isinstance(storage_paths, dict)
        or len(storage_paths) > 10
        or any(
            not isinstance(name, str)
            or _STORAGE_METRIC.fullmatch(name) is None
            or not isinstance(raw_path, str)
            or not 1 <= len(raw_path) <= 4096
            or not Path(raw_path).is_absolute()
            for name, raw_path in storage_paths.items()
        )
    ):
        raise ValueError("invalid storage paths")
    if (
        not isinstance(lifecycle_cohorts, dict)
        or len(lifecycle_cohorts) > 10
        or any(
            not isinstance(name, str)
            or _LIFECYCLE_LABEL.fullmatch(name) is None
            or not isinstance(value, dict)
            or set(value) != {"service", "cohort_sha256"}
            or value["service"] not in services
            or _HEX32.fullmatch(value["cohort_sha256"]) is None
            for name, value in lifecycle_cohorts.items()
        )
        or bool(lifecycle_cohorts) != bool(public_round_index_url)
    ):
        raise ValueError("invalid lifecycle cohorts")
    states = {}
    for service in services:
        if not re.fullmatch(r"[A-Za-z0-9@_.-]{1,100}\.service", service):
            raise ValueError("invalid service name")
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "show",
                    service,
                    "-p",
                    "ActiveState",
                    "-p",
                    "SubState",
                    "-p",
                    "InvocationID",
                    "-p",
                    "ActiveEnterTimestampMonotonic",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            if (
                result.returncode
                or not {"ActiveState", "SubState", "InvocationID"} <= fields.keys()
            ):
                raise RuntimeError("service_status_unavailable")
            ok = fields["ActiveState"] == "active" and fields["SubState"] == "running"
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("service_status_unavailable") from error
        if ok and service in successor_services:
            invocation = fields["InvocationID"]
            if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
                raise RuntimeError("service_status_unavailable")
            ok = successor_healthy(service, invocation)
        if ok and service in delivery_services:
            invocation = fields["InvocationID"]
            if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
                raise RuntimeError("service_status_unavailable")
            observed = delivery_healthy(service, invocation)
            if observed is None:
                started = fields.get("ActiveEnterTimestampMonotonic", "")
                if not started.isdigit() or int(started) <= 0:
                    raise RuntimeError("service_status_unavailable")
                age_seconds = time.monotonic() - int(started) / 1_000_000
                ok = 0 <= age_seconds < 45 * 60
            else:
                ok = observed
        states[service] = "running" if ok else "failed"
    result = {"schema": "umi-service-heartbeat/1", "services": states}
    if standing_services:
        result["schema"] = "umi-service-heartbeat/2"
        result["progress"] = {
            name: value
            for service in standing_services
            for name, value in standing_progress(service).items()
        }
    if storage_paths:
        resources = {}
        for name, raw_path in storage_paths.items():
            path = Path(raw_path)
            try:
                metadata = path.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or any(
                    candidate.is_symlink() for candidate in (path, *path.parents)
                ):
                    raise OSError("storage path is not a direct directory")
                available = shutil.disk_usage(path).free
                if type(available) is not int or not 0 <= available < 2**53:
                    raise OSError("storage value is outside protocol bounds")
            except OSError as error:
                raise RuntimeError("storage_status_unavailable") from error
            resources[name] = available
        result["schema"] = "umi-service-heartbeat/3"
        result["resources"] = resources
    if lifecycle_cohorts:
        result["schema"] = "umi-service-heartbeat/4"
        try:
            latest_round, public_rounds = public_round_index(public_round_index_url)
        except (OSError, ValueError, TimeoutError):
            # An unavailable public API must not suppress the independent host
            # heartbeat. The monitor treats null lifecycle observations as
            # missing, preserving its existing lifecycle alarm rather than
            # claiming publication or progress succeeded.
            result["lifecycles"] = {name: None for name in lifecycle_cohorts}
            return result
        result["lifecycles"] = {
            name: (
                None
                if (observed := lifecycle_status(value["service"], value["cohort_sha256"])) is None
                else {
                    **observed,
                    "public_round_sequence": latest_round,
                    "public_round_present": (
                        None
                        if observed["expected_round_sha256"] is None
                        else observed["expected_round_sha256"] in public_rounds
                    ),
                }
            )
            for name, value in lifecycle_cohorts.items()
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    url = urllib.parse.urlsplit(config["url"])
    if (
        url.scheme != "https"
        or url.path != "/heartbeat"
        or url.query
        or url.fragment
        or url.username
    ):
        raise ValueError("invalid monitor URL")
    request = urllib.request.Request(
        config["url"],
        data=json.dumps(
            heartbeat(
                config["services"],
                config.get("standing_services", []),
                config.get("successor_services", []),
                config.get("storage_paths", {}),
                config.get("lifecycle_cohorts", {}),
                config.get("public_round_index_url"),
                config.get("delivery_services", []),
            )
        ).encode(),
        headers={
            "Authorization": "Bearer " + config["token"],
            "Content-Type": "application/json",
            "User-Agent": "umi-cohort-monitor/1",
        },
        method="POST",
    )

    # Redirects must not forward the monitor credential to a different origin.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
        data = json.loads(response.read(4097))
        if response.status != 200 or data.get("accepted") is not True:
            raise ValueError("heartbeat rejected")
    print(json.dumps({"status": "heartbeat_accepted"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        result = {"status": "heartbeat_failed", "error_type": type(error).__name__}
        if isinstance(error, urllib.error.HTTPError):
            result["http_status"] = error.code
        print(json.dumps(result))
        raise SystemExit(1) from None
