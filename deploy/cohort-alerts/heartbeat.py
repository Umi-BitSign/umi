"""Send selected systemd service states to the external operational monitor."""

import argparse
import asyncio
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


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
        "--output-fields=MESSAGE",
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


def successor_healthy(service):
    try:
        lines = asyncio.run(read_successor_journal(service)).splitlines()
        for line in lines:
            entry = json.loads(line)
            message = json.loads(entry.get("MESSAGE", ""))
            if (
                not isinstance(message, dict)
                or message.get("schema") != "umi-successor-host-status/1"
            ):
                continue
            return message.get("status") in {"worker_started", "worker_healthy"}
    except (OSError, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
        pass
    return False


def heartbeat(services, standing_services=(), successor_services=()):
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
    states = {}
    for service in services:
        if not re.fullmatch(r"[A-Za-z0-9@_.-]{1,100}\.service", service):
            raise ValueError("invalid service name")
        try:
            result = subprocess.run(
                ["systemctl", "show", service, "-p", "ActiveState", "-p", "SubState"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            if result.returncode or not {"ActiveState", "SubState"} <= fields.keys():
                raise RuntimeError("service_status_unavailable")
            ok = fields["ActiveState"] == "active" and fields["SubState"] == "running"
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("service_status_unavailable") from error
        if ok and service in successor_services:
            ok = successor_healthy(service)
        states[service] = "running" if ok else "failed"
    result = {"schema": "umi-service-heartbeat/1", "services": states}
    if standing_services:
        result["schema"] = "umi-service-heartbeat/2"
        result["progress"] = {
            name: value
            for service in standing_services
            for name, value in standing_progress(service).items()
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
