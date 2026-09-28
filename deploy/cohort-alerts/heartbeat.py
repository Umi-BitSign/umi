"""Send selected systemd service states to the external operational monitor."""

import argparse
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def heartbeat(services):
    if not services or len(services) > 20 or len(set(services)) != len(services):
        raise ValueError("invalid services")
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
        states[service] = "running" if ok else "failed"
    return {"schema": "umi-service-heartbeat/1", "services": states}


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
        data=json.dumps(heartbeat(config["services"])).encode(),
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
