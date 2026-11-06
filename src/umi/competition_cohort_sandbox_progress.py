"""Bounded diagnostic IPC for the selected timed child; never result authority."""

import asyncio
import json
import logging
import math
import os
import re
import socket
from collections import OrderedDict
from contextlib import contextmanager

MAX_PROGRESS_BYTES = 4096
MAX_CHILD_SCOPES = 64
_LOG = logging.getLogger("umi.competition.progress")
_STATES = {
    "started",
    "running",
    "completed",
    "waiting",
    "stalled",
    "retrying",
    "refused",
    "repair_required",
    "repair_completed",
}


def _number(value):
    return type(value) in (int, float) and 0 <= value <= 10**15 and math.isfinite(value)


def progress_event(value, *, job_sha256, pid):
    if (
        not isinstance(value, dict)
        or value.get("schema") != "umi-transport-work-progress/1"
        or value.get("job_sha256") != job_sha256
        or value.get("pid") != pid
        or type(value.get("work_id")) is not int
        or value.get("status") not in _STATES
        or any(
            not isinstance(value.get(key), str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,119}", value[key]) is None
            for key in ("stage", "unit")
        )
    ):
        raise ValueError("timed child progress identity differs")
    count, total = value.get("completed_units"), value.get("total_units")
    if type(count) is not int or type(total) is not int or not 0 <= count <= total <= 2**63 - 1:
        raise ValueError("timed child progress counts differ")
    if not _number(value.get("elapsed_seconds")):
        raise ValueError("timed child progress clock differs")
    eta, planning = value.get("eta_seconds"), value.get("planning_eta_seconds")
    if eta is not None and not _number(eta):
        raise ValueError("timed child progress estimate differs")
    if planning is not None and (
        not isinstance(planning, (list, tuple))
        or len(planning) != 2
        or not all(_number(item) for item in planning)
        or planning[0] > planning[1]
    ):
        raise ValueError("timed child progress range differs")
    event = {
        key: value.get(key)
        for key in (
            "schema",
            "pid",
            "work_id",
            "job_sha256",
            "stage",
            "status",
            "unit",
            "completed_units",
            "total_units",
            "elapsed_seconds",
            "eta_seconds",
            "planning_eta_seconds",
        )
    }
    for key in ("eta_basis", "eta_scope", "reason_code"):
        item = value.get(key)
        if item is not None and (
            not isinstance(item, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,159}", item) is None
        ):
            raise ValueError("timed child progress reason differs")
        event[key] = item
    event["certification_authority"] = False
    return event


class ChildProgress(logging.Handler):
    def __init__(self, channel, request_sha256, job_sha256):
        super().__init__()
        self.channel, self.request, self.job = channel, request_sha256, job_sha256
        self.dropped = 0

    def emit(self, record):
        # Never block a timing observer or turn diagnostic delivery into a
        # native execution failure. The next packet reports any queue loss.
        try:
            value = json.loads(record.getMessage())
            if value.get("schema") != "umi-transport-work-progress/1":
                return
            event = progress_event(value, job_sha256=self.job, pid=os.getpid())
            raw = json.dumps(
                dict(request_sha256=self.request, dropped=self.dropped, event=event),
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
            if len(raw) > MAX_PROGRESS_BYTES:
                raise ValueError("timed child progress packet exceeds bound")
            if self.channel.send(raw) != len(raw):
                raise OSError("timed child progress packet incomplete")
        except (OSError, ValueError, TypeError, AttributeError):
            self.dropped += 1


@contextmanager
def child_progress(fd, request_sha256, job_sha256):
    if fd is None:
        yield
        return
    with socket.socket(fileno=fd) as channel:
        channel.setblocking(False)
        sink = ChildProgress(channel, request_sha256, job_sha256)
        _LOG.addHandler(sink)
        try:
            yield
        finally:
            _LOG.removeHandler(sink)
            sink.close()


class ParentProgress:
    def __init__(self, progress, request_sha256, job_sha256):
        self.progress, self.request, self.job = progress, request_sha256, job_sha256
        self.reader, self.writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        for channel in (self.reader, self.writer):
            channel.setblocking(False)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        self.reporters = OrderedDict()
        self.pid = self.loop = None
        self.dropped = 0

    def start(self, pid):
        self.pid = pid
        self.writer.close()
        self.loop = asyncio.get_running_loop()
        self.loop.add_reader(self.reader.fileno(), self.drain)

    def drain(self):
        # Yield back to the loop after bounded work even if a child floods it.
        for _ in range(16):
            try:
                raw = self.reader.recv(MAX_PROGRESS_BYTES + 1)
            except BlockingIOError:
                break
            except OSError:
                return
            try:
                if not raw or len(raw) > MAX_PROGRESS_BYTES:
                    raise ValueError("timed child progress packet exceeds bound")
                packet = json.loads(raw)
                if packet.get("request_sha256") != self.request:
                    raise ValueError("timed child progress request differs")
                dropped = packet.get("dropped")
                if type(dropped) is not int or dropped < self.dropped:
                    raise ValueError("timed child progress loss counter differs")
                event = progress_event(packet.get("event"), job_sha256=self.job, pid=self.pid)
                if dropped > self.dropped:
                    self.progress.emit("retrying", reason="timed_child_progress_dropped")
                    self.dropped = dropped
                key = event["work_id"]
                if key not in self.reporters:
                    self.reporters[key] = self.progress.child_report()
                    if len(self.reporters) > MAX_CHILD_SCOPES:
                        self.reporters.popitem(last=False)
                self.reporters[key](event)
            except (ValueError, TypeError, AttributeError):
                self.progress.emit("retrying", reason="timed_child_progress_invalid")

    def close(self):
        if self.loop is not None:
            self.loop.remove_reader(self.reader.fileno())
            self.drain()
            self.loop = None
        self.reader.close()
        self.writer.close()
