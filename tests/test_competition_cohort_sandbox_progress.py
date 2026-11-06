"""Timed child diagnostics are bounded, scoped and independent of native results."""

import asyncio
import json
import logging
import os
import socket
import sys
from pathlib import Path

import pytest

from umi import competition_cohort_sandbox_progress as module
from umi.competition_transport_verification import TransferProgress

REQUEST = "a" * 64
JOB = "b" * 64


def event(**change):
    return dict(
        schema="umi-transport-work-progress/1",
        pid=os.getpid(),
        work_id=-1,
        job_sha256=JOB,
        stage="model_cache_conditioning",
        status="running",
        unit="pages",
        completed_units=1,
        total_units=10,
        elapsed_seconds=1.0,
        eta_seconds=9.0,
        planning_eta_seconds=None,
        eta_basis="native_work_units",
        eta_scope="current_transfer_substage",
        **change,
    )


def packet(value, **change):
    return json.dumps(dict(request_sha256=REQUEST, dropped=0, event=value, **change)).encode()


async def test_child_counts_refresh_parent_without_completing_invocation():
    reports = []
    progress = TransferProgress("timed_host_invocation", 1, reports.append, unit="cases")
    channel = module.ParentProgress(progress, REQUEST, JOB)
    sender = channel.writer.dup()
    try:
        channel.start(os.getpid())
        progress.changed -= 120
        value = event()
        value["private_path"] = "/private/model"
        sender.send(packet(value))
        channel.drain()
        refreshed = progress.changed
        assert progress.completed == 0
        assert progress.child["completed_units"] == 1
        assert progress.child["stage"] == "model_cache_conditioning"
        assert all("/private/" not in str(row) for row in reports)
        sender.send(packet(value))
        channel.drain()
        assert progress.changed == refreshed, "heartbeat must not conceal a stalled child"
        value["completed_units"] = 2
        sender.send(packet(value))
        channel.drain()
        assert progress.changed > refreshed
        assert progress.completed == 0
    finally:
        sender.close()
        channel.close()


@pytest.mark.parametrize(
    "change",
    [
        {"job_sha256": "c" * 64},
        {"pid": -1},
        {"completed_units": 11},
        {"elapsed_seconds": -1},
        {"eta_seconds": float("nan")},
        {"stage": "/private/path"},
        {"reason_code": "private failure"},
        {"planning_eta_seconds": [9, 1]},
        {"unit": "x" * 121},
        {"status": "success"},
    ],
)
def test_invalid_child_metadata_is_refused(change):
    value = event()
    value.update(change)
    with pytest.raises(ValueError):
        module.progress_event(value, job_sha256=JOB, pid=os.getpid())


async def test_malformed_packets_are_diagnostic_only_and_scope_memory_is_bounded():
    reports = []
    progress = TransferProgress("timed_host_invocation", 1, reports.append, unit="cases")
    channel = module.ParentProgress(progress, REQUEST, JOB)
    sender = channel.writer.dup()
    try:
        channel.start(os.getpid())
        for raw in (
            b"invalid",
            b"x" * (module.MAX_PROGRESS_BYTES + 1),
            b"[]",
            packet({}),
            json.dumps({"request_sha256": "wrong"}).encode(),
        ):
            sender.send(raw)
            channel.drain()
        assert progress.completed == 0
        assert reports[-1]["reason_code"] == "timed_child_progress_invalid"
        for i in range(100):
            value = event()
            value["work_id"] = -i
            sender.send(packet(value))
            channel.drain()
        assert len(channel.reporters) == module.MAX_CHILD_SCOPES
    finally:
        sender.close()
        channel.close()


def test_worker_does_not_block_when_parent_queue_is_full_or_closed():
    reader, writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    writer.setblocking(False)
    writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    sink = module.ChildProgress(writer, REQUEST, JOB)
    record = logging.LogRecord("test", logging.INFO, "", 0, json.dumps(event()), (), None)
    try:
        for _ in range(200):
            sink.emit(record)
        assert sink.dropped > 0
        reader.close()
        sink.emit(record)
        assert sink.dropped > 0
    finally:
        reader.close()
        writer.close()


async def test_real_isolated_child_delivers_scoped_transfer_progress():
    reports = []
    progress = TransferProgress("timed_host_invocation", 1, reports.append, unit="cases")
    channel = module.ParentProgress(progress, REQUEST, JOB)
    source = str(Path(module.__file__).resolve().parent.parent)
    code = (
        "import sys,logging;sys.path.insert(0," + repr(source) + ");"
        "from umi.competition_cohort_sandbox_progress import child_progress;"
        "from umi.competition_cohort_public_progress import execution_job_scope;"
        "from umi.competition_transport_verification import TransferProgress;"
        'logging.getLogger("umi.competition.progress").setLevel(logging.INFO);'
        "\nwith child_progress(int(sys.argv[1]),sys.argv[2],sys.argv[3]),"
        "execution_job_scope(sys.argv[3]):"
        '\n with TransferProgress("model_cache_conditioning",4,unit="pages") as work:'
        " work.advance(4)"
    )
    child = None
    try:
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-B",
            "-c",
            code,
            str(channel.writer.fileno()),
            REQUEST,
            JOB,
            pass_fds=(channel.writer.fileno(),),
        )
        channel.start(child.pid)
        assert await asyncio.wait_for(child.wait(), 10) == 0
        channel.drain()
        assert progress.child["stage"] == "model_cache_conditioning"
        assert progress.child["completed_units"] == 4
        assert progress.completed == 0
        assert any(row.get("job_sha256") == JOB for row in reports)
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        channel.close()
