"""Real Linux credential packets and bounded protocol failures (no fake sockets)."""

import asyncio
import os
import socket
from dataclasses import replace

import pytest

from umi.competition_reward_writer_broker_channel import WriterBrokerChannel


@pytest.fixture
def channels():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    a = WriterBrokerChannel(left, peer_pid=os.getpid(), peer_uid=os.getuid())
    b = WriterBrokerChannel(right, peer_pid=os.getpid(), peer_uid=os.getuid())
    try:
        yield a, b
    finally:
        left.close()
        right.close()


async def test_actual_credentials_and_sealed_packet(channels):
    a, b = channels
    pending = asyncio.create_task(b.receive("selected"))
    await a.send("selected", history_identities={".": [1, 2, 3, 4, 448]})
    message = await pending
    assert message.action == "selected"
    assert message._binding == message.seal()
    with pytest.raises(ValueError, match="authentic"):
        replace(message, action="committed").validate("committed")
    message.payload["history_identities"]["."][0] += 1
    with pytest.raises(ValueError, match="authentic"):
        message.validate("selected")


@pytest.mark.parametrize("change", ["pid", "uid", "order"])
async def test_wrong_sender_or_protocol_order_refuses(channels, change):
    a, b = channels
    if change == "pid":
        b.peer_pid += 1
    elif change == "uid":
        b.peer_uid += 1
    await a.send("owned")
    with pytest.raises(ValueError, match=r"sender|order"):
        await b.receive("complete" if change == "order" else "owned")


async def test_closed_peer_and_bounded_metadata(channels):
    a, b = channels
    with pytest.raises(ValueError, match="metadata limit"):
        await a.send("oversized", body="x" * 16384)
    a.endpoint.close()
    with pytest.raises(ConnectionError, match="exited"):
        await b.receive()


async def test_receive_cancellation_keeps_descriptor_usable(channels):
    a, b = channels
    task = asyncio.create_task(b.receive())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await a.send("owned")
    assert (await b.receive()).action == "owned"


async def test_original_lock_ofd_remains_exclusive_after_sender_closes(channels, tmp_path):
    import fcntl

    a, b = channels
    path = tmp_path / "original.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    probe = os.open(path, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    await a.send("owned", descriptors=(fd,))
    received = await b.receive("owned")
    assert len(received.descriptors) == 1
    os.close(fd)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not os.get_inheritable(received.descriptors[0])
    finally:
        os.close(received.descriptors[0])
    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.close(probe)


async def test_drain_owns_native_descendant_that_created_a_separate_session(tmp_path):
    import subprocess
    import sys

    from umi.competition_reward_writer_broker import _drain_child, _own_child_tree

    _own_child_tree()
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(300)'],"
            "start_new_session=True);"
            "print(p.pid,flush=True);os._exit(7)",
        ],
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    assert child.stdout is not None
    descendant = int(await asyncio.to_thread(child.stdout.readline))
    try:
        await asyncio.wait_for(_drain_child(child, left, cancel=False), 10)
        assert child.returncode == 7
        with pytest.raises(ProcessLookupError):
            os.kill(descendant, 0)
    finally:
        left.close()
        right.close()
        child.stdout.close()


def test_worker_permission_failure_logs_native_frames_without_private_paths():
    import subprocess
    import sys
    from pathlib import Path

    code = """
import os, socket, sys
sys.path.insert(0, sys.argv[1])
from umi import competition_reward_writer_broker_worker as worker
left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
def unavailable(_args):
    raise PermissionError(13, 'private-capability-token', '/private-wallet-secret')
worker._installed_account = unavailable
try:
    worker.main(['--unit','fixture.service','--config','/fixture-config',
      '--standing-boot','/fixture-boot','--held-approval','/fixture-held',
      '--history','current','--through-block','1','--socket-fd',str(right.detach()),
      '--parent-pid',str(os.getppid()),'--readiness-only',
      '--launch','/fixture-launch','--launch-sha256','aa'*32,
      '--preparation-approval','/fixture-preparation',
      '--preparation-approval-sha256','bb'*32])
finally:
    left.close()
"""
    result = subprocess.run(
        ["sudo", "-n", sys.executable, "-B", "-c", code, str(Path(__file__).parents[1] / "src")],
        capture_output=True,
        timeout=15,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 1
    output = (result.stdout + result.stderr).decode()
    assert "permission_denied" in output
    assert "umi.competition_reward_writer_broker_worker" in output
    assert "source_frames" in output
    assert "private-capability-token" not in output and "private-wallet-secret" not in output
