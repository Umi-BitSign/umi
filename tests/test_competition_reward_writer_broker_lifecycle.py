"""Actual root broker lifecycle with native selection and explicit worker fault port.

The child is an OS-level protocol actor holding real original flocks. It issues
no native history/control capability. Native reconciliation is qualified by the
separate exchange fixtures; this file isolates root orchestration failure order.
Run explicitly as root. No installed service or production path is accessed.
"""

import asyncio
import fcntl
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_preparation as preparation
from umi import competition_reward_writer_broker as broker
from umi import competition_reward_writer_selection as selection
from umi.protocol import canonical_json_bytes

from .test_competition_reward_writer_adoption import signed_adoptions
from .test_competition_reward_writer_selection import (  # noqa: F401
    activation_case,
    anchor_case,
    boot_inputs,
    chain,
    chain_config,
    control,
    explicit,
    installed_case,
    limits,
    package_case,
    package_limits,
    policy,
    release_identity,
    replay_limits,
    series_case,
    staging_case,
    successor_release,
    trusted_ports,
    worker_capacity,
)
from .test_competition_reward_writer_selection import prepared as native_prepared  # noqa: F401

pytestmark = pytest.mark.skipif(os.getuid() != 0, reason="actual root broker qualification")


@pytest.fixture
def prepared(request, monkeypatch):
    # Root is the service identity in these existing portable anchor fixtures.
    # The production schema excludes GID zero; use its existing group-1 port.
    # Root identity checks, signed anchor and lease issuers, filesystem owners,
    # actual flock exclusion, SO_PASSCRED, SCM_RIGHTS and renameat2 are unchanged.
    monkeypatch.setattr(preparation, "_service_gid", lambda _uid: 1)
    return request.getfixturevalue("native_prepared")


PEER = r"""
import array, fcntl, json, os, signal, socket, subprocess, sys, time
from pathlib import Path
fd, mode, root, eventdir, gid, *paths = sys.argv[1:]
root, eventdir, gid = Path(root), Path(eventdir), int(gid)
s=socket.socket(fileno=int(fd)); held=[]; stopped=False
def event(name):
    (eventdir/name).write_text(str(time.monotonic_ns()))
def terminate(*_):
    global stopped
    stopped=True
signal.signal(signal.SIGTERM,terminate)
def lock(path):
    descriptor=os.open(path,os.O_RDWR)
    fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
    held.append(descriptor)
    return descriptor
def send(action, fds=()):
    anc=[] if not fds else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))]
    s.sendmsg([json.dumps({'action':action,'payload':{}}).encode()],anc)
def receive():
    raw=s.recv(16384)
    if not raw: raise ConnectionError('root closed')
    return json.loads(raw)['action']
send('owned',[lock(paths[0])]);assert receive()=='begin'
send('original_reviewed',[lock(p) for p in paths[1:]])
assert receive()=='selected'
sidecar=root/'rounds.sqlite3-journal'
sidecar.write_bytes(b'active native-write fault port');sidecar.chmod(0o600)
os.chown(sidecar,os.getuid(),gid)
event('candidate_started')
if mode in {'child_death','hot_child_death'}:
    descendant = r'''import os,signal,sys,time
from pathlib import Path
sidecar,eventdir,mode=sys.argv[1:];eventdir=Path(eventdir)
def finish(*_):
    if mode!='hot_child_death':Path(sidecar).unlink()
    (eventdir/'descendant_drained').write_text(str(time.monotonic_ns()))
    raise SystemExit(0)
signal.signal(signal.SIGTERM,finish)
(eventdir/'descendant_ready').write_text(str(os.getpid()))
while True:time.sleep(.01)
'''
    process=subprocess.Popen([sys.executable,'-c',descendant,str(sidecar),str(eventdir),mode],
                             start_new_session=True,close_fds=True)
    while not (eventdir/'descendant_ready').exists():time.sleep(.01)
    event('child_abrupt_exit');os._exit(9)
if mode=='channel_loss':s.close()
while not stopped:time.sleep(.01)
time.sleep(.1)
sidecar.unlink();event('native_quiescent')
if mode not in {'channel_loss'}:
    send('failed')
    try:
        assert receive()=='rolled_back'
        event('child_observed_rollback')
    except ConnectionError:
        pass
event('child_drained')
for descriptor in held:os.close(descriptor)
"""


def assert_locked(paths):
    for path in paths:
        descriptor = os.open(path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)


@pytest.mark.parametrize(
    "fault", ["parent_recheck", "channel_loss", "child_death", "hot_child_death", "root_stop"]
)
@pytest.mark.parametrize("supplemental", [False, True])
async def test_actual_root_orchestration_drains_before_rollback(
    prepared, monkeypatch, tmp_path, fault, supplemental, request
):
    case = prepared
    assert (os.getuid(), os.geteuid()) == (0, 0)
    eventdir = tmp_path / "fault-events"
    eventdir.mkdir(mode=0o700)
    root = case.original.parent
    weights = root / "weights"
    weights.mkdir(mode=0o700)
    paths = [
        case.writer_lock,
        root.parent / "standing-writer.lock",
        weights / "standing-writer.lock",
    ]
    for path in paths[1:]:
        path.write_bytes(b"original retained native lock")
        path.chmod(0o600)
    original_inode = case.original.stat().st_ino
    candidate_inode = (case.root / "history").stat().st_ino
    original_db_inode = (case.original / "rounds.sqlite3").stat().st_ino
    candidate_db_inode = (case.root / "history" / "rounds.sqlite3").stat().st_ino
    controls = (preparation._control(case.path, 65536)[1],)
    adoption_path = None
    if supplemental:
        adoption_path = tmp_path / "root-selected-adoptions.json"
        adoptions = signed_adoptions(case.config, request.getfixturevalue("series_case"))
        case.save(adoption_path, canonical_json_bytes(adoptions))
        controls += (preparation._control(adoption_path, 256 * 1024)[1],)

    def command(_anchor, _args, descriptor):
        return (
            [
                sys.executable,
                "-c",
                PEER,
                str(descriptor),
                fault,
                str(case.original),
                str(eventdir),
                str(case.approval.service_gid),
                *map(str, paths),
            ],
            case.approval,
            controls,
        )

    monkeypatch.setattr(broker, "writer_broker_command", command)
    original_recheck = broker._recheck_native_locks
    original_rollback = selection.WriterHistorySelection.rollback
    injected = False
    rollbacks = []

    def recheck(retained):
        nonlocal injected
        original_recheck(retained)
        if fault == "parent_recheck" and (eventdir / "candidate_started").exists() and not injected:
            injected = True
            raise ValueError("injected parent inspection failure during candidate write")

    def rollback(current):
        if current.value["phase"] != "rolled_back":
            assert_locked(paths)
            assert_locked([case.root / "preparation.lock"])
            completed = eventdir / (
                "descendant_drained"
                if fault in {"child_death", "hot_child_death"}
                else "native_quiescent"
            )
            assert completed.exists(), "rollback attempted before candidate work drained"
            assert case.original.stat().st_ino == candidate_inode
            assert (case.root / "history").stat().st_ino == original_inode
            if fault in {"child_death", "hot_child_death"}:
                descendant = int((eventdir / "descendant_ready").read_text())
                with pytest.raises(ProcessLookupError):
                    os.kill(descendant, 0)
            rollbacks.append(current.value["phase"])
        return original_rollback(current)

    monkeypatch.setattr(broker, "_recheck_native_locks", recheck)
    monkeypatch.setattr(selection.WriterHistorySelection, "rollback", rollback)
    stop = asyncio.Event()

    async def request_stop():
        while not (eventdir / "candidate_started").exists():
            await asyncio.sleep(0.01)
        stop.set()

    stopping = asyncio.create_task(request_stop()) if fault == "root_stop" else None
    args = SimpleNamespace(
        standing_boot=case.boot,
        held_approval=case.held,
        preparation_approval=case.path,
        operation="qualified-v1",
        readiness_only=False,
        reward_adoptions=adoption_path,
    )
    try:
        with pytest.raises((ValueError, ConnectionError, OSError)):
            await asyncio.wait_for(
                broker.launch_writer_history_selection(case.anchor, args, stop), 15
            )
    finally:
        if stopping is not None:
            stopping.cancel()
            await asyncio.gather(stopping, return_exceptions=True)
    assert rollbacks
    if fault == "parent_recheck":
        assert injected
    value = json.loads(selection._journal_path(case.root, "qualified-v1").read_bytes())
    if fault == "hot_child_death":
        assert value["phase"] == "exchanged"
        assert case.original.stat().st_ino == candidate_inode
        assert (case.root / "history").stat().st_ino == original_inode
        assert (case.original / "rounds.sqlite3-journal").is_file()
        assert (case.original / "rounds.sqlite3").stat().st_ino == candidate_db_inode
        assert (case.root / "history" / "rounds.sqlite3").stat().st_ino == original_db_inode
    else:
        assert value["phase"] == "rolled_back"
        assert case.original.stat().st_ino == original_inode
        assert (case.root / "history").stat().st_ino == candidate_inode
        assert (case.original / "rounds.sqlite3").stat().st_ino == original_db_inode
        assert (case.root / "history" / "rounds.sqlite3").stat().st_ino == candidate_db_inode
    assert case.held.read_bytes() == case.hold_bytes
    assert not Path(case.config.approval_path).exists()
    for path in [*paths, case.root / "preparation.lock"]:
        descriptor = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
