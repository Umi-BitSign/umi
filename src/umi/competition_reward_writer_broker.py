"""Root broker retaining staging ownership through native child review and drain."""

from __future__ import annotations

import asyncio
import ctypes
import fcntl
import hashlib
import logging
import os
import signal
import socket
import stat
import subprocess
import time
from contextlib import suppress
from pathlib import Path

from .competition_reward_history_preparation import (
    StandingHistoryPreparationApproval,
    _control,
    hold_history_preparation_lease,
)
from .competition_reward_history_preparation_runtime import (
    HistoryPreparationLaunch,
    _readonly_source,
    preparation_source_identity,
)
from .competition_reward_writer_broker_channel import WriterBrokerChannel
from .competition_reward_writer_review import select_stopped_writer_boot
from .competition_reward_writer_selection import (
    _journal_path,
    hold_writer_history_selection,
    recover_writer_history_selection,
)
from .open_competition import digest
from .protocol import canonical_json_bytes

_LOG = logging.getLogger(__name__)


def _history_identities(root):
    values = {}
    for name in (".", "rounds.sqlite3", "rounds.lock"):
        value = (root / name).lstat()
        values[name] = [
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            stat.S_IMODE(value.st_mode),
        ]
    return values


def _retain_native_locks(message, paths, retained):
    """Retain duplicate original OFDs; no serialized capability is reconstructed."""
    if len(message.descriptors) != len(paths):
        for descriptor in message.descriptors:
            os.close(descriptor)
        raise ValueError("writer child did not transfer its exact original locks")
    try:
        for descriptor, path in zip(message.descriptors, paths, strict=True):
            named, held = path.stat(), os.fstat(descriptor)
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or held.st_size > 65536:
                raise ValueError("writer child transferred another original lock")
            retained.append(
                (
                    descriptor,
                    path,
                    (held.st_dev, held.st_ino),
                    hashlib.sha256(os.pread(descriptor, 65537, 0)).hexdigest(),
                )
            )
        _recheck_native_locks(retained)
    except BaseException:
        for descriptor in message.descriptors:
            if all(item[0] != descriptor for item in retained):
                os.close(descriptor)
        raise


def _recheck_native_locks(retained):
    for descriptor, path, expected, checksum in retained:
        named, held = path.stat(), os.fstat(descriptor)
        if (
            (named.st_dev, named.st_ino) != expected
            or (held.st_dev, held.st_ino) != expected
            or hashlib.sha256(os.pread(descriptor, 65537, 0)).hexdigest() != checksum
        ):
            raise ValueError("retained original writer lock changed")
        probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise ValueError("retained original writer lock is no longer exclusive")
        finally:
            os.close(probe)


def writer_broker_command(anchor, args, descriptor):
    """Fixed root-controlled source/venv, explicit installed config and private FD."""
    selected = select_stopped_writer_boot(
        anchor, args.standing_boot, held_approval=args.held_approval
    )
    raw, launch_identity = _control(args.launch, 64 * 1024)
    launch = HistoryPreparationLaunch.model_validate_json(raw)
    approval_raw, approval_identity = _control(args.preparation_approval, 64 * 1024)
    approval = StandingHistoryPreparationApproval.model_validate_json(approval_raw)
    if (
        canonical_json_bytes(launch) != raw
        or canonical_json_bytes(approval) != approval_raw
        or (
            launch.preparation_approval_sha256 != digest(approval)
            or approval.standing_boot_raw_sha256 != selected.boot_raw_sha256
            or approval.source_config_sha256 != digest(anchor.config)
            or approval.installation_receipt_sha256 != anchor.receipt_sha256
            or approval.history != args.history
        )
    ):
        raise ValueError("writer launch differs from original authenticated preparation")
    source, runtime = Path(launch.source_root), Path(launch.python_root)
    for value in (source, runtime):
        _readonly_source(value, directory=True)
    if preparation_source_identity(source) != launch.source_tree_sha256:
        raise ValueError("writer broker source changed")
    target = approval.through_block if launch.through_block is None else launch.through_block
    series = (
        selected.config.series if args.history == "current" else selected.config.predecessor_series
    )
    if (
        series is None
        or not series.recovery.authority.issued_at_block <= target <= approval.through_block
    ):
        raise ValueError("writer selection target exceeds preparation scope")
    command = [
        str(runtime / ".venv/bin/python"),
        "-I",
        "-S",
        "-B",
        "-u",
        "-c",
        "import sys;sys.path[:0]=[sys.argv.pop(1),sys.argv.pop(1)];"
        "from umi.competition_reward_writer_broker_worker import main;main()",
        str(source / "src"),
        str(runtime / ".venv/lib/python3.12/site-packages"),
        "--unit",
        args.unit,
        "--config",
        str(args.config),
        "--standing-boot",
        str(args.standing_boot),
        "--held-approval",
        str(args.held_approval),
        "--history",
        args.history,
        "--through-block",
        str(target),
        "--socket-fd",
        str(descriptor),
        "--parent-pid",
        str(os.getpid()),
    ]
    if args.readiness_only:
        command.append("--readiness-only")
    return command, approval, (launch_identity, approval_identity)


def _own_child_tree():
    # Native verifier workers can create their own sessions. Become their
    # process-local subreaper so unexpected parent exit cannot orphan them
    # outside our ownership/drain boundary.
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "writer broker cannot own descendant lifecycle")


def _adopted_children():
    values = []
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            body = (path / "stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(body[1]) == os.getpid():
            values.append((int(path.name), body[19]))
    return values


async def _drain_child(child, endpoint, *, cancel):
    """Drain child plus adopted native descendants, including separate sessions."""
    started, last_report = time.monotonic(), 0.0
    signaled = set()
    if cancel:
        endpoint.close()
        with suppress(ProcessLookupError):
            child.send_signal(signal.SIGTERM)
    while True:
        child.poll()
        live = _adopted_children()
        for pid, birth in live:
            if pid == child.pid:
                continue
            # No other asynchronous children are launched by this fresh root
            # broker. An adopted process belongs to the pinned worker tree.
            try:
                ended, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            if ended:
                continue
            if (pid, birth) not in signaled:
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGTERM)
                signaled.add((pid, birth))
        if child.returncode is not None and not _adopted_children():
            break
        if time.monotonic() - last_report >= 25:
            _LOG.info(
                "writer_broker_progress %s",
                {
                    "stage": "native_child_drain",
                    "state": "draining",
                    "elapsed_seconds": time.monotonic() - started,
                    "eta_seconds": None,
                    "eta_basis": "waiting_for_native_workers_and_original_owner_release",
                    "retained_children": len(live),
                },
            )
            last_report = time.monotonic()
        try:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            continue
    child.wait()


async def launch_writer_history_selection(anchor, args, stop):
    if (os.getuid(), os.geteuid()) != (0, 0):
        raise ValueError("writer selection requires actual root broker")
    _own_child_tree()
    parent_socket, worker_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    worker_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child = None
    started = time.monotonic()
    selection = None
    interrupted = False
    result = None
    retained = []
    child_quiescent = False
    active_preparation = None
    try:
        command, approval, controls = writer_broker_command(anchor, args, worker_socket.fileno())
        child = subprocess.Popen(
            command,
            pass_fds=(worker_socket.fileno(),),
            close_fds=True,
            start_new_session=True,
            env={"PATH": "/usr/bin", "LANG": "C.UTF-8"},
        )
        worker_socket.close()
        channel = WriterBrokerChannel(
            parent_socket, peer_pid=child.pid, peer_uid=anchor.service_uid
        )

        def recheck():
            anchor.recheck_for_parent_repair()
            _recheck_native_locks(retained)
            for path, maximum, stamp, checksum in controls:
                if _control(path, maximum)[1] != (path, maximum, stamp, checksum):
                    raise ValueError("writer broker launch controls changed")
            if selection is not None:
                selection.recheck(allow_busy=not child_quiescent)
            elif active_preparation is not None:
                active_preparation.recheck()

        async def receive(action):
            nonlocal interrupted, child_quiescent
            task = asyncio.create_task(channel.receive())
            last = 0.0
            try:
                while not task.done():
                    recheck()
                    if stop.is_set() and not interrupted:
                        child.send_signal(signal.SIGTERM)
                        interrupted = True
                    if time.monotonic() - last >= 25:
                        _LOG.info(
                            "writer_broker_progress %s",
                            {
                                "stage": action,
                                "state": "stopping" if interrupted else "running",
                                "elapsed_seconds": time.monotonic() - started,
                                "eta_seconds": None,
                                "eta_basis": "native_child_progress",
                                "child_pid": child.pid,
                                "chain_submission_authorized": False,
                            },
                        )
                        last = time.monotonic()
                    await asyncio.wait({task}, timeout=1)
                message = task.result()
                if message.action in {
                    "original_reviewed",
                    "candidate_reviewed",
                    "failed",
                    "complete",
                }:
                    child_quiescent = True
                if message.action != action:
                    for descriptor in message.descriptors:
                        os.close(descriptor)
                    raise ValueError(
                        "native writer child did not complete required stage: " + message.action
                    )
                return message
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        if args.readiness_only:
            ready = await receive("namespace_ready")
            if ready.descriptors:
                for descriptor in ready.descriptors:
                    os.close(descriptor)
                raise ValueError("namespace readiness must not transfer original owner locks")
            with hold_history_preparation_lease(
                anchor, standing_boot=args.standing_boot, approval_path=args.preparation_approval
            ) as lease:
                active_preparation = lease
                try:
                    await channel.send("readiness")
                    result = (await receive("complete")).payload["result"]
                finally:
                    await _drain_child(child, parent_socket, cancel=result is None)
                if child.returncode:
                    raise ValueError("writer readiness child failed")
                lease.recheck()
                return result
        owned = await receive("owned")
        _retain_native_locks(
            owned, [Path(anchor.config.state_root) / "supervisor-process.lock"], retained
        )
        path = _journal_path(Path(approval.preparation_directory), args.operation)
        if path.exists() or path.is_symlink():
            recovered = recover_writer_history_selection(
                anchor,
                standing_boot=args.standing_boot,
                approval_path=args.preparation_approval,
                operation=args.operation,
            )
            if recovered == "committed":
                await channel.send("already_committed")
                result = (await receive("complete")).payload["result"]
                await _drain_child(child, parent_socket, cancel=False)
                if child.returncode:
                    raise ValueError("writer committed-repeat child failed")
                return result
        with hold_history_preparation_lease(
            anchor, standing_boot=args.standing_boot, approval_path=args.preparation_approval
        ) as lease:
            active_preparation = lease
            # Acquire the mechanical selection only after original native review
            # has drained its writes and frozen retained directory identities.
            await channel.send("begin")
            try:
                original = await receive("original_reviewed")
                root = lease.logical_history.parent
                paths = [
                    path
                    for path in (
                        root.parent / "standing-writer.lock",
                        root / "weights" / "standing-writer.lock",
                    )
                    if path.exists()
                ]
                _retain_native_locks(original, paths, retained)
                with hold_writer_history_selection(lease, operation=args.operation) as selected:
                    selection = selected
                    try:
                        selection.exchange()
                        child_quiescent = False
                        await channel.send(
                            "selected",
                            history_identities=_history_identities(lease.logical_history),
                        )
                        await receive("candidate_reviewed")
                        selection.commit()
                        await channel.send("committed")
                        result = (await receive("complete")).payload["result"]
                    except BaseException:
                        if selection.value["phase"] != "committed":
                            if not child_quiescent:
                                with suppress(ProcessLookupError):
                                    child.send_signal(signal.SIGTERM)
                                try:
                                    drained = await channel.receive()
                                    for descriptor in drained.descriptors:
                                        os.close(descriptor)
                                    if drained.action not in {
                                        "failed",
                                        "candidate_reviewed",
                                        "original_reviewed",
                                    }:
                                        raise ValueError(
                                            "writer child did not acknowledge native drain"
                                        )
                                    child_quiescent = True
                                except BaseException:
                                    await _drain_child(child, parent_socket, cancel=True)
                            _recheck_native_locks(retained)
                            selection.rollback()
                            await channel.send(
                                "rolled_back",
                                history_identities=_history_identities(lease.logical_history),
                            )
                        raise
                    finally:
                        # Keep the genuine staging lease and selection journal
                        # alive until the child and its provider workers drain.
                        await _drain_child(child, parent_socket, cancel=result is None)
                        if child.returncode and result is not None:
                            raise ValueError("writer child failed after native selection")
            except BaseException:
                if selection is None:
                    try:
                        await channel.send(
                            "rolled_back",
                            history_identities=_history_identities(lease.logical_history),
                        )
                    finally:
                        await _drain_child(child, parent_socket, cancel=True)
                raise
        return result
    finally:
        if child is not None:
            await _drain_child(child, parent_socket, cancel=child.poll() is None)
        parent_socket.close()
        worker_socket.close()
        for descriptor, _, _, _ in retained:
            os.close(descriptor)
