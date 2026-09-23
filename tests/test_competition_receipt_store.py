"""Actual interrupted receipt writes, reached through the native host sealer."""

from __future__ import annotations

import fcntl
import hashlib
import os
import signal
import subprocess
import sys

import pytest

from umi import competition_host_activation as activation

PAYLOAD = b'{"schema":"fixture-receipt/1","retained":"original history"}'


@pytest.fixture
def receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(activation, "_root_owner_uid", os.getuid)
    root = tmp_path / "anchor"
    root.mkdir(mode=0o700)
    return root / "installation-receipt.json"


def pending(receipt, payload=PAYLOAD):
    return receipt.parent / (
        ".installation-receipt." + hashlib.sha256(payload).hexdigest() + ".pending"
    )


def publish(receipt, payload=PAYLOAD):
    activation._write_root_receipt_once(receipt, payload)


CHILD = r"""
import os, signal, stat, sys
from pathlib import Path
from umi import competition_host_activation as activation
from umi import competition_receipt_store as store

activation._root_owner_uid = os.getuid
path, boundary, payload = Path(sys.argv[1]), sys.argv[2], bytes.fromhex(sys.argv[3])
write, fsync, link, unlink = os.write, os.fsync, os.link, os.unlink
def kill(): os.kill(os.getpid(), signal.SIGKILL)
def interrupted_write(fd, raw):
    if boundary == "partial_write":
        write(fd, raw[:13]); kill()
    result = write(fd, raw)
    if boundary == "complete_write": kill()
    return result
def interrupted_fsync(fd):
    fsync(fd)
    info = os.fstat(fd)
    if boundary == "pending_name" and stat.S_ISDIR(info.st_mode): kill()
    if boundary == "sealed_file" and stat.S_ISREG(info.st_mode): kill()
def interrupted_link(*args, **kwargs):
    link(*args, **kwargs)
    if boundary == "published_link": kill()
def interrupted_unlink(*args, **kwargs):
    unlink(*args, **kwargs)
    if boundary == "pending_removed": kill()
store.os.write, store.os.fsync = interrupted_write, interrupted_fsync
store.os.link, store.os.unlink = interrupted_link, interrupted_unlink
activation._write_root_receipt_once(path, payload)
raise SystemExit("fault injection missed")
"""


@pytest.mark.parametrize(
    "boundary",
    [
        "pending_name",
        "partial_write",
        "complete_write",
        "sealed_file",
        "published_link",
        "pending_removed",
    ],
)
def test_killed_sealer_recovers_exact_receipt_without_publishing_partial_body(receipt, boundary):
    completed = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, str(receipt), boundary, PAYLOAD.hex()],
        capture_output=True,
        timeout=20,
    )
    assert completed.returncode == -signal.SIGKILL, completed.stderr.decode()
    if receipt.exists():
        assert receipt.read_bytes() == PAYLOAD
    if boundary == "published_link":
        # Readers fail closed until the writer removes its proven second name.
        with pytest.raises(activation.HostActivationError, match="unsafe"):
            activation._read_root_control_path(receipt, 1024, modes={0o444})
    publish(receipt)
    identity = receipt.stat().st_ino
    publish(receipt)
    assert activation._read_root_control_path(receipt, 1024, modes={0o444}) == PAYLOAD
    assert receipt.stat().st_ino == identity
    assert receipt.stat().st_nlink == 1
    assert receipt.stat().st_mode & 0o777 == 0o444
    assert set(receipt.parent.iterdir()) == {receipt}


def test_partial_receipt_cannot_be_resumed_for_another_target(receipt):
    p = pending(receipt)
    p.write_bytes(PAYLOAD[:8])
    p.chmod(0o600)
    with pytest.raises(activation.HostActivationError, match="different interrupted publication"):
        publish(receipt, PAYLOAD.replace(b"original", b"replaced"))
    assert p.read_bytes() == PAYLOAD[:8] and not receipt.exists()
    publish(receipt)


@pytest.mark.parametrize(
    "fault", ["symlink", "hardlink", "foreign_content", "unsafe_mode", "sealed_partial"]
)
def test_unsafe_pending_file_is_preserved_and_rejected(receipt, fault):
    p = pending(receipt)
    p.write_bytes(PAYLOAD[:8])
    p.chmod(0o600)
    if fault == "symlink":
        p.rename(receipt.parent / "retained")
        p.symlink_to(receipt.parent / "retained")
    elif fault == "hardlink":
        os.link(p, receipt.parent / "retained")
    elif fault == "foreign_content":
        p.write_bytes(b"different")
    else:
        p.chmod(0o644 if fault == "unsafe_mode" else 0o444)
    before = p.read_bytes()
    with pytest.raises(activation.HostActivationError):
        publish(receipt)
    assert p.read_bytes() == before and not receipt.exists()


@pytest.mark.parametrize("fault", ["different_final", "unrelated_pending", "extra_hardlink"])
def test_existing_receipt_never_overwritten_or_unknown_link_removed(receipt, fault):
    publish(receipt)
    p = pending(receipt)
    if fault == "different_final":
        target = PAYLOAD.replace(b"original", b"replaced")
    elif fault == "unrelated_pending":
        p.write_bytes(PAYLOAD)
        p.chmod(0o444)
        target = PAYLOAD
    else:
        os.link(receipt, receipt.parent / "foreign-link")
        target = PAYLOAD
    before = set(receipt.parent.iterdir())
    with pytest.raises(activation.HostActivationError):
        publish(receipt, target)
    assert set(receipt.parent.iterdir()) == before
    assert receipt.read_bytes() == PAYLOAD


def test_concurrent_writer_cannot_enter_same_receipt_directory(receipt):
    fd = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(activation.HostActivationError):
            publish(receipt)
    finally:
        os.close(fd)
    assert not receipt.exists() and not pending(receipt).exists()
    publish(receipt)


@pytest.mark.parametrize("mode", [0o400, 0o440, 0o444])
def test_historical_sealed_receipt_keeps_exact_inode_and_mode(receipt, mode):
    receipt.write_bytes(PAYLOAD)
    receipt.chmod(mode)
    identity = receipt.stat().st_ino
    publish(receipt)
    assert receipt.stat().st_ino == identity and receipt.stat().st_mode & 0o777 == mode


@pytest.mark.parametrize(
    "payload", [b"", b"x" * (activation.MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES + 1)]
)
def test_invalid_size_does_not_create_pending_or_final_receipt(receipt, payload):
    with pytest.raises(activation.HostActivationError, match="size"):
        publish(receipt, payload)
    assert not list(receipt.parent.iterdir())
