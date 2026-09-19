"""Opt-in root file-publication checks, only in the wallet-free rehearsal VM.

No unit is installed under /etc, loaded, stopped or started. Retained test files
live in one dedicated /var/lib directory. Authority issuers are synthetic; root
ownership, no-replace publication and safe descriptor traversal are real.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from umi import competition_host_switch as switch

from .test_competition_host_service import _plan
from .test_competition_host_service import case as case

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_SERVICE_REHEARSAL") != "1",
    reason="requires explicit root opt-in in the isolated service rehearsal VM",
)


@pytest.fixture
def files(case):
    assert os.geteuid() == 0
    root = Path("/var/lib/umi-successor-switch-file-rehearsal")
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0
    assert stat.S_IMODE(info.st_mode) == 0o700
    plan = _plan(case)
    with tempfile.TemporaryDirectory(prefix="run-", dir=root) as name:
        directory = Path(name)
        yield replace(
            plan,
            cleanup_unit_path=directory / plan.cleanup_unit_name,
            drop_in_path=directory / (plan.unit_name + ".d") / plan.drop_in_path.name,
        )


def _publish(files):
    marker = switch._create_switch_marker(files)
    try:
        switch._write_cleanup_once(files)
        switch._write_drop_in_once(files, marker)
    finally:
        os.close(marker)


def test_fixture_removes_its_own_disposable_tree(case):
    fixture = files.__wrapped__(case)
    plan = next(fixture)
    directory = plan.cleanup_unit_path.parent
    try:
        _publish(plan)
        assert directory.is_dir()
    finally:
        fixture.close()
    assert not directory.exists()


def test_actual_root_publication_preserves_exact_bytes_and_refuses_replace(files):
    _publish(files)
    switch._read_drop_in(files)
    for path, expected in (
        (files.cleanup_unit_path, files.cleanup_unit_bytes),
        (files.drop_in_path, files.drop_in_bytes),
    ):
        assert path.read_bytes() == expected
        info = path.lstat()
        assert info.st_uid == 0 and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o444
    with pytest.raises(ValueError, match="already exists"):
        switch._write_cleanup_once(files)
    with pytest.raises(FileExistsError):
        switch._create_switch_marker(files)
    switch._read_drop_in(files)


@pytest.mark.parametrize("change", ["bytes", "mode", "hardlink", "symlink", "fifo"])
def test_actual_root_publication_rejects_changed_companion(files, change):
    _publish(files)
    path = files.cleanup_unit_path
    if change == "bytes":
        path.chmod(0o600)
        path.write_bytes(b"x" * len(files.cleanup_unit_bytes))
        path.chmod(0o444)
    elif change == "mode":
        path.chmod(0o644)
    elif change == "hardlink":
        os.link(path, path.with_suffix(".retained-link"))
    else:
        preserved = path.with_suffix(".retained")
        path.rename(preserved)
        if change == "symlink":
            path.symlink_to(preserved)
        else:
            os.mkfifo(path, 0o444)
    with pytest.raises((OSError, ValueError)):
        switch._read_drop_in(files)
    assert files.drop_in_path.read_bytes() == files.drop_in_bytes


def test_actual_root_publication_rejects_publicly_writable_parent(files):
    files.cleanup_unit_path.parent.chmod(0o777)
    with pytest.raises(ValueError, match="root-controlled"):
        switch._write_cleanup_once(files)
    assert not files.cleanup_unit_path.exists()


def test_root_descriptor_is_supported():
    descriptor = switch._root_directory(Path("/"))
    try:
        assert os.fstat(descriptor).st_uid == 0
    finally:
        os.close(descriptor)


def test_durable_marker_precedes_any_companion_bytes(files):
    marker = switch._create_switch_marker(files)
    try:
        info = files.drop_in_path.parent.lstat()
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755
        assert list(files.drop_in_path.parent.iterdir()) == []
        assert not files.cleanup_unit_path.exists()
        assert info.st_ino == os.fstat(marker).st_ino
    finally:
        os.close(marker)
    # A new process sees the fixed marker, even without a file to load.
    with pytest.raises(FileExistsError):
        switch._create_switch_marker(files)


def test_retained_marker_cannot_be_replaced_during_publication(files):
    marker = switch._create_switch_marker(files)
    try:
        files.drop_in_path.parent.rename(files.drop_in_path.parent.with_suffix(".retained"))
        files.drop_in_path.parent.mkdir(mode=0o755)
        with pytest.raises(ValueError, match="replaced or changed"):
            switch._write_drop_in_once(files, marker)
        assert not files.drop_in_path.exists()
    finally:
        os.close(marker)
