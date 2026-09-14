from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_materialization as material
from umi import competition_materialization_retention as retention

from .test_competition_materialization import (  # noqa: F401
    _stage,
    chain_config,
    explicit,
    limits,
    package_case,
    package_limits,
    policy,
    release_identity,
    replay_limits,
    successor_case,
    successor_chain,
    successor_release,
    trusted_ports,
    v3_predecessor,
    worker_capacity,
)
from .test_competition_materialization import (
    case as case,
)
from .test_competition_materialization import (
    installed as installed,
)


def _retire(installed, retained=None):
    case = installed.case
    if retained is None:
        retained = {case.selection.directive_sha256: (case.selection, case.files)}
    return retention.retire_redundant_successor_inputs(
        anchor=installed.anchor, limits=case.limits, retained=retained
    )


def test_exact_duplicates_retire_but_current_and_durable_package_remain(installed):
    case = installed.case
    current_before = material._tree(installed.source / "current", case.limits, sealed=True)
    package_before = {p.name: p.read_bytes() for p in case.files.package_path.iterdir()}
    assert _retire(installed) == 1
    assert not installed.first.path.exists()
    assert _retire(installed) == 0
    assert material._tree(installed.source / "current", case.limits, sealed=True) == current_before
    assert {p.name: p.read_bytes() for p in case.files.package_path.iterdir()} == package_before
    # A fresh materialization remains reconstructable from the retained source.
    replacement = _stage(case)
    replacement.recheck()


def test_unretained_and_partial_stages_are_preserved(installed):
    partial = installed.cache / ("stage-" + "d" * 32)
    partial.mkdir(mode=0o700)
    note = partial / "partial"
    note.write_bytes(b"interrupted input")
    note.chmod(0o600)
    assert _retire(installed, {}) == 0
    assert installed.first.path.exists() and note.read_bytes() == b"interrupted input"
    assert _retire(installed) == 1
    assert note.read_bytes() == b"interrupted input"


@pytest.mark.parametrize("after_unlinks", [0, 1, 4])
def test_interrupted_retirement_resumes_from_durable_sources(installed, monkeypatch, after_unlinks):
    original = retention.os.unlink
    calls = 0

    def interrupted(*args, **kwargs):
        nonlocal calls
        if calls == after_unlinks:
            raise OSError("injected interruption")
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(retention.os, "unlink", interrupted)
    with pytest.raises(OSError, match="injected interruption"):
        _retire(installed)
    pending = list(installed.cache.glob("retiring-*"))
    assert len(pending) == 1 and not installed.first.path.exists()
    assert (installed.source / "current").exists()
    monkeypatch.setattr(retention.os, "unlink", original)
    assert _retire(installed) == 1
    assert not pending[0].exists()


def test_partial_retirement_refuses_missing_backup(installed, monkeypatch):
    def interrupted(*args):
        raise OSError("injected interruption")

    original = retention._remove_verified_tree
    monkeypatch.setattr(retention, "_remove_verified_tree", interrupted)
    with pytest.raises(OSError):
        _retire(installed)
    pending = next(installed.cache.glob("retiring-*"))
    before = material._tree(pending, installed.case.limits, sealed=False)
    monkeypatch.setattr(retention, "_remove_verified_tree", original)
    with pytest.raises(ValueError, match="lost its durable recovery source"):
        _retire(installed, {})
    assert material._tree(pending, installed.case.limits, sealed=False) == before


def test_retirement_refuses_self_backed_package(installed):
    case = installed.case
    files = replace(case.files, package_path=installed.first.path / "package")
    with pytest.raises(ValueError, match="separate durable recovery package"):
        _retire(installed, {case.selection.directive_sha256: (case.selection, files)})
    installed.first.recheck()


@pytest.mark.parametrize("fault", ["extra", "changed"])
def test_resume_rejects_extra_or_changed_bytes_before_unlink(installed, monkeypatch, fault):
    original = retention._remove_verified_tree

    def interrupted(*args):
        raise OSError("injected interruption")

    monkeypatch.setattr(retention, "_remove_verified_tree", interrupted)
    with pytest.raises(OSError):
        _retire(installed)
    pending = next(installed.cache.glob("retiring-*"))
    pending.chmod(0o700)
    extra = (
        pending / "unrelated"
        if fault == "extra"
        else pending / material.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME
    )
    if extra.exists():
        extra.chmod(0o600)
    extra.write_bytes(b"must remain")
    extra.chmod(0o400)
    monkeypatch.setattr(retention, "_remove_verified_tree", original)
    with pytest.raises(ValueError, match="differs from its durable recovery inputs"):
        _retire(installed)
    assert extra.read_bytes() == b"must remain"


def test_cleanup_never_follows_a_link(installed):
    staged = installed.first.path
    victim = installed.case.state / "keep.txt"
    victim.write_bytes(b"keep")
    staged.chmod(0o700)
    os.symlink(victim, staged / "link")
    with pytest.raises(ValueError, match="link or special file"):
        _retire(installed)
    assert victim.read_bytes() == b"keep"


@pytest.mark.parametrize("fault", ["unknown", "duplicate", "overflow"])
def test_cache_name_rescan_stops_at_first_invalid_entry(monkeypatch, fault):
    first = "stage-" + "a" * 32
    second = {"unknown": "unrelated", "duplicate": first, "overflow": "stage-" + "b" * 32}[fault]

    def entries():
        yield SimpleNamespace(name=first)
        yield SimpleNamespace(name=second)
        raise AssertionError("invalid input must stop the iterator immediately")

    @contextmanager
    def scan(fd):
        yield entries()

    monkeypatch.setattr(retention.os, "scandir", scan)
    with pytest.raises(ValueError, match="changed after inspection"):
        retention._cache_names(10, SimpleNamespace(maximum_stages=1 if fault == "overflow" else 3))


def test_retirement_rejects_current_inode_alias_before_opening_package():
    records = {"": ((1, 2), None)}
    with pytest.raises(ValueError, match="aliases current inputs"):
        retention._require_separate_inodes(records, records, None, None)


def test_unlink_rescan_stops_at_first_unexpected_child(installed, monkeypatch):
    records = material._tree(installed.first.path, installed.case.limits, sealed=True)[1]

    def entries():
        yield SimpleNamespace(name="unexpected")
        raise AssertionError("unexpected child must stop the iterator before deletion")

    @contextmanager
    def scan(fd):
        yield entries()

    monkeypatch.setattr(retention.os, "scandir", scan)
    cache_fd = os.open(installed.cache, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="retiring directory entries changed"):
            retention._remove_verified_tree(cache_fd, installed.first.path.name, records)
    finally:
        os.close(cache_fd)
    assert installed.first.path.stat().st_mode & 0o777 == 0o555
