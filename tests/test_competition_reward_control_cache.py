from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
import threading
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from umi.competition_chain_state import _cache_usage
from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.historical_header_recovery import HistoricalHeaderRecoveryPending

from .test_competition_reward_control_archive import _linked_history, check
from .test_competition_reward_control_archive import chain as chain
from .test_competition_reward_control_archive import chain_config as chain_config
from .test_competition_reward_control_archive import control as control
from .test_competition_reward_control_archive import historical as historical
from .test_competition_reward_control_archive import policy as policy
from .test_competition_reward_control_archive import series_case as series_case


def _provider(
    item: SimpleNamespace, directory: Path, **kwargs: Any
) -> HistoricalRewardControlProvider:
    return HistoricalRewardControlProvider(
        item.config,
        item.policy,
        historical_header_directory=directory,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
        **kwargs,
    )


def _files(root: Path) -> dict[Path, bytes]:
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _hints(provider: HistoricalRewardControlProvider) -> dict[str, str]:
    with closing(provider._hint_connect()) as db:
        return dict(db.execute("SELECT hash,encoded FROM historical_header_hints"))


async def test_physical_exhaustion_preserves_hints_and_current_control_then_resumes(
    historical, monkeypatch
):
    h = historical
    directory = h.item.provider._hint_directory
    await h.item.provider.aclose()
    capacity = 3 * 4096 + 137  # Partial pages must not round the physical limit up.
    h.item.provider = _provider(
        h.item, directory, historical_header_database_maximum_bytes=capacity
    )
    current_verifier = h.item.verifier.verify_many
    walk = await _linked_history(h, monkeypatch, 80)
    provider = h.item.provider
    before = _files(provider._cache_root)
    usage = _cache_usage(provider._cache_root, h.item.config.maximum_cache_bytes)
    with pytest.raises(HistoricalHeaderRecoveryPending, match="database needs capacity") as full:
        await provider.review_control(walk.raw, walk.metadata)
    assert full.value.__cause__.sqlite_errorcode == sqlite3.SQLITE_FULL
    retained = _hints(provider)
    cursor = dict(provider._historical_headers.progress)
    assert 0 < len(retained) < 80
    assert cursor and set(cursor.values()) <= set(retained.values())
    assert sum(map(len, retained.values())) < provider._historical_headers.maximum_bytes
    assert provider._hint_path.stat().st_size <= capacity
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(provider._hint_path.stat().st_mode) == 0o600
    original_database = provider._hint_path.read_bytes()
    with pytest.raises(HistoricalHeaderRecoveryPending, match="database needs capacity"):
        await provider.review_control(walk.raw, walk.metadata)
    assert _hints(provider) == retained
    assert provider._historical_headers.progress == cursor
    assert provider._hint_path.read_bytes() == original_database
    assert _files(provider._cache_root) == before
    assert _cache_usage(provider._cache_root, h.item.config.maximum_cache_bytes) == usage
    with closing(provider._connect()) as db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='historical_header_hints'"
        ).fetchall()

    # Use the fixture's injected current-finality ports for a real control read
    # while the historical database remains full.
    with monkeypatch.context() as current:
        current.setattr(provider, "_owned", False)
        current.setattr(h.item.verifier, "verify_many", current_verifier)
        observed = await provider.collect_control(h.item.hotkey)
        assert observed.snapshot.block_number == walk.head.height
    assert _files(provider._cache_root) == before

    await provider.aclose()
    h.item.provider = walk.owned(
        _provider(h.item, directory, historical_header_database_maximum_bytes=capacity)
    )
    assert _hints(h.item.provider) == retained
    assert not h.item.provider._historical_headers.progress
    with pytest.raises(HistoricalHeaderRecoveryPending, match="database needs capacity"):
        await h.item.provider.review_control(walk.raw, walk.metadata)
    assert _hints(h.item.provider) == retained

    await h.item.provider.aclose()
    h.item.provider = walk.owned(
        _provider(h.item, directory, historical_header_database_maximum_bytes=128 * 1024)
    )
    proof = await h.item.provider.review_control(walk.raw, walk.metadata)
    check(h, proof)
    assert proof.snapshot.block_number == walk.original.height
    assert h.blocks.get(walk.original.height) is None
    assert len(_hints(h.item.provider)) == 80
    assert all(walk.calls.count(block_hash) == 1 for block_hash in retained)
    assert len(set(walk.calls)) == 80
    assert _files(h.item.provider._cache_root) == before


async def test_each_connection_bounds_pages_and_checks_existing_oversize(control, tmp_path):
    item = control
    await item.provider.aclose()
    item.provider = _provider(
        item, tmp_path / "hints", historical_header_database_maximum_bytes=4 * 4096 + 37
    )
    provider = item.provider
    for _ in range(3):
        with closing(provider._hint_connect()) as db:
            assert db.execute("PRAGMA max_page_count").fetchone()[0] == 4
            assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert db.execute("PRAGMA synchronous").fetchone()[0] == 2
    provider._historical_headers._save("retained", "original")
    before = _files(provider._cache_root)
    # An independent connection has no inherited max_page_count. Simulate a
    # database grown outside this owner, then require the next open to reject it.
    with closing(sqlite3.connect(provider._hint_path, isolation_level=None)) as db:
        db.execute("CREATE TABLE growth (body BLOB)")
        db.execute("INSERT INTO growth VALUES (zeroblob(65536))")
    oversized = provider._hint_path.read_bytes()
    with pytest.raises(ValueError, match="physical byte ceiling"):
        provider._historical_headers._save("new", "not written")
    assert provider._hint_path.read_bytes() == oversized
    assert _files(provider._cache_root) == before

    await provider.aclose()
    with pytest.raises(ValueError, match="physical byte ceiling"):
        _provider(item, tmp_path / "hints", historical_header_database_maximum_bytes=4 * 4096)
    assert provider._hint_path.read_bytes() == oversized
    assert _files(provider._cache_root) == before
    item.provider = _provider(
        item, tmp_path / "hints", historical_header_database_maximum_bytes=128 * 1024
    )
    assert _hints(item.provider) == {"retained": "original"}


@pytest.mark.parametrize("relation", ["same", "ancestor", "descendant", "namespace"])
async def test_historical_directory_must_be_disjoint(control, relation):
    item = control
    root = item.provider._cache_root
    directory = {
        "same": root,
        "ancestor": root.parent,
        "descendant": root / "hints",
        "namespace": item.provider._path.parent,
    }[relation]
    before = _files(root)
    with pytest.raises(ValueError, match="disjoint"):
        _provider(item, directory)
    assert _files(root) == before
    assert (await item.provider.collect_control(item.hotkey)).control_sha256 is not None


@pytest.mark.parametrize(
    "unsafe",
    [
        "relative",
        "dotdot",
        "symlink",
        "parent_symlink",
        "directory_mode",
        "database_symlink",
        "database_hardlink",
        "database_mode",
        "database_fifo",
        "lock_symlink",
        "sidecar_symlink",
    ],
)
async def test_unsafe_hint_paths_are_rejected_without_modification(control, tmp_path, unsafe):
    directory = tmp_path / "hints"
    directory.mkdir(mode=0o700)
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"preserve")
    sentinel.chmod(0o600)
    database = directory / "historical-headers.sqlite3"
    if unsafe == "relative":
        directory = Path("hints")
    elif unsafe == "dotdot":
        directory = directory / ".." / "other"
    elif unsafe == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        directory = alias
    elif unsafe == "parent_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        directory = alias / "hints"
    elif unsafe == "directory_mode":
        directory.chmod(0o755)
    elif unsafe == "database_symlink":
        database.symlink_to(sentinel)
    elif unsafe == "database_hardlink":
        os.link(sentinel, database)
    elif unsafe == "database_mode":
        database.touch(mode=0o644)
    elif unsafe == "database_fifo":
        os.mkfifo(database, 0o600)
    elif unsafe == "lock_symlink":
        (directory / "owner.lock").symlink_to(sentinel)
    else:
        Path(f"{database}-journal").symlink_to(sentinel)
    before = _files(control.provider._cache_root)
    with pytest.raises((ValueError, OSError)):
        _provider(control, directory)
    assert sentinel.read_bytes() == b"preserve"
    assert _files(control.provider._cache_root) == before


async def test_owner_contention_and_constructor_failure_release_lock(control, tmp_path):
    item = control
    directory = tmp_path / "hints"
    # The historical lock is acquired first; a current-cache owner then causes
    # construction to fail. The next attempt must be able to acquire both.
    with pytest.raises(BlockingIOError):
        _provider(item, directory)
    await item.provider.aclose()
    item.provider = _provider(item, directory)
    item.provider._historical_headers._save("retained", "original")
    other = SimpleNamespace(**vars(item))
    other.config = item.config.model_copy(update={"state_directory": str(tmp_path / "other")})
    before = _files(directory)
    for _ in range(2):
        with pytest.raises(BlockingIOError):
            _provider(other, directory)
        assert _files(directory) == before
        assert not Path(other.config.state_directory).exists()
    await item.provider.aclose()
    item.provider = _provider(item, directory)
    assert _hints(item.provider) == {"retained": "original"}


async def test_owner_lock_is_held_until_cancelled_write_drains(historical, monkeypatch):
    h = historical
    walk = await _linked_history(h, monkeypatch, 4)
    provider = h.item.provider
    entered, release = threading.Event(), threading.Event()
    save = provider._historical_headers._save

    def blocked(block_hash: str, encoded: str) -> None:
        entered.set()
        assert release.wait(10)
        save(block_hash, encoded)

    monkeypatch.setattr(provider._historical_headers, "_save", blocked)
    task = asyncio.create_task(provider.review_control(walk.raw, walk.metadata))
    closing_task = None
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        closing_task = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0.02)
        assert not task.done() and not closing_task.done()
        with pytest.raises(BlockingIOError):
            _provider(h.item, provider._hint_directory)
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        if closing_task is not None:
            await closing_task
    assert provider._hint_lock is None
    h.item.provider = walk.owned(h.reopen())
    assert len(_hints(h.item.provider)) == 1
    check(h, await h.item.provider.review_control(walk.raw, walk.metadata))


@pytest.mark.parametrize(
    "code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_CORRUPT]
)
async def test_non_capacity_sqlite_errors_are_not_translated(historical, monkeypatch, code):
    h = historical
    walk = await _linked_history(h, monkeypatch, 4)
    error = sqlite3.OperationalError("original sqlite failure")
    error.sqlite_errorcode = code

    def failed(block_hash: str) -> None:
        raise error

    monkeypatch.setattr(h.item.provider._historical_headers, "_load", failed)
    with pytest.raises(sqlite3.OperationalError) as raised:
        await h.item.provider.review_control(walk.raw, walk.metadata)
    assert raised.value is error
    assert not h.item.provider._historical_headers.progress


@pytest.mark.parametrize("field", ["evidence", "metadata"])
@pytest.mark.parametrize("value", [None, "text", bytearray(b"mutable")])
async def test_retained_proof_requires_bytes_before_hashing(historical, field, value):
    h = historical
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    with pytest.raises(ValueError, match="selected owned proof"):
        check(h, replace(proof, **{field: value}))


@pytest.mark.parametrize("capacity", [True, 0, -1, 1.5])
def test_database_capacity_must_be_a_positive_integer(control, tmp_path, capacity):
    with pytest.raises(ValueError, match="database capacity must be positive"):
        _provider(control, tmp_path / "hints", historical_header_database_maximum_bytes=capacity)
    assert not (tmp_path / "hints").exists()
