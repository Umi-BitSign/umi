"""Long-running intake retains admission evidence without accumulating idle polls."""

import hashlib
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_chain import (
    CompetitionChainConfig,
    FinalizedRegistrationProvider,
    RegistrationCacheFull,
)
from umi.protocol import canonical_json_bytes

from .test_competition_chain import _HEIGHT
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_open_competition import policy as policy


def advance(chain, height):
    chain.finality.ref = replace(
        chain.finality.ref,
        block_number=height,
        block_hash="0x" + hashlib.sha256(str(height).encode()).hexdigest(),
    )


def retained_rows(provider):
    with sqlite3.connect(provider._path) as db:
        return db.execute("SELECT * FROM captures ORDER BY block").fetchall()


def test_twenty_gib_operational_budget_preserves_legacy_default(chain_config):
    original = chain_config.model_dump(mode="json", by_alias=True)
    assert original["maximum_cache_bytes"] == 256 * 1024**2
    enlarged = CompetitionChainConfig.model_validate(
        {**original, "maximum_cache_bytes": 20 * 1024**3}
    )
    assert enlarged.maximum_cache_bytes == 21_474_836_480
    assert enlarged.model_dump(mode="json", by_alias=True) == {
        **original,
        "maximum_cache_bytes": 21_474_836_480,
    }


async def test_repeated_rollovers_preserve_receipts_recent_window_and_restart_guard(chain):
    first = await chain.provider.collect()
    original = retained_rows(chain.provider)[0]
    pinned = {_HEIGHT}
    provider = FinalizedRegistrationProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
        retained_capture_blocks=lambda: frozenset(pinned),
    )
    # The same existing cache/config can be upgraded without rewriting its binding.
    assert canonical_json_bytes(provider.config) == canonical_json_bytes(chain.config)
    window = chain.policy.maximum_snapshot_age_blocks
    with sqlite3.connect(provider._path) as db:
        artifact_bytes = db.execute("SELECT SUM(length(body)) FROM artifacts").fetchone()[0]
    provider.config = provider.config.model_copy(
        update={"maximum_cache_bytes": artifact_bytes + (window + 4) * len(original[4])}
    )
    # Enough collections to exhaust the old append-only cache several times.
    for height in range(_HEIGHT + 1, _HEIGHT + 5 * window + 1):
        advance(chain, height)
        await provider.collect()
        if height == _HEIGHT + 2:
            pinned.add(height)
        assert len(retained_rows(provider)) <= window + 3
    rows = retained_rows(provider)
    assert rows[0] == original
    final_height = chain.finality.ref.block_number
    assert {row[0] for row in rows} == pinned | set(range(final_height - window, final_height + 1))
    with sqlite3.connect(provider._path) as db:
        assert db.execute("SELECT block FROM observed_head").fetchone()[0] == final_height
        assert db.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 1

    reopened = FinalizedRegistrationProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
        retained_capture_blocks=lambda: frozenset(pinned),
    )
    advance(chain, final_height - 1)
    with pytest.raises(ValueError, match="rolled back"):
        await reopened.collect()
    assert retained_rows(reopened)[0][2] == first.provenance["snapshot_sha256"]


async def test_full_required_window_is_not_pruned_to_make_room(chain):
    await chain.provider.collect()
    original = retained_rows(chain.provider)
    provider = chain.provider
    provider._retained_capture_blocks = frozenset
    provider.config = provider.config.model_copy(update={"maximum_cache_bytes": 1})
    advance(chain, _HEIGHT + 1)
    with pytest.raises(RegistrationCacheFull):
        await provider.collect()
    assert retained_rows(provider) == original


@pytest.mark.parametrize("failure", ["capacity", "freshness", "retention"])
async def test_failed_save_rolls_back_pruning_and_highwater(chain, failure):
    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)

    def retained():
        if failure == "retention":
            raise RuntimeError("receipt ledger unavailable")
        if failure == "freshness":
            chain.clock.now += 121_000  # Simulate expiry after proof collection.
        return frozenset()

    provider._retained_capture_blocks = retained
    if failure == "capacity":
        provider.config = provider.config.model_copy(update={"maximum_cache_bytes": 1})
    with pytest.raises((ValueError, RuntimeError)):
        await provider.collect()
    assert retained_rows(provider) == before
    with sqlite3.connect(provider._path) as db:
        assert db.execute("SELECT block FROM observed_head").fetchone()[0] == _HEIGHT


async def test_retention_is_opt_in_for_non_intake_providers(chain):
    await chain.provider.collect()
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    await chain.provider.collect()
    assert len(retained_rows(chain.provider)) == 2


async def test_admission_archive_can_exceed_working_cache_budget(chain):
    provider = chain.provider
    await provider.collect()
    pinned = {_HEIGHT}
    provider._retained_capture_blocks = lambda: frozenset(pinned)
    with sqlite3.connect(provider._path) as db:
        metadata_bytes = db.execute("SELECT SUM(length(body)) FROM artifacts").fetchone()[0]
    evidence_bytes = len(retained_rows(provider)[0][4])
    provider.config = provider.config.model_copy(
        update={"maximum_cache_bytes": metadata_bytes + 3 * evidence_bytes}
    )
    for height in range(_HEIGHT + 1, _HEIGHT + 40):
        advance(chain, height)
        await provider.collect()
        pinned.add(height)  # Each capture is now used by an accepted receipt.
    rows = retained_rows(provider)
    assert len(rows) == 40
    assert sum(len(row[4]) for row in rows) > provider.config.maximum_cache_bytes
    assert {row[0] for row in rows} == pinned


@pytest.mark.parametrize("invalid", [{1}, frozenset({None}), frozenset({True}), frozenset({-1})])
async def test_invalid_retention_cannot_delete_evidence(chain, invalid):
    await chain.provider.collect()
    before = retained_rows(chain.provider)
    chain.provider._retained_capture_blocks = lambda: invalid
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    with pytest.raises(ValueError, match="invalid retained"):
        await chain.provider.collect()
    assert retained_rows(chain.provider) == before


def test_capacity_warning_precedes_exhaustion_and_only_logs_transitions(chain, monkeypatch, caplog):
    provider = chain.provider
    disk = SimpleNamespace(total=100 * 1024**3, free=80 * 1024**3)
    monkeypatch.setattr("umi.competition_chain.shutil.disk_usage", lambda _: disk)
    limit = provider.config.maximum_cache_bytes
    with caplog.at_level("INFO", logger="umi.competition_chain"):
        provider._report_capacity(limit // 2, limit * 2)
        assert not caplog.records
        provider._report_capacity(limit * 9 // 10, limit * 2)
        provider._report_capacity(limit * 9 // 10, limit * 2)
        assert len(caplog.records) == 1
        assert "cache_pressure=True disk_pressure=False" in caplog.text
        disk.free = 10 * 1024**3
        provider._report_capacity(limit // 2, limit * 2)
        assert "cache_pressure=False disk_pressure=True" in caplog.text
        disk.free = 80 * 1024**3
        provider._report_capacity(limit // 2, limit * 2)
        assert "registration_storage_pressure_recovered" in caplog.text
        provider._report_capacity(limit * 9 // 10, limit * 2)
        assert len(caplog.records) == 4
    assert str(provider._path) not in caplog.text


async def test_capacity_probe_failure_does_not_undo_a_saved_proof(chain, monkeypatch, caplog):
    def unavailable(_):
        raise OSError("PRIVATE path or secret")

    monkeypatch.setattr("umi.competition_chain.shutil.disk_usage", unavailable)
    await chain.provider.collect()
    assert len(retained_rows(chain.provider)) == 1
    assert "registration_storage_capacity_unavailable" in caplog.text
    assert "PRIVATE" not in caplog.text
