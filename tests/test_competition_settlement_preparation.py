from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from umi.competition_evaluator import _read
from umi.competition_publication import (
    build_settlement_publication,
    independent_evidence_set_digest,
)
from umi.competition_settlement_preparation import (
    SettlementPreparation,
    prepare_retained_settlement,
    validate_preparation,
)
from umi.competition_store import CompetitionStore, SettlementNotReadyError
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_rounds import OwnedProvider
from .test_open_competition import policy as policy


@pytest.fixture
def setup(policy, replay_limits, tmp_path):
    value = _scenario(policy, tmp_path, replay_limits, settle=False)
    value.provider = OwnedProvider(160)
    value.limits = replay_limits
    value.output = tmp_path / "settlement-proposals"
    return value


async def prepare(s):
    return await prepare_retained_settlement(
        store=s.store,
        provider=s.provider,
        cutoff=s.cutoff_certificate,
        suite=s.suite,
        limits=s.limits,
        output_directory=s.output,
    )


def published(s):
    path = s.output / (digest(s.round) + ".settlement-proposal.json")
    return _read(path, SettlementPreparation)


def mutate(s, sql, args=()):
    with sqlite3.connect(s.store.path) as db:
        db.create_function("umi_writer_generation", 0, lambda: 2)
        db.create_function("umi_submission_checkpoint_binding", 0, lambda: None)
        db.execute(sql, args)


@pytest.mark.asyncio
async def test_owned_complete_round_prepares_actual_70_30_settlement(setup):
    s = setup
    assert s.policy.endpoint_reward_bps == 7000 and s.policy.model_reward_bps == 3000
    assert s.store.settlement_status(digest(s.round)) is None
    assert await prepare(s) == "prepared"
    prepared = published(s)
    assert validate_preparation(prepared, s.policy, s.limits) == prepared
    assert prepared.publication.settlement.registration_snapshot.block == 160
    assert prepared.publication.settlement.promotion_head.contributor_hotkey is not None
    assert prepared.publication.settlement.projection.weights.count(0) == 254
    assert sum(prepared.publication.settlement.projection.weights) == 65535
    assert not prepared.chain_submission_authorized
    assert "signatures" not in type(prepared.publication).model_fields
    assert prepared.publication == build_settlement_publication(
        cutoff_certificate=s.cutoff_certificate,
        retained_settlement=prepared.publication.settlement,
        submissions=s.submissions,
        evidence=s.evidence,
        policy=s.policy,
        limits=s.limits,
    )


@pytest.mark.asyncio
async def test_restart_retry_preserves_snapshot_evidence_and_exact_output(setup):
    s = setup
    await prepare(s)
    before = canonical_json_bytes(published(s))
    s.store = CompetitionStore(s.store.directory, s.policy)
    s.provider.block = 170
    await prepare(s)
    assert canonical_json_bytes(published(s)) == before
    assert published(s).publication.settlement.observed_block == 160


@pytest.mark.asyncio
@pytest.mark.parametrize("block,expected", [(159, "waiting"), (301, "expired")])
async def test_outside_window_does_not_create_a_settlement_or_output(setup, block, expected):
    s = setup
    s.provider.block = block
    assert await prepare(s) == expected
    assert s.store.settlement_status(digest(s.round)) is None
    assert not s.output.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("late", [False, True])
async def test_missing_or_late_roster_member_is_not_silently_skipped(setup, late):
    s = setup
    if late:
        mutate(s, "UPDATE independent_evaluation_evidence SET first_observed_block=161")
    else:
        mutate(
            s,
            "DELETE FROM independent_evaluation_evidence WHERE submission=?",
            (s.round.roster[0],),
        )
    with pytest.raises(SettlementNotReadyError):
        await prepare(s)
    assert s.store.settlement_status(digest(s.round)) is None
    assert not s.output.exists()


@pytest.mark.parametrize(
    "table,key",
    [
        ("submissions", "digest"),
        ("rounds", "digest"),
        ("competition_settlements", "round"),
        ("independent_evaluation_evidence", "digest"),
    ],
)
@pytest.mark.asyncio
async def test_size_bounds_are_checked_before_loading_retained_bodies(setup, table, key):
    s = setup
    if table == "competition_settlements":
        await prepare(s)
    mutate(s, f"UPDATE {table} SET body=zeroblob(11000000)")
    with pytest.raises(ValueError, match="byte bound"):
        s.store.settlement_material(s.round, limits=s.limits)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["result", "submission", "time", "digest", "noncanonical"])
async def test_corrupt_retained_evidence_is_rejected(setup, change):
    s = setup
    if change == "time":
        mutate(s, "UPDATE independent_evaluation_evidence SET first_observed_block=149")
    elif change == "noncanonical":
        mutate(s, "UPDATE independent_evaluation_evidence SET body=CAST(body AS TEXT)||' '")
    else:
        mutate(
            s,
            f"UPDATE independent_evaluation_evidence SET {change}=? WHERE submission=?",
            (
                "e" * 64,
                s.round.roster[0],
            ),
        )
    with pytest.raises(ValueError):
        await prepare(s)
    assert not s.output.exists()


@pytest.mark.asyncio
async def test_conflict_after_output_remains_held_on_retry(setup):
    s = setup
    await prepare(s)
    old = canonical_json_bytes(published(s))
    mutate(s, "INSERT INTO round_conflicts VALUES (?,?)", (digest(s.round), 161))
    s.provider.block = 162
    with pytest.raises(ValueError, match="conflicting quorum"):
        await prepare(s)
    assert canonical_json_bytes(published(s)) == old
    assert s.store.settlement_status(digest(s.round))["disputed"]


@pytest.mark.asyncio
async def test_existing_settlement_pins_original_first_observation(setup):
    s = setup
    await prepare(s)
    mutate(s, "UPDATE independent_evaluation_evidence SET first_observed_block=151")
    with pytest.raises(ValueError, match="observation changed"):
        await prepare(s)


@pytest.mark.asyncio
async def test_owned_capture_required_and_head_cannot_regress(setup):
    s = setup
    original = s.provider.collect
    count = 0

    async def corrupt():
        nonlocal count
        count += 1
        if count == 2:
            s.provider.block = 159
        return await original()

    s.provider.collect = corrupt
    with pytest.raises(ValueError, match="regressed"):
        await prepare(s)
    assert s.store.settlement_status(digest(s.round)) is None

    async def unowned():
        return replace(await original(), provenance={})

    s.provider.collect = unowned
    with pytest.raises(ValueError, match="provenance"):
        await prepare(s)


@pytest.mark.asyncio
async def test_wrong_cutoff_or_suite_cannot_poison_the_settlement(setup):
    s = setup
    original = s.suite
    s.suite = s.suite.model_copy(update={"cases": tuple(reversed(s.suite.cases))})
    with pytest.raises(ValueError, match="suite differs"):
        await prepare(s)
    s.suite = original
    s.cutoff_certificate = s.cutoff_certificate.model_copy(update={"signatures": ()})
    with pytest.raises(ValueError):
        await prepare(s)
    assert s.store.settlement_status(digest(s.round)) is None


@pytest.mark.asyncio
async def test_missing_model_allocation_does_not_turn_into_endpoint_only(setup):
    s = setup
    mutate(s, "DELETE FROM promotions WHERE sequence>0")
    with pytest.raises(ValueError, match="promoted contributor"):
        await prepare(s)
    assert s.store.settlement_status(digest(s.round)) is None
    assert not s.output.exists()


@pytest.mark.asyncio
async def test_aggregate_evidence_limit_is_enforced_before_settlement(setup):
    s = setup
    size = len(canonical_json_bytes(s.evidence[0][1])) + 1
    s.limits = s.limits.model_copy(update={"maximum_evidence_bytes": size})
    with pytest.raises(ValueError, match="byte bound"):
        await prepare(s)
    assert s.store.settlement_status(digest(s.round)) is None


def test_material_evidence_digest_matches_publication_contract(setup):
    s = setup
    material = s.store.settlement_material(s.round, limits=s.limits)
    assert independent_evidence_set_digest(material["evidence"], maximum_bytes=5_000_000) == (
        independent_evidence_set_digest(s.evidence, maximum_bytes=5_000_000)
    )
    assert material["submissions"] == s.submissions
    assert material["retained_settlement"] is None


def test_settlement_transport_bound_is_16_mib_before_model_parsing(setup):
    from umi.competition_settlement_preparation import MAX_BYTES

    assert MAX_BYTES == 16 * 1024**2
    with pytest.raises(ValueError, match="transport byte bound"):
        validate_preparation({"oversized": "a" * MAX_BYTES}, setup.policy, setup.limits)


@pytest.mark.asyncio
async def test_expiry_during_final_collection_does_not_commit(setup):
    s = setup
    collect = s.provider.collect
    calls = 0

    async def advance():
        nonlocal calls
        calls += 1
        if calls == 2:
            s.provider.block = s.round.valid_through_block + 1
        return await collect()

    s.provider.collect = advance
    assert await prepare(s) == "expired"
    assert s.store.settlement_status(digest(s.round)) is None


@pytest.mark.asyncio
async def test_crash_after_store_commit_republishes_exact_original(setup, monkeypatch):
    from umi import competition_settlement_preparation as module

    s = setup
    original = module._publish

    def fail(*args, **kwargs):
        raise OSError("interrupted after durable settlement")

    monkeypatch.setattr(module, "_publish", fail)
    with pytest.raises(OSError):
        await prepare(s)
    retained = s.store.settlement_material(s.round, limits=s.limits)["retained_settlement"]
    assert retained.observed_block == 160
    s.store = CompetitionStore(s.store.directory, s.policy)
    s.provider.block = 175
    monkeypatch.setattr(module, "_publish", original)
    assert await prepare(s) == "prepared"
    assert published(s).publication.settlement == retained


@pytest.mark.asyncio
async def test_later_evidence_variant_cannot_change_an_existing_settlement(setup):
    from umi.competition_evidence import independent_evidence_digest

    s = setup
    await prepare(s)
    previous = canonical_json_bytes(published(s))
    signed, evidence = s.evidence[0]
    variant = evidence.model_copy(
        update={"evaluator_runs": tuple(reversed(evidence.evaluator_runs))}
    )
    assert independent_evidence_digest(variant) != independent_evidence_digest(evidence)
    s.store.record_independent_evaluation(
        signed=signed,
        evidence=variant,
        round_=s.round,
        suite=s.suite,
        observed_block=161,
    )
    s.provider.block = 162
    await prepare(s)
    assert canonical_json_bytes(published(s)) == previous


@pytest.mark.asyncio
async def test_conflict_arriving_after_commit_blocks_file_publication(setup, monkeypatch):
    s = setup
    original = s.store.settle

    def conflict(**kwargs):
        result = original(**kwargs)
        mutate(s, "INSERT INTO round_conflicts VALUES (?,?)", (digest(s.round), 160))
        return result

    monkeypatch.setattr(s.store, "settle", conflict)
    with pytest.raises(ValueError, match="conflicting quorum"):
        await prepare(s)
    assert not s.output.exists()
