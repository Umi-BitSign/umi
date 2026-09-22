"""Native repair certificates release scheduling, without rewriting dispatches."""

import json
import sqlite3
import time
from types import SimpleNamespace

import pytest

from umi.competition_dispatch_capacity import DispatchTimingBudget
from umi.competition_scheduling import AssignmentPublicationJournal
from umi.competition_scheduling_timing import qualify_dispatch
from umi.protocol import canonical_json_bytes

from .test_competition_dispatch_repair import (
    authorization as authorization,
)
from .test_competition_dispatch_repair import (
    dispatch as dispatch,
)
from .test_competition_dispatch_repair import (
    feed as feed,
)
from .test_competition_dispatch_repair import (
    lost as lost,
)
from .test_competition_dispatch_repair import (
    policy as policy,
)
from .test_competition_dispatch_repair import (
    release_identity as release_identity,
)
from .test_competition_dispatch_repair import (
    runtime as runtime,
)
from .test_competition_endpoint_execution import paired_setup as original_setup


@pytest.fixture
def paired_setup(dispatch, tmp_path, monkeypatch, request):
    setup = original_setup.__wrapped__(dispatch, tmp_path, monkeypatch)
    item, driver, journal = dispatch.feed.item, dispatch.driver, dispatch.feed.journal
    budget = DispatchTimingBudget(
        proof_collection_ms=1,
        origin_collection_ms=1,
        publication_ingestion_ms=1,
        local_cycle_ms=1,
        publication_delay_ms=0,
        block_advance_numerator=1,
        block_advance_denominator_ms=60000,
        finality_headroom_blocks=0,
        measurement_sha256="ab" * 32,
    )
    driver.config = dispatch.config = dispatch.config.model_copy(
        update={
            "timing_budget": budget,
            "maximum_concurrency": 4,
            "page_size": 8,
            "poll_seconds": 1,
            "discovery_grace_seconds": 5,
            "request_timeout_seconds": 1,
        }
    )
    driver._configure_timing()
    journal.maximum_bytes = 16 * 1024**3
    if getattr(request, "param", True) is False:
        return setup
    journal.reserve_batch(
        batch_id="af" * 32,
        publications=(item.publication.publication,),
        observed=item.finalized_blocks.blocks[item.request.issued_block],
        announcements=(item.finalized_blocks.blocks[1000],),
        evaluator_hotkey=driver.config.evaluator_hotkey,
    )
    return setup


def retire(lost):
    return lost.journal.retire_void(evidence=lost.evidence, suite=lost.item.suite)


def events(journal):
    with sqlite3.connect(journal.path) as db:
        return db.execute("SELECT * FROM events ORDER BY ordinal").fetchall()


async def test_certified_void_releases_timing_and_unused_proofs_without_retry(lost):
    journal = lost.journal
    before = events(journal)
    with journal._transaction() as db:
        allowance = journal._proof_allowance(db)
        assert allowance > 0
        with pytest.raises(ValueError, match="prior claim outcome"):
            qualify_dispatch(
                journal,
                db,
                (),
                SimpleNamespace(height=lost.item.round.valid_through_block + 1),
                time.time_ns() // 1_000_000,
                lost.driver.config.evaluator_hotkey,
            )
    assert retire(lost) == {lost.key}
    assert events(journal) == before
    assert journal.status(lost.key)["state"] == "uncertain_dispatched"
    with journal._transaction() as db:
        assert journal._proof_allowance(db) == 0
        result = qualify_dispatch(
            journal,
            db,
            (),
            SimpleNamespace(height=lost.item.round.valid_through_block + 1),
            time.time_ns() // 1_000_000,
            lost.driver.config.evaluator_hotkey,
        )
        assert result["plan"]["assignment_count"] == 0
    for _ in range(3):
        await lost.driver.poll_once()
        await lost.driver.drain()
    assert lost.dispatch.miner.translator.calls == 6
    assert events(journal) == before


async def test_retirement_restart_and_duplicate_delivery_preserve_history(lost):
    retire(lost)
    before = events(lost.journal)
    restarted = AssignmentPublicationJournal(
        lost.journal.path.parent,
        lost.item.policy,
        lost.item.legacy_policy,
        maximum_bytes=16 * 1024**3,
    )
    assert restarted.retire_void(evidence=lost.evidence, suite=lost.item.suite) == {lost.key}
    with restarted._transaction() as db:
        assert restarted.retired_claims(db) == {lost.key}
        assert db.execute("SELECT COUNT(*) FROM scheduling_retirements").fetchone()[0] == 1
        for operation in ("DELETE FROM", "UPDATE"):
            statement = operation + " scheduling_retirements"
            if operation == "UPDATE":
                statement += " SET retained_unix_ms=0"
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                db.execute(statement)
    assert events(restarted) == before


@pytest.mark.parametrize("paired_setup", [False, True], indirect=True)
async def test_next_cohort_admission_recovers_after_certified_void(lost):
    from .test_competition_authorization import build_authorization_fixture

    legacy = lost.item.legacy_policy
    lost.dispatch.feed.clock.ns += (
        legacy.clock.window_stride_blocks * legacy.clock.target_block_interval_seconds * 10**9
    )
    future = build_authorization_fixture(
        lost.item.policy,
        legacy_policy=legacy,
        incumbent_sha256=lost.item.round.incumbent_model_sha256,
        window_index=1,
        sequence=lost.item.round.sequence + 1,
    )
    assert future.policy == lost.item.policy
    announcement = legacy.activation_block + legacy.clock.window_stride_blocks
    kwargs = dict(
        batch_id="bf" * 32,
        publications=(future.publication.publication,),
        observed=future.finalized_blocks.blocks[future.request.issued_block],
        announcements=(future.finalized_blocks.blocks[announcement],),
        evaluator_hotkey=lost.driver.config.evaluator_hotkey,
    )
    with pytest.raises(ValueError, match=r"prior claim outcome|drain dispatched incomplete"):
        lost.journal.reserve_batch(**kwargs)
    retire(lost)
    result = lost.journal.reserve_batch(**kwargs)
    assert result["batch_id"] == "bf" * 32
    assert (
        lost.journal.retained_reservation(
            "bf" * 32,
            evaluator_hotkey=lost.driver.config.evaluator_hotkey,
        )
        is not None
    )
    assert lost.journal.status(lost.key)["state"] == "uncertain_dispatched"


@pytest.mark.parametrize("mutation", ["signature", "suite", "claim", "identity", "publication"])
async def test_retirement_revalidates_durable_bytes_even_after_cached_success(lost, mutation):
    retire(lost)
    with lost.journal._transaction() as db:
        assert lost.journal.retired_claims(db) == {lost.key}
        # Deliberately bypass local immutability to exercise read-time validation.
        if mutation == "claim":
            db.execute("DROP TRIGGER immutable_events_update")
            db.execute(
                "UPDATE events SET observed_ms=observed_ms+1 WHERE assignment_id=? "
                "AND kind='dispatched'",
                (lost.key,),
            )
        elif mutation == "publication":
            db.execute("DROP TRIGGER immutable_publications_update")
            raw = json.loads(db.execute("SELECT signed FROM publications").fetchone()[0])
            raw["signatures"][0]["signature"] = "0x" + "00" * 64
            db.execute("UPDATE publications SET signed=?", (canonical_json_bytes(raw),))
        else:
            db.execute("DROP TRIGGER immutable_scheduling_retirements_update")
            raw = json.loads(
                db.execute("SELECT document FROM scheduling_retirements").fetchone()[0]
            )
            if mutation == "signature":
                raw["evidence"]["certificate"]["signatures"][0]["signature"] = "0x" + "00" * 64
            elif mutation == "suite":
                raw["suite"]["schema"] = "invalid"
            else:
                db.execute("UPDATE scheduling_retirements SET decision_sha256=?", ("00" * 32,))
            db.execute("UPDATE scheduling_retirements SET document=?", (canonical_json_bytes(raw),))
    with lost.journal._transaction() as db, pytest.raises(ValueError):
        lost.journal._capacity(db)


async def test_valid_signature_variant_keeps_original_envelope_and_claim(lost):
    from umi.competition_dispatch_repair import SignedDispatchRepair
    from umi.open_competition import digest, sign_object

    from .test_competition_endpoint_execution import make_job
    from .test_competition_evaluator import signed_order
    from .test_competition_void import announce, certify

    variant = lost.item.publication.model_copy(
        update={
            "signatures": tuple(reversed(lost.item.publication.signatures)),
        }
    )
    order = signed_order(make_job(lost.setup), lost.signers, publication=variant)
    body = lost.repair.amendment.model_copy(update={"order_sha256": digest(order.order)})
    repair = SignedDispatchRepair(
        amendment=body,
        signatures=tuple(sign_object(body, w) for w in lost.signers),
    )
    first = lost.first.model_copy(update={"publication": variant, "repair": repair})
    second = lost.second.model_copy(update={"publication": variant})
    observations = tuple(
        announce(e, order, w)
        for e, w in zip(
            (first, second),
            lost.signers,
            strict=True,
        )
    )
    certificate = certify({**lost.context, "signed_order": order}, observations, lost.signers)
    evidence = lost.evidence.model_copy(update={"order": order, "certificate": certificate})
    before = events(lost.journal)
    assert lost.journal.retire_void(evidence=evidence, suite=lost.item.suite) == {lost.key}
    assert events(lost.journal) == before
    with lost.journal._transaction() as db:
        raw = bytes(db.execute("SELECT signed FROM publications").fetchone()[0])
        assert raw == canonical_json_bytes(lost.item.publication)
        assert raw != canonical_json_bytes(variant)
    assert lost.journal.status(lost.key)["state"] == "uncertain_dispatched"


async def test_retirement_capacity_failure_rolls_back_only_new_disposition(lost):
    before = events(lost.journal)
    lost.journal.maximum_bytes = 1024
    with pytest.raises(ValueError, match="capacity exhausted"):
        retire(lost)
    assert events(lost.journal) == before
    with lost.journal._transaction() as db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='scheduling_retirements'"
        ).fetchone()
    lost.journal.maximum_bytes = 16 * 1024**3
    assert retire(lost) == {lost.key}
