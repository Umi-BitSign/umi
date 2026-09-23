from __future__ import annotations

import json
import sqlite3

import pytest

from umi.competition_cohort_availability import (
    CohortServiceAvailability,
    pending_availability_progress,
)
from umi.competition_cohort_coordinator import AttestedCohortPhaseProgress
from umi.competition_cohort_recovery import PHASES
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_coordinator import harness as harness
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import policy as policy


def observe(observer, harness, block, serving=True):
    return observer.observe(
        harness.cohort,
        capture_at(block),
        serving=serving,
        genesis_signatures=harness.genesis_signatures,
    )


def extend(harness, block, amount):
    proposal = harness.store.reserve(
        harness.cohort,
        phase=harness.state.phase,
        operation="extend",
        observed_at_block=block,
        evidence_sha256=digest({"block": block}),
        extension_blocks=amount,
    )
    harness.store.commit(signed_transition(proposal))


def test_healthy_samples_duplicate_poll_and_pending_progress(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    for block in range(200, 301, 10):
        receipt = observe(observer, harness, block)
        assert receipt.unavailable_blocks == 0
        assert observe(observer, harness, block) == receipt
    result = pending_availability_progress(harness.state, receipt)
    assert result.completion == "pending" and result.phase_result_sha256 is None
    assert result.evidence_sha256 == digest(receipt)
    # Time alone does not create completion evidence or authorize rewards.
    assert result.observed_at_block == 300


@pytest.mark.parametrize("first", [160, 199, 200, 205, 9000])
def test_first_observation_credits_no_unobserved_service(harness, first):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    receipt = observe(observer, harness, first)
    assert receipt.unavailable_blocks == max(0, first - 200)
    assert observe(observer, harness, first + 1).unavailable_blocks == receipt.unavailable_blocks


def test_reported_failure_and_unknown_gaps_remain_cumulative(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    observe(observer, harness, 200)
    assert observe(observer, harness, 205, False).unavailable_blocks == 5
    assert observe(observer, harness, 210).unavailable_blocks == 10
    assert observe(observer, harness, 220).unavailable_blocks == 10
    # A ready response after a large gap does not prove intervening availability.
    assert observe(observer, harness, 1420).unavailable_blocks == 1210
    assert observe(observer, harness, 1425).unavailable_blocks == 1210


@pytest.mark.parametrize("gap", [1, 1200, 10000])
def test_reopen_creates_new_epoch_and_restores_whole_unobserved_gap(harness, gap):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    before = observe(observer, harness, 200)
    harness.restart()
    reopened = CohortServiceAvailability(harness.store, harness.policy)
    after = observe(reopened, harness, 200 + gap)
    assert after.process_epoch != before.process_epoch
    assert after.unavailable_blocks == gap
    assert after.predecessor_sha256 == digest(before)
    assert observe(reopened, harness, 201 + gap).unavailable_blocks == gap


def test_short_restart_at_same_block_does_not_double_count(harness):
    first = CohortServiceAvailability(harness.store, harness.policy)
    observe(first, harness, 200)
    second = CohortServiceAvailability(harness.store, harness.policy)
    assert observe(second, harness, 200).unavailable_blocks == 0
    assert observe(second, harness, 201).unavailable_blocks == 0


def test_extension_keeps_phase_counter_and_refuses_old_progress_tip(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    old = observe(observer, harness, 210)
    assert old.unavailable_blocks == 10
    extend(harness, 210, 10)
    with pytest.raises(ValueError, match="another cohort"):
        pending_availability_progress(harness.state, old)
    new = observe(observer, harness, 211)
    assert new.unavailable_blocks == 10 and new.phase_started_block == 200
    assert new.recovery_tip_sha256 != old.recovery_tip_sha256


@pytest.mark.parametrize("phase", PHASES)
def test_phase_counter_starts_at_its_authoritative_opening(harness, phase):
    harness.advance_to(phase)
    start = 200 if phase == "intake" else harness.state.observed_at_block
    observer = CohortServiceAvailability(harness.store, harness.policy)
    receipt = observe(observer, harness, start + 1200)
    assert receipt.phase == phase and receipt.phase_started_block == start
    assert receipt.unavailable_blocks == 1200


def test_coordinator_automatically_restores_observed_outage_once(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    observe(observer, harness, 200)
    observe(observer, harness, 210)
    harness.restart()
    observer = CohortServiceAvailability(harness.store, harness.policy)

    async def native_progress(state, capture):
        receipt = observer.observe(
            harness.cohort, capture, serving=True, genesis_signatures=harness.genesis_signatures
        )
        progress = pending_availability_progress(state, receipt)
        return AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress))

    harness.observe = native_progress
    harness.block = 1410
    before = harness.state.targets
    assert harness.tick()["status"] == "phase_decision_published"
    assert harness.state.phase == "intake"
    assert all(
        b.target_block == a.target_block + 1200
        for a, b in zip(before, harness.state.targets, strict=True)
    )
    assert harness.tick()["status"] == "waiting_phase_progress"
    assert harness.state.sequence == 1


def test_capacity_failure_preserves_work_and_capacity_can_increase(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy, maximum_bytes=1024)
    original = observe(observer, harness, 200)
    with pytest.raises(OSError, match="capacity"):
        observe(observer, harness, 201)
    assert observe(observer, harness, 200) == original
    # Retry through the same process epoch after adding operational capacity.
    observer.maximum_bytes = 16384
    retry = observe(observer, harness, 201)
    assert retry.predecessor_sha256 == digest(original) and retry.unavailable_blocks == 0


@pytest.mark.parametrize("corruption", ["counter", "predecessor", "delete_first", "noncanonical"])
def test_replay_rejects_changed_or_incomplete_observations(harness, corruption):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    observe(observer, harness, 200)
    last = observe(observer, harness, 205)
    if corruption == "delete_first":
        harness.db.execute("DELETE FROM cohort_service_observations WHERE sequence=1")
    else:
        value = last.model_dump(mode="json", by_alias=True)
        if corruption == "counter":
            value["unavailable_blocks"] = 99
        if corruption == "predecessor":
            value["predecessor_sha256"] = "ab" * 32
        raw = (
            json.dumps(value).encode()
            if corruption == "noncanonical"
            else canonical_json_bytes(value)
        )
        harness.db.execute("UPDATE cohort_service_observations SET body=? WHERE sequence=2", (raw,))
    harness.db.commit()
    with pytest.raises(ValueError, match=r"incomplete|inconsistent"):
        observe(observer, harness, 206)


def test_other_connection_invalidates_cache_and_keeps_outage(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    observe(observer, harness, 200)
    db = sqlite3.connect(harness.path)
    try:
        peer = CohortServiceAvailability(CohortRecoveryStore(db), harness.policy)
        receipt = observe(peer, harness, 205, False)
    finally:
        db.close()
    after = observe(observer, harness, 210)
    assert after.predecessor_sha256 == digest(receipt)
    assert after.unavailable_blocks == 10


def test_no_credit_from_historical_or_changed_finality(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    observe(observer, harness, 210)
    with pytest.raises(ValueError, match="regressed"):
        observe(observer, harness, 209)
    capture = capture_at(211)
    capture.provenance["evidence_class"] = "verified_finalized_ancestry"
    with pytest.raises(ValueError):
        observer.observe(
            harness.cohort, capture, serving=True, genesis_signatures=harness.genesis_signatures
        )
    assert observe(observer, harness, 211).unavailable_blocks == 10


def test_policy_quorum_sampling_and_boolean_are_bound(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    for value in (1, "true", None):
        with pytest.raises(ValueError, match="boolean"):
            observe(observer, harness, 200, value)
    with pytest.raises(ValueError):
        observer.observe(
            harness.cohort,
            capture_at(200),
            serving=True,
            genesis_signatures=harness.genesis_signatures[:1],
        )
    with pytest.raises(ValueError, match="sampling rule"):
        CohortServiceAvailability(harness.store, harness.policy, maximum_sample_gap_blocks=11)
    altered = harness.policy.model_copy(update={"valid_through_block": 20000})
    changed = CohortServiceAvailability(harness.store, altered)
    with pytest.raises(ValueError, match="policy differs"):
        observe(changed, harness, 200)
    assert observe(observer, harness, 200).sequence == 1


def test_history_transaction_reader_does_not_publish_pending_decisions(harness):
    with pytest.raises(ValueError, match="transaction"):
        harness.store.read_history(harness.cohort, genesis_signatures=harness.genesis_signatures)
    harness.store.reserve(
        harness.cohort,
        phase="intake",
        operation="extend",
        observed_at_block=200,
        evidence_sha256="ab" * 32,
        extension_blocks=5,
    )
    observer = CohortServiceAvailability(harness.store, harness.policy)
    receipt = observe(observer, harness, 200)
    assert receipt.recovery_tip_sha256 == harness.state.tip_sha256
    assert harness.state.sequence == 0


def test_phase_change_starts_a_new_counter_and_revocation_rejects_new_samples(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    assert observe(observer, harness, 210).unavailable_blocks == 10
    harness.advance_to("preparation")
    assert observe(observer, harness, 300).unavailable_blocks == 0
    proposal = harness.store.reserve(
        harness.cohort,
        phase="preparation",
        operation="revoke",
        observed_at_block=301,
        evidence_sha256="ab" * 32,
    )
    harness.store.commit(signed_transition(proposal))
    with pytest.raises(ValueError, match="terminal"):
        observe(observer, harness, 301)


def test_same_block_changed_state_root_cannot_credit_service(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    prior = observe(observer, harness, 200)
    capture = capture_at(200)
    capture.provenance["state_root"] = "0x" + "fe" * 32
    assert capture.provenance["state_root"] != prior.observation.state_root
    with pytest.raises(ValueError, match="finality"):
        observer.observe(
            harness.cohort, capture, serving=True, genesis_signatures=harness.genesis_signatures
        )
    assert observe(observer, harness, 200) == prior


def test_failed_sql_write_does_not_advance_the_observed_boundary(harness):
    observer = CohortServiceAvailability(harness.store, harness.policy)
    prior = observe(observer, harness, 200)
    harness.db.execute(
        "CREATE TRIGGER fail_sample BEFORE INSERT ON cohort_service_observations "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
    harness.db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        observe(observer, harness, 1400)
    harness.db.execute("DROP TRIGGER fail_sample")
    harness.db.commit()
    after = observe(observer, harness, 1405)
    assert after.predecessor_sha256 == digest(prior)
    assert after.unavailable_blocks == 1205
