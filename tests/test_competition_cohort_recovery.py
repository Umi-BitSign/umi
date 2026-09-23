from __future__ import annotations

import multiprocessing
import os
import signal
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from pydantic import ValidationError

from umi.competition_cohort_recovery import (
    PHASES,
    CohortRecoveryAuthority,
    PhaseTarget,
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    SignedCohortRecoveryTransition,
    admit_recoverable_cohort,
    apply_recovery_transition,
    propose_recovery_transition,
    verify_recovery_authority,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_open_competition import policy as policy
from .test_open_competition import wallet


def signatures(body, names=("Charlie", "Dave")):
    return tuple(
        sorted((sign_object(body, wallet(n)) for n in names), key=lambda s: identity(s.hotkey))
    )


def signed_transition(body):
    return SignedCohortRecoveryTransition(transition=body, signatures=signatures(body))


@pytest.fixture
def recovery(policy):
    plan = RecoverableCohortPlan(
        schema="umi-recoverable-cohort-plan/1",
        policy_sha256=digest(policy),
        launch_sha256="a3" * 32,
        sequence=5,
        suite_sha256="a4" * 32,
        not_before_block=200,
        initial_targets=tuple(
            PhaseTarget(phase=p, target_block=300 + 90 * i) for i, p in enumerate(PHASES)
        ),
    )
    body = CohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/1",
        policy_sha256=digest(policy),
        cohort_sha256s=(digest(plan),),
        issued_at_block=150,
        minimum_recovery_margin_blocks=20,
        maximum_extension_step_blocks=1200,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
    )
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    _, state = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
    return plan, authority, state


def advance(state, authority, policy, operation, block, extension=None):
    proposal = propose_recovery_transition(
        state,
        authority.authority,
        operation=operation,
        observed_at_block=block,
        evidence_sha256="a5" * 32,
        extension_blocks=extension,
    )
    return apply_recovery_transition(state, signed_transition(proposal), authority, policy)


def at_phase(recovery, policy, target_phase):
    _, authority, state = recovery
    for phase in PHASES:
        if phase == target_phase:
            return state
        state = advance(
            state, authority, policy, "close_phase", state.targets[PHASES.index(phase)].target_block
        )
    raise AssertionError(target_phase)


@pytest.mark.parametrize("phase", PHASES)
def test_every_phase_survives_four_hour_outage_past_original_policy(recovery, policy, phase):
    plan, authority, _ = recovery
    state = at_phase(recovery, policy, phase)
    old_targets = state.targets
    index = PHASES.index(phase)
    # 1,200 blocks at the nominal 12-second cadence. All original targets and
    # ordinary policy validity have passed, but explicit recovery is still valid.
    block = old_targets[index].target_block + 1200
    recovered = advance(state, authority, policy, "extend", block)
    recovered = advance(recovered, authority, policy, "extend", block)
    assert recovered.phase == phase
    assert recovered.cohort_sha256 == digest(plan)
    assert recovered.targets[:index] == old_targets[:index]
    assert recovered.targets[index].target_block >= block + 20
    shifts = {
        b.target_block - a.target_block
        for a, b in zip(old_targets[index:], recovered.targets[index:], strict=True)
    }
    assert shifts == {1220}
    assert recovered.targets[-1].target_block > policy.valid_through_block


def test_restores_lost_time_before_target_is_near(recovery, policy):
    _, authority, state = recovery
    recovered = advance(state, authority, policy, "extend", 220, extension=15)
    assert [v.target_block for v in recovered.targets] == [
        v.target_block + 15 for v in state.targets
    ]


def test_repeated_outages_have_no_count_or_total_extension_limit(recovery, policy):
    _, authority, state = recovery
    for _ in range(40):
        state = advance(state, authority, policy, "extend", state.targets[0].target_block + 1200)
    assert state.sequence == 40
    assert state.targets[0].target_block == 48300
    # A late phase completion shifts all remaining budgets and can still finish.
    for phase in PHASES:
        state = advance(
            state,
            authority,
            policy,
            "close_phase",
            state.targets[PHASES.index(phase)].target_block + 100,
        )
    assert state.phase == "complete"


@pytest.mark.parametrize("operation", ["extend", "close_phase", "revoke"])
@pytest.mark.parametrize("terminal", ["complete", "revoked"])
def test_terminal_cohort_cannot_reopen(recovery, policy, terminal, operation):
    _, authority, state = recovery
    if terminal == "revoked":
        state = advance(state, authority, policy, "revoke", 170)
    else:
        state = at_phase(recovery, policy, "first_admission")
        state = advance(state, authority, policy, "close_phase", 930)
    with pytest.raises(ValueError, match="completed or revoked"):
        advance(state, authority, policy, operation, 10000)


def test_late_close_preserves_downstream_budgets_and_historical_target(recovery, policy):
    _, authority, _ = recovery
    state = at_phase(recovery, policy, "requests")
    old = state.targets
    state = advance(state, authority, policy, "close_phase", 1800)
    assert state.targets[:3] == old[:3]
    assert state.observed_at_block == 1800
    assert state.targets[3].target_block == 1890
    assert state.phase == "reference_reveal"


def test_revealed_cases_cannot_be_reopened_by_a_signed_extension(recovery, policy):
    _, authority, _ = recovery
    state = at_phase(recovery, policy, "evidence")
    proposal = propose_recovery_transition(
        state,
        authority.authority,
        operation="extend",
        observed_at_block=700,
        evidence_sha256="a5" * 32,
    )
    bad = proposal.model_copy(update={"phase": "requests"})
    with pytest.raises(ValueError, match="forks history"):
        apply_recovery_transition(state, signed_transition(bad), authority, policy)
    altered = list(proposal.targets)
    altered[2] = altered[2].model_copy(update={"target_block": altered[2].target_block + 1})
    bad = proposal.model_copy(update={"targets": tuple(altered)})
    with pytest.raises(ValueError, match="forks history"):
        apply_recovery_transition(state, signed_transition(bad), authority, policy)


@pytest.mark.parametrize("phase", ["intake", "requests"])
def test_announced_participant_windows_cannot_close_early(recovery, policy, phase):
    _, authority, _ = recovery
    state = at_phase(recovery, policy, phase)
    with pytest.raises(ValueError, match="cannot shorten"):
        advance(
            state,
            authority,
            policy,
            "close_phase",
            state.targets[PHASES.index(phase)].target_block - 1,
        )


@pytest.mark.parametrize("block", [99, 149, 1001, True])
def test_no_new_admission_after_policy_expires_or_before_authority(recovery, policy, block):
    plan, authority, _ = recovery
    with pytest.raises(ValueError, match="timely explicit admission"):
        admit_recoverable_cohort(plan, authority, policy, admitted_at_block=block)


def test_authority_cannot_be_reused_for_another_cohort_or_policy(recovery, policy):
    plan, authority, _ = recovery
    with pytest.raises(ValueError, match="timely explicit admission"):
        admit_recoverable_cohort(
            plan.model_copy(update={"sequence": 6}), authority, policy, admitted_at_block=160
        )
    with pytest.raises(ValueError, match="selected policy"):
        verify_recovery_authority(authority, policy.model_copy(update={"sequence": 2}))


@pytest.mark.parametrize("names", [("Charlie",), ("Alice", "Charlie"), ("Charlie", "Charlie")])
def test_real_quorum_required(recovery, policy, names):
    _, authority, _ = recovery
    bad = authority.model_copy(update={"signatures": signatures(authority.authority, names)})
    with pytest.raises(ValueError):
        verify_recovery_authority(bad, policy)


def test_tampered_signature_fails_native_crypto(recovery, policy):
    _, authority, _ = recovery
    changed = authority.authority.model_copy(update={"minimum_recovery_margin_blocks": 30})
    with pytest.raises(ValueError):
        verify_recovery_authority(authority.model_copy(update={"authority": changed}), policy)


@pytest.mark.parametrize(
    "operation,block,extension",
    [
        ("extend", 199, 20),
        ("close_phase", 199, None),
        ("extend", 200, None),
        ("extend", 300, 1201),
        ("extend", 300, 0),
        ("extend", 300, True),
        ("close_phase", 300, 20),
        ("revoke", 300, 20),
        ("extend", 159, 20),
    ],
)
def test_rejects_early_invalid_or_unbounded_decisions(
    recovery, policy, operation, block, extension
):
    _, authority, state = recovery
    with pytest.raises(ValueError):
        advance(state, authority, policy, operation, block, extension)


def test_no_zero_evidence_or_invalid_phase_order(recovery):
    plan, authority, state = recovery
    with pytest.raises(ValidationError):
        propose_recovery_transition(
            state,
            authority.authority,
            operation="extend",
            observed_at_block=300,
            evidence_sha256="0" * 64,
        )
    with pytest.raises(ValidationError):
        RecoverableCohortPlan.model_validate_json(
            canonical_json_bytes(
                plan.model_copy(update={"initial_targets": tuple(reversed(plan.initial_targets))})
            )
        )


@pytest.fixture
def ledger(tmp_path, recovery, policy):
    db = sqlite3.connect(tmp_path / "recovery.sqlite3")
    store = CohortRecoveryStore(db)
    plan, authority, _ = recovery
    store.admit(plan, authority, policy, admitted_at_block=160)
    yield store
    db.close()


def test_reopen_preserves_reservation_then_catches_up(ledger, recovery, policy, tmp_path):
    plan, authority, initial = recovery
    cohort = digest(plan)
    pending = ledger.reserve(
        cohort, phase="intake", operation="extend", observed_at_block=300, evidence_sha256="a5" * 32
    )
    with sqlite3.connect(tmp_path / "recovery.sqlite3") as db:
        reopened = CohortRecoveryStore(db)
        assert reopened.status(cohort) == (initial, pending)
        assert (
            reopened.reserve(
                cohort,
                phase="intake",
                operation="close_phase",
                observed_at_block=3000,
                evidence_sha256="a6" * 32,
            )
            == pending
        )
        state = reopened.commit(signed_transition(pending))
        later = reopened.reserve(
            cohort,
            phase="intake",
            operation="extend",
            observed_at_block=3000,
            evidence_sha256="a6" * 32,
        )
        state = reopened.commit(signed_transition(later))
        assert state.sequence == 2
        assert state.targets[0].target_block == 1520
        assert reopened.status(cohort) == (state, None)
        # A repeated old commit cannot undo the later extension.
        assert reopened.commit(signed_transition(pending)) == state
        assert reopened.admit(plan, authority, policy, admitted_at_block=160) == state


def test_conflicting_reserved_body_is_never_signed_or_adopted(ledger, recovery):
    plan, authority, initial = recovery
    cohort = digest(plan)
    reserved = ledger.reserve(
        cohort, phase="intake", operation="extend", observed_at_block=300, evidence_sha256="a5" * 32
    )
    other = propose_recovery_transition(
        initial,
        authority.authority,
        operation="close_phase",
        observed_at_block=300,
        evidence_sha256="a6" * 32,
    )
    with pytest.raises(ValueError, match="conflicts with a reserved"):
        ledger.commit(signed_transition(other))
    assert ledger.status(cohort) == (initial, reserved)


def test_follower_accepts_certified_next_body_but_not_a_gap(ledger, recovery, policy):
    plan, authority, initial = recovery
    first = propose_recovery_transition(
        initial,
        authority.authority,
        operation="extend",
        observed_at_block=300,
        evidence_sha256="a5" * 32,
    )
    state = apply_recovery_transition(initial, signed_transition(first), authority, policy)
    second = propose_recovery_transition(
        state,
        authority.authority,
        operation="extend",
        observed_at_block=320,
        evidence_sha256="a6" * 32,
    )
    with pytest.raises(ValueError, match="forks history"):
        ledger.commit(signed_transition(second))
    assert ledger.commit(signed_transition(first)) == state
    assert ledger.commit(signed_transition(second)).sequence == 2
    assert ledger.status(digest(plan))[1] is None


def test_store_refuses_conflicting_admission(ledger, recovery, policy):
    plan, authority, _ = recovery
    with pytest.raises(ValueError, match="different recovery binding"):
        ledger.admit(plan, authority, policy, admitted_at_block=170)


@pytest.mark.parametrize("operation", ["extend", "close_phase"])
def test_lost_commit_acknowledgement_does_not_apply_same_evidence_twice(
    ledger, recovery, operation
):
    cohort = digest(recovery[0])
    original = ledger.reserve(
        cohort,
        phase="intake",
        operation=operation,
        observed_at_block=300,
        evidence_sha256="a5" * 32,
    )
    committed = ledger.commit(signed_transition(original))
    retried = ledger.reserve(
        cohort,
        phase="intake",
        operation=operation,
        observed_at_block=4000,
        evidence_sha256="a5" * 32,
    )
    assert retried == original
    assert ledger.commit(signed_transition(retried)) == committed
    assert ledger.status(cohort) == (committed, None)
    if operation == "close_phase":
        with pytest.raises(ValueError, match="closed or different phase"):
            ledger.reserve(
                cohort,
                phase="intake",
                operation=operation,
                observed_at_block=4000,
                evidence_sha256="a6" * 32,
            )


def test_follower_rejects_quorum_attempt_to_reuse_extension_evidence(ledger, recovery):
    cohort = digest(recovery[0])
    original = ledger.reserve(
        cohort, phase="intake", operation="extend", observed_at_block=300, evidence_sha256="a5" * 32
    )
    state = ledger.commit(signed_transition(original))
    repeated = propose_recovery_transition(
        state,
        recovery[1].authority,
        operation="extend",
        observed_at_block=320,
        evidence_sha256="a5" * 32,
    )
    with pytest.raises(ValueError, match="already has a decision"):
        ledger.commit(signed_transition(repeated))
    assert ledger.status(cohort) == (state, None)


@pytest.mark.parametrize(
    "corruption", ["sequence_gap", "noncanonical", "missing_signature", "body_changed"]
)
def test_reopen_authenticates_whole_history(ledger, recovery, corruption):
    plan, _, _ = recovery
    cohort = digest(plan)
    pending = ledger.reserve(
        cohort, phase="intake", operation="extend", observed_at_block=300, evidence_sha256="a5" * 32
    )
    signed = signed_transition(pending)
    ledger.commit(signed)
    if corruption == "sequence_gap":
        ledger.db.execute("UPDATE cohort_recovery_decisions SET sequence=2")
    elif corruption == "noncanonical":
        ledger.db.execute(
            "UPDATE cohort_recovery_decisions SET body=?", (b" " + canonical_json_bytes(pending),)
        )
    elif corruption == "missing_signature":
        ledger.db.execute(
            "UPDATE cohort_recovery_decisions SET certificate=?",
            (
                canonical_json_bytes(
                    signed.model_copy(update={"signatures": signed.signatures[:1]})
                ),
            ),
        )
    else:
        ledger.db.execute(
            "UPDATE cohort_recovery_decisions SET body=?",
            (canonical_json_bytes(pending.model_copy(update={"evidence_sha256": "a7" * 32})),),
        )
    ledger.db.commit()
    with pytest.raises(ValueError):
        ledger.status(cohort)


def test_atomic_competing_reservations(tmp_path, ledger, recovery):
    cohort = digest(recovery[0])
    barrier = Barrier(2)

    def reserve(block):
        db = sqlite3.connect(tmp_path / "recovery.sqlite3", timeout=10)
        try:
            store = CohortRecoveryStore(db)
            barrier.wait(timeout=10)
            return store.reserve(
                cohort,
                phase="intake",
                operation="extend",
                observed_at_block=block,
                evidence_sha256=f"{block:064x}",
            )
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(reserve, 290)
        b = pool.submit(reserve, 295)
        assert a.result(timeout=20) == b.result(timeout=20)
    assert ledger.status(cohort)[1] == a.result()


def _crash_writer(database: str, cohort: str, point: str):
    db = sqlite3.connect(database)
    store = CohortRecoveryStore(db)

    def kill_at_commit(sql):
        if sql == "COMMIT":
            os.kill(os.getpid(), signal.SIGKILL)

    if point == "reserve_before_commit":
        db.set_trace_callback(kill_at_commit)
    pending = store.reserve(
        cohort, phase="intake", operation="extend", observed_at_block=300, evidence_sha256="a5" * 32
    )
    if point == "reserve_after_commit":
        os.kill(os.getpid(), signal.SIGKILL)
    signed = signed_transition(pending)
    if point == "certificate_before_commit":
        db.set_trace_callback(kill_at_commit)
    store.commit(signed)
    os.kill(os.getpid(), signal.SIGKILL)


@pytest.mark.parametrize(
    "point",
    [
        "reserve_before_commit",
        "reserve_after_commit",
        "certificate_before_commit",
        "certificate_after_commit",
    ],
)
def test_sigkill_recovers_at_each_durable_boundary(tmp_path, ledger, recovery, point):
    cohort = digest(recovery[0])
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_writer, args=(str(tmp_path / "recovery.sqlite3"), cohort, point)
    )
    process.start()
    process.join(timeout=30)
    if process.is_alive():
        process.kill()
        process.join()
        pytest.fail("crash writer did not reach its boundary")
    assert process.exitcode == -signal.SIGKILL
    state, pending = ledger.status(cohort)
    assert state.sequence == int(point == "certificate_after_commit")
    assert (pending is not None) == (point in {"reserve_after_commit", "certificate_before_commit"})
    # Resume the reserved bytes or form the first unacknowledged proposal, then
    # retry acknowledgment. Neither path creates a second extension.
    if state.sequence == 0:
        proposal = ledger.reserve(
            cohort,
            phase="intake",
            operation="extend",
            observed_at_block=300,
            evidence_sha256="a5" * 32,
        )
        committed = signed_transition(proposal)
        state = ledger.commit(committed)
        assert ledger.commit(committed) == state
    assert state.sequence == 1
    assert state.targets[0].target_block == 320


def test_store_does_not_take_over_callers_transaction(tmp_path):
    with sqlite3.connect(tmp_path / "busy.sqlite3") as db:
        db.execute("BEGIN")
        with pytest.raises(ValueError, match="existing transaction"):
            CohortRecoveryStore(db)
