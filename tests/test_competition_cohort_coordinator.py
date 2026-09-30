from __future__ import annotations

import asyncio
import sqlite3

import pytest

from umi.competition_chain import RegistrationCapture
from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
    CohortRecoveryCoordinator,
    poll_recovery_cohorts,
)
from umi.competition_cohort_recovery import PHASES, admit_recoverable_cohort
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_execution import execution_boundary
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import policy as policy
from .test_open_competition import snapshot


class Harness:
    def __init__(self, tmp_path, recovery, policy):
        self.plan, self.authority, _ = recovery
        self.policy = policy
        self.path = tmp_path / "recovery.sqlite3"
        self.db = sqlite3.connect(self.path)
        self.store = CohortRecoveryStore(self.db)
        self.store.admit(self.plan, self.authority, policy, admitted_at_block=160)
        genesis, _ = admit_recoverable_cohort(
            self.plan, self.authority, policy, admitted_at_block=160
        )
        self.genesis_signatures = signatures(genesis)
        self.block = 220
        self.unavailable = 0
        self.complete = False
        self.collects = 0
        self.fail_collect = False
        self.fail_sign = False
        self.fail_publish_sequence = None
        self.progress_changes = {}
        self.names = ("Charlie", "Dave")
        self.attempts = []
        self.publications = []

    @property
    def cohort(self):
        return digest(self.plan)

    @property
    def state(self):
        return self.store.status(self.cohort)[0]

    def coordinator(self):
        return CohortRecoveryCoordinator(
            self.store,
            self.cohort,
            self.policy,
            self.genesis_signatures,
            self,
            self.observe,
            self.certify,
            self.publish,
        )

    def restart(self):
        self.db.close()
        self.db = sqlite3.connect(self.path)
        self.store = CohortRecoveryStore(self.db)
        return self.coordinator()

    async def collect(self):
        self.collects += 1
        if self.fail_collect:
            raise OSError("RPC throttled")
        snap = snapshot(self.block)
        return RegistrationCapture(
            snapshot=snap,
            provenance={
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "chain_submission_authorized": False,
                "snapshot_sha256": digest(snap),
                "block": snap.block,
                "block_hash": snap.block_hash,
                "state_root": "0x" + "aa" * 32,
                "evidence_sha256": "bb" * 32,
            },
        )

    async def observe(self, state, capture):
        progress = CohortPhaseProgress(
            schema="umi-cohort-phase-progress/1",
            cohort_sha256=self.cohort,
            recovery_tip_sha256=state.tip_sha256,
            phase=state.phase,
            observed_at_block=capture.snapshot.block,
            unavailable_blocks=self.unavailable,
            completion="complete" if self.complete else "pending",
            phase_result_sha256="c1" * 32 if self.complete else None,
            evidence_sha256="c2" * 32,
        ).model_copy(update=self.progress_changes)
        return AttestedCohortPhaseProgress(
            progress=progress, signatures=signatures(progress, self.names)
        )

    async def certify(self, proposal, evidence):
        assert proposal.evidence_sha256 == digest(evidence)
        assert self.store.source(self.cohort, digest(evidence), CohortDecisionInput) == evidence
        assert self.store.status(self.cohort)[1] == proposal
        self.attempts.append(proposal)
        if self.fail_sign:
            raise OSError("certifier unavailable")
        return signed_transition(proposal)

    async def publish(self, history):
        self.publications.append(history)
        if self.fail_publish_sequence == len(history.transitions):
            raise OSError("publication acknowledgement lost")

    def tick(self, coordinator=None):
        return asyncio.run((coordinator or self.coordinator()).tick())

    def advance_to(self, phase):
        self.complete = True
        while self.state.phase != phase:
            state = self.state
            self.block = state.targets[PHASES.index(state.phase)].target_block
            self.tick()
        self.complete = False


@pytest.fixture
def harness(tmp_path, recovery, policy):
    value = Harness(tmp_path, recovery, policy)
    yield value
    value.db.close()


def test_healthy_window_does_not_extend_each_poll_or_close_on_time_alone(harness):
    for block in (200, 220, 290, 299):
        harness.block = block
        assert harness.tick()["status"] == "waiting_phase_progress"
        assert harness.state.sequence == 0
    harness.block = 300
    harness.tick()
    assert harness.state.phase == "intake"
    assert harness.state.targets[0].target_block == 320
    assert harness.attempts[-1].operation == "extend"


@pytest.mark.parametrize("phase", PHASES)
def test_four_hour_outage_can_resume_every_phase_then_complete(harness, phase):
    harness.advance_to(phase)
    before = harness.state
    index = PHASES.index(phase)
    harness.block = before.targets[index].target_block + 1200
    harness.unavailable = 1200
    harness.tick(harness.restart())
    assert harness.state.targets[index].target_block == before.targets[index].target_block + 1200
    assert harness.state.phase == phase
    harness.complete = True
    harness.block += 1
    harness.tick(harness.restart())
    assert harness.state.phase == (PHASES[index + 1] if index < 7 else "complete")
    assert harness.state.targets[:index] == before.targets[:index]
    assert harness.publications[-1].transitions[-1].transition.operation == "close_phase"
    assert harness.block > harness.policy.valid_through_block


def test_partial_outage_compensation_is_not_counted_twice_after_restart(harness):
    harness.unavailable = 1500
    harness.block = 1700
    harness.tick()
    assert harness.state.targets[0].target_block == 1500
    harness.tick(harness.restart())
    assert harness.state.targets[0].target_block == 1800
    sequence = harness.state.sequence
    assert harness.tick(harness.restart())["status"] == "waiting_phase_progress"
    assert harness.state.sequence == sequence
    harness.block = 1800
    harness.complete = True
    harness.tick()
    assert harness.state.phase == "preparation"


@pytest.mark.parametrize("phase", ["intake", "requests"])
def test_quorum_cannot_close_participant_window_without_restoring_lost_time(harness, phase):
    harness.advance_to(phase)
    before = harness.state
    harness.block = before.targets[PHASES.index(phase)].target_block
    harness.complete = True
    harness.unavailable = 100
    with pytest.raises(ValueError, match="restoring unavailable"):
        harness.tick()
    assert harness.state == before
    harness.block += 100
    harness.tick()
    assert harness.attempts[-1].operation == "close_phase"


def test_completed_nonwindow_work_is_not_reopened_to_compensate_outage(harness):
    harness.advance_to("evidence")
    harness.block = harness.state.targets[4].target_block + 1200
    harness.unavailable = 1200
    harness.complete = True
    harness.tick()
    assert harness.state.phase == "review"
    assert harness.attempts[-1].operation == "close_phase"
    assert harness.state.targets[5].target_block == harness.block + 90


def test_reference_reveal_waits_for_a_subsequent_finalized_block(harness):
    harness.advance_to("reference_reveal")
    harness.complete = True
    assert harness.tick()["status"] == "waiting_phase_progress"
    assert harness.state.phase == "reference_reveal"
    harness.block += 1
    harness.tick()
    assert harness.state.phase == "evidence"


def test_reserved_signature_retry_survives_reboot_and_throttled_rpc(harness):
    harness.block = 300
    harness.fail_sign = True
    with pytest.raises(OSError, match="certifier"):
        harness.tick()
    original = canonical_json_bytes(harness.attempts[-1])
    assert harness.state.sequence == 0
    harness.fail_collect = True
    harness.fail_sign = False
    harness.block += 1200
    harness.tick(harness.restart())
    assert harness.collects == 1
    assert canonical_json_bytes(harness.attempts[-1]) == original
    assert harness.state.sequence == 1


def test_publication_ack_loss_retries_committed_history_before_observing(harness):
    harness.block = 300
    harness.fail_publish_sequence = 1
    with pytest.raises(OSError, match="acknowledgement"):
        harness.tick()
    assert harness.state.sequence == 1
    committed = harness.publications[-1]
    harness.fail_publish_sequence = None
    harness.fail_collect = True
    with pytest.raises(OSError, match="RPC"):
        harness.tick(harness.restart())
    assert harness.publications[-1] == committed
    assert len(harness.attempts) == 1


@pytest.mark.parametrize("terminal", ["complete", "revoked"])
def test_terminal_history_republishes_without_rpc_or_signer(harness, terminal):
    if terminal == "complete":
        harness.advance_to("first_admission")
        harness.block = harness.state.targets[-1].target_block
        harness.complete = True
        harness.tick()
    else:
        pending = harness.store.reserve(
            harness.cohort,
            phase="intake",
            operation="revoke",
            observed_at_block=170,
            evidence_sha256="c3" * 32,
        )
        assert harness.tick()["status"] == "awaiting_revocation_certificate"
        assert not harness.attempts
        harness.store.commit(signed_transition(pending))
    previous_collects = harness.collects
    harness.fail_collect = harness.fail_sign = True
    assert harness.tick(harness.restart())["status"] == terminal
    assert harness.collects == previous_collects


@pytest.mark.parametrize(
    "changes",
    [
        {"recovery_tip_sha256": "e0" * 32},
        {"cohort_sha256": "e1" * 32},
        {"phase": "requests"},
        {"observed_at_block": 150},
        {"observed_at_block": 289},
        {"observed_at_block": 301},
    ],
)
def test_wrong_scope_future_or_stale_progress_never_reserves(harness, changes):
    harness.block = 300
    harness.progress_changes = changes
    with pytest.raises(ValueError, match="stale, regressed"):
        harness.tick()
    assert harness.store.status(harness.cohort)[1] is None
    assert not harness.attempts


def test_single_group_cannot_authorize_extension(harness):
    harness.block = 300
    harness.names = ("Charlie",)
    with pytest.raises(ValueError):
        harness.tick()
    assert not harness.attempts


@pytest.mark.parametrize("unavailable", [20, 1500])
def test_outage_counter_cannot_regress_after_compensated_extension(harness, unavailable):
    harness.unavailable = unavailable
    harness.tick()
    harness.unavailable -= 1
    with pytest.raises(ValueError, match="regressed"):
        harness.tick(harness.restart())


@pytest.mark.parametrize("damage", ["missing", "tampered"])
def test_retained_input_corruption_stops_restart_without_new_signatures(harness, damage):
    harness.block = 300
    harness.tick()
    if damage == "missing":
        harness.db.execute("DELETE FROM cohort_recovery_sources")
    else:
        harness.db.execute("UPDATE cohort_recovery_sources SET body=?", (b"{}",))
    harness.db.commit()
    with pytest.raises(ValueError):
        harness.restart()
    assert len(harness.attempts) == 1


def test_ancestral_observation_cannot_stand_in_for_current_finality(harness):
    async def run():
        capture = await harness.collect()
        evidence = CohortDecisionInput(
            schema="umi-cohort-decision-input/1",
            progress=await harness.observe(harness.state, capture),
            observation=execution_boundary(capture),
        )
        modified = evidence.model_copy(
            update={
                "observation": evidence.observation.model_copy(
                    update={"source": "verified_finalized_ancestry"}
                )
            }
        )
        with pytest.raises(ValueError):
            CohortDecisionInput.model_validate_json(canonical_json_bytes(modified))

    asyncio.run(run())


def test_cancelled_signer_leaves_resumable_intent(harness):
    async def run():
        harness.block = 300
        entered = asyncio.Event()
        coordinator = harness.coordinator()

        async def waiting(proposal, evidence):
            entered.set()
            await asyncio.Event().wait()

        coordinator.certify = waiting
        task = asyncio.create_task(coordinator.tick())
        await asyncio.wait_for(entered.wait(), 2)
        pending = harness.store.status(harness.cohort)[1]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        harness.fail_collect = True
        await harness.restart().tick()
        assert harness.attempts == [pending]

    asyncio.run(run())


def test_certifier_cannot_replace_reserved_decision(harness):
    async def run():
        harness.block = 300
        coordinator = harness.coordinator()

        async def wrong(proposal, _evidence):
            return signed_transition(proposal.model_copy(update={"observed_at_block": 301}))

        coordinator.certify = wrong
        with pytest.raises(ValueError, match="another cohort decision"):
            await coordinator.tick()
        assert harness.state.sequence == 0
        pending = harness.store.status(harness.cohort)[1]
        harness.fail_collect = True
        await harness.restart().tick()
        assert harness.attempts == [pending]

    asyncio.run(run())


def test_concurrent_controllers_finish_one_reserved_decision(harness):
    async def run():
        harness.block = 300
        entered = 0
        both = asyncio.Event()
        first, second = harness.coordinator(), harness.coordinator()

        async def delayed(proposal, evidence):
            nonlocal entered
            entered += 1
            if entered == 2:
                both.set()
            await asyncio.wait_for(both.wait(), 2)
            harness.attempts.append(proposal)
            return signed_transition(proposal)

        first.certify = second.certify = delayed
        await asyncio.gather(first.tick(), second.tick())
        assert entered == 2
        assert harness.attempts[0] == harness.attempts[1]
        assert harness.state.sequence == 1
        assert harness.state.targets[0].target_block == 320

    asyncio.run(run())


def test_transient_provider_failure_retries_without_manual_intervention():
    async def run():
        stop = asyncio.Event()
        reports = []

        class Recovering:
            cohort = "a" * 64
            calls = 0

            async def tick(self):
                self.calls += 1
                if self.calls == 1:
                    raise OSError("provider throttled")
                return {"status": "advanced"}

        def report(value):
            reports.append(value)
            if value["status"] == "advanced":
                stop.set()

        await asyncio.wait_for(
            poll_recovery_cohorts([Recovering()], stop, report, poll_seconds=0.001), 2
        )
        assert [r["status"] for r in reports] == ["cohort_recovery_retry", "advanced"]

    asyncio.run(run())


def test_slow_cohort_does_not_block_other_cohorts_and_stop_joins_tasks():
    async def run():
        stop, entered, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
        reports = []

        class Slow:
            cohort = "a" * 64

            async def tick(self):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

        class Available:
            cohort = "b" * 64

            async def tick(self):
                await entered.wait()
                return {"status": "advanced", "cohort_sha256": self.cohort}

        def report(value):
            reports.append(value)
            stop.set()

        await asyncio.wait_for(
            poll_recovery_cohorts([Slow(), Available()], stop, report, poll_seconds=0.01), 2
        )
        assert reports == [{"status": "advanced", "cohort_sha256": "b" * 64}]
        assert cancelled.is_set()

    asyncio.run(run())
