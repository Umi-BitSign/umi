from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortRecoveryCoordinator,
    _choice,
    replay_cohort_decisions,
)
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeFenced,
    CohortIntakePublisher,
    history_tip,
)
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_execution import execution_boundary
from umi.open_competition import digest

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import policy as policy


def extension_input(phase, scenario, block=305):
    history = scenario["intake_history"]
    state, _, _ = replay_cohort_decisions(history, scenario["policy"], lambda _: None)
    from umi.competition_cohort_coordinator import CohortPhaseProgress

    progress = CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=digest(history.plan),
        recovery_tip_sha256=history_tip(history),
        phase="intake",
        observed_at_block=block,
        unavailable_blocks=0,
        completion="pending",
        phase_result_sha256=None,
        evidence_sha256="cd" * 32,
    )
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress)),
        observation=execution_boundary(capture_at(block)),
    )
    choice, _ = _choice(state, history.authority.authority, scenario["policy"], evidence, 0, 0)
    return history.model_copy(update={"transitions": (signed_transition(choice),)}), evidence


def test_reopened_fence_restores_closed_interval_even_without_process_restart(phase, scenario):
    original = healthy(phase, scenario)
    history, evidence = extension_input(phase, scenario)
    phase.intake.publish(history, capture_at(305), decision_inputs=(evidence,))
    result = observe(phase, scenario, 305)
    assert result.seal is None and result.progress.unavailable_blocks == 5
    assert result.service.recovery_tip_sha256 != original.service.recovery_tip_sha256
    for block in (310, 315, 320, 325):
        assert observe(phase, scenario, block).seal is None
    assert observe(phase, scenario, 330).seal.observation.block == 330


@pytest.mark.parametrize("bad", ["missing", "duplicate", "signature"])
def test_bad_decision_inputs_cannot_publish_new_history(phase, scenario, bad):
    history, evidence = extension_input(phase, scenario)
    inputs = () if bad == "missing" else (evidence, evidence)
    if bad == "signature":
        evidence = evidence.model_copy(
            update={
                "progress": evidence.progress.model_copy(
                    update={"signatures": signatures(evidence.progress.progress, ("Alice",))}
                )
            }
        )
        inputs = (evidence,)
    with pytest.raises(ValueError):
        phase.intake.publish(history, capture_at(305), decision_inputs=inputs)
    assert phase.intake.history(digest(history.plan)) == scenario["intake_history"]


def test_retry_restores_decision_input_after_partial_publication(phase, scenario, monkeypatch):
    history, evidence = extension_input(phase, scenario)
    original = CohortRecoveryStore.retain_source

    def interrupted(*args, **kwargs):
        raise OSError("lost source commit")

    monkeypatch.setattr(CohortRecoveryStore, "retain_source", interrupted)
    with pytest.raises(OSError, match="lost source"):
        phase.intake.publish(history, capture_at(305), decision_inputs=(evidence,))
    with pytest.raises(ValueError, match="source is missing"):
        observe(phase, scenario, 305)
    monkeypatch.setattr(CohortRecoveryStore, "retain_source", original)
    phase.intake.publish(history, capture_at(305), decision_inputs=(evidence,))
    result = observe(phase, scenario, 305)
    assert result.seal is None and result.progress.unavailable_blocks == 105


@pytest.fixture
def phase(intake, scenario):
    intake.retain(request_for(scenario), capture_at(210))
    return CohortIntakePhaseObserver(intake)


def observe(phase, scenario, block, serving=True):
    cohort = digest(scenario["intake_history"].plan)
    return phase.observe(
        cohort,
        capture_at(block),
        serving=serving,
        expected_tip_sha256=history_tip(phase.intake.history(cohort)),
    )


def healthy(phase, scenario, end=300):
    for block in range(200, end + 1, 5):
        result = observe(phase, scenario, block)
    return result


def test_native_fence_survives_signing_outage_and_keeps_original_evidence(phase, scenario):
    result = healthy(phase, scenario)
    assert result.progress.completion == "complete"
    assert result.seal.observation.block == 300
    cohort = result.progress.cohort_sha256
    with pytest.raises(CohortIntakeFenced):
        phase.intake.retain(request_for(scenario, sequence=2, block=301), capture_at(301))
    reopened = CohortIntakePhaseObserver(CohortIntake(phase.intake.config, scenario["policy"]))
    recovered = observe(reopened, scenario, 10000)
    assert recovered.seal == result.seal
    assert recovered.service == result.service
    assert recovered.progress.unavailable_blocks == 0
    assert recovered.progress.observed_at_block == 10000
    assert phase.intake.sealed(cohort) == result.seal


def test_short_database_connections_share_service_epoch_but_restart_does_not(phase, scenario):
    before = observe(phase, scenario, 200)
    assert observe(phase, scenario, 205).service.process_epoch == before.service.process_epoch
    reopened = CohortIntakePhaseObserver(phase.intake)
    after = observe(reopened, scenario, 210)
    assert after.service.process_epoch != before.service.process_epoch
    assert after.progress.unavailable_blocks == 5


def test_unknown_gap_delays_fence_even_without_a_published_extension(phase, scenario):
    observe(phase, scenario, 200)
    result = observe(phase, scenario, 1400)
    assert result.seal is None and result.progress.unavailable_blocks == 1200
    for block in range(1405, 1500, 5):
        assert observe(phase, scenario, block).seal is None
    assert observe(phase, scenario, 1500).seal.observation.block == 1500


def test_failed_readiness_at_target_keeps_admission_open(phase, scenario):
    healthy(phase, scenario, 295)
    failed = observe(phase, scenario, 300, False)
    assert failed.seal is None and failed.progress.unavailable_blocks == 5
    recovered = observe(phase, scenario, 305)
    assert recovered.seal is None and recovered.progress.unavailable_blocks == 10
    assert observe(phase, scenario, 310).seal is not None


def test_empty_intake_returns_pending_so_controller_can_extend(intake, scenario):
    result = healthy(CohortIntakePhaseObserver(intake), scenario)
    assert result.seal is None and result.progress.completion == "pending"


def test_capacity_failure_is_recorded_as_unavailable_service(phase, scenario):
    observe(phase, scenario, 200)
    phase.intake.capacity = phase.intake.capacity.model_copy(update={"maximum_records": 1})
    result = observe(phase, scenario, 205)
    assert not result.service.serving and result.progress.unavailable_blocks == 5


def test_seal_and_service_evidence_commit_atomically(phase, scenario):
    healthy(phase, scenario, 295)
    path = Path(phase.intake.config.directory) / "intake.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TRIGGER stop_seal BEFORE INSERT ON cohort_intake_service_seals
            BEGIN SELECT RAISE(ABORT,'interrupted seal'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="interrupted seal"):
        observe(phase, scenario, 300)
    assert phase.intake.sealed(digest(scenario["intake_history"].plan)) is None
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER stop_seal")
    result = observe(phase, scenario, 300)
    assert result.seal is not None and result.progress.unavailable_blocks == 0


def test_legacy_seal_cannot_fabricate_service_evidence_after_restart(phase, scenario):
    cohort = digest(scenario["intake_history"].plan)
    phase.intake.seal(
        cohort, capture_at(300), expected_tip_sha256=history_tip(phase.intake.history(cohort))
    )
    with pytest.raises(ValueError, match="lacks retained service"):
        observe(phase, scenario, 10000)


def test_extensions_require_original_progress_inputs(phase, scenario):
    history = transition(
        scenario["intake_history"], scenario["policy"], "extend", 300, extension=20
    )
    phase.intake.publish(history, capture_at(310))
    with pytest.raises(ValueError, match="source is missing"):
        observe(phase, scenario, 310)


def test_fork_cannot_reuse_parent_service_epoch(phase, scenario, monkeypatch):
    import umi.competition_cohort_availability as module

    pid = module.os.getpid()
    monkeypatch.setattr(module.os, "getpid", lambda: pid + 1)
    with pytest.raises(ValueError, match="another process"):
        observe(phase, scenario, 200)


def test_observer_rejects_changed_generation(phase, scenario):
    cohort = digest(scenario["intake_history"].plan)
    with pytest.raises(ValueError, match="history changed"):
        phase.observe(cohort, capture_at(200), serving=True, expected_tip_sha256="01" * 32)


@pytest.mark.parametrize("sequence", [10, 21])
def test_corrupt_service_fence_is_not_accepted_on_retry(phase, scenario, sequence):
    healthy(phase, scenario)
    with sqlite3.connect(Path(phase.intake.config.directory) / "intake.sqlite3") as db:
        db.execute("DELETE FROM cohort_service_observations WHERE sequence=?", (sequence,))
    with pytest.raises(ValueError, match=r"incomplete or inconsistent|differs from its service"):
        observe(phase, scenario, 10000)


@pytest.mark.parametrize("fail_publication", [False, True])
@pytest.mark.parametrize("failure_stage", ["progress_attestation", "transition_signing"])
def test_native_controller_restores_outage_once_and_closes_after_signing_restart(
    phase,
    scenario,
    tmp_path,
    fail_publication,
    failure_stage,
):
    history = scenario["intake_history"]
    cohort = digest(history.plan)
    with sqlite3.connect(tmp_path / "coordinator.sqlite3") as db:
        store = CohortRecoveryStore(db)
        store.publish_history(history, scenario["policy"], current_block=200)
        block = 200
        fail_sign = False

        class Provider:
            async def collect(self):
                return capture_at(block)

        provider = Provider()

        async def source(cohort, key):
            return store.source(cohort, key, CohortDecisionInput)

        publisher = CohortIntakePublisher(phase.intake, provider.collect, source)
        published = False

        async def publish(history):
            nonlocal published
            await publisher(history)
            if fail_publication and len(history.transitions) == 1 and not published:
                published = True
                raise OSError("lost publication acknowledgement")

        async def progress(state, capture):
            result = phase.observe(
                cohort, capture, serving=True, expected_tip_sha256=state.tip_sha256
            )
            if fail_sign and failure_stage == "progress_attestation":
                raise OSError("signer unavailable")
            return AttestedCohortPhaseProgress(
                progress=result.progress, signatures=signatures(result.progress)
            )

        async def certify(proposal, evidence):
            if fail_sign:
                raise OSError("signer unavailable")
            return signed_transition(proposal)

        def coordinator():
            return CohortRecoveryCoordinator(
                store,
                cohort,
                scenario["policy"],
                history.genesis_signatures,
                provider,
                progress,
                certify,
                publish,
            )

        asyncio.run(coordinator().tick())
        block = 1400
        if fail_publication:
            with pytest.raises(OSError, match="acknowledgement"):
                asyncio.run(coordinator().tick())
        asyncio.run(coordinator().tick())
        assert store.status(cohort)[0].targets[0].target_block == 1500
        assert store.status(cohort)[0].sequence == 1
        for block in range(1405, 1500, 5):  # noqa: B007 - provider reads the closure
            asyncio.run(coordinator().tick())
        block = 1500
        fail_sign = True
        with pytest.raises(OSError, match="signer unavailable"):
            asyncio.run(coordinator().tick())
        frozen = phase.intake.sealed(cohort)
        assert frozen.observation.block == 1500
        fail_sign = False
        block = 10000
        asyncio.run(coordinator().tick())
        state = store.status(cohort)[0]
        assert state.phase == "preparation" and state.sequence == 2
        assert phase.intake.sealed(cohort, frozen.recovery_tip_sha256) == frozen
        assert phase.intake.history(cohort).transitions[-1].transition.observed_at_block == (
            1500 if failure_stage == "transition_signing" else 10000
        )
        with pytest.raises(ValueError, match="closed"):
            observe(phase, scenario, 10000)
