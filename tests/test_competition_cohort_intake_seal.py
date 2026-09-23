from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from umi.competition_cohort_coordinator import CohortDecisionInput, CohortRecoveryCoordinator
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeFenced,
    CohortIntakePublisher,
    history_tip,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_service import create_intake_app
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for, seal_and_close
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_service import Provider
from .test_competition_service import config as config
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import policy as policy


def identity(intake, scenario):
    cohort = digest(scenario["intake_history"].plan)
    return cohort, history_tip(intake.history(cohort))


def test_seal_freezes_latest_submission_and_keeps_receipts_after_long_outage(intake, scenario):
    first, second = request_for(scenario), request_for(scenario, sequence=2, block=310)
    receipt = intake.retain(first, capture_at(210))
    receipt2 = intake.retain(second, capture_at(310))
    cohort, tip = identity(intake, scenario)
    seal = intake.seal(cohort, capture_at(320), expected_tip_sha256=tip)
    assert seal.record_count == 2
    assert len(seal.selected) == 1
    assert seal.selected[0].consent_sha256 == digest(second.consent.consent)
    assert seal.selected[0].record_sha256 == receipt2["record_sha256"]
    assert seal.selected[0].uid == 6
    reopened = CohortIntake(intake.config, scenario["policy"])
    assert reopened.seal(cohort, capture_at(5000), expected_tip_sha256=tip) == seal
    assert reopened.receipt(first) == receipt
    assert reopened.retain(second, capture_at(5000)) == receipt2
    with pytest.raises(CohortIntakeFenced):
        reopened.retain(request_for(scenario, sequence=3, block=5000), capture_at(5000))
    assert reopened.retained_registration_blocks() == frozenset({210, 310, 320})


def test_empty_or_early_window_is_not_fenced(intake, scenario):
    cohort, tip = identity(intake, scenario)
    with pytest.raises(ValueError):
        intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    request = request_for(scenario)
    intake.retain(request, capture_at(210))
    for block, expected in [(299, tip), (300, "ab" * 32)]:
        with pytest.raises(ValueError):
            intake.seal(cohort, capture_at(block), expected_tip_sha256=expected)
        assert intake.sealed(cohort) is None
    assert intake.seal(cohort, capture_at(300), expected_tip_sha256=tip).record_count == 1


def test_extension_opens_new_generation_without_changing_the_preserved_seal(intake, scenario):
    first = request_for(scenario)
    intake.retain(first, capture_at(210))
    cohort, tip = identity(intake, scenario)
    old = intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    history = transition(intake.history(cohort), scenario["policy"], "extend", 1600, extension=1200)
    intake.publish(history, capture_at(1600))
    assert intake.sealed(cohort) is None
    second = request_for(scenario, sequence=2, block=1600)
    intake.retain(second, capture_at(1600))
    assert intake.sealed(cohort, tip) == old
    new = intake.seal(cohort, capture_at(1601), expected_tip_sha256=history_tip(history))
    assert new.record_count == 2 and new.selected[0].sequence == 2
    closed, evidence, _ = seal_and_close(intake, scenario, block=1601)
    intake.publish(closed, capture_at(5000), closure_input=evidence)
    assert intake.sealed(cohort, tip) == old
    with pytest.raises(ValueError, match="not open"):
        intake.retain(request_for(scenario, sequence=3, block=5000), capture_at(5000))


@pytest.mark.parametrize(
    "failure",
    ["missing_seal", "missing_input", "result", "quorum", "progress_tip", "decision_digest"],
)
def test_closure_cannot_publish_unfenced_or_different_membership(intake, scenario, failure):
    intake.retain(request_for(scenario), capture_at(210))
    cohort, _ = identity(intake, scenario)
    before = intake.history(cohort)
    closed, evidence, _ = seal_and_close(intake, scenario)
    if failure == "missing_seal":
        with sqlite3.connect(Path(intake.config.directory) / "intake.sqlite3") as db:
            db.execute("DELETE FROM cohort_intake_seals")
    elif failure == "missing_input":
        evidence = None
    elif failure == "quorum":
        evidence = evidence.model_copy(
            update={
                "progress": evidence.progress.model_copy(
                    update={"signatures": evidence.progress.signatures[:1]}
                )
            }
        )
    elif failure in ("result", "progress_tip"):
        field = "phase_result_sha256" if failure == "result" else "recovery_tip_sha256"
        progress = evidence.progress.progress.model_copy(update={field: "ab" * 32})
        evidence = evidence.model_copy(
            update={
                "progress": evidence.progress.model_copy(
                    update={"progress": progress, "signatures": signatures(progress)}
                )
            }
        )
    elif failure == "decision_digest":
        closing = closed.transitions[-1].transition.model_copy(
            update={"evidence_sha256": "ab" * 32}
        )
        closed = closed.model_copy(
            update={"transitions": (*closed.transitions[:-1], signed_transition(closing))}
        )
    with pytest.raises(ValueError):
        intake.publish(closed, capture_at(310), closure_input=evidence)
    assert intake.history(cohort) == before


@pytest.mark.parametrize("failure", ["seal_changed", "record_missing"])
def test_modified_record_or_seal_is_detected_after_restart(intake, scenario, failure):
    intake.retain(request_for(scenario), capture_at(210))
    intake.retain(request_for(scenario, sequence=2, block=300), capture_at(300))
    cohort, tip = identity(intake, scenario)
    seal = intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    with sqlite3.connect(Path(intake.config.directory) / "intake.sqlite3") as db:
        if failure == "seal_changed":
            db.execute(
                "UPDATE cohort_intake_seals SET body=?",
                (canonical_json_bytes(seal.model_copy(update={"records_sha256": "ab" * 32})),),
            )
        else:
            db.execute("DELETE FROM cohort_consents WHERE sequence=1")
    with pytest.raises(ValueError, match="differs from its original records"):
        CohortIntake(intake.config, scenario["policy"]).sealed(cohort)


@pytest.mark.parametrize("who_first", ["submission", "seal"])
def test_concurrent_submission_is_either_included_or_retryable(intake, scenario, who_first):
    # Real separate CohortIntake objects share the private file lock.
    import threading

    cohort, tip = identity(intake, scenario)
    intake.retain(request_for(scenario), capture_at(210))
    second = request_for(scenario, sequence=2, block=300)
    other = CohortIntake(intake.config, scenario["policy"])
    start = threading.Barrier(2)
    first_done = threading.Event()

    def submit():
        start.wait(timeout=5)
        if who_first == "seal":
            assert first_done.wait(5)
        try:
            return other.retain(second, capture_at(300))
        except CohortIntakeFenced:
            return "fenced"
        finally:
            if who_first == "submission":
                first_done.set()

    def seal():
        start.wait(timeout=5)
        if who_first == "submission":
            assert first_done.wait(5)
        try:
            return intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
        finally:
            if who_first == "seal":
                first_done.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(submit), pool.submit(seal)
        receipt, result = a.result(timeout=10), b.result(timeout=10)
    if who_first == "submission":
        assert receipt["record_sha256"] == result.selected[0].record_sha256
        assert result.record_count == 2
    else:
        assert receipt == "fenced" and result.record_count == 1
        assert other.receipt(second) is None


def test_commit_failure_does_not_partially_fence_or_lose_work(intake, scenario):
    intake.retain(request_for(scenario), capture_at(210))
    cohort, tip = identity(intake, scenario)
    path = Path(intake.config.directory) / "intake.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TRIGGER fail_seal BEFORE INSERT ON cohort_intake_seals "
            "BEGIN SELECT RAISE(ABORT,'disk full'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="disk full"):
        intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    assert intake.sealed(cohort) is None
    intake.retain(request_for(scenario, sequence=2, block=310), capture_at(310))
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER fail_seal")
    assert intake.seal(cohort, capture_at(320), expected_tip_sha256=tip).record_count == 2


def test_fenced_api_preserves_accepted_retry_without_registration_rpc(
    config, policy, intake, scenario
):
    request = request_for(scenario)
    receipt = intake.retain(request, capture_at(210))
    cohort, tip = identity(intake, scenario)
    intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    provider = Provider(config.chain, policy)
    provider.capture = capture_at(310)
    config = config.model_copy(update={"recoverable_intake": intake.config})
    with TestClient(
        create_intake_app(config, policy, provider_factory=lambda *_: provider)
    ) as client:
        url = f"/v1/competition/cohorts/{cohort}/participation"
        new = client.post(
            url,
            content=canonical_json_bytes(request_for(scenario, sequence=2, block=310)),
            headers={"content-type": "application/json"},
        )
        assert new.status_code == 503
        provider.error = OSError("provider throttled")
        again = client.post(
            url, content=canonical_json_bytes(request), headers={"content-type": "application/json"}
        )
        assert again.status_code == 200 and again.json() == receipt


async def test_controller_restarts_after_lost_signature_and_publication_ack_with_same_seal(
    tmp_path, intake, scenario
):
    policy = scenario["policy"]
    history = scenario["intake_history"]
    cohort = digest(history.plan)
    intake.retain(request_for(scenario), capture_at(210))
    path = tmp_path / "coordinator.sqlite3"
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.admit(
        history.plan, history.authority, policy, admitted_at_block=history.genesis.admitted_at_block
    )
    block = 300
    lost_signature = True
    lost_ack = True
    observed = []

    class ProviderPort:
        async def collect(self):
            return capture_at(block)

    async def observe(state, capture):
        _, evidence, seal = seal_and_close(intake, scenario, block=capture.snapshot.block)
        observed.append(seal)
        return evidence.progress

    async def certify(proposal, evidence):
        nonlocal lost_signature
        if lost_signature:
            lost_signature = False
            raise OSError("signer unavailable before reply")
        assert evidence.progress.progress.phase_result_sha256 == digest(observed[0])
        return signed_transition(proposal)

    async def source(cohort, key):
        return store.source(cohort, key, CohortDecisionInput)

    publisher = CohortIntakePublisher(intake, ProviderPort().collect, source)

    async def publish(value):
        nonlocal lost_ack
        await publisher(value)
        if value.transitions and lost_ack:
            lost_ack = False
            raise OSError("publication committed, reply lost")

    def controller():
        return CohortRecoveryCoordinator(
            store,
            cohort,
            policy,
            history.genesis_signatures,
            ProviderPort(),
            observe,
            certify,
            publish,
        )

    try:
        with pytest.raises(OSError, match="signer unavailable"):
            await controller().tick()
        db.close()
        db = sqlite3.connect(path)
        store = CohortRecoveryStore(db)
        block = 1600  # Beyond the original policy after a four-hour outage.
        with pytest.raises(OSError, match="reply lost"):
            await controller().tick()
        assert len(observed) == 1
        assert intake.history(cohort).transitions[-1].transition.phase == "intake"
        assert store.status(cohort)[0].phase == "preparation"
        # Republishing the exact committed history is safe after another restart.
        db.close()
        db = sqlite3.connect(path)
        store = CohortRecoveryStore(db)
        await publisher(store.export_history(cohort, genesis_signatures=history.genesis_signatures))
        assert intake.sealed(cohort, observed[0].recovery_tip_sha256) == observed[0]
        assert intake.receipt(request_for(scenario))["status"] == "pending_attestation"
    finally:
        db.close()
