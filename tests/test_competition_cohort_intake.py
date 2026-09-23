from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
)
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeBinding,
    CohortIntakeConfig,
    CohortIntakePublisher,
    history_tip,
)
from umi.competition_cohort_participation import CohortParticipationRequest
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.competition_execution import execution_boundary
from umi.competition_service import create_intake_app
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_service import Provider
from .test_competition_service import config as config
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, submission, wallet


def capture_at(block):
    provider = Provider(None, None)
    snap = snapshot(block)
    return provider.capture.__class__(
        snapshot=snap,
        provenance={
            **provider.capture.provenance,
            "block": block,
            "block_hash": snap.block_hash,
            "snapshot_sha256": digest(snap),
        },
    )


@pytest.fixture
def intake(tmp_path, scenario):
    history = scenario["intake_history"]
    config = CohortIntakeConfig(
        directory=str(tmp_path / "cohort-intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=digest(history.plan),
                authority_sha256=digest(history.authority.authority),
            ),
        ),
    )
    service = CohortIntake(config, scenario["policy"], initialize=True)
    service.publish(history, capture_at(210))
    return service


def request_for(scenario, *, sequence=1, block=200):
    signed = submission(scenario["policy"], sequence=sequence)
    body = scenario["consent"].consent.model_copy(
        update={
            "signed_at_block": block,
            "submission_sha256": digest(signed.submission),
        }
    )
    consent = scenario["consent"].__class__(
        consent=body, signature=sign_object(body, wallet("Alice"))
    )
    return CohortParticipationRequest(signed_submission=signed, consent=consent)


def seal_and_close(intake, scenario, *, block=300):
    policy = scenario["policy"]
    cohort = digest(scenario["intake_history"].plan)
    history = intake.history(cohort)
    tip = history_tip(history)
    seal = intake.seal(cohort, capture_at(block), expected_tip_sha256=tip)
    progress = CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=cohort,
        recovery_tip_sha256=tip,
        phase="intake",
        observed_at_block=block,
        unavailable_blocks=0,
        completion="complete",
        phase_result_sha256=digest(seal),
        evidence_sha256=digest(seal),
    )
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress)),
        observation=execution_boundary(capture_at(block)),
    )
    state = verify_cohort_history(
        history, policy, expected_tip_sha256=tip, current_block=block
    ).state
    closing = propose_recovery_transition(
        state,
        history.authority.authority,
        operation="close_phase",
        observed_at_block=block,
        evidence_sha256=digest(evidence),
    )
    closed = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(closing))}
    )
    return closed, evidence, seal


def test_extended_intake_retains_explicit_consent_beyond_original_expiry(intake, scenario):
    history = transition(
        scenario["intake_history"], scenario["policy"], "extend", 1600, extension=1200
    )
    intake.publish(history, capture_at(1610))
    request = request_for(scenario, block=1610)
    original = canonical_json_bytes(request.signed_submission)
    receipt = intake.retain(request, capture_at(1610))
    assert receipt["status"] == "pending_attestation"
    assert receipt["certified"] is receipt["rewards_active"] is False
    assert receipt["proposed_admission"]["uid"] == 6
    assert intake.retained_registration_blocks() == frozenset({1610})
    reopened = CohortIntake(intake.config, scenario["policy"])
    assert reopened.receipt(request) == receipt
    assert canonical_json_bytes(request.signed_submission) == original


def test_closed_intake_rejects_new_work_but_keeps_exact_receipt(intake, scenario):
    request = request_for(scenario)
    receipt = intake.retain(request, capture_at(210))
    history, evidence, _ = seal_and_close(intake, scenario)
    intake.publish(history, capture_at(310), closure_input=evidence)
    assert intake.receipt(request) == receipt
    with pytest.raises(ValueError, match="not open"):
        intake.retain(request_for(scenario, sequence=2, block=310), capture_at(310))


def test_published_history_cannot_roll_back_or_fork(intake, scenario):
    original = scenario["intake_history"]
    current = transition(original, scenario["policy"], "extend", 300, extension=20)
    cohort = digest(original.plan)
    intake.publish(current, capture_at(310))
    intake.publish(current, capture_at(310))
    for candidate in (
        original,
        transition(original, scenario["policy"], "extend", 300, extension=30),
    ):
        with pytest.raises(ValueError, match=r"rolls back|forks"):
            intake.publish(candidate, capture_at(310))
    assert intake.history(cohort) == current


def test_failed_multiphase_import_is_atomic(intake, scenario):
    cohort = digest(scenario["intake_history"].plan)
    intake.retain(request_for(scenario), capture_at(210))
    closed, evidence, _ = seal_and_close(intake, scenario)
    complete = transition(closed, scenario["policy"], "close_phase", 400)
    path = Path(intake.config.directory) / "intake.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TRIGGER stop_import BEFORE INSERT ON cohort_recovery_decisions
            WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'simulated interruption'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="interruption"):
        intake.publish(complete, capture_at(1800), closure_input=evidence)
    assert intake.history(cohort) == scenario["intake_history"]
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER stop_import")
    intake.publish(complete, capture_at(1800), closure_input=evidence)
    assert intake.history(cohort) == complete


def test_no_silent_state_recreation_or_configuration_rebinding(intake, scenario):
    config = intake.config
    changed = scenario["policy"].model_copy(update={"sequence": 2})
    with pytest.raises(ValueError, match="another configuration"):
        CohortIntake(config, changed)
    (Path(config.directory) / "intake.sqlite3").unlink()
    with pytest.raises(FileNotFoundError):
        CohortIntake(config, scenario["policy"])
    assert not (Path(config.directory) / "intake.sqlite3").exists()


@pytest.mark.parametrize("damage", ["ancestry", "snapshot", "wrong_tip"])
def test_publication_rejects_unowned_or_future_observations(intake, scenario, damage):
    capture = capture_at(210)
    if damage == "ancestry":
        capture.provenance["evidence_class"] = "verified_finalized_ancestry"
    elif damage == "snapshot":
        capture.provenance["snapshot_sha256"] = "01" * 32
    else:
        capture = capture_at(150)
    with pytest.raises(ValueError):
        intake.publish(scenario["intake_history"], capture)


def test_service_exposes_live_history_and_retries_without_new_finality(
    config, policy, intake, scenario
):
    config = config.model_copy(update={"recoverable_intake": intake.config})
    provider = Provider(config.chain, policy)
    provider.capture = capture_at(210)
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)
    cohort = digest(scenario["intake_history"].plan)
    request = request_for(scenario)
    url = f"/v1/competition/cohorts/{cohort}/participation"
    with TestClient(app) as client:
        index = client.get("/v1/competition/cohorts")
        assert index.status_code == 200
        assert index.headers["cache-control"] == "no-store"
        assert index.json()["cohorts"][0]["cohort_sha256"] == cohort
        reply = client.post(
            url, content=canonical_json_bytes(request), headers={"content-type": "application/json"}
        )
        assert reply.status_code == 200, reply.text
        assert reply.json()["status"] == "pending_attestation"
        assert client.get(f"/v1/competition/cohorts/{cohort}/history").json() == scenario[
            "intake_history"
        ].model_dump(mode="json", by_alias=True)
        provider.error = OSError("PRIVATE RPC endpoint throttled")
        again = client.post(
            url, content=canonical_json_bytes(request), headers={"content-type": "application/json"}
        )
        assert again.status_code == 200
        assert again.json() == reply.json()
        new = client.post(
            url,
            content=canonical_json_bytes(request_for(scenario, sequence=2)),
            headers={"content-type": "application/json"},
        )
        assert new.status_code == 503
        assert "PRIVATE" not in new.text
    assert provider.closed


def test_old_service_config_bytes_and_routes_are_unchanged(config, policy):
    assert "recoverable_intake" not in config.model_dump(mode="json", by_alias=True)
    provider = Provider(config.chain, policy)
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)
    with TestClient(app) as client:
        assert client.get("/v1/competition/cohorts").status_code == 404


def test_state_overlap_is_rejected_by_service_config(config, intake):
    invalid = config.model_copy(
        update={
            "recoverable_intake": intake.config.model_copy(
                update={"directory": config.state_directory}
            )
        }
    )
    with pytest.raises(ValueError, match="overlap"):
        type(config).model_validate_json(canonical_json_bytes(invalid))


def test_publication_cannot_retroactively_invalidate_accepted_work(intake, scenario):
    request = request_for(scenario, block=310)
    receipt = intake.retain(request, capture_at(310))
    history = transition(scenario["intake_history"], scenario["policy"], "close_phase", 300)
    with pytest.raises(ValueError, match="predates retained"):
        intake.publish(history, capture_at(320))
    assert intake.receipt(request) == receipt
    current, evidence, _ = seal_and_close(intake, scenario, block=320)
    intake.publish(current, capture_at(320), closure_input=evidence)
    assert intake.receipt(request) == receipt


def test_different_valid_record_cannot_replace_retry_receipt(intake, scenario):
    first, second = request_for(scenario), request_for(scenario, sequence=2, block=300)
    intake.retain(first, capture_at(210))
    intake.retain(second, capture_at(310))
    with sqlite3.connect(Path(intake.config.directory) / "intake.sqlite3") as db:
        raw = db.execute(
            "SELECT body FROM cohort_consents WHERE consent=?", (digest(second.consent.consent),)
        ).fetchone()[0]
        db.execute(
            "UPDATE cohort_consents SET body=? WHERE consent=?",
            (raw, digest(first.consent.consent)),
        )
    with pytest.raises(ValueError, match="another request"):
        intake.receipt(first)


def test_rejected_configuration_does_not_change_journal_mode(intake, scenario):
    path = Path(intake.config.directory) / "intake.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
    changed = scenario["policy"].model_copy(update={"sequence": 2})
    with pytest.raises(ValueError, match="another configuration"):
        CohortIntake(intake.config, changed)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_capacity_can_increase_without_expiring_retained_work(intake, scenario):
    from umi.competition_store import AdmissionCapacity, AdmissionCapacityError

    limited = CohortIntake(
        intake.config, scenario["policy"], capacity=AdmissionCapacity(maximum_records=1)
    )
    first = request_for(scenario)
    original = limited.retain(first, capture_at(210))
    second = request_for(scenario, sequence=2, block=300)
    with pytest.raises(AdmissionCapacityError):
        limited.retain(second, capture_at(310))
    assert limited.receipt(first) == original
    larger = CohortIntake(
        intake.config, scenario["policy"], capacity=AdmissionCapacity(maximum_records=2)
    )
    assert larger.retain(second, capture_at(310))["status"] == "pending_attestation"
    assert larger.receipt(first) == original


def test_concurrent_duplicate_requests_retain_one_receipt(intake, scenario):
    from concurrent.futures import ThreadPoolExecutor

    request = request_for(scenario)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: intake.retain(request, capture_at(210)), range(8)))
    assert results == [results[0]] * 8
    with sqlite3.connect(Path(intake.config.directory) / "intake.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone()[0] == 1


async def test_native_publisher_drains_commit_before_cancellation(intake, scenario, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    publish = intake.publish
    history = transition(
        scenario["intake_history"], scenario["policy"], "extend", 300, extension=20
    )

    def blocked(history, capture):
        entered.set()
        assert release.wait(5)
        return publish(history, capture)

    async def capture():
        return capture_at(310)

    monkeypatch.setattr(intake, "publish", blocked)
    task = asyncio.create_task(CohortIntakePublisher(intake, capture)(history))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert intake.history(digest(history.plan)) == history
