from __future__ import annotations

import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
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


def request_for(scenario, *, sequence=1, block=200, name="Alice"):
    signed = submission(scenario["policy"], sequence=sequence, name=name)
    body = scenario["consent"].consent.model_copy(
        update={
            "signed_at_block": block,
            "submission_sha256": digest(signed.submission),
            "hotkey": signed.submission.hotkey,
        }
    )
    consent = scenario["consent"].__class__(consent=body, signature=sign_object(body, wallet(name)))
    return CohortParticipationRequest(signed_submission=signed, consent=consent)


def test_retained_history_read_does_not_wait_for_an_unrelated_sqlite_reader(intake, scenario):
    cohort = digest(scenario["intake_history"].plan)
    database = Path(intake.directory) / "intake.sqlite3"
    # A retained read transaction (for example, a backup reader) must not make
    # a native read-only history lookup require SQLite's exclusive write lock.
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as reader:
        reader.execute("BEGIN")
        original_binding = reader.execute("SELECT body FROM intake_binding").fetchall()
        assert intake.history(cohort) == scenario["intake_history"]
        assert reader.execute("SELECT body FROM intake_binding").fetchall() == original_binding
        reader.rollback()


def test_authority_history_does_not_wait_for_intake_writer(intake, scenario):
    cohort = digest(scenario["intake_history"].plan)
    # A real native owner and an uncommitted SQLite write must not prevent
    # either an internal or a fresh exporter lookup of committed history.
    with ThreadPoolExecutor(max_workers=2) as pool, intake._connection() as (db, _):
        db.execute("BEGIN IMMEDIATE")
        try:
            calls = [pool.submit(intake.history, cohort) for _ in range(2)]
            assert [f.result(timeout=60) for f in calls] == [scenario["intake_history"]] * 2
        finally:
            db.rollback()


def test_authority_history_snapshot_rejects_mutation(intake, scenario):
    cohort = digest(scenario["intake_history"].plan)
    with intake._connection(prefer_history=True) as (db, store):
        assert store.published_history(cohort) == scenario["intake_history"]
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("DELETE FROM cohort_consents")
        with pytest.raises(ValueError, match="own atomic transaction"):
            store.retain_source(cohort, scenario["intake_history"].genesis)
        assert store.published_history(cohort) == scenario["intake_history"]
    assert intake.history(cohort) == scenario["intake_history"]


@pytest.mark.parametrize("fault", ["binding", "replacement"])
def test_authority_history_snapshot_rejects_changed_owner(intake, scenario, fault):
    import shutil

    cohort = digest(scenario["intake_history"].plan)
    path = intake.directory / "intake.sqlite3"
    if fault == "binding":
        with intake._connection() as (db, _):
            db.execute("UPDATE intake_binding SET body=?", (b"{}",))
        with pytest.raises(ValueError, match="another configuration"):
            intake.history(cohort)
    else:
        with (
            pytest.raises(ValueError, match="file changed"),
            intake._connection(prefer_history=True) as (_, store),
        ):
            assert store.published_history(cohort) == scenario["intake_history"]
            replacement = path.with_suffix(".replacement")
            shutil.copyfile(path, replacement)
            replacement.chmod(0o600)
            replacement.replace(path)


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


def test_owner_export_includes_superseded_consent_and_bounds_complete_inventory(intake, scenario):
    from umi.competition_cohort_intake_records import read_participation
    from umi.competition_store import AdmissionCapacityError

    intake.retain(request_for(scenario), capture_at(210))
    intake.retain(request_for(scenario, sequence=2, block=240), capture_at(240))
    cohort = digest(scenario["intake_history"].plan)
    original = intake.export_records(cohort, maximum_bytes=1024**2, maximum_records=2)
    assert len(original) == 2
    assert {
        read_participation(raw).request.signed_submission.submission.sequence for _, raw in original
    } == {1, 2}
    for size, count in ((1, 2), (1024**2, 1)):
        with pytest.raises(AdmissionCapacityError):
            intake.export_records(cohort, maximum_bytes=size, maximum_records=count)
    restored = CohortIntake(intake.config, intake.policy)
    assert restored.export_records(cohort, maximum_bytes=1024**2, maximum_records=2) == original


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
        # The bounded verified capture still applies, including its admission
        # interval fence; a failed refresh does not erase valid evidence.
        assert new.status_code == 409
        assert new.json()["detail"] == "cohort intake or submission is not eligible"
        assert "PRIVATE" not in new.text
        other = client.post(
            url,
            content=canonical_json_bytes(request_for(scenario, name="Bob")),
            headers={"content-type": "application/json"},
        )
        assert other.status_code == 200, other.text
        assert other.json()["status"] == "pending_attestation"
        cache = app.state.registration_snapshot_cache
        expired = cache._monotonic() + cache._maximum_age + 1
        cache._monotonic = lambda: expired
        unavailable = client.post(
            url,
            content=canonical_json_bytes(request_for(scenario, sequence=2)),
            headers={"content-type": "application/json"},
        )
        assert unavailable.status_code == 503
        assert "PRIVATE" not in unavailable.text
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


def test_local_intake_callers_queue_before_external_lock_timeout(intake, scenario, monkeypatch):
    from umi import competition_cohort_intake as module

    entered, release = threading.Event(), threading.Event()
    local = threading.local()
    real_monotonic = module.time.monotonic

    def monotonic():
        if not getattr(local, "accelerated", False):
            return real_monotonic()
        local.calls = getattr(local, "calls", 0) + 1
        return 0 if local.calls == 1 else 11

    def holding_call():
        with intake._connection():
            entered.set()
            assert release.wait(2)

    def queued_call():
        local.accelerated = True
        return intake.retain(request_for(scenario), capture_at(210))

    monkeypatch.setattr(module.time, "monotonic", monotonic)
    first = threading.Thread(target=holding_call)
    second_result = []

    def second_call():
        second_result.append(queued_call())

    second = threading.Thread(target=second_call)
    first.start()
    assert entered.wait(1)
    second.start()
    try:
        second.join(0.05)
        assert second.is_alive()
    finally:
        release.set()
        first.join(2)
        second.join(2)
    assert not first.is_alive() and not second.is_alive()
    assert second_result == [intake.retain(request_for(scenario), capture_at(210))]


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


def test_verified_seal_reuse_keeps_private_copies_and_fresh_publication(
    intake, scenario, monkeypatch
):
    import umi.competition_cohort_intake as module

    intake.retain(request_for(scenario), capture_at(210))
    closed, evidence, expected = seal_and_close(intake, scenario)
    cohort, tip = expected.cohort_sha256, expected.recovery_tip_sha256
    assert intake.sealed(cohort, tip) == expected  # First complete verification.

    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged original seal was reconstructed again")

    monkeypatch.setattr(module, "_build_intake_seal_from_participations", unexpected)
    caller = intake.sealed(cohort, tip)
    object.__setattr__(caller, "selected", ())
    assert intake.sealed(cohort, tip) == expected
    intake.publish(closed, capture_at(310), closure_input=evidence)
    intake.publish(closed, capture_at(320), closure_input=evidence)
    with pytest.raises(ValueError):
        intake.publish(closed, capture_at(150), closure_input=evidence)


@pytest.mark.parametrize("damage", ["seal", "body", "missing-consent", "tip-index"])
def test_verified_seal_reuse_rechecks_changed_original_inputs(intake, scenario, damage):
    intake.retain(request_for(scenario), capture_at(210))
    _, _, expected = seal_and_close(intake, scenario)
    cohort, tip = expected.cohort_sha256, expected.recovery_tip_sha256
    assert intake.sealed(cohort, tip) == expected
    with intake._connection() as (db, _):
        if damage == "seal":
            db.execute("UPDATE cohort_intake_seals SET body=?", (b"{}",))
        elif damage == "body":
            db.execute("UPDATE cohort_consents SET body=?", (b"{}",))
        elif damage == "missing-consent":
            db.execute("DELETE FROM cohort_consents")
        else:
            db.execute("UPDATE cohort_consents SET recovery_tip=?", ("00" * 32,))
    with pytest.raises(ValueError):
        intake.sealed(cohort, tip)


@pytest.mark.parametrize("change", ["restart", "database", "index"])
def test_verified_seal_reuse_reconstructs_new_materialization(
    intake, scenario, monkeypatch, change
):
    import shutil

    import umi.competition_cohort_intake as module

    intake.retain(request_for(scenario), capture_at(210))
    _, _, expected = seal_and_close(intake, scenario)
    cohort, tip = expected.cohort_sha256, expected.recovery_tip_sha256
    assert intake.sealed(cohort, tip) == expected
    original = module._build_intake_seal_from_participations
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "_build_intake_seal_from_participations", counted)
    if change == "restart":
        intake = CohortIntake(intake.config, intake.policy)
    elif change == "database":
        path = Path(intake.config.directory) / "intake.sqlite3"
        replacement = path.with_suffix(".replacement")
        shutil.copyfile(path, replacement)
        replacement.chmod(0o600)
        replacement.replace(path)
    else:
        with intake._connection() as (db, _):
            db.execute("UPDATE cohort_consents SET observed=observed+1")
    assert intake.sealed(cohort, tip) == expected
    assert calls == [1]


def test_verified_seal_reuse_cannot_ignore_new_original_consent(intake, scenario):
    intake.retain(request_for(scenario), capture_at(210))
    _, _, expected = seal_and_close(intake, scenario)
    cohort, tip = expected.cohort_sha256, expected.recovery_tip_sha256
    assert intake.sealed(cohort, tip) == expected
    with intake._connection() as (db, _):
        row = db.execute("SELECT * FROM cohort_consents").fetchone()
        changed = ("00" * 32, *row[1:4], row[4] + 1, *row[5:])
        db.execute("INSERT INTO cohort_consents VALUES (?,?,?,?,?,?,?,?)", changed)
    with pytest.raises(ValueError):
        intake.sealed(cohort, tip)


@pytest.fixture
def participation_decode_observation(intake, scenario, monkeypatch):
    import umi.competition_cohort_intake_records as module
    from umi.competition_assignment_reuse import AssignmentVerificationReuse

    intake.retain(request_for(scenario), capture_at(210))
    cohort = digest(scenario["intake_history"].plan)
    _, raw = intake.export_records(cohort, maximum_bytes=1024**2, maximum_records=1)[0]
    monkeypatch.setattr(module, "_participation_decode_reuse", AssignmentVerificationReuse())
    original = module.RetainedCohortParticipation.model_validate_json
    calls = []

    def counted(cls, body):
        calls.append(body)
        return original(body)

    monkeypatch.setattr(
        module.RetainedCohortParticipation, "model_validate_json", classmethod(counted)
    )
    return module, raw, calls


def test_participation_decode_reuse_keeps_private_results(participation_decode_observation):
    module, raw, calls = participation_decode_observation
    expected = module.read_participation(raw)
    caller = module.read_participation(raw)
    object.__setattr__(caller.observation, "block", 999)
    assert module.read_participation(raw) == expected
    assert calls == [raw]


def test_participation_decode_reuse_reads_changed_bytes(participation_decode_observation):
    module, raw, calls = participation_decode_observation
    retained = module.read_participation(raw)
    altered = retained.model_copy(
        update={"observation": retained.observation.model_copy(update={"block": 211})}
    )
    changed = canonical_json_bytes(altered)
    assert changed != raw
    assert module.read_participation(changed) == altered
    assert calls == [raw, changed]


def test_participation_decode_reuse_does_not_remember_failure(participation_decode_observation):
    module, raw, calls = participation_decode_observation
    module.read_participation(raw)
    noncanonical = raw + b" "
    for _ in range(2):
        with pytest.raises(ValueError, match="not canonical"):
            module.read_participation(noncanonical)
    assert calls == [raw, noncanonical, noncanonical]
    assert module.read_participation(raw)
    assert len(calls) == 3


def test_participation_decode_reuse_refuses_inherited_process_results(
    participation_decode_observation,
):
    module, raw, calls = participation_decode_observation
    expected = module.read_participation(raw)
    module._participation_decode_reuse._pid = -1
    assert module.read_participation(raw) == expected
    assert calls == [raw, raw]


@pytest.mark.parametrize("bad", [b"", b"x" * (4 * 1024**2 + 1), bytearray(b"{}")])
def test_participation_decode_reuse_preserves_input_bound(participation_decode_observation, bad):
    module, _, calls = participation_decode_observation
    with pytest.raises(ValueError, match="byte bound"):
        module.read_participation(bad)
    assert not calls
