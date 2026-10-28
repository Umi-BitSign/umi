"""Owned artifact admission and real intake fencing with synthetic finality."""

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from umi import competition_cohort_intake as intake_module
from umi import competition_cohort_model_acceptance_store as acceptance_module
from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
    direct_model_object_key,
)
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeBinding,
    CohortIntakeConfig,
    history_tip,
)
from umi.competition_cohort_intake_export import IntakeReviewExporter, replay_intake_export
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_intake_review import NativeIntakeProgressSource
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelAcceptancePublication,
    ModelArtifactReviewInputs,
    ModelReviewRequest,
    verify_model_acceptance,
)
from umi.competition_cohort_model_acceptance_store import (
    CohortModelAcceptances,
    PendingModelArtifacts,
)
from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_recovery import ModelDeliveryProfile, propose_recovery_transition
from umi.competition_cohort_settlement_preparation import SettlementArtifactPreparation
from umi.open_competition import digest, identity, sign_object
from umi.private_files import publish_private_model, read_private_model
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_roster import retained
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def prepared(tmp_path, receipt_scenario, runtime):
    s = setup_scenario(receipt_scenario, tmp_path / "source", runtime)
    h = s["intake_history"]
    cfg = CohortIntakeConfig(
        directory=str(tmp_path / "intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=digest(h.plan), authority_sha256=digest(h.authority.authority)
            ),
        ),
    )
    intake = CohortIntake(cfg, s["policy"], eligible_tracks=("endpoint", "model"), initialize=True)
    intake.publish(h, capture_at(210))
    queue = CohortAdmissionQueue(intake)
    subs = []
    for name in ("Alice", "Bob"):
        member = retained(s, name, 1)
        intake.retain(member.record.request, capture_at(210))
        for sig in member.admission.signatures:
            queue.publish_vote(
                CohortAdmissionVote(admission=member.admission.admission, signature=sig),
                capture_at(210),
            )
        subs.append(member.record.request.signed_submission.submission)
    archive = tmp_path / "archive"
    preserve_bundle(
        s["signed"].submission.model_bundle, tmp_path / "source/candidate", archive, s["policy"]
    )
    owner = CohortModelAcceptances(intake, archive)
    inputs = ModelArtifactReviewInputs(
        model_sha256=s["signed"].submission.model_revision,
        rights_evidence={"fixture": "reviewed license and provenance"},
        reconstruction_evidence={"fixture": "independent offline reconstruction"},
    )
    return owner, digest(h.plan), tuple(subs), inputs


def adopt_direct_transport(intake, cohort, *, block=211, part_size_bytes=5 * 1024**2):
    """Synthetic signed amendment; production dual-fence/inventory is separate."""
    history = intake.history(cohort)
    proposal = prepare_model_delivery_adoption(
        history,
        intake.policy,
        expected_tip_sha256=history_tip(history),
        current_block=block,
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=part_size_bytes,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        ),
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
    )
    amended = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(proposal))}
    )
    intake.publish(amended, capture_at(block))
    return amended


def certify(owner, cohort, sub, inputs, *, block=220, names=("Charlie", "Dave")):
    body = owner.prepare(cohort, digest(sub), inputs, capture_at(block))
    return ModelAcceptancePublication(
        certificate=CertifiedModelArtifactAcceptance(
            acceptance=body, signatures=signatures(body, names)
        ),
        inputs=inputs,
    )


def test_model_export_replays_only_its_original_participant(prepared, tmp_path, monkeypatch):
    owner, cohort, _, inputs = prepared
    with owner.intake._connection() as (db, _):
        raw = db.execute(
            "SELECT body FROM cohort_consents WHERE cohort=? ORDER BY consent DESC LIMIT 1",
            (cohort,),
        ).fetchone()[0]
    target = acceptance_module.read_participation(raw).request.signed_submission.submission
    expected = owner.publish(certify(owner, cohort, target, inputs), capture_at(220))
    read = acceptance_module.read_participation
    seen = []

    def observe_record(raw):
        record = read(raw)
        seen.append(identity(record.request.signed_submission.submission.hotkey))
        return record

    monkeypatch.setattr(intake_module, "read_participation", observe_record)
    monkeypatch.setattr(acceptance_module, "read_participation", observe_record)
    assert owner.export(cohort, digest(target), tmp_path / "export") == expected
    assert seen and set(seen) == {identity(target.hotkey)}
    path = tmp_path / "export/model-reward-preparation" / cohort / (digest(target) + ".json")
    request = read_private_model(path, ModelReviewRequest)
    assert request == owner.review_request(cohort, digest(target))
    original = path.read_bytes()
    assert owner.export(cohort, digest(target), tmp_path / "export") == expected
    assert path.read_bytes() == original


@pytest.mark.parametrize("fault", [None, "certificate", "admission", "authority", "record"])
async def test_export_is_usable_before_closure_but_requires_certified_bindings(
    prepared, tmp_path, fault
):
    owner, cohort, subs, inputs = prepared
    target = subs[0]
    publication = owner.publish(certify(owner, cohort, target, inputs), capture_at(220))
    root = tmp_path / "export"
    owner.export(cohort, digest(target), root)
    request_path = root / "model-reward-preparation" / cohort / (digest(target) + ".json")
    certificate_path = root / "model-reward-acceptances" / cohort / (digest(target) + ".json")
    request = read_private_model(request_path, ModelReviewRequest)
    if fault == "certificate":
        certificate_path.unlink()
        publish_private_model(
            certificate_path,
            publication.certificate.model_copy(
                update={"signatures": publication.certificate.signatures[:1]}
            ),
        )
    elif fault in {"admission", "record"}:
        request_path.unlink()
        change = (
            {
                "admission": request.admission.model_copy(
                    update={"signatures": request.admission.signatures[:1]}
                )
            }
            if fault == "admission"
            else {
                "record": request.record.model_copy(
                    update={
                        "proposed_admission": request.record.proposed_admission.model_copy(
                            update={"snapshot_sha256": "01" * 32}
                        )
                    }
                )
            }
        )
        publish_private_model(request_path, request.model_copy(update=change))
    history = owner.intake.history(cohort)
    config = SimpleNamespace(
        policy=owner.intake.policy,
        series=SimpleNamespace(
            recovery=(
                history.authority
                if fault != "authority"
                else SimpleNamespace(authority={"unexpected": "authority"})
            ),
            cohorts=(history.plan,),
        ),
    )
    prep = SettlementArtifactPreparation(config, SimpleNamespace(directory=root), {})
    # Keep original local materialization; no final handoff, label reveal or RPC.
    prep.archive = owner.archive
    key = "accepted/" + cohort + "/" + digest(target)
    if fault:
        with pytest.raises(ValueError):
            prep._accepted(key, request_path)
    else:
        participant, certificate = prep._accepted(key, request_path)
        assert certificate == publication.certificate
        assert participant.record == request.record
        report = await prep.poll_once(asyncio.Event())
        assert report["entries_pending"] == 0 and report["entries_ready"] == 2
        assert not report["chain_submission_authorized"]


@pytest.mark.parametrize("index", ["hotkey", "track", "recovery_tip"])
def test_model_export_rejects_target_index_tampering(prepared, tmp_path, index):
    owner, cohort, subs, inputs = prepared
    target = subs[0]
    owner.publish(certify(owner, cohort, target, inputs), capture_at(220))
    with owner.intake._connection() as (db, _):
        db.execute(
            f"UPDATE cohort_consents SET {index}=? WHERE cohort=? AND hotkey=? AND track='model'",
            ("endpoint" if index == "track" else "0" * 64, cohort, identity(target.hotkey)),
        )
    with pytest.raises(ValueError):
        owner.export(cohort, digest(target), tmp_path / "export")


def observe(phase, cohort, block):
    return phase.observe(
        cohort,
        capture_at(block),
        serving=True,
        expected_tip_sha256=history_tip(phase.intake.history(cohort)),
    )


def test_intake_waits_for_every_model_and_closes_after_delayed_certification(prepared, caplog):
    owner, cohort, subs, inputs = prepared
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    phase = CohortIntakePhaseObserver(owner.intake)
    for block in range(200, 301, 5):
        result = observe(phase, cohort, block)
    assert result.seal is None
    waits = [
        json.loads(record.getMessage().split(" ", 1)[1])
        for record in caplog.records
        if record.getMessage().startswith("cohort_intake_wait ")
    ]
    assert waits[-1]["reason_code"] == "selected_model_artifact_acceptance_pending"
    assert waits[-1]["pending_submission_sha256"] in {digest(sub) for sub in subs}
    assert waits[-1]["serving"] is True
    assert waits[-1]["observed_at_block"] >= waits[-1]["earliest_seal_block"]
    assert (waits[-1]["completed"], waits[-1]["total"], waits[-1]["percent"]) == (0, 2, 0)
    first = certify(owner, cohort, subs[0], inputs, block=300)
    owner.publish(first, capture_at(300))
    assert observe(phase, cohort, 305).seal is None
    latest = json.loads(
        next(
            r.getMessage().split(" ", 1)[1]
            for r in reversed(caplog.records)
            if r.getMessage().startswith("cohort_intake_wait ")
        )
    )
    assert (latest["completed"], latest["total"], latest["percent"]) == (1, 2, 50)
    second = certify(owner, cohort, subs[1], inputs, block=4000)
    assert second.certificate.acceptance.accepted_ordinal == 2
    owner.publish(second, capture_at(4000))
    closed = observe(phase, cohort, 4000)
    assert closed.seal is not None and len(closed.seal.selected) == 2
    completed = json.loads(
        next(
            r.getMessage().split(" ", 1)[1]
            for r in reversed(caplog.records)
            if r.getMessage().startswith("cohort_model_certification_progress ")
        )
    )
    assert (completed["completed"], completed["total"], completed["percent"]) == (2, 2, 100)
    assert completed["certification_authority"] is False
    reopened = CohortIntakePhaseObserver(
        CohortIntake(
            owner.intake.config, owner.intake.policy, eligible_tracks=("endpoint", "model")
        )
    )
    assert observe(reopened, cohort, 10000).seal == closed.seal


def test_proposal_retry_keeps_original_ordinal_and_documents_without_live_files(prepared):
    owner, cohort, subs, inputs = prepared
    a = certify(owner, cohort, subs[0], inputs)
    b = certify(owner, cohort, subs[1], inputs, block=221)
    old = owner.archive
    old.rename(old.with_name("archive-offline"))
    resumed = CohortModelAcceptances(owner.intake, old)
    assert resumed.prepare(cohort, digest(subs[0]), inputs, None) == a.certificate.acceptance
    assert resumed.prepare(cohort, digest(subs[1]), inputs, None) == b.certificate.acceptance
    intent = resumed.intent(cohort, digest(subs[0]))
    assert intent.inputs == inputs
    changed = inputs.model_copy(update={"rights_evidence": {"different": True}})
    with pytest.raises(ValueError, match="original review"):
        resumed.prepare(cohort, digest(subs[0]), changed, None)


@pytest.mark.parametrize("bad", ["no-quorum", "self-review", "changed-doc", "changed-ordinal"])
def test_bad_review_never_becomes_an_acceptance(prepared, bad):
    owner, cohort, subs, inputs = prepared
    names = (
        ("Charlie",)
        if bad == "no-quorum"
        else ("Alice", "Dave")
        if bad == "self-review"
        else ("Charlie", "Dave")
    )
    value = certify(owner, cohort, subs[0], inputs, names=names)
    if bad == "changed-doc":
        value = value.model_copy(
            update={"inputs": inputs.model_copy(update={"rights_evidence": {"changed": True}})}
        )
    if bad == "changed-ordinal":
        a = value.certificate.acceptance.model_copy(update={"accepted_ordinal": 9})
        value = value.model_copy(
            update={
                "certificate": CertifiedModelArtifactAcceptance(
                    acceptance=a, signatures=signatures(a)
                )
            }
        )
    with pytest.raises(ValueError):
        owner.publish(value, capture_at(220))
    with pytest.raises(PendingModelArtifacts):
        owner.retained(cohort, digest(subs[0]))


def test_complete_remote_intake_export_cannot_omit_model_acceptances(prepared):
    owner, cohort, subs, inputs = prepared
    for sub in subs:
        owner.publish(certify(owner, cohort, sub, inputs), capture_at(220))
    phase = CohortIntakePhaseObserver(owner.intake)
    for block in range(200, 301, 5):
        result = observe(phase, cohort, block)
    exporter = IntakeReviewExporter(
        NativeIntakeProgressSource(owner.intake), wallet("Charlie").hotkey.ss58_address, None
    )
    exported = exporter.export(result.progress)
    assert exported.schema_ == "umi-intake-review-export/2"
    assert len(exported.model_acceptances) == 2
    replay_intake_export(exported, owner.intake.policy, maximum_sample_gap_blocks=10)
    damaged = exported.model_copy(update={"model_acceptances": exported.model_acceptances[:1]})
    with pytest.raises(PendingModelArtifacts, match="entire sealed"):
        replay_intake_export(damaged, owner.intake.policy, maximum_sample_gap_blocks=10)


async def test_recurring_worker_recovers_lost_export_ack_without_rpc_or_inputs(
    prepared, tmp_path, monkeypatch
):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"

    async def capture():
        return capture_at(220)

    worker = ModelAcceptanceWorker(owner, capture, root, out)
    publish_private_model(root / "model-reviews" / (inputs.model_sha256 + ".json"), inputs)
    report = await worker.poll_once()
    assert report["entries_pending"] == 2
    for sub in subs:
        value = certify(owner, cohort, sub, inputs)
        publish_private_model(
            root / "model-acceptance-publications" / cohort / (digest(sub) + ".json"), value
        )
    original = owner.export

    def lost_ack(*args):
        original(*args)
        raise OSError("lost export acknowledgement")

    monkeypatch.setattr(owner, "export", lost_ack)
    assert (await worker.poll_once())["entries_pending"] == 2
    root.rename(root.with_name("input-delivery-offline"))
    owner.archive.rename(owner.archive.with_name("payload-offline"))

    async def offline():
        raise AssertionError("completed acceptance must recover before RPC")

    restored = CohortModelAcceptances(owner.intake, owner.archive)
    resumed = ModelAcceptanceWorker(restored, offline, root, out)
    assert (await resumed.poll_once())["entries_exported"] == 2
    for sub in subs:
        certificate = read_private_model(
            out / "model-reward-acceptances" / cohort / (digest(sub) + ".json"),
            CertifiedModelArtifactAcceptance,
        )
        assert certificate == restored.retained(cohort, digest(sub)).certificate
        for body in (inputs.rights_evidence, inputs.reconstruction_evidence):
            assert (
                out / "objects" / (digest(body) + ".json")
            ).read_bytes() == canonical_json_bytes(body)


async def test_worker_promotes_before_publication_and_retries_retained_acceptances(
    prepared, tmp_path
):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"
    publications = {digest(sub): certify(owner, cohort, sub, inputs) for sub in subs}
    for key, value in publications.items():
        publish_private_model(
            root / "model-acceptance-publications" / cohort / (key + ".json"), value
        )
    publish_private_model(root / "model-reviews" / (inputs.model_sha256 + ".json"), inputs)
    failed = digest(subs[0])
    calls = []

    async def capture():
        return capture_at(220)

    async def promote(publication):
        key = publication.certificate.acceptance.submission_sha256
        calls.append(key)
        if key == failed or calls.count(key) == 1:
            with pytest.raises(PendingModelArtifacts):
                owner.retained(cohort, key)
        else:
            owner.retained(cohort, key)
        if key == failed and calls.count(key) == 1:
            raise OSError("promotion acknowledgement lost")

    worker = ModelAcceptanceWorker(owner, capture, root, out, promote=promote)
    first = await worker.poll_once()
    assert first["entries_exported"] == 1
    assert first["entries_pending"] == 1
    with pytest.raises(PendingModelArtifacts):
        owner.retained(cohort, failed)

    second = await worker.poll_once()
    assert second["entries_exported"] == 2
    assert second["entries_pending"] == 0
    assert calls.count(failed) == 2
    assert calls.count(digest(subs[1])) == 2


async def test_worker_reports_actual_pending_item_before_whole_batch_finishes(
    prepared, tmp_path, monkeypatch, caplog
):
    owner, cohort, _, inputs = prepared
    publish_private_model(
        tmp_path / "inputs/model-reviews" / (inputs.model_sha256 + ".json"), inputs
    )
    started, release = asyncio.Event(), asyncio.Event()

    async def held_payload(*_args):
        started.set()
        await release.wait()
        raise OSError("private document diagnostic must not leak")

    monkeypatch.setattr(owner, "ensure_payload", held_payload)
    worker = ModelAcceptanceWorker(owner, None, tmp_path / "inputs", tmp_path / "output")
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    task = asyncio.create_task(worker.poll_once())
    try:
        await asyncio.wait_for(started.wait(), timeout=10)
        assert not task.done()
        messages = [r.getMessage() for r in caplog.records]
        stages = [
            json.loads(m.split(" ", 1)[1])
            for m in messages
            if m.startswith("model_acceptance_stage ")
        ]
        active = next(s for s in stages if s["stage"] == "payload")
        assert active["cohort_sha256"] == cohort
        assert len(active["submission_sha256"]) == 64
        assert active["completed"] == 0 and active["status"] == "running"
        release.set()
        assert (await task)["entries_pending"] == 2
        assert "private document diagnostic" not in caplog.text
        assert '"error_type":"OSError"' in caplog.text
        assert '"state":"accounting_mismatch"' not in caplog.text
    finally:
        release.set()
        if not task.done():
            await task


@pytest.mark.parametrize("damage", ["missing", "malformed"])
async def test_missing_review_inputs_do_not_trigger_remote_payload_work(
    prepared, tmp_path, monkeypatch, damage
):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"
    if damage == "malformed":
        path = root / "model-reviews" / (inputs.model_sha256 + ".json")
        path.parent.mkdir(mode=0o700, parents=True)
        path.write_bytes(b"{}")
        path.chmod(0o600)

    async def forbidden(*args):
        raise AssertionError("unavailable review input caused model byte work or new finality")

    monkeypatch.setattr(owner, "ensure_payload", forbidden)
    worker = ModelAcceptanceWorker(owner, forbidden, root, out)
    for _ in range(2):
        result = await worker.poll_once()
        assert result["entries_pending"] == 2
        assert result["entries_exported"] == 0
    for sub in subs:
        assert not owner.has_intent(cohort, digest(sub))


async def test_retained_intent_recovers_without_external_review_file_but_requires_payload(
    prepared, tmp_path, monkeypatch
):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"
    for sub in subs:
        publication = certify(owner, cohort, sub, inputs)
        assert owner.has_intent(cohort, digest(sub))
        publish_private_model(
            root / "model-acceptance-publications" / cohort / (digest(sub) + ".json"), publication
        )
    assert not (root / "model-reviews").exists()
    calls = []

    async def unavailable(*args):
        calls.append(args)
        raise OSError("remote byte verification unavailable")

    monkeypatch.setattr(owner, "ensure_payload", unavailable)

    async def capture():
        return capture_at(220)

    worker = ModelAcceptanceWorker(owner, capture, root, out)
    result = await worker.poll_once()
    assert result["entries_pending"] == len(calls) == 2
    for sub in subs:
        with pytest.raises(PendingModelArtifacts):
            owner.retained(cohort, digest(sub))

    async def available(*args):
        calls.append(args)

    monkeypatch.setattr(owner, "ensure_payload", available)
    assert (await worker.poll_once())["entries_exported"] == 2
    assert len(calls) == 4


async def test_latest_pending_candidate_runs_before_old_export_cursor_wraps(prepared, tmp_path):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"
    published = certify(owner, cohort, subs[0], inputs)
    owner.publish(published, capture_at(220))
    pending = certify(owner, cohort, subs[1], inputs)
    publish_private_model(
        root / "model-acceptance-publications" / cohort / (digest(subs[1]) + ".json"), pending
    )
    keys = [key for key, _ in owner.entries(cohort)]
    assert [digest(sub) for _, sub in owner.pending_latest_entries(cohort)] == [digest(subs[1])]

    async def capture():
        return capture_at(220)

    worker = ModelAcceptanceWorker(owner, capture, root, out, batch_size=1)
    worker.cursors[cohort] = max(keys)
    assert (await worker.poll_once())["entries_exported"] == 1
    assert owner.retained(cohort, digest(subs[1])).certificate == pending.certificate
    assert not owner.pending_latest_entries(cohort)
    # The ordinary cursor remains fair: existing publication exports still run.
    for _ in range(2):
        await worker.poll_once()
    assert (out / "model-reward-acceptances" / cohort / (digest(subs[0]) + ".json")).exists()


def replace_model_submission(owner, cohort, original_sub):
    from umi.competition_cohort_intake_records import read_participation

    key, _ = next((k, s) for k, s in owner.entries(cohort) if s == original_sub)
    original = read_participation(CohortAdmissionQueue(owner.intake).record(cohort, key)).request
    sub = original.signed_submission.submission.model_copy(update={"sequence": 2})
    signed = original.signed_submission.model_copy(
        update={"submission": sub, "signature": sign_object(sub, wallet("Alice"))}
    )
    consent = original.consent.consent.model_copy(update={"submission_sha256": digest(sub)})
    request = original.model_copy(
        update={
            "signed_submission": signed,
            "consent": original.consent.model_copy(
                update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))}
            ),
        }
    )
    owner.intake.retain(
        request, capture_at(210 + owner.intake.policy.minimum_submission_interval_blocks)
    )
    return sub


def test_priority_uses_latest_sequence_and_keeps_superseded_recovery_scan(prepared):
    owner, cohort, subs, _ = prepared
    sub = replace_model_submission(owner, cohort, subs[0])
    priority = {digest(s) for _, s in owner.pending_latest_entries(cohort)}
    assert digest(sub) in priority and digest(subs[0]) not in priority
    assert digest(subs[1]) in priority
    assert {digest(s) for _, s in owner.entries(cohort)} == priority | {digest(subs[0])}
    ordered = owner.pending_latest_entries(cohort)
    assert owner.pending_latest_entries(cohort, limit=1, offset=1) == ordered[1:2]
    assert owner.pending_latest_entries(cohort, limit=1, offset=len(ordered)) == ()
    with pytest.raises(ValueError, match="offset exceeds"):
        owner.pending_latest_entries(
            cohort, limit=1, offset=owner.intake.capacity.maximum_records + 1
        )


async def test_intake_certifies_replacement_before_closure_and_reuses_after_restart(
    prepared, tmp_path, monkeypatch
):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"
    original_history = canonical_json_bytes(owner.intake.history(cohort))
    for sub in subs:
        owner.publish(certify(owner, cohort, sub, inputs), capture_at(220))
    assert owner.certification_inventory(cohort)["completed"] == 2
    replacement = replace_model_submission(owner, cohort, subs[0])
    inventory = owner.certification_inventory(cohort)
    assert (inventory["completed"], inventory["total"]) == (1, 2)
    assert inventory["pending_submission_sha256s"] == (digest(replacement),)
    assert inventory["selection_scope"] == "latest_model_submissions"
    queue = CohortAdmissionQueue(owner.intake)
    key, _ = next((k, s) for k, s in owner.entries(cohort) if s == replacement)
    record = acceptance_module.read_participation(queue.record(cohort, key))
    for signature in signatures(record.proposed_admission):
        queue.publish_vote(
            CohortAdmissionVote(admission=record.proposed_admission, signature=signature),
            capture_at(220),
        )
    publication = certify(owner, cohort, replacement, inputs)
    publish_private_model(
        root / "model-acceptance-publications" / cohort / (digest(replacement) + ".json"),
        publication,
    )

    async def capture():
        return capture_at(220)

    # Restarts retain the original proposal, votes and certificate. No lifecycle
    # controller is run: certification must happen while intake remains open.
    worker = ModelAcceptanceWorker(owner, capture, root, out)
    assert (await worker.poll_once())["entries_pending"] == 0
    assert canonical_json_bytes(owner.intake.history(cohort)) == original_history
    assert owner.certification_inventory(cohort)["completed"] == 2
    root.rename(tmp_path / "inputs-offline")
    owner.archive.rename(tmp_path / "archive-offline")

    async def offline():
        raise AssertionError("completed intake certificates must not repeat RPC or payload work")

    restored = CohortModelAcceptances(owner.intake, owner.archive)
    monkeypatch.setattr(restored, "prepare", offline)
    resumed = ModelAcceptanceWorker(restored, offline, root, out)
    assert (await resumed.poll_once())["entries_pending"] == 0
    assert restored.retained(cohort, digest(replacement)).certificate == publication.certificate


def test_priority_refuses_changed_native_sequence_index(prepared):
    owner, cohort, _, _ = prepared
    key, _ = owner.entries(cohort)[0]
    with owner.intake._connection() as (db, _):
        db.execute("UPDATE cohort_consents SET sequence=999 WHERE consent=?", (key,))
    with pytest.raises(ValueError, match="index differs"):
        owner.pending_latest_entries(cohort)


def test_missing_payload_cannot_reserve_a_model_position(prepared):
    owner, cohort, subs, inputs = prepared
    owner.archive.rename(owner.archive.with_name("payload-offline"))
    with pytest.raises(FileNotFoundError):
        owner.prepare(cohort, digest(subs[0]), inputs, capture_at(220))
    assert owner.intent(cohort, digest(subs[0])) is None


@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("transport", ["adopted", "unadopted", "wrong_profile"])
def test_direct_acceptance_retains_exact_owner_reservation_without_local_archive(
    prepared, tmp_path, transport
):
    owner, cohort, subs, inputs = prepared
    original_plan = canonical_json_bytes(owner.intake.history(cohort).plan)
    legacy = certify(owner, cohort, subs[1], inputs, block=210)
    owner.publish(legacy, capture_at(210))
    legacy_bytes = canonical_json_bytes(legacy)
    if transport != "unadopted":
        adopt_direct_transport(
            owner.intake,
            cohort,
            part_size_bytes=(6 if transport == "wrong_profile" else 5) * 1024**2,
        )
    retained = {}
    verified = []

    def artifact(request):
        key = digest(request)
        if key not in retained:
            submission = request.signed_submission.submission
            bundle = submission.model_bundle
            total = sum(record.size_bytes for record in bundle.files)
            attempt = "a1" * 32
            object_key = direct_model_object_key(cohort, key, attempt)
            payload = DirectModelPayload(
                schema="umi-direct-model-payload/1",
                upload_sha256=key,
                model_sha256=digest(bundle),
                payload_sha256="b2" * 32,
                total_bytes=total,
                file_count=len(bundle.files),
                part_size_bytes=5 * 1024**2,
                total_parts=1,
            )
            reservation = DirectModelUploadReservation(
                schema="umi-direct-model-upload-reservation/1",
                cohort_sha256=cohort,
                hotkey=submission.hotkey,
                payload=payload,
                attempt_id=attempt,
                generation=1,
                object_key_sha256=sha256_hex(object_key.encode()),
                provider_upload_id_sha256="c3" * 32,
                created_at_unix_ms=1_800_000_000_000,
            )
            retained[key] = SignedDirectModelUploadReservation(
                schema="umi-signed-direct-model-upload-reservation/1",
                reservation=reservation,
                signature=sign_object(reservation, wallet("Charlie")),
            )
        return retained[key]

    direct = CohortModelAcceptances(
        owner.intake,
        tmp_path / "no-local-candidate-archive",
        verify_request=lambda request: verified.append(digest(request)),
        review_artifact=artifact,
    )
    if transport != "adopted":
        with pytest.raises(ValueError, match="authenticated transport profile"):
            certify(direct, cohort, subs[0], inputs)
        assert direct.intent(cohort, digest(subs[0])) is None
        assert not verified  # No remote payload work for an unauthorized transport.
        return
    publication = certify(direct, cohort, subs[0], inputs)
    acceptance = publication.certificate.acceptance
    assert acceptance.schema_ == "umi-cohort-model-artifact-acceptance/2"
    assert acceptance.direct_artifact == artifact(
        direct.review_request(cohort, digest(subs[0])).record.request
    )
    direct.publish(publication, capture_at(220))
    assert direct.retained(cohort, digest(subs[0])).certificate == publication.certificate
    assert verified == [acceptance.direct_artifact.reservation.payload.upload_sha256] * 2

    def offline(*args):
        raise AssertionError("retained preparation must not reread delivery or RPC")

    resumed = CohortModelAcceptances(
        owner.intake,
        tmp_path / "no-local-candidate-archive",
        verify_request=offline,
        review_artifact=offline,
    )
    assert (
        resumed.review_request(cohort, digest(subs[0])).direct_artifact
        == acceptance.direct_artifact
    )
    assert resumed.export(cohort, digest(subs[0]), tmp_path / "resumed-export") == publication

    # Later authenticated phases must not be mistaken for an acceptance deadline.
    history = owner.intake.history(cohort)
    state = verify_cohort_history(
        history, owner.intake.policy, expected_tip_sha256=history_tip(history), current_block=220
    ).state
    closing = signed_transition(
        propose_recovery_transition(
            state,
            history.authority.authority,
            operation="close_phase",
            observed_at_block=300,
            evidence_sha256="35" * 32,
        )
    )
    later = history.model_copy(update={"transitions": (*history.transitions, closing)})
    for accepted in (publication, legacy):
        body = accepted.certificate.acceptance
        record = owner.review_request(cohort, body.submission_sha256).record
        verify_model_acceptance(
            accepted.certificate,
            record,
            later,
            owner.intake.policy,
            maximum_block=body.accepted_at_block,
        )
    assert canonical_json_bytes(legacy) == legacy_bytes
    assert canonical_json_bytes(later.plan) == original_plan


def test_concurrent_identical_proposals_keep_one_position(prepared, monkeypatch):
    import umi.competition_cohort_model_acceptance_store as module

    owner, cohort, subs, inputs = prepared
    original, ready = module.verify_preserved_bundle, Barrier(2)

    def verified(*args):
        result = original(*args)
        ready.wait(timeout=10)
        return result

    monkeypatch.setattr(module, "verify_preserved_bundle", verified)
    with ThreadPoolExecutor(max_workers=2) as workers:
        a, b = tuple(
            workers.submit(owner.prepare, cohort, digest(subs[0]), inputs, capture_at(220))
            for _ in range(2)
        )
        assert a.result() == b.result()
        assert a.result().accepted_ordinal == 1


def test_capacity_hold_preserves_proposal_until_capacity_is_increased(prepared):
    owner, cohort, subs, inputs = prepared
    publication = certify(owner, cohort, subs[0], inputs)
    before = owner.intake.capacity
    with owner.intake._connection() as (db, _):
        used = owner.intake.retained_bytes(db)
    owner.intake.capacity = before.model_copy(update={"maximum_bytes": used})
    with pytest.raises(ValueError, match="additional durable capacity"):
        owner.publish(publication, capture_at(220))
    assert owner.intent(cohort, digest(subs[0])).acceptance == publication.certificate.acceptance
    owner.intake.capacity = before
    assert owner.publish(publication, capture_at(20000)) == publication


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_verified_seal_reuse_never_hides_changed_model_acceptance(prepared, damage):
    owner, cohort, subs, inputs = prepared
    for sub in subs:
        owner.publish(certify(owner, cohort, sub, inputs), capture_at(220))
    tip = history_tip(owner.intake.history(cohort))
    expected = owner.intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    assert owner.intake.sealed(cohort, tip) == expected
    with owner.intake._connection() as (db, _):
        if damage == "missing":
            db.execute(
                "DELETE FROM cohort_model_acceptances WHERE submission=?", (digest(subs[0]),)
            )
        else:
            db.execute(
                "UPDATE cohort_model_acceptances SET body=? WHERE submission=?",
                (b"{}", digest(subs[0])),
            )
    with pytest.raises((ValueError, PendingModelArtifacts)):
        owner.intake.sealed(cohort, tip)


@pytest.mark.parametrize("damage", ["missing", "malformed"])
async def test_private_review_preparation_repairs_missing_only_and_is_reused(
    prepared, tmp_path, damage
):
    owner, cohort, subs, inputs = prepared
    root, out = tmp_path / "inputs", tmp_path / "output"
    sub = subs[0]
    path = root / "model-reviews" / (sub.model_revision + ".json")
    if damage == "malformed":
        path.parent.mkdir(mode=0o700, parents=True)
        path.write_bytes(b"{}")
        path.chmod(0o600)
    calls = []

    async def prepare(selected_cohort, selected_sub):
        calls.append((selected_cohort, selected_sub))
        return inputs

    async def capture():
        return capture_at(220)

    worker = ModelAcceptanceWorker(owner, capture, root, out, prepare_review=prepare)
    if damage == "malformed":
        with pytest.raises(ValueError):
            await worker._one(cohort, sub)
        assert not calls and path.read_bytes() == b"{}"
    else:
        with pytest.raises(FileNotFoundError):
            await worker._one(cohort, sub)  # Independent publication has not arrived.
        assert calls == [(cohort, sub)]
        assert path.exists() and owner.has_intent(cohort, digest(sub))
        with pytest.raises(FileNotFoundError):
            await worker._one(cohort, sub)
        assert calls == [(cohort, sub)]
