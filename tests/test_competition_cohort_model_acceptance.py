"""Owned artifact admission and real intake fencing with synthetic finality."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

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
)
from umi.competition_cohort_model_acceptance_store import (
    CohortModelAcceptances,
    PendingModelArtifacts,
)
from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
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
from .test_competition_cohort_recovery import signatures
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


def test_intake_waits_for_every_model_and_closes_after_delayed_certification(prepared):
    owner, cohort, subs, inputs = prepared
    phase = CohortIntakePhaseObserver(owner.intake)
    for block in range(200, 301, 5):
        result = observe(phase, cohort, block)
    assert result.seal is None
    first = certify(owner, cohort, subs[0], inputs, block=300)
    owner.publish(first, capture_at(300))
    assert observe(phase, cohort, 305).seal is None
    second = certify(owner, cohort, subs[1], inputs, block=4000)
    assert second.certificate.acceptance.accepted_ordinal == 2
    owner.publish(second, capture_at(4000))
    closed = observe(phase, cohort, 4000)
    assert closed.seal is not None and len(closed.seal.selected) == 2
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


def test_missing_payload_cannot_reserve_a_model_position(prepared):
    owner, cohort, subs, inputs = prepared
    owner.archive.rename(owner.archive.with_name("payload-offline"))
    with pytest.raises(FileNotFoundError):
        owner.prepare(cohort, digest(subs[0]), inputs, capture_at(220))
    assert owner.intent(cohort, digest(subs[0])) is None


def test_direct_acceptance_retains_exact_owner_reservation_without_local_archive(
    prepared, tmp_path
):
    owner, cohort, subs, inputs = prepared
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
    publication = certify(direct, cohort, subs[0], inputs)
    acceptance = publication.certificate.acceptance
    assert acceptance.schema_ == "umi-cohort-model-artifact-acceptance/2"
    assert acceptance.direct_artifact == artifact(
        direct.review_request(cohort, digest(subs[0])).record.request
    )
    direct.publish(publication, capture_at(220))
    assert direct.retained(cohort, digest(subs[0])).certificate == publication.certificate
    assert verified == [acceptance.direct_artifact.reservation.payload.upload_sha256] * 2


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
