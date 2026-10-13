"""Native R2 artifact receipts remain coverage dependencies after restart."""

import hashlib
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_reward_coverage_model_ledger as model_ledger
from umi import competition_reward_coverage_models as models
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
    DirectModelSettlementVerifier,
)
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
    direct_model_object_key,
    preserved_model_object_key,
)
from umi.competition_cohort_model_acceptance import CertifiedModelArtifactAcceptance
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_roster import RecoverableRosterParticipant
from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from umi.competition_reward_coverage_models import (
    CoverageModelDependencyRepairRequired,
    capture_coverage_model_dependencies,
    restore_coverage_model_dependencies,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes, sha256_hex
from umi.r2_sigv4 import R2Credentials, R2SigV4

from .test_competition_cohort_direct_model_review import ReadOnlyObject
from .test_competition_cohort_direct_model_review import base_policy as base_policy
from .test_competition_cohort_direct_model_review import legacy_scenario as legacy_scenario
from .test_competition_cohort_direct_model_review import policy as policy
from .test_competition_cohort_direct_model_review import prepared as prepared
from .test_competition_cohort_direct_model_review import receipt_scenario as receipt_scenario
from .test_competition_cohort_direct_model_review import recovery as recovery
from .test_competition_cohort_direct_model_review import reviews as reviews
from .test_competition_cohort_direct_model_review import runtime as runtime
from .test_competition_cohort_recovery import signatures
from .test_competition_reward_coverage_checkpoint import checkpoint as checkpoint
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
async def dependency(reviews):
    original = reviews.request
    submission = original.record.request.signed_submission.submission
    bundle = submission.model_bundle
    model_root = reviews.owner.archive / digest(bundle) / "model"
    raw = b"".join((model_root / record.path).read_bytes() for record in bundle.files)
    upload = digest(original.record.request)
    direct_key = direct_model_object_key(original.acceptance.cohort_sha256, upload, "a1" * 32)
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=upload,
        model_sha256=digest(bundle),
        payload_sha256=hashlib.sha256(raw).hexdigest(),
        total_bytes=len(raw),
        file_count=len(bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=original.acceptance.cohort_sha256,
        hotkey=submission.hotkey,
        payload=payload,
        attempt_id="a1" * 32,
        generation=1,
        object_key_sha256=sha256_hex(direct_key.encode()),
        provider_upload_id_sha256="b2" * 32,
        created_at_unix_ms=1_800_000_000_000,
    )
    signed = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    request = original.model_copy(
        update={
            "schema_": "umi-cohort-model-review-request/2",
            "direct_artifact": signed,
            "acceptance": original.acceptance.model_copy(
                update={
                    "schema_": "umi-cohort-model-artifact-acceptance/2",
                    "direct_artifact": signed,
                }
            ),
        }
    )
    policy = reviews.owner.intake.policy
    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(policy),
        contribution_terms_sha256=policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-02T12:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    source = ReadOnlyObject(
        preserved_model_object_key(
            reservation.cohort_sha256, payload.model_sha256, payload.payload_sha256
        ),
        raw,
    )
    protected = reviews.root / "protected-state"
    protected.mkdir(mode=0o700)
    artifacts = DirectModelArtifactReviewer(
        DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/2",
            r2_credentials_file=str(reviews.root / "unused-credentials"),
            r2_bucket="umi-model-artifacts",
            materialization_protected_roots=(str(protected),),
            standing_review_policy=standing,
        ),
        policy,
        wallet("Charlie").hotkey.ss58_address,
        multipart=source,
        verification_root=reviews.root / "remote-verification",
    )
    inputs, _ = await artifacts.verify(request, preserved=True)
    verified_reads = source.ranges_read
    acceptance = request.acceptance.model_copy(
        update={
            "rights_evidence_sha256": digest(inputs.rights_evidence),
            "reconstruction_evidence_sha256": digest(inputs.reconstruction_evidence),
        }
    )
    certificate = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=signatures(acceptance)
    )
    participant = RecoverableRosterParticipant(record=request.record, admission=request.admission)
    verifier = DirectModelSettlementVerifier(
        artifacts, reviews.owner.archive, reviews.root / "settlement-receipts"
    )
    await verifier.ensure(participant, certificate)
    package = SimpleNamespace(
        inputs=SimpleNamespace(roster=SimpleNamespace(participants=(participant,)))
    )
    prepared = SimpleNamespace(
        allocation=SimpleNamespace(model_award=SimpleNamespace(acceptances=(certificate,)))
    )
    preparation = SimpleNamespace(model_artifacts=verifier, policy_sha256=digest(policy))
    raw_snapshot = await capture_coverage_model_dependencies(preparation, package, prepared)
    assert source.ranges_read == verified_reads
    return SimpleNamespace(
        reviews=reviews,
        artifacts=artifacts,
        verifier=verifier,
        source=source,
        preparation=preparation,
        package=package,
        prepared=prepared,
        certificate=certificate,
        participant=participant,
        snapshot=raw_snapshot,
    )


async def test_native_receipt_dependencies_restore_after_restart_without_payloads(
    dependency, monkeypatch
):
    case = dependency
    prior_reads = case.source.ranges_read
    verifier = DirectModelSettlementVerifier(
        case.artifacts, case.verifier.archive, case.verifier.receipts
    )
    case.preparation.model_artifacts = verifier

    def prohibit(*args, **kwargs):
        raise AssertionError("compact coverage replay read original model/package bytes")

    monkeypatch.setattr(case.artifacts, "verify", prohibit)
    monkeypatch.setattr(case.source, "read_range", prohibit)
    monkeypatch.setattr(verifier, "ensure", prohibit)
    for _ in range(2):
        assert await restore_coverage_model_dependencies(case.preparation, case.snapshot)
    assert case.source.ranges_read == prior_reads


async def test_completed_coverage_rechecks_model_metadata_before_reusing_issued_endpoint(
    dependency, checkpoint
):
    case = dependency
    checkpoint.endpoint.model_dependencies = case.snapshot
    checkpoint.owner.remember(checkpoint.endpoint, checkpoint.keys)
    saved = checkpoint.owner.load(checkpoint.key)
    path = case.verifier._path(case.certificate)
    original = path.read_bytes()
    path.unlink()
    with pytest.raises(CoverageCheckpointRepairRequired, match="explicit scoped repair"):
        checkpoint.owner.load(checkpoint.key)
    path.write_bytes(original)
    path.chmod(0o600)
    # Every consumer goes through this load, including credit() when handed an
    # endpoint that was issued before another consumer observed the damage.
    with pytest.raises(CoverageCheckpointRepairRequired, match="explicit scoped repair"):
        checkpoint.owner.load(checkpoint.key)
    await case.verifier.ensure(case.participant, case.certificate)
    await capture_coverage_model_dependencies(
        case.preparation, case.package, case.prepared, repair_reason="original receipt restored"
    )
    assert checkpoint.owner.load(checkpoint.key) == saved


@pytest.mark.parametrize(
    "damage",
    [
        "receipt_missing",
        "receipt_changed",
        "missing",
        "etag",
        "size",
        "head_malformed",
        "qualification_missing",
    ],
)
async def test_observed_damage_remains_held_until_explicit_native_repair(
    dependency, monkeypatch, damage
):
    case = dependency
    path = case.verifier._path(case.certificate)
    original = path.read_bytes()
    context = models.ModelDependencyContext.model_validate_json(
        canonical_json_bytes(case.snapshot["context"])
    )
    item = models.CoverageModelDependency.model_validate_json(
        canonical_json_bytes(case.snapshot["items"][0])
    )
    qualification_path = models._qualification_path(case.verifier, context, item)
    qualification_bytes = qualification_path.read_bytes()
    prior_reads = case.source.ranges_read
    with monkeypatch.context() as patch:
        if damage == "receipt_missing":
            path.unlink()
        elif damage == "receipt_changed":
            value = case.snapshot["items"][0]["receipt"].copy()
            value["model_sha256"] = "cc" * 32
            path.write_bytes(canonical_json_bytes(value))
        elif damage == "qualification_missing":
            qualification_path.unlink()
        elif damage == "etag":
            patch.setattr(case.source, "etag", "another-generation")
        elif damage == "size":
            patch.setattr(case.source, "payload", b"different-size")
        else:

            async def head(*args, **kwargs):
                if damage == "head_malformed":
                    raise ValueError("malformed HEAD")
                return None

            patch.setattr(case.source, "head", head)
        with pytest.raises(CoverageModelDependencyRepairRequired, match="explicit scoped repair"):
            await restore_coverage_model_dependencies(case.preparation, case.snapshot)
    if damage.startswith("receipt_"):
        path.write_bytes(original)
        path.chmod(0o600)
    if damage == "qualification_missing":
        qualification_path.write_bytes(qualification_bytes)
        qualification_path.chmod(0o600)
    case.preparation.model_artifacts = DirectModelSettlementVerifier(
        case.artifacts, case.verifier.archive, case.verifier.receipts
    )
    with pytest.raises(CoverageModelDependencyRepairRequired, match="explicit original repair"):
        await restore_coverage_model_dependencies(case.preparation, case.snapshot)
    # Native preparation rechecks its exact acceptance. Only the explicit repair
    # path may then remove this original dependency's persistent hold.
    await case.preparation.model_artifacts.ensure(case.participant, case.certificate)
    repaired = await capture_coverage_model_dependencies(
        case.preparation, case.package, case.prepared, repair_reason="original dependency restored"
    )
    assert repaired == case.snapshot
    assert await restore_coverage_model_dependencies(case.preparation, repaired)
    assert case.source.ranges_read == prior_reads


@pytest.mark.parametrize(
    "change", ["standing_review", "namespace", "owner", "receipts", "semantics"]
)
async def test_restore_binds_selected_verifier_context(dependency, monkeypatch, change):
    case = dependency
    if change == "standing_review":
        patch = case.artifacts.config.standing_review_policy.model_copy(
            update={"maximum_document_bytes": 1}
        )
        monkeypatch.setattr(
            case.artifacts,
            "config",
            case.artifacts.config.model_copy(update={"standing_review_policy": patch}),
        )
    elif change == "namespace":
        monkeypatch.setattr(
            case.source,
            "signer",
            R2SigV4(
                "https://11111111111111111111111111111111.r2.cloudflarestorage.com",
                "umi-model-artifacts",
                R2Credentials("0123456789ABCDEF", "offline-test-secret"),
            ),
        )
    elif change == "owner":
        monkeypatch.setattr(case.artifacts, "owner_hotkey", None)
    elif change == "receipts":
        case.preparation.model_artifacts = DirectModelSettlementVerifier(
            case.artifacts, case.verifier.archive, case.reviews.root / "other-receipts"
        )
    else:
        monkeypatch.setattr(models, "runtime_identity", lambda: "ff" * 32)
    with pytest.raises(
        CoverageModelDependencyRepairRequired, match="context requires explicit repair"
    ):
        await restore_coverage_model_dependencies(case.preparation, case.snapshot)


async def test_legacy_models_keep_native_path_and_no_model_receipts_need_no_payload(dependency):
    case = dependency
    assert not await restore_coverage_model_dependencies(case.preparation, None)
    legacy = case.certificate.model_copy(
        update={
            "acceptance": case.certificate.acceptance.model_copy(update={"direct_artifact": None})
        }
    )
    case.prepared.allocation.model_award = SimpleNamespace(acceptances=(legacy,))
    fallback = await capture_coverage_model_dependencies(
        case.preparation, case.package, case.prepared
    )
    assert fallback["mode"] == "native_required"
    assert not await restore_coverage_model_dependencies(case.preparation, fallback)
    case.preparation.model_artifacts = None
    assert await restore_coverage_model_dependencies(case.preparation, None)
    absent = await capture_coverage_model_dependencies(
        case.preparation, case.package, case.prepared
    )
    assert absent["mode"] == "not_selected"
    assert await restore_coverage_model_dependencies(case.preparation, absent)
    case.preparation.model_artifacts = case.verifier
    with pytest.raises(CoverageModelDependencyRepairRequired, match="selection changed"):
        await restore_coverage_model_dependencies(case.preparation, absent)


def _dependency_metadata(case):
    context = models.ModelDependencyContext.model_validate_json(
        canonical_json_bytes(case.snapshot["context"])
    )
    item = models.CoverageModelDependency.model_validate_json(
        canonical_json_bytes(case.snapshot["items"][0])
    )
    return context, item, models._qualification_path(case.verifier, context, item)


async def test_lost_completed_qualification_before_capture_requires_metadata_repair(
    dependency, monkeypatch, caplog
):
    case = dependency
    context, item, path = _dependency_metadata(case)
    original = path.read_bytes()
    completed = model_ledger.QualificationLedger(case.verifier.receipts).load(context, item)
    path.unlink()

    def prohibit(*args, **kwargs):
        raise AssertionError("lost completion was mistaken for a new native qualification")

    monkeypatch.setattr(case.artifacts, "verify", prohibit)
    monkeypatch.setattr(case.source, "read_range", prohibit)
    with pytest.raises(CoverageModelDependencyRepairRequired, match="metadata repair"):
        await capture_coverage_model_dependencies(case.preparation, case.package, case.prepared)
    # Fresh capture observes and holds the loss before any compact restore ran.
    assert models._held(case.verifier, item) is not None
    case.preparation.model_artifacts = DirectModelSettlementVerifier(
        case.artifacts, case.verifier.archive, case.verifier.receipts
    )
    with pytest.raises(CoverageModelDependencyRepairRequired, match="explicit original repair"):
        await capture_coverage_model_dependencies(case.preparation, case.package, case.prepared)
    with caplog.at_level("INFO"):
        repaired = await capture_coverage_model_dependencies(
            case.preparation, case.package, case.prepared, repair_reason="restore native metadata"
        )
    assert repaired == case.snapshot
    assert path.read_bytes() == original
    assert model_ledger.QualificationLedger(case.verifier.receipts).load(context, item) == completed
    assert models._held(case.verifier, item) is None
    assert "coverage_model_qualification_metadata_repair" in caplog.text
    assert await restore_coverage_model_dependencies(case.preparation, repaired)


@pytest.mark.parametrize("damage", ["database", "owner", "completion_pair", "schema"])
async def test_qualification_completion_owner_loss_never_restarts_native_work(
    dependency, monkeypatch, damage
):
    case = dependency
    _context, item, path = _dependency_metadata(case)
    ledger = model_ledger.QualificationLedger(case.verifier.receipts)
    path.unlink()
    if damage == "database":
        ledger.journal.path.unlink()
    elif damage == "owner":
        (case.verifier.receipts / "coverage-qualification-owner.json").unlink()
    else:
        with sqlite3.connect(ledger.journal.path) as db:
            name = model_ledger._TABLE + "_delete"
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                db.execute("DELETE FROM records WHERE kind='model_qualification'")
            db.execute("DROP TRIGGER " + name)
            if damage == "completion_pair":
                db.execute("DELETE FROM records WHERE kind='model_qualification'")
                db.execute(model_ledger._triggers()[name])

    def prohibit(*args, **kwargs):
        raise AssertionError("damaged completion owner caused another model check")

    monkeypatch.setattr(case.artifacts, "verify", prohibit)
    with pytest.raises(CoverageModelDependencyRepairRequired, match="metadata repair"):
        await capture_coverage_model_dependencies(case.preparation, case.package, case.prepared)
    assert models._held(case.verifier, item) is not None
    with pytest.raises(CoverageModelDependencyRepairRequired, match="metadata repair"):
        await capture_coverage_model_dependencies(
            case.preparation, case.package, case.prepared, repair_reason="owner restoration needed"
        )


async def test_legacy_qualification_migrates_exact_bytes_without_native_recheck(
    dependency, monkeypatch, caplog
):
    case = dependency
    context, item, path = _dependency_metadata(case)
    original = path.read_bytes()
    # Reproduce the supported pre-ledger layout with its original qualifier.
    shutil.rmtree(case.verifier.receipts / "coverage-qualification-ledger")
    (case.verifier.receipts / "coverage-qualification-owner.json").unlink()

    def prohibit(*args, **kwargs):
        raise AssertionError("legacy metadata migration rechecked model payloads")

    monkeypatch.setattr(case.artifacts, "verify", prohibit)
    with caplog.at_level("INFO"):
        assert await restore_coverage_model_dependencies(case.preparation, case.snapshot)
    assert path.read_bytes() == original
    assert model_ledger.QualificationLedger(case.verifier.receipts).load(context, item)
    assert "coverage_model_qualification_ledger_migration" in caplog.text
    assert (
        await capture_coverage_model_dependencies(case.preparation, case.package, case.prepared)
        == case.snapshot
    )


async def test_model_qualification_ledger_refuses_reservation_transition(dependency):
    case = dependency
    context, item, _path = _dependency_metadata(case)
    ledger = model_ledger.QualificationLedger(case.verifier.receipts)
    completed = ledger.load(context, item)
    with ledger.journal.read_transaction() as db:
        original_schema = db.execute(
            "SELECT type,name,sql FROM sqlite_master ORDER BY name"
        ).fetchall()
    with pytest.raises(ValueError, match="does not support reservations"):
        ledger.journal.reserve_records("unsupported", ())
    with ledger.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (5,)
        assert (
            db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
            == original_schema
        )
    assert model_ledger.QualificationLedger(case.verifier.receipts).load(context, item) == completed


async def test_interrupted_qualification_publication_retains_original_completion(
    dependency, monkeypatch
):
    case = dependency
    context, item, _path = _dependency_metadata(case)
    context = context.model_copy(update={"semantics_sha256": "ef" * 32})
    value = models.ModelDependencyQualification(
        schema="umi-coverage-model-qualification/1",
        context_sha256=digest(context),
        dependency_sha256=digest(item),
    )

    def interrupted(*args, **kwargs):
        raise OSError("interrupted before qualifier publication")

    with monkeypatch.context() as patch:
        patch.setattr(models, "publish_private_model", interrupted)
        with pytest.raises(OSError, match="interrupted"):
            models._publish_qualification(case.verifier, context, item, value)
    assert model_ledger.QualificationLedger(case.verifier.receipts).load(context, item) == value
    with pytest.raises(ValueError, match=r"completed.*missing"):
        models._qualification(case.verifier, context, item, required=False)
    assert (
        models._qualification(case.verifier, context, item, required=False, repairing=True) == value
    )
    assert models._qualification_path(case.verifier, context, item).read_bytes() == (
        canonical_json_bytes(value)
    )


async def test_interrupted_legacy_qualification_migration_resumes_without_rewriting_bytes(
    dependency, monkeypatch
):
    case = dependency
    context, item, path = _dependency_metadata(case)
    original = path.read_bytes()
    root = case.verifier.receipts / "coverage-qualification-ledger"
    shutil.rmtree(root)
    (case.verifier.receipts / "coverage-qualification-owner.json").unlink()

    def interrupted(*args, **kwargs):
        raise OSError("interrupted legacy completion migration")

    with monkeypatch.context() as patch:
        patch.setattr(model_ledger.TransferProgress, "advance", interrupted)
        with pytest.raises(OSError, match="interrupted"):
            model_ledger.QualificationLedger(case.verifier.receipts)
    with sqlite3.connect(root / "rounds.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM records").fetchone() == (0,)
    ledger = model_ledger.QualificationLedger(case.verifier.receipts)
    assert ledger.load(context, item)
    assert path.read_bytes() == original
