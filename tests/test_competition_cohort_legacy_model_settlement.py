"""Legacy /1 native admissions settle through authenticated R2 without archives."""

import asyncio
import shutil
from types import SimpleNamespace

import pytest

from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
    DirectModelSettlementVerifier,
)
from umi.competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from umi.competition_cohort_legacy_model_settlement import (
    LegacyModelSettlementStorage,
    legacy_seal_path,
    legacy_snapshot_path,
)
from umi.competition_cohort_legacy_model_storage import LegacyModelStorageRepairRequired
from umi.competition_cohort_model_acceptance import CertifiedModelArtifactAcceptance
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_roster import RecoverableRosterParticipant
from umi.competition_cohort_settlement_preparation import SettlementArtifactPreparation
from umi.competition_reward_coverage_models import (
    CoverageModelDependencies,
    CoverageModelDependencyRepairRequired,
    capture_coverage_model_dependencies,
    check_coverage_model_metadata,
    restore_coverage_model_dependencies,
)
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_chunked_model_backup import Remote
from .test_competition_cohort_legacy_model_storage import (
    authenticated,
)
from .test_competition_cohort_legacy_model_storage import base_policy as base_policy
from .test_competition_cohort_legacy_model_storage import (
    case as case,
)
from .test_competition_cohort_legacy_model_storage import legacy_scenario as legacy_scenario
from .test_competition_cohort_legacy_model_storage import policy as policy
from .test_competition_cohort_legacy_model_storage import prepared as prepared
from .test_competition_cohort_legacy_model_storage import receipt_scenario as receipt_scenario
from .test_competition_cohort_legacy_model_storage import recovery as recovery
from .test_competition_cohort_legacy_model_storage import runtime as runtime
from .test_competition_cohort_recovery import signatures
from .test_competition_reward_coverage_checkpoint import checkpoint as checkpoint

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def consumer(case, tmp_path, auth=None):
    auth = auth or authenticated(case)
    original = next(e for e in case.legacy.entries if e.certificate_raw_sha256 is not None)
    request = next(r for r in case.requests if digest(r.record.request) == original.request_sha256)
    certificate = CertifiedModelArtifactAcceptance.model_validate_json(
        case.objects[original.certificate_raw_sha256]
    )
    bundle = request.record.request.signed_submission.submission.model_bundle
    local = case.owner.archive / digest(bundle) / "model"
    prefix = next(
        m.object_key_prefix for m in auth.preservation.models if m.model_sha256 == digest(bundle)
    )
    objects = {
        prefix + "chunks/sha256/" + r.sha256: (local / r.path).read_bytes() for r in bundle.files
    }
    remote = Remote(objects)
    readers = LegacyModelStorageReaders(
        {case.cohort: auth},
        policy=case.policy,
        load_original=case.objects.__getitem__,
        multipart=remote,
        verification_root=tmp_path / "durable-bytes",
    )
    legacy = LegacyModelSettlementStorage(readers, case.cohort)
    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(case.policy),
        contribution_terms_sha256=case.policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-02T12:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    artifacts = DirectModelArtifactReviewer(
        DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/2",
            r2_credentials_file=str(tmp_path / "unused-credentials"),
            r2_bucket=remote.signer.bucket,
            standing_review_policy=standing,
            materialization_protected_roots=(str(tmp_path / "protected-state"),),
        ),
        case.policy,
        None,
        multipart=remote,
        verification_root=tmp_path / "direct-byte-results",
    )
    verifier = DirectModelSettlementVerifier(
        artifacts, tmp_path / "absent-archive", tmp_path / "receipts", legacy_storage=legacy
    )
    participant = RecoverableRosterParticipant(record=request.record, admission=request.admission)
    package = SimpleNamespace(
        inputs=SimpleNamespace(roster=SimpleNamespace(participants=(participant,)))
    )
    prepared = SimpleNamespace(
        allocation=SimpleNamespace(model_award=SimpleNamespace(acceptances=(certificate,)))
    )
    preparation = SimpleNamespace(model_artifacts=verifier, policy_sha256=digest(case.policy))
    return SimpleNamespace(
        case=case,
        legacy=legacy,
        verifier=verifier,
        remote=remote,
        readers=readers,
        artifacts=artifacts,
        participant=participant,
        certificate=certificate,
        package=package,
        prepared=prepared,
        preparation=preparation,
    )


@pytest.fixture
def remote_case(case, tmp_path):
    selected = consumer(case, tmp_path)
    shutil.rmtree(case.owner.archive)
    return selected


async def test_independent_full_bytes_then_fresh_consumers_reuse_without_local_archive(remote_case):
    c = remote_case
    original = canonical_json_bytes(c.certificate)
    await c.verifier.ensure(c.participant, c.certificate)
    assert len(c.remote.reads) == 7
    c.verifier.verify_candidate(c.certificate, c.participant)
    assert not c.verifier.archive.exists()
    restarted = DirectModelSettlementVerifier(
        c.artifacts,
        c.verifier.archive,
        c.verifier.receipts,
        legacy_storage=LegacyModelSettlementStorage(c.readers, c.case.cohort),
    )
    before = tuple(c.remote.reads)
    await restarted.ensure(c.participant, c.certificate)
    restarted.verify_candidate(c.certificate, c.participant)
    assert tuple(c.remote.reads) == before
    assert canonical_json_bytes(c.certificate) == original
    assert c.certificate.acceptance.direct_artifact is None


async def test_selected_generation_owner_reuses_legacy_settlement_and_coverage(remote_case):
    from umi.competition_chunked_model_backup import BYTE_ABI
    from umi.competition_model_byte_store import ModelByteStoreConfig
    from umi.competition_model_generation_store import (
        ModelGenerationStoreConfig,
        initialize_generation_owner,
    )
    from umi.competition_transport_verification import verifier_semantics

    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    receipt = c.legacy.verify_candidate(c.participant, c.certificate, c.verifier.receipts)
    original_paths = (
        legacy_snapshot_path(c.verifier.receipts, receipt),
        legacy_seal_path(c.verifier.receipts, receipt),
        c.verifier._path(c.certificate),
    )
    original = {path: path.read_bytes() for path in original_paths}
    resolution = c.legacy.resolution(receipt.original_request_sha256)
    reader = c.readers.reader(resolution)
    owner = ModelGenerationStoreConfig(
        schema="umi-model-generation-owner/1",
        owner_sha256="ab" * 32,
        namespace_sha256=digest(reader._namespace()),
        retention="retain_original_generations_until_authenticated_release",
    )
    initialize_generation_owner(reader.root, owner, semantics=[BYTE_ABI, verifier_semantics()])
    c.readers.byte_stores[c.case.cohort] = ModelByteStoreConfig(
        schema="umi-model-byte-verification-store/1",
        directory=str(reader.root),
        generation_owner=owner,
    )
    c.remote.heads.clear()
    c.remote.reads.clear()
    await c.verifier.ensure(c.participant, c.certificate)
    coverage = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    assert await restore_coverage_model_dependencies(c.preparation, coverage)
    assert c.remote.heads == c.remote.reads == []
    assert all(path.read_bytes() == raw for path, raw in original.items())
    selected = c.readers.reader(resolution)
    key = next(iter(c.remote.etags))
    c.remote.etags[key] = "changed-generation"
    with pytest.raises(ValueError, match="generation changed"):
        await selected.available()
    with pytest.raises(LegacyModelStorageRepairRequired):
        await c.verifier.ensure(c.participant, c.certificate)
    with pytest.raises(CoverageModelDependencyRepairRequired):
        await restore_coverage_model_dependencies(c.preparation, coverage)


@pytest.mark.parametrize("prefix", ["", "preservation/v1/"])
async def test_prefixed_completions_survive_restart_and_reward_coverage_without_byte_reads(
    case, tmp_path, monkeypatch, prefix
):
    preservation = case.preservation.model_copy(
        update={
            "models": tuple(
                m.model_copy(update={"object_key_prefix": prefix}) for m in case.preservation.models
            )
        }
    )
    c = consumer(case, tmp_path, authenticated(case, preservation=preservation))
    await c.verifier.ensure(c.participant, c.certificate)
    assert c.remote.reads and all(
        key.startswith(prefix + "chunks/sha256/") for key in c.remote.reads
    )
    receipt = c.legacy.verify_candidate(c.participant, c.certificate, c.verifier.receipts)
    paths = (
        legacy_snapshot_path(c.verifier.receipts, receipt),
        legacy_seal_path(c.verifier.receipts, receipt),
        c.verifier._path(c.certificate),
    )
    retained = {p: p.read_bytes() for p in paths}
    signed = canonical_json_bytes(c.certificate)
    shutil.rmtree(case.owner.archive)

    async def forbidden(*args, **kwargs):
        raise AssertionError("completed settlement must never fetch model payload bytes")

    monkeypatch.setattr(c.remote, "read_range", forbidden)
    restarted = DirectModelSettlementVerifier(
        c.artifacts,
        c.verifier.archive,
        c.verifier.receipts,
        legacy_storage=LegacyModelSettlementStorage(c.readers, c.case.cohort),
    )
    await restarted.ensure(c.participant, c.certificate)
    restarted.verify_candidate(c.certificate, c.participant)
    c.preparation.model_artifacts = restarted
    coverage = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    assert await restore_coverage_model_dependencies(c.preparation, coverage)
    check_coverage_model_metadata(
        CoverageModelDependencies.model_validate_json(canonical_json_bytes(coverage))
    )
    assert all(p.read_bytes() == raw for p, raw in retained.items())
    assert canonical_json_bytes(c.certificate) == signed
    assert c.certificate.acceptance.direct_artifact is None


@pytest.mark.parametrize("fault", ["prefix", "generation"])
async def test_prefixed_completed_snapshot_still_rejects_namespace_or_generation_changes(
    case, tmp_path, monkeypatch, fault
):
    preservation = case.preservation.model_copy(
        update={
            "models": tuple(
                m.model_copy(update={"object_key_prefix": "preservation/v1/"})
                for m in case.preservation.models
            )
        }
    )
    c = consumer(case, tmp_path, authenticated(case, preservation=preservation))
    await c.verifier.ensure(c.participant, c.certificate)

    async def forbidden(*args, **kwargs):
        raise AssertionError("namespace repair cannot silently reread model bytes")

    monkeypatch.setattr(c.remote, "read_range", forbidden)
    if fault == "prefix":
        original = c.readers.reader

        def substituted(resolution):
            reader = original(resolution)
            reader.selection = reader.selection.model_copy(
                update={
                    "binding": reader.selection.binding.model_copy(
                        update={"object_key_prefix": "other/v1/"}
                    )
                }
            )
            return reader

        monkeypatch.setattr(c.readers, "reader", substituted)
    else:
        c.remote.etags[next(iter(c.remote.objects))] = "changed-generation"
    with pytest.raises(LegacyModelStorageRepairRequired):
        await c.verifier.ensure(c.participant, c.certificate)


async def test_settlement_preparation_uses_selected_legacy_r2(remote_case, tmp_path):
    c = remote_case
    root = tmp_path / "promotion"
    request = next(r for r in c.case.requests if r.acceptance == c.certificate.acceptance)
    key = c.certificate.acceptance.submission_sha256
    publish_private_model(
        root / "model-reward-preparation" / c.case.cohort / (key + ".json"), request
    )
    publish_private_model(
        root / "model-reward-acceptances" / c.case.cohort / (key + ".json"), c.certificate
    )
    config = SimpleNamespace(
        policy=c.case.policy,
        series=SimpleNamespace(recovery=c.case.history.authority, cohorts=(c.case.history.plan,)),
    )
    worker = SettlementArtifactPreparation(
        config, SimpleNamespace(directory=root), {c.case.cohort: c.verifier}
    )
    result = await worker.poll_once(asyncio.Event())
    assert result["entries_ready"] == 1 and result["entries_pending"] == 0
    reads, heads = tuple(c.remote.reads), tuple(c.remote.heads)
    restarted = SettlementArtifactPreparation(
        config, SimpleNamespace(directory=root), {c.case.cohort: c.verifier}
    )
    assert (await restarted.poll_once(asyncio.Event()))["entries_ready"] == 1
    assert tuple(c.remote.reads) == reads and tuple(c.remote.heads) == heads
    receipt_path = c.verifier._path(c.certificate)
    original_receipt = receipt_path.read_bytes()
    receipt_path.unlink()
    assert (await restarted.poll_once(asyncio.Event()))["entries_ready"] == 1
    assert receipt_path.read_bytes() == original_receipt and tuple(c.remote.reads) == reads
    heads = tuple(c.remote.heads)
    # Background readiness confers no freshness or settlement authority. The
    # final native consumer must still detect a changed remote generation.
    key = next(iter(c.remote.etags))
    c.remote.etags[key] = "changed-generation"
    result = await restarted.poll_once(asyncio.Event())
    assert result["entries_ready"] == 1 and result["entries_pending"] == 0
    assert result["scoring_authorized"] is result["chain_submission_authorized"] is False
    assert tuple(c.remote.reads) == reads and tuple(c.remote.heads) == heads
    with pytest.raises(LegacyModelStorageRepairRequired):
        await c.verifier.ensure_all((c.participant,), (c.certificate,))
    # Damaged completion metadata remains pending; advisory polling must not
    # silently rebuild or fetch payloads to make that record ready.
    c.verifier._path(c.certificate).write_bytes(b"{broken")
    heads = tuple(c.remote.heads)
    result = await restarted.poll_once(asyncio.Event())
    assert result["entries_ready"] == 0 and result["entries_pending"] == 1
    assert tuple(c.remote.reads) == reads and tuple(c.remote.heads) == heads


async def test_compact_coverage_replays_original_legacy_acceptance_without_payload_reads(
    remote_case,
):
    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    reads = tuple(c.remote.reads)
    raw = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    assert raw["schema"] == "umi-coverage-model-dependencies/2"
    assert raw["mode"] == "remote"
    assert len(canonical_json_bytes(raw)) < 8192
    c.preparation.model_artifacts = DirectModelSettlementVerifier(
        c.artifacts,
        c.verifier.archive,
        c.verifier.receipts,
        legacy_storage=LegacyModelSettlementStorage(c.readers, c.case.cohort),
    )
    assert await restore_coverage_model_dependencies(c.preparation, raw)
    check_coverage_model_metadata(
        CoverageModelDependencies.model_validate_json(canonical_json_bytes(raw))
    )
    assert tuple(c.remote.reads) == reads


@pytest.mark.parametrize(
    "fault",
    [
        "receipt_missing",
        "receipt_corrupt",
        "snapshot_missing",
        "snapshot_corrupt",
        "seal_missing",
        "seal_corrupt",
        "namespace",
        "generation",
        "selection_missing",
    ],
)
async def test_coverage_invalidation_requires_explicit_repair_and_never_gets_weights(
    remote_case, fault
):
    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    raw = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    receipt = c.legacy.verify_candidate(c.participant, c.certificate, c.verifier.receipts)
    if fault.startswith("receipt"):
        path = c.verifier._path(c.certificate)
    elif fault.startswith("snapshot"):
        path = legacy_snapshot_path(c.verifier.receipts, receipt)
    elif fault.startswith("seal_"):
        path = legacy_seal_path(c.verifier.receipts, receipt)
    else:
        path = None
    if path is not None:
        if fault.endswith("missing"):
            path.unlink()
        else:
            path.write_bytes(b"{}")
    elif fault == "namespace":
        c.remote.signer.bucket = "other-model-artifacts"
    elif fault == "generation":
        c.remote.etags[next(iter(c.remote.objects))] = "changed-generation"
    else:
        c.verifier.legacy_storage = None
    before = tuple(c.remote.reads)
    with pytest.raises(CoverageModelDependencyRepairRequired):
        await restore_coverage_model_dependencies(c.preparation, raw)
    assert tuple(c.remote.reads) == before


async def test_lost_completion_acknowledgement_has_explicit_metadata_only_repair(remote_case):
    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    path = c.verifier._path(c.certificate)
    expected = path.read_bytes()
    path.unlink()
    before = tuple(c.remote.reads)
    with pytest.raises(LegacyModelStorageRepairRequired):
        await c.legacy.ensure(c.participant, c.certificate, c.verifier.receipts)
    # The actual native worker selects the qualified metadata-only repair.
    heads = len(c.remote.heads)
    await c.verifier.ensure(c.participant, c.certificate)
    assert path.read_bytes() == expected and tuple(c.remote.reads) == before
    # Repair consumes one generation assessment; publishing the exact small
    # receipt does not change its already checked remote-object dependencies.
    checked = c.remote.heads[heads:]
    assert len(checked) == len(set(checked)) == len(c.remote.objects)


async def test_interrupted_first_byte_pass_resumes_only_unfinished_files(remote_case):
    c = remote_case
    failed = c.participant.record.request.signed_submission.submission.model_bundle.files[3].sha256
    c.remote.fail = "chunks/sha256/" + failed
    with pytest.raises(OSError):
        await c.verifier.ensure(c.participant, c.certificate)
    completed = tuple(c.remote.reads)
    c.remote.fail = None
    await c.verifier.ensure(c.participant, c.certificate)
    assert all(c.remote.reads.count(key) == 1 for key in completed)


async def test_corrupt_remote_bytes_never_create_settlement_receipt(remote_case):
    c = remote_case
    key = next(iter(c.remote.objects))
    c.remote.objects[key] = b"x" * len(c.remote.objects[key])
    with pytest.raises(ValueError):
        await c.verifier.ensure(c.participant, c.certificate)
    assert not c.verifier._path(c.certificate).exists()


async def test_original_admitted_entry_may_gain_genuine_certificate_after_adoption(case, tmp_path):
    entries = tuple(
        e.model_copy(update={"intent_raw_sha256": None, "certificate_raw_sha256": None})
        for e in case.legacy.entries
    )
    legacy = case.legacy.model_copy(update={"entries": entries})
    preservation = case.preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    auth = authenticated(case, legacy=legacy, preservation=preservation)
    # Build the consumer using the original publication, then select the amended
    # census lacking old intents. This creates no replacement upload reservation.
    original = next(e for e in case.legacy.entries if e.certificate_raw_sha256 is not None)
    request = next(r for r in case.requests if digest(r.record.request) == original.request_sha256)
    c = consumer(case, tmp_path, auth=auth)
    acceptance = request.acceptance.model_copy(update={"accepted_at_block": 225})
    certificate = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=signatures(acceptance)
    )
    shutil.rmtree(case.owner.archive)
    await c.verifier.ensure(c.participant, certificate)
    c.verifier.verify_candidate(certificate, c.participant)
    assert certificate.acceptance.direct_artifact is None
    early = acceptance.model_copy(update={"accepted_at_block": 220})
    early_certificate = CertifiedModelArtifactAcceptance(
        acceptance=early, signatures=signatures(early)
    )
    with pytest.raises(ValueError, match="predates"):
        c.legacy.accepted(c.participant, early_certificate)


@pytest.mark.parametrize("fault", ["different_participant", "changed_intent", "bad_quorum"])
async def test_authenticated_storage_never_replaces_native_acceptance_evidence(remote_case, fault):
    c = remote_case
    participant, certificate = c.participant, c.certificate
    if fault == "different_participant":
        other = next(r for r in c.case.requests if r.record != participant.record)
        participant = RecoverableRosterParticipant(record=other.record, admission=other.admission)
    elif fault == "changed_intent":
        acceptance = certificate.acceptance.model_copy(update={"accepted_ordinal": 99})
        certificate = CertifiedModelArtifactAcceptance(
            acceptance=acceptance, signatures=signatures(acceptance)
        )
    else:
        certificate = certificate.model_copy(update={"signatures": certificate.signatures[:1]})
    with pytest.raises(ValueError):
        await c.verifier.ensure(participant, certificate)
    assert not c.remote.reads


async def test_mixed_legacy_and_direct_originals_share_remote_coverage_without_archives(
    remote_case,
):
    from umi.competition_cohort_direct_model_upload import (
        DirectModelPayload,
        DirectModelUploadReservation,
        SignedDirectModelUploadReservation,
        direct_model_object_key,
        preserved_model_object_key,
    )
    from umi.open_competition import sign_object
    from umi.protocol import sha256_hex

    from .test_open_competition import wallet

    c = remote_case
    other = next(r for r in c.case.requests if r.record != c.participant.record)
    participant = RecoverableRosterParticipant(record=other.record, admission=other.admission)
    bundle = other.record.request.signed_submission.submission.model_bundle
    data = b"".join(c.remote.objects["chunks/sha256/" + f.sha256] for f in bundle.files)
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(other.record.request),
        model_sha256=digest(bundle),
        payload_sha256=sha256_hex(data),
        total_bytes=len(data),
        file_count=len(bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    key = direct_model_object_key(c.case.cohort, payload.upload_sha256, "a1" * 32)
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=c.case.cohort,
        hotkey=other.record.request.signed_submission.submission.hotkey,
        payload=payload,
        attempt_id="a1" * 32,
        generation=1,
        object_key_sha256=sha256_hex(key.encode()),
        provider_upload_id_sha256="b2" * 32,
        created_at_unix_ms=1_800_000_000_000,
    )
    signed = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    acceptance = other.acceptance.model_copy(
        update={
            "schema_": "umi-cohort-model-artifact-acceptance/2",
            "direct_artifact": signed,
            "accepted_at_block": 225,
        }
    )
    prototype = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=signatures(acceptance)
    )
    preserved = preserved_model_object_key(
        c.case.cohort, payload.model_sha256, payload.payload_sha256
    )
    c.remote.objects[preserved] = data
    c.remote.etags[preserved] = "original-generation"
    original_read = c.remote.read_range

    async def read_range(key, *, offset, size_bytes):
        if key == preserved:
            c.remote.reads.append(key)
            return data[offset : offset + size_bytes]
        return await original_read(key, offset=offset, size_bytes=size_bytes)

    c.remote.read_range = read_range
    request = c.verifier._request(participant, prototype)
    inputs, _ = await c.artifacts.verify(request, preserved=True)
    acceptance = acceptance.model_copy(
        update={
            "rights_evidence_sha256": digest(inputs.rights_evidence),
            "reconstruction_evidence_sha256": digest(inputs.reconstruction_evidence),
        }
    )
    direct_certificate = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=signatures(acceptance)
    )
    pairs = sorted(
        ((c.participant, c.certificate), (participant, direct_certificate)),
        key=lambda pair: pair[1].acceptance.submission_sha256,
    )
    participants = tuple(pair[0] for pair in pairs)
    certificates = tuple(pair[1] for pair in pairs)
    await c.verifier.ensure_all(participants, certificates)
    for p, cert in pairs:
        c.verifier.verify_candidate(cert, p)
    package = SimpleNamespace(
        inputs=SimpleNamespace(roster=SimpleNamespace(participants=participants))
    )
    prepared = SimpleNamespace(
        allocation=SimpleNamespace(model_award=SimpleNamespace(acceptances=certificates))
    )
    before = tuple(c.remote.reads)
    snapshot = await capture_coverage_model_dependencies(c.preparation, package, prepared)
    assert snapshot["mode"] == "remote" and len(snapshot["items"]) == 2
    assert await restore_coverage_model_dependencies(c.preparation, snapshot)
    assert tuple(c.remote.reads) == before
    assert not c.verifier.archive.exists()


async def test_existing_native_required_checkpoint_migrates_without_rewriting_original(
    remote_case, checkpoint
):
    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    remote = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    old = dict(remote, schema="umi-coverage-model-dependencies/1", mode="native_required", items=[])
    assert not await restore_coverage_model_dependencies(c.preparation, old)
    checkpoint.endpoint.model_dependencies = old
    checkpoint.owner.remember(checkpoint.endpoint, checkpoint.keys)
    original = checkpoint.owner.load(checkpoint.key)
    checkpoint.endpoint.model_dependencies = remote
    before = tuple(c.remote.reads)
    checkpoint.owner.remember(checkpoint.endpoint, checkpoint.keys)
    migrated = checkpoint.owner.load(checkpoint.key)
    assert migrated["repair"] == "authenticated legacy R2 model dependency migration"
    assert checkpoint.journal.get("coverage_verified", digest(original)) == original
    assert await restore_coverage_model_dependencies(c.preparation, migrated["model_dependencies"])
    assert tuple(c.remote.reads) == before


async def test_issued_checkpoint_keeps_legacy_receipt_damage_hold_until_explicit_repair(
    remote_case, checkpoint
):
    from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired

    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    snapshot = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    checkpoint.endpoint.model_dependencies = snapshot
    checkpoint.owner.remember(checkpoint.endpoint, checkpoint.keys)
    saved = checkpoint.owner.load(checkpoint.key)
    path = c.verifier._path(c.certificate)
    path.unlink()
    with pytest.raises(CoverageCheckpointRepairRequired):
        checkpoint.owner.load(checkpoint.key)
    before = tuple(c.remote.reads)
    await c.legacy.ensure(c.participant, c.certificate, c.verifier.receipts, repairing=True)
    with pytest.raises(CoverageCheckpointRepairRequired):
        checkpoint.owner.load(checkpoint.key)
    await capture_coverage_model_dependencies(
        c.preparation,
        c.package,
        c.prepared,
        repair_reason="original legacy receipt restored from completion",
    )
    assert checkpoint.owner.load(checkpoint.key) == saved
    assert tuple(c.remote.reads) == before


async def test_legacy_verifier_semantics_change_invalidates_only_legacy_receipt(
    remote_case, monkeypatch
):
    from umi import competition_cohort_legacy_model_settlement as module

    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    snapshot = await capture_coverage_model_dependencies(c.preparation, c.package, c.prepared)
    before = tuple(c.remote.reads)
    monkeypatch.setattr(module, "LEGACY_SETTLEMENT_ABI", "incompatible-fixture-verifier/2")
    with pytest.raises(CoverageModelDependencyRepairRequired):
        await restore_coverage_model_dependencies(c.preparation, snapshot)
    assert tuple(c.remote.reads) == before


async def test_settlement_reuses_shared_prior_review_byte_facts_without_rereading_payload(
    remote_case,
):
    c = remote_case
    resolution = c.legacy.accepted(c.participant, c.certificate)
    documents = tuple(
        f.path for f in resolution.selection.bundle.files if f.role in {"license", "provenance"}
    )
    await c.readers.reader(resolution).verify(document_paths=documents)
    prior = tuple(c.remote.reads)
    await c.verifier.ensure(c.participant, c.certificate)
    assert tuple(c.remote.reads) == prior
    c.verifier.verify_candidate(c.certificate, c.participant)


async def test_series_wide_verifier_uses_cohort_selected_storage_and_reuses_original_receipts(
    remote_case,
):
    c = remote_case
    await c.verifier.ensure(c.participant, c.certificate)
    prior = tuple(c.remote.reads)
    series_verifier = DirectModelSettlementVerifier(
        c.artifacts, c.verifier.archive, c.verifier.receipts, legacy_readers=c.readers
    )
    assert series_verifier.legacy_for(c.case.cohort).authenticated == c.legacy.authenticated
    assert series_verifier.legacy_for("ff" * 32) is None
    await series_verifier.ensure(c.participant, c.certificate)
    series_verifier.verify_candidate(c.certificate, c.participant)
    preparation = SimpleNamespace(
        model_artifacts=series_verifier, policy_sha256=digest(c.case.policy)
    )
    snapshot = await capture_coverage_model_dependencies(preparation, c.package, c.prepared)
    await restore_coverage_model_dependencies(preparation, snapshot)
    assert tuple(c.remote.reads) == prior
