"""Frozen native admissions without intents continue on R2 after adoption."""

import asyncio
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import verify_preserved_bundle
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
)
from umi.competition_cohort_legacy_model_admission import LegacyModelAdmissionPayloads
from umi.competition_cohort_legacy_model_cache import LegacyCohortModelCache
from umi.competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from umi.competition_cohort_legacy_model_storage import (
    LegacyModelOriginals,
    LegacyModelPreservationInventory,
    LegacyModelStorageInventory,
)
from umi.competition_cohort_model_acceptance_store import CohortModelAcceptances
from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from umi.competition_cohort_model_review import ModelArtifactReviewer, ModelReviewConfig
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.competition_cohort_service_host import CohortModelPayloadRouter
from umi.competition_model_cache_space import BootDiskModelCacheConfig
from umi.open_competition import digest, sign_object
from umi.private_files import publish_private_model

from .test_competition_chunked_model_backup import Remote
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_legacy_model_storage import authenticated, backup, retain
from .test_competition_cohort_model_acceptance import certify
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_recovery import signed_transition
from .test_open_competition import bundle_at, wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def freeze(owner, cohort, baseline, *, block=220):
    """Capture originals before reserving any acceptance; no journal deletion."""
    history, policy = owner.intake.history(cohort), owner.intake.policy
    objects, entries, requests, subs = {}, [], [], []
    with owner.intake._connection() as (db, _):
        for _, _, record in owner.intake._parsed_records(db, history, track="model"):
            request = record.request
            sub = request.signed_submission.submission
            certificate = db.execute(
                "SELECT body FROM cohort_admission_certificates WHERE consent=?",
                (record.proposed_admission.consent_sha256,),
            ).fetchone()[0]
            assert (
                db.execute(
                    "SELECT 1 FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
                    (cohort, digest(sub)),
                ).fetchone()
                is None
            )
            entries.append(
                LegacyModelOriginals(
                    request_sha256=digest(request),
                    model_sha256=sub.model_revision,
                    request_raw_sha256=retain(objects, request),
                    payload_state="preserved",
                    participation_raw_sha256=retain(objects, record),
                    admission_raw_sha256=retain(objects, certificate),
                )
            )
            requests.append(request)
            subs.append(sub)
    common = dict(
        cohort_sha256=cohort,
        policy_sha256=digest(policy),
        authority_sha256=digest(history.authority.authority),
        predecessor_sha256=digest(
            history.transitions[-1].transition if history.transitions else history.genesis
        ),
    )
    legacy = LegacyModelStorageInventory(
        schema="umi-cohort-legacy-model-storage-inventory/1",
        **common,
        captured_at_block=block,
        baseline_model_sha256=digest(baseline),
        baseline_manifest_raw_sha256=retain(objects, baseline),
        entries=tuple(sorted(entries, key=lambda entry: entry.request_sha256)),
    )
    bundles = {digest(bundle): bundle for bundle in (baseline, *(s.model_bundle for s in subs))}
    preservation = LegacyModelPreservationInventory(
        schema="umi-cohort-legacy-model-preservation-inventory/1",
        **common,
        legacy_inventory_sha256=digest(legacy),
        models=tuple(backup(objects, bundles[key], policy) for key in sorted(bundles)),
    )
    return SimpleNamespace(
        owner=owner,
        cohort=cohort,
        policy=policy,
        history=history,
        objects=objects,
        legacy=legacy,
        preservation=preservation,
        baseline=baseline,
        subs=subs,
        requests=requests,
    )


@pytest.fixture
def frozen(prepared, tmp_path, request):
    original, cohort, subs, inputs = prepared
    baseline = bundle_at(tmp_path / "baseline", "baseline")
    case = freeze(original, cohort, baseline)
    if getattr(request, "param", None) in {"unadmitted", "incomplete"}:
        case.legacy = case.legacy.model_copy(
            update={
                "entries": tuple(
                    entry.model_copy(
                        update={
                            "participation_raw_sha256": None,
                            "admission_raw_sha256": None,
                            "payload_state": "incomplete_upload"
                            if request.param == "incomplete"
                            else "preserved",
                        }
                    )
                    for entry in case.legacy.entries
                )
            }
        )
        case.preservation = case.preservation.model_copy(
            update={
                "legacy_inventory_sha256": digest(case.legacy),
                "models": tuple(
                    model
                    for model in case.preservation.models
                    if request.param != "incomplete" or model.model_sha256 == digest(baseline)
                ),
            }
        )
    auth = authenticated(case)
    remote = Remote(
        {
            "chunks/sha256/" + file.sha256: (
                original.archive / sub.model_revision / "model" / file.path
            ).read_bytes()
            for sub in subs
            for file in sub.model_bundle.files
        }
    )
    sources = LegacyModelStorageReaders(
        {cohort: auth},
        policy=original.intake.policy,
        load_original=case.objects.__getitem__,
        multipart=remote,
        verification_root=tmp_path / "verification",
    )

    def create():
        payloads = LegacyModelAdmissionPayloads(original.intake, sources)
        owner = CohortModelAcceptances(
            original.intake,
            original.archive,
            legacy_payloads=payloads,
            review_artifact=lambda request: router.review_artifact(request),
        )
        router = CohortModelPayloadRouter(
            (case.history.plan,),
            legacy=SimpleNamespace(),
            direct=SimpleNamespace(),
            intake=original.intake,
            acceptances=owner,
            legacy_payloads=payloads,
        )
        return owner, router

    # Preserve its binding, but remove all payloads from the active archive.
    (original.archive / subs[0].model_revision).rename(tmp_path / "offline-original")
    owner, router = create()
    return SimpleNamespace(
        case=case,
        owner=owner,
        router=router,
        sources=sources,
        remote=remote,
        inputs=inputs,
        sub=subs[0],
        root=tmp_path,
        create=create,
    )


async def test_new_intent_uses_exact_frozen_admission_and_restart_reuses_bytes(frozen):
    f, c = frozen, frozen.case
    original_bytes = dict(c.objects)
    key = digest(f.sub)
    assert f.owner.intent(c.cohort, key) is None
    with pytest.raises(OSError, match="awaits owned R2"):
        f.owner.prepare(c.cohort, key, f.inputs, capture_at(230))
    await f.owner.ensure_payload(c.cohort, key)
    publication = certify(f.owner, c.cohort, f.sub, f.inputs, block=230)
    body = publication.certificate.acceptance
    assert body.schema_ == "umi-cohort-model-artifact-acceptance/1"
    assert body.accepted_ordinal == 1 and body.accepted_at_block == 230
    reads = tuple(f.remote.reads)
    assert len(reads) == len(f.sub.model_bundle.files)
    restarted, router = f.create()
    # Exact intent retry does not need payload verification or a new observation.
    assert restarted.prepare(c.cohort, key, f.inputs, None) == body
    await restarted.ensure_payload(c.cohort, key)
    assert tuple(f.remote.reads) == reads
    assert router.review_artifact(c.requests[0]) is None
    assert restarted.publish(publication, capture_at(231)) == publication
    request = restarted.review_request(c.cohort, key)
    f.sources.accepted(
        c.cohort, record=request.record, admission=request.admission, acceptance=body
    )
    f.remote.objects.clear()
    assert f.create()[0].publish(publication, None) == publication
    assert c.objects == original_bytes


@pytest.mark.parametrize("fault", ["unavailable", "corrupt", "interrupted"])
async def test_failed_remote_bytes_consume_no_ordinal_and_resume_completed_files(frozen, fault):
    f, c = frozen, frozen.case
    files = f.sub.model_bundle.files
    key = "chunks/sha256/" + files[-1].sha256
    original = f.remote.objects[key]
    if fault == "unavailable":
        del f.remote.objects[key]
    elif fault == "corrupt":
        f.remote.objects[key] = bytes(value ^ 1 for value in original)
    else:
        f.remote.fail = key
    with pytest.raises((OSError, ValueError)):
        await f.owner.ensure_payload(c.cohort, digest(f.sub))
    assert f.owner.intent(c.cohort, digest(f.sub)) is None
    completed = tuple(f.remote.reads)
    f.remote.objects[key], f.remote.fail = original, None
    restarted, _ = f.create()
    await restarted.ensure_payload(c.cohort, digest(f.sub))
    if fault == "interrupted":
        assert tuple(f.remote.reads[: len(completed)]) == completed
        assert all(f.remote.reads.count(item) == 1 for item in completed)
    assert (
        restarted.prepare(c.cohort, digest(f.sub), f.inputs, capture_at(230)).accepted_ordinal == 1
    )


@pytest.mark.parametrize(
    "field", ["request_raw_sha256", "participation_raw_sha256", "admission_raw_sha256"]
)
async def test_changed_original_metadata_refuses_before_remote_read(frozen, field):
    f, c = frozen, frozen.case
    entry = next(e for e in c.legacy.entries if e.request_sha256 == digest(c.requests[0]))
    c.objects[getattr(entry, field)] = b"{}"
    with pytest.raises(ValueError, match="changed identity"):
        await f.owner.ensure_payload(c.cohort, digest(f.sub))
    assert not f.remote.reads and f.owner.intent(c.cohort, digest(f.sub)) is None


async def test_damaged_owned_receipt_is_explicit_repair_not_a_supplied_digest(frozen, caplog):
    f, c = frozen, frozen.case
    await f.owner.ensure_payload(c.cohort, digest(f.sub))
    root = Path(f.sources.verification_root) / f.sub.model_revision / "remote"
    receipt = next(root.glob("*.json"))
    receipt.write_text("{}")
    with pytest.raises(OSError, match="requires repair"):
        f.owner.prepare(c.cohort, digest(f.sub), f.inputs, capture_at(230))
    assert f.owner.intent(c.cohort, digest(f.sub)) is None
    await f.owner.ensure_payload(c.cohort, digest(f.sub))
    assert f.owner.prepare(c.cohort, digest(f.sub), f.inputs, capture_at(230)).accepted_ordinal == 1


@pytest.mark.parametrize("frozen", ["unadmitted", "incomplete"], indirect=True)
async def test_upload_only_or_incomplete_original_cannot_create_legacy_acceptance(frozen):
    f, c = frozen, frozen.case
    assert not f.owner.legacy_payloads.contains(c.requests[0])
    assert f.router._mechanism(c.requests[0]) == "direct_r2_multipart_v1"
    f.owner.review_artifact = lambda _: None
    await f.owner.ensure_payload(c.cohort, digest(f.sub))
    with pytest.raises(ValueError, match="authenticated transport"):
        f.owner.prepare(c.cohort, digest(f.sub), f.inputs, capture_at(230))
    assert not f.remote.reads and f.owner.intent(c.cohort, digest(f.sub)) is None


@pytest.mark.parametrize("during", [False, True])
async def test_actual_owner_certificate_rechecked_at_both_reservation_boundaries(
    frozen, monkeypatch, during
):
    f, c = frozen, frozen.case
    await f.owner.ensure_payload(c.cohort, digest(f.sub))

    def damage():
        with f.owner.intake._connection() as (db, _):
            db.execute("UPDATE cohort_admission_certificates SET body=CAST(body || ' ' AS BLOB)")

    if during:
        verify = f.owner._verify_artifacts

        def verify_then_change(record):
            verify(record)
            damage()

        monkeypatch.setattr(f.owner, "_verify_artifacts", verify_then_change)
    else:
        damage()
    with pytest.raises(ValueError, match="canonical bytes"):
        f.owner.prepare(c.cohort, digest(f.sub), f.inputs, capture_at(230))
    assert f.owner.intent(c.cohort, digest(f.sub)) is None


async def test_committed_history_change_during_remote_verification_consumes_no_ordinal(
    frozen, monkeypatch
):
    f, c = frozen, frozen.case
    read = f.remote.read_range
    changed = False

    async def read_and_revoke(key, **kwargs):
        nonlocal changed
        raw = await read(key, **kwargs)
        if not changed:
            changed = True
            history = f.owner.intake.history(c.cohort)
            with f.owner.intake._connection() as (_, store):
                state, _ = store.status(c.cohort)
            transition = propose_recovery_transition(
                state,
                history.authority.authority,
                operation="revoke",
                observed_at_block=230,
                evidence_sha256="ab" * 32,
            )
            f.owner.intake.publish(
                history.model_copy(
                    update={
                        "transitions": (*history.transitions, signed_transition(transition)),
                    }
                ),
                capture_at(230),
            )
        return raw

    monkeypatch.setattr(f.remote, "read_range", read_and_revoke)
    with pytest.raises((OSError, ValueError), match=r"changed|revoked|inactive"):
        await f.owner.ensure_payload(c.cohort, digest(f.sub))
    assert changed and f.owner.intent(c.cohort, digest(f.sub)) is None


async def test_publication_rechecks_actual_participation_after_payload_verification(
    frozen, monkeypatch
):
    f, c = frozen, frozen.case
    await f.owner.ensure_payload(c.cohort, digest(f.sub))
    publication = certify(f.owner, c.cohort, f.sub, f.inputs, block=230)
    verify = f.owner._verify_artifacts

    def verify_then_change(record):
        verify(record)
        with f.owner.intake._connection() as (db, _):
            db.execute("UPDATE cohort_consents SET body=CAST(body || ' ' AS BLOB)")

    monkeypatch.setattr(f.owner, "_verify_artifacts", verify_then_change)
    with pytest.raises(ValueError, match="original participation"):
        f.owner.publish(publication, capture_at(230))
    with f.owner.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_model_acceptances").fetchone()[0] == 0
    assert f.owner.intent(c.cohort, digest(f.sub)).acceptance == publication.certificate.acceptance


async def test_owner_publication_consumes_bounded_restore_after_interruption_and_eviction(frozen):
    f, c = frozen, frozen.case
    await f.owner.ensure_payload(c.cohort, digest(f.sub))
    publication = certify(f.owner, c.cohort, f.sub, f.inputs, block=230)
    f.owner.publish(publication, capture_at(230))
    request = f.owner.review_request(c.cohort, digest(f.sub))
    source = f.sources.accepted(
        c.cohort, record=request.record, admission=request.admission, acceptance=request.acceptance
    )
    config = DirectModelReviewSourceConfig(
        schema="umi-direct-model-review-source/2",
        r2_credentials_file=str(f.root / "unused-credentials"),
        r2_bucket=f.remote.signer.bucket,
        maximum_materialized_bytes=1024**2,
        materialization_free_space_reserve_bytes=64 * 1024**2,
        materialization_protected_roots=(str(f.owner.archive),),
        materialization_boot_disk_cache=BootDiskModelCacheConfig(
            schema="umi-boot-disk-model-cache/1",
            directory=str(f.root / "cache"),
            maximum_allocated_bytes=2 * 1024**2,
        ),
        standing_review_policy=StandingModelReviewPolicy(
            schema="umi-standing-model-artifact-review-policy/1",
            competition_policy_sha256=digest(c.policy),
            contribution_terms_sha256=c.policy.contribution_terms_sha256,
            standing_approval_record_sha256="ef" * 32,
            approved_by="fixture@example.test",
            approved_at_utc="2026-10-02T12:00:00Z",
            complete_declared_bundle_rights_approved=True,
            licenses_and_notices_reviewed=True,
            public_redistribution_and_evaluation_approved=True,
        ),
    )

    def cache():
        artifacts = DirectModelArtifactReviewer(
            config,
            c.policy,
            None,
            multipart=f.remote,
            verification_root=f.sources.verification_root,
        )
        return LegacyCohortModelCache(artifacts, f.sources)

    archive = f.root / "cache" / "archive"
    f.remote.fail = "chunks/sha256/" + f.sub.model_bundle.files[-1].sha256
    with pytest.raises(OSError, match="interrupted"):
        await cache().materialize(source, archive)
    assert await cache().resumable(source, archive)
    reads = tuple(f.remote.reads)
    f.remote.fail = None
    await cache().materialize(source, archive)
    assert len(f.remote.reads) == len(reads) + 1
    assert verify_preserved_bundle(f.sub.model_bundle, archive, c.policy) == f.sub.model_revision
    assert await cache().materialized(source, archive)
    # Synthetic consumer is released; delete only this test's disposable cache.
    shutil.rmtree(archive)
    await cache().materialize(source, archive)
    assert verify_preserved_bundle(f.sub.model_bundle, archive, c.policy) == f.sub.model_revision
    reads = tuple(f.remote.reads)
    await f.create()[0].ensure_payload(c.cohort, digest(f.sub))
    assert tuple(f.remote.reads) == reads


async def test_worker_independent_review_and_lost_ack_preserve_originals(frozen):
    f, c = frozen, frozen.case

    async def capture():
        return capture_at(230)

    async def history(cohort):
        return CohortAdmissionQueue(f.owner.intake).history(cohort)

    peers = []
    for name in ("Charlie", "Dave"):
        config = ModelReviewConfig(
            schema="umi-cohort-model-review-config/1",
            directory=str(f.root / (name + "-journal")),
            approvals_directory=str(f.root / (name + "-approvals")),
            archive_directory=str(f.owner.archive),
            policy_sha256=digest(c.policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=f.owner.intake.config.cohorts,
        )
        publish_private_model(
            Path(config.approvals_directory) / (f.sub.model_revision + ".json"), f.inputs
        )

        async def sign(body, name=name):
            return sign_object(body, wallet(name))

        independent_sources = LegacyModelStorageReaders(
            f.sources.authenticated,
            policy=c.policy,
            load_original=c.objects.__getitem__,
            multipart=f.remote,
            verification_root=f.root / (name + "-verification"),
        )
        reviewer = ModelArtifactReviewer(
            config, c.policy, capture, history, sign, legacy_readers=independent_sources
        )
        peers.append(
            SimpleNamespace(
                policy=c.policy,
                cohorts=config.cohorts,
                signer=config.signer,
                attest=reviewer.attest,
            )
        )
    inputs, output = f.root / "inputs", f.root / "output"
    publish_private_model(inputs / "model-reviews" / (f.sub.model_revision + ".json"), f.inputs)
    worker = ModelAcceptanceWorker(f.owner, capture, inputs, output, reviewers=peers)
    await worker._one(c.cohort, f.sub)
    publication = f.owner.retained(c.cohort, digest(f.sub))
    assert len(publication.certificate.signatures) == 2
    assert publication.certificate.acceptance.direct_artifact is None
    reads = tuple(f.remote.reads)

    async def offline():
        raise AssertionError("completed publication must recover without finality or review")

    f.remote.objects.clear()
    await ModelAcceptanceWorker(f.create()[0], offline, inputs, output)._one(c.cohort, f.sub)
    assert tuple(f.remote.reads) == reads
    raw = (output / "model-reward-preparation" / c.cohort / (digest(f.sub) + ".json")).read_bytes()
    assert json.loads(raw)["acceptance"]["accepted_ordinal"] == 1


async def test_owned_remote_retry_reauthenticates_original_and_reads_only_requested_file(frozen):
    f = frozen
    request = f.case.requests[0]
    payloads = f.owner.legacy_payloads
    await payloads.ensure_owned(request)
    payloads.require_owned_payload(request)
    file = request.signed_submission.submission.model_bundle.files[0]
    raw = f.remote.objects["chunks/sha256/" + file.sha256]
    f.remote.reads.clear()
    await payloads.compare_retry(request, file_index=0, offset=0, data=raw)
    assert f.remote.reads == ["chunks/sha256/" + file.sha256]
    assert not (f.owner.archive / f.sub.model_revision).exists()
    # A fresh owner reconstructs its snapshot using persistent file results.
    restarted, _ = f.create()
    f.remote.reads.clear()
    await restarted.legacy_payloads.ensure_owned(request)
    restarted.legacy_payloads.require_owned_payload(request)
    assert not f.remote.reads


@pytest.mark.parametrize("failure", ["bytes", "generation", "owner_changed", "owner_refused"])
async def test_owned_remote_retry_failure_revokes_process_capability(frozen, monkeypatch, failure):
    f = frozen
    request = f.case.requests[0]
    payloads = f.owner.legacy_payloads
    await payloads.ensure_owned(request)
    file = request.signed_submission.submission.model_bundle.files[0]
    key = "chunks/sha256/" + file.sha256
    data = f.remote.objects[key]
    if failure == "bytes":
        data = bytes([data[0] ^ 1]) + data[1:]
    elif failure == "generation":
        f.remote.etags[key] = "changed-generation"
    else:
        original = payloads.owned_original
        calls = 0

        def changed(request):
            nonlocal calls
            calls += 1
            if failure == "owner_refused":
                raise ValueError("fixture original no longer authenticated")
            value = original(request)
            return value if calls == 1 else ("changed-tip", *value[1:])

        monkeypatch.setattr(payloads, "owned_original", changed)
    f.remote.reads.clear()
    with pytest.raises((OSError, ValueError)):
        await payloads.compare_retry(request, file_index=0, offset=0, data=data)
    assert digest(request) not in payloads.verified
    assert not (f.owner.archive / f.sub.model_revision).exists()
    if failure in {"generation", "owner_refused"}:
        assert not f.remote.reads


@pytest.mark.parametrize("failure", ["changed", "refused", "cancelled"])
async def test_owned_remote_verification_refuses_history_change_before_publication(
    frozen, monkeypatch, failure
):
    f = frozen
    request = f.case.requests[0]
    payloads = f.owner.legacy_payloads
    original = payloads.owned_original
    calls = 0

    def changed(request):
        nonlocal calls
        calls += 1
        value = original(request)
        if calls > 1 and failure == "refused":
            raise ValueError("fixture post-verification owner refusal")
        if calls > 1 and failure == "cancelled":
            raise asyncio.CancelledError("fixture post-verification cancellation")
        return value if calls == 1 else ("changed-tip", *value[1:])

    monkeypatch.setattr(payloads, "owned_original", changed)
    with pytest.raises((OSError, ValueError, asyncio.CancelledError)):
        await payloads.ensure_owned(request)
    assert digest(request) not in payloads.verified
