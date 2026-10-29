"""Real reviewer checkpoints, one batch signature, and bounded parallel work."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_intake_export import IntakeReviewExporter, replay_intake_export
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_intake_review import NativeIntakeProgressSource
from umi.competition_cohort_model_acceptance import (
    ModelAcceptanceBatchManifest,
    ModelAcceptancePublication,
    model_acceptance_batch_certificates,
)
from umi.competition_cohort_model_batch import (
    CertifiedModelAcceptanceBatch,
    SignedModelBatchCertificationAdoption,
    build_model_acceptance_batch,
    prepare_model_batch_certification_adoption,
)
from umi.competition_cohort_model_batch_review import (
    ModelBatchReviewRequest,
    model_batch_candidate_snapshot,
)
from umi.competition_cohort_model_review_http import (
    BATCH_VOTE_PATH,
    ModelReviewPeer,
    model_review_routes,
)
from umi.competition_cohort_public_results import PublicModelInventory, project_models
from umi.competition_cohort_recovery import (
    CohortEvaluationSuiteAdoption,
    propose_recovery_transition,
)
from umi.competition_cohort_roster import RecoverableRosterParticipant
from umi.open_competition import digest
from umi.private_files import publish_private_model

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import observe
from .test_competition_cohort_model_review import base_policy as base_policy
from .test_competition_cohort_model_review import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_review import policy as policy
from .test_competition_cohort_model_review import prepared as prepared
from .test_competition_cohort_model_review import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_review import recovery as recovery
from .test_competition_cohort_model_review import reviews as reviews
from .test_competition_cohort_model_review import runtime as runtime
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def batch_reviews(reviews, tmp_path):
    r = reviews
    history, policy = r.owner.intake.history(r.cohort), r.owner.intake.policy
    adoption = prepare_model_batch_certification_adoption(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        effective_at_block=220,
    )
    signed = SignedModelBatchCertificationAdoption(
        adoption=adoption, signatures=signatures(adoption)
    )
    r.owner.prepare(r.cohort, digest(r.subs[1]), r.inputs, capture_at(220))
    requests = tuple(
        sorted(
            (r.owner.review_request(r.cohort, digest(s)) for s in r.subs),
            key=lambda request: request.acceptance.submission_sha256,
        )
    )
    batch = build_model_acceptance_batch(
        tuple(request.acceptance for request in requests),
        signed,
        history,
        policy,
        candidate_snapshot_sha256="11" * 32,
        roster_sha256=r.owner.certification_inventory(r.cohort)["roster_sha256"],
        certified_at_block=230,
    )
    batch = batch.model_copy(
        update={
            "candidate_snapshot_sha256": model_batch_candidate_snapshot(requests, batch),
        }
    )
    request = ModelBatchReviewRequest(batch=batch, adoption=signed, requests=requests)
    approvals = tmp_path / "batch-adoptions"
    publish_private_model(approvals / (r.cohort + ".json"), signed)

    def create(name="Charlie", concurrency=10):
        reviewer = r.create(name)
        reviewer.config = reviewer.config.model_copy(
            update={
                "batch_certification_adoptions_directory": str(approvals),
                "preparation_concurrency": concurrency,
            }
        )
        return reviewer

    return SimpleNamespace(original=r, request=request, create=create)


async def test_batch_prepares_models_concurrently_and_signs_once(batch_reviews, monkeypatch):
    r = batch_reviews
    reviewer = r.create()
    original = reviewer._review_inputs
    started = 0
    overlap = asyncio.Event()

    async def prepare(request, **kwargs):
        nonlocal started
        started += 1
        if started == 2:
            overlap.set()
        await asyncio.wait_for(overlap.wait(), 5)
        return await original(request, **kwargs)

    monkeypatch.setattr(reviewer, "_review_inputs", prepare)
    first = await reviewer.attest_batch(r.request)
    assert started == 2
    assert first.batch == r.request.batch
    assert len(r.original.state.signing) == 1
    assert r.original.state.signing[0][1] == r.request.batch
    r.original.state.online = False
    r.original.owner.archive.rename(r.original.owner.archive.with_name("offline-artifacts"))
    assert await r.create().attest_batch(r.request) == first
    assert len(r.original.state.signing) == 1


async def test_batch_partial_failure_reuses_successful_preparation(batch_reviews, monkeypatch):
    r = batch_reviews
    reviewer = r.create()
    original = reviewer._review_inputs
    failed_key = r.request.requests[0].acceptance.submission_sha256
    calls = []

    async def fail_one(request, **kwargs):
        key = request.acceptance.submission_sha256
        calls.append(key)
        if key == failed_key:
            raise OSError("injected unavailable object")
        return await original(request, **kwargs)

    monkeypatch.setattr(reviewer, "_review_inputs", fail_one)
    with pytest.raises(OSError, match="incomplete"):
        await reviewer.attest_batch(r.request)
    assert len(calls) == 2
    assert not r.original.state.signing
    restarted = r.create()
    original = restarted._review_inputs
    calls.clear()

    async def prepare(request, **kwargs):
        calls.append(request.acceptance.submission_sha256)
        return await original(request, **kwargs)

    monkeypatch.setattr(restarted, "_review_inputs", prepare)
    await restarted.attest_batch(r.request)
    assert calls == [failed_key]
    assert len(r.original.state.signing) == 1


async def test_batch_reuses_individual_review_without_payload_access(batch_reviews, monkeypatch):
    r = batch_reviews
    reviewer = r.create()
    for request in r.request.requests:
        await reviewer.attest(request)

    async def forbidden(*args, **kwargs):
        raise AssertionError("unchanged completed model must not be reread")

    monkeypatch.setattr(reviewer, "_review_inputs", forbidden)
    await reviewer.attest_batch(r.request)
    assert len(r.original.state.signing) == 3  # two old votes plus one cohort vote


async def test_batch_requires_selected_adoption_before_work(batch_reviews):
    r = batch_reviews
    with pytest.raises(ValueError, match="adoption is not selected"):
        await r.original.create("Charlie").attest_batch(r.request)
    assert not r.original.state.signing


async def test_batch_route_requires_auth_and_rejects_wrong_signer(batch_reviews):
    r = batch_reviews
    token = "batch-secret" * 4
    app = FastAPI()
    app.include_router(model_review_routes(r.create(), token=token))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://review.example",
    ) as client:
        assert (await client.post(BATCH_VOTE_PATH, json={})).status_code == 401
        peer = ModelReviewPeer(
            client,
            "https://review.example",
            policy=r.original.owner.intake.policy,
            cohorts=r.original.owner.intake.config.cohorts,
            signer=wallet("Dave").hotkey.ss58_address,
            token=token,
        )
        with pytest.raises(ValueError, match="independent reviewer"):
            await peer.attest_batch(r.request)


async def test_batch_rejects_self_review_before_payload_io(batch_reviews, monkeypatch):
    r = batch_reviews
    reviewer = r.create()
    reviewer.config = reviewer.config.model_copy(
        update={
            "signer": r.request.requests[0].acceptance.recipient_hotkey,
        }
    )
    with pytest.raises(ValueError, match="own artifacts"):
        await reviewer.attest_batch(r.request)
    assert not r.original.state.signing


async def test_cancelled_batch_drains_workers_and_reuses_checkpoints(batch_reviews, monkeypatch):
    r = batch_reviews
    reviewer = r.create()
    entered, release = asyncio.Event(), asyncio.Event()
    original = reviewer._review_inputs

    async def prepare(request, **kwargs):
        entered.set()
        await release.wait()
        return await original(request, **kwargs)

    monkeypatch.setattr(reviewer, "_review_inputs", prepare)
    task = asyncio.create_task(reviewer.attest_batch(r.request))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not r.original.state.signing
    restarted = r.create()

    async def forbidden(*args, **kwargs):
        raise AssertionError("completed preparation was lost on caller cancellation")

    monkeypatch.setattr(restarted, "_review_inputs", forbidden)
    await restarted.attest_batch(r.request)
    assert len(r.original.state.signing) == 1


async def test_parallel_artifact_slots_are_bounded_keyed_and_released(receipt_scenario):
    from umi.competition_cohort_direct_model_review import DirectModelArtifactReviewer

    reviewer = object.__new__(DirectModelArtifactReviewer)
    reviewer.verification_slots = asyncio.Semaphore(2)
    reviewer._verification_locks = {}
    release = asyncio.Event()
    active, entered, peak = set(), [], 0

    async def check(key):
        nonlocal peak
        async with reviewer._verification_slot(key):
            assert key not in active
            active.add(key)
            entered.append(key)
            peak = max(peak, len(active))
            try:
                await release.wait()
            finally:
                active.remove(key)

    tasks = [asyncio.create_task(check(key)) for key in ("a", "a", "b", "c")]
    for _ in range(10):
        await asyncio.sleep(0)
    assert entered == ["a", "b"]
    tasks[1].cancel()
    with pytest.raises(asyncio.CancelledError):
        await tasks[1]
    release.set()
    await asyncio.gather(tasks[0], *tasks[2:])
    assert peak == 2
    assert not reviewer._verification_locks


def test_public_catalog_accepts_later_batch_clock_without_changing_model_body(batch_reviews):
    r = batch_reviews
    certificate = CertifiedModelAcceptanceBatch(
        batch=r.request.batch,
        adoption=r.request.adoption,
        signatures=signatures(r.request.batch),
    )
    manifest = ModelAcceptanceBatchManifest(
        schema="umi-cohort-model-acceptance-manifest/1",
        certificate=certificate,
        acceptances=tuple(item.acceptance for item in r.request.requests),
    )
    inventory = PublicModelInventory(
        schema="umi-native-public-model-inventory/1",
        scope="all_admitted_model_submissions",
        policy=r.original.owner.intake.policy,
        history=r.original.owner.intake.history(r.original.cohort),
        participants=tuple(
            RecoverableRosterParticipant(record=item.record, admission=item.admission)
            for item in r.request.requests
        ),
        acceptances=model_acceptance_batch_certificates(manifest),
    )
    catalog, _ = project_models(inventory)
    assert len(catalog.items) == 2
    assert all(item.acceptance_sha256 is not None for item in catalog.items)


def test_batch_memberships_survive_native_seal_export_and_independent_replay(batch_reviews):
    r = batch_reviews
    owner, cohort = r.original.owner, r.original.cohort
    manifest = ModelAcceptanceBatchManifest(
        schema="umi-cohort-model-acceptance-manifest/1",
        certificate=CertifiedModelAcceptanceBatch(
            batch=r.request.batch,
            adoption=r.request.adoption,
            signatures=signatures(r.request.batch),
        ),
        acceptances=tuple(item.acceptance for item in r.request.requests),
    )
    for certificate in model_acceptance_batch_certificates(manifest):
        owner.publish(
            ModelAcceptancePublication(certificate=certificate, inputs=r.original.inputs),
            capture_at(230),
        )
    phase = CohortIntakePhaseObserver(owner.intake)
    for block in range(200, 301, 5):
        result = observe(phase, cohort, block)
    exporter = IntakeReviewExporter(
        NativeIntakeProgressSource(owner.intake),
        wallet("Charlie").hotkey.ss58_address,
        None,
    )
    exported = exporter.export(result.progress)
    assert len(exported.model_acceptances) == 2
    assert all(c.batch_proof is not None for c in exported.model_acceptances)
    replay_intake_export(exported, owner.intake.policy, maximum_sample_gap_blocks=10)


async def test_reviewer_reuses_preparation_after_authenticated_intake_amendment(batch_reviews):
    r = batch_reviews
    reviewer = r.create()

    async def unavailable(_):
        raise OSError("signer temporarily unavailable")

    reviewer.sign = unavailable
    with pytest.raises(OSError, match="signer temporarily"):
        await reviewer.attest_batch(r.request)
    owner, cohort = r.original.owner, r.original.cohort
    history = owner.intake.history(cohort)
    with owner.intake._connection() as (_, store):
        state, _ = store.status(cohort)
    suite = CohortEvaluationSuiteAdoption(
        schema="umi-cohort-evaluation-suite-adoption/1",
        original_plan=history.plan,
        previous_suite_sha256=history.plan.suite_sha256,
        suite_sha256="4a" * 32,
        selection_manifest_sha256="4b" * 32,
    )
    amendment = propose_recovery_transition(
        state,
        history.authority.authority,
        operation="adopt_evaluation_suite",
        observed_at_block=240,
        evidence_sha256=digest(suite),
        evaluation_suite_adoption=suite,
    )
    owner.intake.publish(
        history.model_copy(
            update={
                "transitions": (*history.transitions, signed_transition(amendment)),
            }
        ),
        capture_at(240),
    )
    r.original.state.block = 250
    restarted = r.create()

    async def forbidden(*args, **kwargs):
        raise AssertionError("authenticated history extension must reuse completed model checks")

    restarted._review_inputs = forbidden
    vote = await restarted.attest_batch(r.request)
    assert vote.batch == r.request.batch
    assert len(r.original.state.signing) == 1
