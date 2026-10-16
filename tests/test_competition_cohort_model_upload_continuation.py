"""Native unchanged-request continuation; finality and R2 are fixture ports."""

import asyncio
import hashlib
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_client import CompetitionSubmissionError
from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
)
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
)
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_legacy_model_admission import LegacyModelAdmissionPayloads
from umi.competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from umi.competition_cohort_legacy_model_storage import (
    LegacyModelOriginals,
    LegacyModelPreservationInventory,
    LegacyModelStorageInventory,
    authenticate_legacy_storage_inventories,
    verify_legacy_storage_originals,
)
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_cohort_model_acceptance_store import CohortModelAcceptances
from umi.competition_cohort_model_client import submit_cohort_model
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_model_transport_selection import CommittedModelDeliveryHistory
from umi.competition_cohort_model_upload import CohortModelUploads, authorize_model_delivery
from umi.competition_cohort_model_upload_continuation import verify_upload_continuation
from umi.competition_cohort_model_upload_delivery import ModelUploadDelivery
from umi.competition_cohort_model_upload_http import model_upload_routes
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_cohort_service_host import CohortModelPayloadRouter
from umi.open_competition import digest, sign_object, verify_signature
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_direct_model_client import Multipart
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_legacy_model_storage import BUCKET, ENDPOINT, backup, retain
from .test_competition_cohort_model_acceptance import certify
from .test_competition_cohort_model_client import direct_profile
from .test_competition_cohort_model_upload import base_policy as base_policy
from .test_competition_cohort_model_upload import delivery as delivery
from .test_competition_cohort_model_upload import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_upload import policy as policy
from .test_competition_cohort_model_upload import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_upload import recovery as recovery
from .test_competition_cohort_model_upload import runtime as runtime
from .test_competition_cohort_model_upload import signed_chunk, standing_review_policy, upload_all
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import bundle_at, wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def continuation(delivery, tmp_path, monkeypatch, request):
    h, state = delivery, getattr(request, "param", "incomplete")
    monkeypatch.setenv("UMI_MODEL_VERIFICATION_DIRECTORY", str(tmp_path / "client-verification"))
    key = h.owner.reserve(h.request, capture_at(210))
    bundle = h.request.signed_submission.submission.model_bundle
    if state == "incomplete":
        first = bundle.files[0]
        data = (h.source / first.path).read_bytes()[: max(1, first.size_bytes // 2)]
        h.owner.put_chunk(*signed_chunk(key, 0, data), data)
    else:
        upload_all(h, h.owner, key)
    objects = {}
    participation = None
    if state == "uncertified":
        h.intake.retain(h.request, capture_at(210))
        participation = retain(
            objects,
            CohortAdmissionQueue(h.intake).record(h.cohort, digest(h.request.consent.consent)),
        )
    baseline = bundle_at(tmp_path / "baseline", "baseline")
    history = h.intake.history(h.cohort)
    common = dict(
        cohort_sha256=h.cohort,
        policy_sha256=digest(h.intake.policy),
        authority_sha256=digest(history.authority.authority),
        predecessor_sha256=history_tip(history),
    )
    legacy = LegacyModelStorageInventory(
        schema="umi-cohort-legacy-model-storage-inventory/1",
        **common,
        captured_at_block=210,
        baseline_model_sha256=digest(baseline),
        baseline_manifest_raw_sha256=retain(objects, baseline),
        entries=(
            LegacyModelOriginals(
                request_sha256=key,
                request_raw_sha256=retain(objects, h.request),
                model_sha256=digest(bundle),
                payload_state="incomplete_upload" if state == "incomplete" else "preserved",
                participation_raw_sha256=participation,
            ),
        ),
    )
    models = [backup(objects, baseline, h.intake.policy)]
    if state != "incomplete":
        models.append(backup(objects, bundle, h.intake.policy))
    preservation = LegacyModelPreservationInventory(
        schema="umi-cohort-legacy-model-preservation-inventory/1",
        **common,
        legacy_inventory_sha256=digest(legacy),
        models=tuple(sorted(models, key=lambda value: value.model_sha256)),
    )
    profile = direct_profile()
    proposal = prepare_model_delivery_adoption(
        history,
        h.intake.policy,
        expected_tip_sha256=history_tip(history),
        current_block=211,
        delivery=profile,
        legacy_inventory_sha256=digest(legacy),
        preservation_inventory_sha256=digest(preservation),
    )
    adopted = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(proposal))}
    )
    h.intake.publish(adopted, capture_at(211))
    selection = CommittedModelDeliveryHistory(
        schema="umi-committed-model-delivery-history/1",
        history=adopted,
        committed_tip_sha256=history_tip(adopted),
        observed_at_block=211,
    )
    authenticated = authenticate_legacy_storage_inventories(
        canonical_json_bytes(legacy),
        canonical_json_bytes(preservation),
        selection=selection,
        policy=h.intake.policy,
        expected_baseline_sha256=digest(baseline),
    )
    verify_legacy_storage_originals(
        authenticated, load_original=objects.__getitem__, endpoint=ENDPOINT, bucket=BUCKET
    )
    multipart = Multipart()
    sources = LegacyModelStorageReaders(
        {h.cohort: authenticated},
        policy=h.intake.policy,
        load_original=objects.__getitem__,
        multipart=multipart,
        verification_root=tmp_path / "legacy-verification",
    )
    direct_config = DirectModelUploadOwnerConfig(
        schema="umi-direct-model-upload-owner-config/1",
        directory=str(tmp_path / "direct"),
        cohort_sha256=h.cohort,
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        delivery=profile,
        maximum_uploads=8,
        attempt_lease_seconds=30,
        admission_reviews_directory=str(tmp_path / "reviews"),
        standing_review_policy=standing_review_policy(h),
    )

    async def capture():
        return capture_at(212)

    async def authorize(original):
        authorize_model_delivery(
            h.intake, original, await capture(), mechanism="direct_r2_multipart_v1"
        )

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    def start():
        h.owner = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
        remote = LegacyModelAdmissionPayloads(h.intake, sources)
        direct = DirectModelUploadOwner(
            direct_config,
            multipart,
            authorize=authorize,
            sign=sign,
            policy=h.intake.policy,
            new_attempt_id=lambda: "ab" * 32,
        )
        router = CohortModelPayloadRouter(
            (history.plan,), legacy=h.owner, direct=direct, intake=h.intake, legacy_payloads=remote
        )
        app = FastAPI()
        app.include_router(
            cohort_routes(h.intake, capture, maximum_body_bytes=4 * 1024**2, models=router)
        )
        app.include_router(model_upload_routes(h.owner, capture, remote_payloads=remote))
        app.include_router(
            direct_model_upload_routes(direct, now_unix_ms=lambda: 1_800_000_000_000)
        )
        return SimpleNamespace(remote=remote, direct=direct, router=router, app=app)

    return SimpleNamespace(
        h=h,
        key=key,
        legacy=legacy,
        preservation=preservation,
        sources=sources,
        multipart=multipart,
        start=start,
        profile=profile,
    )


@pytest.mark.parametrize("continuation", ["incomplete", "preserved", "uncertified"], indirect=True)
async def test_unchanged_legacy_original_completes_as_native_direct_upload(continuation):
    f, h = continuation, continuation.h
    original = canonical_json_bytes(h.request)
    inventory_bytes = canonical_json_bytes(f.legacy), canonical_json_bytes(f.preservation)
    allocation, before = h.owner.allocations.snapshot(), h.owner.status(f.key)
    initial_plan = canonical_json_bytes(h.intake.history(h.cohort).plan)
    receipts, state = [], f.start()
    first = asyncio.Event()
    interrupted = False
    declarations = []
    events, proof_busy = [], True

    async def upload(wire):
        nonlocal interrupted
        data = await wire.aread()
        number = int(wire.url.params["partNumber"])
        f.multipart.parts[number] = data
        if not interrupted:
            interrupted = True
            first.set()
            await asyncio.Event().wait()  # R2 commits a part before the miner loses its reply.
        return httpx.Response(
            200, headers={"ETag": hashlib.md5(data, usedforsecurity=False).hexdigest()}
        )

    def arguments(state):
        native = httpx.ASGITransport(state.app)

        async def send(wire):
            nonlocal proof_busy
            if wire.url.path.endswith("/continuation") and proof_busy:
                proof_busy = False
                return httpx.Response(503)
            if wire.method == "POST" and wire.url.path.endswith("direct-model-uploads"):
                from umi.competition_cohort_direct_model_upload import (
                    DirectModelUploadReservationRequest,
                )

                declared = DirectModelUploadReservationRequest.model_validate_json(wire.content)
                assert canonical_json_bytes(declared.request) == original
                verify_signature(declared.payload.payload, declared.payload.signature)
                assert (
                    declared.payload.signature.hotkey
                    == h.request.signed_submission.submission.hotkey
                )
                # sr25519 may sign the same declaration with different valid bytes.
                declarations.append(canonical_json_bytes(declared.payload.payload))
            assert not (wire.method == "PUT" and "/model-uploads/" in wire.url.path)
            return await native.handle_async_request(wire)

        return dict(
            origin="https://intake.example",
            policy=h.intake.policy,
            request=h.request,
            source=h.source,
            wallet=wallet("Alice"),
            transport=httpx.MockTransport(send),
            object_transport=httpx.MockTransport(upload),
            retry_seconds=0.001,
            report=events.append,
        )

    task = asyncio.create_task(submit_cohort_model(**arguments(state)))
    reached_part = asyncio.create_task(first.wait())
    try:
        done, _ = await asyncio.wait(
            (task, reached_part), timeout=20, return_when=asyncio.FIRST_COMPLETED
        )
        if task in done:
            await task  # Surface failures before R2 instead of masking them as timeouts.
        assert reached_part in done
    finally:
        reached_part.cancel()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await reached_part
        with suppress(asyncio.CancelledError):
            await task
    assert h.owner.journal.get_raw("upload", f.key) == original
    for _ in range(2):
        state = f.start()

        async def verify(state=state):
            while True:
                await state.direct.poll_once(now_unix_ms=1_800_000_000_000)
                await asyncio.sleep(0.005)

        worker = asyncio.create_task(verify())
        try:
            receipts.append(await asyncio.wait_for(submit_cohort_model(**arguments(state)), 20))
        finally:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
        assert h.owner.journal.get_raw("upload", f.key) == original
        assert h.owner.allocations.snapshot() == allocation
        assert h.owner.status(f.key) == before
        assert (
            canonical_json_bytes(f.legacy),
            canonical_json_bytes(f.preservation),
        ) == inventory_bytes
        assert canonical_json_bytes(h.intake.history(h.cohort).plan) == initial_plan
    assert receipts[0] == receipts[1] and f.multipart.creates == 1
    assert len(set(declarations)) == 1
    progress = [row for row in events if row.get("stage") == "model_upload_continuation"]
    assert any(row["status"] == "retrying" and row["eta_seconds"] is None for row in progress)
    assert sum(row["status"] == "completed" for row in progress) == 3
    queue = CohortAdmissionQueue(h.intake)
    for name in ("Charlie", "Dave"):
        queue.publish_vote(
            CohortAdmissionVote(
                admission=receipts[0].proposed_admission,
                signature=sign_object(receipts[0].proposed_admission, wallet(name)),
            ),
            capture_at(213),
        )
    acceptance = CohortModelAcceptances(
        h.intake,
        h.owner.archive,
        verify_request=state.router.require_payload,
        review_artifact=state.router.review_artifact,
        legacy_payloads=state.remote,
    )
    sub = h.request.signed_submission.submission
    inputs = read_private_model(
        Path(state.direct.config.admission_reviews_directory) / (sub.model_revision + ".json"),
        ModelArtifactReviewInputs,
        maximum_bytes=33 * 1024**2,
    )
    publication = certify(acceptance, h.cohort, sub, inputs, block=214)
    assert publication.certificate.acceptance.schema_ == "umi-cohort-model-artifact-acceptance/2"
    acceptance.publish(publication, capture_at(215))
    assert acceptance.retained(h.cohort, digest(sub)) == publication
    review = acceptance.review_request(h.cohort, digest(sub))
    reviewer = DirectModelArtifactReviewer(
        DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/2",
            r2_credentials_file=str(h.owner.root / "unused-fixture-credentials"),
            r2_bucket="umi-model-artifacts",
            materialization_protected_roots=(str(h.owner.root),),
            standing_review_policy=state.direct.config.standing_review_policy,
        ),
        h.intake.policy,
        state.direct.config.owner_hotkey,
        multipart=f.multipart,
        verification_root=h.owner.root / "independent-review",
    )
    assert await reviewer.review(review) == inputs
    state = f.start()
    assert await asyncio.wait_for(submit_cohort_model(**arguments(state)), 20) == receipts[0]
    reopened = CohortModelAcceptances(h.intake, h.owner.archive)
    assert reopened.review_request(h.cohort, digest(sub)) == review
    assert reopened.export(h.cohort, digest(sub), h.owner.root / "export") == publication
    assert h.owner.allocations.snapshot() == allocation
    assert f.multipart.creates == 1
    assert canonical_json_bytes(h.request) == original


async def test_pending_owner_decision_cannot_export_a_continuation(continuation):
    f, h = continuation, continuation.h
    state = f.start()
    original = h.owner.journal.get_raw("upload", f.key)
    allocation = h.owner.allocations.snapshot()
    with h.intake._connection() as (_, store):
        pending = store.reserve(
            h.cohort,
            phase="intake",
            operation="revoke",
            observed_at_block=212,
            evidence_sha256="fa" * 32,
        )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(state.app), base_url="https://intake.example"
    ) as client:
        response = await client.get(f"/v1/competition/model-uploads/{f.key}/continuation")
    assert response.status_code == 503
    with h.intake._connection() as (_, store):
        assert store.status(h.cohort)[1] == pending
    assert h.owner.journal.get_raw("upload", f.key) == original
    assert h.owner.allocations.snapshot() == allocation
    assert f.multipart.creates == 0


@pytest.mark.parametrize(
    "fault",
    ["request", "inventory", "profile", "signature", "certified", "missing_original", "authority"],
)
async def test_untrusted_continuation_never_creates_direct_reservation(continuation, fault):
    f, h = continuation, continuation.h
    state = f.start()
    value = ModelUploadDelivery(h.owner, remote_payloads=state.remote).continuation(f.key)
    assert verify_upload_continuation(value, h.request, h.intake.policy) == f.profile
    if fault == "authority":
        # Independently valid quorum history for the same immutable plan must
        # not change the authority explicitly named in this original consent.
        history = value.selection.history
        authority = history.authority.authority.model_copy(
            update={"issued_at_block": history.authority.authority.issued_at_block - 1}
        )
        signed = SignedCohortRecoveryAuthority(
            authority=authority, signatures=signatures(authority)
        )
        genesis, _ = admit_recoverable_cohort(
            history.plan,
            signed,
            h.intake.policy,
            admitted_at_block=history.genesis.admitted_at_block,
        )
        alternate = history.model_copy(
            update={
                "authority": signed,
                "genesis": genesis,
                "genesis_signatures": signatures(genesis),
                "transitions": (),
            }
        )
        legacy = value.legacy_inventory.model_copy(
            update={
                "authority_sha256": digest(authority),
                "predecessor_sha256": digest(genesis),
            }
        )
        preservation = f.preservation.model_copy(
            update={
                "authority_sha256": digest(authority),
                "predecessor_sha256": digest(genesis),
                "legacy_inventory_sha256": digest(legacy),
            }
        )
        proposal = prepare_model_delivery_adoption(
            alternate,
            h.intake.policy,
            expected_tip_sha256=digest(genesis),
            current_block=211,
            delivery=f.profile,
            legacy_inventory_sha256=digest(legacy),
            preservation_inventory_sha256=digest(preservation),
        )
        alternate = alternate.model_copy(update={"transitions": (signed_transition(proposal),)})
        verify_cohort_history(
            alternate, h.intake.policy, expected_tip_sha256=digest(proposal), current_block=211
        )
        assert canonical_json_bytes(alternate.plan) == canonical_json_bytes(history.plan)
        value = value.model_copy(
            update={
                "selection": value.selection.model_copy(
                    update={
                        "history": alternate,
                        "committed_tip_sha256": digest(proposal),
                    }
                ),
                "legacy_inventory": legacy,
            }
        )
    data = value.model_dump(mode="json", by_alias=True)
    if fault == "request":
        data["request_sha256"] = "ff" * 32
    elif fault == "inventory":
        data["legacy_inventory"]["captured_at_block"] += 1
    elif fault == "profile":
        data["selection"]["history"]["transitions"][-1]["transition"]["model_delivery_adoption"][
            "delivery"
        ]["part_size_bytes"] *= 2
    elif fault == "signature":
        data["selection"]["history"]["transitions"][-1]["signatures"] = []
    elif fault == "certified":
        data["legacy_inventory"]["entries"][0]["admission_raw_sha256"] = "ff" * 32
    elif fault == "missing_original":
        data["legacy_inventory"]["entries"] = []
    native = httpx.ASGITransport(state.app)

    async def send(wire):
        assert "direct-model-uploads" not in wire.url.path
        if wire.url.path.endswith("continuation"):
            return httpx.Response(200, json=data)
        return await native.handle_async_request(wire)

    with pytest.raises(CompetitionSubmissionError, match="invalid_model_upload_continuation"):
        await submit_cohort_model(
            origin="https://intake.example",
            policy=h.intake.policy,
            request=h.request,
            source=h.source,
            wallet=wallet("Alice"),
            transport=httpx.MockTransport(send),
        )
    assert f.multipart.creates == 0
