"""Native round reconstruction and separate promotion review over private HTTP."""

from __future__ import annotations

import asyncio
import sqlite3

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortRecoveryCoordinator,
    _choice,
    replay_cohort_decisions,
)
from umi.competition_cohort_intake import CohortIntakePublisher, history_tip
from umi.competition_cohort_intake_export import IntakeReviewRequest
from umi.competition_cohort_phase_vote_http import PhaseVotePeer, phase_vote_routes
from umi.competition_cohort_preparation_export import (
    PreparationReviewExporter,
    RemotePreparationProgressReviewer,
    SignedPreparationReviewResponse,
    replay_preparation_export,
)
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_phase import NativePreparationProgressSource
from umi.competition_cohort_preparation_review_http import (
    PATH,
    PreparationReviewHTTPClient,
    preparation_review_routes,
)
from umi.competition_cohort_progress_signer import (
    CertifiedPhaseObserver,
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_execution import execution_boundary
from umi.competition_store import CompetitionStore
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_queue import relay as relay
from .test_competition_cohort_admission_queue import submit
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_admission_signer import closed_source
from .test_competition_cohort_admission_signer import harness as harness
from .test_competition_cohort_consumers import scenario as legacy_scenario  # noqa: F401
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_lifecycle import scenario as standing_scenario  # noqa: F401
from .test_competition_cohort_preparation import preparation as preparation
from .test_competition_cohort_preparation_review import reviewed as reviewed
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_historical_registration import archive as archive
from .test_open_competition import bundle_at, wallet
from .test_open_competition import policy as policy


@pytest.fixture(params=["legacy", "standing"])
def scenario(request):
    return request.getfixturevalue(request.param + "_scenario")


@pytest.fixture
def remote(reviewed, tmp_path):
    h = reviewed
    h.owner_identity = wallet("Charlie").hotkey.ss58_address
    h.requests, h.remote_calls, h.remote_fail = [], [], False

    async def owner_sign(body):
        return sign_object(body, wallet("Charlie"))

    h.exporter = PreparationReviewExporter(h.source, h.owner_identity, owner_sign)
    h.exported = h.exporter.export(h.progress)
    h.peer_store = CompetitionStore(tmp_path / "peer-promotion", h.intake.policy)
    model = tmp_path / "peer-model"
    bundle = bundle_at(model)
    preserve_bundle(bundle, model, tmp_path / "peer-model-archive", h.intake.policy)
    h.peer_store.initialize_baseline(bundle, tmp_path / "peer-model-archive")
    assert h.peer_store.directory != h.store.directory

    async def fetch(request):
        h.requests.append(request)
        if h.offline:
            raise OSError("owner unavailable")
        return await h.exporter.respond(request)

    async def archive(observation):
        return b"proof", b"metadata"

    h.remote = RemotePreparationProgressReviewer(
        h.provider, h.intake.config.cohorts, h.owner_identity, fetch, archive, h.peer_store
    )

    def signer():
        async def sign(body):
            h.remote_calls.append(body)
            if h.remote_fail:
                raise OSError("signature reply lost")
            return sign_object(body, wallet("Dave"))

        config = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(tmp_path / "remote-signing"),
            policy_sha256=digest(h.intake.policy),
            signer=wallet("Dave").hotkey.ss58_address,
            cohorts=h.intake.config.cohorts,
        )
        return CohortProgressSigner(config, h.remote, sign)

    h.remote_signer = signer
    return h


async def test_remote_rebuilds_original_round_over_http_with_separate_promotion_store(remote):
    h = remote
    app = FastAPI()
    app.include_router(preparation_review_routes(h.exporter, token="private-test-token" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        h.remote.fetch = PreparationReviewHTTPClient(
            client, "https://owner.example", token="private-test-token" * 3
        )
        reviewed = await h.remote.review(h.progress)
        assert reviewed == h.source.read(h.progress).record
        assert len(h.exported.records) == 2 and len(h.prepared.roster.participants) == 1
        vote = await h.remote_signer().attest(h.progress)
    h.offline = True
    assert await h.remote_signer().attest(h.progress) == vote
    assert len(h.remote_calls) == 1


async def test_remote_signs_only_the_exact_native_transition(remote):
    h = remote
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(
            progress=h.progress, signatures=signatures(h.progress)
        ),
        observation=execution_boundary(capture_at(h.block)),
    )
    sources = {digest(h.closing): h.closing}
    state, restored, prior = replay_cohort_decisions(
        h.history, h.intake.policy, sources.__getitem__
    )
    body, _ = _choice(
        state, h.history.authority.authority, h.intake.policy, evidence, restored, prior
    )
    vote = await h.remote_signer().certify(body, evidence)
    assert len(h.requests) == 3
    h.offline = True
    assert await h.remote_signer().certify(body, evidence) == vote
    assert len(h.remote_calls) == 1


async def test_signature_retry_after_long_outage_uses_original_round_and_promotion(
    remote, monkeypatch
):
    h = remote
    h.remote_fail = True
    with pytest.raises(OSError, match="reply lost"):
        await h.remote_signer().attest(h.progress)
    h.block += 100_000
    h.remote_fail = False

    def new_head(*args, **kwargs):
        pytest.fail("retry tried to select a new promotion head")

    monkeypatch.setattr(h.peer_store, "reviewed_promotion_head", new_head)
    await h.remote_signer().attest(h.progress)
    assert h.remote_calls == [h.progress, h.progress]
    assert h.exporter.export(h.progress) == h.exported


@pytest.mark.parametrize("failure", ["missing", "corrupt", "tracks"])
async def test_independent_promotion_or_track_failure_blocks_signing(remote, failure):
    h = remote
    if failure == "tracks":
        h.remote.tracks = ("endpoint", "model")
    else:
        with h.peer_store._connection() as db:
            if failure == "missing":
                db.execute("DELETE FROM promotions")
            else:
                db.execute("UPDATE promotions SET body=?", (b"{}",))
    with pytest.raises(ValueError):
        await h.remote_signer().attest(h.progress)
    assert h.remote_calls == []


@pytest.mark.parametrize(
    "failure",
    [
        "inventory",
        "selected_only",
        "admission",
        "round",
        "observation",
        "promotion",
        "decision",
        "decision_duplicate",
    ],
)
def test_changed_originals_cannot_certify_a_smaller_or_different_round(remote, failure):
    h = remote
    value = h.exported
    if failure == "inventory":
        value = value.model_copy(update={"records": ()})
    elif failure == "selected_only":
        value = value.model_copy(
            update={
                "records": tuple(
                    r for r in value.records if r.request.signed_submission.submission.sequence == 2
                )
            }
        )
    elif failure in ("decision", "decision_duplicate"):
        value = value.model_copy(
            update={"decisions": () if failure == "decision" else value.decisions * 2}
        )
    elif failure == "observation":
        value = value.model_copy(
            update={
                "evidence": value.evidence.model_copy(
                    update={"observation": execution_boundary(capture_at(h.block + 1))}
                )
            }
        )
    elif failure == "promotion":
        promotion = value.prepared.promotion_head.model_copy(
            update={"contributor_hotkey": wallet("Alice").hotkey.ss58_address}
        )
        value = value.model_copy(
            update={"prepared": value.prepared.model_copy(update={"promotion_head": promotion})}
        )
    else:
        roster = value.prepared.roster
        if failure == "round":
            roster = roster.model_copy(
                update={"round": roster.round.model_copy(update={"runtime_sha256": "ab" * 32})}
            )
        else:
            participant = roster.participants[0]
            admission = participant.admission.model_copy(update={"signatures": ()})
            roster = roster.model_copy(
                update={"participants": (participant.model_copy(update={"admission": admission}),)}
            )
        value = value.model_copy(
            update={"prepared": value.prepared.model_copy(update={"roster": roster})}
        )
    with pytest.raises(ValueError):
        replay_preparation_export(
            value, h.intake.policy, h.prepared.promotion_head, eligible_tracks=("endpoint",)
        )


@pytest.mark.parametrize("failure", ["challenge", "owner", "authority", "progress", "canonical"])
async def test_untrusted_response_is_rejected_before_proof_or_promotion_review(
    remote, failure, monkeypatch
):
    h = remote

    async def fetch(request):
        raw = await h.exporter.respond(request)
        signed = SignedPreparationReviewResponse.model_validate_json(raw)
        response = signed.response
        if failure == "canonical":
            return raw + b" "
        if failure == "challenge":
            response = response.model_copy(update={"challenge": "ab" * 32})
        elif failure == "progress":
            exported = response.evidence.model_copy(
                update={
                    "progress": h.progress.model_copy(update={"observed_at_block": h.block + 1})
                }
            )
            response = response.model_copy(update={"evidence": exported})
        elif failure == "authority":
            history = response.evidence.history
            authority = history.authority.model_copy(
                update={
                    "authority": history.authority.authority.model_copy(
                        update={"issued_at_block": 1}
                    )
                }
            )
            exported = response.evidence.model_copy(
                update={"history": history.model_copy(update={"authority": authority})}
            )
            response = response.model_copy(update={"evidence": exported})
        return canonical_json_bytes(
            SignedPreparationReviewResponse(
                response=response,
                signature=sign_object(
                    response, wallet("Dave" if failure == "owner" else "Charlie")
                ),
            )
        )

    def forbidden(*args, **kwargs):
        pytest.fail("untrusted input reached local promotion history")

    h.remote.fetch = fetch
    monkeypatch.setattr(h.peer_store, "reviewed_promotion_at", forbidden)
    with pytest.raises(ValueError):
        await h.remote_signer().attest(h.progress)
    assert h.remote_calls == []


@pytest.mark.parametrize(
    "failure", ["proof", "revoked", "offline", "replayed_response", "promotion_changed"]
)
async def test_originals_are_rechecked_after_proof_review(remote, failure):
    h = remote
    fetch = h.remote.fetch
    saved = None

    async def old_response(request):
        nonlocal saved
        if saved is None:
            saved = await fetch(request)
        return saved

    if failure == "replayed_response":
        h.remote.fetch = old_response

    async def original(observation):
        if failure == "proof":
            return b"wrong proof", b"metadata"
        if failure == "revoked":
            history = transition(h.history, h.intake.policy, "revoke", 350)
            h.intake.publish(history, capture_at(350), decision_inputs=(h.closing,))
        if failure == "offline":
            h.offline = True
        if failure == "promotion_changed":
            with h.peer_store._connection() as db:
                db.execute("DELETE FROM promotions")
        return b"proof", b"metadata"

    h.remote.archive = original
    with pytest.raises((OSError, ValueError)):
        await h.remote_signer().attest(h.progress)
    assert h.remote_calls == []


async def test_incomplete_export_capacity_preserves_round_and_recovers(remote):
    h = remote
    h.exporter.maximum_bytes = 1024
    with pytest.raises(OSError, match="capacity"):
        await h.remote_signer().attest(h.progress)
    h.exporter.maximum_bytes = 64 * 1024**2
    assert h.exporter.export(h.progress) == h.exported
    await h.remote_signer().attest(h.progress)


async def test_private_route_rejects_cross_phase_request_before_owner_read(remote):
    h = remote
    app = FastAPI()
    app.include_router(preparation_review_routes(h.exporter, token="private-test-token" * 3))
    request = IntakeReviewRequest(
        schema="umi-intake-review-request/1", challenge="ab" * 32, progress=h.progress
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        result = await client.post(
            "https://owner.example" + PATH,
            content=canonical_json_bytes(request),
            headers={
                "authorization": "Bearer " + "private-test-token" * 3,
                "content-type": "application/json",
            },
        )
        assert result.status_code == 422
    assert h.remote_calls == []


async def test_remote_transport_cancel_drains_before_signer_releases_ownership(remote):
    h = remote
    entered, drained = asyncio.Event(), asyncio.Event()

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    h.remote.fetch = blocked
    task = asyncio.create_task(h.remote_signer().attest(h.progress))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert drained.is_set() and h.remote_calls == []


@pytest.mark.parametrize("damaged", [False, True])
async def test_separate_reviewer_replays_native_archives_with_owned_headers(
    relay, tmp_path, damaged
):
    h = relay
    await submit(h)
    await h.reviewer("Charlie").poll_once()
    await h.reviewer("Dave").poll_once()
    closed = closed_source(h)
    h.intake.seal(h.cohort, h.archive.capture, expected_tip_sha256=history_tip(h.source.history))
    capture = await h.archive.reviewer.collect()
    h.intake.publish(closed.history, capture, closure_input=closed.closure)
    model = tmp_path / "shared-model"
    bundle = bundle_at(model)
    model_archive = tmp_path / "preserved-model"
    preserve_bundle(bundle, model, model_archive, h.intake.policy)
    owner_store, peer_store = [
        CompetitionStore(tmp_path / name, h.intake.policy)
        for name in ("owner-promotion", "peer-promotion")
    ]
    for store in (owner_store, peer_store):
        store.initialize_baseline(bundle, model_archive)
    source = NativePreparationProgressSource(CohortPreparation(h.queue, owner_store))
    with h.queue._connection() as (_, store):
        state, _ = store.status(h.cohort)
    progress = source.observe(state, capture)

    async def owner_sign(body):
        return sign_object(body, wallet("Charlie"))

    exporter = PreparationReviewExporter(source, wallet("Charlie").hotkey.ss58_address, owner_sign)

    async def original(observation):
        raw, metadata = await h.archive.reviewer.retained_archive(observation)
        return raw, b"changed" if damaged else metadata

    app = FastAPI()
    app.include_router(preparation_review_routes(exporter, token="private-test-token" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        fetch = PreparationReviewHTTPClient(
            client, "https://owner.example", token="private-test-token" * 3
        )
        reviewer = RemotePreparationProgressReviewer(
            h.archive.reviewer,
            h.intake.config.cohorts,
            wallet("Charlie").hotkey.ss58_address,
            fetch,
            original,
            peer_store,
        )
        before = len(h.archive.chain.verifier.checked)
        if damaged:
            with pytest.raises(ValueError):
                await reviewer.review(progress)
        else:
            reviewed = await reviewer.review(progress)
            assert reviewed == source.read(progress).record
            assert len(h.archive.chain.verifier.checked) > before


async def test_native_controller_recovers_remote_http_quorum_after_long_outage(remote, tmp_path):
    h = remote
    owner_app, peer_app = FastAPI(), FastAPI()
    owner_app.include_router(preparation_review_routes(h.exporter, token="owner-private-token" * 3))
    peer_app.include_router(
        phase_vote_routes(h.remote_signer(), phase="preparation", token="peer-private-token" * 3)
    )
    db = sqlite3.connect(tmp_path / "remote-control.sqlite3")
    store = CohortRecoveryStore(db)
    store.admit(
        h.history.plan,
        h.history.authority,
        h.intake.policy,
        admitted_at_block=h.history.genesis.admitted_at_block,
    )
    store.retain_source(h.cohort, h.closing)
    store.publish_history(h.history, h.intake.policy, current_block=h.block)

    async def decision(cohort, key):
        return store.source(cohort, key, CohortDecisionInput)

    publisher = CohortIntakePublisher(h.intake, h.provider.collect, decision)
    try:
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=owner_app)) as owner_client,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=peer_app)) as peer_client,
        ):
            h.remote.fetch = PreparationReviewHTTPClient(
                owner_client, "https://owner.example", token="owner-private-token" * 3
            )
            peer = PhaseVotePeer(
                peer_client,
                "https://reviewer.example",
                policy=h.intake.policy,
                cohorts=h.intake.config.cohorts,
                signer=wallet("Dave").hotkey.ss58_address,
                phase="preparation",
                token="peer-private-token" * 3,
            )

            def controller():
                ports = CertifiedPhaseObserver(
                    h.source.sample, (h.signer("Charlie"), peer), h.intake.policy
                )
                return CohortRecoveryCoordinator(
                    store,
                    h.cohort,
                    h.intake.policy,
                    h.history.genesis_signatures,
                    h.provider,
                    None,
                    ports.certify,
                    publisher,
                    sample_progress=ports.sample,
                    attest_progress=ports.attest,
                )

            h.remote_fail = True
            with pytest.raises(ValueError, match="quorum"):
                await controller().tick()
            assert store.status(h.cohort)[0].phase == "preparation"
            h.remote_fail = False
            h.block += 100_000
            db.close()
            db = sqlite3.connect(tmp_path / "remote-control.sqlite3")
            store = CohortRecoveryStore(db)
            assert (await controller().tick())["phase"] == "requests"
            history = h.intake.history(h.cohort)
            original = store.source(
                h.cohort, history.transitions[-1].transition.evidence_sha256, CohortDecisionInput
            )
            assert original.observation.block == h.progress.observed_at_block
            assert original.progress.progress.phase_result_sha256 == digest(h.prepared.roster.round)
            # Committed votes remain deliverable with both original sources offline.
            h.offline = True
            assert await peer.attest(original.progress.progress)
            assert await peer.certify(history.transitions[-1].transition, original)
            assert sum(1 for name, body in h.calls if name == "Charlie" and body == h.progress) == 1
    finally:
        db.close()


@pytest.mark.parametrize("failure", ["wrong_signer", "wrong_body", "noncanonical", "ack_only"])
async def test_remote_peer_accepts_only_exact_native_signature(remote, failure):
    h = remote

    def response(request):
        if failure == "ack_only":
            raw = b'{"accepted":true}'
        else:
            body = (
                h.progress
                if failure != "wrong_body"
                else h.progress.model_copy(update={"observed_at_block": h.block + 1})
            )
            vote = sign_object(body, wallet("Charlie" if failure == "wrong_signer" else "Dave"))
            raw = canonical_json_bytes(vote) + (b" " if failure == "noncanonical" else b"")
        return httpx.Response(200, headers={"content-type": "application/json"}, content=raw)

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        peer = PhaseVotePeer(
            client,
            "https://reviewer.example",
            policy=h.intake.policy,
            cohorts=h.intake.config.cohorts,
            signer=wallet("Dave").hotkey.ss58_address,
            phase="preparation",
            token="peer-private-token" * 3,
        )
        with pytest.raises(ValueError):
            await peer.attest(h.progress)


async def test_remote_peer_cancellation_drains_signing_request(remote):
    h = remote
    entered, drained = asyncio.Event(), asyncio.Event()

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    async with httpx.AsyncClient(transport=httpx.MockTransport(blocked)) as client:
        peer = PhaseVotePeer(
            client,
            "https://reviewer.example",
            policy=h.intake.policy,
            cohorts=h.intake.config.cohorts,
            signer=wallet("Dave").hotkey.ss58_address,
            phase="preparation",
            token="peer-private-token" * 3,
        )
        task = asyncio.create_task(peer.attest(h.progress))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert drained.is_set() and h.remote_calls == []
