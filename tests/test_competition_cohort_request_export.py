"""Remote request closure uses native terminals; synthetic chain and inference."""

import asyncio
import sqlite3

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_coordinator import CohortDecisionInput, CohortRecoveryCoordinator
from umi.competition_cohort_intake import CohortIntakePublisher
from umi.competition_cohort_phase_vote_http import PhaseVotePeer, phase_vote_routes
from umi.competition_cohort_progress_signer import (
    CertifiedPhaseObserver,
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_request_export import (
    RequestReviewExporter,
    SignedRequestReviewResponse,
    replay_request_export,
)
from umi.competition_cohort_request_remote_review import RemoteRequestProgressReviewer
from umi.competition_cohort_request_review_http import (
    RequestReviewHTTPClient,
    request_review_routes,
)
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.concurrency import run_owned_thread
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_request_phase import base_policy as base_policy
from .test_competition_cohort_request_phase import chain as chain
from .test_competition_cohort_request_phase import chain_config as chain_config
from .test_competition_cohort_request_phase import endpoint as endpoint
from .test_competition_cohort_request_phase import execution as execution
from .test_competition_cohort_request_phase import granted as granted
from .test_competition_cohort_request_phase import harness as harness
from .test_competition_cohort_request_phase import known_video_bytes as known_video_bytes
from .test_competition_cohort_request_phase import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_phase import miner_policy as miner_policy
from .test_competition_cohort_request_phase import original_harness as original_harness
from .test_competition_cohort_request_phase import policy as policy
from .test_competition_cohort_request_phase import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_phase import recovery as recovery
from .test_competition_cohort_request_phase import recovery_case as recovery_case
from .test_competition_cohort_request_phase import relay as relay
from .test_competition_cohort_request_phase import request_owner as request_owner
from .test_competition_cohort_request_phase import runtime as runtime
from .test_competition_cohort_request_phase import scenario as scenario
from .test_competition_cohort_request_phase import service as service
from .test_competition_cohort_request_phase import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_request_phase import service_closed as service_closed
from .test_competition_cohort_request_phase import service_owner as service_owner
from .test_competition_cohort_request_phase import shared_control_group as shared_control_group
from .test_open_competition import wallet


@pytest.fixture
def remote(request_owner, tmp_path):
    h = request_owner
    h.owner_identity = wallet("Charlie").hotkey.ss58_address
    h.remote_calls, h.remote_fail, h.requests = [], False, []

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    h.exporter = RequestReviewExporter(h.source, h.owner_identity, sign)

    async def fetch(request):
        h.requests.append(request)
        if h.offline:
            raise OSError("owner offline")
        return await h.exporter.respond(request)

    async def archive(observation):
        return b"proof", b"metadata"

    h.remote = RemoteRequestProgressReviewer(
        h.provider,
        h.intake.config.cohorts,
        h.owner_identity,
        fetch,
        archive,
        roster=h.source.roster,
        catalogs=h.source.catalogs,
        transport=h.source.transport,
        maximum_sample_gap_blocks=300,
    )

    def signer():
        async def sign_vote(body):
            if h.remote_fail:
                raise OSError("reviewer signer offline")
            h.remote_calls.append(body)
            return sign_object(body, wallet("Dave"))

        cfg = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(tmp_path / "remote-signing"),
            policy_sha256=digest(h.intake.policy),
            signer=wallet("Dave").hotkey.ss58_address,
            cohorts=h.intake.config.cohorts,
        )
        return CohortProgressSigner(cfg, h.remote, sign_vote)

    h.remote_signer = signer
    return h


def replay(h, value):
    return replay_request_export(
        value,
        h.intake.policy,
        roster=h.source.roster,
        catalogs=h.source.catalogs,
        transport=h.source.transport,
        maximum_sample_gap_blocks=300,
        maximum_bytes=64 * 1024**2,
    )


@pytest.mark.parametrize("completion", ["pending", "fenced_pending", "complete"])
async def test_remote_request_export_matches_native_owner(remote, completion):
    h = remote
    if completion == "pending":
        progress = h.sample()
    else:
        h.withheld = completion == "fenced_pending"
        progress = h.window()
    value = h.exporter.export(progress)
    assert replay(h, value) == h.source.read(progress)
    if completion == "complete":
        assert value.objects and value.seals and value.record.fence
    else:
        assert value.objects == value.seals == ()
        assert progress.completion == "pending"
    app = FastAPI()
    app.include_router(request_review_routes(h.exporter, token="owner-private-token" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        h.remote.fetch = RequestReviewHTTPClient(
            client, "https://owner.example", token="owner-private-token" * 3
        )
        assert await h.remote.review(progress) == h.source.read(progress).record
        vote = await h.remote_signer().attest(progress)
    h.offline = True
    assert await h.remote_signer().attest(progress) == vote
    assert len(h.remote_calls) == 1


@pytest.mark.parametrize(
    "damage",
    [
        "missing_response",
        "changed_object",
        "extra_object",
        "inventory",
        "seals",
        "service",
        "fence",
        "catalog",
        "roster",
        "transport",
    ],
)
def test_remote_cannot_close_changed_or_incomplete_native_evidence(remote, damage):
    h = remote
    progress = h.window()
    value = h.exporter.export(progress)
    if damage == "missing_response":
        key = h.b["service_terminal"].terminal.response_sha256
        assert key in {o.sha256 for o in value.objects}
        value = value.model_copy(
            update={"objects": tuple(o for o in value.objects if o.sha256 != key)}
        )
    elif damage == "changed_object":
        first = value.objects[0].model_copy(update={"value": {"wrong": True}})
        value = value.model_copy(update={"objects": (first, *value.objects[1:])})
    elif damage == "extra_object":
        extra = RewardPackageObject(sha256=digest({"extra": True}), value={"extra": True})
        value = value.model_copy(
            update={"objects": tuple(sorted((*value.objects, extra), key=lambda o: o.sha256))}
        )
    elif damage == "inventory":
        value = value.model_copy(update={"records": value.records[1:]})
    elif damage == "seals":
        value = value.model_copy(update={"seals": ()})
    elif damage == "service":
        value = value.model_copy(update={"services": value.services[1:]})
    elif damage == "fence":
        value = value.model_copy(update={"record": value.record.model_copy(update={"fence": None})})
    elif damage == "catalog":
        value = value.model_copy(update={"catalogs": ("ab" * 32,)})
    else:
        value = value.model_copy(update={damage + "_sha256": "ab" * 32})
    with pytest.raises((OSError, ValueError)):
        replay(h, value)


@pytest.mark.parametrize("damage", ["challenge", "owner", "progress", "canonical"])
async def test_response_identity_is_checked_before_native_review(remote, damage, monkeypatch):
    h = remote
    progress = h.window()

    async def fetch(request):
        raw = await h.exporter.respond(request)
        if damage == "canonical":
            return raw + b" "
        signed = SignedRequestReviewResponse.model_validate_json(raw)
        response = signed.response
        if damage == "challenge":
            response = response.model_copy(update={"challenge": "ab" * 32})
        elif damage == "progress":
            record = response.evidence.record.model_copy(
                update={"progress": progress.model_copy(update={"observed_at_block": h.block + 1})}
            )
            response = response.model_copy(
                update={"evidence": response.evidence.model_copy(update={"record": record})}
            )
        return canonical_json_bytes(
            SignedRequestReviewResponse(
                response=response,
                signature=sign_object(response, wallet("Dave" if damage == "owner" else "Charlie")),
            )
        )

    h.remote.fetch = fetch
    with pytest.raises(ValueError):
        await h.remote_signer().attest(progress)
    assert h.remote_calls == []


@pytest.mark.parametrize("failure", ["proof", "offline", "saved_response"])
async def test_proof_failures_and_owner_loss_prevent_new_votes(remote, failure):
    h = remote
    progress = h.window()
    fetch = h.remote.fetch
    saved = None
    if failure == "saved_response":

        async def old(request):
            nonlocal saved
            if saved is None:
                saved = await fetch(request)
            return saved

        h.remote.fetch = old

    async def archive(observation):
        if failure == "offline":
            h.offline = True
        return (b"invalid" if failure == "proof" else b"proof"), b"metadata"

    h.remote.archive = archive
    with pytest.raises((OSError, ValueError)):
        await h.remote_signer().attest(progress)
    assert h.remote_calls == []


async def test_request_export_capacity_and_cancellation_preserve_completion(remote):
    h = remote
    progress = h.window()
    original = h.exporter.export(progress)
    h.exporter.maximum_bytes = 1024
    with pytest.raises((OSError, ValueError)):
        await h.remote_signer().attest(progress)
    h.exporter.maximum_bytes = 64 * 1024**2
    assert h.exporter.export(progress) == original
    entered, drained = asyncio.Event(), asyncio.Event()

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    h.remote.fetch = blocked
    task = asyncio.create_task(h.remote_signer().attest(progress))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert drained.is_set() and h.remote_calls == []


async def test_native_controller_recovers_remote_request_vote_after_long_delay(remote, tmp_path):
    h = remote
    complete = h.window()
    owner, reviewer = FastAPI(), FastAPI()
    owner.include_router(request_review_routes(h.exporter, token="owner-private-token" * 3))
    reviewer.include_router(
        phase_vote_routes(h.remote_signer(), phase="requests", token="peer-private-token" * 3)
    )
    db = sqlite3.connect(tmp_path / "remote-controller.sqlite3")
    store = CohortRecoveryStore(db)
    history, policy = h.b["history"], h.b["policy"]
    store.admit(
        history.plan, history.authority, policy, admitted_at_block=history.genesis.admitted_at_block
    )
    for d in h.b["decisions"].values():
        store.retain_source(h.cohort, d)
    store.publish_history(history, policy, current_block=h.block)

    async def decision(cohort, key):
        return store.source(cohort, key, CohortDecisionInput)

    publisher = CohortIntakePublisher(h.intake, h.provider.collect, decision)

    async def sample(state, observed):
        return await run_owned_thread(lambda: h.source.observe(state, observed, serving=True))

    try:
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=owner)) as owner_client,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=reviewer)) as reviewer_client,
        ):
            h.remote.fetch = RequestReviewHTTPClient(
                owner_client, "https://owner.example", token="owner-private-token" * 3
            )
            peer = PhaseVotePeer(
                reviewer_client,
                "https://reviewer.example",
                policy=policy,
                cohorts=h.intake.config.cohorts,
                signer=wallet("Dave").hotkey.ss58_address,
                phase="requests",
                token="peer-private-token" * 3,
            )

            def controller():
                ports = CertifiedPhaseObserver(sample, (h.signer("Charlie"), peer), policy)
                return CohortRecoveryCoordinator(
                    store,
                    h.cohort,
                    policy,
                    history.genesis_signatures,
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
            assert store.status(h.cohort)[0].phase == "requests"
            h.remote_fail = False
            h.block += 100000
            db.close()
            db = sqlite3.connect(tmp_path / "remote-controller.sqlite3")
            store = CohortRecoveryStore(db)
            assert (await controller().tick())["phase"] == "reference_reveal"
            history = h.intake.history(h.cohort)
            original = store.source(
                h.cohort, history.transitions[-1].transition.evidence_sha256, CohortDecisionInput
            )
            assert original.progress.progress == complete
            h.offline = True
            assert await peer.attest(complete)
            assert await peer.certify(history.transitions[-1].transition, original)
    finally:
        db.close()


async def test_remote_review_retains_outage_compensation_before_request_closure(remote):
    h = remote
    h.sample()
    h.source = h.reopen()
    h.exporter.source = h.source
    late = h.sample(h.block + 30000)
    assert late.completion == "pending" and late.unavailable_blocks >= 30000
    assert h.c.queue.retained_seal() is None
    assert await h.remote.review(late) == h.source.read(late).record
    complete = h.window()
    assert complete.completion == "complete"
    assert complete.unavailable_blocks == late.unavailable_blocks
    value = h.exporter.export(complete)
    assert replay(h, value).record.progress == complete
    # A signed owner cannot remove downtime from the retained sampling history.
    receipt = value.services[1].model_copy(update={"unavailable_blocks": 0})
    shortened = value.model_copy(
        update={"services": (value.services[0], receipt, *value.services[2:])}
    )
    with pytest.raises(ValueError, match="service history"):
        replay(h, shortened)
    assert await h.remote_signer().attest(complete)
