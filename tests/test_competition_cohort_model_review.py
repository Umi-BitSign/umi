"""Native artifact votes and recurring quorum recovery; finality is synthetic."""

import asyncio
import os
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_model_acceptance import ModelArtifactVote
from umi.competition_cohort_model_acceptance_store import PendingModelArtifacts
from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from umi.competition_cohort_model_review import ModelArtifactReviewer, ModelReviewConfig
from umi.competition_cohort_model_review_http import VOTE_PATH, ModelReviewPeer, model_review_routes
from umi.competition_cohort_service_host import ServiceAdmissionHost, ServiceAdmissionHostConfig
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_reward_manifest import RewardReplayRequirement, StandingRewardManifest
from umi.competition_store import CompetitionStore
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, sign_object
from umi.private_files import lock_private_file, publish_private_model

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_acceptance import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_acceptance import (
    policy as policy,
)
from .test_competition_cohort_model_acceptance import (
    prepared as prepared,
)
from .test_competition_cohort_model_acceptance import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_acceptance import (
    recovery as recovery,
)
from .test_competition_cohort_model_acceptance import (
    runtime as runtime,
)
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def reviews(prepared, tmp_path):
    owner, cohort, subs, inputs = prepared
    root = tmp_path / "reviews"
    state = SimpleNamespace(block=230, signing=[], online=True)

    async def capture():
        if not state.online:
            raise AssertionError("committed vote must not contact RPC")
        return capture_at(state.block)

    async def history(key):
        if not state.online:
            raise AssertionError("committed vote must not contact coordinator")
        return CohortAdmissionQueue(owner.intake).history(key)

    def create(name):
        config = ModelReviewConfig(
            schema="umi-cohort-model-review-config/1",
            directory=str(root / name / "journal"),
            approvals_directory=str(root / name / "approvals"),
            archive_directory=str(owner.archive),
            policy_sha256=digest(owner.intake.policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=owner.intake.config.cohorts,
        )

        async def sign(body):
            state.signing.append((name, body))
            return sign_object(body, wallet(name))

        return ModelArtifactReviewer(config, owner.intake.policy, capture, history, sign)

    for name in ("Charlie", "Dave"):
        publish_private_model(root / name / "approvals" / (inputs.model_sha256 + ".json"), inputs)
    owner.prepare(cohort, digest(subs[0]), inputs, capture_at(220))
    request = owner.review_request(cohort, digest(subs[0]))
    return SimpleNamespace(
        owner=owner,
        cohort=cohort,
        subs=subs,
        inputs=inputs,
        state=state,
        create=create,
        request=request,
        root=root,
        capture=capture,
    )


async def test_committed_vote_returns_after_restart_with_owner_rpc_and_files_offline(reviews):
    r = reviews
    first = await r.create("Charlie").attest(r.request)
    r.state.online = False
    (r.root / "Charlie/approvals").rename(r.root / "Charlie/offline")
    r.owner.archive.rename(r.owner.archive.with_name("offline-artifacts"))
    assert await r.create("Charlie").attest(r.request) == first
    assert len(r.state.signing) == 1


async def test_unfinished_signing_resumes_original_review_after_ten_hour_delay(reviews):
    r = reviews
    reviewer = r.create("Charlie")

    async def unavailable(_):
        raise OSError("signer temporarily unavailable")

    reviewer.sign = unavailable
    with pytest.raises(OSError):
        await reviewer.attest(r.request)
    (r.root / "Charlie/approvals").rename(r.root / "Charlie/offline")
    r.owner.archive.rename(r.owner.archive.with_name("offline-artifacts"))
    r.state.block += 3000
    vote = await r.create("Charlie").attest(r.request)
    assert vote.acceptance == r.request.acceptance
    assert vote.acceptance.accepted_at_block == 220
    assert len(r.state.signing) == 1


@pytest.mark.parametrize(
    "bad", ["missing-approval", "changed-doc", "missing-payload", "admission", "self"]
)
async def test_request_cannot_replace_independent_review(reviews, bad):
    r = reviews
    reviewer = r.create("Charlie")
    request = r.request
    if bad == "missing-approval":
        (r.root / "Charlie/approvals").rename(r.root / "Charlie/offline")
    elif bad == "changed-doc":
        a = request.acceptance.model_copy(update={"rights_evidence_sha256": "ef" * 32})
        request = request.model_copy(update={"acceptance": a})
    elif bad == "missing-payload":
        r.owner.archive.rename(r.owner.archive.with_name("offline-artifacts"))
    elif bad == "admission":
        request = request.model_copy(
            update={
                "admission": request.admission.model_copy(
                    update={"signatures": request.admission.signatures[:1]}
                )
            }
        )
    else:
        # An authorized evaluator still cannot attest its own model.
        reviewer.config = reviewer.config.model_copy(
            update={"signer": request.acceptance.recipient_hotkey}
        )
    with pytest.raises((ValueError, OSError)):
        await reviewer.attest(request)
    assert not r.state.signing


async def test_signer_will_not_reuse_ordinal_or_change_original_proposal(reviews):
    r = reviews
    reviewer = r.create("Charlie")
    await reviewer.attest(r.request)
    changed = r.request.model_copy(
        update={"acceptance": r.request.acceptance.model_copy(update={"accepted_at_block": 221})}
    )
    with pytest.raises(ValueError, match="original request"):
        await reviewer.attest(changed)
    r.owner.prepare(r.cohort, digest(r.subs[1]), r.inputs, capture_at(221))
    second = r.owner.review_request(r.cohort, digest(r.subs[1]))
    second = second.model_copy(
        update={"acceptance": second.acceptance.model_copy(update={"accepted_ordinal": 1})}
    )
    with pytest.raises(ValueError):
        await reviewer.attest(second)
    assert len(r.state.signing) == 1


async def test_worker_collects_remote_votes_across_restarts_and_lost_ack(reviews, tmp_path):
    r = reviews
    # Only the first model has an owner proposal; the other may wait independently.
    root, out = tmp_path / "owner-inputs", tmp_path / "owner-exports"
    token = "review-token" * 4
    unavailable = {"Dave"}
    reviewers = {name: r.create(name) for name in ("Charlie", "Dave")}
    apps = {}
    for name, reviewer in reviewers.items():
        app = FastAPI()
        app.include_router(model_review_routes(reviewer, token=token))
        apps[name] = app

    async def handle(request):
        name = "Charlie" if request.url.host == "charlie.example" else "Dave"
        if name in unavailable:
            raise httpx.ConnectError("temporarily offline", request=request)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=apps[name])) as server:
            return await server.send(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        peers = tuple(
            ModelReviewPeer(
                client,
                f"https://{name.lower()}.example",
                policy=r.owner.intake.policy,
                cohorts=r.owner.intake.config.cohorts,
                signer=wallet(name).hotkey.ss58_address,
                token=token,
            )
            for name in reviewers
        )
        worker = ModelAcceptanceWorker(r.owner, r.capture, root, out, reviewers=peers)
        assert (await worker.poll_once())["entries_pending"] == 2
        assert len(r.owner.votes(r.cohort, digest(r.subs[0]))) == 1
        with pytest.raises(PendingModelArtifacts):
            r.owner.retained(r.cohort, digest(r.subs[0]))
        # The first peer disappears, but its accepted vote is already durable.
        unavailable.clear()
        unavailable.add("Charlie")
        r.state.block += 3000
        worker = ModelAcceptanceWorker(r.owner, r.capture, root, out, reviewers=peers)
        assert (await worker.poll_once())["entries_exported"] == 1
        approved = r.owner.retained(r.cohort, digest(r.subs[0]))
        assert approved.certificate.acceptance == r.request.acceptance
        assert len(approved.certificate.signatures) == 2
        unavailable.add("Dave")
        r.state.online = False
        assert (await worker.poll_once())["entries_exported"] == 1
        assert len(r.state.signing) == 2


async def test_private_route_authenticates_and_peer_rejects_wrong_signer(reviews):
    r = reviews
    token = "vote-secret" * 4
    app = FastAPI()
    app.include_router(model_review_routes(r.create("Charlie"), token=token))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://review.example"
    ) as client:
        assert (await client.post(VOTE_PATH, json={})).status_code == 401
        peer = ModelReviewPeer(
            client,
            "https://review.example",
            policy=r.owner.intake.policy,
            cohorts=r.owner.intake.config.cohorts,
            signer=wallet("Dave").hotkey.ss58_address,
            token=token,
        )
        with pytest.raises(ValueError, match="independent reviewer"):
            await peer.attest(r.request)


def test_owner_does_not_count_missing_quorum_or_changed_body(reviews):
    r = reviews
    a = r.request.acceptance
    vote = ModelArtifactVote(acceptance=a, signature=sign_object(a, wallet("Charlie")))
    r.owner.publish_vote(vote)
    assert r.owner.publish_vote(vote) == vote
    with pytest.raises(PendingModelArtifacts):
        r.owner.certified_votes(r.cohort, digest(r.subs[0]))
    changed = a.model_copy(update={"accepted_ordinal": 4})
    with pytest.raises(ValueError, match="body"):
        r.owner.publish_vote(
            ModelArtifactVote(acceptance=changed, signature=sign_object(changed, wallet("Dave")))
        )


async def test_cancelled_signing_keeps_process_lock_until_owned_key_work_drains(reviews):
    r = reviews
    reviewer = r.create("Charlie")
    entered, finish = asyncio.Event(), asyncio.Event()

    async def sign(body):
        entered.set()
        await finish.wait()
        return sign_object(body, wallet("Charlie"))

    reviewer.sign = sign
    task = asyncio.create_task(reviewer.attest(r.request))
    await asyncio.wait_for(entered.wait(), 3)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError):
        lock_private_file(reviewer.journal.lock_path)
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    os.close(lock_private_file(reviewer.journal.lock_path))
    assert (await r.create("Charlie").attest(r.request)).acceptance == r.request.acceptance


async def test_configured_owner_service_collects_model_votes(reviews, tmp_path, monkeypatch):
    from umi import competition_cohort_service_host as host_module
    from umi.competition_cohort_model_review_http import ModelReviewPeerConfig

    r = reviews
    history = r.owner.intake.history(r.cohort)
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(r.owner.intake.policy),
        cohorts=(
            RewardReplayRequirement(
                cohort_sha256=r.cohort, terms_sha256="ab" * 32, catalog_sha256s=("cd" * 32,)
            ),
        ),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(r.owner.intake.policy),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Charlie").hotkey.ss58_address,
        recovery=history.authority,
        cohorts=(history.plan,),
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=100,
        maximum_transaction_lifetime_blocks=64,
        lifetime="until_superseded_or_revoked",
    )
    configs, apps = [], {}
    token = "private-model-peer" * 3
    for name in ("Charlie", "Dave"):
        token_path = tmp_path / (name + ".token")
        token_path.write_text(token)
        token_path.chmod(0o400)
        configs.append(
            ModelReviewPeerConfig(
                signer=wallet(name).hotkey.ss58_address,
                origin=f"https://{name.lower()}.example",
                token_file=str(token_path),
            )
        )
        app = FastAPI()
        app.include_router(model_review_routes(r.create(name), token=token))
        apps[name.lower() + ".example"] = app
    native_client = httpx.AsyncClient

    async def handle(request):
        async with native_client(
            transport=httpx.ASGITransport(app=apps[request.url.host])
        ) as server:
            return await server.send(request)

    monkeypatch.setattr(
        host_module.httpx,
        "AsyncClient",
        lambda **kwargs: native_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    # Root credential loader is a host boundary already covered by boot tests.
    monkeypatch.setattr(
        host_module, "_read_root_control_path", lambda path, *_args, **_kw: path.read_bytes()
    )
    cfg = ServiceAdmissionHostConfig(
        schema="umi-cohort-service-admission-host/2",
        series=series,
        manifest=manifest,
        queue_directory=str(tmp_path / "queues"),
        inputs_directory=str(tmp_path / "input-delivery"),
        model_review_peers=tuple(configs),
    )
    store = CompetitionStore(tmp_path / "promotion", r.owner.intake.policy)
    r.owner.archive.rename(store.directory / "model-reward-artifacts")
    stop = asyncio.Event()

    async def archive(_):
        raise AssertionError("no serving work in this artifact review test")

    service = ServiceAdmissionHost(cfg, r.owner.intake, store, r.capture, archive)
    original = service.poll_once

    async def one_cycle():
        report = await original()
        assert report["model_acceptance"]["entries_exported"] == 1
        stop.set()
        return report

    # Reviewers already own their artifact archive. Copy the preserved fixture
    # back as independent reviewer input after selecting the owner's destination.
    import shutil

    shutil.copytree(store.directory / "model-reward-artifacts", r.owner.archive)
    monkeypatch.setattr(service, "poll_once", one_cycle)
    await service.run(stop)
    assert (
        len(service.models.owner.retained(r.cohort, digest(r.subs[0])).certificate.signatures) == 2
    )
