"""Native intake, remote signing and quorum; synthetic chain and HTTPS ports."""

import asyncio
import hashlib
import json
from contextlib import AsyncExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_review_boot as boot
from umi.competition_cohort_admission_http import (
    HISTORY_PATH,
    MAX_VOTE_REQUEST_BYTES,
    VOTE_PATH,
    AdmissionHistoryExporter,
    AdmissionHistoryHTTPClient,
    AdmissionHistoryReader,
    AdmissionVotePeer,
    SignedAdmissionHistoryResponse,
    admission_history_routes,
    admission_vote_routes,
)
from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_worker import CohortAdmissionWorker
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_intake_records import read_participation
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_reward_manifest import RewardReplayRequirement, StandingRewardManifest
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_admission_queue import (  # noqa: F401
    accepted,
    archive,
    chain,
    chain_config,
    harness,
    policy,
    recovery,
    status,
    submit,
)
from .test_competition_cohort_admission_queue import (
    relay as relay,
)
from .test_competition_cohort_admission_signer import closed_source
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_lifecycle import legacy_scenario as legacy_scenario
from .test_competition_cohort_lifecycle import scenario as scenario
from .test_competition_cohort_review_boot import config_for, with_admission
from .test_competition_historical_registration import change_block
from .test_open_competition import wallet

OWNER_TOKEN = "owner-credential-" * 4
VOTE_TOKEN = "review-credential-" * 4
OWNER = wallet("Charlie").hotkey.ss58_address


@pytest.fixture
async def remote(relay):
    h = relay
    await submit(h)
    async with AsyncExitStack() as resources:

        async def sign(body):
            return sign_object(body, wallet("Charlie"))

        exporter = AdmissionHistoryExporter(h.queue, OWNER, sign)
        h.app.include_router(admission_history_routes(exporter, token=OWNER_TOKEN))
        owner_client = await resources.enter_async_context(
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=h.app),
                base_url="https://owner.example",
            )
        )
        history_fetch = AdmissionHistoryHTTPClient(
            owner_client,
            "https://owner.example",
            token=OWNER_TOKEN,
        )
        history = AdmissionHistoryReader(OWNER, history_fetch)

        async def reviewer(name):
            native = h.worker(name)
            native.history = history
            archive_port = AsyncMock(return_value=(h.archive.raw, h.archive.metadata))
            native.archive = archive_port
            app = FastAPI()
            app.include_router(admission_vote_routes(native, token=VOTE_TOKEN))
            client = await resources.enter_async_context(
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="https://review.example",
                )
            )
            peer = AdmissionVotePeer(
                client,
                "https://review.example",
                policy=h.queue.policy,
                cohorts=h.intake.config.cohorts,
                signer=wallet(name).hotkey.ss58_address,
                token=VOTE_TOKEN,
            )
            return SimpleNamespace(
                native=native,
                peer=peer,
                archive=archive_port,
                client=client,
                worker=CohortAdmissionWorker(h.queue, peer, provider=h.archive.reviewer),
            )

        h.remote, h.history_fetch, h.exporter = reviewer, history_fetch, exporter
        h.owner_client = owner_client
        yield h


async def test_remote_independent_votes_publish_the_native_public_certificate(remote):
    h = remote
    first, second = await h.remote("Charlie"), await h.remote("Dave")
    assert (await first.worker.poll_once())["votes_published"] == 1
    assert (await status(h)).status == "pending_attestation"
    assert (await second.worker.poll_once())["certificates_published"] == 1
    result = await status(h)
    assert result.status == "admission_certified"
    assert result.certificate.admission == read_participation(h.raw).proposed_admission
    assert len(h.calls) == 2
    assert (await first.worker.poll_once())["votes_published"] == 0


async def test_committed_vote_recovers_with_no_owner_proofs_or_rpc(remote, monkeypatch):
    h = remote
    first = await h.remote("Charlie")
    original = await first.peer.attest(h.raw)
    restarted = await h.remote("Charlie")
    restarted.native.history = AsyncMock(side_effect=OSError("owner offline"))
    restarted.archive.side_effect = FileNotFoundError("inbox missing")
    monkeypatch.setattr(h.archive.reviewer, "review_archive", AsyncMock(side_effect=OSError("RPC")))
    assert await restarted.peer.attest(h.raw) == original
    assert len(h.calls) == 1
    restarted.native.history.assert_not_called()
    restarted.archive.assert_not_called()


@pytest.mark.parametrize("failure", [OSError, asyncio.TimeoutError])
async def test_lost_vote_ack_retries_original_after_intake_closes(remote, failure):
    h = remote
    first = await h.remote("Charlie")
    transport = first.peer.transport

    async def lost(request):
        await transport(request)
        raise failure("ack lost")

    first.peer.transport = lost
    assert (await first.worker.poll_once())["retry_count"] == 1
    assert len(h.calls) == 1
    closed = closed_source(h)
    h.intake.seal(h.cohort, h.archive.capture, expected_tip_sha256=history_tip(h.source.history))
    h.intake.publish(
        closed.history, await h.archive.reviewer.collect(), closure_input=closed.closure
    )
    assert (await (await h.remote("Charlie")).worker.poll_once())["votes_published"] == 1
    assert (await (await h.remote("Dave")).worker.poll_once())["certificates_published"] == 1
    assert len(h.calls) == 2
    assert (await status(h)).status == "admission_certified"


async def test_ten_hour_interruption_resumes_same_intent_without_renewal(remote):
    h = remote
    original_history = h.queue.history(h.cohort)
    h.fail = True
    first = await h.remote("Charlie")
    assert (await first.worker.poll_once())["retry_count"] == 1
    assert len(h.calls) == 1
    a = h.archive
    a.chain.clock.now += 10 * 60 * 60 * 1000
    encoded = change_block(a.chain, a.fresh.height + 3000)
    proof = canonical_json_bytes(
        {
            **json.loads(a.fresh.finality_evidence),
            "block": {"scale_header": encoded},
        }
    )
    a.blocks[a.chain.finality.ref.block_number] = replace(
        a.fresh,
        height=a.chain.finality.ref.block_number,
        block_hash=a.chain.finality.ref.block_hash,
        timestamp_ms=a.chain.finality.timestamp,
        finality_evidence=proof,
        finality_evidence_sha256=hashlib.sha256(proof).hexdigest(),
    )
    h.fail = False
    restarted = await h.remote("Charlie")
    restarted.archive.side_effect = FileNotFoundError("inbox lost during outage")
    assert (await restarted.worker.poll_once())["votes_published"] == 1
    restarted.archive.assert_not_called()
    assert (await (await h.remote("Dave")).worker.poll_once())["certificates_published"] == 1
    assert h.queue.history(h.cohort) == original_history
    assert h.calls[0][1] == h.calls[1][1]
    assert (await status(h)).status == "admission_certified"


@pytest.mark.parametrize(
    "failure", ["proof_missing", "proof_changed", "owner_offline", "rpc_offline"]
)
async def test_missing_dependencies_leave_same_admission_retryable(remote, monkeypatch, failure):
    h = remote
    reviewer = await h.remote("Charlie")
    if failure == "proof_missing":
        reviewer.archive.side_effect = FileNotFoundError("no proof")
    elif failure == "proof_changed":
        reviewer.archive.return_value = (h.archive.raw, b"wrong metadata")
    elif failure == "owner_offline":
        reviewer.native.history = AsyncMock(side_effect=OSError("owner offline"))
    else:
        monkeypatch.setattr(
            h.archive.reviewer, "review_archive", AsyncMock(side_effect=OSError("RPC"))
        )
    assert (await reviewer.worker.poll_once())["retry_count"] == 1
    assert not h.calls
    assert (await status(h)).status == "pending_attestation"


async def test_new_vote_rejects_revoked_cohort(remote):
    h = remote
    revoked = transition(h.source.history, h.queue.policy, "revoke", h.archive.fresh.height)
    h.intake.publish(revoked, await h.archive.reviewer.collect())
    reviewer = await h.remote("Charlie")
    with pytest.raises(OSError):
        await reviewer.peer.attest(h.raw)
    assert not h.calls


@pytest.mark.parametrize("failure", ["owner", "challenge", "cohort", "signature", "canonical"])
async def test_authenticated_history_rejects_substituted_exports(remote, failure):
    h = remote

    async def changed(request):
        raw = await h.exporter.respond(request)
        signed = SignedAdmissionHistoryResponse.model_validate_json(raw)
        if failure == "canonical":
            return b" " + raw
        body = signed.response
        if failure == "challenge":
            body = body.model_copy(update={"challenge": "f1" * 32})
        elif failure == "cohort":
            body = body.model_copy(
                update={
                    "history": body.history.model_copy(
                        update={
                            "plan": body.history.plan.model_copy(update={"sequence": 99}),
                        }
                    )
                }
            )
        signature = sign_object(body, wallet("Dave" if failure == "owner" else "Charlie"))
        if failure == "signature":
            signature = signature.model_copy(update={"signature": "0x" + "00" * 64})
        return canonical_json_bytes(
            SignedAdmissionHistoryResponse(response=body, signature=signature)
        )

    with pytest.raises(ValueError):
        await AdmissionHistoryReader(OWNER, changed)(h.cohort)
    assert not h.calls


@pytest.mark.parametrize("failure", ["reviewer", "body", "signature", "canonical"])
async def test_peer_checks_exact_vote_and_selected_identity(remote, failure):
    h = remote
    reviewer = await h.remote("Charlie")
    body = read_participation(h.raw).proposed_admission
    if failure == "body":
        body = body.model_copy(update={"uid": 255})
    signature = sign_object(body, wallet("Dave" if failure == "reviewer" else "Charlie"))
    if failure == "signature":
        signature = signature.model_copy(update={"signature": "0x" + "00" * 64})
    raw = canonical_json_bytes(CohortAdmissionVote(admission=body, signature=signature))
    reviewer.peer.transport = AsyncMock(
        return_value=(b" " + raw if failure == "canonical" else raw)
    )
    with pytest.raises(ValueError):
        await reviewer.peer.attest(h.raw)


async def test_private_routes_authenticate_and_bound_requests(remote):
    h = remote
    reviewer = await h.remote("Charlie")
    assert (await reviewer.client.post(VOTE_PATH, json={})).status_code == 401
    assert (await h.owner_client.post(HISTORY_PATH, json={})).status_code == 401
    headers = {"authorization": "Bearer " + VOTE_TOKEN, "content-type": "application/json"}
    assert (
        await reviewer.client.post(VOTE_PATH, content=b"{}", headers=headers)
    ).status_code == 422
    assert (
        await reviewer.client.post(
            VOTE_PATH,
            content=b" " * (MAX_VOTE_REQUEST_BYTES + 1),
            headers=headers,
        )
    ).status_code == 413
    assert not h.calls


async def test_record_outside_scope_fails_before_network(remote):
    h = remote
    reviewer = await h.remote("Charlie")
    record = read_participation(h.raw)
    raw = canonical_json_bytes(
        record.model_copy(
            update={
                "proposed_admission": record.proposed_admission.model_copy(
                    update={"cohort_sha256": "ff" * 32}
                ),
            }
        )
    )
    reviewer.peer.transport = AsyncMock()
    with pytest.raises(ValueError, match="outside"):
        await reviewer.peer.attest(raw)
    reviewer.peer.transport.assert_not_called()


def test_remote_worker_requires_its_own_matching_publication_provider(relay):
    h = relay
    peer = SimpleNamespace(policy=h.queue.policy, cohorts=h.intake.config.cohorts, signer=OWNER)
    with pytest.raises(ValueError):
        CohortAdmissionWorker(h.queue, peer)
    with pytest.raises(ValueError):
        CohortAdmissionWorker(h.queue, peer, provider=SimpleNamespace(policy=None))


async def test_actual_reviewer_host_signs_original_proof_then_recovers_offline(
    remote, monkeypatch, tmp_path
):
    h = remote
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(h.queue.policy),
        cohorts=(
            RewardReplayRequirement(
                cohort_sha256=h.cohort,
                terms_sha256="ab" * 32,
                catalog_sha256s=("ac" * 32,),
            ),
        ),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(h.queue.policy),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=OWNER,
        recovery=h.source.history.authority,
        cohorts=(h.source.history.plan,),
        validators=(wallet("Dave").hotkey.ss58_address,),
        maximum_proof_lag_blocks=32,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    host_chain = h.archive.chain.config.model_copy(
        update={
            "state_directory": str(tmp_path / "host-chain"),
            "proof_rpc_fallback_urls": ("wss://backup-one.example", "wss://backup-two.example"),
        }
    )
    config = with_admission(
        config_for(
            SimpleNamespace(
                series=series, manifest=manifest, policy=h.queue.policy, chain=host_chain
            ),
            tmp_path / "host",
        )
    )
    monkeypatch.setattr(
        boot, "_token", lambda path: OWNER_TOKEN if path == config.owner_token_file else VOTE_TOKEN
    )
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *_: wallet("Dave"))
    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", lambda *_: h.archive.reviewer)
    started, closed = AsyncMock(), AsyncMock()
    monkeypatch.setattr(h.archive.reviewer, "start", started)
    monkeypatch.setattr(h.archive.reviewer, "aclose", closed)
    client_type = httpx.AsyncClient
    monkeypatch.setattr(
        boot.httpx,
        "AsyncClient",
        lambda **kw: client_type(
            transport=httpx.ASGITransport(app=h.app),
            **kw,
        ),
    )
    signed_bodies = []

    def record_sign(body, key):
        signed_bodies.append(body)
        return sign_object(body, key)

    monkeypatch.setattr(boot, "sign_object", record_sign)
    observation = read_participation(h.raw).observation
    proofs = RewardProofArchive(Path(config.proof_import_directory))
    async with (
        boot.phase_review_app(config) as app,
        client_type(
            transport=httpx.ASGITransport(app=app),
        ) as client,
    ):
        peer = AdmissionVotePeer(
            client,
            "https://review.example",
            policy=h.queue.policy,
            cohorts=h.intake.config.cohorts,
            signer=config.signing.signer,
            token=VOTE_TOKEN,
        )
        with pytest.raises(OSError):
            await peer.attest(h.raw)
        assert not signed_bodies
        proofs.write(
            "registration",
            digest(observation),
            context=observation.model_dump(mode="json", by_alias=True),
            fields={"proof": h.archive.raw, "metadata": h.archive.metadata},
        )
        vote = await peer.attest(h.raw)
        assert len(signed_bodies) == 1
    (
        Path(config.proof_import_directory) / "registration" / (digest(observation) + ".json")
    ).unlink()
    monkeypatch.setattr(
        AdmissionHistoryReader, "__call__", AsyncMock(side_effect=OSError("offline owner"))
    )
    monkeypatch.setattr(
        h.archive.reviewer, "review_archive", AsyncMock(side_effect=OSError("offline RPC"))
    )
    async with (
        boot.phase_review_app(config) as app,
        client_type(
            transport=httpx.ASGITransport(app=app),
        ) as client,
    ):
        peer = AdmissionVotePeer(
            client,
            "https://review.example",
            policy=h.queue.policy,
            cohorts=h.intake.config.cohorts,
            signer=config.signing.signer,
            token=VOTE_TOKEN,
        )
        assert await peer.attest(h.raw) == vote
    assert len(signed_bodies) == 1
    assert started.await_count == closed.await_count == 2
