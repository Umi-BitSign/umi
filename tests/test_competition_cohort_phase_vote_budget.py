"""Scaled serial review deadlines through real HTTP routes and signer journals.

The proof reader is synthetic. These tests qualify deadline propagation and
owned cancellation, not native proof throughput or a live cohort.
"""

import asyncio
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_phase_vote_http as votes
from umi import competition_cohort_review_http as http
from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
)
from umi.competition_cohort_intake import CohortIntakeBinding
from umi.competition_cohort_progress_signer import (
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_recovery import PHASES, CohortRecoveryTransition, PhaseTarget
from umi.competition_cohort_review_budget import PhaseReviewBudget
from umi.competition_execution import ExecutionBoundary
from umi.concurrency import run_owned_thread, wait_for_owned
from umi.open_competition import digest, sign_object
from umi.protocol import StrictProtocolModel, canonical_json_bytes

from .test_open_competition import policy as policy
from .test_open_competition import wallet

TOKEN = "private-synthetic-token-" * 2
SCALE = 0.0001


class ReadRequest(StrictProtocolModel):
    progress: CohortPhaseProgress


class ReviewRecord(StrictProtocolModel):
    history_sha256: str


@pytest.fixture
def configured(policy, tmp_path, monkeypatch):
    async def scaled(coroutine, *, timeout):
        return await wait_for_owned(coroutine, timeout=timeout * SCALE)

    monkeypatch.setattr(http, "wait_for_owned", scaled)
    monkeypatch.setattr(votes, "wait_for_owned", scaled)
    budget = PhaseReviewBudget(
        schema="umi-cohort-phase-review-budget/1",
        policy_sha256=digest(policy),
        evaluation_runtime_sha256=policy.evaluation_runtime_sha256,
        maximum_aggregate_evidence_bytes=4 * 1024**3,
        export_seconds=1000,
        replay_seconds=1500,
        authority_seconds=100,
        signing_seconds=300,
        transport_seconds=100,
        vote_queue_seconds=1000,
        export_queue_slots=2,
    )
    cohorts = (CohortIntakeBinding(cohort_sha256="11" * 32, authority_sha256="22" * 32),)
    progress = CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=cohorts[0].cohort_sha256,
        recovery_tip_sha256="33" * 32,
        phase="requests",
        observed_at_block=200,
        unavailable_blocks=0,
        completion="complete",
        phase_result_sha256="44" * 32,
        evidence_sha256="55" * 32,
    )
    state = SimpleNamespace(
        policy=policy,
        budget=budget,
        cohorts=cohorts,
        progress=progress,
        exports=0,
        replays=0,
        signs=0,
        replay_hook=lambda: time.sleep(0.1),
    )

    class Exporter:
        maximum_bytes = 1024
        timeout_seconds = budget.export_seconds

        async def respond(self, request):
            assert request.progress == progress
            state.exports += 1
            await asyncio.sleep(0.055)
            return b'{"evidence":"original"}'

    class Reviewer:
        async def read(self, value):
            raw = await wait_for_owned(
                state.fetch(ReadRequest(progress=value)),
                timeout=budget.export_exchange_seconds * SCALE,
            )
            assert raw == b'{"evidence":"original"}'
            state.replays += 1
            await run_owned_thread(state.replay_hook)

        async def review(self, value):
            await self.read(value)
            await self.read(value)
            return ReviewRecord(history_sha256="66" * 32)

        async def decision(self, transition, evidence):
            await self.read(evidence.progress.progress)
            return "66" * 32

    reviewer = Reviewer()
    reviewer.policy, reviewer.cohorts = policy, cohorts

    async def sign(body):
        state.signs += 1
        return sign_object(body, wallet("Dave"))

    state.signer_config = CohortProgressSignerConfig(
        schema="umi-cohort-progress-signer-config/1",
        directory=str(tmp_path / "signer"),
        policy_sha256=digest(policy),
        signer=wallet("Dave").hotkey.ss58_address,
        cohorts=cohorts,
    )
    state.signer = lambda: CohortProgressSigner(state.signer_config, reviewer, sign)
    state.owner = FastAPI()
    state.owner.include_router(
        http.phase_review_routes(Exporter(), token=TOKEN, path="/export", request_model=ReadRequest)
    )
    return state


def decision(state):
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(
            progress=state.progress, signatures=(sign_object(state.progress, wallet("Dave")),)
        ),
        observation=ExecutionBoundary(
            source="verifier_attested_finality",
            block=200,
            block_hash="0x" + "77" * 32,
            state_root="0x" + "88" * 32,
            snapshot_sha256="99" * 32,
            evidence_sha256="aa" * 32,
        ),
    )
    transition = CohortRecoveryTransition(
        schema="umi-cohort-recovery-transition/1",
        cohort_sha256=state.progress.cohort_sha256,
        authority_sha256=state.cohorts[0].authority_sha256,
        sequence=1,
        predecessor_sha256=state.progress.recovery_tip_sha256,
        phase="requests",
        operation="close_phase",
        extension_blocks=None,
        observed_at_block=200,
        evidence_sha256=digest(evidence),
        targets=tuple(
            PhaseTarget(phase=phase, target_block=300 + i) for i, phase in enumerate(PHASES)
        ),
    )
    return transition, evidence


@pytest.mark.parametrize("kind", ["progress", "decision"])
async def test_complete_serial_review_survives_legacy_deadline_and_reopens(configured, kind):
    h = configured
    original = canonical_json_bytes(h.progress)
    app = FastAPI()
    app.include_router(votes.phase_vote_routes(h.signer(), phase="requests", token=TOKEN))
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=h.owner)) as owner_client,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as peer_client,
    ):
        h.fetch = http.PhaseReviewHTTPClient(
            owner_client,
            "https://owner.example",
            token=TOKEN,
            path="/export",
            maximum_bytes=1024,
            timeout_seconds=h.budget.export_exchange_seconds,
        )
        # The old route's 2400-second work budget expires inside serial replay.
        request = votes.ProgressVoteRequest(
            schema="umi-cohort-progress-vote-request/1", progress=h.progress
        )
        response = await peer_client.post(
            "https://reviewer.example/internal/cohorts/requests/votes/progress",
            content=canonical_json_bytes(request),
            headers={"authorization": "Bearer " + TOKEN, "content-type": "application/json"},
        )
        assert response.status_code == 503
        assert h.signs == 0
        signer = h.signer()
        with signer.journal.transaction() as db:
            assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 0
        app = FastAPI()
        app.include_router(
            votes.phase_vote_routes(signer, phase="requests", token=TOKEN, budget=h.budget)
        )
        peer_client._transport = httpx.ASGITransport(app=app)
        peer = votes.PhaseVotePeer(
            peer_client,
            "https://reviewer.example",
            policy=h.policy,
            cohorts=h.cohorts,
            signer=signer.config.signer,
            phase="requests",
            token=TOKEN,
            budget=h.budget,
        )
        h.exports = h.replays = 0
        transition, evidence = decision(h)
        vote = await (
            peer.attest(h.progress) if kind == "progress" else peer.certify(transition, evidence)
        )
        assert h.exports == h.replays == (2 if kind == "progress" else 3)
        assert h.signs == 1

        # Network placement/deadline changes leave the original durable vote reusable.
        async def offline(*args):
            raise AssertionError("committed vote attempted another owner read")

        h.fetch = offline
        reopened = h.signer()
        assert vote == await (
            reopened.attest(h.progress)
            if kind == "progress"
            else reopened.certify(transition, evidence)
        )
        assert canonical_json_bytes(h.progress) == original


async def test_peer_repeated_cancellation_drains_native_replay_before_retry(configured):
    h = configured
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(5)
        finished.set()

    h.replay_hook = blocked
    signer = h.signer()
    app = FastAPI()
    app.include_router(
        votes.phase_vote_routes(signer, phase="requests", token=TOKEN, budget=h.budget)
    )
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=h.owner)) as owner_client,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as peer_client,
    ):
        h.fetch = http.PhaseReviewHTTPClient(
            owner_client,
            "https://owner.example",
            token=TOKEN,
            path="/export",
            maximum_bytes=1024,
            timeout_seconds=h.budget.export_exchange_seconds,
        )
        peer = votes.PhaseVotePeer(
            peer_client,
            "https://reviewer.example",
            policy=h.policy,
            cohorts=h.cohorts,
            signer=signer.config.signer,
            phase="requests",
            token=TOKEN,
            budget=h.budget,
        )
        task = asyncio.create_task(peer.attest(h.progress))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            for _ in range(10):
                await asyncio.sleep(0)
            task.cancel()
            for _ in range(10):
                await asyncio.sleep(0)
            assert signer.serial.locked() and not task.done()
            assert h.signs == 0 and not finished.is_set()
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert finished.is_set() and not signer.serial.locked()
        h.replay_hook = lambda: None
        assert await peer.attest(h.progress)
        assert h.signs == 1


@pytest.mark.parametrize("queue", ["route", "signer"])
async def test_peer_deadline_includes_route_and_shared_signer_queues(configured, queue):
    h = configured
    entered, release = threading.Event(), threading.Event()

    def blocked():
        entered.set()
        assert release.wait(5)

    h.replay_hook = blocked
    signer = h.signer()
    app = FastAPI()
    app.include_router(
        votes.phase_vote_routes(signer, phase="requests", token=TOKEN, budget=h.budget)
    )
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=h.owner)) as owner_client,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as peer_client,
    ):
        h.fetch = http.PhaseReviewHTTPClient(
            owner_client,
            "https://owner.example",
            token=TOKEN,
            path="/export",
            maximum_bytes=1024,
            timeout_seconds=h.budget.export_exchange_seconds,
        )
        common = dict(
            policy=h.policy,
            cohorts=h.cohorts,
            signer=signer.config.signer,
            phase="requests",
            token=TOKEN,
        )
        selected = votes.PhaseVotePeer(
            peer_client, "https://reviewer.example", **common, budget=h.budget
        )
        short = votes.PhaseVotePeer(
            peer_client, "https://reviewer.example", **common, timeout_seconds=300
        )
        first = asyncio.create_task(selected.attest(h.progress))
        transition, evidence = decision(h)
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            # Progress queues outside the route timer; decision acquires its
            # own route but queues on the same signer's lock inside that timer.
            with pytest.raises(asyncio.TimeoutError):
                await (
                    short.attest(h.progress)
                    if queue == "route"
                    else short.certify(transition, evidence)
                )
            assert not first.done() and signer.serial.locked()
            assert h.replays == 1 and h.signs == 0
        finally:
            release.set()
            vote = await first
        assert await selected.attest(h.progress) == vote
        assert h.signs == 1
