"""Native stores/signing/HTTP adoption with synthetic owned finality and keys."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_coordinator import CohortDecisionInput, _choice
from umi.competition_cohort_history_http import (
    CohortHistoryExporter,
    CohortHistoryHTTPClient,
    CohortHistoryReader,
    cohort_history_routes,
)
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_lifecycle import PHASES, CohortLifecycleService
from umi.competition_cohort_participation import (
    CohortParticipationConsent,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_phase_vote_http import phase_vote_routes
from umi.competition_cohort_progress_signer import CohortProgressSigner, CohortProgressSignerConfig
from umi.competition_cohort_readiness import intake_readiness
from umi.competition_cohort_request_rule import prepare_request_tail_adoption
from umi.competition_cohort_request_rule_api import (
    ROOT,
    VOTE_PATH,
    RequestTailAdoptionCommit,
    RequestTailAdoptionPrepare,
    RequestTailAdoptionProposal,
    RequestTailAdoptionReviewer,
    RequestTailAdoptionVotePeer,
    assemble_request_tail_adoption,
    request_tail_adoption_owner_routes,
    request_tail_adoption_vote_routes,
)
from umi.competition_cohort_request_rule_reservation import (
    RequestTailReservationReader,
    request_tail_reservation_routes,
)
from umi.competition_execution import execution_boundary
from umi.competition_reward_decisions import StandingRewardSeries
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .logging_helpers import json_progress_payloads
from .test_competition_cohort_coordinator import Harness
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_request_rule_adoption import original as original
from .test_competition_cohort_standing_phases import standing
from .test_competition_execution import boundary
from .test_open_competition import policy as policy
from .test_open_competition import submission, wallet


@pytest.fixture
def api(original, policy, tmp_path, request):
    history, state = original
    if getattr(request, "param", None) == "endpoint":
        plan = history.plan.model_copy(
            update={"eligible_tracks": ("endpoint",), "service_pool_bps": 10000}
        )
        authority, genesis, state = standing(plan, policy)
        history = history.model_copy(
            update={
                "plan": plan,
                "authority": authority,
                "genesis": genesis,
                "genesis_signatures": signatures(genesis),
            }
        )
    h = Harness(tmp_path, (history.plan, history.authority, state), policy)
    # Production imports the intake's exact certified genesis into control;
    # independently signing the same body changes the immutable history hash.
    h.genesis_signatures = history.genesis_signatures
    h.store.publish_history(history, policy, current_block=h.block)
    h.series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(policy),
        policy_epoch=1,
        manifest_sha256="aa" * 32,
        control_hotkey=wallet("Charlie").hotkey.ss58_address,
        recovery=history.authority,
        cohorts=(history.plan,),
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=100,
        maximum_transaction_lifetime_blocks=100,
        lifetime="until_superseded_or_revoked",
    )
    h.intake = CohortIntake(
        CohortIntakeConfig(
            directory=str(tmp_path / "intake"),
            cohorts=(
                CohortIntakeBinding(
                    cohort_sha256=h.cohort,
                    authority_sha256=digest(history.authority.authority),
                ),
            ),
        ),
        policy,
        eligible_tracks=history.plan.eligible_tracks,
        initialize=True,
    )
    h.intake.publish(history, capture_at(h.block))

    async def publish(value):
        if h.fail_publish_sequence == len(value.transitions):
            raise OSError("publication reply lost")
        h.intake.publish(value, capture_at(h.block))

    async def unused():
        pytest.fail("adoption must not instantiate phase progress")

    def reopen():
        async def sign_history(body):
            return sign_object(body, wallet("Charlie"))

        async def reconcile():
            pending = h.intake.pending_request_tail_adoption(h.cohort)
            if pending is not None:
                h.store.reserve_exact(pending)

        h.node = CohortLifecycleService(
            h.store,
            h.cohort,
            policy,
            h.genesis_signatures,
            h,
            publish,
            {phase: unused for phase in PHASES},
            before_tick=reconcile,
        )
        h.host = SimpleNamespace(
            service=SimpleNamespace(
                config=SimpleNamespace(
                    series=h.series,
                    admission_owner=SimpleNamespace(
                        owner_hotkey=wallet("Charlie").hotkey.ss58_address
                    ),
                ),
                intake=h.intake,
            ),
            nodes={h.cohort: h.node},
            policy=policy,
            provider=h,
            timeout_seconds=30,
            sign=sign_history,
        )
        h.app = FastAPI()
        h.app.include_router(request_tail_adoption_owner_routes(h.host, token="o" * 32))

        h.app.include_router(
            cohort_history_routes(
                CohortHistoryExporter(
                    h.intake, wallet("Charlie").hotkey.ss58_address, sign_history
                ),
                token="h" * 32,
            )
        )
        h.app.include_router(request_tail_reservation_routes(h.host, token="h" * 32))

    async def current_finalized_block():
        if h.fail_collect:
            raise OSError("synthetic owned finality unavailable")
        return h.block

    h.current_finalized_block = current_finalized_block
    h.reopen = reopen
    reopen()
    yield h
    h.db.close()


async def post(client, path, value, token="o" * 32):
    return await client.post(
        path,
        content=canonical_json_bytes(value),
        headers={
            "content-type": "application/json",
            "authorization": "Bearer " + token,
        },
    )


def proposal(h, block=220):
    return RequestTailAdoptionProposal(
        schema="umi-request-tail-adoption-proposal/1",
        series_sha256=digest(h.series),
        transition=prepare_request_tail_adoption(
            h.store.export_history(h.cohort, genesis_signatures=h.genesis_signatures),
            h.policy,
            boundary(block),
        ),
    )


def test_exact_reservation_refuses_same_phase_race_and_wrong_bytes(api):
    h = api
    first = proposal(h)
    h.store.commit(signed_transition(first.transition))
    changed = first.transition.model_copy(update={"observed_at_block": 221})
    with pytest.raises(ValueError, match="conflicts"):
        h.store.reserve_exact(changed)
    assert h.store.status(h.cohort)[1] is None
    assert h.store.reserve_exact(first.transition) == first.transition


async def test_normal_pending_is_preserved_and_no_adoption_is_inserted(api):
    h = api
    p = proposal(h)
    h.block = 500
    h.complete = True
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=await h.observe(h.state, await h.collect()),
        observation=execution_boundary(await h.collect()),
    )
    ordinary, _ = _choice(h.state, h.authority.authority, h.policy, evidence, 0, 0)
    h.store.reserve_exact(ordinary)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        assert (await post(client, ROOT + "/reserve", p)).status_code == 503
    assert h.intake.pending_request_tail_adoption(h.cohort) is None
    with pytest.raises(ValueError, match="conflicts"):
        h.store.reserve_exact(p.transition)
    assert h.store.status(h.cohort)[1] == ordinary


async def test_owner_prepare_reserve_certificate_publication_restart_and_lost_ack(api):
    h = api
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        prepare = RequestTailAdoptionPrepare(
            schema="umi-request-tail-adoption-prepare/1",
            series_sha256=digest(h.series),
            cohort_sha256=h.cohort,
            predecessor_sha256=h.state.tip_sha256,
        )
        assert (await post(client, ROOT + "/prepare", prepare, token="h" * 32)).status_code == 401
        response = await post(client, ROOT + "/prepare", prepare)
        assert response.status_code == 200
        p = RequestTailAdoptionProposal.model_validate_json(response.content)
        assert h.store.status(h.cohort)[1] is None
        assert (await post(client, ROOT + "/reserve", p)).content == response.content
        signed = signed_transition(p.transition)
        commit = RequestTailAdoptionCommit(
            schema="umi-request-tail-adoption-commit/1",
            series_sha256=digest(h.series),
            certificate=signed,
        )
        h.fail_publish_sequence = 1
        assert (await post(client, ROOT + "/commit", commit)).status_code == 503
        assert h.state.sequence == 1
    h.restart()
    h.reopen()
    h.fail_publish_sequence = None
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        assert (await post(client, ROOT + "/reserve", p)).content == canonical_json_bytes(p)
        assert (await post(client, ROOT + "/commit", commit)).status_code == 200
        assert (await post(client, ROOT + "/commit", commit)).status_code == 200
    assert h.intake.history(h.cohort).transitions == (signed,)
    assert h.state.phase == "intake" and h.state.targets == original_targets(h)


def original_targets(h):
    from umi.competition_cohort_recovery import admit_recoverable_cohort

    return admit_recoverable_cohort(h.plan, h.authority, h.policy, admitted_at_block=160)[1].targets


async def test_native_owner_history_review_votes_restart_and_phase_slot_conflict(api, tmp_path):
    h = api
    p = proposal(h)
    h.intake.reserve_request_tail_adoption(p.transition)
    h.store.reserve_exact(p.transition)
    h.sign_calls = []
    h.sign_failure_once = {"Charlie"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=h.app)) as owner_client:
        history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(owner_client, "https://owner.example", token="h" * 32),
        )
        reviewer = SimpleNamespace(
            policy=h.policy,
            cohorts=h.intake.config.cohorts,
            adoption=RequestTailAdoptionReviewer(
                h.series,
                h.policy,
                h,
                history,
                RequestTailReservationReader(
                    owner_client,
                    "https://owner.example",
                    token="h" * 32,
                    owner=wallet("Charlie").hotkey.ss58_address,
                ),
            ),
        )

        def make_signer(name):
            async def sign(body):
                h.sign_calls.append((name, digest(body)))
                if name in h.sign_failure_once:
                    h.sign_failure_once.remove(name)
                    raise OSError("native signing reply lost")
                return sign_object(body, wallet(name))

            return CohortProgressSigner(
                CohortProgressSignerConfig(
                    schema="umi-cohort-progress-signer-config/1",
                    directory=str(tmp_path / name),
                    policy_sha256=digest(h.policy),
                    signer=wallet(name).hotkey.ss58_address,
                    cohorts=h.intake.config.cohorts,
                ),
                reviewer,
                sign,
            )

        votes = []
        for name in ("Charlie", "Dave"):
            app = FastAPI()
            signer = make_signer(name)
            app.include_router(request_tail_adoption_vote_routes(signer, h.series, token="v" * 32))
            app.include_router(phase_vote_routes(signer, phase="intake", token="v" * 32))
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://review.example"
            ) as client:
                peer = RequestTailAdoptionVotePeer(
                    client,
                    "https://review.example",
                    signer=wallet(name).hotkey.ss58_address,
                    token="v" * 32,
                )
                if name == "Charlie":
                    with pytest.raises(OSError):
                        await peer.certify(p)
                    h.block += 1
                votes.append(await peer.certify(p))
                assert await peer.certify(p) == votes[-1]
                assert (await post(client, VOTE_PATH, p, token="o" * 32)).status_code == 401
                assert (
                    await post(
                        client,
                        "/internal/cohorts/intake/votes/decision",
                        {
                            "schema": "umi-cohort-decision-vote-request/1",
                            "transition": p.transition.model_dump(mode="json", by_alias=True),
                        },
                        token="v" * 32,
                    )
                ).status_code == 422
        signed = assemble_request_tail_adoption(p, reversed(votes), h.policy)
        assert signed.transition == p.transition and len(signed.signatures) == 2
        h.fail_collect = True
        assert await make_signer("Charlie").certify_request_tail_adoption(p.transition) == votes[0]
        assert len(h.sign_calls) == 3
        h.fail_collect = False
        h.block, h.complete = 500, True
        capture = await h.collect()
        evidence = CohortDecisionInput(
            schema="umi-cohort-decision-input/1",
            progress=await h.observe(h.state, capture),
            observation=execution_boundary(capture),
        )
        ordinary, _ = _choice(h.state, h.authority.authority, h.policy, evidence, 0, 0)
        with pytest.raises(ValueError, match="progress-backed"):
            await make_signer("Charlie").certify(p.transition, evidence)
        with pytest.raises(ValueError, match="reserved for another body"):
            await make_signer("Charlie").certify(ordinary, evidence)
        assert len(h.sign_calls) == 3


async def test_independent_review_rejects_changed_tip_before_signing(api):
    h = api
    p = proposal(h)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=h.app)) as client:
        history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(client, "https://owner.example", token="h" * 32),
        )
        review = RequestTailAdoptionReviewer(
            h.series,
            h.policy,
            h,
            history,
            RequestTailReservationReader(
                client,
                "https://owner.example",
                token="h" * 32,
                owner=wallet("Charlie").hotkey.ss58_address,
            ),
        )
        changed = p.transition.model_copy(update={"predecessor_sha256": "aa" * 32})
        with pytest.raises(ValueError, match="differs"):
            await review(changed)
        h.block = 219
        with pytest.raises(ValueError, match="ahead"):
            await review(p.transition)


async def test_lost_signature_intent_refuses_changed_adoption_and_recovers_exact(api, tmp_path):
    h = api
    p = proposal(h)
    reviews, attempts = [], []

    async def reviewed(transition):
        reviews.append(digest(transition))
        return {"reviewed": digest(transition)}

    async def lost_reply(body):
        attempts.append(digest(body))
        if len(attempts) == 1:
            raise OSError("signing response lost")
        return sign_object(body, wallet("Charlie"))

    config = CohortProgressSignerConfig(
        schema="umi-cohort-progress-signer-config/1",
        directory=str(tmp_path / "lost-vote"),
        policy_sha256=digest(h.policy),
        signer=wallet("Charlie").hotkey.ss58_address,
        cohorts=h.intake.config.cohorts,
    )
    reviewer = SimpleNamespace(policy=h.policy, cohorts=h.intake.config.cohorts, adoption=reviewed)
    first = CohortProgressSigner(config, reviewer, lost_reply)
    with pytest.raises(OSError, match="lost"):
        await first.certify_request_tail_adoption(p.transition)
    restarted = CohortProgressSigner(config, reviewer, lost_reply)
    changed = p.transition.model_copy(update={"observed_at_block": 221})
    with pytest.raises(ValueError, match="reserved for another body"):
        await restarted.certify_request_tail_adoption(changed)
    vote = await restarted.certify_request_tail_adoption(p.transition)
    assert vote == await restarted.certify_request_tail_adoption(p.transition)
    assert attempts == reviews == [digest(p.transition)] * 2


async def test_intake_first_reservation_recovers_before_any_lifecycle_progress(api):
    h = api
    p = proposal(h)
    h.intake.reserve_request_tail_adoption(p.transition)
    assert h.store.status(h.cohort)[1] is None
    original_history = h.intake.history(h.cohort)
    h.restart()
    h.reopen()
    h.fail_publish_sequence = 0  # A gated predecessor must not be republished.
    for _ in range(2):
        assert (await h.node.tick())["status"] == "awaiting_request_tail_adoption_certificate"
    assert h.store.status(h.cohort)[1] == p.transition
    assert h.intake.pending_request_tail_adoption(h.cohort) == p.transition
    assert h.intake.history(h.cohort) == original_history
    assert h.collects == 0


async def test_reservation_is_unavailable_service_and_unreserved_vote_is_refused(api):
    h = api
    p = proposal(h)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=h.app)) as client:
        reservation = RequestTailReservationReader(
            client,
            "https://owner.example",
            token="h" * 32,
            owner=wallet("Charlie").hotkey.ss58_address,
        )
        with pytest.raises(OSError):
            await reservation(p.transition, h.intake.history(h.cohort))
        h.intake.reserve_request_tail_adoption(p.transition)
        # An intake-only crash state is still not a signable dual reservation.
        with pytest.raises(OSError):
            await reservation(p.transition, h.intake.history(h.cohort))
        h.store.reserve_exact(p.transition)
        original_transport, retained = reservation.transport, []

        async def capture(request):
            raw = await original_transport(request)
            retained.append(raw)
            return raw

        reservation.transport = capture
        await reservation(p.transition, h.intake.history(h.cohort))

        async def replay(request):
            return retained[0]

        reservation.transport = replay
        with pytest.raises(ValueError, match="challenge"):
            await reservation(p.transition, h.intake.history(h.cohort))
    ready = intake_readiness(
        h.intake, h.cohort, capture_at(220), nonce="aa" * 16, archive_available=True
    )
    assert not ready.ready and ready.reason_code == "fenced"
    phase = CohortIntakePhaseObserver(h.intake)
    receipt = phase.sample_service(h.state, capture_at(220), serving=True)
    assert receipt is not None and not receipt.serving
    progress = phase.observe(
        h.cohort, capture_at(221), serving=True, expected_tip_sha256=h.state.tip_sha256
    )
    assert progress.progress.completion == "pending" and not progress.service.serving


async def test_ordinary_certificate_prevents_adoption_vote_after_signer_restart(api, tmp_path):
    h = api
    p = proposal(h)
    h.block, h.complete = 500, True
    capture = await h.collect()
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=await h.observe(h.state, capture),
        observation=execution_boundary(capture),
    )
    ordinary, _ = _choice(h.state, h.authority.authority, h.policy, evidence, 0, 0)
    reviewed_history = digest(h.intake.history(h.cohort))

    async def review(progress):
        assert progress == evidence.progress.progress
        return SimpleNamespace(
            history_sha256=reviewed_history,
            model_dump=lambda **_: {"history_sha256": reviewed_history},
        )

    async def decision(transition, retained):
        assert transition == ordinary and retained == evidence
        return reviewed_history

    async def adoption(transition):
        pytest.fail("another phase decision already owns the signing slot")

    calls = []

    async def sign(body):
        calls.append(digest(body))
        return sign_object(body, wallet("Charlie"))

    config = CohortProgressSignerConfig(
        schema="umi-cohort-progress-signer-config/1",
        directory=str(tmp_path / "ordinary-first"),
        policy_sha256=digest(h.policy),
        signer=wallet("Charlie").hotkey.ss58_address,
        cohorts=h.intake.config.cohorts,
    )
    reviewer = SimpleNamespace(
        policy=h.policy,
        cohorts=h.intake.config.cohorts,
        review=review,
        decision=decision,
        adoption=adoption,
    )
    await CohortProgressSigner(config, reviewer, sign).certify(ordinary, evidence)
    with pytest.raises(ValueError, match="reserved for another body"):
        await CohortProgressSigner(config, reviewer, sign).certify_request_tail_adoption(
            p.transition
        )
    assert calls == [digest(ordinary)]


@pytest.mark.parametrize("api", ["endpoint"], indirect=True)
async def test_native_sealed_intake_refuses_adoption_without_reopening_membership(api):
    h = api
    signed = submission(h.policy)
    consent = CohortParticipationConsent(
        schema="umi-cohort-participation-consent/1",
        cohort_sha256=h.cohort,
        authority_sha256=digest(h.authority.authority),
        submission_sha256=digest(signed.submission),
        hotkey=signed.submission.hotkey,
        signed_at_block=210,
        lifetime="until_cohort_completed_or_revoked",
        timing_rule="quorum_recovery_history/1",
        original_submission_expiry_does_not_end_participation=True,
    )
    request = CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )
    receipt = h.intake.retain(request, capture_at(210))
    phase = CohortIntakePhaseObserver(h.intake)
    for block in range(200, 301, 5):
        progress = phase.observe(
            h.cohort, capture_at(block), serving=True, expected_tip_sha256=h.state.tip_sha256
        )
    assert progress.seal is not None
    h.block = 350
    p = proposal(h, 350)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        assert (await post(client, ROOT + "/reserve", p)).status_code == 503
    assert h.store.status(h.cohort)[1] is None
    assert h.intake.pending_request_tail_adoption(h.cohort) is None
    assert h.intake.sealed(h.cohort) == progress.seal
    assert h.intake.receipt(request) == receipt


async def test_profile_covers_slow_history_finality_reservation_and_complete_vote(
    api, tmp_path, caplog, monkeypatch
):
    """Every staged delay exceeds the legacy scalar; native proof/signature checks remain."""
    import asyncio
    import logging

    from umi import competition_work_progress as progress
    from umi.competition_cohort_review_budget import PhaseReviewBudget

    h = api
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    monkeypatch.setattr(progress, "_HEARTBEAT_SECONDS", 0.05)
    p = proposal(h)
    h.intake.reserve_request_tail_adoption(p.transition)
    h.store.reserve_exact(p.transition)
    budget = PhaseReviewBudget(
        schema="umi-cohort-phase-review-budget/1",
        policy_sha256=digest(h.policy),
        evaluation_runtime_sha256=h.policy.evaluation_runtime_sha256,
        maximum_aggregate_evidence_bytes=4 * 1024**3,
        export_seconds=2,
        replay_seconds=2,
        authority_seconds=2,
        signing_seconds=1,
        transport_seconds=1,
        vote_queue_seconds=1,
        export_queue_slots=2,
    )
    stages = []

    async def owned_block():
        stages.append("owned_height")
        await asyncio.sleep(1.05)
        return h.block

    async def forbidden_membership():
        pytest.fail("adoption must use verified owned height, never membership collection")

    h.current_finalized_block = owned_block
    h.collect = forbidden_membership

    async def delayed_owner_sign(body):
        stages.append("history" if hasattr(body, "source") else "reservation")
        await asyncio.sleep(1.05)
        return sign_object(body, wallet("Charlie"))

    h.host.sign = delayed_owner_sign
    h.host.timeout_seconds = budget.export_seconds
    owner_app = FastAPI()
    owner_app.include_router(
        cohort_history_routes(
            CohortHistoryExporter(
                h.intake,
                wallet("Charlie").hotkey.ss58_address,
                delayed_owner_sign,
                timeout_seconds=budget.export_seconds,
            ),
            token="h" * 32,
        )
    )
    owner_app.include_router(request_tail_reservation_routes(h.host, token="h" * 32))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=owner_app)) as owner_client:
        native_history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(
                owner_client,
                "https://owner.example",
                token="h" * 32,
                timeout_seconds=budget.export_exchange_seconds,
            ),
            timeout_seconds=budget.export_exchange_seconds,
        )
        native_reservation = RequestTailReservationReader(
            owner_client,
            "https://owner.example",
            token="h" * 32,
            owner=wallet("Charlie").hotkey.ss58_address,
            timeout_seconds=budget.export_exchange_seconds,
            complete_exchange=True,
        )

        reviewer = SimpleNamespace(
            policy=h.policy,
            cohorts=h.intake.config.cohorts,
            adoption=RequestTailAdoptionReviewer(
                h.series, h.policy, h, native_history, native_reservation, budget=budget
            ),
        )

        async def sign(body):
            stages.append("sign")
            return sign_object(body, wallet("Charlie"))

        config = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(tmp_path / "profile-signer"),
            policy_sha256=digest(h.policy),
            signer=wallet("Charlie").hotkey.ss58_address,
            cohorts=h.intake.config.cohorts,
            signing_timeout_seconds=1,
        )
        signer = CohortProgressSigner(config, reviewer, sign)
        app = FastAPI()
        app.include_router(
            request_tail_adoption_vote_routes(
                signer, h.series, token="v" * 32, timeout_seconds=1, budget=budget
            )
        )
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
            peer = RequestTailAdoptionVotePeer(
                client,
                "https://review.example",
                signer=config.signer,
                token="v" * 32,
                timeout_seconds=1,
                policy=h.policy,
                budget=budget,
            )
            assert peer.timeout_seconds == peer.transport.timeout_seconds == 25
            vote = await peer.certify(p)
            assert stages == ["history", "owned_height", "history", "reservation", "sign"]
            assert vote.hotkey == config.signer
            # The actual signed proposal and durable vote are reused unchanged.
            assert await peer.certify(p) == vote
            assert stages == ["history", "owned_height", "history", "reservation", "sign"]
            assert h.store.status(h.cohort)[1] == p.transition
    events = json_progress_payloads(
        caplog.records,
        logger="umi.competition.progress",
        schema=("umi-competition-work-progress/1", "umi-competition-phase/1"),
    )
    expected = {
        "adoption_history_before",
        "adoption_history_replay",
        "adoption_owned_finality",
        "adoption_history_after",
        "adoption_reservation_proof",
    }
    assert expected <= {e.get("stage") for e in events if e.get("state") == "completed"}
    waiting = [e for e in events if e.get("state") == "waiting"]
    assert {
        "adoption_history_before",
        "adoption_owned_finality",
        "adoption_history_after",
        "adoption_reservation_proof",
    } <= {e["stage"] for e in waiting}
    assert all(e["eta_seconds"] is None and e["percent"] == 0 for e in waiting)
    assert all(e["elapsed_seconds"] > 0 for e in waiting)
    assert any(e.get("phase") == "cohort_request_tail_adoption_vote" for e in events)


@pytest.mark.parametrize("failure", ["owned_finality", "lost_reply"])
async def test_native_owned_height_publication_recovers_exact_committed_adoption(api, failure):
    from umi.competition_cohort_intake import CohortIntakePublisher
    from umi.competition_cohort_lifecycle_host import LifecycleHost

    from .test_competition_cohort_review_budget import profile

    h = api
    original = canonical_json_bytes(h.intake.history(h.cohort))
    p = proposal(h, block=h.block)
    h.host.service.config.admission_owner.phase_review_budget = profile(h.policy)
    fail = True

    async def owned_height():
        if fail and failure == "owned_finality":
            raise OSError("fresh owned finality unavailable")
        return h.block

    async def forbidden_membership():
        pytest.fail("profile-selected publication must not collect membership")

    h.current_finalized_block, h.collect = owned_height, forbidden_membership
    native = CohortIntakePublisher(
        h.intake, h.collect, current_block=lambda: LifecycleHost._publication_block(h.host)
    )

    async def publish(history):
        await native(history)
        if fail:
            raise OSError("publication acknowledgement lost")

    h.node.publish_history = publish
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        # Reservation needs fresh finality before introducing any durable intent.
        fail = False
        assert (await post(client, ROOT + "/reserve", p)).status_code == 200
        fail = True
        signed = signed_transition(p.transition)
        commit = RequestTailAdoptionCommit(
            schema="umi-request-tail-adoption-commit/1",
            series_sha256=digest(h.series),
            certificate=signed,
        )
        assert (await post(client, ROOT + "/commit", commit)).status_code == 503
        assert h.store.status(h.cohort)[1] is None  # Native commit preceded publication.
        if failure == "owned_finality":
            assert canonical_json_bytes(h.intake.history(h.cohort)) == original
            assert h.intake.pending_request_tail_adoption(h.cohort) == p.transition
        else:
            assert h.intake.history(h.cohort).transitions == (signed,)
        fail = False
        first = await post(client, ROOT + "/commit", commit)
        assert first.status_code == 200
        assert (await post(client, ROOT + "/commit", commit)).content == first.content
    assert h.intake.history(h.cohort).transitions == (signed,)
    assert h.intake.pending_request_tail_adoption(h.cohort) is None
    assert h.state.targets == original_targets(h)


async def test_adoption_replay_keeps_event_loop_live_and_drains_before_unlock(api, tmp_path):
    import asyncio
    import threading

    h = api
    p = proposal(h, block=h.block)
    entered, release = threading.Event(), threading.Event()
    source = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, None).read(
        h.cohort
    )

    async def history(_):
        return source

    async def forbidden(*_):
        pytest.fail("cancelled review cannot reserve or sign")

    adoption = RequestTailAdoptionReviewer(h.series, h.policy, h, history, forbidden)
    native_replay = adoption._replay
    loop_thread = threading.get_ident()

    def blocked(value):
        assert threading.get_ident() != loop_thread
        entered.set()
        assert release.wait(5)
        return native_replay(value)

    adoption._replay = blocked
    config = CohortProgressSignerConfig(
        schema="umi-cohort-progress-signer-config/1",
        directory=str(tmp_path / "cancel-vote"),
        policy_sha256=digest(h.policy),
        signer=wallet("Charlie").hotkey.ss58_address,
        cohorts=h.intake.config.cohorts,
    )
    signer = CohortProgressSigner(
        config,
        SimpleNamespace(policy=h.policy, cohorts=h.intake.config.cohorts, adoption=adoption),
        forbidden,
    )
    task = asyncio.create_task(signer.certify_request_tail_adoption(p.transition))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and signer.serial.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not signer.serial.locked()
    slot = digest({"cohort": h.cohort, "tip": p.transition.predecessor_sha256})
    assert signer.journal.get("phase_decision_intent", slot) is None
    assert signer.journal.get("phase_decision_vote", slot) is None


@pytest.mark.parametrize("selected_profile", [False, True])
async def test_real_lifecycle_node_seeds_and_publishes_with_selected_finality(
    api, tmp_path, selected_profile
):
    from contextlib import ExitStack

    from umi.competition_cohort_lifecycle_host import LifecycleHost

    from .test_competition_cohort_review_budget import profile

    h = api
    assert h.plan.sequence > 5
    original = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, None).read(
        h.cohort
    )
    calls = []
    failed = selected_profile

    async def history(_):
        return original

    async def owned_height():
        calls.append("height")
        if failed:
            raise OSError("owned height unavailable")
        return h.block

    async def membership():
        calls.append("membership")
        assert not selected_profile
        return capture_at(h.block)

    h.host.service.config.admission_owner.phase_review_budget = (
        profile(h.policy) if selected_profile else None
    )
    h.host.service.history = history
    h.current_finalized_block, h.collect = owned_height, membership
    host = LifecycleHost.__new__(LifecycleHost)
    host.service, host.policy, host.provider = h.host.service, h.policy, h
    host.config = SimpleNamespace(maximum_state_bytes=1024**3)
    host.root, host.nodes, host.stores, host.gate = tmp_path / "native-lifecycle", {}, {}, None
    with ExitStack() as host.resources:
        if selected_profile:
            with pytest.raises(OSError, match="owned height"):
                await host.node(h.cohort)
            assert not host.stores[h.cohort].has_published_history(h.cohort)
            assert h.cohort not in host.nodes
            assert calls == ["height"]
            calls.clear()
            failed = False
        node = await host.node(h.cohort)
        assert (node.publish_history.current_block is not None) == selected_profile
        await node._publish(original.history)
        assert calls == (["height", "height"] if selected_profile else ["membership"] * 2)
        assert canonical_json_bytes(host.stores[h.cohort].published_history(h.cohort)) == (
            canonical_json_bytes(original.history)
        )
        assert canonical_json_bytes(h.intake.history(h.cohort)) == canonical_json_bytes(
            original.history
        )


async def test_profile_reservation_exchange_timeout_drains_its_owned_transport(api):
    import asyncio

    h = api
    p = proposal(h)
    cleaning, release = asyncio.Event(), asyncio.Event()

    class Transport:
        timeout_seconds = 0.02  # Synthetic clock-scale I/O budget.

        async def __call__(self, request):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleaning.set()
                await release.wait()
                raise

    reader = RequestTailReservationReader(
        None,
        "https://owner.example",
        token="h" * 32,
        owner=wallet("Charlie").hotkey.ss58_address,
        complete_exchange=True,
    )
    reader.transport = Transport()
    task = asyncio.create_task(reader(p.transition, h.intake.history(h.cohort)))
    try:
        await asyncio.wait_for(cleaning.wait(), timeout=1)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.TimeoutError):
        await task


def test_adoption_route_and_peer_reject_incompatible_selected_profile(api):
    from .test_competition_cohort_review_budget import profile

    h = api
    budget = profile(h.policy)
    peer = dict(signer=wallet("Charlie").hotkey.ss58_address, token="v" * 32)
    with pytest.raises(ValueError, match="selected policy"):
        RequestTailAdoptionVotePeer(None, "https://review.example", budget=budget, **peer)
    bad = budget.model_copy(update={"evaluation_runtime_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="runtime"):
        RequestTailAdoptionVotePeer(
            None, "https://review.example", policy=h.policy, budget=bad, **peer
        )
    signer = SimpleNamespace(
        policy=h.policy, config=SimpleNamespace(signing_timeout_seconds=budget.signing_seconds + 1)
    )
    with pytest.raises(ValueError, match="signing"):
        request_tail_adoption_vote_routes(signer, h.series, token="v" * 32, budget=budget)


@pytest.mark.parametrize("kind", ["prepare", "reserve"])
async def test_owned_finality_failure_refuses_control_without_membership_fallback(api, kind):
    h = api

    async def failed():
        raise ValueError("owned finalized head failed freshness or rollback checks")

    async def forbidden():
        pytest.fail("an unavailable owned height cannot fall back to membership/RPC labels")

    h.current_finalized_block, h.collect = failed, forbidden
    value = (
        proposal(h)
        if kind == "reserve"
        else RequestTailAdoptionPrepare(
            schema="umi-request-tail-adoption-prepare/1",
            series_sha256=digest(h.series),
            cohort_sha256=h.cohort,
            predecessor_sha256=h.state.tip_sha256,
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        assert (await post(client, ROOT + "/" + kind, value)).status_code == 503
    assert h.store.status(h.cohort)[1] is None
    assert h.intake.pending_request_tail_adoption(h.cohort) is None
