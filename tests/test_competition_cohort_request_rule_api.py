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
