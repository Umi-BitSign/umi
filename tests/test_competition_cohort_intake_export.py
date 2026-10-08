"""Independent intake review over owner exports; native proofs, synthetic chain."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    _choice,
    replay_cohort_decisions,
)
from umi.competition_cohort_history_http import (
    CohortHistoryExporter,
    CohortHistoryHTTPClient,
    CohortHistoryReader,
    SignedCohortHistoryResponse,
    cohort_history_routes,
)
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_export import (
    IntakeReviewExporter,
    IntakeReviewRequest,
    RemoteIntakeProgressReviewer,
    SignedIntakeReviewResponse,
    replay_intake_export,
)
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_intake_review import NativeIntakeProgressSource
from umi.competition_cohort_intake_review_http import (
    PATH,
    IntakeReviewHTTPClient,
    intake_review_routes,
)
from umi.competition_cohort_progress_signer import CohortProgressSigner, CohortProgressSignerConfig
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_consumers import scenario as legacy_scenario  # noqa: F401
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_intake_phase import healthy
from .test_competition_cohort_intake_phase import phase as phase
from .test_competition_cohort_lifecycle import scenario as standing_scenario  # noqa: F401
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_historical_registration import archive as archive
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture(params=["legacy", "standing"])
def scenario(request):
    return request.getfixturevalue(request.param + "_scenario")


@pytest.fixture
def remote(archive, accepted, tmp_path):
    a = archive
    config, history, _, _receipt = accepted
    intake = CohortIntake(config, a.chain.policy)
    phase = CohortIntakePhaseObserver(intake)
    cohort = digest(history.plan)
    for block in range(a.old.height - 100, a.old.height, 5):
        phase.observe(
            cohort, capture_at(block), serving=True, expected_tip_sha256=history_tip(history)
        )
    result = phase.observe(
        cohort, a.capture, serving=True, expected_tip_sha256=history_tip(history)
    )
    assert result.seal is not None
    h = SimpleNamespace(
        archive=a,
        intake=intake,
        phase=phase,
        history=history,
        result=result,
        requests=[],
        calls=[],
        offline=False,
        fail_sign=False,
    )
    source = NativeIntakeProgressSource(intake)
    owner = wallet("Charlie").hotkey.ss58_address

    async def owner_sign(body):
        return sign_object(body, wallet("Charlie"))

    h.exporter = IntakeReviewExporter(source, owner, owner_sign)

    async def fetch(request):
        if h.offline:
            raise OSError("owner unavailable")
        h.requests.append(request)
        return await h.exporter.respond(request)

    async def proofs(expected):
        assert expected == a.expected
        return a.raw, a.metadata

    h.reviewer = RemoteIntakeProgressReviewer(a.reviewer, config.cohorts, owner, fetch, proofs)
    h.exported = h.exporter.export(result.progress)

    def signer():
        async def sign(body):
            h.calls.append(body)
            if h.fail_sign:
                raise OSError("signature reply lost")
            return sign_object(body, wallet("Dave"))

        return CohortProgressSigner(
            CohortProgressSignerConfig(
                schema="umi-cohort-progress-signer-config/1",
                directory=str(tmp_path / "reviewer-signing"),
                policy_sha256=digest(a.chain.policy),
                signer=wallet("Dave").hotkey.ss58_address,
                cohorts=config.cohorts,
            ),
            h.reviewer,
            sign,
        )

    h.signer = signer
    return h


async def test_owner_history_http_returns_original_published_decisions(remote):
    from fastapi import FastAPI

    h = remote

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    exporter = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, sign)
    app = FastAPI()
    app.include_router(cohort_history_routes(exporter, token="h" * 32))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        fetch = CohortHistoryHTTPClient(client, "https://owner.example", token="h" * 32)
        reader = CohortHistoryReader(wallet("Charlie").hotkey.ss58_address, fetch)
        source = await reader(digest(h.history.plan))
        assert source.history == h.intake.history(digest(h.history.plan))
        assert source.inputs().keys() == {
            t.transition.evidence_sha256
            for t in source.history.transitions
            if t.transition.operation != "revoke"
        }
        fetch.token = "x" * 32
        with pytest.raises(OSError):
            await reader(digest(h.history.plan))


@pytest.mark.parametrize("fault", ["challenge", "signer", "signature", "canonical", "decisions"])
async def test_owner_history_rejects_replayed_or_modified_export(remote, fault):
    h = remote

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    exporter = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, sign)

    async def fetch(request):
        raw = await exporter.respond(request)
        if fault == "canonical":
            return b" " + raw
        value = SignedCohortHistoryResponse.model_validate_json(raw)
        response, signature = value.response, value.signature
        if fault == "challenge":
            response = response.model_copy(update={"challenge": "aa" * 32})
            signature = sign_object(response, wallet("Charlie"))
        elif fault == "signer":
            signature = sign_object(response, wallet("Dave"))
        elif fault == "signature":
            signature = sign_object(
                response.model_copy(update={"challenge": "aa" * 32}), wallet("Charlie")
            )
        else:
            extra = CohortDecisionInput(
                schema="umi-cohort-decision-input/1",
                progress=AttestedCohortPhaseProgress(
                    progress=h.result.progress, signatures=signatures(h.result.progress)
                ),
                observation=execution_boundary(h.archive.capture),
            )
            response = response.model_copy(
                update={
                    "source": response.source.model_copy(
                        update={"decisions": (*response.source.decisions, extra)}
                    )
                }
            )
            signature = sign_object(response, wallet("Charlie"))
        return canonical_json_bytes(
            SignedCohortHistoryResponse(response=response, signature=signature)
        )

    reader = CohortHistoryReader(wallet("Charlie").hotkey.ss58_address, fetch)
    with pytest.raises(ValueError):
        await reader(digest(h.history.plan))


async def test_remote_native_proof_review_matches_owner_and_retains_offline_vote(remote):
    h = remote
    before = len(h.archive.chain.verifier.checked)
    result = await h.reviewer.review(h.result.progress)
    assert result == h.exporter.source.read(h.result.progress).record
    assert len(h.archive.chain.verifier.checked) > before
    assert len(h.requests) == 2 and h.requests[0].challenge != h.requests[1].challenge
    vote = await h.signer().attest(h.result.progress)
    h.offline = True
    assert await h.signer().attest(h.result.progress) == vote
    assert len(h.calls) == 1
    assert not hasattr(h.reviewer, "intake") and not hasattr(h.reviewer, "source")


async def test_remote_exact_transition_uses_durable_signer(remote):
    h = remote
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(
            progress=h.result.progress, signatures=signatures(h.result.progress)
        ),
        observation=execution_boundary(h.archive.capture),
    )
    state, restored, prior = replay_cohort_decisions(h.history, h.intake.policy, lambda _: None)
    body, _ = _choice(
        state, h.history.authority.authority, h.intake.policy, evidence, restored, prior
    )
    vote = await h.signer().certify(body, evidence)
    assert len(h.requests) == 3
    h.offline = True
    assert await h.signer().certify(body, evidence) == vote
    assert len(h.calls) == 1


async def test_lost_signature_retries_original_body_without_expiry(remote):
    h = remote
    h.fail_sign = True
    with pytest.raises(OSError, match="reply lost"):
        await h.signer().attest(h.result.progress)
    h.fail_sign = False
    await h.signer().attest(h.result.progress)
    assert h.calls == [h.result.progress, h.result.progress]


@pytest.mark.parametrize(
    "failure", ["owner", "challenge", "signature", "bytes", "authority", "progress"]
)
async def test_unauthenticated_or_misbound_response_never_touches_proof_port(remote, failure):
    h = remote

    async def fetch(request):
        raw = await h.exporter.respond(request)
        value = SignedIntakeReviewResponse.model_validate_json(raw)
        response = value.response
        if failure == "owner":
            value = value.model_copy(update={"signature": sign_object(response, wallet("Dave"))})
        elif failure == "signature":
            value = value.model_copy(update={"signature": sign_object(request, wallet("Charlie"))})
        elif failure == "bytes":
            return raw + b" "
        else:
            if failure == "challenge":
                response = response.model_copy(update={"challenge": "ab" * 32})
            elif failure == "progress":
                changed = response.evidence.progress.model_copy(
                    update={"observed_at_block": response.evidence.progress.observed_at_block + 1}
                )
                response = response.model_copy(
                    update={"evidence": response.evidence.model_copy(update={"progress": changed})}
                )
            else:
                authority = response.evidence.history.authority
                authority = authority.model_copy(
                    update={
                        "authority": authority.authority.model_copy(update={"issued_at_block": 1})
                    }
                )
                history = response.evidence.history.model_copy(update={"authority": authority})
                response = response.model_copy(
                    update={"evidence": response.evidence.model_copy(update={"history": history})}
                )
            value = value.model_copy(
                update={"response": response, "signature": sign_object(response, wallet("Charlie"))}
            )
        return canonical_json_bytes(value)

    async def forbidden(*args):
        pytest.fail("untrusted response reached proof review")

    h.reviewer.fetch, h.reviewer.archive = fetch, forbidden
    with pytest.raises(ValueError):
        await h.signer().attest(h.result.progress)
    assert not h.calls


@pytest.mark.parametrize(
    "failure",
    [
        "record_missing",
        "record_duplicate",
        "record_changed",
        "sample_missing",
        "sample_changed",
        "service_credit",
        "seal",
    ],
)
def test_replay_rejects_incomplete_or_changed_originals(remote, failure):
    h = remote
    value = h.exported
    if failure == "record_missing":
        value = value.model_copy(update={"records": ()})
    elif failure == "record_duplicate":
        value = value.model_copy(update={"records": value.records * 2})
    elif failure == "record_changed":
        record = value.records[0]
        record = record.model_copy(
            update={
                "proposed_admission": record.proposed_admission.model_copy(
                    update={"admitted_at_block": 1}
                )
            }
        )
        value = value.model_copy(update={"records": (record,)})
    elif failure == "sample_missing":
        value = value.model_copy(update={"services": value.services[1:]})
    elif failure in ("sample_changed", "service_credit"):
        sample = value.services[-1]
        field = "predecessor_sha256" if failure == "sample_changed" else "unavailable_blocks"
        sample = sample.model_copy(update={field: "ab" * 32 if failure == "sample_changed" else 1})
        value = value.model_copy(update={"services": (*value.services[:-1], sample)})
    else:
        value = value.model_copy(update={"seal": None})
    with pytest.raises(ValueError):
        replay_intake_export(value, h.intake.policy, maximum_sample_gap_blocks=10)


@pytest.mark.parametrize(
    "failure", ["archive", "owner_offline", "owner_revoked", "replayed_response"]
)
async def test_history_is_rechecked_after_original_proof_io(remote, failure):
    h = remote
    fetch, proofs = h.reviewer.fetch, h.reviewer.archive
    first = None

    async def repeated(request):
        nonlocal first
        if first is None:
            first = await fetch(request)
        return first

    if failure == "replayed_response":
        h.reviewer.fetch = repeated

    async def changed(expected):
        if failure == "archive":
            return h.archive.raw, b"invalid metadata"
        if failure == "owner_offline":
            h.offline = True
        elif failure == "owner_revoked" and h.intake.history(digest(h.history.plan)) == h.history:
            revoked = transition(h.history, h.intake.policy, "revoke", h.archive.old.height)
            h.intake.publish(revoked, h.archive.capture)
        return await proofs(expected)

    h.reviewer.archive = changed
    with pytest.raises((OSError, ValueError)):
        await h.signer().attest(h.result.progress)
    assert not h.calls


async def test_cancellation_drains_remote_transport_before_retry(remote):
    h = remote
    entered, drained = asyncio.Event(), asyncio.Event()

    async def stuck(request):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    h.reviewer.fetch = stuck
    task = asyncio.create_task(h.signer().attest(h.result.progress))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert drained.is_set() and not h.calls


async def test_capacity_failure_preserves_intake_and_retries_complete_export(remote):
    h = remote
    h.exporter.maximum_bytes = 1024
    with pytest.raises(OSError, match="capacity"):
        await h.signer().attest(h.result.progress)
    h.exporter.maximum_bytes = 64 * 1024**2
    assert h.exporter.export(h.result.progress) == h.exported
    await h.signer().attest(h.result.progress)


def test_pending_export_stays_stable_when_later_samples_arrive(remote):
    h = remote
    service = h.exported.services[-2]
    from umi.competition_cohort_availability import pending_availability_progress

    state, _, _ = replay_cohort_decisions(h.history, h.intake.policy, lambda _: None)
    progress = pending_availability_progress(state, service)
    exported = h.exporter.export(progress)
    assert exported.seal is None and exported.records == ()
    assert exported.services[-1] == service
    assert replay_intake_export(
        exported, h.intake.policy, maximum_sample_gap_blocks=10
    ) == h.exporter.source.read(progress)


async def test_changed_decision_is_rejected_before_signing(remote):
    h = remote
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(
            progress=h.result.progress, signatures=signatures(h.result.progress)
        ),
        observation=execution_boundary(h.archive.capture),
    )
    state, restored, prior = replay_cohort_decisions(h.history, h.intake.policy, lambda _: None)
    body, _ = _choice(
        state, h.history.authority.authority, h.intake.policy, evidence, restored, prior
    )
    body = body.model_copy(update={"evidence_sha256": "ab" * 32})
    with pytest.raises(ValueError, match="decision differs"):
        await h.signer().certify(body, evidence)
    assert not h.calls


async def test_remote_signer_uses_private_http_route_and_original_proofs(remote):
    h = remote
    app = FastAPI()
    app.include_router(intake_review_routes(h.exporter, token="test-credential-" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        h.reviewer.fetch = IntakeReviewHTTPClient(
            client, "https://owner.example", token="test-credential-" * 3
        )
        vote = await h.signer().attest(h.result.progress)
        assert vote.hotkey == wallet("Dave").hotkey.ss58_address


async def test_owner_publishes_every_referenced_proof_before_signing(remote):
    h = remote
    published = []

    async def publish(observation):
        published.append(observation)

    h.exporter.publish_archive = publish
    request = IntakeReviewRequest(
        schema="umi-intake-review-request/1",
        challenge="ab" * 32,
        progress=h.result.progress,
    )
    await h.exporter.respond(request)
    expected = [d.observation for d in h.exported.decisions]
    expected.append(h.exported.services[-1].observation)
    if h.exported.seal is not None:
        expected.append(h.exported.seal.observation)
        expected.extend(r.observation for r in h.exported.records)
    assert tuple(map(digest, published)) == tuple(dict.fromkeys(map(digest, expected)))

    signed = len(h.calls)

    async def unavailable(_observation):
        raise FileNotFoundError("proof source unavailable")

    h.exporter.publish_archive = unavailable
    with pytest.raises(FileNotFoundError, match="proof source unavailable"):
        await h.exporter.respond(request)
    assert len(h.calls) == signed


@pytest.mark.parametrize(
    "failure,status",
    [("unauthenticated", 401), ("body_limit", 413), ("invalid", 422), ("type", 415)],
)
async def test_private_http_rejects_requests_before_exporting(remote, failure, status):
    h = remote

    async def forbidden(*args):
        pytest.fail("invalid request reached owner export")

    h.exporter.respond = forbidden
    app = FastAPI()
    app.include_router(intake_review_routes(h.exporter, token="test-credential-" * 3))
    headers = {
        "authorization": "Bearer " + "test-credential-" * 3,
        "content-type": "application/json",
    }
    if failure == "unauthenticated":
        headers.pop("authorization")
    if failure == "type":
        headers["content-type"] = "text/plain"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        result = await client.post(
            "https://owner.example" + PATH,
            headers=headers,
            content=b"a" * 16385 if failure == "body_limit" else b"invalid",
        )
        assert result.status_code == status


@pytest.mark.parametrize("failure", ["redirect", "overflow", "type"])
async def test_private_client_bounds_delivery_and_never_follows_redirect(remote, failure):
    seen = []

    def transport(request):
        seen.append(request.url)
        if failure == "redirect":
            return httpx.Response(307, headers={"location": "https://other.example"})
        return httpx.Response(
            200,
            headers={"content-type": "text/html" if failure == "type" else "application/json"},
            content=b"a" * 1025,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        fetch = IntakeReviewHTTPClient(
            client, "https://owner.example", token="test-credential-" * 3, maximum_bytes=1024
        )
        with pytest.raises((OSError, ValueError)):
            await fetch(
                IntakeReviewRequest(
                    schema="umi-intake-review-request/1",
                    challenge="ab" * 32,
                    progress=remote.result.progress,
                )
            )
    assert len(seen) == 1 and seen[0].host == "owner.example"


async def test_private_http_releases_capacity_after_cancelled_export(remote):
    h = remote
    original = h.exporter.respond
    entered, drained = asyncio.Event(), asyncio.Event()

    async def blocked(request):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    h.exporter.respond = blocked
    app = FastAPI()
    app.include_router(intake_review_routes(h.exporter, token="test-credential-" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        fetch = IntakeReviewHTTPClient(
            client, "https://owner.example", token="test-credential-" * 3
        )
        request = IntakeReviewRequest(
            schema="umi-intake-review-request/1", challenge="ab" * 32, progress=h.result.progress
        )
        task = asyncio.create_task(fetch(request))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert drained.is_set()
        h.exporter.respond = original
        response = SignedIntakeReviewResponse.model_validate_json(await fetch(request))
        assert response.response.evidence.progress == h.result.progress


async def test_private_http_queues_behind_long_export(remote):
    h = remote
    original = h.exporter.respond
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def delayed(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            await release.wait()
        return await original(request)

    h.exporter.respond = delayed
    app = FastAPI()
    app.include_router(intake_review_routes(h.exporter, token="test-credential-" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        fetch = IntakeReviewHTTPClient(
            client, "https://owner.example", token="test-credential-" * 3
        )
        request = IntakeReviewRequest(
            schema="umi-intake-review-request/1", challenge="ab" * 32, progress=h.result.progress
        )
        first = asyncio.create_task(fetch(request))
        await entered.wait()
        second = asyncio.create_task(fetch(request))
        await asyncio.sleep(1.1)
        assert not second.done()
        release.set()
        one, two = await asyncio.gather(first, second)
        first_response = SignedIntakeReviewResponse.model_validate_json(one)
        second_response = SignedIntakeReviewResponse.model_validate_json(two)
        assert first_response.response.evidence.progress == h.result.progress
        assert second_response.response.evidence.progress == h.result.progress


def test_export_includes_superseded_consent_in_original_inventory(phase, scenario):
    phase.intake.retain(request_for(scenario, sequence=2, block=240), capture_at(240))
    result = healthy(phase, scenario)
    owner = wallet("Charlie").hotkey.ss58_address
    exporter = IntakeReviewExporter(NativeIntakeProgressSource(phase.intake), owner, None)
    exported = exporter.export(result.progress)
    assert len(exported.records) == 2 and len(exported.seal.selected) == 1
    assert replay_intake_export(
        exported, phase.intake.policy, maximum_sample_gap_blocks=10
    ) == exporter.source.read(result.progress)
    selected_only = exported.model_copy(
        update={
            "records": tuple(
                r for r in exported.records if r.request.signed_submission.submission.sequence == 2
            )
        }
    )
    with pytest.raises(ValueError, match="sealed original inventory"):
        replay_intake_export(selected_only, phase.intake.policy, maximum_sample_gap_blocks=10)


@pytest.mark.parametrize("port", ["reader", "exporter"])
async def test_authenticated_history_validation_does_not_block_event_loop(
    remote, monkeypatch, port
):
    import threading

    from umi import competition_cohort_history_http as module

    h = remote
    loop_thread = threading.get_ident()

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    exporter = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, sign)
    cohort = digest(h.history.plan)
    checked = []
    original = module.canonical_json_bytes
    if port == "reader":

        async def fetch(request):
            # The response is prepared before inspecting reader validation.
            monkeypatch.setattr(module, "canonical_json_bytes", original)
            raw = await exporter.respond(request)
            monkeypatch.setattr(module, "canonical_json_bytes", check)
            return raw

        async def invoke():
            return await CohortHistoryReader(wallet("Charlie").hotkey.ss58_address, fetch)(cohort)
    else:

        async def invoke():
            request = module.CohortHistoryRequest(
                schema="umi-cohort-history-request/1", cohort_sha256=cohort, challenge="cc" * 32
            )
            return await exporter.respond(request)

    def check(value):
        if isinstance(value, module.SignedCohortHistoryResponse) or (
            port == "exporter" and isinstance(value, module.CohortHistoryResponse)
        ):
            checked.append(threading.get_ident())
            assert checked[-1] != loop_thread, "native history validation blocked the event loop"
        return original(value)

    monkeypatch.setattr(module, "canonical_json_bytes", check)
    assert await invoke()
    assert checked


async def test_cancelled_history_reader_drains_native_verification(remote, monkeypatch):
    import threading

    from umi import competition_cohort_history_http as module

    h = remote
    loop_thread = threading.get_ident()
    entered, release = threading.Event(), threading.Event()

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    exporter = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, sign)
    original = module.canonical_json_bytes

    def paused(value):
        if isinstance(value, module.SignedCohortHistoryResponse):
            assert threading.get_ident() != loop_thread
            entered.set()
            assert release.wait(60)
        return original(value)

    async def fetch(request):
        raw = await exporter.respond(request)
        monkeypatch.setattr(module, "canonical_json_bytes", paused)
        return raw

    reader = CohortHistoryReader(wallet("Charlie").hotkey.ss58_address, fetch)
    task = asyncio.create_task(reader(digest(h.history.plan)))
    try:
        assert await asyncio.to_thread(entered.wait, 30)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()


def test_authenticated_history_read_progresses_during_background_intake(remote):
    from concurrent.futures import ThreadPoolExecutor

    h = remote
    cohort = digest(h.history.plan)
    exporter = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, None)
    with ThreadPoolExecutor(max_workers=2) as pool, h.intake._connection() as (db, store):
        original = store.published_history(cohort)
        db.execute("BEGIN IMMEDIATE")
        try:
            # Keep the real process and file write owners held. Export must
            # still return one consistent history plus its transition inputs.
            calls = [pool.submit(exporter.read, cohort) for _ in range(2)]
            sources = [future.result(timeout=60) for future in calls]
        finally:
            db.rollback()
    assert sources[0] == sources[1]
    assert sources[0].history == original == h.intake.history(cohort)
    assert sources[0].inputs().keys() == {
        t.transition.evidence_sha256
        for t in sources[0].history.transitions
        if t.transition.operation != "revoke"
    }


async def test_bounded_private_history_four_replies_keep_fresh_signed_challenges(remote):
    """Concurrent history callers retain bounded export and fresh signed challenges."""
    h = remote
    owner = wallet("Charlie").hotkey.ss58_address

    async def sign(body):
        return sign_object(body, wallet("Charlie").hotkey)

    exporter = CohortHistoryExporter(h.intake, owner, sign)
    original = exporter.respond
    entered, release = asyncio.Queue(), asyncio.Event()
    active, peak = 0, 0

    async def blocked(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await entered.put(request.challenge)
        try:
            await release.wait()
            return await original(request)
        finally:
            active -= 1

    exporter.respond = blocked
    app = FastAPI()
    app.include_router(cohort_history_routes(exporter, token="test-credential-" * 3))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        wire = CohortHistoryHTTPClient(
            client, "https://owner.example", token="test-credential-" * 3
        )
        reader = CohortHistoryReader(owner, wire)
        tasks = [asyncio.create_task(reader(digest(h.history.plan))) for _ in range(5)]
        try:
            challenges = await asyncio.wait_for(
                asyncio.gather(*(entered.get() for _ in range(4))), timeout=30
            )
            assert len(set(challenges)) == 4 and active == peak == 4
            for _ in range(5):
                await asyncio.sleep(0)
            assert entered.empty() and not any(task.done() for task in tasks)
        finally:
            release.set()
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=120)
        assert all(source.history == h.history for source in results)
        assert all(source.inputs().keys() == results[0].inputs().keys() for source in results)
        assert peak == 4 and active == 0


@pytest.mark.parametrize("concurrency", [-1, 0, 9, True, 1.0, "4"])
def test_private_review_capacity_rejects_invalid_configuration(remote, concurrency):
    from umi.competition_cohort_review_http import phase_review_routes

    with pytest.raises(ValueError, match="concurrency"):
        phase_review_routes(
            remote.exporter,
            token="test-credential-" * 3,
            path=PATH,
            request_model=IntakeReviewRequest,
            concurrency=concurrency,
        )
