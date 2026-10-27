"""Typed transport and real signing; completed native review is an explicit fixture.

Native package/proof validation is qualified separately. These tests substitute
only those owners' completed outputs, never a permissive production adapter.
"""

import asyncio
import hashlib
import shutil
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_adoption_exchange as module
from umi import competition_reward_transition_native as native
from umi.competition_reward_coverage_service import StandingRewardCoverageService
from umi.competition_reward_decisions import SignedRewardControlDecision
from umi.competition_reward_transition_controls import (
    RewardTransitionApproval,
    RewardTransitionControlReader,
    SignedRewardTransitionApproval,
)
from umi.competition_reward_transition_signing import RewardAdoptionJournal, RewardAdoptionSigner
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_reward_adoption_feed import initial, revision
from .test_competition_reward_decisions import signatures
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_competition_reward_transition_timing import predecessor
from .test_open_competition import wallet


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(source, destination)


@pytest.fixture
def exchange_case(opportunity_case, tmp_path, monkeypatch):
    c = opportunity_case
    evidence, metadata = b"original native control evidence", b"original runtime metadata"
    state = SimpleNamespace(
        events=[],
        signatures=[],
        held=False,
        held_after_review=False,
        current_valid=True,
        native_error=False,
        bad_native=False,
    )

    def exchange(name, signer_name):
        async def sign(body):
            state.signatures.append((signer_name, body))
            return sign_object(body, wallet(signer_name))

        return module.RewardAdoptionReviewExchange(
            signer=RewardAdoptionSigner(
                RewardAdoptionJournal(
                    tmp_path / (name + "-state"),
                    series=c.series,
                    policy=c.policy,
                    signer=wallet(signer_name).hotkey.ss58_address,
                    chain_config_sha256="11" * 32,
                    maximum_bytes=32 * 1024**2,
                    reward_adoptions=initial(c),
                ),
                sign,
            ),
            proposer=wallet("Charlie").hotkey.ss58_address,
            inbox=tmp_path / (name + "-in"),
            outbox=tmp_path / (name + "-out"),
        )

    leader, peer = exchange("leader", "Charlie"), exchange("peer", "Dave")
    prior = predecessor(c)
    signed_prior = SignedRewardControlDecision(decision=prior, signatures=signatures(prior))
    reader = SimpleNamespace(
        series=c.series,
        policy=c.policy,
        chain_config_sha256="11" * 32,
        refresh_reward_adoptions=lambda: None,
    )
    pinned, current, package, live = object(), object(), object(), object()

    async def review_control(raw, meta):
        assert (raw, meta) == (evidence, metadata)
        state.events.append("pinned")
        return pinned

    async def collect_control(hotkey):
        assert hotkey == c.series.control_hotkey
        state.events.append("current")
        if not state.current_valid:
            raise ValueError("current predecessor changed")
        return current

    def package_load(sha):
        assert sha == state.request.intent.proposal.package_sha256
        state.events.append("package")
        return package

    provider = SimpleNamespace(
        review_control=review_control,
        collect_control=collect_control,
        ensure_observer_running=lambda: None,
    )
    reviewer = object.__new__(native.NativeRewardTransitionReviewer)
    reviewer.reviewer = SimpleNamespace(
        reader=reader,
        provider=provider,
        files=SimpleNamespace(verified_package=package_load),
    )

    async def native_review(**kwargs):
        assert kwargs["package"] is package
        assert kwargs["observation"] is pinned
        assert kwargs["current_observation"] is current
        assert kwargs["predecessor"] == signed_prior
        assert kwargs["proposal"] == state.request.intent.proposal
        assert kwargs["live_endpoint"] is (live if state.automatic else None)
        state.events.append("native")
        if state.native_error:
            raise ValueError("native package review refused")
        if state.held_after_review:
            state.held = True
        result = native.ReviewedRewardAdoption(
            state.request.intent,
            _issuer=native._ISSUER,
            _binding=digest(state.request.intent),
        )
        return replace(result, _issuer=None) if state.bad_native else result

    monkeypatch.setattr(reviewer, "review", native_review)
    controls = object.__new__(RewardTransitionControlReader)
    controls.series, controls.policy = c.series, c.policy

    def held(cohort):
        assert cohort == digest(c.series.cohorts[1])
        state.events.append("hold")
        return state.held

    monkeypatch.setattr(controls, "held", held)
    coverage = object.__new__(StandingRewardCoverageService)
    coverage.provider, coverage.preparation = provider, SimpleNamespace(reader=reader)

    async def replay(key):
        assert key == state.request.intent.proposal.early_release.live_age.live_endpoint_sha256
        state.events.append("anchor")
        return live

    async def source(activation):
        assert activation == prior.activation
        return SimpleNamespace(replay=replay)

    monkeypatch.setattr(coverage, "_source", source)

    async def prepare(*, automatic=False):
        body = revision(c, automatic=automatic).adoption
        intent = native.RewardAdoptionReviewIntent(
            schema="umi-reward-adoption-review-intent/1",
            proposal=body,
            predecessor_decision_sha256=digest(prior),
            manifest_sha256=digest(c.manifest),
            control_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            control_metadata_sha256=hashlib.sha256(metadata).hexdigest(),
            chain_config_sha256="11" * 32,
        )
        reviewed = native.ReviewedRewardAdoption(
            intent, _issuer=native._ISSUER, _binding=digest(intent)
        )
        await leader.signer.attest(reviewed)
        approval = None
        if not automatic:
            approval_body = RewardTransitionApproval(
                schema="umi-reward-transition-approval/1",
                series_sha256=digest(c.series),
                predecessor_decision_sha256=digest(prior),
                successor_cohort_sha256=body.cohort_sha256,
                successor_package_sha256=body.package_sha256,
                reason=body.early_release.reason,
            )
            approval = SignedRewardTransitionApproval(
                approval=approval_body, signature=sign_object(approval_body, wallet("Ferdie"))
            )
        request = leader.publish_request(
            body,
            predecessor=signed_prior,
            control_evidence=evidence,
            control_metadata=metadata,
            operator_approval=approval,
        )
        state.request, state.automatic = request, automatic
        return request

    return SimpleNamespace(
        c=c,
        state=state,
        leader=leader,
        peer=peer,
        reopen=lambda: exchange("peer", "Dave"),
        prepare=prepare,
        reviewer=reviewer,
        controls=controls,
        coverage=coverage,
        evidence=evidence,
        metadata=metadata,
        prior=signed_prior,
        peerkey=wallet("Dave").hotkey.ss58_address,
    )


async def test_request_vote_quorum_and_restart_keep_original_bytes(exchange_case, monkeypatch):
    h = exchange_case
    request = await h.prepare()
    body = request.intent.proposal
    slot = h.leader.signer.journal.slot(body)
    port = h.leader.vote_port(h.peerkey)
    with pytest.raises(FileNotFoundError):
        await port(request)
    copy(h.leader._request_path(h.leader.outbox, slot), h.peer._request_path(h.peer.inbox, slot))
    delivered = h.peer.request(body.cohort_sha256, body.revision)
    assert delivered == request
    await h.peer.review(delivered, h.reviewer, controls=h.controls)
    vote_path = h.peer._vote_path(h.peer.outbox, slot, h.peerkey)
    original = vote_path.read_bytes()
    assert h.state.events == ["hold", "pinned", "package", "current", "native", "hold"]
    h.peer = h.reopen()
    h.state.events.clear()
    h.state.held = True
    h.state.current_valid = False
    # Lost delivery may resend an already permanent signature under a later hold.
    await h.peer.review(request, h.reviewer, controls=h.controls)
    assert h.state.events == [] and vote_path.read_bytes() == original
    assert [name for name, _ in h.state.signatures] == ["Charlie", "Dave"]
    copy(vote_path, h.leader._vote_path(h.leader.inbox, slot, h.peerkey))
    await h.leader.signer.collect(slot, await port(request))
    assert (await h.leader.signer.certify(slot)).adoption == body


async def test_automatic_peer_restores_exact_anchor_then_obtains_fresh_control(exchange_case):
    h = exchange_case
    request = await h.prepare(automatic=True)
    await h.peer.review(request, h.reviewer, coverage=h.coverage, controls=h.controls)
    assert h.state.events == ["hold", "pinned", "package", "anchor", "current", "native", "hold"]


@pytest.mark.parametrize("when", ["before", "during"])
async def test_hold_blocks_new_signature_even_after_native_review(exchange_case, when):
    h = exchange_case
    request = await h.prepare()
    h.state.held = when == "before"
    h.state.held_after_review = when == "during"
    with pytest.raises(module.RewardAdoptionProgressionHeld):
        await h.peer.review(request, h.reviewer, controls=h.controls)
    assert not any(name == "Dave" for name, _ in h.state.signatures)
    if when == "before":
        assert h.state.events == ["hold"]


async def test_native_failure_retry_reuses_pinned_proof_but_refreshes_current_control(
    exchange_case,
):
    h = exchange_case
    request = await h.prepare()
    h.state.native_error = True
    with pytest.raises(ValueError, match="native package"):
        await h.peer.review(request, h.reviewer, controls=h.controls)
    assert not any(name == "Dave" for name, _ in h.state.signatures)
    h.state.native_error = False
    await h.peer.review(request, h.reviewer, controls=h.controls)
    assert h.state.events.count("pinned") == 1 and h.state.events.count("current") == 2


@pytest.mark.parametrize("what", ["current", "unissued_review", "duck_reviewer", "duck_controls"])
async def test_native_and_current_authority_cannot_be_substituted(exchange_case, what):
    h = exchange_case
    request = await h.prepare()
    reviewer, controls = h.reviewer, h.controls
    if what == "current":
        h.state.current_valid = False
    elif what == "unissued_review":
        h.state.bad_native = True
    elif what == "duck_reviewer":
        reviewer = SimpleNamespace(reviewer=h.reviewer.reviewer, review=h.reviewer.review)
    else:
        controls = SimpleNamespace(series=h.c.series, policy=h.c.policy, held=lambda _: False)
    with pytest.raises((ValueError, TypeError)):
        await h.peer.review(request, reviewer, controls=controls)
    assert not any(name == "Dave" for name, _ in h.state.signatures)


@pytest.mark.parametrize("field", ["control_evidence_hex", "control_metadata_hex"])
async def test_changed_original_bytes_never_reach_native_review_or_signer(exchange_case, field):
    h = exchange_case
    request = (await h.prepare()).model_copy(update={field: b"changed original".hex()})
    with pytest.raises(ValueError, match="original proof"):
        await h.peer.review(request, h.reviewer, controls=h.controls)
    assert h.state.events == ["hold"]
    assert not any(name == "Dave" for name, _ in h.state.signatures)


@pytest.mark.parametrize("what", ["missing", "signer", "reason", "package", "predecessor"])
async def test_operator_approval_must_authorize_this_exact_release(exchange_case, what):
    h = exchange_case
    request = await h.prepare()
    signed = request.operator_approval
    if what == "missing":
        changed = None
    elif what == "signer":
        changed = signed.model_copy(
            update={"signature": sign_object(signed.approval, wallet("Alice"))}
        )
    else:
        field = {
            "reason": "reason",
            "package": "successor_package_sha256",
            "predecessor": "predecessor_decision_sha256",
        }[what]
        body = signed.approval.model_copy(
            update={field: "another reason" if what == "reason" else "ff" * 32}
        )
        changed = SignedRewardTransitionApproval(
            approval=body, signature=sign_object(body, wallet("Ferdie"))
        )
    request = request.model_copy(update={"operator_approval": changed})
    with pytest.raises(ValueError):
        await h.peer.review(request, h.reviewer, controls=h.controls)
    assert h.state.events == [] and not any(name == "Dave" for name, _ in h.state.signatures)


@pytest.mark.parametrize("what", ["proposer", "predecessor_quorum", "issuance"])
async def test_request_cannot_change_proposer_signed_predecessor_or_issuance(exchange_case, what):
    h = exchange_case
    request = await h.prepare()
    if what == "proposer":
        request = request.model_copy(
            update={"proposer_vote": sign_object(request.intent.proposal, wallet("Dave"))}
        )
    elif what == "predecessor_quorum":
        request = request.model_copy(
            update={
                "predecessor": h.prior.model_copy(update={"signatures": h.prior.signatures[:1]})
            }
        )
    else:
        proposal = request.intent.proposal.model_copy(update={"issued_at_block": 203})
        request = request.model_copy(
            update={"intent": request.intent.model_copy(update={"proposal": proposal})}
        )
    with pytest.raises(ValueError):
        await h.peer.review(request, h.reviewer, controls=h.controls)
    assert h.state.events == []


async def test_lost_vote_delivery_retries_without_second_signature(exchange_case, monkeypatch):
    h = exchange_case
    request = await h.prepare()
    publish = module.publish_private_model

    def fail(*args, **kwargs):
        raise OSError("delivery unavailable")

    monkeypatch.setattr(module, "publish_private_model", fail)
    with pytest.raises(OSError):
        await h.peer.review(request, h.reviewer, controls=h.controls)
    monkeypatch.setattr(module, "publish_private_model", publish)
    h.state.events.clear()
    await h.peer.review(request, h.reviewer, controls=h.controls)
    assert h.state.events == []
    assert [name for name, _ in h.state.signatures] == ["Charlie", "Dave"]


@pytest.mark.parametrize("what", ["signer", "body"])
async def test_peer_vote_is_bound_to_requested_body_and_configured_signer(exchange_case, what):
    h = exchange_case
    request = await h.prepare()
    body = request.intent.proposal
    if what == "body":
        body = body.model_copy(update={"issued_at_block": 203})
    vote = sign_object(body, wallet("Charlie" if what == "signer" else "Dave"))
    slot = h.leader.signer.journal.slot(body)
    path = h.leader._vote_path(h.leader.inbox, slot, h.peerkey)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_bytes(canonical_json_bytes(vote))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        await h.leader.vote_port(h.peerkey)(request)


async def test_invalid_feed_stops_peer_poll_before_request_or_proof_reads(
    exchange_case, monkeypatch
):
    h = exchange_case
    stop = asyncio.Event()

    def invalid():
        stop.set()
        raise ValueError("feed changed")

    def prohibited(*args):
        pytest.fail("invalid feed must not start adoption request reads")

    h.reviewer.reviewer.reader.refresh_reward_adoptions = invalid
    monkeypatch.setattr(h.peer, "request", prohibited)
    await h.peer.run_reviewer(h.reviewer, stop, poll_seconds=0.001, controls=h.controls)
    assert h.state.signatures == []


async def test_unchanged_publication_and_peer_request_use_only_source_metadata(
    exchange_case, monkeypatch
):
    h = exchange_case
    request = await h.prepare()
    body = request.intent.proposal
    slot = h.leader.signer.journal.slot(body)
    copy(h.leader._request_path(h.leader.outbox, slot), h.peer._request_path(h.peer.inbox, slot))
    assert h.peer.request(body.cohort_sha256, body.revision) == request

    def prohibited(*args, **kwargs):
        pytest.fail("unchanged request repeated payload I/O or hashing")

    monkeypatch.setattr(module, "read", prohibited)
    monkeypatch.setattr(module, "_archive", prohibited)
    monkeypatch.setattr(module, "publish_private_model", prohibited)
    assert (
        h.leader.publish_request(
            body,
            predecessor=h.prior,
            control_evidence=h.evidence,
            control_metadata=h.metadata,
            operator_approval=request.operator_approval,
        )
        is request
    )
    assert h.peer.request(body.cohort_sha256, body.revision) == request


@pytest.mark.parametrize("change", ["content", "mode", "missing", "hardlink"])
async def test_changed_request_source_cannot_borrow_cached_completion(exchange_case, change):
    import os

    h = exchange_case
    request = await h.prepare()
    body = request.intent.proposal
    slot = h.leader.signer.journal.slot(body)
    path = h.peer._request_path(h.peer.inbox, slot)
    copy(h.leader._request_path(h.leader.outbox, slot), path)
    assert h.peer.request(body.cohort_sha256, body.revision) == request
    if change == "content":
        changed = request.model_copy(update={"control_evidence_hex": b"changed evidence".hex()})
        path.write_bytes(canonical_json_bytes(changed))
    elif change == "mode":
        path.chmod(0o644)
    elif change == "missing":
        path.unlink()
    else:
        os.link(path, path.with_suffix(".linked"))
    with pytest.raises(ValueError):
        h.peer.request(body.cohort_sha256, body.revision)


async def test_identical_atomic_redelivery_revalidates_only_changed_transport_once(
    exchange_case, monkeypatch
):
    import os

    h = exchange_case
    request = await h.prepare()
    body = request.intent.proposal
    slot = h.leader.signer.journal.slot(body)
    path = h.peer._request_path(h.peer.inbox, slot)
    copy(h.leader._request_path(h.leader.outbox, slot), path)
    assert h.peer.request(body.cohort_sha256, body.revision) == request
    replacement = path.with_suffix(".replacement")
    copy(path, replacement)
    os.replace(replacement, path)
    assert h.peer.request(body.cohort_sha256, body.revision) == request

    def prohibited(*args, **kwargs):
        pytest.fail("unchanged replacement repeated request payload read")

    monkeypatch.setattr(module, "read", prohibited)
    assert h.peer.request(body.cohort_sha256, body.revision) == request
