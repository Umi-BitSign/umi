"""Recurring adoption with real signatures, journals, feed and offer selection.

Package import/semantic review, coverage replay, approval delivery and remote
exchange are explicit substituted boundaries. Native package review and remote
transport have separate qualification; these tests submit no chain transaction.
"""

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_offers as offers_module
from umi import competition_reward_transition_native as native
from umi import competition_reward_transition_producer as module
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_reward_adoption import RewardAdoptionSelection, SignedRewardModelAdoption
from umi.competition_reward_coordinator import (
    RewardReviewPending,
    StandingRewardCoordinator,
    StandingRewardDecisionReviewer,
)
from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
from umi.competition_reward_offers import StandingRewardOffers
from umi.competition_reward_transition_anchor import RewardLiveAnchorMissing
from umi.competition_reward_transition_signing import RewardAdoptionJournal, RewardAdoptionSigner
from umi.competition_reward_transition_timing import REWARD_TRANSITION_WAIT_MS
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_reward_adoption_feed import initial, owner
from .test_competition_reward_decisions import signatures, signed
from .test_competition_reward_transition_native import historical_control
from .test_competition_reward_transition_review import chain as chain
from .test_competition_reward_transition_review import chain_config as chain_config
from .test_competition_reward_transition_review import control as control
from .test_competition_reward_transition_review import live_case as live_case
from .test_competition_reward_transition_review import manifest_case as manifest_case
from .test_competition_reward_transition_review import opportunity_case as opportunity_case
from .test_competition_reward_transition_review import policy as policy
from .test_competition_reward_transition_review import series_case as series_case
from .test_open_competition import wallet


@pytest.fixture
async def producer_case(live_case, tmp_path, monkeypatch):
    h, c = live_case, live_case.c
    prior = h.args["predecessor"]
    prefix = (signed(c.admission), signed(prior))
    cohort = digest(c.series.cohorts[1])
    package = SimpleNamespace(
        allocation={"synthetic_native_allocation": 1},
        service={"synthetic_native_service": 1},
        benchmark={"synthetic_native_quality": 1},
        inputs=SimpleNamespace(history=SimpleNamespace(transitions=(), genesis={"tip": 1})),
    )
    body = (
        initial(c)
        .adoptions[0]
        .adoption.model_copy(
            update={
                "allocation_sha256": digest(package.allocation),
                "service_certificate_sha256": digest(package.service),
                "quality_manifest_sha256": digest(package.benchmark),
                "parameters": cohort_reward_parameters(c.series.cohorts[1].sequence),
            }
        )
    )
    c.feed_initial = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),),
    )
    state = SimpleNamespace(
        approved=True,
        held=False,
        package_available=True,
        peer_ready=True,
        anchor_missing=False,
        endpoint=h.args["live_endpoint"],
        collects=[],
        restores=[],
        reviews=[],
        signatures=[],
        requests=[],
        discoveries=[],
        anchor_lookups=[],
        replays=[],
        observations={},
        prefix=prefix,
        cohort=cohort,
        package=package,
        c=c,
        h=h,
    )
    files = object()

    def package_digest(value):
        assert value is package
        return body.package_sha256

    monkeypatch.setattr(module, "verified_package_digest", package_digest)
    monkeypatch.setattr(offers_module, "verified_package_digest", package_digest)
    provider = h.control.provider
    collect = provider.collect_control

    async def current(hotkey):
        value = await collect(hotkey)
        state.collects.append(value)
        state.observations[value.evidence] = value
        return value

    async def restore(evidence, metadata):
        state.restores.append((evidence, metadata))
        observed = state.observations[evidence]
        assert metadata == observed.runtime.metadata_bytes
        return historical_control(observed)

    monkeypatch.setattr(provider, "collect_control", current)
    # Production uses HistoricalRewardControlProvider; this current-control
    # fixture adds only its separately qualified retained-proof boundary.
    monkeypatch.setattr(provider, "review_control", restore, raising=False)

    def held(selected):
        assert selected in {cohort, prior.activation.cohort_sha256}
        return state.held

    def approval(selected, predecessor_sha, package_sha):
        assert (selected, predecessor_sha, package_sha) == (
            cohort,
            digest(prior),
            body.package_sha256,
        )
        if state.approved:
            return SimpleNamespace(approval=SimpleNamespace(reason="Operator releases now"))
        return None

    controls = SimpleNamespace(held=held, approval=approval)

    def anchor(activation, **kwargs):
        assert activation == prior.activation
        assert kwargs["chain_config_sha256"] == digest(h.control.config)
        state.anchor_lookups.append(kwargs)
        if state.anchor_missing:
            raise RewardLiveAnchorMissing("fixture has no retained matching row-write")
        return state.endpoint.point.key()

    async def replay(key):
        state.replays.append(key)
        assert key == state.endpoint.point.key()
        return state.endpoint

    async def source(activation):
        assert activation == prior.activation
        return SimpleNamespace(replay=replay)

    coverage = SimpleNamespace(
        provider=provider, journal=SimpleNamespace(first_live_anchor=anchor), _source=source
    )

    def publish_request(
        proposal, *, predecessor, control_evidence, control_metadata, operator_approval
    ):
        request = SimpleNamespace(
            proposal=proposal,
            predecessor=predecessor,
            evidence=control_evidence,
            metadata=control_metadata,
            approval=operator_approval,
        )
        state.requests.append(request)
        return request

    def vote_port(hotkey):
        assert hotkey == wallet("Dave").hotkey.ss58_address

        async def vote(request):
            if not state.peer_ready:
                raise FileNotFoundError("independent review pending")
            return sign_object(request.proposal, wallet("Dave"))

        return vote

    exchange = SimpleNamespace(publish_request=publish_request, vote_port=vote_port)

    def reopen(*, original_root=None):
        feed = owner(tmp_path, c)
        reader = c.reader
        reader._configure_reward_adoptions(initial(c), series=c.series, policy=c.policy, feed=feed)
        reviewer = object.__new__(StandingRewardDecisionReviewer)
        reviewer.reader, reviewer.provider = reader, provider
        reviewer.files, reviewer.manifest, reviewer.verification_reuse = files, c.manifest, None
        native_reviewer = native.NativeRewardTransitionReviewer(reviewer)

        async def review(**kwargs):
            # Substitute only the completed native-package semantic review.
            # Keep current/pinned control validation and immutable intent real.
            native_reviewer._control(kwargs["observation"], prior)
            native_reviewer._control(kwargs["current_observation"], prior, current=True)
            assert kwargs["package"] is package and kwargs["predecessor"] == prefix[-1]
            state.reviews.append(kwargs)
            observed = kwargs["observation"]
            metadata = getattr(observed, "metadata", None)
            if metadata is None:
                metadata = observed.runtime.metadata_bytes
            intent = native.RewardAdoptionReviewIntent(
                schema="umi-reward-adoption-review-intent/1",
                proposal=kwargs["proposal"],
                predecessor_decision_sha256=digest(prior),
                manifest_sha256=digest(c.manifest),
                control_evidence_sha256=hashlib.sha256(observed.evidence).hexdigest(),
                control_metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                chain_config_sha256=digest(h.control.config),
            )
            return native.ReviewedRewardAdoption(
                intent, _issuer=native._ISSUER, _binding=digest(intent)
            )

        native_reviewer.review = review
        journal = RewardAdoptionJournal(
            tmp_path / "signer",
            series=c.series,
            policy=c.policy,
            signer=wallet("Charlie").hotkey.ss58_address,
            chain_config_sha256=digest(h.control.config),
            maximum_bytes=32 * 1024**2,
            reward_adoptions=initial(c),
            reward_adoption_feed=feed,
        )

        async def sign(proposal):
            state.signatures.append(proposal)
            return sign_object(proposal, wallet("Charlie"))

        signer = RewardAdoptionSigner(journal, sign)
        offers = object.__new__(StandingRewardOffers)
        offers.series, offers.policy, offers.files = c.series, c.policy, files
        offers.manifest, offers.coverage = c.manifest, coverage
        offers.handoff = LegacyRewardHandoffPlan(
            schema="umi-legacy-reward-handoff-plan/1",
            series_sha256=digest(c.series),
            cohort_sha256=digest(c.series.cohorts[0]),
            legacy_policy_sha256="11" * 32,
            legacy_round_sha256="22" * 32,
            legacy_package_sha256="33" * 32,
        )
        offers._reported_missing_successor_adoptions = set()
        offers._configure_reward_adoptions(initial(c), series=c.series, policy=c.policy, feed=feed)

        def completed(selected, index):
            assert selected == cohort and index == 1
            state.discoveries.append(selected)
            return package if state.package_available else None

        offers._completed_package = completed
        producer = module.StandingRewardTransitionProducer(
            root=original_root or tmp_path / "originals",
            reviewer=native_reviewer,
            signer=signer,
            exchange=exchange,
            coverage=coverage,
            offers=offers,
            controls=controls,
            feed=feed,
            maximum_bytes=32 * 1024**2,
        )
        state.producer, state.feed, state.signer, state.offers = producer, feed, signer, offers
        return producer

    def advance(milliseconds=1):
        item = h.control
        item.finality.timestamp += milliseconds
        item.rpc.values[("Timestamp", "Now", ())] = item.finality.timestamp
        item.finality.ref = replace(
            item.finality.ref,
            block_number=item.finality.ref.block_number + 1,
            block_hash="0x" + f"{item.finality.ref.block_number + 1:064x}",
        )

    state.reopen, state.advance = reopen, advance
    reopen()
    return state


async def test_operator_release_signs_under_24_hours_without_coverage_work(producer_case):
    c = producer_case
    c.endpoint = c.h.endpoint(changes={"timestamp_ms": c.h.args["observation"].timestamp_ms})
    result = await c.producer.step(c.cohort, c.prefix)
    assert result.status == "selected" and result.observation is c.collects[0]
    assert len(c.signatures) == len(c.reviews) == len(c.collects) == 1
    assert c.anchor_lookups == c.replays == []
    selected = c.feed.selected.latest(c.cohort)
    assert selected.adoption.early_release.schema_ == "umi-reward-early-release/1"
    assert len(selected.signatures) == 2
    assert c.offers(c.cohort, c.prefix).reward_adoption_sha256 == digest(selected.adoption)


@pytest.mark.parametrize("reason", ["missing_package", "held"])
@pytest.mark.parametrize("approved", [False, True])
async def test_no_current_collection_or_signing_when_not_ready(producer_case, reason, approved):
    c = producer_case
    c.approved = approved
    c.package_available = reason != "missing_package"
    c.held = reason == "held"
    result = await c.producer.step(c.cohort, c.prefix)
    assert result.status == ("progression_held" if c.held else "allocation_pending")
    assert c.collects == c.reviews == c.signatures == c.requests == []
    assert len(c.discoveries) == (0 if c.held else 1)


async def test_automatic_release_waits_exactly_24_hours_from_owned_live_anchor(producer_case):
    c = producer_case
    c.approved = False
    c.endpoint = c.h.endpoint(changes={"timestamp_ms": c.h.native.timestamp_ms + 1})
    first = await c.producer.step(c.cohort, c.prefix)
    assert first.status == "operator_or_timeout_pending" and first.remaining_seconds == 0.001
    assert not c.signatures and not c.requests
    c.advance(1)
    second = await c.producer.step(c.cohort, c.prefix)
    assert second.status == "selected"
    release = c.feed.selected.latest(c.cohort).adoption.early_release
    assert release.schema_ == "umi-reward-early-release/2"
    assert release.live_age.ready
    assert (
        release.live_age.observed_timestamp_ms - release.live_age.live_timestamp_ms
        == REWARD_TRANSITION_WAIT_MS
    )
    assert release.live_age.live_endpoint_sha256 == c.endpoint.point.key()
    assert len(c.anchor_lookups) == len(c.replays) == 1
    assert len(c.collects) == 2 and len(c.signatures) == 1


async def test_missing_live_anchor_waits_without_signing(producer_case):
    c = producer_case
    c.approved, c.anchor_missing = False, True
    result = await c.producer.step(c.cohort, c.prefix)
    assert result.status == "first_live_anchor_pending"
    assert len(c.collects) == 1 and not c.signatures and not c.requests


async def test_quorum_retry_and_restart_reuse_same_original_intent_and_signature(producer_case):
    c = producer_case
    c.peer_ready = False
    first = await c.producer.step(c.cohort, c.prefix)
    assert first.status == "adoption_quorum_pending"
    proposal = c.signatures[0]
    original = c.producer._original
    assert original.proposal == proposal
    c.advance()
    assert (await c.producer.step(c.cohort, c.prefix)).status == "adoption_quorum_pending"
    assert len(c.signatures) == len(c.reviews) == 1
    assert c.requests[0].evidence == c.requests[1].evidence
    c.reopen()
    c.peer_ready = True
    c.advance()
    assert (await c.producer.step(c.cohort, c.prefix)).status == "selected"
    assert c.feed.selected.latest(c.cohort).adoption == proposal
    assert c.producer._original == original
    assert len(c.signatures) == 1 and len(c.reviews) == 2 and len(c.restores) == 1
    assert c.restores[0] == (
        bytes.fromhex(original.control_evidence_hex),
        bytes.fromhex(original.control_metadata_hex),
    )
    assert len({canonical_json_bytes(r.proposal) for r in c.requests}) == 1
    assert len({r.evidence for r in c.requests}) == len({r.metadata for r in c.requests}) == 1


async def test_missing_original_with_signed_intent_requires_repair(producer_case, tmp_path):
    c = producer_case
    c.peer_ready = False
    assert (await c.producer.step(c.cohort, c.prefix)).status == "adoption_quorum_pending"
    c.reopen(original_root=tmp_path / "missing-originals")
    before = len(c.collects)
    with pytest.raises(ValueError, match=r"repair.*retained original"):
        await c.producer.step(c.cohort, c.prefix)
    assert len(c.collects) == before and len(c.signatures) == 1


async def test_automatic_intent_survives_later_operator_approval(producer_case):
    c = producer_case
    c.approved = c.peer_ready = False
    assert (await c.producer.step(c.cohort, c.prefix)).status == "adoption_quorum_pending"
    original = c.producer._original
    assert original.proposal.early_release.schema_ == "umi-reward-early-release/2"
    c.reopen()
    c.advance()
    c.approved = c.peer_ready = True
    assert (await c.producer.step(c.cohort, c.prefix)).status == "selected"
    assert c.producer._original == original
    assert c.feed.selected.latest(c.cohort).adoption == original.proposal
    assert len(c.signatures) == 1
    assert c.requests[-1].approval is None
    assert c.requests[-1].evidence == bytes.fromhex(original.control_evidence_hex)
    assert c.requests[-1].metadata == bytes.fromhex(original.control_metadata_hex)


async def test_hold_during_native_review_preserves_original_without_signing(
    producer_case, monkeypatch
):
    c = producer_case
    review = c.producer.reviewer.review

    async def hold_after_review(**kwargs):
        result = await review(**kwargs)
        c.held = True
        return result

    monkeypatch.setattr(c.producer.reviewer, "review", hold_after_review)
    result = await c.producer.step(c.cohort, c.prefix)
    assert result.status == "progression_held"
    assert len(c.reviews) == 1 and not c.signatures and not c.requests
    original = c.producer._original
    slot = c.signer.journal.slot(original.proposal)
    retained = c.producer.originals.get("transition_original", slot)
    assert (
        module.RewardTransitionOriginal.model_validate_json(canonical_json_bytes(retained))
        == original
    )
    assert c.signer.journal.load(slot) is None
    assert c.feed.selected.latest(c.cohort).adoption.early_release is None

    # Releasing the hold reuses the completed review and its exact original.
    c.held = False
    assert (await c.producer.step(c.cohort, c.prefix)).status == "selected"
    assert c.producer._original == original
    assert len(c.reviews) == len(c.signatures) == 1


async def test_hold_after_quorum_prevents_publication(producer_case, monkeypatch):
    c = producer_case
    attest = c.signer.attest

    async def hold_after_signing(review):
        result = await attest(review)
        c.held = True
        return result

    monkeypatch.setattr(c.signer, "attest", hold_after_signing)
    assert (await c.producer.step(c.cohort, c.prefix)).status == "progression_held"
    assert len(c.signatures) == 1
    assert c.feed.selected.latest(c.cohort).adoption.early_release is None


async def test_coordinator_reuses_producer_current_observation(producer_case):
    c = producer_case
    # Existing-prefix publication/readback is a separate boundary here. Stop
    # at the coordinator's native decision-review entry, before decision signing.
    coordinator = object.__new__(StandingRewardCoordinator)
    coordinator.transition_producer, coordinator.offers = c.producer, c.offers
    coordinator._unreviewed = coordinator._reviewed = None
    coordinator._prefix = lambda: c.prefix
    coordinator._pending = lambda _: None
    coordinator._readback = lambda _: None

    async def no_revision(_):
        return None

    async def delivered(*_):
        return None

    async def published(_):
        return SimpleNamespace(status="control_finalized", decision_sha256=digest(c.prefix[-1]))

    decisions = []

    async def pending_review(body, prefix):
        assert prefix == c.prefix
        decisions.append(body)
        raise RewardReviewPending

    coordinator._revision_proposal = no_revision
    coordinator.signer = SimpleNamespace(publish=delivered)
    coordinator.reviewer = SimpleNamespace(review=pending_review)
    coordinator.publisher = SimpleNamespace(
        series=c.c.series,
        reader=c.producer.reviewer.reviewer.reader,
        provider=c.h.control.provider,
        hotkey=c.c.series.control_hotkey,
        files=SimpleNamespace(package=lambda _: None),
        step=published,
    )
    result = await coordinator._step()
    assert result.status == "review_pending" and len(decisions) == 1
    assert len(c.collects) == 1
    assert decisions[0].observed_at_block == c.collects[0].snapshot.block_number
    assert decisions[0].activation.reward_adoption_sha256 == digest(
        c.feed.selected.latest(c.cohort).adoption
    )
