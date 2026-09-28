"""Recurring coordinator with explicit synthetic native-review/provider boundaries.

Real journals, quorum signatures, delivery files and the real mortal control
publisher are used; these faults do not qualify installed remote evaluators.
"""

import asyncio
from dataclasses import replace

import pytest

from umi import competition_reward_decision_review as review_module
from umi.competition_reward_coordinator import (
    RewardReviewPending,
    StandingRewardCoordinator,
    StandingRewardDecisionReviewer,
)
from umi.competition_reward_decision_review import ReviewedRewardDecision, RewardDecisionIntent
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from umi.open_competition import digest, sign_object

from .test_competition_reward_control_publisher import chain as chain
from .test_competition_reward_control_publisher import chain_config as chain_config
from .test_competition_reward_control_publisher import control as control
from .test_competition_reward_control_publisher import native_encoding as native_encoding
from .test_competition_reward_control_publisher import policy as policy
from .test_competition_reward_control_publisher import publisher_case as publisher_case
from .test_competition_reward_control_publisher import series_case as series_case
from .test_open_competition import wallet


@pytest.fixture
def coordinator_case(publisher_case, tmp_path, monkeypatch):
    h = publisher_case
    h.reviews, h.votes = [], []
    h.remote_down, h.review_pending, h.bad_offer = False, False, False
    h.offer = None
    h.readback = StandingRewardFiles(
        tmp_path / "readback", maximum_package_bytes=1_000_000, maximum_witness_bytes=1_000_000
    )

    async def current(_):
        return h.current.control

    monkeypatch.setattr(h.item.provider, "collect_control", current)

    def reopen():
        # Substitute only the already separately qualified native reviewer.
        reviewer = object.__new__(StandingRewardDecisionReviewer)
        reviewer.publisher = h.publisher

        async def review(body, prefix):
            h.reviews.append(body)
            if h.review_pending:
                raise RewardReviewPending
            if h.bad_offer:
                raise ValueError("invalid offered package")
            intent = RewardDecisionIntent(
                schema="umi-reward-decision-intent/1",
                decision=body,
                manifest_sha256=h.c.series.manifest_sha256,
                control_evidence_sha256="12" * 32,
                control_metadata_sha256="34" * 32,
                control_history_sha256="56" * 32,
                chain_config_sha256=digest(h.item.config),
            )
            result = ReviewedRewardDecision(intent, prefix, _issuer=review_module._ISSUER)
            return replace(result, _binding=review_module._binding(result))

        reviewer.review = review
        journal = RewardDecisionJournal(
            tmp_path / "signer",
            h.c.series,
            h.item.policy,
            wallet("Charlie").hotkey.ss58_address,
            expected_chain_config_sha256=digest(h.item.config),
            maximum_bytes=16 * 1024**2,
        )

        async def sign(body):
            h.votes.append(body)
            return sign_object(body, wallet("Charlie"))

        async def peer(body, prefix):
            if h.remote_down:
                raise ConnectionError("evaluator unavailable")
            return sign_object(body, wallet("Dave"))

        h.owner = RewardDecisionSigner(journal, sign)
        return StandingRewardCoordinator(
            reviewer=reviewer,
            signer=h.owner,
            readback=h.readback,
            offers=lambda _: h.offer,
            voters=(peer,),
        )

    h.coordinator, h.reopen_coordinator = reopen(), reopen
    return h


async def test_restart_preserves_reviewed_intent_and_waits_for_delivery_before_chain(
    coordinator_case,
):
    h = coordinator_case
    with h.publisher.hold_writer():
        h.review_pending = True
        assert (await h.coordinator.step()).status == "review_pending"
        assert h.owner.journal.load(0) is None and not h.votes and not h.sends
    h.coordinator = h.reopen_coordinator()
    h.review_pending, h.remote_down = False, True
    h.current = h.state(block=500)
    with h.publisher.hold_writer():
        assert (await h.coordinator.step()).status == "quorum_pending"
        original = h.owner.journal.load(0).decision
        assert original.observed_at_block == 500
        count = len(h.reviews)
        assert (await h.coordinator.step()).status == "quorum_pending"
        assert len(h.reviews) == count and len(h.votes) == 1
    h.coordinator = h.reopen_coordinator()
    h.current = h.state(block=600)
    h.remote_down = False
    with h.publisher.hold_writer():
        assert (await h.coordinator.step()).status == "certified_delivery_pending"
        assert len(h.votes) == 1 and not h.sends
        assert (await h.coordinator.step()).status == "delivery_pending"
        assert not h.sends
        cert = h.owner.journal.prefix(1)[0]
        h.readback.retain_decision(cert)
        assert (await h.coordinator.step()).status == "submitted_unconfirmed"
        assert len(h.sends) == 1 and len(h.votes) == 1
        assert (await h.coordinator.step()).status == "transaction_pending"
        h.current, h.selected = h.state(block=601, nonce=5, current=digest(original)), 0
        assert (await h.coordinator.step()).status == "allocation_pending"
        assert h.owner.journal.load(1) is None
        assert len(h.sends) == 1
        assert all(body == original for body in h.reviews[1:])


async def test_changed_offer_cannot_replace_reserved_original_or_skip_cohort(coordinator_case):
    h = coordinator_case
    with h.publisher.hold_writer():
        await h.coordinator.step()
        cert = h.owner.journal.prefix(1)[0]
        h.readback.retain_decision(cert)
        h.selected = 0
        h.current = h.state(block=500, current=digest(cert.decision))
        h.offer = h.c.decision(cert, 6).decision.activation
        with pytest.raises(ValueError, match="skips the next"):
            await h.coordinator.step()
        assert h.owner.journal.load(1) is None
        h.offer = h.c.decision(cert, 5).decision.activation
        h.remote_down = True
        assert (await h.coordinator.step()).status == "quorum_pending"
        original = h.owner.journal.load(1).decision
        h.offer = h.c.decision(cert, 6).decision.activation
        h.current = h.state(block=600, current=digest(cert.decision))
        assert (await h.coordinator.step()).status == "quorum_pending"
        assert h.owner.journal.load(1).decision == original
        assert h.reviews[-1] == original


async def test_rejected_offer_does_not_pin_the_sequence_or_sign(coordinator_case):
    h = coordinator_case
    h.bad_offer = True
    with h.publisher.hold_writer():
        with pytest.raises(ValueError, match="invalid offered"):
            await h.coordinator.step()
        assert h.owner.journal.load(0) is None and not h.votes and not h.sends
        h.current = h.state(block=600)
        h.bad_offer = False
        assert (await h.coordinator.step()).status == "certified_delivery_pending"
        assert h.owner.journal.load(0).decision.observed_at_block == 600
        assert len(h.votes) == 1 and not h.sends


async def test_recurring_owner_recovers_peer_without_replaying_or_resigning(coordinator_case):
    h = coordinator_case
    stop = asyncio.Event()
    attempts = []

    async def peer(body, prefix):
        attempts.append(body)
        if len(attempts) == 1:
            raise ConnectionError("peer temporarily offline")
        stop.set()
        return sign_object(body, wallet("Dave"))

    h.coordinator.voters = (peer,)
    await asyncio.wait_for(h.coordinator.run(stop, poll_seconds=0.001), timeout=10)
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert len(h.votes) == len(h.reviews) == 1 and not h.sends
    assert h.owner.journal.certify(0).decision == attempts[0]
    with h.publisher.hold_writer():
        assert (await h.coordinator.step()).status == "delivery_pending"


async def test_retry_log_identifies_phase_without_exception_credentials(coordinator_case, caplog):
    h = coordinator_case
    stop = asyncio.Event()

    async def rejected(body, prefix):
        stop.set()
        raise ValueError("failed URL https://example.test/private?token=secret-test-value")

    h.coordinator.reviewer.review = rejected
    await h.coordinator.run(stop, poll_seconds=0.001)
    assert "phase=native_review sequence=0 reason=ValueError" in caplog.text
    assert "secret-test-value" not in caplog.text
    assert not h.votes and not h.sends and h.owner.journal.load(0) is None
