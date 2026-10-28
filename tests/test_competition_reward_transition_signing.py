"""Durable vote ownership; semantic native review is qualified in its own module."""

import asyncio
from dataclasses import replace

import pytest

from umi import competition_reward_transition_native as native
from umi.competition_reward_signing import RewardQuorumPending
from umi.competition_reward_transition_signing import RewardAdoptionJournal, RewardAdoptionSigner
from umi.open_competition import digest, sign_object

from .test_competition_reward_adoption_feed import initial, owner, revision
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_competition_reward_transition_timing import predecessor
from .test_open_competition import wallet


def journal(tmp_path, c, *, name="signer", selected=None):
    return RewardAdoptionJournal(
        tmp_path / name,
        series=c.series,
        policy=c.policy,
        signer=wallet("Charlie").hotkey.ss58_address,
        chain_config_sha256="11" * 32,
        maximum_bytes=32 * 1024**2,
        reward_adoptions=initial(c) if selected is None else selected,
    )


def reviewed(c):
    # Substitute only the completed native-review boundary. All intent storage,
    # cryptography, independent-group quorum and publication below are real.
    body = revision(c).adoption
    intent = native.RewardAdoptionReviewIntent(
        schema="umi-reward-adoption-review-intent/1",
        proposal=body,
        predecessor_decision_sha256=digest(predecessor(c)),
        manifest_sha256=digest(c.manifest),
        control_evidence_sha256="21" * 32,
        control_metadata_sha256="22" * 32,
        chain_config_sha256="11" * 32,
    )
    return native.ReviewedRewardAdoption(intent, _issuer=native._ISSUER, _binding=digest(intent))


async def test_votes_and_quorum_resume_after_restart_without_resigning(tmp_path, opportunity_case):
    c = opportunity_case
    calls = []
    review = reviewed(c)

    async def sign(body):
        calls.append(digest(body))
        return sign_object(body, wallet("Charlie"))

    first = RewardAdoptionSigner(journal(tmp_path, c), sign)
    own = await first.attest(review)
    slot = first.journal.slot(review.intent.proposal)
    with pytest.raises(RewardQuorumPending):
        await first.certify(slot)
    resumed = RewardAdoptionSigner(journal(tmp_path, c), sign)
    assert await resumed.attest(review) == own
    assert len(calls) == 1
    await resumed.collect(slot, sign_object(review.intent.proposal, wallet("Dave")))
    signed = await resumed.certify(slot)
    assert await resumed.certify(slot) == signed
    feed = owner(tmp_path, c)
    published = await resumed.publish(slot, feed)
    assert published.adoptions[-1] == signed
    assert await resumed.publish(slot, feed) == published
    assert len(calls) == 1


async def test_unreviewed_or_conflicting_intent_never_reaches_signer(tmp_path, opportunity_case):
    c = opportunity_case
    calls = []

    async def sign(body):
        calls.append(body)
        return sign_object(body, wallet("Charlie"))

    signer = RewardAdoptionSigner(journal(tmp_path, c), sign)
    good = reviewed(c)
    with pytest.raises(ValueError, match="native"):
        await signer.attest(replace(good, _issuer=None))
    assert calls == []
    await signer.attest(good)
    changed = good.intent.model_copy(update={"control_metadata_sha256": "ff" * 32})
    conflict = replace(good, intent=changed, _binding=digest(changed))
    with pytest.raises(ValueError, match="different retained intent"):
        await signer.attest(conflict)
    assert len(calls) == 1


async def test_cancellation_drains_signature_before_releasing_ownership(tmp_path, opportunity_case):
    c = opportunity_case
    entered, release = asyncio.Event(), asyncio.Event()

    async def sign(body):
        entered.set()
        await release.wait()
        return sign_object(body, wallet("Charlie"))

    signer = RewardAdoptionSigner(journal(tmp_path, c), sign)
    review = reviewed(c)
    task = asyncio.create_task(signer.attest(review))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    slot = signer.journal.slot(review.intent.proposal)
    assert signer.journal.vote(slot, wallet("Charlie").hotkey.ss58_address) is not None
    assert await signer.attest(review) is not None


async def test_signature_failure_keeps_same_native_intent_for_retry(tmp_path, opportunity_case):
    c = opportunity_case
    calls = []

    async def sign(body):
        calls.append(body)
        if len(calls) == 1:
            raise OSError("signer unavailable")
        return sign_object(body, wallet("Charlie"))

    signer = RewardAdoptionSigner(journal(tmp_path, c), sign)
    review = reviewed(c)
    with pytest.raises(OSError):
        await signer.attest(review)
    slot = signer.journal.slot(review.intent.proposal)
    assert signer.journal.load(slot) == review.intent
    await signer.attest(review)
    assert calls[0] == calls[1]


async def test_unauthorized_and_wrong_body_votes_are_rejected(tmp_path, opportunity_case):
    c = opportunity_case

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    signer = RewardAdoptionSigner(journal(tmp_path, c), sign)
    review = reviewed(c)
    await signer.attest(review)
    slot = signer.journal.slot(review.intent.proposal)
    with pytest.raises(ValueError):
        await signer.collect(slot, sign_object(review.intent.proposal, wallet("Alice")))
    other = review.intent.proposal.model_copy(update={"issued_at_block": 203})
    with pytest.raises(ValueError):
        await signer.collect(slot, sign_object(other, wallet("Dave")))
    with pytest.raises(RewardQuorumPending):
        await signer.certify(slot)
