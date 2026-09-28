"""Signing lifecycle faults use an explicitly substituted native-review result.

Native package/control review is exercised with the full fixture in
test_competition_reward_preparation, not established by these journal tests.
"""

import asyncio
from dataclasses import replace

import pytest

from umi import competition_reward_decision_review as review_module
from umi.competition_reward_decision_review import ReviewedRewardDecision, RewardDecisionIntent
from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from umi.open_competition import digest, sign_object
from umi.private_files import PrivateStateBusyError

from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_open_competition import wallet


@pytest.fixture
def signing_case(series_case, tmp_path):
    c = series_case

    def review(body=None, prefix=()):
        intent = RewardDecisionIntent(
            schema="umi-reward-decision-intent/1",
            decision=body or c.genesis.decision,
            manifest_sha256=c.series.manifest_sha256,
            control_evidence_sha256="12" * 32,
            control_metadata_sha256="34" * 32,
            control_history_sha256="56" * 32,
            chain_config_sha256=digest(c.control.config),
        )
        value = ReviewedRewardDecision(intent, prefix, _issuer=review_module._ISSUER)
        return replace(value, _binding=review_module._binding(value))

    def journal(*, maximum_bytes=16 * 1024**2):
        return RewardDecisionJournal(
            tmp_path / "signer",
            c.series,
            c.control.policy,
            wallet("Charlie").hotkey.ss58_address,
            expected_chain_config_sha256=digest(c.control.config),
            maximum_bytes=maximum_bytes,
        )

    c.review, c.signing_journal, c.sign_calls = review, journal, []

    async def sign(body):
        c.sign_calls.append(body)
        assert journal().load(body.sequence).decision == body
        return sign_object(body, wallet("Charlie"))

    c.sign = sign
    return c


async def test_restart_keeps_vote_partial_quorum_and_first_certificate(signing_case):
    c = signing_case
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    vote = await owner.attest(c.review())
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    assert await owner.attest(c.review()) == vote
    assert len(c.sign_calls) == 1
    with pytest.raises(ValueError, match="quorum"):
        await owner.certify(0)
    peer = sign_object(c.genesis.decision, wallet("Dave"))
    await owner.collect(0, peer)
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    certificate = await owner.certify(0)
    # sr25519 can produce distinct valid signatures; keep the committed one.
    assert await owner.collect(0, sign_object(c.genesis.decision, wallet("Dave"))) == peer
    assert await owner.certify(0) == certificate
    assert c.signing_journal().prefix(1) == (certificate,)


async def test_pending_signature_survives_failure_and_rejects_changed_proposal(signing_case):
    c = signing_case

    async def unavailable(_):
        raise ConnectionError("signing port unavailable")

    with pytest.raises(ConnectionError):
        await RewardDecisionSigner(c.signing_journal(), unavailable).attest(c.review())
    assert c.signing_journal().load(0) is not None
    assert c.signing_journal().vote(0, wallet("Charlie").hotkey.ss58_address) is None
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    changed = c.genesis.decision.model_copy(update={"observed_at_block": 161})
    with pytest.raises(ValueError, match="different retained intent"):
        await owner.attest(c.review(changed))
    assert not c.sign_calls
    assert await owner.attest(c.review())
    assert len(c.sign_calls) == 1


async def test_cancellation_drains_signature_and_commit_under_process_ownership(signing_case):
    c = signing_case
    entered, release = asyncio.Event(), asyncio.Event()

    async def delayed(body):
        entered.set()
        await release.wait()
        return await c.sign(body)

    owner = RewardDecisionSigner(c.signing_journal(), delayed)
    task = asyncio.create_task(owner.attest(c.review()))
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    with pytest.raises(PrivateStateBusyError), c.signing_journal().journal.locked():
        pytest.fail("signer released ownership before signature completion")
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert c.signing_journal().vote(0, wallet("Charlie").hotkey.ss58_address)
    await RewardDecisionSigner(c.signing_journal(), c.sign).attest(c.review())
    assert len(c.sign_calls) == 1


async def test_timeout_keeps_intent_retryable_and_does_not_publish_a_certificate(signing_case):
    c = signing_case

    async def stalled(_):
        await asyncio.Event().wait()

    owner = RewardDecisionSigner(c.signing_journal(), stalled, signing_timeout_seconds=1)
    with pytest.raises(TimeoutError):
        await owner.attest(c.review())
    assert owner.journal.load(0)
    with pytest.raises(FileNotFoundError):
        owner.journal.prefix(1)
    assert await RewardDecisionSigner(c.signing_journal(), c.sign).attest(c.review())


async def test_capacity_failure_is_atomic_before_signing_and_can_be_increased(signing_case):
    c = signing_case
    journal = c.signing_journal(maximum_bytes=1024)
    with pytest.raises(ValueError, match="capacity"):
        await RewardDecisionSigner(journal, c.sign).attest(c.review())
    assert not c.sign_calls and journal.load(0) is None
    assert not journal.journal.keys("reward_certificate")
    assert await RewardDecisionSigner(c.signing_journal(), c.sign).attest(c.review())


async def test_forged_review_bad_peer_and_wrong_local_key_never_certify(signing_case):
    c = signing_case
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    for value in (replace(c.review(), _issuer=None), replace(c.review(), _binding="00" * 32)):
        with pytest.raises(ValueError, match="native pre-signing"):
            await owner.attest(value)
    assert not c.sign_calls

    async def wrong_key(body):
        return sign_object(body, wallet("Dave"))

    with pytest.raises(ValueError, match="another evaluator"):
        await RewardDecisionSigner(c.signing_journal(), wrong_key).attest(c.review())
    with pytest.raises(ValueError, match="unauthorized"):
        await owner.collect(0, sign_object(c.genesis.decision, wallet("Alice")))
    changed = c.genesis.decision.model_copy(update={"observed_at_block": 161})
    with pytest.raises(ValueError):
        await owner.collect(0, sign_object(changed, wallet("Dave")))
    assert not owner.journal.vote(0, wallet("Dave").hotkey.ss58_address)
    assert await owner.attest(c.review())


async def test_prefix_cannot_replace_unfinished_vote_or_restart_old_sequence(signing_case):
    c = signing_case
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    await owner.attest(c.review())
    other = c.decision(observed=161)
    first = c.decision(other, 5, observed=162)
    with pytest.raises(ValueError, match="unfinished local vote"):
        await owner.attest(c.review(first.decision, (other,)))
    assert len(c.sign_calls) == 1
    good = c.decision(c.genesis, 5, observed=162)
    await owner.attest(c.review(good.decision, (c.genesis,)))
    assert len(c.sign_calls) == 2
    # An existing signature can be recovered after later work starts.
    assert await owner.attest(c.review())
    assert len(c.sign_calls) == 2


async def test_later_prefix_does_not_enable_new_ancestor_votes(signing_case):
    c = signing_case
    first = c.decision(c.genesis, 5, observed=162)
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    await owner.attest(c.review(first.decision, (c.genesis,)))
    with pytest.raises(ValueError, match="roll back"):
        await owner.attest(c.review())
    assert len(c.sign_calls) == 1
