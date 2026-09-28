"""Canonical exchange and durable votes; native review is substituted here.

The full reward-preparation fixture separately runs the exchange through native
review. File copies stand in for independently authenticated remote replication.
"""

import asyncio
import shutil
from types import SimpleNamespace

import pytest

from umi.competition_reward_exchange import RewardReviewExchange, RewardReviewRequest
from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_reward_signing import chain as chain
from .test_competition_reward_signing import chain_config as chain_config
from .test_competition_reward_signing import control as control
from .test_competition_reward_signing import policy as policy
from .test_competition_reward_signing import series_case as series_case
from .test_competition_reward_signing import signing_case as signing_case
from .test_open_competition import wallet


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(source, target)


@pytest.fixture
def exchange_case(signing_case, tmp_path):
    c = signing_case
    owner = RewardDecisionSigner(c.signing_journal(), c.sign)
    proposer, peerkey = (wallet(name).hotkey.ss58_address for name in ("Charlie", "Dave"))
    leader = RewardReviewExchange(
        signer=owner,
        proposer=proposer,
        inbox=tmp_path / "leader-in",
        outbox=tmp_path / "leader-out",
    )
    signed = []

    def peer():
        async def sign(body):
            signed.append(body)
            return sign_object(body, wallet("Dave"))

        return RewardReviewExchange(
            signer=RewardDecisionSigner(
                RewardDecisionJournal(
                    tmp_path / "peer-state",
                    c.series,
                    c.control.policy,
                    peerkey,
                    expected_chain_config_sha256=digest(c.control.config),
                    maximum_bytes=16 * 1024**2,
                ),
                sign,
            ),
            proposer=proposer,
            inbox=tmp_path / "peer-in",
            outbox=tmp_path / "peer-out",
        )

    async def review(body, prefix):
        return c.review(body, prefix)

    async def signer_vote():
        return await owner.attest(c.review())

    reviewer = SimpleNamespace(
        reader=SimpleNamespace(
            series=c.series, policy=c.control.policy, chain_config_sha256=digest(c.control.config)
        ),
        review=review,
        provider=SimpleNamespace(ensure_observer_running=lambda: None),
    )
    return SimpleNamespace(
        c=c,
        owner=owner,
        leader=leader,
        peer=peer(),
        reopen=peer,
        signed=signed,
        reviewer=reviewer,
        peerkey=peerkey,
        first=signer_vote,
    )


async def test_exchange_recovers_request_vote_and_lost_delivery_after_restart(exchange_case):
    h = exchange_case
    body = h.c.genesis.decision
    port = h.leader.vote_port(h.peerkey)
    with pytest.raises(ValueError, match="durable vote"):
        await port(body, ())
    await h.first()
    with pytest.raises(FileNotFoundError):
        await port(body, ())
    request = h.leader._request_path(h.leader.outbox, 0)
    copy(request, h.peer._request_path(h.peer.inbox, 0))
    h.peer = h.reopen()
    await h.peer.review(h.peer.request(0), h.reviewer)
    vote_file = h.peer._vote_path(h.peer.outbox, 0, h.peerkey)
    original = vote_file.read_bytes()
    # A peer restart after export but before transport acknowledgement reuses
    # its original signature and immutable message bytes.
    h.peer = h.reopen()
    await h.peer.review(h.peer.request(0), h.reviewer)
    assert h.signed == [body] and vote_file.read_bytes() == original
    copy(vote_file, h.leader._vote_path(h.leader.inbox, 0, h.peerkey))
    vote = await port(body, ())
    await h.owner.collect(0, vote)
    assert (await h.owner.certify(0)).decision == body


async def test_wrong_proposer_slot_or_changed_body_cannot_request_a_signature(exchange_case):
    h = exchange_case
    vote = await h.first()
    request = RewardReviewRequest(
        schema="umi-reward-review-request/1",
        decision=h.c.genesis.decision,
        preceding=(),
        proposer_vote=vote,
    )
    for bad in (
        request.model_copy(update={"proposer_vote": sign_object(request.decision, wallet("Dave"))}),
        request.model_copy(
            update={"decision": request.decision.model_copy(update={"observed_at_block": 161})}
        ),
    ):
        with pytest.raises(ValueError):
            await h.peer.review(bad, h.reviewer)
    with pytest.raises(ValueError, match="sequence"):
        h.peer._check(request, 1)
    assert not h.signed


@pytest.mark.parametrize("wrong", ["signer", "decision"])
async def test_peer_delivery_cannot_replace_signer_or_decision(exchange_case, wrong):
    h = exchange_case
    body = h.c.genesis.decision
    await h.first()
    altered = body.model_copy(update={"observed_at_block": body.observed_at_block + 1})
    vote = sign_object(
        altered if wrong == "decision" else body,
        wallet("Charlie" if wrong == "signer" else "Dave"),
    )
    path = h.leader._vote_path(h.leader.inbox, 0, h.peerkey)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_bytes(canonical_json_bytes(vote))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        await h.leader.vote_port(h.peerkey)(body, ())
    assert h.owner.journal.vote(0, h.peerkey) is None


async def test_reviewer_loop_retains_completed_vote_without_resigning(exchange_case):
    h = exchange_case
    await h.first()
    h.leader.publish_request(h.c.genesis.decision, ())
    copy(h.leader._request_path(h.leader.outbox, 0), h.peer._request_path(h.peer.inbox, 0))
    stop = asyncio.Event()
    task = asyncio.create_task(h.peer.run_reviewer(h.reviewer, stop, poll_seconds=0.001))
    try:
        for _ in range(200):
            if h.peer._vote_path(h.peer.outbox, 0, h.peerkey).exists():
                break
            await asyncio.sleep(0.005)
        else:
            pytest.fail("review service failed to export a vote")
        await asyncio.sleep(0.02)
    finally:
        stop.set()
        await task
    assert len(h.signed) == 1
    assert (
        canonical_json_bytes(h.peer.signer.journal.vote(0, h.peerkey))
        == h.peer._vote_path(h.peer.outbox, 0, h.peerkey).read_bytes()
    )
