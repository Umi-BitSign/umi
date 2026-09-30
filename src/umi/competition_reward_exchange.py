"""Durable signed requests and votes for independent standing reward reviewers.

Replication copies only these bounded canonical messages. A configured leader's
signature authenticates each request; every peer still performs native review
before signing. Missing delivery has no cohort deadline.
"""

from __future__ import annotations

import asyncio
import logging
import math
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_reward_coordinator import Prefix, StandingRewardDecisionReviewer
from .competition_reward_decisions import (
    MAX_DECISION_BYTES,
    MAX_DECISIONS,
    RewardControlDecision,
    SignedRewardControlDecision,
    verify_reward_decision_proposal,
)
from .competition_reward_signing import RewardDecisionSigner
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import ensure_private_directory, private_path, publish_private_model
from .private_files import read_private_model as read
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class RewardReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-reward-review-request/1"] = Field(alias="schema")
    decision: RewardControlDecision
    preceding: Annotated[tuple[SignedRewardControlDecision, ...], Field(max_length=MAX_DECISIONS)]
    proposer_vote: Signature


class RewardReviewExchange:
    def __init__(self, *, signer: RewardDecisionSigner, proposer: str, inbox: Path, outbox: Path):
        if type(signer) is not RewardDecisionSigner:
            raise TypeError("reward exchange requires a durable decision signer")
        self.signer, self.proposer = signer, identity(proposer)
        if self.proposer not in signer.journal.reviewers:
            raise ValueError("reward proposer is outside the approved evaluator set")
        self.inbox, self.outbox = (Path(private_path(str(p))) for p in (inbox, outbox))
        if self.inbox.is_relative_to(self.outbox) or self.outbox.is_relative_to(self.inbox):
            raise ValueError("reward exchange inbox and outbox must be disjoint")
        for path in (self.inbox, self.outbox):
            ensure_private_directory(path)
        self.series = digest(signer.journal.series)
        self.maximum_bytes = (len(signer.journal.series.cohorts) + 2) * MAX_DECISION_BYTES

    def _request_path(self, root: Path, sequence: int) -> Path:
        return root / "requests" / self.series / (self.signer.journal._slot(sequence) + ".json")

    def _vote_path(self, root: Path, sequence: int, hotkey: str) -> Path:
        return (
            root
            / "votes"
            / self.series
            / self.signer.journal._slot(sequence)
            / (identity(hotkey) + ".json")
        )

    def _check(self, request: RewardReviewRequest, sequence: int) -> RewardReviewRequest:
        j = self.signer.journal
        verify_reward_decision_proposal(j.series, j.policy, request.preceding, request.decision)
        if (
            request.decision.sequence != sequence
            or identity(request.proposer_vote.hotkey) != self.proposer
        ):
            raise ValueError("reward request changes its sequence or configured proposer")
        verify_signature(request.decision, request.proposer_vote)
        return request

    def publish_request(self, body: RewardControlDecision, prefix: Prefix) -> None:
        j = self.signer.journal
        if j.signer != self.proposer:
            raise ValueError("only the configured proposer may publish review requests")
        with j.journal.locked():
            intent = j.load(body.sequence)
            vote = j.vote(body.sequence, j.reviewers[self.proposer].hotkey)
            if intent is None or intent.decision != body or vote is None:
                raise ValueError("reward request lacks the proposer's reviewed durable vote")
            request = RewardReviewRequest(
                schema="umi-reward-review-request/1",
                decision=body,
                preceding=prefix,
                proposer_vote=vote,
            )
            self._check(request, body.sequence)
            publish_private_model(
                self._request_path(self.outbox, body.sequence),
                request,
                maximum_bytes=self.maximum_bytes,
            )

    def request(self, sequence: int) -> RewardReviewRequest:
        return self._check(
            read(
                self._request_path(self.inbox, sequence),
                RewardReviewRequest,
                maximum_bytes=self.maximum_bytes,
            ),
            sequence,
        )

    def vote_port(self, hotkey: str):
        account = identity(hotkey)
        if account not in self.signer.journal.reviewers or account == self.proposer:
            raise ValueError("reward peer is outside the approved independent reviewers")

        async def vote(body: RewardControlDecision, prefix: Prefix) -> Signature:
            await run_owned_thread(self.publish_request, body, prefix)
            value = await run_owned_thread(
                partial(
                    read,
                    self._vote_path(self.inbox, body.sequence, hotkey),
                    Signature,
                    maximum_bytes=2048,
                )
            )
            if identity(value.hotkey) != account:
                raise ValueError("reward peer delivery changes its selected signer")
            verify_signature(body, value)
            return value

        return vote

    async def review(self, request: RewardReviewRequest, reviewer: StandingRewardDecisionReviewer):
        # Incoming JSON or a copied vote cannot replace native original review.
        self._check(request, request.decision.sequence)
        j = self.signer.journal
        if (
            digest(reviewer.reader.series) != self.series
            or digest(reviewer.reader.policy) != digest(j.policy)
            or reviewer.reader.chain_config_sha256 != j.chain_config_sha256
        ):
            raise ValueError("reward reviewer differs from the selected exchange")
        reviewed = await reviewer.review(request.decision, request.preceding)
        vote = await self.signer.attest(reviewed)
        await run_owned_thread(
            partial(
                publish_private_model,
                self._vote_path(
                    self.outbox, request.decision.sequence, j.reviewers[j.signer].hotkey
                ),
                vote,
                maximum_bytes=2048,
            )
        )

    async def run_reviewer(
        self, reviewer: StandingRewardDecisionReviewer, stop: asyncio.Event, *, poll_seconds: float
    ) -> None:
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("reward reviewer poll interval is invalid")
        completed: dict[int, bytes] = {}
        while not stop.is_set():
            reviewer.provider.ensure_observer_running()
            # Fixed approved slots, not an unbounded directory scan. An early
            # missing or failed request cannot starve a delivered successor.
            for sequence in range(len(self.signer.journal.series.cohorts) + 1):
                if stop.is_set():
                    break
                try:
                    request = await run_owned_thread(self.request, sequence)
                    raw = canonical_json_bytes(request)
                    if sequence in completed:
                        if completed[sequence] != raw:
                            raise ValueError("completed reward request changed")
                        continue
                    await self.review(request, reviewer)
                    completed[sequence] = raw
                    logger.info("reward_review_delivered sequence=%d", sequence)
                except FileNotFoundError:
                    continue
                except Exception as error:
                    logger.warning(
                        "reward_review_retry sequence=%d reason=%s", sequence, type(error).__name__
                    )
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
