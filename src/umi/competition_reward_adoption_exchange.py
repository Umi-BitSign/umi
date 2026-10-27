"""Bounded original-proof requests and independent native adoption votes.

The configured proposer authenticates the exact proposal. Original proof bytes
pin issuance; they never substitute for the peer's native historical review or
its separate fresh current-control observation before a new signature.

Peers select the same immutable logical chain configuration. Physical runtime
and state locations may be independently bound through the supported resource
layout; a different logical chain configuration remains an explicit refusal.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import os
import stat
from collections import OrderedDict
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_recovery import verify_recovery_quorum
from .competition_evidence_codec import MAX_EVIDENCE_BYTES, MAX_METADATA_BYTES, checked_digest
from .competition_reward_adoption import MAX_REWARD_DECISIONS, RewardAutomaticRelease
from .competition_reward_coverage_service import StandingRewardCoverageService
from .competition_reward_decisions import MAX_DECISION_BYTES, SignedRewardControlDecision
from .competition_reward_transition_controls import (
    RewardTransitionControlReader,
    SignedRewardTransitionApproval,
    verify_transition_approval,
)
from .competition_reward_transition_native import (
    NativeRewardTransitionReviewer,
    RewardAdoptionReviewIntent,
    validate_reward_adoption_review,
)
from .competition_reward_transition_signing import MAX_ADOPTION_BYTES, RewardAdoptionSigner
from .competition_work_progress import WorkProgress
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import ensure_private_directory, private_path, publish_private_model
from .private_files import read_private_model as read
from .protocol import StrictProtocolModel

logger = logging.getLogger(__name__)
MAX_ADOPTION_REVIEW_BYTES = (
    2 * (MAX_EVIDENCE_BYTES + MAX_METADATA_BYTES) + MAX_ADOPTION_BYTES + MAX_DECISION_BYTES + 8192
)


class RewardAdoptionReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-reward-adoption-review-request/1"] = Field(alias="schema")
    intent: RewardAdoptionReviewIntent
    predecessor: SignedRewardControlDecision
    proposer_vote: Signature
    control_evidence_hex: Annotated[str, Field(min_length=2, max_length=2 * MAX_EVIDENCE_BYTES)]
    control_metadata_hex: Annotated[str, Field(min_length=2, max_length=2 * MAX_METADATA_BYTES)]
    operator_approval: SignedRewardTransitionApproval | None = None


class RewardAdoptionProgressionHeld(ValueError):
    """An existing cohort hold takes precedence over either release trigger."""


def _archive(request):
    result = []
    for encoded, expected, maximum in (
        (
            request.control_evidence_hex,
            request.intent.control_evidence_sha256,
            MAX_EVIDENCE_BYTES,
        ),
        (
            request.control_metadata_hex,
            request.intent.control_metadata_sha256,
            MAX_METADATA_BYTES,
        ),
    ):
        if type(encoded) is not str or not 2 <= len(encoded) <= 2 * maximum:
            raise ValueError("adoption original proof exceeds its bound")
        raw = bytes.fromhex(encoded)
        if raw.hex() != encoded or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("adoption original proof differs from its reviewed intent")
        result.append(raw)
    return tuple(result)


def _request_identity(request):
    # Exact original proof hashes are already fields of the immutable intent.
    # Do not reserialize the large proof strings for small journal bookkeeping.
    return digest(
        [
            digest(request.intent),
            digest(request.predecessor),
            digest(request.proposer_vote),
            None if request.operator_approval is None else digest(request.operator_approval),
        ]
    )


def _request_stamp(path):
    private_path(str(path))
    parent, info = path.parent.stat(), path.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o077
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
        or not 0 < info.st_size <= MAX_ADOPTION_REVIEW_BYTES
    ):
        raise ValueError("adoption request must retain its bounded private source identity")
    return (
        os.getpid(),
        parent.st_dev,
        parent.st_ino,
        parent.st_uid,
        parent.st_gid,
        parent.st_mode,
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class RewardAdoptionReviewExchange:
    def __init__(self, *, signer: RewardAdoptionSigner, proposer: str, inbox: Path, outbox: Path):
        if type(signer) is not RewardAdoptionSigner:
            raise TypeError("adoption exchange requires its durable native-reviewed signer")
        self.signer, self.proposer = signer, identity(proposer)
        if self.proposer not in signer.journal.reviewers:
            raise ValueError("adoption proposer is outside the configured evaluator set")
        self.inbox, self.outbox = (Path(private_path(str(p))) for p in (inbox, outbox))
        if self.inbox.is_relative_to(self.outbox) or self.outbox.is_relative_to(self.inbox):
            raise ValueError("adoption exchange inbox and outbox must be disjoint")
        for path in (self.inbox, self.outbox):
            ensure_private_directory(path)
        self.series = digest(signer.journal.series)
        self.serial = asyncio.Lock()
        self._pinned = None
        self._requests = OrderedDict()
        self._publication = None

    def _remember_request(self, path, stamp, request):
        self._requests[path] = stamp, request
        self._requests.move_to_end(path)
        # At most four large envelopes reside here; durable signing records do
        # not expire with this bounded transport working set.
        while len(self._requests) > 4:
            self._requests.popitem(last=False)

    def _read_request(self, path, slot):
        previous = self._requests.get(path)
        try:
            before = _request_stamp(path)
        except FileNotFoundError:
            if previous is not None:
                raise ValueError("adoption exchange lost its completed request") from None
            raise
        if previous is not None and previous[0] == before:
            self._requests.move_to_end(path)
            return previous[1]
        request = self._check(
            read(path, RewardAdoptionReviewRequest, maximum_bytes=MAX_ADOPTION_REVIEW_BYTES), slot
        )
        if _request_stamp(path) != before:
            raise ValueError("adoption request changed during its bounded read")
        if previous is not None and previous[1] != request:
            raise ValueError("adoption exchange changed its completed request")
        self._remember_request(path, before, request)
        return request

    @staticmethod
    def _slot(cohort, revision):
        checked_digest(cohort)
        if type(revision) is not int or not 1 <= revision <= MAX_REWARD_DECISIONS:
            raise ValueError("adoption exchange revision is outside its bound")
        return f"{cohort}-{revision:06d}"

    def _request_path(self, root, slot):
        return root / "requests" / self.series / ("adoption-" + slot + ".json")

    def _vote_path(self, root, slot, hotkey):
        return root / "votes" / self.series / ("adoption-" + slot) / (identity(hotkey) + ".json")

    def _check(self, request, slot):
        if type(request) is not RewardAdoptionReviewRequest:
            raise TypeError("adoption exchange requires its typed review request")
        j = self.signer.journal
        intent = j._intent(request.intent)
        if (
            j.slot(intent.proposal) != slot
            or identity(request.proposer_vote.hotkey) != self.proposer
            or digest(request.predecessor.decision) != intent.predecessor_decision_sha256
            or request.predecessor.decision.series_sha256 != self.series
        ):
            raise ValueError("adoption request changes its proposer, slot or signed predecessor")
        verify_signature(intent.proposal, request.proposer_vote)
        verify_recovery_quorum(
            request.predecessor.decision, request.predecessor.signatures, j.policy
        )
        if isinstance(intent.proposal.early_release, RewardAutomaticRelease):
            if request.operator_approval is not None:
                raise ValueError("automatic adoption must retain its selected timer trigger")
        else:
            if request.operator_approval is None:
                raise ValueError("operator adoption lacks its signed exact release approval")
            verify_transition_approval(
                request.operator_approval, series=j.series, proposal=intent.proposal
            )
        return request

    def publish_request(
        self,
        proposal,
        *,
        predecessor,
        control_evidence: bytes,
        control_metadata: bytes,
        operator_approval: SignedRewardTransitionApproval | None = None,
    ) -> RewardAdoptionReviewRequest:
        j = self.signer.journal
        if j.signer != self.proposer:
            raise ValueError("only the configured proposer may publish adoption requests")
        if type(control_evidence) is not bytes or type(control_metadata) is not bytes:
            raise TypeError("adoption request needs the original native proof bytes")
        slot = j.slot(proposal)
        with j.journal.locked():
            intent = j.load(slot)
            vote = j.vote(slot, j.reviewers[self.proposer].hotkey)
            if intent is None or intent.proposal != proposal or vote is None:
                raise ValueError("adoption request lacks the proposer's native durable vote")
            path = self._request_path(self.outbox, slot)
            publication = self._publication
            if publication is not None and publication[:5] == (
                intent,
                predecessor,
                vote,
                operator_approval,
                slot,
            ):
                if (control_evidence, control_metadata) != publication[5:]:
                    raise ValueError("adoption original bytes changed after request publication")
                return self._read_request(path, slot)
            request = RewardAdoptionReviewRequest(
                schema="umi-reward-adoption-review-request/1",
                intent=intent,
                predecessor=predecessor,
                proposer_vote=vote,
                control_evidence_hex=control_evidence.hex(),
                control_metadata_hex=control_metadata.hex(),
                operator_approval=operator_approval,
            )
            self._check(request, slot)
            _archive(request)
            publish_private_model(
                path,
                request,
                maximum_bytes=MAX_ADOPTION_REVIEW_BYTES,
            )
            self._remember_request(path, _request_stamp(path), request)
            self._publication = (
                intent,
                predecessor,
                vote,
                operator_approval,
                slot,
                control_evidence,
                control_metadata,
            )
            return request

    def request(self, cohort, revision):
        slot = self._slot(cohort, revision)
        return self._read_request(self._request_path(self.inbox, slot), slot)

    def vote_port(self, hotkey):
        account = identity(hotkey)
        if account not in self.signer.journal.reviewers or account == self.proposer:
            raise ValueError("adoption peer is outside the configured independent reviewers")

        async def vote(request: RewardAdoptionReviewRequest) -> Signature:
            slot = self.signer.journal.slot(request.intent.proposal)
            self._check(request, slot)
            value = await run_owned_thread(
                partial(
                    read, self._vote_path(self.inbox, slot, hotkey), Signature, maximum_bytes=2048
                )
            )
            if identity(value.hotkey) != account:
                raise ValueError("adoption vote delivery changes its selected signer")
            verify_signature(request.intent.proposal, value)
            return value

        return vote

    async def review(
        self, request, reviewer: NativeRewardTransitionReviewer, *, coverage=None, controls=None
    ):
        if type(reviewer) is not NativeRewardTransitionReviewer:
            raise TypeError("adoption exchange requires the selected native transition reviewer")
        async with self.serial:
            return await self._review(request, reviewer, coverage=coverage, controls=controls)

    async def _review(self, request, reviewer, *, coverage, controls):
        j, native = self.signer.journal, reviewer.reviewer
        slot = j.slot(request.intent.proposal)
        self._check(request, slot)
        if (
            digest(native.reader.series) != self.series
            or digest(native.reader.policy) != digest(j.policy)
            or native.reader.chain_config_sha256 != j.chain_config_sha256
        ):
            raise ValueError("native adoption reviewer differs from selected exchange")
        with WorkProgress(
            "reward_adoption_peer_review",
            4,
            unit="stages",
            cohort=request.intent.proposal.cohort_sha256,
            estimate=False,
            planning_range_seconds=(1, 300),
            planning_basis="one pinned native review, fresh control, durable vote and delivery",
        ) as progress:
            # A returned signature is already permanent. Lost delivery only
            # republishes it; it cannot create a new signature after a cutover.
            retained = await run_owned_thread(j.load, slot)
            vote = await run_owned_thread(j.vote, slot, j.reviewers[j.signer].hotkey)
            if retained is not None and retained != request.intent:
                raise ValueError("adoption request changes its retained native intent")
            if vote is None:
                if (
                    type(controls) is not RewardTransitionControlReader
                    or controls.series != j.series
                    or controls.policy != j.policy
                ):
                    raise TypeError(
                        "adoption signing requires its authoritative progression controls"
                    )
                if await run_owned_thread(controls.held, request.intent.proposal.cohort_sha256):
                    raise RewardAdoptionProgressionHeld("cohort progression is explicitly held")
                request_id = _request_identity(request)
                pinned_identity = (
                    reviewer,
                    request_id,
                    request.control_evidence_hex,
                    request.control_metadata_hex,
                )
                if self._pinned is None or self._pinned[0] != pinned_identity:
                    evidence, metadata = _archive(request)
                    observation = await native.provider.review_control(evidence, metadata)
                    self._pinned = pinned_identity, observation
                observation = self._pinned[1]
                progress.advance()
                package = await run_owned_thread(
                    native.files.verified_package, request.intent.proposal.package_sha256
                )
                live = None
                release = request.intent.proposal.early_release
                if isinstance(release, RewardAutomaticRelease):
                    if (
                        type(coverage) is not StandingRewardCoverageService
                        or coverage.provider is not native.provider
                        or coverage.preparation.reader is not native.reader
                    ):
                        raise TypeError(
                            "automatic adoption requires its selected native coverage owner"
                        )
                    source = await coverage._source(request.predecessor.decision.activation)
                    live = await source.replay(release.live_age.live_endpoint_sha256)
                current = await native.provider.collect_control(native.reader.series.control_hotkey)
                reviewed = await reviewer.review(
                    package=package,
                    proposal=request.intent.proposal,
                    predecessor=request.predecessor,
                    observation=observation,
                    current_observation=current,
                    live_endpoint=live,
                )
                if validate_reward_adoption_review(reviewed) != request.intent:
                    raise ValueError("independent adoption review differs from the pinned request")
                progress.advance()
                if await run_owned_thread(controls.held, request.intent.proposal.cohort_sha256):
                    raise RewardAdoptionProgressionHeld("cohort progression became explicitly held")
                vote = await self.signer.attest(reviewed)
                progress.advance()
            else:
                for _ in range(3):
                    progress.advance()
            await run_owned_thread(
                partial(
                    publish_private_model,
                    self._vote_path(self.outbox, slot, j.reviewers[j.signer].hotkey),
                    vote,
                    maximum_bytes=2048,
                )
            )
            progress.advance()
            return vote

    async def run_reviewer(
        self, reviewer, stop: asyncio.Event, *, poll_seconds: float, coverage=None, controls=None
    ):
        if type(reviewer) is not NativeRewardTransitionReviewer:
            raise TypeError("adoption exchange requires its native transition reviewer")
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("adoption reviewer poll interval is invalid")
        while not stop.is_set():
            native = reviewer.reviewer
            native.provider.ensure_observer_running()
            try:
                await run_owned_thread(native.reader.refresh_reward_adoptions)
                selected = await run_owned_thread(self.signer.journal.refresh_reward_adoptions)
            except Exception as error:
                logger.warning("adoption_review_feed_retry reason=%s", type(error).__name__)
            else:
                # One next revision per admitted successor, not an inbox scan.
                for plan in self.signer.journal.series.cohorts[1:]:
                    if stop.is_set():
                        break
                    cohort = digest(plan)
                    latest = None if selected is None else selected.latest(cohort)
                    revision = 1 if latest is None else latest.adoption.revision + 1
                    if revision > MAX_REWARD_DECISIONS:
                        continue
                    try:
                        request = await run_owned_thread(self.request, cohort, revision)
                        await self.review(request, reviewer, coverage=coverage, controls=controls)
                    except FileNotFoundError:
                        continue
                    except Exception as error:
                        logger.warning(
                            "adoption_review_retry cohort_sha256=%s revision=%d reason=%s",
                            cohort,
                            revision,
                            type(error).__name__,
                        )
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
