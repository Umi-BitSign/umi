"""Proof-backed admission control for UMI miner requests.

An authenticated validator is still an adversarial network peer.  The miner must
therefore derive the only acceptable request window from independently verified
chain history before caller-controlled identifiers reach durable resource state.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .policy import (
    ScoringPolicy,
    require_live_chain_observation,
    scoring_policy_hash,
)
from .protocol import TranslationRequest
from .validator_plans import VerifiedFinalizedAnnouncementPort, VerifiedFinalizedBlock
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, WindowClock


class MinerAdmissionError(RuntimeError):
    """Stable request rejection at the miner's chain-authority boundary."""

    def __init__(self, reason_code: str, *, retryable: bool = False) -> None:
        if not isinstance(reason_code, str) or not reason_code:
            raise ValueError("admission reason code must be nonempty text")
        self.reason_code = reason_code
        self.retryable = retryable
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class MinerWindowAdmission:
    """Authoritative schedule identity admitted for one exact request."""

    window_index: int
    window_id: str
    response_close_round: int
    reveal_round: int
    observed_finalized_height: int


@runtime_checkable
class MinerWindowAuthority(Protocol):
    """Resolve a request against a verifier-owned finalized-chain view."""

    async def authorize(self, request: TranslationRequest) -> MinerWindowAdmission:
        """Return the derived window or reject before any resource reservation."""


class ProofBackedMinerWindowAuthority:
    """Admit only requests matching a policy-derived, verifier-owned window."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        finalized_blocks: VerifiedFinalizedAnnouncementPort,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be a ScoringPolicy")
        if not callable(getattr(finalized_blocks, "finalized_head_height", None)) or not callable(
            getattr(finalized_blocks, "verified_block_at", None)
        ):
            raise TypeError("finalized_blocks must implement the verified finalized-block port")
        pins = policy.implementation_pins
        if (
            pins.pin_profile != "live_shadow_calibration"
            or pins.live_chain is None
            or pins.finality_verifier is None
        ):
            raise ValueError("proof-backed miner admission requires live chain/finality pins")
        self._policy = policy
        self._policy_hash = scoring_policy_hash(policy)
        self._finalized_blocks = finalized_blocks
        self._clock = WindowClock(
            activation_block=policy.activation_block,
            window_stride_blocks=policy.clock.window_stride_blocks,
            proposal_blocks=policy.clock.proposal_blocks,
            anchor_blocks=policy.clock.anchor_blocks,
            target_block_interval_seconds=policy.clock.target_block_interval_seconds,
            selection_finality_buffer_seconds=policy.clock.selection_finality_buffer_seconds,
            issue_allowance_seconds=policy.clock.issue_allowance_seconds,
            response_window_seconds=policy.clock.response_window_seconds,
            delivery_grace_seconds=policy.clock.delivery_grace_seconds,
            reveal_margin_seconds=policy.clock.reveal_margin_seconds,
        )

    async def authorize(self, request: TranslationRequest) -> MinerWindowAdmission:
        if not isinstance(request, TranslationRequest):
            raise TypeError("request must be a TranslationRequest")
        if request.issued_block < self._policy.activation_block:
            raise MinerAdmissionError("request_precedes_policy_activation")

        window_index = (
            request.issued_block - self._policy.activation_block
        ) // self._policy.clock.window_stride_blocks
        announcement_height = (
            self._policy.activation_block + window_index * self._policy.clock.window_stride_blocks
        )
        try:
            head = await self._finalized_blocks.finalized_head_height()
        except Exception as error:
            raise MinerAdmissionError("finalized_head_unavailable", retryable=True) from error
        if isinstance(head, bool) or not isinstance(head, int) or head < 0:
            raise MinerAdmissionError("finalized_head_invalid", retryable=True)
        if head < request.issued_block:
            raise MinerAdmissionError("issuance_block_not_finalized", retryable=True)
        if head > request.deadline_block:
            raise MinerAdmissionError("request_block_deadline_elapsed")

        try:
            announcement, issuance = await asyncio.gather(
                self._finalized_blocks.verified_block_at(announcement_height),
                self._finalized_blocks.verified_block_at(request.issued_block),
            )
        except Exception as error:
            raise MinerAdmissionError("finalized_history_unavailable", retryable=True) from error
        if announcement is None or issuance is None:
            raise MinerAdmissionError("finalized_history_unavailable", retryable=True)
        self._validate_verified_block(announcement, expected_height=announcement_height)
        self._validate_verified_block(issuance, expected_height=request.issued_block)

        schedule = self._clock.derive(
            window_index,
            netuid=self._policy.netuid,
            announcement_block_hash=announcement.block_hash,
            announcement_timestamp_ms=announcement.timestamp_ms,
            scoring_policy_hash=self._policy_hash,
        )
        selection_ms = QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS
        issue_close_ms = QUICKNET_GENESIS_MS + (schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        if request.issued_block <= schedule.closing_block:
            raise MinerAdmissionError("issuance_block_not_after_pool_close")
        if not selection_ms <= issuance.timestamp_ms < issue_close_ms:
            raise MinerAdmissionError("issuance_outside_window")

        expected_deadline = request.issued_block + schedule.response_deadline_blocks
        if (
            request.scoring_policy_hash != self._policy_hash
            or request.window_id != schedule.window_id
            or request.issued_block_hash != issuance.block_hash
            or request.deadline_block != expected_deadline
            or request.response_close_round != schedule.response_close_round
            or request.reveal_round != schedule.reveal_round
        ):
            raise MinerAdmissionError("request_window_binding_mismatch")
        return MinerWindowAdmission(
            window_index=window_index,
            window_id=schedule.window_id,
            response_close_round=schedule.response_close_round,
            reveal_round=schedule.reveal_round,
            observed_finalized_height=head,
        )

    def _validate_verified_block(
        self,
        block: VerifiedFinalizedBlock,
        *,
        expected_height: int,
    ) -> None:
        if not isinstance(block, VerifiedFinalizedBlock) or block.height != expected_height:
            raise MinerAdmissionError("finalized_block_invalid", retryable=True)
        if block.scoring_policy_hash != self._policy_hash:
            raise MinerAdmissionError("finalized_block_policy_mismatch")
        try:
            require_live_chain_observation(self._policy, block.chain_observation)
        except (TypeError, RuntimeError) as error:
            raise MinerAdmissionError("finalized_block_chain_mismatch") from error
        pin = self._policy.implementation_pins.finality_verifier
        if pin is None or block.finality_verifier_sha256 not in set(
            pin.release_sha256_by_target.values()
        ):
            raise MinerAdmissionError("finality_verifier_mismatch")


@dataclass(frozen=True, slots=True)
class LocalComponentWindowAuthority:
    """Explicitly non-conforming authority for isolated component fixtures only."""

    window_index: int = 0

    async def authorize(self, request: TranslationRequest) -> MinerWindowAdmission:
        if not isinstance(request, TranslationRequest):
            raise TypeError("request must be a TranslationRequest")
        return MinerWindowAdmission(
            window_index=self.window_index,
            window_id=request.window_id,
            response_close_round=request.response_close_round,
            reveal_round=request.reveal_round,
            observed_finalized_height=request.issued_block,
        )


__all__ = [
    "LocalComponentWindowAuthority",
    "MinerAdmissionError",
    "MinerWindowAdmission",
    "MinerWindowAuthority",
    "ProofBackedMinerWindowAuthority",
]
