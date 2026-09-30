"""Construct bounded requests from verifier-owned blocks and retain their proof bytes."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .competition_cohort_endpoint import endpoint_attempt_wire_ids
from .miner_admission import ProofBackedMinerWindowAuthority
from .policy import LiveChainObservationPin, ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, Hex32, StrictProtocolModel, Task, TranslationRequest, Video
from .validator_plans import MAX_FINALITY_EVIDENCE_BYTES, VerifiedFinalizedBlock
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, WindowClock


class RetainedRequestBlock(StrictProtocolModel):
    height: Annotated[int, Field(ge=0)]
    block_hash: str
    state_root: str
    timestamp_ms: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    chain_observation: LiveChainObservationPin
    finality_verifier_sha256: Hex32
    finality_evidence_hex: Annotated[
        str, Field(pattern=r"^(?:[0-9a-f]{2})+$", max_length=2 * MAX_FINALITY_EVIDENCE_BYTES)
    ]
    finality_evidence_sha256: Hex32

    @classmethod
    def capture(cls, value: VerifiedFinalizedBlock):
        if not isinstance(value, VerifiedFinalizedBlock):
            raise TypeError("request window requires verified finalized blocks")
        return cls(
            **{
                name: getattr(value, name)
                for name in cls.model_fields
                if name != "finality_evidence_hex"
            },
            finality_evidence_hex=value.finality_evidence.hex(),
        )

    def verified(self):
        # The original port verifies finality. Recovery checks the retained proof
        # bytes, their digest and policy pins; it does not claim a fresh proof.
        return VerifiedFinalizedBlock(
            **self.model_dump(exclude={"finality_evidence_hex", "chain_observation"}),
            chain_observation=self.chain_observation,
            finality_evidence=bytes.fromhex(self.finality_evidence_hex),
        )


class EndpointRequestWindow(StrictProtocolModel):
    announcement: RetainedRequestBlock
    issuance: RetainedRequestBlock

    def schedule(self, transport: ScoringPolicy):
        announcement, issuance = self.announcement.verified(), self.issuance.verified()
        if issuance.height < transport.activation_block:
            raise ValueError("request issuance precedes transport activation")
        index = (
            issuance.height - transport.activation_block
        ) // transport.clock.window_stride_blocks
        height = transport.activation_block + index * transport.clock.window_stride_blocks
        # This native validator checks chain identity and finality verifier pins.
        authority = ProofBackedMinerWindowAuthority(policy=transport, finalized_blocks=_NoReads())
        authority._validate_verified_block(announcement, expected_height=height)
        authority._validate_verified_block(issuance, expected_height=issuance.height)
        clock = WindowClock(
            activation_block=transport.activation_block,
            **transport.clock.model_dump(
                exclude={"weight_commit_buffer_blocks", "weight_commit_submission_blocks"}
            ),
        )
        schedule = clock.derive(
            index,
            netuid=transport.netuid,
            announcement_block_hash=announcement.block_hash,
            announcement_timestamp_ms=announcement.timestamp_ms,
            scoring_policy_hash=scoring_policy_hash(transport),
        )
        start = QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS
        stop = QUICKNET_GENESIS_MS + (schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        if issuance.height <= schedule.closing_block or not start <= issuance.timestamp_ms < stop:
            raise ValueError("request issuance is outside its verified window")
        return schedule

    def check(self, request: TranslationRequest, transport: ScoringPolicy):
        schedule = self.schedule(transport)
        issuance = self.issuance
        if (
            request.scoring_policy_hash != scoring_policy_hash(transport)
            or request.window_id != schedule.window_id
            or request.issued_block != issuance.height
            or request.issued_block_hash != issuance.block_hash
            or request.deadline_block != issuance.height + schedule.response_deadline_blocks
            or request.response_close_round != schedule.response_close_round
            or request.reveal_round != schedule.reveal_round
        ):
            raise ValueError("request differs from its retained verified window")

    def request(self, job, case, video: Video, attempt: int, transport: ScoringPolicy):
        return self.request_with_ids(
            case, video, endpoint_attempt_wire_ids(job, attempt, case.case_id), transport
        )

    def request_with_ids(
        self, case, video: Video, wire_ids: tuple[str, str], transport: ScoringPolicy
    ):
        """Construct a window-bound request; the caller supplies authorized work IDs."""
        schedule = self.schedule(transport)
        if video.sha256 != case.video_sha256:
            raise ValueError("request video differs from its assigned case")
        batch, challenge = wire_ids
        return TranslationRequest(
            protocol=PROTOCOL_VERSION,
            window_id=schedule.window_id,
            batch_id=batch,
            challenge_id=challenge,
            issued_block=self.issuance.height,
            issued_block_hash=self.issuance.block_hash,
            deadline_block=self.issuance.height + schedule.response_deadline_blocks,
            response_close_round=schedule.response_close_round,
            reveal_round=schedule.reveal_round,
            video=video,
            task=Task(source_language="ase", target_language="en", stratum=case.stratum),
            scoring_policy_hash=scoring_policy_hash(transport),
        )


class _NoReads:
    """Only policy-pin validation is used during offline replay."""

    async def finalized_head_height(self):
        raise RuntimeError("offline request witness")

    async def verified_block_at(self, height):
        raise RuntimeError("offline request witness")


async def capture_request_window(transport, finalized_blocks, issued_block):
    if type(issued_block) is not int or issued_block < transport.activation_block:
        raise ValueError("request issuance precedes transport activation")
    index = (issued_block - transport.activation_block) // transport.clock.window_stride_blocks
    height = transport.activation_block + index * transport.clock.window_stride_blocks
    head = await finalized_blocks.finalized_head_height()
    if type(head) is not int or head < issued_block:
        raise OSError("request issuance is not finalized")
    announcement = await finalized_blocks.verified_block_at(height)
    issuance = await finalized_blocks.verified_block_at(issued_block)
    if announcement is None or issuance is None:
        raise OSError("request window history unavailable")
    window = EndpointRequestWindow(
        announcement=RetainedRequestBlock.capture(announcement),
        issuance=RetainedRequestBlock.capture(issuance),
    )
    if window.issuance.height != issued_block:
        raise ValueError("request window port returned another issuance")
    window.schedule(transport)
    return window
