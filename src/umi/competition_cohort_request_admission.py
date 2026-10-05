"""Independently verify a quorum-authorized cohort attempt or its legacy window."""

from __future__ import annotations

from .competition_cohort_request_window import capture_cohort_attempt_window
from .miner_admission import (
    MinerAdmissionError,
    MinerWindowAdmission,
    ProofBackedMinerWindowAuthority,
)


class CohortRequestWindowAuthority:
    """Use only with a job already authenticated from its exact signed grant."""

    def __init__(self, *, policy, finalized_blocks, job, attempt_number):
        self.policy, self.blocks = policy, finalized_blocks
        self.job, self.attempt_number = job, attempt_number
        self.legacy = ProofBackedMinerWindowAuthority(
            policy=policy, finalized_blocks=finalized_blocks
        )

    async def authorize(self, request):
        try:
            window = await capture_cohort_attempt_window(
                self.policy, self.blocks, request.issued_block, self.job, self.attempt_number
            )
        except (OSError, TimeoutError) as error:
            raise MinerAdmissionError("finalized_history_unavailable", retryable=True) from error
        if request.window_id != window.schedule(self.policy).window_id:
            return await self.legacy.authorize(request)
        try:
            window.check(request, self.policy)
        except ValueError as error:
            raise MinerAdmissionError("request_window_binding_mismatch") from error
        head = await self.blocks.finalized_head_height()
        if type(head) is not int or head < request.issued_block:
            raise MinerAdmissionError("issuance_block_not_finalized", retryable=True)
        if head > request.deadline_block:
            raise MinerAdmissionError("request_block_deadline_elapsed")
        schedule = window.schedule(self.policy)
        return MinerWindowAdmission(
            window_index=schedule.index,
            window_id=schedule.window_id,
            response_close_round=schedule.response_close_round,
            reveal_round=schedule.reveal_round,
            observed_finalized_height=head,
        )
