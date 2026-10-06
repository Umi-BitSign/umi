"""A cohort attempt's two deadlines derive from the same verified issuance.

This is an explicit cohort recovery extension, not a reinterpretation of the
legacy selection clock. Its window ID binds the authorized job and attempt.
Legacy requests keep their original window IDs and expiry rules.
"""

from __future__ import annotations

from .open_competition import digest
from .policy import ScoringPolicy, scoring_policy_hash
from .validator_plans import VerifiedFinalizedBlock
from .window import WindowSchedule, ceil_div, quicknet_round_at_ms


def cohort_attempt_schedule(
    transport: ScoringPolicy,
    issuance: VerifiedFinalizedBlock,
    *,
    cohort_sha256: str,
    job_sha256: str,
    attempt_number: int,
) -> WindowSchedule:
    if not isinstance(issuance, VerifiedFinalizedBlock):
        raise TypeError("attempt clock requires verified issuance")
    if issuance.height < transport.activation_block:
        raise ValueError("attempt issuance precedes transport activation")
    if type(attempt_number) is not int or not 1 <= attempt_number <= 2**53 - 1:
        raise ValueError("invalid cohort attempt number")
    for value in (cohort_sha256, job_sha256):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("invalid cohort attempt identity")
    clock = transport.clock
    blocks = ceil_div(
        clock.issue_allowance_seconds + clock.response_window_seconds,
        clock.target_block_interval_seconds,
    )
    # Round up once to the block budget, then derive both representations from
    # it. Quicknet rounds add at most one round of quantization, not another
    # selection-window lifetime.
    budget_ms = blocks * clock.target_block_interval_seconds * 1000
    deadline_block = issuance.height + blocks
    response_close_round = quicknet_round_at_ms(issuance.timestamp_ms + budget_ms)
    reveal_round = quicknet_round_at_ms(
        issuance.timestamp_ms + budget_ms + clock.reveal_margin_seconds * 1000
    )
    window_id = digest(
        [
            "umi-cohort-attempt-window/2",
            cohort_sha256,
            job_sha256,
            attempt_number,
            scoring_policy_hash(transport),
            issuance.height,
            issuance.block_hash,
            issuance.timestamp_ms,
            deadline_block,
            response_close_round,
            reveal_round,
        ]
    )
    return WindowSchedule(
        index=(issuance.height - transport.activation_block) // clock.window_stride_blocks,
        announcement_block=issuance.height,
        proposal_close_block=issuance.height,
        closing_block=issuance.height,
        selection_round=quicknet_round_at_ms(issuance.timestamp_ms),
        issue_close_round=quicknet_round_at_ms(
            issuance.timestamp_ms + clock.issue_allowance_seconds * 1000
        ),
        response_close_round=response_close_round,
        response_deadline_blocks=blocks,
        reveal_round=reveal_round,
        window_id=window_id,
    )
