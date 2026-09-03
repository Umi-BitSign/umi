from __future__ import annotations

from dataclasses import replace

import pytest

from umi.miner_admission import MinerAdmissionError, ProofBackedMinerWindowAuthority
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import TranslationRequest
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .factories import challenge_request
from .test_validator_plans import FinalizedPort, _block, _clock, _live_policy


def _case() -> tuple[ScoringPolicy, TranslationRequest, FinalizedPort]:
    policy = _live_policy(activation_block=1_000)
    announcement = _block(policy, 0, block_byte="31")
    schedule = _clock(policy).derive(
        0,
        netuid=policy.netuid,
        announcement_block_hash=announcement.block_hash,
        announcement_timestamp_ms=announcement.timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    issued_block = schedule.closing_block + 1
    issued_at_ms = QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS
    issuance = _block(
        policy,
        0,
        block_byte="41",
        height=issued_block,
        timestamp_ms=issued_at_ms,
    )
    request = challenge_request().model_copy(
        update={
            "window_id": schedule.window_id,
            "issued_block": issued_block,
            "issued_block_hash": issuance.block_hash,
            "deadline_block": issued_block + schedule.response_deadline_blocks,
            "response_close_round": schedule.response_close_round,
            "reveal_round": schedule.reveal_round,
            "scoring_policy_hash": scoring_policy_hash(policy),
        }
    )
    port = FinalizedPort(
        head=issued_block,
        blocks={announcement.height: announcement, issuance.height: issuance},
    )
    return policy, request, port


@pytest.mark.asyncio
async def test_admits_only_the_exact_proof_backed_window() -> None:
    policy, request, port = _case()
    authority = ProofBackedMinerWindowAuthority(policy=policy, finalized_blocks=port)

    admitted = await authority.authorize(request)

    assert admitted.window_index == 0
    assert admitted.window_id == request.window_id
    assert admitted.response_close_round == request.response_close_round
    assert admitted.reveal_round == request.reveal_round
    assert admitted.observed_finalized_height == request.issued_block
    assert port.block_calls == [policy.activation_block, request.issued_block]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("window_id", "99" * 32),
        ("issued_block_hash", "0x" + "99" * 32),
        ("response_close_round", 1),
        ("reveal_round", 2),
    ),
)
async def test_rejects_caller_selected_window_bindings(field: str, value: object) -> None:
    policy, request, port = _case()
    changed = request.model_copy(update={field: value})
    authority = ProofBackedMinerWindowAuthority(policy=policy, finalized_blocks=port)

    with pytest.raises(MinerAdmissionError, match="request_window_binding_mismatch"):
        await authority.authorize(changed)


@pytest.mark.asyncio
async def test_rejects_when_exact_finalized_history_was_not_observed() -> None:
    policy, request, port = _case()
    port.blocks.pop(request.issued_block)
    authority = ProofBackedMinerWindowAuthority(policy=policy, finalized_blocks=port)

    with pytest.raises(MinerAdmissionError, match="finalized_history_unavailable") as raised:
        await authority.authorize(request)
    assert raised.value.retryable is True


@pytest.mark.asyncio
async def test_rejects_after_the_block_deadline_without_reserving_work() -> None:
    policy, request, port = _case()
    port.head = request.deadline_block + 1
    authority = ProofBackedMinerWindowAuthority(policy=policy, finalized_blocks=port)

    with pytest.raises(MinerAdmissionError, match="request_block_deadline_elapsed"):
        await authority.authorize(request)
    assert port.block_calls == []


@pytest.mark.asyncio
async def test_rejects_an_issuance_block_outside_the_schedule_interval() -> None:
    policy, request, port = _case()
    issuance = port.blocks[request.issued_block]
    assert issuance is not None
    port.blocks[request.issued_block] = replace(issuance, timestamp_ms=1_692_803_367_000)
    authority = ProofBackedMinerWindowAuthority(policy=policy, finalized_blocks=port)

    with pytest.raises(MinerAdmissionError, match="issuance_outside_window"):
        await authority.authorize(request)
