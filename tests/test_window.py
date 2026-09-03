from __future__ import annotations

import hashlib

import pytest

from umi.window import (
    QUICKNET_GENESIS_MS,
    WindowClock,
    ceil_div,
    quicknet_round_at_ms,
)


def _clock() -> WindowClock:
    return WindowClock(
        activation_block=1_000,
        window_stride_blocks=360,
        proposal_blocks=30,
        anchor_blocks=45,
        target_block_interval_seconds=12,
        selection_finality_buffer_seconds=300,
        issue_allowance_seconds=61,
        response_window_seconds=62,
        delivery_grace_seconds=60,
        reveal_margin_seconds=301,
    )


def test_window_schedule_reproduces_the_binary_protocol_formula() -> None:
    clock = _clock()
    index = 7
    timestamp_ms = QUICKNET_GENESIS_MS + 10_000_000
    block_hash = "0x" + "11" * 32
    policy_hash = "22" * 32

    schedule = clock.derive(
        index,
        netuid=78,
        announcement_block_hash=block_hash,
        announcement_timestamp_ms=timestamp_ms,
        scoring_policy_hash=policy_hash,
    )

    announcement = 1_000 + index * 360
    selection_ms = timestamp_ms + 1_000 * (45 * 12 + 300)
    elapsed = selection_ms - QUICKNET_GENESIS_MS
    selection_round = (elapsed + 2_999) // 3_000 + 1
    issue_close = selection_round + (61 + 2) // 3
    response_close = issue_close + (62 + 2) // 3
    reveal = response_close + (301 + 2) // 3
    expected_id = hashlib.sha256(
        b"umi-window-v1\0"
        + (78).to_bytes(2, "big")
        + index.to_bytes(8, "big")
        + bytes.fromhex(block_hash[2:])
        + (announcement + 45).to_bytes(8, "big")
        + selection_round.to_bytes(8, "big")
        + response_close.to_bytes(8, "big")
        + reveal.to_bytes(8, "big")
        + bytes.fromhex(policy_hash)
    ).hexdigest()

    assert schedule.announcement_block == announcement
    assert schedule.proposal_close_block == announcement + 30
    assert schedule.closing_block == announcement + 45
    assert schedule.selection_round == selection_round
    assert schedule.issue_close_round == issue_close
    assert schedule.response_close_round == response_close
    assert schedule.response_deadline_blocks == (61 + 62 + 11) // 12
    assert schedule.reveal_round == reveal
    assert schedule.window_id == expected_id


@pytest.mark.parametrize(
    ("timestamp_ms", "round_number"),
    [
        (QUICKNET_GENESIS_MS - 1, 1),
        (QUICKNET_GENESIS_MS, 1),
        (QUICKNET_GENESIS_MS + 1, 2),
        (QUICKNET_GENESIS_MS + 2_999, 2),
        (QUICKNET_GENESIS_MS + 3_000, 2),
        (QUICKNET_GENESIS_MS + 3_001, 3),
    ],
)
def test_quicknet_round_at_ms_uses_the_first_round_at_or_after_the_timestamp(
    timestamp_ms: int,
    round_number: int,
) -> None:
    assert quicknet_round_at_ms(timestamp_ms) == round_number


def test_integer_ceiling_division_rejects_implicit_booleans_and_invalid_ranges() -> None:
    assert ceil_div(0, 3) == 0
    assert ceil_div(1, 3) == 1
    assert ceil_div(6, 3) == 2
    assert ceil_div(7, 3) == 3
    assert ceil_div(2**80 + 1, 3) == ((2**80 + 1) + 2) // 3

    with pytest.raises(TypeError):
        ceil_div(True, 3)
    with pytest.raises(TypeError):
        quicknet_round_at_ms(False)
    with pytest.raises(ValueError):
        ceil_div(-1, 3)
    with pytest.raises(ValueError):
        ceil_div(1, 0)


def test_window_clock_and_derive_fail_closed_on_noncanonical_inputs() -> None:
    with pytest.raises(ValueError, match="proposal_blocks"):
        WindowClock(
            activation_block=0,
            window_stride_blocks=1,
            proposal_blocks=5,
            anchor_blocks=5,
            target_block_interval_seconds=12,
            selection_finality_buffer_seconds=1,
            issue_allowance_seconds=1,
            response_window_seconds=1,
            delivery_grace_seconds=1,
            reveal_margin_seconds=1,
        )

    clock = _clock()
    common = {
        "netuid": 78,
        "announcement_block_hash": "0x" + "11" * 32,
        "announcement_timestamp_ms": QUICKNET_GENESIS_MS,
        "scoring_policy_hash": "22" * 32,
    }
    with pytest.raises(ValueError, match="window index"):
        clock.derive(-1, **common)
    with pytest.raises(ValueError, match="netuid"):
        clock.derive(0, **{**common, "netuid": 65_536})
    with pytest.raises(ValueError, match="0x-prefixed"):
        clock.derive(0, **{**common, "announcement_block_hash": "11" * 32})
    with pytest.raises(ValueError, match="block hash"):
        clock.derive(0, **{**common, "announcement_block_hash": "0x11"})
