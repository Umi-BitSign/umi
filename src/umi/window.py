"""Deterministic selection-window scheduling for protocol version 0.1."""

from __future__ import annotations

from dataclasses import dataclass

from .encoding import raw_sha256, sha256_domain, u16be, u64be

QUICKNET_GENESIS_MS = 1_692_803_367_000
QUICKNET_PERIOD_MS = 3_000


def ceil_div(numerator: int, denominator: int) -> int:
    if isinstance(numerator, bool) or isinstance(denominator, bool):
        raise TypeError("ceil_div operands must be integers")
    if not isinstance(numerator, int) or not isinstance(denominator, int):
        raise TypeError("ceil_div operands must be integers")
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div requires a non-negative numerator and positive denominator")
    return (numerator + denominator - 1) // denominator


def quicknet_round_at_ms(timestamp_ms: int) -> int:
    """Return the first Quicknet round published at or after a UTC millisecond."""

    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int):
        raise TypeError("timestamp_ms must be an integer")
    elapsed = timestamp_ms - QUICKNET_GENESIS_MS
    if elapsed <= 0:
        return 1
    return ceil_div(elapsed, QUICKNET_PERIOD_MS) + 1


@dataclass(frozen=True)
class WindowSchedule:
    index: int
    announcement_block: int
    proposal_close_block: int
    closing_block: int
    selection_round: int
    issue_close_round: int
    response_close_round: int
    response_deadline_blocks: int
    reveal_round: int
    window_id: str


@dataclass(frozen=True)
class WindowClock:
    activation_block: int
    window_stride_blocks: int
    proposal_blocks: int
    anchor_blocks: int
    target_block_interval_seconds: int
    selection_finality_buffer_seconds: int
    issue_allowance_seconds: int
    response_window_seconds: int
    delivery_grace_seconds: int
    reveal_margin_seconds: int

    def __post_init__(self) -> None:
        integer_fields = (
            "activation_block",
            "window_stride_blocks",
            "proposal_blocks",
            "anchor_blocks",
            "target_block_interval_seconds",
            "selection_finality_buffer_seconds",
            "issue_allowance_seconds",
            "response_window_seconds",
            "delivery_grace_seconds",
            "reveal_margin_seconds",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
        if self.activation_block < 0:
            raise ValueError("activation_block must not be negative")
        if self.window_stride_blocks <= 0:
            raise ValueError("window_stride_blocks must be positive")
        if not 0 < self.proposal_blocks < self.anchor_blocks:
            raise ValueError("policy requires 0 < proposal_blocks < anchor_blocks")
        for name in (
            "target_block_interval_seconds",
            "selection_finality_buffer_seconds",
            "issue_allowance_seconds",
            "response_window_seconds",
            "delivery_grace_seconds",
            "reveal_margin_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")

    def derive(
        self,
        index: int,
        *,
        netuid: int,
        announcement_block_hash: str | bytes,
        announcement_timestamp_ms: int,
        scoring_policy_hash: str | bytes,
    ) -> WindowSchedule:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("window index must be a non-negative integer")
        if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= 0xFFFF:
            raise ValueError("netuid must fit u16")
        if isinstance(announcement_timestamp_ms, bool) or not isinstance(
            announcement_timestamp_ms, int
        ):
            raise TypeError("announcement_timestamp_ms must be an integer")

        announcement = self.activation_block + index * self.window_stride_blocks
        proposal_close = announcement + self.proposal_blocks
        closing = announcement + self.anchor_blocks
        selection_timestamp_ms = announcement_timestamp_ms + 1000 * (
            self.anchor_blocks * self.target_block_interval_seconds
            + self.selection_finality_buffer_seconds
        )
        selection_round = quicknet_round_at_ms(selection_timestamp_ms)
        issue_close_round = selection_round + ceil_div(self.issue_allowance_seconds, 3)
        response_close_round = issue_close_round + ceil_div(self.response_window_seconds, 3)
        response_deadline_blocks = ceil_div(
            self.issue_allowance_seconds + self.response_window_seconds,
            self.target_block_interval_seconds,
        )
        reveal_round = response_close_round + ceil_div(self.reveal_margin_seconds, 3)
        window_id = sha256_domain(
            b"umi-window-v1\0",
            u16be(netuid),
            u64be(index),
            _raw_block_hash(announcement_block_hash),
            u64be(closing),
            u64be(selection_round),
            u64be(response_close_round),
            u64be(reveal_round),
            raw_sha256(scoring_policy_hash, field="scoring policy hash"),
        ).hex()
        return WindowSchedule(
            index=index,
            announcement_block=announcement,
            proposal_close_block=proposal_close,
            closing_block=closing,
            selection_round=selection_round,
            issue_close_round=issue_close_round,
            response_close_round=response_close_round,
            response_deadline_blocks=response_deadline_blocks,
            reveal_round=reveal_round,
            window_id=window_id,
        )


def _raw_block_hash(value: str | bytes) -> bytes:
    if isinstance(value, str):
        if not value.startswith("0x"):
            raise ValueError("block hash must be 0x-prefixed")
        value = value[2:]
    return raw_sha256(value, field="block hash")


__all__ = [
    "QUICKNET_GENESIS_MS",
    "QUICKNET_PERIOD_MS",
    "WindowClock",
    "WindowSchedule",
    "ceil_div",
    "quicknet_round_at_ms",
]
