"""Prepare matching native reward boot candidates from one signed selection.

This pure step changes neither installed configuration nor a reward hold. The
caller must retain the exact candidate bytes, select them through the supported
cooperative owner handoff, and verify each restarted consumer's selected bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .competition_reward_adoption import (
    RewardAdoptionSelection,
    SignedRewardModelAdoption,
    select_signed_initial_reward_adoption,
)
from .competition_reward_boot import StandingRewardBootConfig
from .competition_reward_coordinator_boot import RewardCoordinatorConfig
from .protocol import canonical_json_bytes

WRITER_SUPPLEMENTAL_MODE = 0o444


@dataclass(frozen=True)
class RewardAdoptionBootCandidates:
    selection: RewardAdoptionSelection
    coordinator: bytes
    writer: bytes
    writer_supplemental: bytes


def _candidate(original: bytes, selected: RewardAdoptionSelection, kind):
    value = json.loads(original)
    value["reward_adoptions"] = selected.model_dump(mode="json", by_alias=True)
    raw = canonical_json_bytes(value)
    parsed = kind.model_validate_json(raw)
    if parsed.reward_adoptions != selected:
        raise ValueError("reward boot candidate changed its signed selection")
    return raw


def prepare_reward_adoption_boot_candidates(
    coordinator_raw: bytes,
    writer_raw: bytes,
    signed: SignedRewardModelAdoption,
) -> RewardAdoptionBootCandidates:
    """Extend both original boots with the same authenticated initial adoption.

    Inputs are compact native boot metadata. No package object, model payload,
    journal, key, RPC endpoint or installed service is opened here.
    """
    coordinator = RewardCoordinatorConfig.model_validate_json(coordinator_raw)
    writer = StandingRewardBootConfig.model_validate_json(writer_raw)
    if (
        canonical_json_bytes(coordinator) != coordinator_raw
        or canonical_json_bytes(writer) != writer_raw
    ):
        raise ValueError("reward handoff requires canonical installed boot bytes")
    if (
        coordinator.series != writer.series
        or coordinator.policy != writer.policy
        or coordinator.reward_adoptions != writer.reward_adoptions
    ):
        raise ValueError("coordinator and writer disagree on signed reward lineage")
    selected = select_signed_initial_reward_adoption(
        coordinator.reward_adoptions,
        signed,
        series=coordinator.series,
        policy=coordinator.policy,
    )
    return RewardAdoptionBootCandidates(
        selection=selected,
        coordinator=_candidate(coordinator_raw, selected, RewardCoordinatorConfig),
        writer=_candidate(writer_raw, selected, StandingRewardBootConfig),
        writer_supplemental=canonical_json_bytes(selected),
    )
