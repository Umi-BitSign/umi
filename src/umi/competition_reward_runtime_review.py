"""Authenticated runtime selection for independent current and archive reviewers.

These entrypoints retain all complete-row, native-code, finality and consensus
checks of their underlying consumers. Imported height/profile hints cannot select
a different native root or turn a portable summary into verification authority.
"""

from __future__ import annotations

from .competition_chain_state import validate_owned_weight_observation
from .competition_reward_eligibility import collect_reward_eligibility, validate_reward_eligibility
from .competition_reward_eligibility_archive import review_reward_eligibility
from .competition_reward_runtime_adoption import SelectedRewardRuntime
from .open_competition import digest


def validate_selected_reward_eligibility(
    value, *, selection: SelectedRewardRuntime, expected_chain_config_sha256: str
):
    selection.recheck()
    validate_owned_weight_observation(value.chain)
    profile, adoption = selection.selected(value.chain.block)
    validate_reward_eligibility(
        value,
        expected_runtime_profile_sha256=digest(profile),
        expected_chain_config_sha256=expected_chain_config_sha256,
    )
    return adoption


async def collect_selected_reward_eligibility(
    provider, chain, *, selection: SelectedRewardRuntime, maximum_parent_hotkeys=4096
):
    selection.recheck()
    validate_owned_weight_observation(chain)
    if selection.policy_sha256 != digest(provider.policy):
        raise ValueError("selected reward runtime differs from provider policy")
    profile, _ = selection.selected(chain.block)
    value = await collect_reward_eligibility(
        provider,
        chain,
        profile,
        expected_runtime_profile_sha256=digest(profile),
        maximum_parent_hotkeys=maximum_parent_hotkeys,
    )
    validate_selected_reward_eligibility(
        value, selection=selection, expected_chain_config_sha256=digest(provider.config)
    )
    return value


async def review_selected_reward_eligibility(
    provider,
    *,
    selection: SelectedRewardRuntime,
    block: int,
    runtime_profile_sha256: str,
    runtime_adoption_sha256: str | None,
    **evidence,
):
    """Review an explicit original/effective archive identity at its native root."""
    selection.recheck()
    if selection.policy_sha256 != digest(provider.policy):
        raise ValueError("selected reward runtime differs from archive policy")
    profile = selection.check(
        block=block, profile_sha256=runtime_profile_sha256, adoption_sha256=runtime_adoption_sha256
    )
    value = await review_reward_eligibility(
        provider, profile=profile, expected_runtime_profile_sha256=digest(profile), **evidence
    )
    if value.control.snapshot.block_number != block:
        raise ValueError("runtime adoption archive hint differs from native proved block")
    return value
