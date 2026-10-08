"""Policy-bound request windows from an owned registration finality observer.

Finality evidence describes the chain, not scoring rules. This view checks both
configurations and the observer's original binding before exposing the unchanged
proof bytes under the selected transport policy. It never rewrites the store.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_historical_registration import HistoricalRegistrationProvider


def _compatible_live_chain_runtime(frozen, current) -> bool:
    """Accept the exact pin or a later runtime on the same chain family.

    A cohort can outlive a Subtensor runtime upgrade. The current registration
    provider verifies storage against the current metadata and runtime-code pin,
    while the frozen transport policy continues to bind scoring and request
    semantics. Runtime-dependent hashes may therefore advance together with a
    strictly newer spec version. Chain identity and SCALE/extrinsic families do
    not migrate implicitly.
    """

    if frozen == current:
        return True
    return (
        frozen is not None
        and frozen.network == current.network
        and frozen.genesis_block_hash == current.genesis_block_hash
        and frozen.transaction_version == current.transaction_version
        and frozen.state_version == current.state_version
        and frozen.runtime_spec_version < current.runtime_spec_version
    )


class CompetitionTransportFinality:
    def __init__(self, provider: HistoricalRegistrationProvider, transport: ScoringPolicy):
        self.provider = provider
        self.transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
        pins, config = self.transport.implementation_pins, provider.config
        if (
            pins.pin_profile != "live_shadow_calibration"
            or not _compatible_live_chain_runtime(pins.live_chain, config.chain_pin)
            or pins.finality_verifier != config.finality_pin
            or self.transport.netuid != provider.policy.netuid
        ):
            raise ValueError("transport and registration require compatible chain runtime pins")
        self.policy_hash = scoring_policy_hash(self.transport)

    async def finalized_head_height(self):
        # Window capture needs fresh owned finality, not another complete subnet
        # membership proof. Admission/review retains its separate collect() calls.
        return await self.provider.current_finalized_block()

    async def verified_block_at(self, height):
        block = await self.provider._finality.verified_block_at(height)
        if block is None:
            block = await self.provider._historical_request_blocks.recover(height)
            if block is None:
                return None
        else:
            self.provider._check_finality_context(block)
        if block.height != height:
            raise ValueError("transport observer returned another block")
        # The owned registration observer may advance to a newer compatible
        # Subtensor runtime while a cohort continues under its frozen transport
        # policy.  The compatibility check above binds that newer observation to
        # the same chain family.  Expose the unchanged finalized proof under the
        # transport's exact policy pins so request construction and miners do not
        # have to weaken their exact policy checks for arbitrary block sources.
        return replace(
            block,
            scoring_policy_hash=self.policy_hash,
            chain_observation=self.transport.implementation_pins.live_chain,
        )
