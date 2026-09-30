"""Policy-bound request windows from an owned registration finality observer.

Finality evidence describes the chain, not scoring rules. This view checks both
configurations and the observer's original binding before exposing the unchanged
proof bytes under the selected transport policy. It never rewrites the store.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from .competition_execution import execution_boundary
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_historical_registration import HistoricalRegistrationProvider


class CompetitionTransportFinality:
    def __init__(self, provider: HistoricalRegistrationProvider, transport: ScoringPolicy):
        self.provider = provider
        self.transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
        pins, config = self.transport.implementation_pins, provider.config
        if (
            pins.pin_profile != "live_shadow_calibration"
            or pins.live_chain != config.chain_pin
            or pins.finality_verifier != config.finality_pin
            or self.transport.netuid != provider.policy.netuid
        ):
            raise ValueError("transport and registration require identical chain and verifier pins")
        self.policy_hash = scoring_policy_hash(self.transport)

    async def finalized_head_height(self):
        # A current registration capture already enforces startup, observer and
        # timestamp freshness. Historical windows are not fresh captures.
        return execution_boundary(await self.provider.collect()).block

    async def verified_block_at(self, height):
        block = await self.provider._finality.verified_block_at(height)
        if block is None:
            return None
        self.provider._check_finality_context(block)
        if block.height != height:
            raise ValueError("transport observer returned another block")
        return replace(block, scoring_policy_hash=self.policy_hash)
