"""Process-local binding of collected outcomes to a stopped host and owned head.

Collection belongs to the host observer. Archives consume this boundary without
importing host installation or activation orchestration.
"""

from __future__ import annotations

import weakref
from dataclasses import dataclass

from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_host_upgrade import HostUpgradeError, StoppedSupervisor
from .competition_recovery_models import BridgeRecoveryOutcome
from .protocol import canonical_json_bytes


@dataclass(frozen=True, eq=False)
class StoppedBridgeObservation:
    observation: OwnedCompetitionChainObservation
    snapshot_sha256: str
    outcomes: tuple[BridgeRecoveryOutcome, ...]
    _stopped: StoppedSupervisor


_BRIDGE_OBSERVATIONS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _bridge_binding(value: StoppedBridgeObservation) -> tuple:
    return (
        id(value.observation),
        value.observation._binding,
        value.snapshot_sha256,
        canonical_json_bytes([item.model_dump(mode="json") for item in value.outcomes]),
        id(value._stopped),
        value._stopped._binding,
    )


def validate_stopped_bridge_observation(
    value: StoppedBridgeObservation,
    *,
    stopped: StoppedSupervisor,
    observation: OwnedCompetitionChainObservation,
    snapshot_sha256: str,
) -> tuple[BridgeRecoveryOutcome, ...]:
    if (
        type(value) is not StoppedBridgeObservation
        or value not in _BRIDGE_OBSERVATIONS
        or _BRIDGE_OBSERVATIONS[value] != _bridge_binding(value)
        or value._stopped is not stopped
        or value.observation is not observation
        or value.snapshot_sha256 != snapshot_sha256
    ):
        raise HostUpgradeError("stopped bridge observation is absent, altered or misbound")
    stopped.recheck_stopped()
    validate_owned_weight_observation(observation)
    return value.outcomes
