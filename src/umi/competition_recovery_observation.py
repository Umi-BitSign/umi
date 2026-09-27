"""Process-local binding of collected outcomes to a stopped host and owned head.

Collection belongs to the host observer. Archives consume this boundary without
importing host installation or activation orchestration.
"""

from __future__ import annotations

import weakref
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from .bridge.drain import VerifiedLegacyDrain
from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_host_upgrade import HostUpgradeError, StoppedSupervisor
from .competition_recovery_models import BridgeRecoveryOutcome
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_legacy_drain import StoppedLegacyDrain


@dataclass(frozen=True, eq=False)
class StoppedLegacyDrainProof:
    """Live stopped-writer and drain evidence, not permission to resume weights."""

    session: StoppedLegacyDrain
    result: VerifiedLegacyDrain

    def recheck(self) -> None:
        if type(self) is not StoppedLegacyDrainProof or _DRAIN_PROOFS.get(self) != _drain_binding(
            self
        ):
            raise HostUpgradeError("stopped legacy drain proof is absent or altered")
        self.session.recheck()


_DRAIN_PROOFS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _drain_binding(proof: StoppedLegacyDrainProof) -> tuple:
    return id(proof.session), canonical_json_bytes(asdict(proof.result))


def validate_stopped_legacy_drain(proof, *, stopped, observation, snapshot_sha256):
    if type(proof) is not StoppedLegacyDrainProof:
        raise HostUpgradeError("legacy drain requires its live stopped proof")
    proof.recheck()
    validate_owned_weight_observation(observation)
    if (
        proof.session.stopped is not stopped
        or proof.session.snapshot.sha256 != snapshot_sha256
        or observation.validator_hotkey != stopped.validator_hotkey
        or observation.block < proof.result.owned_head.block_number
        or (
            observation.block == proof.result.owned_head.block_number
            and observation.block_hash != proof.result.owned_head.block_hash
        )
    ):
        raise HostUpgradeError("legacy drain differs from the stopped snapshot or fresh head")
    return proof.result


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
