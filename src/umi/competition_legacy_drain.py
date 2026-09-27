"""Fresh drain challenges bound to one stopped legacy installation.

No wallet or publication capability exists here. A separate, consented publisher
must include the challenge in a transaction while this context remains open.
Closing or losing the process discards its authority; a retry obtains a new
challenge after checking the stopped writer and unchanged state again.
"""

from __future__ import annotations

import secrets
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .bridge.drain import MARKER_DOMAIN
from .bridge.journal import RegistrationBridgeJournal
from .competition_bridge_recovery import JOURNAL, audit_bridge_history
from .competition_chain_state import FinalizedCompetitionWeightProvider
from .competition_host_upgrade import HostUpgradeError, StoppedSupervisor
from .competition_recovery import (
    LegacySnapshot,
    _check_current_manifest,
    _check_stopped,
    _snapshot_kwargs,
    _unchanged,
    snapshot_legacy_bootstrap,
)
from .competition_recovery_models import RecoveryLimits
from .competition_recovery_observation import (
    _DRAIN_PROOFS,
    StoppedLegacyDrainProof,
    _drain_binding,
)

# This exact signed directive pins worker 695cd09, source tree 8ef3e13a and
# OCI fe83e57e. Its audited bittensor 11.1.0 transport signs once with period 8.
# A policy's era field alone is insufficient: another implementation may ignore
# it. Additional releases require their own source and dependency audit.
_AUDITED_DIRECTIVES = frozenset(
    {
        "48c31a89e51944a2e66b0dcc94eea7594f8484e37c81c2c4ea2f5987128a1748",
    }
)
_SESSIONS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


@dataclass(frozen=True, eq=False)
class StoppedLegacyDrain:
    """A live challenge; it does not assert inclusion, expiry or historical outcome."""

    marker: bytes
    snapshot: LegacySnapshot
    stopped: StoppedSupervisor

    def recheck(self) -> None:
        if type(self) is not StoppedLegacyDrain or _SESSIONS.get(self) != _binding(self):
            raise HostUpgradeError("legacy drain session is absent, altered or closed")
        self.stopped.recheck_stopped()
        _unchanged(self.snapshot)

    async def collect(
        self, provider: FinalizedCompetitionWeightProvider, *, block_number: int, block_hash: str
    ) -> StoppedLegacyDrainProof:
        self.recheck()
        if type(provider) is not FinalizedCompetitionWeightProvider:
            raise HostUpgradeError("legacy drain requires the owned weight provider")
        result = await provider.read_legacy_drain(
            marker=self.marker, block_number=block_number, block_hash=block_hash
        )
        self.recheck()
        if result.included.block_number <= self.snapshot.manifest.accepted_at_finalized_block:
            raise HostUpgradeError("legacy drain marker predates the stopped installation")
        proof = StoppedLegacyDrainProof(self, result)
        _DRAIN_PROOFS[proof] = _drain_binding(proof)
        return proof

    async def find(
        self,
        provider: FinalizedCompetitionWeightProvider,
        *,
        birth_block: int,
        birth_hash: str,
        period: int,
    ) -> StoppedLegacyDrainProof | None:
        self.recheck()
        if type(provider) is not FinalizedCompetitionWeightProvider:
            raise HostUpgradeError("legacy drain requires the owned weight provider")
        result = await provider.find_legacy_drain(
            marker=self.marker, birth_block=birth_block, birth_hash=birth_hash, period=period
        )
        self.recheck()
        if result is None:
            return None
        if result.included.block_number <= self.snapshot.manifest.accepted_at_finalized_block:
            raise HostUpgradeError("legacy drain marker predates the stopped installation")
        proof = StoppedLegacyDrainProof(self, result)
        _DRAIN_PROOFS[proof] = _drain_binding(proof)
        return proof


def _binding(session: StoppedLegacyDrain) -> tuple:
    return (
        session.marker,
        id(session.snapshot),
        session.snapshot.sha256,
        id(session.stopped),
        session.stopped._binding,
    )


@contextmanager
def hold_legacy_drain(
    stopped: StoppedSupervisor,
    *,
    limits: RecoveryLimits,
    historical_manifests=(),
    historical_leases=(),
) -> Iterator[StoppedLegacyDrain]:
    """Generate entropy only after authenticating release, state and both locks.

    The caller must also fence any writer on another machine. Host ownership
    checks here cover this installation; they cannot discover copied hotkeys.
    No journal, lock inode, high-water record or service setting is changed.
    """
    _check_stopped(stopped)
    if stopped.accepted_directive_sha256 not in _AUDITED_DIRECTIVES:
        raise HostUpgradeError("legacy drain requires an audited eight-block release")
    with snapshot_legacy_bootstrap(
        stopped.worker_state_root,
        **_snapshot_kwargs(stopped, limits, historical_manifests, historical_leases),
    ) as snapshot:
        _check_current_manifest(snapshot, stopped)
        if JOURNAL not in snapshot._files:
            raise HostUpgradeError("legacy drain requires a retained bridge journal")
        audit = audit_bridge_history(snapshot._files, hotkey=stopped.validator_hotkey)
        if (
            type(audit.current) is not RegistrationBridgeJournal
            or audit.current.phase not in {"submitting", "outcome_unknown"}
            or set(audit.holds) != {"registration_bridge_attempt_mortality_unknown"}
            or any(type(j) is not RegistrationBridgeJournal for _, j in audit.attempts)
        ):
            raise HostUpgradeError("legacy drain requires one current uncertain v1 attempt")
        _check_stopped(stopped)
        _unchanged(snapshot)
        session = StoppedLegacyDrain(MARKER_DOMAIN + secrets.token_bytes(32), snapshot, stopped)
        _SESSIONS[session] = _binding(session)
        try:
            session.recheck()
            yield session
            session.recheck()
        finally:
            _SESSIONS.pop(session, None)
