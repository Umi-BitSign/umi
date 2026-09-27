"""Owned current-chain observations of a reserved reward-control commitment.

This reader discovers the actual current digest, not whether a cached digest
still matches. The signed control history and reward package are separate
inputs to the standing reward consumer. A slot observation authorizes neither
intake nor a weight call. There is no coordinator or renewal-feed dependency.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import _AwaitingFinality, _hotkey, _uint
from .competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    _cache_usage,
    _runtime_execution_evidence,
)
from .concurrency import wait_for_owned
from .encoding import account_id32
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext
from .validator_anchor_ports import _digest_bytes
from .validator_chain import PinnedRuntimeContext, StorageReadSpec

_ISSUER = object()
_MAX_EVIDENCE_BYTES = 32 * 1024**2


@dataclass(frozen=True, slots=True)
class OwnedRewardControlObservation:
    """Process-local proof result; serialized evidence cannot recreate it."""

    snapshot: FinalizedSnapshotRef
    timestamp_ms: int
    control_hotkey: str
    control_sha256: str | None
    committed_at_block: int | None
    chain_config_sha256: str
    captured_monotonic_ns: int
    expires_monotonic_ns: int
    runtime: PinnedRuntimeContext = field(repr=False)
    evidence: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.evidence).hexdigest()


def _binding(value: OwnedRewardControlObservation) -> str:
    return digest(
        {
            "snapshot": {
                "block": value.snapshot.block_number,
                "hash": value.snapshot.block_hash,
                "parent": value.snapshot.parent_hash,
                "root": value.snapshot.state_root,
            },
            "timestamp_ms": value.timestamp_ms,
            "control_hotkey": value.control_hotkey,
            "control_sha256": value.control_sha256,
            "committed_at_block": value.committed_at_block,
            "chain_config_sha256": value.chain_config_sha256,
            "captured_monotonic_ns": str(value.captured_monotonic_ns),
            "expires_monotonic_ns": str(value.expires_monotonic_ns),
            "evidence_sha256": value.evidence_sha256,
            "runtime_metadata_sha256": value.runtime.metadata_sha256,
            "runtime_version_sha256": hashlib.sha256(
                value.runtime.runtime_version_bytes
            ).hexdigest(),
            "storage_codec_mode": value.runtime.storage_codec_mode,
            "runtime_execution": (
                _runtime_execution_evidence(value.runtime)
                if isinstance(value.runtime, ExecutedRuntimeContext)
                else None
            ),
        }
    )


def validate_owned_reward_control(
    observation: OwnedRewardControlObservation,
    *,
    expected_control_hotkey: str,
    expected_chain_config_sha256: str,
) -> None:
    if (
        type(observation) is not OwnedRewardControlObservation
        or observation._issuer is not _ISSUER
        or observation._binding != _binding(observation)
        or observation.runtime.snapshot != observation.snapshot
        or account_id32(observation.control_hotkey) != account_id32(expected_control_hotkey)
        or observation.chain_config_sha256 != expected_chain_config_sha256
        or not observation.captured_monotonic_ns
        <= time.monotonic_ns()
        <= observation.expires_monotonic_ns
    ):
        raise ValueError("reward control was not issued by the selected current proof adapter")


def _control_value(value: object, block: int) -> tuple[str | None, int | None]:
    if value is None:
        return None, None
    if not isinstance(value, Mapping):
        raise ValueError("reward control commitment is malformed")
    committed = _uint(value.get("block"), block)
    info = value.get("info")
    fields = info.get("fields") if isinstance(info, Mapping) else None
    if (
        not isinstance(fields, Sequence)
        or isinstance(fields, (bytes, bytearray, str))
        or len(fields) != 1
        or not isinstance(fields[0], Mapping)
        or set(fields[0]) != {"Sha256"}
    ):
        raise ValueError("reward control requires exactly one Sha256 commitment")
    return _digest_bytes(fields[0]["Sha256"], "reward control digest").hex(), committed


def _control_evidence(
    *,
    config,
    ref,
    hotkey,
    control,
    committed,
    runtime,
    batch,
    finality,
    schema="umi-reward-control-observation/1",
) -> bytes:
    """Encode bounded proof bytes without granting current or historical authority."""
    evidence = canonical_json_bytes(
        {
            "schema": schema,
            "config_sha256": digest(config),
            "block": ref.block_number,
            "block_hash": ref.block_hash,
            "state_root": ref.state_root,
            "control_hotkey": hotkey,
            "control_sha256": control,
            "committed_at_block": committed,
            "finality": finality,
            "runtime_metadata_sha256": runtime.metadata_sha256,
            "runtime_version": json.loads(runtime.runtime_version_bytes),
            "storage_codec_mode": runtime.storage_codec_mode,
            "runtime_execution": (
                _runtime_execution_evidence(runtime)
                if isinstance(runtime, ExecutedRuntimeContext)
                else None
            ),
            "claims": [
                {
                    "key": "0x" + c.storage_key.hex(),
                    "value": None if c.value is None else "0x" + c.value.hex(),
                }
                for c in batch.evidence.claims
            ],
            "proof": ["0x" + n.hex() for n in batch.evidence.proof],
            "chain_submission_authorized": False,
        }
    )
    if len(evidence) > _MAX_EVIDENCE_BYTES:
        raise ValueError("reward control evidence exceeds its byte bound")
    return evidence


class FinalizedRewardControlProvider(FinalizedCompetitionWeightProvider):
    """Use the same owned observer, exact runtime and proof collector as weights.

    The host supplies the reserved hotkey from its approved authority, never
    from an untrusted package or a numeric UID. Proven absence is returned as
    absence; it is not revocation or permission to reuse a cached allocation.
    Configuration and lifecycle are the existing validator provider's contract.

    Standing control and inherited weight reads extract values from proofs.
    They require the selected helper's proof-read protocol and never fall back
    to separate value requests. Legacy weight providers keep their read path.
    """

    async def _weight_read(self, runtime, specs):
        return await super()._weight_read(runtime, specs, proof_values=True)

    async def collect_control(self, control_hotkey: str) -> OwnedRewardControlObservation:
        if self._closed:
            raise ValueError("reward control provider is closed")
        control_hotkey = _hotkey(control_hotkey)
        return await wait_for_owned(
            self._collect_control_locked(control_hotkey),
            timeout=self.config.collection_timeout_seconds,
        )

    async def _collect_control_locked(self, hotkey: str) -> OwnedRewardControlObservation:
        async with self._lock:
            if self._closed:
                raise ValueError("reward control provider is closed")
            if self._owned and (self._task is None or self._task.done()):
                raise ValueError("owned finality observer is not running")
            _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
            ref = await self._proofs.finalized_snapshot()
            if not isinstance(ref, FinalizedSnapshotRef):
                raise ValueError("reward control finalized snapshot is invalid")
            if ref.block_number < self.config.minimum_finalized_block or (
                self._owned and ref.block_number <= self._startup_floor
            ):
                raise _AwaitingFinality("awaiting a head verified by this observer process")
            block = await self._finality.verified_block_at(ref.block_number)
            self._check_finality(ref, block)
            self._fresh(block.timestamp_ms)
            runtime = await self._runtime_context(ref)
            self._validate_runtime_context(runtime, ref)
            specs = (
                StorageReadSpec("Timestamp", "Now"),
                StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                StorageReadSpec("Commitments", "CommitmentOf", (78, hotkey)),
            )
            batch = await self._weight_read(runtime, specs)
            values = {r.spec: r.decoded_value for r in batch.reads}
            if type(values[specs[0]]) is not int or values[specs[0]] != block.timestamp_ms:
                raise ValueError("reward control proven timestamp differs from finality")
            if values[specs[1]] is not True:
                raise ValueError("SN78 is unavailable")
            control, committed = _control_value(values[specs[2]], ref.block_number)
            newest = await self._finality.verified_finalized_snapshot()
            if (
                newest.block_number < ref.block_number
                or (newest.block_number == ref.block_number and newest != ref)
                or newest.block_number - ref.block_number > self.policy.maximum_snapshot_age_blocks
            ):
                raise ValueError("reward control finality rolled back, changed or became stale")
            evidence = _control_evidence(
                config=self.config,
                ref=ref,
                hotkey=hotkey,
                control=control,
                committed=committed,
                runtime=runtime,
                batch=batch,
                finality=json.loads(block.finality_evidence),
            )
            _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
            self._fresh(block.timestamp_ms)
            observed = time.monotonic_ns()
            value = OwnedRewardControlObservation(
                snapshot=ref,
                timestamp_ms=block.timestamp_ms,
                control_hotkey=hotkey,
                control_sha256=control,
                committed_at_block=committed,
                chain_config_sha256=digest(self.config),
                captured_monotonic_ns=observed,
                expires_monotonic_ns=observed
                + max(0, block.timestamp_ms + self.config.maximum_head_age_ms - self._now_ms())
                * 1_000_000,
                runtime=runtime,
                evidence=evidence,
                _issuer=_ISSUER,
            )
            object.__setattr__(value, "_binding", _binding(value))
            return value
