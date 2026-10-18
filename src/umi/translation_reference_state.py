"""Owned, proof-backed selection for a delegated translation reference worker.

The reference is explicitly delegated by a separately authenticated policy. This
reader proves its current identity, permit, epoch activity and complete row. It
does not independently certify the cohort, reconcile old effects or submit.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .bridge.signing import BridgeSigningState, BridgeSigningStateReader, _SnapshotPort
from .concurrency import await_owned_task
from .encoding import account_id32, datetime_to_unix_ms
from .protocol import canonical_json_bytes
from .translation_reference_policy import (
    ApprovedTranslationReferencePolicy,
    TranslationReferencePolicy,
)
from .validator_chain import (
    FinalizedProofCollector,
    ProofCollectionLimits,
    StorageReadSpec,
    VerifiedStorageBatch,
)

_LOG = logging.getLogger(__name__)


class TranslationReferenceError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _require(condition, reason):
    if not condition:
        raise TranslationReferenceError(reason)


def _uint(value, maximum=2**53 - 1):
    _require(type(value) is int and 0 <= value <= maximum, "reference_unsigned_value_invalid")
    return value


def _spec(item, *params):
    return StorageReadSpec("SubtensorModule", item, params or (78,))


def _base_specs(writer: str, reference: str):
    return (
        _spec("NetworksAdded"),
        _spec("Uids", 78, writer),
        _spec("Uids", 78, reference),
        *(
            _spec(name)
            for name in (
                "SubnetworkN",
                "ValidatorPermit",
                "Active",
                "LastUpdate",
                "Tempo",
                "ActivityCutoffFactorMilli",
                "LastEpochBlock",
                "MechanismCountCurrent",
                "CommitRevealWeightsEnabled",
                "WeightsVersionKey",
                "MinAllowedWeights",
                "MaxAllowedUids",
                "MaxWeightsLimit",
                "WeightsSetRateLimit",
            )
        ),
    )


def _values(batch, runtime, specs):
    _require(type(batch) is VerifiedStorageBatch, "reference_native_batch_required")
    VerifiedStorageBatch(batch.runtime, batch.evidence, batch.reads)
    _require(
        batch.runtime is runtime
        and len(batch.reads) == len(specs)
        and {read.spec for read in batch.reads} == set(specs),
        "reference_proof_coverage_mismatch",
    )
    # Decode the proved bytes again, never a caller's substituted decoded_value.
    return {
        read.spec: runtime.decode_storage(read.spec.pallet, read.spec.item, read.raw_value)
        for read in batch.reads
    }


def _row(value):
    _require(isinstance(value, (list, tuple)), "reference_row_invalid")
    row = []
    for pair in value:
        _require(isinstance(pair, (list, tuple)) and len(pair) == 2, "reference_row_invalid")
        row.append((_uint(pair[0], 255), _uint(pair[1], 65535)))
    _require([uid for uid, _ in row] == list(range(256)), "reference_row_domain_invalid")
    _require(any(weight for _, weight in row), "reference_row_empty")
    return tuple(row)


@dataclass(frozen=True, slots=True)
class TranslationReferenceDecision:
    action: str
    reason_code: str
    next_action_block: int
    reference_uid: int
    reference_last_update: int
    writer_uid: int
    writer_last_update: int
    row: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class TranslationReferenceState:
    """Local native-reader result; never accepted from a JSON/RPC observation."""

    signing: BridgeSigningState
    reference_hotkey: str
    base: VerifiedStorageBatch
    rows: VerifiedStorageBatch

    def decision(self, policy: TranslationReferencePolicy, *, now: datetime):
        signing = BridgeSigningState(
            self.signing.validator_hotkey, self.signing.runtime, self.signing.batch
        )
        runtime, ref = signing.runtime, signing.runtime.snapshot
        _require(
            account_id32(self.reference_hotkey) == account_id32(policy.reference_hotkey)
            and account_id32(signing.validator_hotkey) != account_id32(policy.reference_hotkey),
            "reference_identity_invalid",
        )
        _require(
            0
            <= datetime_to_unix_ms(now) - signing.timestamp_ms
            <= policy.maximum_finalized_age_seconds * 1000,
            "reference_snapshot_stale",
        )
        base = _values(
            self.base, runtime, _base_specs(signing.validator_hotkey, self.reference_hotkey)
        )

        def value(name):
            return base[_spec(name)]

        _require(value("NetworksAdded") is True, "reference_subnet_unavailable")
        count = _uint(value("SubnetworkN"), 256)
        writer = _uint(base[_spec("Uids", 78, signing.validator_hotkey)], 255)
        reference = _uint(base[_spec("Uids", 78, self.reference_hotkey)], 255)
        _require(
            count == 256 and writer < count and reference < count and writer != reference,
            "reference_registration_domain_invalid",
        )
        rows = _values(
            self.rows,
            runtime,
            (
                _spec("Keys", 78, writer),
                _spec("Keys", 78, reference),
                _spec("Weights", 78, writer),
                _spec("Weights", 78, reference),
            ),
        )
        _require(
            account_id32(rows[_spec("Keys", 78, writer)]) == account_id32(signing.validator_hotkey)
            and account_id32(rows[_spec("Keys", 78, reference)])
            == account_id32(self.reference_hotkey),
            "reference_registration_changed",
        )
        for name in ("ValidatorPermit", "Active", "LastUpdate"):
            vector = value(name)
            _require(
                isinstance(vector, (list, tuple)) and len(vector) == count,
                "reference_vector_invalid",
            )
            if name != "LastUpdate":
                _require(all(type(item) is bool for item in vector), "reference_vector_invalid")
            else:
                for item in vector:
                    _uint(item, ref.block_number)
        _require(
            value("ValidatorPermit")[writer] and value("ValidatorPermit")[reference],
            "reference_validator_permit_missing",
        )
        _require(value("Active")[reference], "reference_validator_inactive")
        required = {
            "MechanismCountCurrent": 1,
            "WeightsVersionKey": 4_294_967_296,
            "MinAllowedWeights": 256,
            "MaxAllowedUids": 256,
            "MaxWeightsLimit": 65535,
        }
        _require(
            all(type(value(k)) is int and value(k) == v for k, v in required.items())
            and value("CommitRevealWeightsEnabled") is False,
            "reference_chain_settings_incompatible",
        )
        _uint(value("LastEpochBlock"), ref.block_number)
        tempo = _uint(value("Tempo"), 65535)
        factor = _uint(value("ActivityCutoffFactorMilli"), 65535)
        cutoff = max(1, tempo * factor // 1000)
        rate = _uint(value("WeightsSetRateLimit"))
        refresh = cutoff - policy.refresh_margin_blocks
        _require(
            rate < refresh and tempo > 0 and factor > 0, "reference_refresh_budget_incompatible"
        )
        update = value("LastUpdate")[reference]
        _require(
            policy.minimum_reference_update_block <= update <= ref.block_number,
            "reference_cutover_not_reached",
        )
        _require(ref.block_number - update < cutoff, "reference_update_stale")
        row = _row(rows[_spec("Weights", 78, reference)])
        if isinstance(policy, ApprovedTranslationReferencePolicy):
            _require(
                hashlib.sha256(canonical_json_bytes(row)).hexdigest() == policy.expected_row_sha256,
                "reference_row_not_approved_by_release_authority",
            )
        own_row = rows[_spec("Weights", 78, writer)]
        last = value("LastUpdate")[writer]
        # A row change must respect the chain's own rate; an unchanged row is
        # refreshed before epoch inactivity, even across cohort boundaries.
        due = last + (refresh if tuple(map(tuple, own_row)) == row else rate)
        return TranslationReferenceDecision(
            "submit" if ref.block_number >= due else "wait",
            "reference_refresh_due"
            if ref.block_number >= due
            else "reference_wait_rate_or_refresh",
            due,
            reference,
            update,
            writer,
            last,
            row,
        )


class TranslationReferenceStateReader:
    """Collect all selection inputs at the owned signing snapshot and state root."""

    def __init__(self, *, finality, rpc, verifier, runtime_executor, clock=None, progress=None):
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._finality = finality
        self._progress = progress
        self._signing = BridgeSigningStateReader(
            finality=finality,
            rpc=rpc,
            verifier=verifier,
            runtime_executor=runtime_executor,
            clock=self._clock,
        )
        self._proofs = FinalizedProofCollector(
            rpc,
            finality=_SnapshotPort(finality, rpc),
            verifier=verifier,
            limits=ProofCollectionLimits(
                maximum_storage_keys=32,
                maximum_storage_value_bytes=64 * 1024,
                maximum_storage_values_bytes=1024 * 1024,
                maximum_proof_node_bytes=2 * 1024**2,
                maximum_proof_bytes=8 * 1024**2,
            ),
        )
        self._lock = asyncio.Lock()

    async def read(self, writer: str, policy: TranslationReferencePolicy):
        # Keep the lock and native resource ownership until cancellation drains.
        task = asyncio.create_task(
            asyncio.wait_for(
                self._read(writer, policy),
                timeout=policy.maximum_finalized_age_seconds,
            )
        )
        return await await_owned_task(task, on_cancel=task.cancel)

    def _emit(self, stage, completed, started, *, retrying=False):
        event = {
            "stage": stage,
            "completed": completed,
            "total": 3,
            "percent": 100 * completed / 3,
            "elapsed_seconds": time.monotonic() - started,
            "eta_seconds": 0 if completed == 3 else None,
            "planning_seconds": None if completed == 3 or retrying else [5, 120],
            "eta_basis": "current proof capture only; no calibrated per-stage rate",
            "stalled": retrying,
            "retrying": retrying,
            "chain_submission_authorized": False,
        }
        _LOG.info("translation_reference_progress %s", event)
        if self._progress is not None:
            self._progress(event)

    async def _read(self, writer, policy):
        async with self._lock:
            started = time.monotonic()
            self._emit("owned_signing_state", 0, started)
            try:
                return await self._capture(writer, policy, started)
            except BaseException:
                self._emit("reference_capture_incomplete", 0, started, retrying=True)
                raise

    async def _capture(self, writer, policy, started):
        signing = await self._signing.read(writer)
        self._emit("reference_identity_and_epoch", 1, started)
        runtime, ref = signing.runtime, signing.runtime.snapshot
        specs = _base_specs(writer, policy.reference_hotkey)
        # The native multiproof already contains these values. Separate RPC
        # reads add handshakes and can time out before the proof is collected.
        # Extract at the same owned root, then verify the complete claims as
        # usual; an invalid or unsupported proof never falls back to RPC data.
        base = await self._proofs.storage_reads(runtime, specs, proof_values=True)
        values = _values(base, runtime, specs)
        writer_uid = _uint(values[_spec("Uids", 78, writer)], 255)
        reference_uid = _uint(values[_spec("Uids", 78, policy.reference_hotkey)], 255)
        _require(writer_uid != reference_uid, "reference_identity_invalid")
        self._emit("reference_full_rows", 2, started)
        rows = await self._proofs.storage_reads(
            runtime,
            (
                _spec("Keys", 78, writer_uid),
                _spec("Keys", 78, reference_uid),
                _spec("Weights", 78, writer_uid),
                _spec("Weights", 78, reference_uid),
            ),
            proof_values=True,
        )
        state = TranslationReferenceState(signing, policy.reference_hotkey, base, rows)
        state.decision(policy, now=self._clock())
        newest = await self._finality.read_finalized_identity()
        _require(
            type(newest.number) is int
            and ref.block_number <= newest.number < ref.block_number + policy.submission_era_period
            and (newest.number != ref.block_number or newest.block_hash == ref.block_hash),
            "reference_finality_advanced_during_capture",
        )
        self._emit("reference_capture_completed", 3, started)
        return state
