"""Owned historical registration review without relaxing current-capture freshness."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import FinalizedRegistrationProvider
from .competition_execution import ExecutionBoundary
from .competition_registration_archive import (
    MAX_ARCHIVE_BYTES,
    MAX_METADATA_BYTES,
    RegistrationArchive,
    replay_registration_archive,
)
from .concurrency import run_owned_thread
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header
from .historical_header_recovery import HistoricalHeaderRecovery
from .open_competition import RegistrationSnapshot, digest
from .protocol import canonical_json_bytes
from .validator_plans import VerifiedFinalizedBlock


class HistoricalRegistrationUnavailable(FileNotFoundError):
    """Required retained evidence is missing; recovery may supply it and retry."""


@dataclass(frozen=True, slots=True)
class HistoricalRegistration:
    """Historical membership; deliberately not a RegistrationCapture.

    A caller cannot use this as a fresh execution or registration observation.
    The replayed_at head describes when the owned reviewer rechecked evidence,
    not when the original registration or participation happened.
    """

    snapshot: RegistrationSnapshot
    original: ExecutionBoundary
    replayed_at: FinalizedSnapshotRef


class HistoricalRegistrationProvider(FinalizedRegistrationProvider):
    """Replay original captures against this process's owned finality history.

    Missing headers are reconstructed in durable bounded passes from an owned
    finalized descendant. Coordinator-supplied headers cannot anchor that walk.
    Original observer captures are the form accepted by recoverable intake.
    Existing collect()/collect_at() freshness rules remain in force.
    """

    def __init__(
        self,
        *args,
        historical_header_maximum_bytes=256 * 1024**2,
        historical_header_batch_size=256,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._historical_headers = HistoricalHeaderRecovery(
            self._connect,
            maximum_bytes=historical_header_maximum_bytes,
            batch_size=historical_header_batch_size,
        )

    async def _original_header(self, expected, archive, head, head_block):
        supplied = archive.finality
        if (
            not isinstance(supplied, dict)
            or not isinstance(supplied.get("block"), dict)
            or not isinstance(supplied["block"].get("scale_header"), str)
            or supplied.get("evidence_class") != "verifier_attested_finality"
            or supplied.get("offline_finality_proof") is not False
            or supplied.get("genesis_hash") != "0x" + self.config.chain_pin.genesis_block_hash
        ):
            raise ValueError("historical registration has invalid original evidence")
        encoded = supplied["block"]["scale_header"]
        decoded = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        ref = FinalizedSnapshotRef(
            decoded["number"], decoded["hash"], decoded["parent_hash"], decoded["state_root"]
        )
        if (ref.block_number, ref.block_hash, ref.state_root) != (
            expected.block,
            expected.block_hash,
            expected.state_root,
        ) or digest(archive.snapshot) != expected.snapshot_sha256:
            raise ValueError("historical registration differs from its original observation")
        original = await self._finality.verified_block_at(expected.block)
        if original is not None:
            self._check_finality(ref, original)
            if json.loads(original.finality_evidence)["block"]["scale_header"] != encoded:
                raise ValueError("historical registration differs from owned original evidence")
            if original.timestamp_ms > head_block.timestamp_ms:
                raise ValueError("historical timestamp exceeds owned head")
            return ref, original.timestamp_ms, original.timestamp_ms
        if not self._owned or self._registration_rpc is None:
            raise HistoricalRegistrationUnavailable(
                "owned historical registration header is unavailable"
            )
        anchor = await self._finality.verified_block_after(expected.block, maximum_distance=None)
        if not isinstance(anchor, VerifiedFinalizedBlock):
            raise HistoricalRegistrationUnavailable(
                "owned historical registration anchor is unavailable"
            )
        self._check_finality_context(anchor)
        if anchor.height > head.block_number or anchor.timestamp_ms > head_block.timestamp_ms:
            raise ValueError("historical anchor exceeds owned current head")
        recovered = await self._historical_headers.recover(
            anchor, ref, self._registration_rpc.request
        )
        if recovered.encoded != encoded:
            raise ValueError("historical registration header differs from finalized ancestry")
        return recovered.snapshot, None, anchor.timestamp_ms

    def _retained_archive(self, expected: ExecutionBoundary) -> tuple[bytes, bytes]:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT hash,snapshot,evidence_sha256,substr(evidence,1,?) "
                "FROM captures WHERE block=?",
                (MAX_ARCHIVE_BYTES + 1, expected.block),
            ).fetchone()
            if row is None:
                raise HistoricalRegistrationUnavailable(
                    "historical registration archive is unavailable"
                )
            if row[:3] != (expected.block_hash, expected.snapshot_sha256, expected.evidence_sha256):
                raise ValueError("retained registration index differs from original observation")
            raw = row[3]
            if not 0 < len(raw) <= MAX_ARCHIVE_BYTES:
                raise ValueError("registration archive exceeds its byte bound")
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError("registration archive must be an object")
            metadata = db.execute(
                "SELECT substr(body,1,?) FROM artifacts WHERE digest=?",
                (MAX_METADATA_BYTES + 1, body.get("runtime_metadata_sha256")),
            ).fetchone()
            if metadata is None:
                raise HistoricalRegistrationUnavailable(
                    "historical registration metadata is unavailable"
                )
            return raw, metadata[0]
        finally:
            db.close()

    async def retained_archive(self, expected: ExecutionBoundary) -> tuple[bytes, bytes]:
        """Return exact retained bytes; callers must review them before signing."""
        expected = ExecutionBoundary.model_validate_json(canonical_json_bytes(expected))
        return await run_owned_thread(self._retained_archive, expected)

    async def review_retained(self, expected: ExecutionBoundary) -> HistoricalRegistration:
        raw, metadata = await self.retained_archive(expected)
        return await self.review_archive(expected, raw, metadata)

    async def review_archive(
        self,
        expected: ExecutionBoundary,
        raw: bytes,
        metadata: bytes,
    ) -> HistoricalRegistration:
        """Verify supplied proof bytes using only this provider's owned historical header."""
        expected = ExecutionBoundary.model_validate_json(canonical_json_bytes(expected))
        try:
            return await asyncio.wait_for(
                self._review_archive(expected, raw, metadata),
                timeout=self.config.collection_timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise ValueError("historical registration review timed out") from error

    async def _review_archive(self, expected, raw, metadata):
        async with self._lock:
            if self._closed or (self._owned and (self._task is None or self._task.done())):
                raise ValueError("owned registration reviewer is not running")
            archive = await run_owned_thread(RegistrationArchive, raw, metadata)
            if archive.evidence_sha256 != expected.evidence_sha256:
                raise ValueError("historical registration evidence digest differs")
            head = await self._proofs.finalized_snapshot()
            head_block = await self._finality.verified_block_at(head.block_number)
            self._check_finality(head, head_block)
            self._fresh(head_block.timestamp_ms)
            if (
                head.block_number < self.config.minimum_finalized_block
                or (self._owned and head.block_number <= self._startup_floor)
                or expected.block > head.block_number
            ):
                raise ValueError("historical review lacks a current owned finalized head")
            await run_owned_thread(self._check_prior, head)
            ref, timestamp, maximum_timestamp = await self._original_header(
                expected, archive, head, head_block
            )
            snapshot = await replay_registration_archive(
                archive,
                snapshot=ref,
                policy=self.policy,
                pin=self._runtime_pin,
                proofs=self._proofs,
                reviewed_codec=self._storage_codec is not None,
                timestamp_ms=timestamp,
                maximum_timestamp_ms=maximum_timestamp,
            )
            newest = await self._finality.verified_finalized_snapshot()
            if (
                not isinstance(newest, FinalizedSnapshotRef)
                or newest.block_number < head.block_number
                or (newest.block_number == head.block_number and newest != head)
            ):
                raise ValueError("historical review finalized head rolled back or changed")
            self._fresh(head_block.timestamp_ms)
            return HistoricalRegistration(snapshot, expected, head)
