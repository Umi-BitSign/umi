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
from .open_competition import RegistrationSnapshot, digest
from .protocol import canonical_json_bytes


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

    Missing archive bytes or missing owned historical headers remain retryable
    dependencies; coordinator-supplied headers never substitute for the latter.
    Original observer captures are the form accepted by recoverable intake.
    Existing collect()/collect_at() freshness rules remain in force.
    """

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

    async def review_retained(self, expected: ExecutionBoundary) -> HistoricalRegistration:
        expected = ExecutionBoundary.model_validate_json(canonical_json_bytes(expected))
        raw, metadata = await run_owned_thread(self._retained_archive, expected)
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
            original = await self._finality.verified_block_at(expected.block)
            if original is None:
                raise HistoricalRegistrationUnavailable(
                    "owned historical registration header is unavailable"
                )
            self._check_finality_context(original)
            decoded = _decode_header(
                json.loads(original.finality_evidence)["block"]["scale_header"],
                maximum_bytes=MAXIMUM_HEADER_BYTES,
            )
            ref = FinalizedSnapshotRef(
                decoded["number"], decoded["hash"], decoded["parent_hash"], decoded["state_root"]
            )
            self._check_finality(ref, original)
            # Another reviewer has its own observer request ID and receipt.
            # Compare the authenticated header, never require identical local receipts.
            supplied = archive.finality
            if (
                (ref.block_number, ref.block_hash, ref.state_root)
                != (expected.block, expected.block_hash, expected.state_root)
                or digest(archive.snapshot) != expected.snapshot_sha256
                or not isinstance(supplied, dict)
                or not isinstance(supplied.get("block"), dict)
                or supplied.get("evidence_class") != "verifier_attested_finality"
                or supplied.get("offline_finality_proof") is not False
                or supplied.get("genesis_hash") != "0x" + self.config.chain_pin.genesis_block_hash
                or supplied.get("block", {}).get("scale_header")
                != json.loads(original.finality_evidence)["block"]["scale_header"]
                or original.timestamp_ms > head_block.timestamp_ms
            ):
                raise ValueError("historical registration differs from owned original evidence")
            snapshot = await replay_registration_archive(
                archive,
                snapshot=ref,
                policy=self.policy,
                pin=self._runtime_pin,
                proofs=self._proofs,
                reviewed_codec=self._storage_codec is not None,
                timestamp_ms=original.timestamp_ms,
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
