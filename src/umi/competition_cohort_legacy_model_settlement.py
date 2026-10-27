"""Independent legacy R2 byte checks without rewriting original acceptances.

The original certificate remains the authority for rights/reconstruction. This
consumer authenticates that exact admission lineage and independently verifies
all signed model-file hashes from the separately authenticated R2 association.
It does not replace a historical review with today's standing-review policy.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_chunked_model_backup import ChunkedModelVerification
from .competition_cohort_legacy_model_storage import (
    LegacyModelStorageRepairRequired,
)
from .competition_cohort_model_acceptance import verify_model_acceptance
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex

LEGACY_SETTLEMENT_ABI = "umi-legacy-r2-model-settlement/1"


class LegacyModelSettlementVerification(StrictProtocolModel):
    schema_: Literal["umi-legacy-r2-model-settlement-verification/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    submission_sha256: Hex32
    original_request_sha256: Hex32
    participant_sha256: Hex32
    acceptance_sha256: Hex32
    model_sha256: Hex32
    storage_selection_sha256: Hex32
    verification_context_sha256: Hex32
    byte_snapshot_sha256: Hex32
    byte_snapshot_size_bytes: Annotated[int, Field(ge=1)]
    total_bytes: Annotated[int, Field(ge=1)]


def legacy_snapshot_path(receipts, receipt):
    return Path(receipts) / "legacy-byte-snapshots" / (receipt.byte_snapshot_sha256 + ".json")


def legacy_seal_path(receipts, receipt):
    return (
        Path(receipts)
        / "legacy-completions"
        / receipt.cohort_sha256
        / (receipt.submission_sha256 + ".json")
    )


def check_legacy_settlement_metadata(receipts, receipt):
    """A completed byte fact cannot silently become a missing-cache first pass."""
    seal = read_private_model(
        legacy_seal_path(receipts, receipt),
        LegacyModelSettlementVerification,
        maximum_bytes=64 * 1024,
    )
    if seal != receipt:
        raise LegacyModelStorageRepairRequired(
            "legacy settlement completion changed; repair required"
        )
    snapshot = read_private_model(
        legacy_snapshot_path(receipts, receipt),
        ChunkedModelVerification,
        maximum_bytes=receipt.byte_snapshot_size_bytes,
    )
    if digest(snapshot) != receipt.byte_snapshot_sha256:
        raise LegacyModelStorageRepairRequired(
            "legacy settlement byte snapshot changed; repair required"
        )
    return snapshot


class LegacyModelSettlementStorage:
    """Selected authenticated storage; no implicit legacy-to-R2 fallback."""

    def __init__(self, sources, cohort):
        if not sources.has_cohort(cohort):
            raise ValueError("legacy settlement storage has no authenticated cohort")
        self.sources, self.cohort = sources, cohort

    @property
    def authenticated(self):
        return self.sources.authenticated[self.cohort]

    @property
    def load_original(self):
        return self.sources.load_original

    def resolution(self, request_sha256):
        return self.sources.resolve(self.cohort, request_sha256=request_sha256)

    def reader(self, resolution):
        return self.sources.reader(resolution)

    def accepted(self, participant, certificate):
        """Preserve pinned old intents; admit genuinely later signed certificates.

        A later certificate may exist for an originally admitted inventory entry
        that had no intent at adoption. The native settlement owner still checks
        its certified acceptance clock against actual cohort closure/finality.
        This storage consumer does not turn that signed clock into a new proof
        of current finality or reopen intake for unrelated requests.
        """
        acceptance = certificate.acceptance
        resolution = self.sources.accepted(
            self.cohort,
            record=participant.record,
            admission=participant.admission,
            acceptance=acceptance,
        )
        original = resolution.originals
        if (
            original.certificate_raw_sha256 is not None
            and sha256_hex(canonical_json_bytes(certificate)) != original.certificate_raw_sha256
        ):
            raise ValueError("legacy settlement changes its original certificate")
        verify_model_acceptance(
            certificate,
            participant.record,
            self.authenticated.original_history,
            self.authenticated.policy,
            maximum_block=acceptance.accepted_at_block,
        )
        return resolution

    @staticmethod
    def receipt_path(receipts, certificate):
        a = certificate.acceptance
        return Path(receipts) / a.cohort_sha256 / (a.submission_sha256 + ".json")

    def _expected(self, participant, certificate, resolution, snapshot):
        reader = self.reader(resolution)
        return LegacyModelSettlementVerification(
            schema="umi-legacy-r2-model-settlement-verification/1",
            cohort_sha256=certificate.acceptance.cohort_sha256,
            submission_sha256=certificate.acceptance.submission_sha256,
            original_request_sha256=digest(participant.record.request),
            participant_sha256=digest(participant),
            acceptance_sha256=digest(certificate),
            model_sha256=digest(resolution.selection.bundle),
            storage_selection_sha256=digest(resolution.selection),
            verification_context_sha256=digest([LEGACY_SETTLEMENT_ABI, reader._context()]),
            byte_snapshot_sha256=digest(snapshot),
            byte_snapshot_size_bytes=len(canonical_json_bytes(snapshot)),
            total_bytes=sum(f.size_bytes for f in resolution.selection.bundle.files),
        )

    def _bound_snapshot(self, receipts, receipt):
        resolution = self.resolution(receipt.original_request_sha256)
        reader = self.reader(resolution)
        snapshot = check_legacy_settlement_metadata(receipts, receipt)
        expected = {
            reader._key(chunk): (key, chunk.size_bytes) for key, chunk in reader.chunks.items()
        }
        actual = {item.key: (item.sha256, item.size_bytes) for item in snapshot.objects}
        if (
            receipt.cohort_sha256 != self.authenticated.legacy.cohort_sha256
            or receipt.model_sha256 != resolution.originals.model_sha256
            or receipt.storage_selection_sha256 != digest(resolution.selection)
            or receipt.verification_context_sha256
            != digest([LEGACY_SETTLEMENT_ABI, reader._context()])
            or receipt.total_bytes != sum(f.size_bytes for f in resolution.selection.bundle.files)
            or snapshot.selection_sha256 != digest(resolution.selection)
            or snapshot.namespace_sha256 != digest(reader._namespace())
            or snapshot.documents
            or expected != actual
            or len(actual) != len(snapshot.objects)
        ):
            raise LegacyModelStorageRepairRequired(
                "legacy settlement verification binding changed; repair required"
            )
        return reader, snapshot

    def verify_candidate(self, participant, certificate, receipts):
        resolution = self.accepted(participant, certificate)
        try:
            receipt = read_private_model(
                self.receipt_path(receipts, certificate),
                LegacyModelSettlementVerification,
                maximum_bytes=64 * 1024,
            )
            _, snapshot = self._bound_snapshot(receipts, receipt)
            if receipt != self._expected(participant, certificate, resolution, snapshot):
                raise ValueError("legacy settlement receipt differs from original acceptance")
        except (FileNotFoundError, ValueError) as error:
            raise LegacyModelStorageRepairRequired(
                "legacy settlement original completion requires repair"
            ) from error
        return receipt

    async def check_receipt(self, receipts, receipt):
        """Read metadata and HEAD generations only; never repair by rereading weights."""
        try:
            reader, snapshot = await run_owned_thread(self._bound_snapshot, receipts, receipt)
            await reader._heads(None, expected={v.sha256: v for v in snapshot.objects})
            if (
                await run_owned_thread(check_legacy_settlement_metadata, receipts, receipt)
                != snapshot
            ):
                raise ValueError("legacy settlement snapshot changed during generation check")
        except (FileNotFoundError, ValueError) as error:
            raise LegacyModelStorageRepairRequired(
                "legacy settlement original metadata or remote generation requires repair"
            ) from error

    async def ensure(self, participant, certificate, receipts, *, repairing=False):
        resolution = await run_owned_thread(self.accepted, participant, certificate)
        path = self.receipt_path(receipts, certificate)
        seal = (
            Path(receipts)
            / "legacy-completions"
            / certificate.acceptance.cohort_sha256
            / (certificate.acceptance.submission_sha256 + ".json")
        )
        try:
            completed = await run_owned_thread(
                read_private_model, seal, LegacyModelSettlementVerification
            )
        except FileNotFoundError:
            completed = None
        except ValueError as error:
            raise LegacyModelStorageRepairRequired(
                "legacy settlement completion seal is damaged; repair required"
            ) from error
        if completed is not None:
            checked = None
            if repairing and not path.exists():
                # Restore only an exact missing small receipt from its retained
                # independent completion. Changed generations never authorize a
                # different byte result under the original completion identity.
                await self.check_receipt(receipts, completed)
                checked = completed
                with TransferProgress(
                    "legacy_settlement_receipt_repair",
                    1,
                    unit="receipts",
                    planning_unit_seconds=(0.001, 1.0),
                ) as progress:
                    await run_owned_thread(publish_private_model, path, completed)
                    progress.advance(1, restored=True)
            receipt = await run_owned_thread(
                self.verify_candidate, participant, certificate, receipts
            )
            if receipt != checked:
                await self.check_receipt(receipts, receipt)
            return receipt
        if path.exists():
            raise LegacyModelStorageRepairRequired(
                "legacy settlement completion seal is missing; repair required"
            )
        snapshot = await self.reader(resolution).verify()
        receipt = self._expected(participant, certificate, resolution, snapshot)
        await run_owned_thread(
            partial(publish_private_model, maximum_bytes=receipt.byte_snapshot_size_bytes),
            legacy_snapshot_path(receipts, receipt),
            snapshot,
        )
        await run_owned_thread(publish_private_model, seal, receipt)
        await run_owned_thread(publish_private_model, path, receipt)
        return receipt
