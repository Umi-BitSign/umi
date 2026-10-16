"""Preserve old HTTP retry identities after authenticated model storage release.

The local ledger fences writes. Only the configured native legacy admission owner
can prove an exact frozen original now has verified R2 bytes. This adapter cannot
release capacity, remove files, admit participants or replace signed requests.
"""

from __future__ import annotations

import sqlite3
from functools import partial
from typing import TYPE_CHECKING

from .competition_cohort_model_upload import validate_model_upload_chunk
from .competition_cohort_model_upload_continuation import (
    LegacyModelUploadContinuation,
    owned_upload_continuation,
)
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest

if TYPE_CHECKING:
    from .competition_cohort_legacy_model_admission import LegacyModelAdmissionPayloads
    from .competition_cohort_model_upload import CohortModelUploads, ModelUploadChunk
    from .competition_cohort_model_upload_replay import ContinuedModelUploadPayloads
    from .competition_cohort_participation import CohortParticipationRequest
    from .open_competition import Signature


class ModelUploadDelivery:
    def __init__(
        self,
        uploads: CohortModelUploads,
        *,
        remote_payloads: LegacyModelAdmissionPayloads | None = None,
        continued_payloads: ContinuedModelUploadPayloads | None = None,
    ) -> None:
        self.uploads, self.remote = uploads, remote_payloads
        self.intake, self.continued = uploads.intake, continued_payloads
        for owner in (remote_payloads, continued_payloads):
            if owner is not None and owner.intake is not self.intake:
                raise ValueError("remote model retries require the same native intake owner")

    def _payload_owner(self, request):
        for owner in (self.remote, self.continued):
            if owner is not None and owner.contains(request):
                return owner
        raise OSError("released model awaits its authenticated remote retry owner")

    def require_owned_payload(self, request):
        self._payload_owner(request).require_owned_payload(request)

    def _remote_review(self, request):
        owner = self._payload_owner(request)
        owner.require_owned_payload(request)
        if owner is self.continued:
            # The exact retained /2 publication, original native admission and
            # owner's review are already required by the continuation bridge.
            return "ready", ""
        return self.uploads._ensure_review(
            request.signed_submission.submission.model_bundle, allow_local=False
        )

    def _remote_request(self, key: str) -> CohortParticipationRequest | None:
        request = self.uploads.retained(key)
        model = request.signed_submission.submission.model_revision
        if self.uploads.allocations.state(model) not in {"release_prepared", "released"}:
            return None
        self._payload_owner(request)
        return request

    def continuation(self, key: str) -> LegacyModelUploadContinuation | None:
        """Export only committed authority for a new direct declaration.

        Existing /1 admissions and intents continue on their original path.
        No old upload record, payload, clock or allocation is changed here.
        """
        request = self.uploads.retained(key)
        sources = (
            self.remote.sources
            if self.remote is not None
            else (self.continued.sources if self.continued is not None else None)
        )
        return owned_upload_continuation(self.intake, sources, request)

    def _remote_status(self, key: str, request: CohortParticipationRequest) -> dict[str, object]:
        if self._remote_request(key) != request:
            raise OSError("model allocation changed during remote retry")
        self.require_owned_payload(request)
        bundle = request.signed_submission.submission.model_bundle
        return {
            "upload_sha256": key,
            "model_sha256": digest(bundle),
            "complete_files": list(range(len(bundle.files))),
            "file_offsets": [file.size_bytes for file in bundle.files],
            "total_files": len(bundle.files),
            "payload_preserved": True,
            # Delivery status grants neither admission nor artifact acceptance.
            "participation_admitted": False,
            "artifact_review_certified": False,
        }

    async def status(self, key: str) -> dict[str, object]:
        request = await run_owned_thread(self._remote_request, key)
        if request is None:
            return await run_owned_thread(self.uploads.status, key)
        try:
            await self._payload_owner(request).ensure_owned(request)
            return await run_owned_thread(self._remote_status, key, request)
        except ValueError as error:
            # The caller supplied only a retained identity. Failure to authenticate
            # its original metadata/source requires repair, not a changed request.
            raise OSError("remote model delivery requires storage verification repair") from error

    async def poll_once(self, *, report=None) -> dict[str, object]:
        """Restore remote byte facts before the ordinary recurring upload poll.

        This shares the authenticated HTTP retry boundary. It neither releases
        capacity nor creates local payloads, and the synchronous poll rechecks
        current owned authority before counting a model as preserved.
        """
        keys = await run_owned_thread(self.uploads.journal.keys, "upload")
        with TransferProgress(
            "legacy_model_remote_reconciliation", len(keys), report, unit="requests"
        ) as progress:
            for key in keys:
                try:
                    request = await run_owned_thread(self._remote_request, key)
                    if request is not None:
                        await self.status(key)
                    progress.advance(1)
                except (OSError, ValueError, sqlite3.Error):
                    # Missing/damaged storage retains a pending model in the
                    # native poll below. Do not turn a failed check into a
                    # success, and continue independent models in this cycle.
                    progress.emit("retrying", reason="remote_model_storage_repair_required")
            return await run_owned_thread(
                partial(
                    self.uploads.poll_once, remote_payloads=self, remote_review=self._remote_review
                )
            )

    async def put_chunk(
        self, chunk: ModelUploadChunk, signature: Signature, data: bytes
    ) -> dict[str, object]:
        request = await run_owned_thread(self._remote_request, chunk.upload_sha256)
        if request is None:
            await run_owned_thread(self.uploads.put_chunk, chunk, signature, data)
            return await self.status(chunk.upload_sha256)
        chunk = await run_owned_thread(validate_model_upload_chunk, request, chunk, signature, data)
        await self._payload_owner(request).compare_retry(
            request, file_index=chunk.file_index, offset=chunk.offset, data=data
        )
        try:
            return await run_owned_thread(self._remote_status, chunk.upload_sha256, request)
        except ValueError as error:
            raise OSError("remote model delivery requires storage verification repair") from error
