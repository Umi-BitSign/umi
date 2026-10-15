"""Preserve old HTTP retry identities after authenticated model storage release.

The local ledger fences writes. Only the configured native legacy admission owner
can prove an exact frozen original now has verified R2 bytes. This adapter cannot
release capacity, remove files, admit participants or replace signed requests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .competition_cohort_model_upload import validate_model_upload_chunk
from .concurrency import run_owned_thread
from .open_competition import digest

if TYPE_CHECKING:
    from .competition_cohort_legacy_model_admission import LegacyModelAdmissionPayloads
    from .competition_cohort_model_upload import CohortModelUploads, ModelUploadChunk
    from .competition_cohort_participation import CohortParticipationRequest
    from .open_competition import Signature


class ModelUploadDelivery:
    def __init__(
        self,
        uploads: CohortModelUploads,
        *,
        remote_payloads: LegacyModelAdmissionPayloads | None = None,
    ) -> None:
        self.uploads, self.remote = uploads, remote_payloads
        if remote_payloads is not None and remote_payloads.intake is not uploads.intake:
            raise ValueError("remote model retries require the same native intake owner")

    def _remote_request(self, key: str) -> CohortParticipationRequest | None:
        request = self.uploads.retained(key)
        model = request.signed_submission.submission.model_revision
        if self.uploads.allocations.state(model) not in {"release_prepared", "released"}:
            return None
        if self.remote is None or not self.remote.contains(request):
            raise OSError("released model awaits its authenticated remote retry owner")
        return request

    def _remote_status(self, key: str, request: CohortParticipationRequest) -> dict[str, object]:
        if self._remote_request(key) != request:
            raise OSError("model allocation changed during remote retry")
        self.remote.require_owned_payload(request)
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
            await self.remote.ensure_owned(request)
            return await run_owned_thread(self._remote_status, key, request)
        except ValueError as error:
            # The caller supplied only a retained identity. Failure to authenticate
            # its original metadata/source requires repair, not a changed request.
            raise OSError("remote model delivery requires storage verification repair") from error

    async def put_chunk(
        self, chunk: ModelUploadChunk, signature: Signature, data: bytes
    ) -> dict[str, object]:
        request = await run_owned_thread(self._remote_request, chunk.upload_sha256)
        if request is None:
            await run_owned_thread(self.uploads.put_chunk, chunk, signature, data)
            return await self.status(chunk.upload_sha256)
        chunk = await run_owned_thread(validate_model_upload_chunk, request, chunk, signature, data)
        await self.remote.compare_retry(
            request, file_index=chunk.file_index, offset=chunk.offset, data=data
        )
        try:
            return await run_owned_thread(self._remote_status, chunk.upload_sha256, request)
        except ValueError as error:
            raise OSError("remote model delivery requires storage verification repair") from error
