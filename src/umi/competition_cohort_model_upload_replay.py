"""Old delivery retries backed by an independently accepted direct continuation.

This reader grants no release, refund or admission authority. A future release
owner must still qualify every consumer before fencing the original allocation.
"""

from dataclasses import dataclass

from .competition_cohort_intake_records import replay_participation
from .competition_cohort_model_upload_continuation import (
    owned_upload_continuation,
    verify_upload_continuation,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .r2_multipart import MAXIMUM_RANGE_BYTES


@dataclass(frozen=True)
class _ContinuedPayload:
    owner: object
    authority_sha256: str
    publication_sha256: str
    review_sha256: str
    key: str
    head: object
    promotion: object


class ContinuedModelUploadPayloads:
    """Require the actual native /2 publication and its retained R2 promotion."""

    def __init__(self, uploads, sources, acceptances, direct):
        if acceptances.intake is not uploads.intake or digest(sources.policy) != digest(
            uploads.intake.policy
        ):
            raise ValueError("continued model retries require the same native intake and policy")
        self.uploads, self.sources, self.acceptances, self.direct = (
            uploads,
            sources,
            acceptances,
            direct,
        )
        self.intake = uploads.intake
        self.verified = {}

    def contains(self, request):
        """Select a candidate only; this does not establish any authority."""
        selected = self.sources.authenticated.get(request.consent.consent.cohort_sha256)
        return selected is not None and any(
            entry.request_sha256 == digest(request)
            and entry.admission_raw_sha256 is None
            and entry.intent_raw_sha256 is None
            and entry.certificate_raw_sha256 is None
            for entry in selected.legacy.entries
        )

    def _owned_source(self, request):
        if self.uploads.retained(digest(request)) != request or not self.contains(request):
            raise ValueError("continued retry differs from its frozen original request")
        proof = owned_upload_continuation(self.intake, self.sources, request)
        if proof is None:
            raise OSError("continued retry requires committed transport adoption")
        cohort, submission = (
            request.consent.consent.cohort_sha256,
            digest(request.signed_submission.submission),
        )
        publication = self.acceptances.retained(cohort, submission)
        review = self.acceptances.review_request(cohort, submission)
        if (
            review.record.request != request
            or review.acceptance != publication.certificate.acceptance
            or review.direct_artifact is None
        ):
            raise ValueError("continued retry requires its certified native direct acceptance")
        admission = replay_participation(review.record, proof.selection.history, self.intake.policy)
        if review.admission.admission != admission:
            raise ValueError("continued retry changes its native certified admission")
        verify_recovery_quorum(admission, review.admission.signatures, self.intake.policy)
        owner = self.direct.owners.get(cohort)
        # The adoption may precede later history transitions. Its exact delivery
        # is independently recovered by the continuation verifier above.
        delivery = verify_upload_continuation(proof, request, self.intake.policy)
        if (
            owner is None
            or owner.policy != self.intake.policy
            or owner.config.delivery != delivery
            or identity(owner.config.owner_hotkey)
            != identity(review.direct_artifact.signature.hotkey)
        ):
            raise ValueError("continued retry differs from its selected direct owner")
        key, head, promotion = owner.promoted_payload(publication)
        return _ContinuedPayload(
            owner, digest(proof), digest(publication), digest(review), key, head, promotion
        )

    async def _require_head(self, source):
        head = await source.owner.multipart.head(source.key)
        if head is None or (head.size_bytes, head.etag) != (
            source.head.size_bytes,
            source.head.etag,
        ):
            raise OSError("continued model changed its preserved remote generation")

    async def ensure_owned(self, request):
        key = digest(request)
        self.verified.pop(key, None)
        with TransferProgress(
            "continued_model_remote_reconciliation", 1, unit="objects"
        ) as progress:
            try:
                before = await run_owned_thread(self._owned_source, request)
                await self._require_head(before)
                if await run_owned_thread(self._owned_source, request) != before:
                    raise OSError("continued model authority changed during remote retry")
                self.verified[key] = before
                progress.advance(1, restored=True)
            except BaseException:
                self.verified.pop(key, None)
                progress.emit("retrying", reason="continued_model_remote_repair_required")
                raise

    def require_owned_payload(self, request):
        key = digest(request)
        try:
            if self.verified.get(key) != self._owned_source(request):
                raise OSError("continued model requires current owned remote verification")
        except BaseException:
            self.verified.pop(key, None)
            raise

    async def compare_retry(self, request, *, file_index, offset, data):
        key = digest(request)
        try:
            await self.ensure_owned(request)
            before = self.verified[key]
            files = request.signed_submission.submission.model_bundle.files
            if not 0 <= file_index < len(files) or not 0 <= offset <= files[
                file_index
            ].size_bytes - len(data):
                raise ValueError("continued retry exceeds the original file")
            position = sum(file.size_bytes for file in files[:file_index]) + offset
            expected = bytearray()
            while len(expected) < len(data):
                size = min(MAXIMUM_RANGE_BYTES, len(data) - len(expected))
                part = await before.owner.multipart.read_range(
                    before.key, offset=position + len(expected), size_bytes=size
                )
                if len(part) != size:
                    raise OSError("continued model retry returned an incomplete range")
                expected.extend(part)
            await self._require_head(before)
            if await run_owned_thread(self._owned_source, request) != before:
                raise OSError("continued model authority changed during range comparison")
        except ValueError as error:
            self.verified.pop(key, None)
            raise OSError("continued model retry requires verification repair") from error
        except BaseException:
            self.verified.pop(key, None)
            raise
        if data != expected:
            self.verified.pop(key, None)
            raise ValueError("retry differs from the completed original file")
