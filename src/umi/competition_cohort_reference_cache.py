"""Restore certified inherited references through authenticated retained sources.

The benchmark owner supplies its native applied-baseline reader. A source record
never grants reference authority. Existing legacy and direct materializers keep
their original byte identities, policy checks, cache budgets and recovery state.
"""

from dataclasses import dataclass

from .competition_cohort_direct_model_review import DirectModelArtifactReviewer
from .competition_cohort_model_acceptance import ModelAcceptanceIntent, ModelReviewRequest
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class CertifiedReferenceSource:
    selection: object
    legacy: bool


@dataclass(frozen=True)
class _ReferenceMetadataNeeded:
    review: object


class CohortReferenceModelCache:
    def __init__(self, artifacts, *, legacy, journal, reference, metadata=None):
        self.artifacts, self.legacy = artifacts, legacy
        self.journal, self.reference = journal, reference
        self.metadata = metadata
        # A previous winner may have been delivered by a different policy
        # evaluator. Native baseline authority below selects that exact source;
        # the direct reviewer still checks its evaluator and bundle bindings.
        self.references = DirectModelArtifactReviewer(
            artifacts.config,
            artifacts.policy,
            None,
            multipart=artifacts.multipart,
            verification_root=artifacts.verification_root,
        )

    def execution_source(self, job, role, bundle, request=None):
        source = (
            None
            if self.legacy is None
            else self.legacy.execution_source(job, role, bundle, request)
        )
        if source is not None:
            return CertifiedReferenceSource(source, legacy=True)
        if role != "incumbent":
            return None
        with TransferProgress(
            "certified_reference_byte_source",
            1,
            unit="models",
            planning_unit_seconds=(0.001, 1),
        ) as progress:
            review = self.reference(job, bundle)
            if review is None:
                progress.advance(1)
                return None
            if (
                review.model != bundle
                or review.target_cohort_sha256 != job.round.cohort_sha256
                or review.target_sequence != job.round.sequence
                or review.policy_sha256 != job.round.policy_sha256
                or review.candidate.model_sha256 != job.round.incumbent_model_sha256
            ):
                raise ValueError("certified reference source differs from its frozen execution")
            if self.legacy is not None:
                sources = self.legacy.sources
                # Earlier adopted cohorts retain their authenticated source
                # metadata after their model becomes a later cohort's baseline.
                for cohort in sorted(sources.authenticated):
                    retained = sources.preserved_reference(cohort, bundle)
                    if retained is not None:
                        progress.advance(1)
                        return CertifiedReferenceSource(retained, legacy=True)
            slot = review.source_cohort_sha256 + ":" + review.candidate.submission_sha256
            raw = self.journal.get("model_request", slot)
            raw_intent = self.journal.get("model_intent", slot)
            if raw is None or raw_intent is None:
                if self.metadata is not None:
                    progress.emit(
                        "metadata_required", reason="certified_reference_metadata_required"
                    )
                    # Selection is complete; the awaited reader owns metadata
                    # fetch/verification progress, not this local lookup scope.
                    progress.advance(1)
                    return _ReferenceMetadataNeeded(review)
                progress.emit("repair_required", reason="certified_reference_source_missing")
                raise ValueError("certified reference source requires retained-journal repair")
            retained = ModelReviewRequest.model_validate_json(canonical_json_bytes(raw))
            intent = ModelAcceptanceIntent.model_validate_json(canonical_json_bytes(raw_intent))
            submission = retained.record.request.signed_submission.submission
            if (
                retained.direct_artifact is None
                or intent.acceptance != retained.acceptance
                or retained.acceptance.cohort_sha256 != review.source_cohort_sha256
                or retained.acceptance.model_sha256 != review.candidate.model_sha256
                or retained.acceptance.policy_sha256 != review.policy_sha256
                or submission.model_bundle != bundle
                or digest(submission) != review.candidate.submission_sha256
                or identity(submission.hotkey) != identity(review.candidate.contributor_hotkey)
            ):
                raise ValueError("certified reference changes its retained reviewed source")
            progress.advance(1)
            return CertifiedReferenceSource(retained, legacy=False)

    async def resolve_execution_source(self, job, role, bundle, request=None):
        source = await run_owned_thread(self.execution_source, job, role, bundle, request)
        if not isinstance(source, _ReferenceMetadataNeeded):
            return source
        retained = await self.metadata(job, source.review)
        if retained.direct_artifact is None:
            raise ValueError("certified reference metadata lacks its original direct artifact")
        return CertifiedReferenceSource(retained, legacy=False)

    def _materializer(self, source):
        return self.legacy if source.legacy else self.references

    def cache_identity(self, source):
        return self._materializer(source).cache_identity(source.selection)

    async def available(self, source):
        await self._materializer(source).available(source.selection)

    async def resumable(self, source, archive):
        return await self._materializer(source).resumable(source.selection, archive)

    async def materialized(self, source, archive):
        return await self._materializer(source).materialized(source.selection, archive)

    async def materialize(self, source, archive):
        return await self._materializer(source).materialize(source.selection, archive)
