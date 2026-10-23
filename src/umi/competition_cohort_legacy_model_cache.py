"""Restore original /1 models and pinned reference models into the shared cache."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path

from .competition_artifacts import verify_preserved_bundle
from .competition_chunked_model_backup import ChunkedBackupBinding
from .competition_cohort_model_acceptance import ModelReviewRequest
from .competition_model_cache_space import BootDiskModelCache, disjoint
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import read_private_model
from .protocol import canonical_json_bytes


class LegacyCohortModelCache:
    """Byte restoration only; original review/order journals still own authority."""

    def __init__(self, artifacts, sources, *, reference_authorized=None):
        if digest(artifacts.policy) != digest(sources.policy):
            raise ValueError("legacy cache policy differs from its authenticated readers")
        self.artifacts, self.sources = artifacts, sources
        if reference_authorized is not None and not callable(reference_authorized):
            raise ValueError("certified reference authorization must be callable")
        self.reference_authorized = reference_authorized

    def execution_source(self, job, role, bundle, request=None):
        cohort = job.round.cohort_sha256
        if not self.sources.has_cohort(cohort):
            return None
        authenticated = self.sources.authenticated[cohort]
        if role == "candidate":
            request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
            if request.direct_artifact is not None:
                return None
            if (
                request.acceptance.schema_ != "umi-cohort-model-artifact-acceptance/1"
                or request.acceptance.cohort_sha256 != cohort
                or request.record.request.signed_submission != job.submission
                or request.record.request.signed_submission.submission.model_bundle != bundle
            ):
                raise ValueError("legacy candidate request differs from its retained execution")
            resolved = self.sources.accepted(
                cohort,
                record=request.record,
                admission=request.admission,
                acceptance=request.acceptance,
            )
        elif role == "incumbent":
            if digest(bundle) != job.round.incumbent_model_sha256:
                raise ValueError("legacy execution reference differs from its certified round")
            model = digest(bundle)
            if (
                model != authenticated.legacy.baseline_model_sha256
                and not any(
                    value.model_sha256 == model for value in authenticated.legacy.incumbents
                )
                and self.reference_authorized is not None
            ):
                with TransferProgress(
                    "certified_cohort_reference_selection",
                    1,
                    unit="models",
                    planning_unit_seconds=(0.001, 1),
                ) as progress:
                    if self.reference_authorized(job, bundle) is True:
                        # The later baseline certificate selects the reference;
                        # the original adoption still selects only its byte source.
                        # This grants no new admission or execution order.
                        preserved = self.sources.preserved_reference(cohort, bundle)
                        progress.advance(1)
                        return preserved
            resolved = self.sources.resolve(
                cohort,
                baseline=digest(bundle) == authenticated.legacy.baseline_model_sha256,
                incumbent_sha256=(
                    None
                    if digest(bundle) == authenticated.legacy.baseline_model_sha256
                    else digest(bundle)
                ),
            )
        else:
            raise ValueError("legacy cache execution role is unsupported")
        if resolved.selection.bundle != bundle:
            raise ValueError("legacy storage model differs from its retained execution")
        return resolved

    def cache_identity(self, source):
        return digest(
            {"schema": "umi-legacy-model-cache-selection/1", "selection": digest(source.selection)}
        )

    async def resumable(self, source, archive):
        try:
            retained = await run_owned_thread(
                read_private_model,
                Path(archive) / "chunked-materialization.json",
                ChunkedBackupBinding,
            )
        except FileNotFoundError:
            return False
        return retained == source.selection.binding

    async def materialized(self, source, archive):
        if not await self.resumable(source, archive):
            return False
        with TransferProgress("legacy_model_cache_validation", 1, unit="models") as progress:
            try:
                await run_owned_thread(
                    verify_preserved_bundle,
                    source.selection.bundle,
                    Path(archive),
                    self.artifacts.policy,
                )
            except (OSError, ValueError):
                progress.emit("repair_required", reason="legacy_model_cache_missing_or_damaged")
                return False
            progress.advance(1)
            return True

    async def materialize(self, source, archive):
        archive = Path(archive)
        c = self.artifacts.config
        boot = c.materialization_boot_disk_cache
        if not disjoint(archive, Path(self.sources.verification_root)) or (
            boot is not None
            and not disjoint(Path(boot.directory), Path(self.sources.verification_root))
        ):
            raise ValueError("durable legacy verification state overlaps the disposable cache")
        self.artifacts.verify_materialization_filesystem(archive.parent)
        cache = (
            None
            if boot is None
            else BootDiskModelCache(boot, reserve_bytes=c.materialization_free_space_reserve_bytes)
        )

        def available():
            return self.artifacts.verify_materialization_filesystem(archive.parent).free

        def check_write(size):
            if available() < size + c.materialization_free_space_reserve_bytes:
                raise OSError("legacy model scratch capacity is unavailable")

        async with self.artifacts.materialization_serial:
            with cache.allocation_lease() if cache is not None else nullcontext():
                if cache is not None:
                    with TransferProgress(
                        "legacy_model_cache_space_preparation", 1, unit="models"
                    ) as progress:
                        cache.prepare(source.selection.bundle, archive=archive)
                        progress.advance(1)
                return await self.sources.reader(source).materialize(
                    archive,
                    maximum_materialized_bytes=c.maximum_materialized_bytes,
                    available_bytes=available if cache is None else cache.available_bytes,
                    reserve_bytes=c.materialization_free_space_reserve_bytes,
                    check_write=check_write if cache is None else cache.check_write,
                    check_file_write=None if cache is None else cache.check_file_write,
                )
