"""One authenticated frozen reference in the native settlement working set.

Reference authority comes from the exact retained round and locally applied
baseline receipt, never the latest promotion or an older transport baseline.
The original source acceptance selects bytes; native materialization and
preservation retain their existing verification receipts and recovery behavior.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from pydantic import RootModel

from .competition_artifacts import (
    preserve_bundle,
    reclaim_interrupted_preservation,
    verify_preserved_bundle,
)
from .competition_cohort_baseline_review import (
    CertifiedCohortBaselineReview,
    verify_baseline_review,
)
from .competition_cohort_direct_model_review import DirectModelArtifactReviewer
from .competition_cohort_legacy_model_cache import LegacyCohortModelCache
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelReviewRequest,
)
from .competition_model_cache_space import BootDiskModelCache
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import ModelBundle, digest, identity
from .private_files import (
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)

try:
    import fcntl
except ImportError:
    fcntl = None


@dataclass(frozen=True)
class _Source:
    bundle: ModelBundle
    selection: object = None
    legacy: bool = False


def _original_source(promotion, review):
    """Reuse certified original metadata; do not issue another rights review."""
    c = review.candidate
    slot = Path(review.source_cohort_sha256) / (c.submission_sha256 + ".json")
    request = read_private_model(
        promotion.directory / "model-reward-preparation" / slot,
        ModelReviewRequest,
        maximum_bytes=16 * 1024**2,
    )
    certificate = read_private_model(
        promotion.directory / "model-reward-acceptances" / slot,
        CertifiedModelArtifactAcceptance,
        maximum_bytes=256 * 1024,
    )
    a = certificate.acceptance
    sub = request.record.request.signed_submission.submission
    if (
        digest(certificate) != c.acceptance_sha256
        or request.acceptance != a
        or a.cohort_sha256 != review.source_cohort_sha256
        or a.authority_sha256 != c.authority_sha256
        or a.policy_sha256 != review.policy_sha256
        or a.submission_sha256 != c.submission_sha256
        or digest(sub) != c.submission_sha256
        or sub.model_bundle != review.model
        or a.model_sha256 != c.model_sha256
        or a.content_sha256 != c.content_sha256
        or identity(a.recipient_hotkey) != identity(c.contributor_hotkey)
        or identity(sub.hotkey) != identity(c.contributor_hotkey)
        or a.accepted_ordinal != c.accepted_ordinal
        or a.rights_evidence_sha256 != c.rights_evidence_sha256
        or a.reconstruction_evidence_sha256 != c.reconstruction_evidence_sha256
    ):
        raise ValueError("frozen reference changes its original certified source")
    return request


class SettlementReferencePreparation:
    """A bounded leased reference; created bytes retire after the last release.

    Existing archive entries are never owned or deleted here. A selected reader
    keeps its lease through native replay and recurring use; changing reference,
    releasing settlement inputs, or normal shutdown releases that dependency.
    Kernel leases also fence other processes using the same physical archive.
    """

    def __init__(self, artifacts, archive, promotion, *, legacy=None, maximum_bytes):
        if fcntl is None:
            raise RuntimeError("reference working sets require POSIX archive leases")
        self.artifacts, self.archive, self.promotion = artifacts, Path(archive), promotion
        self.legacy, self.maximum_bytes = legacy, maximum_bytes
        self.serial = asyncio.Lock()
        self.active = None
        self.reclaim_after = ""
        selected = artifacts.config.reference_preservation_directory
        self.preservation = None if selected is None else Path(selected)
        if self.preservation is not None:
            expected, actual = self.archive.stat(), self.preservation.stat()
            if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
                raise ValueError("reference preservation alias changes the selected archive")
        self.leases = self.archive / ".reference-working-set"
        if self.preservation is not None:
            ensure_private_directory(self.preservation / ".reference-working-set")

    def _source(self, prepared):
        if prepared.policy_sha256 != digest(self.artifacts.policy):
            raise ValueError("frozen reference changes selected policy")
        model = prepared.incumbent_model_sha256
        review = self.promotion.certified_cohort_baseline_reference(
            prepared.cohort_sha256,
            prepared.sequence,
            model,
            maximum_bytes=min(self.maximum_bytes, 16 * 1024**2),
        )
        if review is None and not (self.archive / model).exists():
            # Reward-only replay stores may have no promotion head. An original
            # quorum certificate can select bytes for this already frozen round;
            # it neither appends history nor changes the selected reference.
            try:
                certificate = read_private_model(
                    self.promotion.directory
                    / "model-reward-references"
                    / prepared.cohort_sha256
                    / (model + ".json"),
                    CertifiedCohortBaselineReview,
                    maximum_bytes=4 * 1024**2,
                )
            except FileNotFoundError:
                certificate = None
            if certificate is not None:
                review = verify_baseline_review(certificate, self.artifacts.policy).review
        if review is not None:
            if (
                review.target_cohort_sha256 != prepared.cohort_sha256
                or review.target_sequence != prepared.sequence
                or review.policy_sha256 != prepared.policy_sha256
                or digest(review.model) != model
            ):
                raise ValueError("certified reference differs from the frozen round")
            if (self.archive / model).exists():
                return _Source(review.model)
            if self.legacy is not None:
                for cohort in sorted(self.legacy.authenticated):
                    selected = self.legacy.preserved_reference(cohort, review.model)
                    if selected is not None:
                        return _Source(review.model, selected, True)
            request = _original_source(self.promotion, review)
            if request.direct_artifact is None:
                # Older local-only installations keep their original storage.
                return _Source(review.model)
            return _Source(review.model, request)
        if self.legacy is not None and self.legacy.has_cohort(prepared.cohort_sha256):
            cohort = prepared.cohort_sha256
            inventory = self.legacy.authenticated[cohort].legacy
            if model == inventory.baseline_model_sha256 or any(
                v.model_sha256 == model for v in inventory.incumbents
            ):
                selected = self.legacy.resolve(
                    cohort,
                    baseline=model == inventory.baseline_model_sha256,
                    incumbent_sha256=None if model == inventory.baseline_model_sha256 else model,
                )
                if digest(selected.selection.bundle) != model:
                    raise ValueError("legacy reference differs from the frozen round")
                return _Source(selected.selection.bundle, selected, True)
        bundle = read_private_model(
            self.archive / model / "manifest.json", ModelBundle, maximum_bytes=16 * 1024**2
        )
        if digest(bundle) != model:
            raise ValueError("local reference differs from the frozen round")
        return _Source(bundle)

    def _marker(self, model):
        root = self.archive if self.preservation is None else self.preservation
        return root / ".reference-working-set" / (model + ".json")

    def _pending_marker(self, model):
        return self._marker(model).with_suffix(".pending.json")

    def _expected(self, source, *, completed=False):
        result = {
            "schema": "umi-settlement-reference-working-set/1",
            "model_sha256": digest(source.bundle),
        }
        if completed:
            info = (self.archive / digest(source.bundle)).lstat()
            result["generation"] = [
                str(v) for v in (info.st_dev, info.st_ino, info.st_uid, info.st_mtime_ns)
            ]
        return result

    def _owned(self, source):
        try:
            marker = read_private_model(self._marker(digest(source.bundle)), RootModel[dict]).root
        except FileNotFoundError:
            return False
        if marker == self._expected(source):
            # Publication was interrupted before ownership could be proved.
            # Reuse native bytes, but never retire an unproven generation.
            return False
        if marker != self._expected(source, completed=True):
            raise ValueError("reference working-set ownership changed; repair required")
        return True

    def _remove_slot(self, slot):
        if not slot.exists() and not slot.is_symlink():
            return
        info = slot.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("reference cache slot changed its private owner")
        shutil.rmtree(slot)

    def _release(self):
        if self.active is None:
            return
        source, fd = self.active
        self.active = None
        self._release_lease(source, fd)

    def _release_lease(self, source, fd):
        """Retire only after the cached owner and every scoped reader release."""
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            if not self._owned(source):
                return
            if (
                self.preservation is None
                or not self.artifacts.config.reference_working_set_reclamation
            ):
                with TransferProgress(
                    "settlement_reference_reclamation", 1, unit="models"
                ) as progress:
                    progress.emit("blocked", reason="archive_consumer_lease_rollout_not_selected")
                return
            # This exact model was created by this owner. Every selected native
            # consumer holds the shared inode while it may replay the bundle.
            with TransferProgress("settlement_reference_reclamation", 1, unit="models") as progress:
                self._remove_slot(self.preservation / digest(source.bundle))
                (self.preservation / (".verified-" + digest(source.bundle) + ".json")).unlink(
                    missing_ok=True
                )
                self._marker(digest(source.bundle)).unlink()
                self._pending_marker(digest(source.bundle)).unlink(missing_ok=True)
                progress.advance(1)
        finally:
            os.close(fd)

    def close(self):
        self._release()

    async def reclaim_released(self):
        """The recurring writable owner completes retirement after RO readers exit."""
        if self.preservation is None or not self.artifacts.config.reference_working_set_reclamation:
            return
        async with self.serial:
            await run_owned_thread(self._reclaim_one)

    def _reclaim_one(self):
        markers = sorted(
            p
            for p in self.leases.glob("*.json")
            if len(p.stem) == 64 and all(c in "0123456789abcdef" for c in p.stem)
        )
        if not markers:
            return
        marker = next((p for p in markers if p.name > self.reclaim_after), markers[0])
        self.reclaim_after = marker.name
        if self.active is not None and digest(self.active[0].bundle) == marker.stem:
            return
        fd = lock_private_file(self._lock_path(marker.stem), shared=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            path = self.archive / marker.stem
            if path.exists():
                bundle = read_private_model(
                    path / "manifest.json", ModelBundle, maximum_bytes=16 * 1024**2
                )
                if digest(bundle) != marker.stem:
                    raise ValueError("reference reclamation manifest changed")
                # Hand the same locked descriptor to ordinary retirement.
                owned, fd = fd, None
                self._release_lease(_Source(bundle), owned)
            else:
                completed = read_private_model(marker, RootModel[dict]).root
                if completed.get("model_sha256") != marker.stem or "generation" not in completed:
                    raise ValueError(
                        "missing reference has no completed ownership; repair required"
                    )
                # Complete an interrupted deletion; no remaining model directory
                # and no live reader or writer can now depend on this generation.
                (self.preservation / (".verified-" + marker.stem + ".json")).unlink(missing_ok=True)
                self._marker(marker.stem).unlink()
                self._pending_marker(marker.stem).unlink(missing_ok=True)
        finally:
            if fd is not None:
                os.close(fd)

    async def ensure(self, prepared):
        async with self.serial:
            await self._ensure(prepared)

    def _lock_path(self, model):
        root = (
            self.leases
            if self.preservation is None
            else self.preservation / ".reference-working-set"
        )
        return root / (model + ".lock")

    async def _acquire_lease(self, model):
        acquired = []

        def acquire():
            acquired.append(lock_private_file(self._lock_path(model), shared=True))

        try:
            await run_owned_thread(acquire)
        except BaseException:
            # The owned thread drains before cancellation propagates. A newly
            # opened descriptor must not be abandoned with its result.
            if acquired:
                os.close(acquired[0])
            raise
        return acquired[0]

    @asynccontextmanager
    async def scope(self, prepared):
        """Hold this caller's model through replay while another caller switches."""
        lease = None
        async with self.serial:
            await self._ensure(prepared)
            if self.active is not None:
                source = self.active[0]
                fd = await self._acquire_lease(digest(source.bundle))
                lease = source, fd
        try:
            yield
        finally:
            if lease is not None:
                await run_owned_thread(self._release_lease, *lease)

    async def _ensure(self, prepared):
        """Called only by the serial owner; scopes add their lease before unlock."""
        source = await run_owned_thread(self._source, prepared)
        if self.active is not None and digest(self.active[0].bundle) == digest(source.bundle):
            # Preserve the native immutable receipt; this is metadata only.
            await run_owned_thread(
                verify_preserved_bundle, source.bundle, self.archive, self.artifacts.policy
            )
            return
        await run_owned_thread(self._release)
        model = digest(source.bundle)
        lock = self._lock_path(model)
        if self.preservation is None and not lock.exists():
            # Historical read-only archives retain their native behavior.
            # They cannot acquire ownership or enable automatic retirement.
            await run_owned_thread(
                verify_preserved_bundle, source.bundle, self.archive, self.artifacts.policy
            )
            return
        # Readers first acquire a shared lease. Missing content needs an
        # exclusive writer; a concurrent writer remains an ordinary retry.
        fd = await self._acquire_lease(model)
        try:
            if not (self.archive / model).exists():
                fcntl.flock(fd, fcntl.LOCK_UN)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if not (self.archive / model).exists():
                    await self._restore(source)
                fcntl.flock(fd, fcntl.LOCK_SH)
            await run_owned_thread(
                verify_preserved_bundle, source.bundle, self.archive, self.artifacts.policy
            )
            await run_owned_thread(self._cleanup_completed_slot, source)
            self.active = (source, fd)
        except BaseException:
            os.close(fd)
            raise

    def _slot(self, source):
        boot = self.artifacts.config.materialization_boot_disk_cache
        if boot is None:
            return None
        archive = self.archive.stat()
        return Path(boot.directory) / (
            "reference-" + digest([str(archive.st_dev), str(archive.st_ino), digest(source.bundle)])
        )

    def _cleanup_completed_slot(self, source):
        if self.preservation is None:
            return
        slot = self._slot(source)
        if slot is None or not slot.exists():
            return
        # The native canonical receipt has already been checked. Only the
        # exact task slot and its original ownership marker may be reclaimed.
        try:
            marker = read_private_model(self._marker(digest(source.bundle)), RootModel[dict]).root
        except FileNotFoundError:
            marker = read_private_model(
                self._pending_marker(digest(source.bundle)), RootModel[dict]
            ).root
        if marker not in (self._expected(source), self._expected(source, completed=True)):
            raise ValueError("interrupted reference publication needs ownership repair")
        cache = BootDiskModelCache(
            self.artifacts.config.materialization_boot_disk_cache,
            reserve_bytes=self.artifacts.config.materialization_free_space_reserve_bytes,
        )
        with cache.allocation_lease():
            self._remove_slot(slot)
            self._pending_marker(digest(source.bundle)).unlink(missing_ok=True)

    async def _restore(self, source):
        if self.preservation is None:
            raise OSError("frozen reference awaits its selected writable preservation owner")
        if source.selection is None:
            raise OSError(
                "frozen reference has no authenticated remote source; "
                "original archive repair required"
            )
        config = self.artifacts.config
        boot = config.materialization_boot_disk_cache
        if boot is None:
            raise OSError(
                "remote reference restoration requires the supported bounded boot-disk cache"
            )
        cache = BootDiskModelCache(
            boot, reserve_bytes=config.materialization_free_space_reserve_bytes
        )
        cache.validate_root(Path(boot.directory))
        await run_owned_thread(
            reclaim_interrupted_preservation,
            source.bundle,
            self.preservation,
            self.artifacts.policy,
        )
        reserve = config.materialization_free_space_reserve_bytes
        rounded = cache.model_bytes(source.bundle)
        slot = self._slot(source)
        same_device = self.archive.stat().st_dev == Path(boot.directory).stat().st_dev
        with cache.allocation_lease():
            # Already allocated native transfer files count once on retry.
            _, _, resident = cache._measure(selected=slot)
            remaining = max(0, rounded - resident)
            free = shutil.disk_usage(self.archive).free
            if free < reserve + rounded + (remaining if same_device else 0):
                raise OSError(
                    "reference restoration cannot preserve operating reserve and both native copies"
                )
        if os.statvfs(self.archive).f_favail < 2 * (len(source.bundle.files) + 64):
            raise OSError("reference restoration lacks inode headroom")
        reader = DirectModelArtifactReviewer(
            config.model_copy(
                update={
                    "materialization_free_space_reserve_bytes": reserve
                    + (rounded if same_device else 0)
                }
            ),
            self.artifacts.policy,
            None,
            multipart=self.artifacts.multipart,
            verification_root=self.artifacts.verification_root,
        )
        materializer = LegacyCohortModelCache(reader, self.legacy) if source.legacy else reader
        await run_owned_thread(
            publish_private_model,
            self._pending_marker(digest(source.bundle)),
            RootModel(self._expected(source)),
        )
        target = await materializer.materialize(source.selection, slot)
        if target != slot / digest(source.bundle):
            raise ValueError("native reference materializer selected another bundle")

        def check_write(size):
            if shutil.disk_usage(self.archive).free < reserve + size:
                raise OSError("reference preservation must retain operating reserve")

        with (
            cache.allocation_lease(),
            TransferProgress(
                "settlement_reference_preservation",
                sum(f.size_bytes for f in source.bundle.files),
                unit="bytes",
            ) as progress,
        ):
            await run_owned_thread(
                partial(
                    preserve_bundle,
                    source.bundle,
                    target / "model",
                    self.preservation,
                    self.artifacts.policy,
                    check_write=check_write,
                    on_bytes_written=progress.advance,
                )
            )
            await run_owned_thread(
                publish_private_model,
                self._marker(digest(source.bundle)),
                RootModel(self._expected(source, completed=True)),
            )
            await run_owned_thread(self._remove_slot, slot)
            self._pending_marker(digest(source.bundle)).unlink(missing_ok=True)
