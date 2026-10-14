"""Publish small native metadata without reopening evidence or model payloads."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Annotated

from pydantic import Field, model_validator

from .competition_cohort_intake import CohortIntake, CohortIntakeConfig
from .competition_cohort_public_api import CohortPublicApiConfig, publish_cohort
from .competition_cohort_public_downloads import PublicArchive, PublicModelDownload, legacy_download
from .competition_cohort_public_inventory import export_public_model_inventory
from .competition_cohort_public_promotion import PublicPromotionJournal
from .competition_cohort_public_results import (
    PublicModelInventory,
    project_models,
    project_paid_results,
)
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_certification import CertifiedServiceAllocation
from .competition_cohort_service_quality import ClosedServiceQuality, ServiceTerms
from .competition_verification_reuse import VerificationReceipt, _payload
from .competition_verification_snapshot import PackageSnapshotRecord, SnapshotPreparation
from .competition_work_progress import WorkProgress
from .open_competition import CompetitionPolicy, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PinnedPublicMetadata(StrictProtocolModel):
    """Operator-selected immutable metadata, not an arbitrary public path."""

    path: str
    sha256: Hex32
    owner_uid: Annotated[int, Field(ge=0)]
    size_bytes: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def absolute(self):
        p = Path(self.path)
        if not p.is_absolute() or ".." in p.parts:
            raise ValueError("native public projection requires an absolute metadata path")
        return self

    def read(self) -> bytes:
        p = Path(self.path)
        if p.resolve() != p:
            raise ValueError("native public projection cannot follow metadata symlinks")
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != self.owner_uid
                or before.st_mode & 0o022
                or before.st_size != self.size_bytes
            ):
                raise ValueError("native public metadata owner, size or layout differs")
            raw = stream.read(self.size_bytes + 1)
            after = os.fstat(stream.fileno())

        def stamp(i):
            return (i.st_dev, i.st_ino, i.st_size, i.st_mtime_ns, i.st_ctime_ns)

        if (
            stamp(before) != stamp(after)
            or stamp(after) != stamp(p.lstat())
            or len(raw) != self.size_bytes
            or hashlib.sha256(raw).hexdigest() != self.sha256
        ):
            raise ValueError("native public metadata changed; repair or select a new native export")
        return raw


class LegacyPublicModelSource(StrictProtocolModel):
    model_sha256: Hex32
    association: PinnedPublicMetadata
    package: PinnedPublicMetadata
    archive: PublicArchive | None = None


class NativePublicIntakeSource(StrictProtocolModel):
    config: CohortIntakeConfig
    cohort_sha256: Hex32
    eligible_tracks: tuple[str, ...]


class CohortPublicPublisherConfig(StrictProtocolModel):
    api: CohortPublicApiConfig
    policy: PinnedPublicMetadata
    # Inventory is independent from rewards and contains all admitted public
    # revisions. It may be refreshed during intake, before any settlement exists.
    inventory: PinnedPublicMetadata | None = None
    native_intake: NativePublicIntakeSource | None = None
    direct_promotion_journal: PublicPromotionJournal | None = None
    snapshot: PinnedPublicMetadata | None = None
    service_quality_receipt: PinnedPublicMetadata | None = None
    legacy_models: Annotated[tuple[LegacyPublicModelSource, ...], Field(max_length=65536)] = ()

    @model_validator(mode="after")
    def paired_paid_sources(self):
        if (self.inventory is None) == (self.native_intake is None):
            raise ValueError("select one pinned inventory or native read-only intake source")
        if (self.snapshot is None) != (self.service_quality_receipt is None):
            raise ValueError("paid projection needs both native snapshot and quality receipt")
        if len({s.model_sha256 for s in self.legacy_models}) != len(self.legacy_models):
            raise ValueError("public legacy source repeats a model")
        return self


def read_paid_projection(config, policy):
    if config.snapshot is None:
        return None
    raw = config.snapshot.read()
    schema = json.loads(raw).get("schema")
    model = {
        "umi-private-verification-preparation/1": SnapshotPreparation,
        "umi-private-verification-snapshot/1": PackageSnapshotRecord,
    }.get(schema)
    if model is None:
        raise ValueError("unsupported native snapshot metadata requires a compatibility reader")
    snapshot = model.model_validate_json(raw).checked()
    envelope = json.loads(snapshot.envelope_json)
    if envelope["policy_sha256"] != digest(policy):
        raise ValueError("native public snapshot uses another policy")
    receipt = VerificationReceipt.model_validate_json(config.service_quality_receipt.read())
    if (
        receipt.checksum
        != hashlib.sha256(
            _payload(receipt.identity, receipt.dependencies, receipt.result_json)
        ).hexdigest()
    ):
        raise ValueError("native quality receipt checksum differs; repair required")
    quality = ClosedServiceQuality.model_validate_json(receipt.result_json)
    certificate = CertifiedServiceAllocation.model_validate_json(
        canonical_json_bytes(envelope["service"])
    )
    roster = RecoverableRosterEvidence.model_validate_json(
        canonical_json_bytes(envelope["inputs"]["roster"])
    )
    terms = ServiceTerms.model_validate_json(canonical_json_bytes(envelope["inputs"]["terms"]))
    return project_paid_results(quality, terms, certificate, roster, policy)


def publish_native_cohort(config: CohortPublicPublisherConfig):
    """Call under a single exporter lease; no native writes or evidence replay."""
    with WorkProgress(
        "public_cohort_publication", 4 + len(config.legacy_models), unit="metadata_items"
    ) as progress:
        policy = CompetitionPolicy.model_validate_json(config.policy.read())
        if config.inventory is not None:
            inventory = PublicModelInventory.model_validate_json(config.inventory.read())
        else:
            source = config.native_intake
            intake = CohortIntake(
                source.config, policy, eligible_tracks=source.eligible_tracks, read_only=True
            )
            inventory = export_public_model_inventory(intake, source.cohort_sha256)
        if inventory.policy != policy:
            raise ValueError("public inventory uses another pinned policy")
        catalog, bundles = project_models(inventory)
        progress.advance()
        paid = read_paid_projection(config, policy)
        progress.advance()
        downloads = {}
        for source in config.legacy_models:
            if source.model_sha256 not in bundles:
                raise ValueError("transport source is not an authorized public model")
            item = legacy_download(
                catalog.cohort_sha256,
                bundles[source.model_sha256],
                json.loads(source.association.read()),
                source.package.read(),
            )
            if source.archive is not None:
                item = PublicModelDownload.model_validate_json(
                    canonical_json_bytes(item.model_copy(update={"archive": source.archive}))
                )
            downloads[source.model_sha256] = item
            progress.advance()
        promoted = (
            set()
            if config.direct_promotion_journal is None
            else config.direct_promotion_journal.completed(inventory.acceptances)
        )
        for c in inventory.acceptances:
            a = c.acceptance
            if (
                a.direct_artifact is None
                or a.model_sha256 not in bundles
                or digest(c) not in promoted
            ):
                continue
            downloads[a.model_sha256] = PublicModelDownload(
                schema="umi-public-model-download/1",
                cohort_sha256=catalog.cohort_sha256,
                model_sha256=a.model_sha256,
                bundle=bundles[a.model_sha256],
                format="concatenated_payload",
                payload=a.direct_artifact.reservation.payload,
            )
        progress.advance()
        descriptor = publish_cohort(config.api, catalog, paid, tuple(downloads.values()))
        progress.advance()
    return {
        "status": "published",
        "cohort_sha256": catalog.cohort_sha256,
        "public_model_entries": len(catalog.items),
        "downloadable_models": len(downloads),
        "paid_miners": None if paid is None else len(paid.items),
        "descriptor": descriptor.model_dump(mode="json"),
        "chain_submission_authorized": False,
    }
