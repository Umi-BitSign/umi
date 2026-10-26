"""Compact model dependencies for previously completed native coverage.

Only the native coverage issuer captures these facts after package preparation.
They retain the selected settlement owner and its exact small model receipts;
restoration checks those receipts and the authenticated R2 object generations.
Neither package payloads nor model weights are loaded by this dependency check.
"""

from __future__ import annotations

import os
import sqlite3
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_direct_model_review import (
    DirectModelSettlementVerification,
    DirectModelSettlementVerifier,
)
from .competition_cohort_direct_model_upload import preserved_model_object_key
from .competition_cohort_legacy_model_settlement import (
    LegacyModelSettlementVerification,
    check_legacy_settlement_metadata,
)
from .competition_reward_coverage_model_ledger import (
    ModelDependencyQualification,
    QualificationLedger,
)
from .competition_reward_coverage_prepared import RetainedCoveragePackage
from .competition_transport_verification import TransferProgress
from .competition_verification_rules import runtime_identity
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import private_path, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex

ABI = "umi-coverage-model-dependencies/1"
REMOTE_ABI = "umi-coverage-model-dependencies/2"


class CoverageModelDependencyRepairRequired(ValueError):
    """An observed change must be repaired under the original native owner."""


class ModelDependencyContext(StrictProtocolModel):
    policy_sha256: Hex32
    standing_review_sha256: Hex32
    namespace_sha256: Hex32
    source_owner: Hex32 | None
    receipts_path: str
    receipts_identity: tuple[int, int, int]
    semantics_sha256: Hex32

    @property
    def receipts(self):
        return Path(self.receipts_path)


class CoverageModelDependency(StrictProtocolModel):
    cohort_sha256: Hex32
    submission_sha256: Hex32
    authority_sha256: Hex32
    source_owner: Hex32
    object_key: Annotated[str, Field(min_length=1, max_length=1024)]
    receipt: DirectModelSettlementVerification

    @model_validator(mode="after")
    def original_object(self):
        if (
            self.object_key
            != preserved_model_object_key(
                self.cohort_sha256, self.receipt.model_sha256, self.receipt.payload_sha256
            )
            or sha256_hex(self.object_key.encode()) != self.receipt.source_object_key_sha256
        ):
            raise ValueError("coverage model dependency changes its accepted object")
        return self


class LegacyCoverageModelDependency(StrictProtocolModel):
    cohort_sha256: Hex32
    submission_sha256: Hex32
    authority_sha256: Hex32
    receipt: LegacyModelSettlementVerification

    @model_validator(mode="after")
    def original_participant(self):
        if (self.cohort_sha256, self.submission_sha256) != (
            self.receipt.cohort_sha256,
            self.receipt.submission_sha256,
        ):
            raise ValueError("coverage legacy dependency changes its original participant")
        return self


class CoverageModelDependencies(StrictProtocolModel):
    schema_: Literal["umi-coverage-model-dependencies/1", "umi-coverage-model-dependencies/2"] = (
        Field(alias="schema")
    )
    mode: Literal["not_selected", "empty", "native_required", "direct", "remote"]
    context: ModelDependencyContext | None
    items: tuple[CoverageModelDependency | LegacyCoverageModelDependency, ...] = ()

    @model_validator(mode="after")
    def selected_shape(self):
        if (
            (self.mode == "not_selected") != (self.context is None)
            or (self.mode in {"direct", "remote"}) != bool(self.items)
            or (self.schema_ == REMOTE_ABI) != (self.mode == "remote")
            or (self.mode == "remote")
            != any(isinstance(v, LegacyCoverageModelDependency) for v in self.items)
            or len({(v.cohort_sha256, v.submission_sha256) for v in self.items}) != len(self.items)
        ):
            raise ValueError("coverage model dependency selection differs")
        return self


class ModelDependencyHold(StrictProtocolModel):
    schema_: Literal["umi-coverage-model-dependency-hold/1"] = Field(alias="schema")
    dependency_sha256: Hex32


def _context(verifier):
    if type(verifier) is not DirectModelSettlementVerifier:
        raise CoverageModelDependencyRepairRequired("coverage model verifier is unsupported")
    artifacts = verifier.artifacts
    if artifacts.multipart.signer.bucket != artifacts.config.r2_bucket:
        raise CoverageModelDependencyRepairRequired("coverage model verifier changed its bucket")
    try:
        private_path(str(verifier.receipts))
        stat = verifier.receipts.stat()
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise ValueError("unsafe coverage model owner")
    except (ValueError, OSError) as error:
        raise CoverageModelDependencyRepairRequired(
            "coverage model owner is missing or unsafe"
        ) from error
    return ModelDependencyContext(
        policy_sha256=digest(artifacts.policy),
        standing_review_sha256=digest(artifacts.config.standing_review_policy),
        namespace_sha256=digest(
            {
                "endpoint": artifacts.multipart.signer.endpoint,
                "bucket": artifacts.multipart.signer.bucket,
            }
        ),
        source_owner=None if artifacts.owner_hotkey is None else identity(artifacts.owner_hotkey),
        receipts_path=str(verifier.receipts),
        receipts_identity=(stat.st_dev, stat.st_ino, stat.st_uid),
        semantics_sha256=digest([ABI, runtime_identity()]),
    )


def _receipt_path(verifier, item):
    return verifier.receipts / item.cohort_sha256 / (item.submission_sha256 + ".json")


def _hold_path(verifier, item):
    return (
        verifier.receipts
        / "coverage-dependency-holds"
        / item.cohort_sha256
        / (item.submission_sha256 + ".json")
    )


def _qualification_path(verifier, context, item):
    return (
        verifier.receipts
        / "coverage-dependency-qualifications"
        / digest(context)
        / item.cohort_sha256
        / (item.submission_sha256 + ".json")
    )


def _qualification(verifier, context, item, *, required, repairing=False):
    expected = ModelDependencyQualification(
        schema="umi-coverage-model-qualification/1",
        context_sha256=digest(context),
        dependency_sha256=digest(item),
    )
    ledger = QualificationLedger(verifier.receipts)
    completed = ledger.load(context, item)
    if completed is not None and completed != expected:
        raise ValueError("completed coverage model qualification ledger changed")
    try:
        value = read_private_model(
            _qualification_path(verifier, context, item),
            ModelDependencyQualification,
            maximum_bytes=64 * 1024,
        )
    except FileNotFoundError:
        if completed is not None and repairing:
            with TransferProgress(
                "coverage_model_qualification_metadata_repair",
                1,
                unit="qualifications",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress:
                publish_private_model(
                    _qualification_path(verifier, context, item),
                    completed,
                    maximum_bytes=64 * 1024,
                )
                progress.advance(1, restored=True)
            return completed
        if required or completed is not None:
            raise ValueError("completed coverage model qualification is missing") from None
        return None
    if value != expected:
        raise ValueError("completed coverage model qualification changed")
    if completed is None:
        # A supported older writer may have completed its exact qualification
        # after the one-time ledger inventory. Preserve those bytes and retain
        # the completion as an explicit metadata-only compatibility migration.
        with TransferProgress(
            "coverage_model_qualification_completion_migration",
            1,
            unit="qualifications",
            planning_unit_seconds=(0.00001, 0.01),
        ) as progress:
            ledger.remember(context, item, value)
            progress.advance(1, restored=True)
    return value


def _publish_qualification(verifier, context, item, value):
    # Commit the permanent fact first. Interrupted file publication becomes a
    # visible scoped metadata repair, never another expensive native check.
    QualificationLedger(verifier.receipts).remember(context, item, value)
    publish_private_model(
        _qualification_path(verifier, context, item), value, maximum_bytes=64 * 1024
    )


def _held(verifier, item):
    try:
        return read_private_model(
            _hold_path(verifier, item), ModelDependencyHold, maximum_bytes=64 * 1024
        )
    except FileNotFoundError:
        return None


def _hold(verifier, item):
    publish_private_model(
        _hold_path(verifier, item),
        ModelDependencyHold(
            schema="umi-coverage-model-dependency-hold/1", dependency_sha256=digest(item)
        ),
        maximum_bytes=64 * 1024,
    )


def _clear_hold(verifier, item):
    path = _hold_path(verifier, item)
    held = _held(verifier, item)
    if held is None:
        return
    if held.dependency_sha256 != digest(item):
        raise CoverageModelDependencyRepairRequired(
            "coverage repair has not restored its original model dependency"
        )
    path.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def model_metadata_seal(value: CoverageModelDependencies):
    """Identity-check native small receipts and completed snapshot metadata only."""
    if value.mode not in {"direct", "remote"}:
        return []
    from .competition_cohort_legacy_model_settlement import legacy_seal_path, legacy_snapshot_path
    from .file_identity import file_fingerprint

    context = value.context
    paths = [
        context.receipts,
        context.receipts / "coverage-qualification-owner.json",
        context.receipts / "coverage-qualification-ledger/rounds.sqlite3",
    ]
    for item in value.items:
        paths.extend(
            (
                _receipt_path(context, item),
                _hold_path(context, item),
                _qualification_path(context, context, item),
            )
        )
        if isinstance(item, LegacyCoverageModelDependency):
            paths.extend(
                (
                    legacy_seal_path(context.receipts, item.receipt),
                    legacy_snapshot_path(context.receipts, item.receipt),
                )
            )
    result = []
    for path in paths:
        private_path(str(path))
        try:
            info = path.lstat()
        except FileNotFoundError:
            result.append([str(path), None])
            continue
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CoverageModelDependencyRepairRequired(
                "coverage dependency metadata owner changed"
            )
        result.append([str(path), list(map(str, file_fingerprint(info)))])
        if path.suffix == ".sqlite3":
            for suffix in ("-wal", "-journal"):
                side = Path(str(path) + suffix)
                result.append(
                    [
                        str(side),
                        list(map(str, file_fingerprint(side.lstat()))) if side.exists() else None,
                    ]
                )
    return result


def check_coverage_model_metadata(value: CoverageModelDependencies, *, checked_cache=None):
    """Keep issued compact endpoints subject to known damage in every consumer.

    This never probes R2: its selected restore owner performs the generation
    check. Private original metadata and durable observed-damage holds remain
    dependencies when a caller later credits an already issued endpoint.
    """
    if value.mode not in {"direct", "remote"}:
        return
    before = model_metadata_seal(value) if checked_cache is not None else None
    cache_key = digest(value) if checked_cache is not None else None
    if checked_cache is not None and checked_cache.get(cache_key) == before:
        return
    owner = value.context
    try:
        private_path(str(owner.receipts))
        stat = owner.receipts.stat()
        if (
            stat.st_dev,
            stat.st_ino,
            stat.st_uid,
        ) != owner.receipts_identity or stat.st_mode & 0o077:
            raise ValueError("coverage model receipt owner changed")
    except (ValueError, OSError) as error:
        raise CoverageModelDependencyRepairRequired(
            "coverage original model owner requires repair"
        ) from error
    for item in value.items:
        try:
            if _held(owner, item) is not None:
                raise CoverageModelDependencyRepairRequired(
                    "coverage model dependency requires explicit original repair"
                )
            if (
                read_private_model(
                    _receipt_path(owner, item),
                    type(item.receipt),
                    maximum_bytes=64 * 1024,
                )
                != item.receipt
            ):
                raise ValueError("coverage model receipt changed")
            if isinstance(item, LegacyCoverageModelDependency):
                check_legacy_settlement_metadata(owner.receipts, item.receipt)
            _qualification(owner, owner, item, required=True)
        except CoverageModelDependencyRepairRequired:
            raise
        except (ValueError, FileNotFoundError, sqlite3.Error) as error:
            try:
                _hold(owner, item)
            except (ValueError, OSError) as hold_error:
                raise CoverageModelDependencyRepairRequired(
                    "coverage model repair hold is damaged"
                ) from hold_error
            raise CoverageModelDependencyRepairRequired(
                "coverage model metadata requires explicit scoped repair"
            ) from error

    if checked_cache is not None:
        if model_metadata_seal(value) != before:
            raise CoverageModelDependencyRepairRequired("coverage metadata changed during check")
        checked_cache[cache_key] = before


async def _check_item(verifier, item, *, context=None, repairing=False):
    try:
        held = await run_owned_thread(_held, verifier, item)
        if held is not None and (not repairing or held.dependency_sha256 != digest(item)):
            raise CoverageModelDependencyRepairRequired(
                "coverage model dependency requires explicit original repair"
            )
        retained = await run_owned_thread(
            partial(read_private_model, maximum_bytes=64 * 1024),
            _receipt_path(verifier, item),
            type(item.receipt),
        )
        if retained != item.receipt:
            raise ValueError("coverage model receipt changed")
        if isinstance(item, LegacyCoverageModelDependency):
            legacy = verifier.legacy_for(item.cohort_sha256)
            if legacy is None:
                raise ValueError("coverage legacy R2 selection is missing")
            if legacy.authenticated.legacy.authority_sha256 != item.authority_sha256:
                raise ValueError("coverage legacy authority changed")
            await legacy.check_receipt(verifier.receipts, item.receipt)
        else:
            head = await verifier.artifacts.multipart.head(item.object_key)
            if head is None or (head.size_bytes, head.etag) != (
                item.receipt.total_bytes,
                item.receipt.provider_etag,
            ):
                raise ValueError("coverage model object generation changed")
        # Observe mutation during the HEAD await before issuing a restored fact.
        if (
            await run_owned_thread(
                partial(read_private_model, maximum_bytes=64 * 1024),
                _receipt_path(verifier, item),
                type(item.receipt),
            )
            != retained
        ):
            raise ValueError("coverage model receipt changed during generation check")
        if context is not None:
            await run_owned_thread(partial(_qualification, required=True), verifier, context, item)
    except CoverageModelDependencyRepairRequired:
        raise
    except (FileNotFoundError, ValueError, AttributeError, TypeError, sqlite3.Error) as error:
        try:
            await run_owned_thread(_hold, verifier, item)
        except (ValueError, OSError) as hold_error:
            raise CoverageModelDependencyRepairRequired(
                "coverage model repair hold is damaged or unavailable"
            ) from hold_error
        raise CoverageModelDependencyRepairRequired(
            "coverage model original receipt or generation requires explicit scoped repair"
        ) from error


async def _qualify_item(verifier, context, item, participant, certificate, *, repairing=False):
    """Migrate /2 model receipts lacking native policy/namespace bindings once."""
    try:
        if await run_owned_thread(
            partial(_qualification, required=False, repairing=repairing), verifier, context, item
        ):
            return
    except (ValueError, FileNotFoundError, sqlite3.Error) as error:
        await run_owned_thread(_hold, verifier, item)
        raise CoverageModelDependencyRepairRequired(
            "coverage model qualification requires original metadata repair"
        ) from error
    if isinstance(item, LegacyCoverageModelDependency):
        # The new receipt already binds authenticated legacy provenance and the
        # independent full-byte result. It needs no historical /2 qualification
        # migration or reinterpretation under today's standing-review policy.
        legacy = verifier.legacy_for(item.cohort_sha256)
        if legacy is None:
            raise CoverageModelDependencyRepairRequired("coverage legacy R2 selection is missing")
        await legacy.check_receipt(verifier.receipts, item.receipt)
        value = ModelDependencyQualification(
            schema="umi-coverage-model-qualification/1",
            context_sha256=digest(context),
            dependency_sha256=digest(item),
        )
        await run_owned_thread(_publish_qualification, verifier, context, item, value)
        return
    request = verifier._request(participant, certificate)
    with TransferProgress(
        "coverage_model_qualification_migration", item.receipt.total_bytes, unit="bytes"
    ) as progress:
        # Existing persistent model-byte results are independent of the local
        # materialization cache. Their unchanged successful checks are reused;
        # the selected standing review still derives its document verdicts.
        inputs, head = await verifier.artifacts.verify(request, preserved=True)
        acceptance = certificate.acceptance
        if (
            (head.size_bytes, head.etag) != (item.receipt.total_bytes, item.receipt.provider_etag)
            or digest(inputs.rights_evidence) != acceptance.rights_evidence_sha256
            or digest(inputs.reconstruction_evidence) != acceptance.reconstruction_evidence_sha256
        ):
            await run_owned_thread(_hold, verifier, item)
            progress.emit("repair_required", reason="coverage_model_native_qualification_changed")
            raise CoverageModelDependencyRepairRequired(
                "coverage model native qualification changed"
            )
        value = ModelDependencyQualification(
            schema="umi-coverage-model-qualification/1",
            context_sha256=digest(context),
            dependency_sha256=digest(item),
        )
        await run_owned_thread(
            _publish_qualification,
            verifier,
            context,
            item,
            value,
        )
        progress.advance(item.receipt.total_bytes, restored=True)


def _selected_participants(package, certificates):
    completed = {c.acceptance.submission_sha256 for c in certificates}
    participants = tuple(
        p
        for p in package.inputs.roster.participants
        if p.record.request.signed_submission.submission.track == "model"
        and digest(p.record.request.signed_submission.submission) in completed
    )
    if tuple(digest(p.record.request.signed_submission.submission) for p in participants) != tuple(
        c.acceptance.submission_sha256 for c in certificates
    ):
        raise ValueError("coverage model acceptances differ from selected roster")
    return participants


def _snapshot_item(verifier, participant, certificate):
    if certificate.acceptance.direct_artifact is None:
        legacy = verifier.legacy_for(certificate.acceptance.cohort_sha256)
        if legacy is None:
            raise CoverageModelDependencyRepairRequired("legacy R2 storage is not selected")
        receipt = legacy.verify_candidate(participant, certificate, verifier.receipts)
        return LegacyCoverageModelDependency(
            cohort_sha256=certificate.acceptance.cohort_sha256,
            submission_sha256=certificate.acceptance.submission_sha256,
            authority_sha256=certificate.acceptance.authority_sha256,
            receipt=receipt,
        )
    request = verifier._request(participant, certificate)
    _, _, key = verifier.artifacts._source(request, preserved=True)
    receipt = read_private_model(
        verifier._path(certificate), DirectModelSettlementVerification, maximum_bytes=64 * 1024
    )
    # The completed native path has already checked the certified full request.
    # Rebind all compact receipt fields before retaining its dependency snapshot.
    payload = request.direct_artifact.reservation.payload
    if (
        receipt.review_request_sha256 != digest(request)
        or receipt.acceptance_sha256 != digest(certificate)
        or receipt.model_sha256 != payload.model_sha256
        or receipt.payload_sha256 != payload.payload_sha256
        or receipt.total_bytes != payload.total_bytes
        or receipt.source_object_key_sha256 != sha256_hex(key.encode())
    ):
        raise CoverageModelDependencyRepairRequired(
            "coverage model receipt differs from native acceptance"
        )
    return CoverageModelDependency(
        cohort_sha256=certificate.acceptance.cohort_sha256,
        submission_sha256=certificate.acceptance.submission_sha256,
        authority_sha256=certificate.acceptance.authority_sha256,
        source_owner=identity(request.direct_artifact.signature.hotkey),
        object_key=key,
        receipt=receipt,
    )


async def capture_coverage_model_dependencies(
    preparation, package, prepared, *, repair_reason=None
):
    """Called only after native package and artifact review by the coverage issuer."""
    verifier = preparation.model_artifacts
    if verifier is None:
        value = CoverageModelDependencies(schema=ABI, mode="not_selected", context=None)
        return value.model_dump(mode="json", by_alias=True)
    context = await run_owned_thread(_context, verifier)
    if context.policy_sha256 != preparation.policy_sha256:
        raise CoverageModelDependencyRepairRequired("coverage model verifier policy changed")
    award = prepared.allocation.model_award
    certificates = () if award is None else award.acceptances
    if not certificates:
        mode, items = "empty", []
    elif type(package) is RetainedCoveragePackage or (
        any(
            c.acceptance.direct_artifact is None
            and verifier.legacy_for(c.acceptance.cohort_sha256) is None
            for c in certificates
        )
    ):
        # Older preserved directory bundles still execute their original native
        # model path on each replay. Never reinterpret them as remotely verified.
        mode, items = "native_required", []
    else:
        mode, items = (
            (
                "remote"
                if any(c.acceptance.direct_artifact is None for c in certificates)
                else "direct"
            ),
            [],
        )
        participants = _selected_participants(package, certificates)
        async with verifier.serial:
            with TransferProgress(
                "coverage_model_dependency_capture", len(certificates), unit="models"
            ) as progress:
                for participant, certificate in zip(participants, certificates, strict=True):
                    item = await run_owned_thread(
                        _snapshot_item, verifier, participant, certificate
                    )
                    try:
                        await _check_item(verifier, item, repairing=repair_reason is not None)
                        await _qualify_item(
                            verifier,
                            context,
                            item,
                            participant,
                            certificate,
                            repairing=repair_reason is not None,
                        )
                        if repair_reason is not None:
                            await run_owned_thread(_clear_hold, verifier, item)
                    except CoverageModelDependencyRepairRequired:
                        progress.emit("repair_required", reason="coverage_model_dependency_changed")
                        raise
                    items.append(item)
                    progress.advance(1, restored=True)
    if await run_owned_thread(_context, verifier) != context:
        raise CoverageModelDependencyRepairRequired("coverage model owner changed during capture")
    value = CoverageModelDependencies(
        schema=REMOTE_ABI if mode == "remote" else ABI,
        mode=mode,
        context=context,
        items=tuple(items),
    )
    return value.model_dump(mode="json", by_alias=True)


async def restore_coverage_model_dependencies(preparation, raw):
    """Return False only for an explicit supported native migration/fallback."""
    verifier = preparation.model_artifacts
    if raw is None:
        if verifier is None:
            return True  # Legacy no-model facts retain their original semantics.
        with TransferProgress(
            "coverage_model_dependency_migration", 1, unit="endpoints"
        ) as progress:
            progress.emit(
                "waiting", reason="legacy_coverage_requires_native_model_dependency_capture"
            )
        return False
    value = CoverageModelDependencies.model_validate_json(canonical_json_bytes(raw))
    if value.mode == "not_selected":
        if verifier is not None:
            raise CoverageModelDependencyRepairRequired("coverage model verifier selection changed")
        return True
    context = await run_owned_thread(_context, verifier)
    if context != value.context or context.policy_sha256 != preparation.policy_sha256:
        raise CoverageModelDependencyRepairRequired(
            "coverage model verifier context requires explicit repair"
        )
    if value.mode == "native_required":
        with TransferProgress(
            "coverage_legacy_model_native_replay", 1, unit="endpoints"
        ) as progress:
            progress.emit(
                "waiting", reason="legacy_directory_model_requires_original_native_checks"
            )
        return False
    async with verifier.serial:
        with TransferProgress(
            "coverage_model_dependency_restore", len(value.items), unit="models"
        ) as progress:
            for item in value.items:
                try:
                    await _check_item(verifier, item, context=context)
                except CoverageModelDependencyRepairRequired:
                    progress.emit("repair_required", reason="coverage_model_dependency_changed")
                    raise
                progress.advance(1, restored=True)
    if await run_owned_thread(_context, verifier) != context:
        raise CoverageModelDependencyRepairRequired("coverage model owner changed during restore")
    return True


async def restore_completed_model_dependencies(preparation, raw, checked_cache):
    """Refresh identical completed endpoint dependencies once per selected owner."""
    if checked_cache is None:
        return await restore_coverage_model_dependencies(preparation, raw)
    if raw is None:
        return await restore_coverage_model_dependencies(preparation, raw)
    value = CoverageModelDependencies.model_validate_json(canonical_json_bytes(raw))
    key = digest(value)
    before = await run_owned_thread(model_metadata_seal, value)
    verifier = preparation.model_artifacts
    context = None if verifier is None else await run_owned_thread(_context, verifier)
    if context != value.context or (
        context is not None and context.policy_sha256 != preparation.policy_sha256
    ):
        raise CoverageModelDependencyRepairRequired("coverage dependency verifier context changed")
    if checked_cache.get(key) == before:
        return True
    result = await restore_coverage_model_dependencies(preparation, raw)
    after = await run_owned_thread(model_metadata_seal, value)
    if after != before:
        raise CoverageModelDependencyRepairRequired("coverage dependencies changed during refresh")
    if result:
        checked_cache[key] = after
    return result
