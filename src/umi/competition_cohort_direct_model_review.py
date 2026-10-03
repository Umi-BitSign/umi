"""Independent, bounded review of owner-bound model objects stored in R2."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_direct_model_upload import (
    direct_model_object_key,
    preserved_model_object_key,
)
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelArtifactReviewInputs,
    ModelReviewRequest,
)
from .competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review_from_documents,
    verify_standing_review_policy,
)
from .competition_cohort_roster import RecoverableRosterParticipant
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, Hotkey, digest, identity, validate_bundle_policy
from .private_files import (
    Directory,
    ensure_private_directory,
    private_path,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_limits import R2_MAXIMUM_MULTIPART_BYTES
from .r2_multipart import MAXIMUM_RANGE_BYTES, R2MultipartClient, R2ObjectHead
from .r2_sigv4 import R2SigV4, load_r2_credentials


class DirectModelReviewSourceConfig(StrictProtocolModel):
    """Read-only R2 source and the exact standing review selected before intake."""

    schema_: Literal["umi-direct-model-review-source/1"] = Field(alias="schema")
    r2_credentials_file: Directory
    r2_bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    standing_review_policy: StandingModelReviewPolicy
    r2_timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60
    maximum_materialized_bytes: Annotated[int, Field(ge=1024**2, le=R2_MAXIMUM_MULTIPART_BYTES)] = (
        64 * 1024**3
    )
    materialization_free_space_reserve_bytes: Annotated[int, Field(ge=64 * 1024**2, le=1024**4)] = (
        2 * 1024**3
    )
    materialization_concurrency: Literal[1] = 1

    def stores(self) -> tuple[Path, ...]:
        return (Path(self.r2_credentials_file),)


class DirectModelMaterialization(StrictProtocolModel):
    """Private completion marker written only after full local verification."""

    schema_: Literal["umi-direct-model-materialization/2"] = Field(alias="schema")
    review_request_sha256: Hex32
    source_object_key_sha256: Hex32
    model_sha256: Hex32
    payload_sha256: Hex32
    total_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_MULTIPART_BYTES)]


class DirectModelSettlementVerification(StrictProtocolModel):
    """Private proof that one settlement signer reread the accepted R2 object."""

    schema_: Literal["umi-direct-model-settlement-verification/2"] = Field(alias="schema")
    review_request_sha256: Hex32
    acceptance_sha256: Hex32
    source_object_key_sha256: Hex32
    model_sha256: Hex32
    payload_sha256: Hex32
    total_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_MULTIPART_BYTES)]
    provider_etag: Annotated[str, Field(min_length=1, max_length=256)]


class DirectModelArtifactReviewer:
    """Verify all object bytes and derive review inputs without persistent model storage."""

    def __init__(
        self,
        config: DirectModelReviewSourceConfig,
        policy: CompetitionPolicy,
        owner_hotkey: Hotkey | None,
        *,
        multipart: R2MultipartClient | None = None,
    ) -> None:
        self.config = DirectModelReviewSourceConfig.model_validate_json(
            canonical_json_bytes(config)
        )
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.owner_hotkey = owner_hotkey
        if owner_hotkey is not None and identity(owner_hotkey) not in {
            identity(e.hotkey) for e in self.policy.evaluators
        }:
            raise ValueError("direct model owner is outside policy")
        verify_standing_review_policy(self.config.standing_review_policy, self.policy)
        if multipart is None:
            loaded = load_r2_credentials(Path(self.config.r2_credentials_file))
            multipart = R2MultipartClient(
                R2SigV4(loaded.endpoint, self.config.r2_bucket, loaded.credentials),
                timeout_seconds=self.config.r2_timeout_seconds,
            )
        self.multipart = multipart

    def _source(self, request: ModelReviewRequest, *, preserved: bool = False):
        request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
        signed = request.direct_artifact
        if signed is None:
            raise ValueError("direct model review requires an owner-signed artifact")
        body, submission = signed.reservation, request.record.request.signed_submission.submission
        bundle = submission.model_bundle
        if bundle is None or submission.track != "model":
            raise ValueError("direct model review requires a complete model bundle")
        payload = body.payload
        signer = identity(signed.signature.hotkey)
        expected_owner = None if self.owner_hotkey is None else identity(self.owner_hotkey)
        if (
            (expected_owner is not None and signer != expected_owner)
            or (
                expected_owner is None
                and (
                    signer not in {identity(e.hotkey) for e in self.policy.evaluators}
                    or signer == identity(submission.hotkey)
                )
            )
            or body.cohort_sha256 != request.acceptance.cohort_sha256
            or body.cohort_sha256 != request.record.request.consent.consent.cohort_sha256
            or identity(body.hotkey) != identity(submission.hotkey)
            or payload.upload_sha256 != digest(request.record.request)
            or payload.model_sha256 != digest(bundle)
            or payload.model_sha256 != request.acceptance.model_sha256
            or payload.total_bytes != sum(record.size_bytes for record in bundle.files)
            or payload.file_count != len(bundle.files)
        ):
            raise ValueError("direct model review artifact differs from its request")
        validate_bundle_policy(bundle, self.policy)
        object_key = direct_model_object_key(
            body.cohort_sha256, payload.upload_sha256, body.attempt_id
        )
        if body.object_key_sha256 != sha256_hex(object_key.encode()):
            raise ValueError("direct model review object binding differs")
        if preserved:
            object_key = preserved_model_object_key(
                body.cohort_sha256, payload.model_sha256, payload.payload_sha256
            )
        return bundle, payload, object_key

    async def verify(
        self, request: ModelReviewRequest, *, preserved: bool = False
    ) -> tuple[ModelArtifactReviewInputs, R2ObjectHead]:
        """Reread and authenticate one exact artifact without retaining its payload."""

        bundle, payload, object_key = self._source(request, preserved=preserved)
        head = await self.multipart.head(object_key)
        if head is None or head.size_bytes != payload.total_bytes:
            raise OSError("direct model review object is unavailable")

        stream_hash = hashlib.sha256()
        documents: dict[str, bytes] = {}
        offset = 0
        standing = self.config.standing_review_policy
        for record in bundle.files:
            if record.role in {"license", "provenance"} and not (
                1 <= record.size_bytes <= standing.maximum_document_bytes
            ):
                raise StaticModelReviewHeld("review_document_size_outside_policy")
            file_hash = hashlib.sha256()
            remaining = record.size_bytes
            document = bytearray() if record.role in {"license", "provenance"} else None
            while remaining:
                size = min(remaining, MAXIMUM_RANGE_BYTES)
                data = await self.multipart.read_range(object_key, offset=offset, size_bytes=size)
                if len(data) != size:
                    raise ValueError("direct model review range differs")
                stream_hash.update(data)
                file_hash.update(data)
                if document is not None:
                    document.extend(data)
                offset += size
                remaining -= size
            if file_hash.hexdigest() != record.sha256:
                raise ValueError("direct model review file differs from its manifest")
            if document is not None:
                documents[record.path] = bytes(document)
                document[:] = b"\x00" * len(document)
        if offset != payload.total_bytes or stream_hash.hexdigest() != payload.payload_sha256:
            raise ValueError("direct model review payload digest differs")
        if await self.multipart.head(object_key) != head:
            raise ValueError("direct model review object changed while reading")
        return (
            build_standing_model_review_from_documents(bundle, self.policy, standing, documents),
            head,
        )

    async def review(self, request: ModelReviewRequest) -> ModelArtifactReviewInputs:
        inputs, _ = await self.verify(request)
        return inputs

    async def materialize(self, request: ModelReviewRequest, archive: Path) -> Path:
        """Create one verified bounded cache archive and never reuse partial bytes."""

        request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
        bundle, payload, object_key = self._source(request, preserved=True)
        if payload.total_bytes > self.config.maximum_materialized_bytes:
            raise ValueError("direct model exceeds evaluator materialization capacity")
        head = await self.multipart.head(object_key)
        if head is None or head.size_bytes != payload.total_bytes:
            raise OSError("direct model materialization object is unavailable")
        archive = Path(archive)
        if not archive.is_absolute() or archive.exists() or archive.is_symlink():
            raise ValueError("direct model scratch archive differs")
        archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        required = payload.total_bytes + self.config.materialization_free_space_reserve_bytes
        if shutil.disk_usage(archive.parent).free < required:
            raise OSError("direct model scratch capacity is unavailable")
        archive.mkdir(mode=0o700, parents=True)
        target = archive / digest(bundle)
        model = target / "model"
        model.mkdir(mode=0o700, parents=True)
        offset = 0
        stream_hash = hashlib.sha256()
        try:
            for record in bundle.files:
                destination = model / record.path
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                file_hash = hashlib.sha256()
                remaining = record.size_bytes
                with destination.open("xb") as output:
                    while remaining:
                        size = min(remaining, MAXIMUM_RANGE_BYTES)
                        data = await self.multipart.read_range(
                            object_key, offset=offset, size_bytes=size
                        )
                        if len(data) != size:
                            raise ValueError("direct model materialization range differs")
                        written = await run_owned_thread(output.write, data)
                        if written != len(data):
                            raise OSError("direct model materialization write was incomplete")
                        stream_hash.update(data)
                        file_hash.update(data)
                        offset += size
                        remaining -= size
                    await run_owned_thread(output.flush)
                    await run_owned_thread(os.fsync, output.fileno())
                destination.chmod(0o400)
                if file_hash.hexdigest() != record.sha256:
                    raise ValueError("materialized model file differs from its manifest")
            manifest = target / "manifest.json"
            with manifest.open("xb") as output:
                output.write(canonical_json_bytes(bundle))
                output.flush()
                os.fsync(output.fileno())
            manifest.chmod(0o400)
            if offset != payload.total_bytes or stream_hash.hexdigest() != payload.payload_sha256:
                raise ValueError("materialized model payload differs")
            if await self.multipart.head(object_key) != head:
                raise ValueError("direct model object changed during materialization")
            await run_owned_thread(verify_preserved_bundle, bundle, archive, self.policy)
            marker = DirectModelMaterialization(
                schema="umi-direct-model-materialization/2",
                review_request_sha256=digest(request),
                source_object_key_sha256=sha256_hex(object_key.encode()),
                model_sha256=digest(bundle),
                payload_sha256=payload.payload_sha256,
                total_bytes=payload.total_bytes,
            )
            await run_owned_thread(publish_private_model, archive / "materialization.json", marker)
            return target
        except BaseException:
            await run_owned_thread(partial(shutil.rmtree, archive, ignore_errors=True))
            raise

    async def materialized(self, request: ModelReviewRequest, archive: Path) -> bool:
        """Authenticate a retained cache once after restart before reusing it."""

        request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
        bundle, payload, object_key = self._source(request, preserved=True)
        expected = DirectModelMaterialization(
            schema="umi-direct-model-materialization/2",
            review_request_sha256=digest(request),
            source_object_key_sha256=sha256_hex(object_key.encode()),
            model_sha256=digest(bundle),
            payload_sha256=payload.payload_sha256,
            total_bytes=payload.total_bytes,
        )
        try:
            retained = await run_owned_thread(
                read_private_model,
                Path(archive) / "materialization.json",
                DirectModelMaterialization,
            )
            if retained != expected:
                return False
            await run_owned_thread(verify_preserved_bundle, bundle, Path(archive), self.policy)
            return True
        except (FileNotFoundError, OSError, ValueError):
            return False


class DirectModelSettlementVerifier:
    """Verify direct artifacts once per settlement signer and replay bounded receipts."""

    def __init__(
        self,
        artifacts: DirectModelArtifactReviewer,
        archive: Path,
        receipts: Path,
    ) -> None:
        self.artifacts = artifacts
        self.archive, self.receipts = Path(archive), Path(receipts)
        self.serial = asyncio.Lock()
        private_path(str(self.archive))
        ensure_private_directory(self.receipts)
        if (
            self.archive == self.receipts
            or self.archive in self.receipts.parents
            or self.receipts in self.archive.parents
        ):
            raise ValueError("direct settlement receipts and legacy archive must be disjoint")

    @staticmethod
    def _request(
        participant: RecoverableRosterParticipant,
        certificate: CertifiedModelArtifactAcceptance,
    ) -> ModelReviewRequest | None:
        acceptance = certificate.acceptance
        artifact = acceptance.direct_artifact
        if artifact is None:
            return None
        return ModelReviewRequest(
            schema="umi-cohort-model-review-request/2",
            acceptance=acceptance,
            record=participant.record,
            admission=participant.admission,
            direct_artifact=artifact,
        )

    def _path(self, certificate: CertifiedModelArtifactAcceptance) -> Path:
        acceptance = certificate.acceptance
        return self.receipts / acceptance.cohort_sha256 / (acceptance.submission_sha256 + ".json")

    def _receipt(
        self,
        request: ModelReviewRequest,
        certificate: CertifiedModelArtifactAcceptance,
        head: R2ObjectHead,
    ) -> DirectModelSettlementVerification:
        payload = request.direct_artifact.reservation.payload
        _, _, object_key = self.artifacts._source(request, preserved=True)
        return DirectModelSettlementVerification(
            schema="umi-direct-model-settlement-verification/2",
            review_request_sha256=digest(request),
            acceptance_sha256=digest(certificate),
            source_object_key_sha256=sha256_hex(object_key.encode()),
            model_sha256=payload.model_sha256,
            payload_sha256=payload.payload_sha256,
            total_bytes=payload.total_bytes,
            provider_etag=head.etag,
        )

    async def ensure(
        self,
        participant: RecoverableRosterParticipant,
        certificate: CertifiedModelArtifactAcceptance,
    ) -> None:
        async with self.serial:
            await self._ensure(participant, certificate)

    async def _ensure(
        self,
        participant: RecoverableRosterParticipant,
        certificate: CertifiedModelArtifactAcceptance,
    ) -> None:
        request = self._request(participant, certificate)
        if request is None:
            await run_owned_thread(
                verify_preserved_bundle,
                participant.record.request.signed_submission.submission.model_bundle,
                self.archive,
                self.artifacts.policy,
            )
            return
        bundle, payload, object_key = self.artifacts._source(request, preserved=True)
        path = self._path(certificate)
        try:
            retained = await run_owned_thread(
                read_private_model,
                path,
                DirectModelSettlementVerification,
            )
            head = await self.artifacts.multipart.head(object_key)
            if head is None or retained != self._receipt(request, certificate, head):
                raise ValueError("direct settlement artifact changed after verification")
            return
        except FileNotFoundError:
            pass
        inputs, head = await self.artifacts.verify(request, preserved=True)
        acceptance = certificate.acceptance
        if (
            digest(bundle) != acceptance.model_sha256
            or payload.model_sha256 != acceptance.model_sha256
            or digest(inputs.rights_evidence) != acceptance.rights_evidence_sha256
            or digest(inputs.reconstruction_evidence) != acceptance.reconstruction_evidence_sha256
        ):
            raise ValueError("direct settlement review differs from certified acceptance")
        await run_owned_thread(
            publish_private_model,
            path,
            self._receipt(request, certificate, head),
        )

    async def ensure_all(
        self,
        participants: tuple[RecoverableRosterParticipant, ...],
        certificates: tuple[CertifiedModelArtifactAcceptance, ...],
    ) -> None:
        async with self.serial:
            submissions = tuple(
                digest(participant.record.request.signed_submission.submission)
                for participant in participants
            )
            if submissions != tuple(
                certificate.acceptance.submission_sha256 for certificate in certificates
            ):
                raise ValueError("direct settlement acceptances differ from the model roster")
            for participant, certificate in zip(participants, certificates, strict=True):
                await self._ensure(participant, certificate)

    def verify_candidate(
        self,
        certificate: CertifiedModelArtifactAcceptance,
        participant: RecoverableRosterParticipant,
    ) -> None:
        request = self._request(participant, certificate)
        if request is None:
            verify_preserved_bundle(
                participant.record.request.signed_submission.submission.model_bundle,
                self.archive,
                self.artifacts.policy,
            )
            return
        receipt = read_private_model(
            self._path(certificate),
            DirectModelSettlementVerification,
        )
        payload = request.direct_artifact.reservation.payload
        if (
            receipt.review_request_sha256 != digest(request)
            or receipt.acceptance_sha256 != digest(certificate)
            or receipt.model_sha256 != payload.model_sha256
            or receipt.payload_sha256 != payload.payload_sha256
            or receipt.total_bytes != payload.total_bytes
        ):
            raise ValueError("direct settlement receipt differs from accepted artifact")
