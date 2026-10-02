"""Independent, bounded review of owner-bound model objects stored in R2."""

from __future__ import annotations

import hashlib
import os
import shutil
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_direct_model_upload import direct_model_object_key
from .competition_cohort_model_acceptance import ModelArtifactReviewInputs, ModelReviewRequest
from .competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review_from_documents,
    verify_standing_review_policy,
)
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, Hotkey, digest, identity, validate_bundle_policy
from .private_files import Directory, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_limits import R2_MAXIMUM_MULTIPART_BYTES
from .r2_multipart import MAXIMUM_RANGE_BYTES, R2MultipartClient
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

    schema_: Literal["umi-direct-model-materialization/1"] = Field(alias="schema")
    review_request_sha256: Hex32
    model_sha256: Hex32
    payload_sha256: Hex32
    total_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_MULTIPART_BYTES)]


class DirectModelArtifactReviewer:
    """Verify all object bytes and derive review inputs without persistent model storage."""

    def __init__(
        self,
        config: DirectModelReviewSourceConfig,
        policy: CompetitionPolicy,
        owner_hotkey: Hotkey,
        *,
        multipart: R2MultipartClient | None = None,
    ) -> None:
        self.config = DirectModelReviewSourceConfig.model_validate_json(
            canonical_json_bytes(config)
        )
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.owner_hotkey = owner_hotkey
        if identity(owner_hotkey) not in {identity(e.hotkey) for e in self.policy.evaluators}:
            raise ValueError("direct model owner is outside policy")
        verify_standing_review_policy(self.config.standing_review_policy, self.policy)
        if multipart is None:
            loaded = load_r2_credentials(Path(self.config.r2_credentials_file))
            multipart = R2MultipartClient(
                R2SigV4(loaded.endpoint, self.config.r2_bucket, loaded.credentials),
                timeout_seconds=self.config.r2_timeout_seconds,
            )
        self.multipart = multipart

    def _source(self, request: ModelReviewRequest):
        request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
        signed = request.direct_artifact
        if signed is None:
            raise ValueError("direct model review requires an owner-signed artifact")
        body, submission = signed.reservation, request.record.request.signed_submission.submission
        bundle = submission.model_bundle
        if bundle is None or submission.track != "model":
            raise ValueError("direct model review requires a complete model bundle")
        payload = body.payload
        if (
            identity(signed.signature.hotkey) != identity(self.owner_hotkey)
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
        return bundle, payload, object_key

    async def review(self, request: ModelReviewRequest) -> ModelArtifactReviewInputs:
        bundle, payload, object_key = self._source(request)
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
        return build_standing_model_review_from_documents(bundle, self.policy, standing, documents)

    async def materialize(self, request: ModelReviewRequest, archive: Path) -> Path:
        """Create one verified bounded cache archive and never reuse partial bytes."""

        request = ModelReviewRequest.model_validate_json(canonical_json_bytes(request))
        bundle, payload, object_key = self._source(request)
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
                schema="umi-direct-model-materialization/1",
                review_request_sha256=digest(request),
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
        bundle, payload, _ = self._source(request)
        expected = DirectModelMaterialization(
            schema="umi-direct-model-materialization/1",
            review_request_sha256=digest(request),
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
