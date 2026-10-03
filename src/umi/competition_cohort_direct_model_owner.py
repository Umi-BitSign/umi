"""Crash-safe ownership of direct multipart model uploads.

The public intake authorizes a request once. This owner then retains the exact
miner-signed payload declaration before creating an R2 multipart upload and
retains the provider identity before returning any bearer capability. Provider
IDs and presigned URLs stay private. A process death after provider completion
is reconciled by HEAD against the unique attempt key; independent content
verification remains required before model admission.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator
from typing_extensions import Self

from .competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadObject,
    DirectModelUploadPart,
    DirectModelUploadPartCapabilities,
    DirectModelUploadPartCapability,
    DirectModelUploadReservation,
    DirectModelUploadStatus,
    DirectModelUploadVerification,
    SignedDirectModelPayload,
    SignedDirectModelUploadCompletion,
    SignedDirectModelUploadPartRequest,
    SignedDirectModelUploadReservation,
    SignedDirectModelUploadRestartRequest,
    direct_model_object_key,
    preserved_model_object_key,
    require_part_request_signer,
    require_restart_request_signer,
)
from .competition_cohort_model_acceptance import (
    ModelAcceptancePublication,
    ModelArtifactReviewInputs,
)
from .competition_cohort_model_acceptance_store import MAX_PUBLICATION_BYTES
from .competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review_from_documents,
    verify_standing_review_policy,
)
from .competition_cohort_participation import CohortParticipationRequest
from .competition_cohort_recovery import ModelDeliveryProfile
from .competition_round_journal import RoundJournal
from .open_competition import CompetitionPolicy, Hotkey, Signature, digest, identity
from .private_files import (
    Directory,
    ensure_private_directory,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_multipart import MAXIMUM_RANGE_BYTES, R2MultipartClient, R2ObjectHead


class DirectModelUploadPending(OSError):
    """A retained attempt is still inside its crash-recovery lease."""


class DirectModelUploadOwnerConfig(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-owner-config/1"] = Field(alias="schema")
    directory: Directory
    cohort_sha256: Hex32
    owner_hotkey: Hotkey
    delivery: ModelDeliveryProfile
    maximum_uploads: Annotated[int, Field(ge=1, le=4096)] = 1024
    maximum_attempts_per_upload: Annotated[int, Field(ge=2, le=64)] = 16
    maximum_metadata_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)] = 1024**3
    attempt_lease_seconds: Annotated[int, Field(ge=30, le=900)] = 120
    verification_batch_size: Annotated[int, Field(ge=1, le=16)] = 2
    rejected_object_retention_seconds: Annotated[int, Field(ge=300, le=30 * 24 * 60 * 60)] = (
        7 * 24 * 60 * 60
    )
    cleanup_batch_size: Annotated[int, Field(ge=1, le=16)] = 2
    admission_reviews_directory: Directory | None = None
    standing_review_policy: StandingModelReviewPolicy | None = None

    @model_serializer(mode="wrap")
    def omit_disabled_review(self, handler):
        value = handler(self)
        if self.admission_reviews_directory is None:
            value.pop("admission_reviews_directory", None)
        if self.standing_review_policy is None:
            value.pop("standing_review_policy", None)
        return value

    @model_validator(mode="after")
    def direct_delivery(self) -> Self:
        if self.delivery.mechanism != "direct_r2_multipart_v1":
            raise ValueError("direct upload owner requires the direct R2 delivery profile")
        if (self.admission_reviews_directory is None) != (self.standing_review_policy is None):
            raise ValueError("direct upload review directory and standing policy are inseparable")
        return self


class _DirectModelUploadIntent(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-intent/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    upload_sha256: Hex32
    payload_declaration_sha256: Hex32
    attempt_id: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    object_key: Annotated[str, Field(min_length=1, max_length=1024)]
    created_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    retry_after_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.retry_after_unix_ms <= self.created_at_unix_ms:
            raise ValueError("direct upload attempt lease differs")
        return self


class _DirectModelProviderUpload(StrictProtocolModel):
    schema_: Literal["umi-direct-model-provider-upload/1"] = Field(alias="schema")
    intent_sha256: Hex32
    provider_upload_id: Annotated[str, Field(min_length=1, max_length=2048)]


class _DirectModelReservationIndex(StrictProtocolModel):
    schema_: Literal["umi-direct-model-reservation-index/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    attempt_id: Hex32


class _DirectModelAttemptIndex(StrictProtocolModel):
    schema_: Literal["umi-direct-model-attempt-index/1"] = Field(alias="schema")
    upload_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    attempt_id: Hex32


class DirectModelPromotion(StrictProtocolModel):
    """Private proof that an accepted object reached immutable R2 storage."""

    schema_: Literal["umi-direct-model-promotion/1"] = Field(alias="schema")
    acceptance_sha256: Hex32
    reservation_sha256: Hex32
    source_object_key_sha256: Hex32
    preserved_object_key_sha256: Hex32
    model_sha256: Hex32
    payload_sha256: Hex32
    total_bytes: Annotated[int, Field(ge=1)]
    provider_etag: Annotated[str, Field(min_length=1, max_length=256)]
    promoted_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]


class _DirectModelRejectedCleanupIntent(StrictProtocolModel):
    schema_: Literal["umi-direct-model-rejected-cleanup-intent/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    object_key_sha256: Hex32
    provider_etag: Annotated[str, Field(min_length=1, max_length=256)]
    total_bytes: Annotated[int, Field(ge=1)]
    reason_code: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_]*$")
    ]
    created_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    retain_until_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.retain_until_unix_ms <= self.created_at_unix_ms:
            raise ValueError("rejected object retention interval differs")
        return self


class _DirectModelRejectedCleanupReceipt(StrictProtocolModel):
    schema_: Literal["umi-direct-model-rejected-cleanup-receipt/1"] = Field(alias="schema")
    intent_sha256: Hex32
    reservation_sha256: Hex32
    object_key_sha256: Hex32
    deleted_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]


Authorize = Callable[[CohortParticipationRequest], Awaitable[None]]
Sign = Callable[[StrictProtocolModel], Awaitable[Signature]]
AttemptId = Callable[[], str]


def _at(unix_ms: int) -> datetime:
    if type(unix_ms) is not int or not 0 <= unix_ms <= 2**63 - 1:
        raise ValueError("direct upload time differs")
    return datetime.fromtimestamp(unix_ms / 1000, tz=timezone.utc)


def _attempt_index_key(upload_sha256: str, generation: int) -> str:
    return sha256_hex(f"umi-direct-model-attempt-index/1:{upload_sha256}:{generation}".encode())


class DirectModelUploadOwner:
    """Single-service owner for retained direct R2 multipart attempts."""

    def __init__(
        self,
        config: DirectModelUploadOwnerConfig,
        multipart: R2MultipartClient,
        *,
        authorize: Authorize,
        sign: Sign,
        policy: CompetitionPolicy | None = None,
        new_attempt_id: AttemptId | None = None,
    ) -> None:
        self.config = DirectModelUploadOwnerConfig.model_validate_json(canonical_json_bytes(config))
        if not callable(authorize) or not callable(sign):
            raise ValueError("direct upload owner requires authorization and signing")
        self.multipart, self.authorize, self.sign = multipart, authorize, sign
        self.policy = policy
        self.new_attempt_id = new_attempt_id or (lambda: secrets.token_hex(32))
        self._mutex = asyncio.Lock()
        self._verification_mutex = asyncio.Lock()
        self._promotion_mutex = asyncio.Lock()
        c = self.config
        roots = [Path(c.directory)]
        if c.admission_reviews_directory is not None:
            roots.append(Path(c.admission_reviews_directory))
        if any(
            a == b or a in b.parents or b in a.parents
            for index, a in enumerate(roots)
            for b in roots[index + 1 :]
        ):
            raise ValueError("direct upload and review stores must be disjoint")
        for root in roots:
            ensure_private_directory(root)
        if c.standing_review_policy is not None:
            if policy is None:
                raise ValueError("direct upload standing review requires its competition policy")
            verify_standing_review_policy(c.standing_review_policy, policy)
        self.journal = RoundJournal(
            Path(c.directory) / "journal",
            {
                "schema": "umi-direct-model-upload-owner-binding/1",
                "cohort_sha256": c.cohort_sha256,
                "owner_hotkey": c.owner_hotkey,
                "delivery": c.delivery.model_dump(mode="json", by_alias=True),
                "r2_endpoint": multipart.signer.endpoint,
                "r2_bucket": multipart.signer.bucket,
                "standing_review_policy_sha256": (
                    None if c.standing_review_policy is None else digest(c.standing_review_policy)
                ),
            },
            maximum_rounds=min(65536, c.maximum_uploads * c.maximum_attempts_per_upload),
            maximum_bytes=c.maximum_metadata_bytes,
        )

    def _request(self, request: CohortParticipationRequest) -> tuple[str, object]:
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        key, submission = digest(request), request.signed_submission.submission
        if (
            request.consent.consent.cohort_sha256 != self.config.cohort_sha256
            or submission.track != "model"
            or submission.model_bundle is None
        ):
            raise ValueError("direct upload requires this cohort's model request")
        return key, submission

    def _payload(
        self,
        request: CohortParticipationRequest,
        signed: SignedDirectModelPayload,
    ) -> tuple[str, DirectModelPayload]:
        key, submission = self._request(request)
        signed = SignedDirectModelPayload.model_validate_json(canonical_json_bytes(signed))
        payload, bundle = signed.payload, submission.model_bundle
        part_size = self.config.delivery.part_size_bytes
        if part_size is None:
            raise ValueError("direct upload profile has no part size")
        if (
            identity(signed.signature.hotkey) != identity(submission.hotkey)
            or payload.upload_sha256 != key
            or payload.model_sha256 != digest(bundle)
            or payload.model_sha256 != submission.model_revision
            or payload.total_bytes != sum(record.size_bytes for record in bundle.files)
            or payload.file_count != len(bundle.files)
            or payload.part_size_bytes != part_size
        ):
            raise ValueError("direct model payload differs from its signed request")
        return key, payload

    def _attempts(self, upload_sha256: str) -> list[_DirectModelUploadIntent]:
        values = []
        for generation in range(1, self.config.maximum_attempts_per_upload + 1):
            index_key = _attempt_index_key(upload_sha256, generation)
            raw_index = self.journal.get("direct-attempt-index", index_key)
            if raw_index is None:
                continue
            index = _DirectModelAttemptIndex.model_validate_json(canonical_json_bytes(raw_index))
            if index.upload_sha256 != upload_sha256 or index.generation != generation:
                raise ValueError("direct upload attempt index changed")
            raw = self.journal.get("direct-intent", index.attempt_id)
            if raw is None:
                raise ValueError("direct upload attempt index is incomplete")
            intent = _DirectModelUploadIntent.model_validate_json(canonical_json_bytes(raw))
            if (
                intent.attempt_id != index.attempt_id
                or intent.upload_sha256 != upload_sha256
                or intent.generation != generation
            ):
                raise ValueError("direct upload attempt identity changed")
            values.append(intent)
        if any(a.generation == b.generation for a, b in pairwise(values)):
            raise ValueError("direct upload attempt generation repeated")
        return values

    def _signed_reservation(
        self, attempt: _DirectModelUploadIntent
    ) -> SignedDirectModelUploadReservation | None:
        raw = self.journal.get("direct-reservation", attempt.attempt_id)
        if raw is None:
            return None
        signed = SignedDirectModelUploadReservation.model_validate_json(canonical_json_bytes(raw))
        if (
            signed.reservation.attempt_id != attempt.attempt_id
            or signed.reservation.generation != attempt.generation
            or identity(signed.signature.hotkey) != identity(self.config.owner_hotkey)
        ):
            raise ValueError("retained direct upload reservation changed")
        return signed

    def _provider(self, attempt: _DirectModelUploadIntent) -> _DirectModelProviderUpload | None:
        raw = self.journal.get("direct-provider", attempt.attempt_id)
        if raw is None:
            return None
        provider = _DirectModelProviderUpload.model_validate_json(canonical_json_bytes(raw))
        if provider.intent_sha256 != digest(attempt):
            raise ValueError("retained provider upload changed")
        return provider

    async def _finish_reservation(
        self,
        attempt: _DirectModelUploadIntent,
        signed_payload: SignedDirectModelPayload,
        provider: _DirectModelProviderUpload,
    ) -> SignedDirectModelUploadReservation:
        body_raw = self.journal.get("direct-reservation-body", attempt.attempt_id)
        if body_raw is None:
            body = DirectModelUploadReservation(
                schema="umi-direct-model-upload-reservation/1",
                cohort_sha256=attempt.cohort_sha256,
                hotkey=signed_payload.signature.hotkey,
                payload=signed_payload.payload,
                attempt_id=attempt.attempt_id,
                generation=attempt.generation,
                object_key_sha256=sha256_hex(attempt.object_key.encode()),
                provider_upload_id_sha256=sha256_hex(provider.provider_upload_id.encode()),
                created_at_unix_ms=attempt.created_at_unix_ms,
            )
            self.journal.put("direct-reservation-body", attempt.attempt_id, body)
        else:
            body = DirectModelUploadReservation.model_validate_json(canonical_json_bytes(body_raw))
        signature = await self.sign(body)
        if identity(signature.hotkey) != identity(self.config.owner_hotkey):
            raise ValueError("direct upload reservation signer differs")
        signed = SignedDirectModelUploadReservation(
            schema="umi-signed-direct-model-upload-reservation/1",
            reservation=body,
            signature=signature,
        )
        with self.journal.locked():
            prior = self._signed_reservation(attempt)
            if prior is not None:
                index = self.journal.get("direct-reservation-index", digest(prior.reservation))
                if index is None:
                    raise ValueError("retained direct upload reservation lacks its index")
                return prior
            reservation_sha256 = digest(body)
            self.journal.put_many(
                (
                    ("direct-reservation", attempt.attempt_id, signed),
                    (
                        "direct-reservation-index",
                        reservation_sha256,
                        _DirectModelReservationIndex(
                            schema="umi-direct-model-reservation-index/1",
                            reservation_sha256=reservation_sha256,
                            attempt_id=attempt.attempt_id,
                        ),
                    ),
                )
            )
        return signed

    async def reserve(
        self,
        request: CohortParticipationRequest,
        signed_payload: SignedDirectModelPayload,
        *,
        now_unix_ms: int,
    ) -> SignedDirectModelUploadReservation:
        """Authorize once, then create or recover one multipart reservation."""

        _at(now_unix_ms)
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        signed_payload = SignedDirectModelPayload.model_validate_json(
            canonical_json_bytes(signed_payload)
        )
        upload_sha256, _ = self._payload(request, signed_payload)
        async with self._mutex:
            retained_request = self.journal.get("direct-request", upload_sha256)
            if retained_request is None:
                if len(self.journal.keys("direct-request")) >= self.config.maximum_uploads:
                    raise OSError("direct model upload capacity exhausted")
                await self.authorize(request)
                with self.journal.locked():
                    prior = self.journal.get("direct-request", upload_sha256)
                    if prior is None:
                        self.journal.put_many(
                            (
                                ("direct-request", upload_sha256, request),
                                ("direct-payload", upload_sha256, signed_payload),
                            )
                        )
                    elif prior != request.model_dump(mode="json", by_alias=True):
                        raise ValueError("direct upload request retry differs")
            elif retained_request != request.model_dump(mode="json", by_alias=True):
                raise ValueError("direct upload request retry differs")
            retained_payload = self.journal.get("direct-payload", upload_sha256)
            if retained_payload is None:
                raise ValueError("direct upload retained payload is unavailable")
            retained_signed_payload = SignedDirectModelPayload.model_validate_json(
                canonical_json_bytes(retained_payload)
            )
            if retained_signed_payload.payload != signed_payload.payload or identity(
                retained_signed_payload.signature.hotkey
            ) != identity(signed_payload.signature.hotkey):
                raise ValueError("direct upload payload retry differs")

            attempts = self._attempts(upload_sha256)
            if attempts:
                current = attempts[-1]
                signed = self._signed_reservation(current)
                superseded = (
                    signed is not None
                    and self.journal.get("direct-superseded", digest(signed.reservation))
                    is not None
                )
                if signed is not None and not superseded:
                    reservation_sha256 = digest(signed.reservation)
                    completion_raw = self.journal.get("direct-completion", reservation_sha256)
                    if (
                        completion_raw is not None
                        and self.journal.get("direct-object", reservation_sha256) is None
                    ):
                        completion = SignedDirectModelUploadCompletion.model_validate_json(
                            canonical_json_bytes(completion_raw)
                        )
                        _, retained, attempt, _ = self._completion(completion)
                        if retained != signed:
                            raise ValueError("direct upload completion changed its reservation")
                        head = await self.multipart.head(attempt.object_key, at=_at(now_unix_ms))
                        if head is not None:
                            if head.size_bytes != signed.reservation.payload.total_bytes:
                                raise ValueError("completed direct upload object size differs")
                            self.journal.put(
                                "direct-object",
                                reservation_sha256,
                                DirectModelUploadObject(
                                    schema="umi-direct-model-upload-object/1",
                                    reservation_sha256=reservation_sha256,
                                    generation=signed.reservation.generation,
                                    object_key_sha256=sha256_hex(attempt.object_key.encode()),
                                    provider_etag=head.etag,
                                    completed_at_unix_ms=now_unix_ms,
                                ),
                            )
                    return signed
                provider = self._provider(current)
                if provider is not None and not superseded:
                    return await self._finish_reservation(current, signed_payload, provider)
                if signed is None and now_unix_ms < current.retry_after_unix_ms:
                    raise DirectModelUploadPending("direct upload creation is pending")
            if len(attempts) >= self.config.maximum_attempts_per_upload:
                raise OSError("direct upload attempt capacity exhausted")

            generation = 1 if not attempts else attempts[-1].generation + 1
            attempt_id = self.new_attempt_id()
            if (
                type(attempt_id) is not str
                or len(attempt_id) != 64
                or any(character not in "0123456789abcdef" for character in attempt_id)
            ):
                raise ValueError("direct upload attempt generator differs")
            if self.journal.get("direct-intent", attempt_id) is not None:
                raise ValueError("direct upload attempt identity repeated")
            object_key = direct_model_object_key(
                self.config.cohort_sha256, upload_sha256, attempt_id
            )
            attempt = _DirectModelUploadIntent(
                schema="umi-direct-model-upload-intent/1",
                cohort_sha256=self.config.cohort_sha256,
                upload_sha256=upload_sha256,
                payload_declaration_sha256=digest(signed_payload.payload),
                attempt_id=attempt_id,
                generation=generation,
                object_key=object_key,
                created_at_unix_ms=now_unix_ms,
                retry_after_unix_ms=(now_unix_ms + self.config.attempt_lease_seconds * 1000),
            )
            attempt_index_key = _attempt_index_key(upload_sha256, generation)
            self.journal.put_many(
                (
                    ("direct-intent", attempt_id, attempt),
                    (
                        "direct-attempt-index",
                        attempt_index_key,
                        _DirectModelAttemptIndex(
                            schema="umi-direct-model-attempt-index/1",
                            upload_sha256=upload_sha256,
                            generation=generation,
                            attempt_id=attempt_id,
                        ),
                    ),
                )
            )
            provider_upload_id = await self.multipart.create(object_key, at=_at(now_unix_ms))
            provider = _DirectModelProviderUpload(
                schema="umi-direct-model-provider-upload/1",
                intent_sha256=digest(attempt),
                provider_upload_id=provider_upload_id,
            )
            self.journal.put("direct-provider", attempt_id, provider)
            return await self._finish_reservation(attempt, signed_payload, provider)

    async def restart(
        self,
        signed_restart: SignedDirectModelUploadRestartRequest,
        *,
        now_unix_ms: int,
    ) -> SignedDirectModelUploadReservation:
        """Fence one provider-expired generation and return its durable successor."""

        at = _at(now_unix_ms)
        signed_restart = SignedDirectModelUploadRestartRequest.model_validate_json(
            canonical_json_bytes(signed_restart)
        )
        request = signed_restart.request
        async with self._mutex:
            reservation = self._reservation_by_digest(request.reservation_sha256)
            require_restart_request_signer(signed_restart, reservation.reservation)
            body = reservation.reservation
            attempts = self._attempts(body.payload.upload_sha256)
            attempt_raw = self.journal.get("direct-intent", body.attempt_id)
            if attempt_raw is None:
                raise ValueError("direct upload restart attempt is unavailable")
            attempt = _DirectModelUploadIntent.model_validate_json(
                canonical_json_bytes(attempt_raw)
            )
            retained_restart = self.journal.get(
                "direct-restart-request", request.reservation_sha256
            )
            if retained_restart is not None and retained_restart != signed_restart.model_dump(
                mode="json", by_alias=True
            ):
                raise ValueError("direct upload restart retry differs")
            superseded = self.journal.get("direct-superseded", request.reservation_sha256)
            if superseded is None:
                if not attempts or attempts[-1] != attempt:
                    raise ValueError("direct upload restart reservation was superseded")
                if (
                    self.journal.get("direct-object", request.reservation_sha256) is not None
                    or self.journal.get("direct-completion", request.reservation_sha256) is not None
                ):
                    raise ValueError("completed direct upload cannot be restarted")
                if now_unix_ms < attempt.retry_after_unix_ms:
                    raise DirectModelUploadPending("direct upload restart lease is pending")
                provider = self._provider(attempt)
                if provider is None:
                    raise DirectModelUploadPending("direct upload provider is pending")
                if await self.multipart.multipart_exists(
                    attempt.object_key, upload_id=provider.provider_upload_id, at=at
                ):
                    raise DirectModelUploadPending(
                        "direct upload provider generation remains available"
                    )
                self.journal.put(
                    "direct-restart-request", request.reservation_sha256, signed_restart
                )
                await self.multipart.abort(
                    attempt.object_key, upload_id=provider.provider_upload_id, at=at
                )
                self.journal.put(
                    "direct-superseded",
                    request.reservation_sha256,
                    {
                        "reason_code": request.reason_code,
                        "superseded_at_unix_ms": now_unix_ms,
                    },
                )
            elif retained_restart is None:
                raise ValueError("direct upload supersession lacks its signed request")
            retained_request = self.journal.get("direct-request", body.payload.upload_sha256)
            retained_payload = self.journal.get("direct-payload", body.payload.upload_sha256)
            if retained_request is None or retained_payload is None:
                raise ValueError("direct upload restart inputs are unavailable")
            participation = CohortParticipationRequest.model_validate_json(
                canonical_json_bytes(retained_request)
            )
            payload = SignedDirectModelPayload.model_validate_json(
                canonical_json_bytes(retained_payload)
            )

        replacement = await self.reserve(participation, payload, now_unix_ms=now_unix_ms)
        if replacement.reservation.generation <= request.generation:
            raise ValueError("direct upload restart did not advance generation")
        return replacement

    def capabilities(
        self,
        signed: SignedDirectModelUploadReservation,
        part_numbers: tuple[int, ...],
        *,
        now_unix_ms: int,
    ) -> tuple[DirectModelUploadPartCapability, ...]:
        """Issue transient, exact-size part URLs without retaining bearer values."""

        at = _at(now_unix_ms)
        signed = SignedDirectModelUploadReservation.model_validate_json(
            canonical_json_bytes(signed)
        )
        reservation, payload = signed.reservation, signed.reservation.payload
        attempt_raw = self.journal.get("direct-intent", reservation.attempt_id)
        if attempt_raw is None:
            raise FileNotFoundError("direct upload reservation is not retained")
        attempt = _DirectModelUploadIntent.model_validate_json(canonical_json_bytes(attempt_raw))
        if self._signed_reservation(attempt) != signed:
            raise ValueError("direct upload reservation retry differs")
        if self.journal.get("direct-superseded", digest(reservation)) is not None:
            raise ValueError("direct upload reservation was superseded")
        attempts = self._attempts(payload.upload_sha256)
        if not attempts or attempts[-1] != attempt:
            raise ValueError("direct upload reservation was superseded")
        provider = self._provider(attempt)
        maximum = self.config.delivery.maximum_concurrent_parts
        ttl = self.config.delivery.capability_ttl_seconds
        if provider is None or maximum is None or ttl is None:
            raise ValueError("direct upload provider or profile is incomplete")
        if (
            not part_numbers
            or len(part_numbers) > maximum
            or len(set(part_numbers)) != len(part_numbers)
            or any(not 1 <= number <= payload.total_parts for number in part_numbers)
        ):
            raise ValueError("direct upload capability request differs")
        expires = now_unix_ms + ttl * 1000
        values = []
        for number in part_numbers:
            offset = (number - 1) * payload.part_size_bytes
            size = min(payload.part_size_bytes, payload.total_bytes - offset)
            values.append(
                DirectModelUploadPartCapability(
                    schema="umi-direct-model-upload-part-capability/1",
                    reservation_sha256=digest(reservation),
                    generation=reservation.generation,
                    part_number=number,
                    size_bytes=size,
                    expires_at_unix_ms=expires,
                    url=self.multipart.signer.upload_part_url(
                        attempt.object_key,
                        upload_id=provider.provider_upload_id,
                        part_number=number,
                        expires_seconds=ttl,
                        at=at,
                    ),
                )
            )
        return tuple(values)

    def issue_capabilities(
        self,
        request: SignedDirectModelUploadPartRequest,
        *,
        now_unix_ms: int,
    ) -> DirectModelUploadPartCapabilities:
        request = SignedDirectModelUploadPartRequest.model_validate_json(
            canonical_json_bytes(request)
        )
        reservation = self._reservation_by_digest(request.request.reservation_sha256)
        require_part_request_signer(request, reservation.reservation)
        values = self.capabilities(
            reservation, request.request.part_numbers, now_unix_ms=now_unix_ms
        )
        return DirectModelUploadPartCapabilities(
            schema="umi-direct-model-upload-part-capabilities/1",
            reservation_sha256=request.request.reservation_sha256,
            generation=request.request.generation,
            capabilities=values,
        )

    def status(self, reservation_sha256: str) -> DirectModelUploadStatus:
        reservation = self._reservation_by_digest(reservation_sha256)
        verification_raw = self.journal.get("direct-verification", reservation_sha256)
        verification = (
            None
            if verification_raw is None
            else DirectModelUploadVerification.model_validate_json(
                canonical_json_bytes(verification_raw)
            )
        )
        body = reservation.reservation
        verification_hold = self.journal.get("direct-verification-hold", reservation_sha256)
        review_hold = self.journal.get("direct-review-hold", body.payload.model_sha256)
        hold = verification_hold if verification_hold is not None else review_hold
        hold_reason_code = None if hold is None else hold.get("reason_code")
        return DirectModelUploadStatus(
            schema="umi-direct-model-upload-status/1",
            upload_sha256=body.payload.upload_sha256,
            model_sha256=body.payload.model_sha256,
            reservation=reservation,
            object_complete=self.journal.get("direct-object", reservation_sha256) is not None,
            payload_verified=verification is not None,
            verification=verification,
            hold_reason_code=hold_reason_code,
        )

    def require_payload(self, request: CohortParticipationRequest) -> None:
        """Require this exact request's current R2 object to be fully verified."""

        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        upload_sha256, submission = self._request(request)
        retained = self.journal.get("direct-request", upload_sha256)
        if retained != request.model_dump(mode="json", by_alias=True):
            raise DirectModelUploadPending("deliver and verify the complete model first")
        attempts = self._attempts(upload_sha256)
        if not attempts:
            raise DirectModelUploadPending("deliver and verify the complete model first")
        reservation = self._signed_reservation(attempts[-1])
        if reservation is None:
            raise DirectModelUploadPending("direct model reservation is incomplete")
        reservation_sha256 = digest(reservation.reservation)
        raw = self.journal.get("direct-verification", reservation_sha256)
        if raw is None:
            raise DirectModelUploadPending("direct model verification is incomplete")
        verification = DirectModelUploadVerification.model_validate_json(canonical_json_bytes(raw))
        if (
            verification.reservation_sha256 != reservation_sha256
            or verification.upload_sha256 != upload_sha256
            or verification.model_sha256 != submission.model_revision
        ):
            raise ValueError("direct model verification differs from its request")
        if self.config.admission_reviews_directory is not None:
            try:
                review = read_private_model(
                    Path(self.config.admission_reviews_directory)
                    / (submission.model_revision + ".json"),
                    ModelArtifactReviewInputs,
                    maximum_bytes=MAX_PUBLICATION_BYTES,
                )
            except FileNotFoundError as error:
                hold = self.journal.get("direct-review-hold", submission.model_revision)
                reason = (
                    ": " + hold["reason_code"]
                    if isinstance(hold, dict) and isinstance(hold.get("reason_code"), str)
                    else ""
                )
                raise DirectModelUploadPending(
                    "direct model awaits its bounded rights review" + reason
                ) from error
            if review.model_sha256 != submission.model_revision:
                raise ValueError("direct model review differs from its request")

    def review_artifact(
        self, request: CohortParticipationRequest
    ) -> SignedDirectModelUploadReservation:
        """Return the signed R2 binding only after every admission gate passes."""

        self.require_payload(request)
        upload_sha256, _ = self._request(request)
        attempts = self._attempts(upload_sha256)
        if not attempts:
            raise DirectModelUploadPending("direct model upload has no retained attempt")
        reservation = self._signed_reservation(attempts[-1])
        if reservation is None:
            raise DirectModelUploadPending("direct model upload reservation is pending")
        if self.journal.get("direct-verification", digest(reservation.reservation)) is None:
            raise DirectModelUploadPending("direct model verification is incomplete")
        return reservation

    async def review(
        self, reservation_sha256: str, *, now_unix_ms: int
    ) -> ModelArtifactReviewInputs | None:
        """Read only declared documents from R2 after full-object verification."""

        _at(now_unix_ms)
        standing = self.config.standing_review_policy
        reviews = self.config.admission_reviews_directory
        if standing is None or reviews is None:
            return None
        reservation = self._reservation_by_digest(reservation_sha256)
        payload = reservation.reservation.payload
        if self.journal.get("direct-verification", reservation_sha256) is None:
            raise DirectModelUploadPending("direct model verification is incomplete")
        request_raw = self.journal.get("direct-request", payload.upload_sha256)
        if request_raw is None:
            raise ValueError("direct model review request is unavailable")
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request_raw))
        _, submission = self._request(request)
        bundle = submission.model_bundle
        if bundle is None or digest(bundle) != payload.model_sha256:
            raise ValueError("direct model review bundle changed")
        target = Path(reviews) / (payload.model_sha256 + ".json")
        try:
            prior = read_private_model(
                target, ModelArtifactReviewInputs, maximum_bytes=MAX_PUBLICATION_BYTES
            )
            if prior.model_sha256 != payload.model_sha256:
                raise ValueError("direct model review changed")
            return prior
        except FileNotFoundError:
            pass
        attempt_raw = self.journal.get("direct-intent", reservation.reservation.attempt_id)
        if attempt_raw is None:
            raise ValueError("direct model review attempt is unavailable")
        attempt = _DirectModelUploadIntent.model_validate_json(canonical_json_bytes(attempt_raw))
        documents = {}
        offset = 0
        completed_raw = self.journal.get("direct-object", reservation_sha256)
        if completed_raw is None:
            raise DirectModelUploadPending("direct model review object is incomplete")
        completed = DirectModelUploadObject.model_validate_json(canonical_json_bytes(completed_raw))
        initial_head = await self.multipart.head(attempt.object_key)
        if (
            initial_head is None
            or initial_head.size_bytes != payload.total_bytes
            or initial_head.etag != completed.provider_etag
        ):
            raise ValueError("direct model review object metadata changed")
        try:
            for record in bundle.files:
                if record.role in {"license", "provenance"}:
                    if not 1 <= record.size_bytes <= standing.maximum_document_bytes:
                        raise StaticModelReviewHeld("review_document_size_outside_policy")
                    documents[record.path] = await self.multipart.read_range(
                        attempt.object_key, offset=offset, size_bytes=record.size_bytes
                    )
                offset += record.size_bytes
            if self.policy is None:
                raise ValueError("direct model review policy is unavailable")
            result = build_standing_model_review_from_documents(
                bundle, self.policy, standing, documents
            )
            final_head = await self.multipart.head(attempt.object_key)
            if final_head != initial_head:
                raise ValueError("direct model review object changed while reading")
        except StaticModelReviewHeld as error:
            self.journal.put(
                "direct-review-hold",
                payload.model_sha256,
                {"reason_code": error.reason_code, "review_policy_sha256": digest(standing)},
            )
            raise
        publish_private_model(target, result, maximum_bytes=MAX_PUBLICATION_BYTES)
        return result

    def _completion(
        self, signed: SignedDirectModelUploadCompletion
    ) -> tuple[
        SignedDirectModelUploadCompletion,
        SignedDirectModelUploadReservation,
        _DirectModelUploadIntent,
        _DirectModelProviderUpload,
    ]:
        signed = SignedDirectModelUploadCompletion.model_validate_json(canonical_json_bytes(signed))
        completion = signed.completion
        reservation = self._reservation_by_digest(completion.reservation_sha256)
        body, payload = reservation.reservation, reservation.reservation.payload
        if (
            identity(reservation.signature.hotkey) != identity(self.config.owner_hotkey)
            or identity(signed.signature.hotkey) != identity(body.hotkey)
            or completion.generation != body.generation
            or len(completion.parts) != payload.total_parts
            or any(
                part.size_bytes
                != min(
                    payload.part_size_bytes,
                    payload.total_bytes - (part.part_number - 1) * payload.part_size_bytes,
                )
                for part in completion.parts
            )
        ):
            raise ValueError("direct upload completion differs from its reservation")
        if self.journal.get("direct-superseded", completion.reservation_sha256) is not None:
            raise ValueError("direct upload completion reservation was superseded")
        attempt_raw = self.journal.get("direct-intent", body.attempt_id)
        if attempt_raw is None:
            raise ValueError("direct upload completion attempt is unavailable")
        attempt = _DirectModelUploadIntent.model_validate_json(canonical_json_bytes(attempt_raw))
        attempts = self._attempts(payload.upload_sha256)
        if not attempts or attempts[-1] != attempt:
            raise ValueError("direct upload completion reservation was superseded")
        provider = self._provider(attempt)
        if provider is None:
            raise ValueError("direct upload provider is unavailable")
        return signed, reservation, attempt, provider

    def _reservation_by_digest(self, reservation_sha256: str) -> SignedDirectModelUploadReservation:
        raw_index = self.journal.get("direct-reservation-index", reservation_sha256)
        if raw_index is None:
            raise FileNotFoundError("direct upload reservation is unavailable")
        index = _DirectModelReservationIndex.model_validate_json(canonical_json_bytes(raw_index))
        if index.reservation_sha256 != reservation_sha256:
            raise ValueError("direct upload reservation index changed")
        raw = self.journal.get("direct-reservation", index.attempt_id)
        if raw is None:
            raise ValueError("direct upload reservation index is incomplete")
        retained = SignedDirectModelUploadReservation.model_validate_json(canonical_json_bytes(raw))
        if (
            retained.reservation.attempt_id != index.attempt_id
            or digest(retained.reservation) != reservation_sha256
            or identity(retained.signature.hotkey) != identity(self.config.owner_hotkey)
        ):
            raise ValueError("direct upload reservation signer differs")
        return retained

    async def complete(
        self,
        signed: SignedDirectModelUploadCompletion,
        *,
        now_unix_ms: int,
    ) -> DirectModelUploadObject:
        """Retain completion first; reconcile a completed provider call after crash."""

        at = _at(now_unix_ms)
        async with self._mutex:
            signed, reservation, attempt, provider = self._completion(signed)
            key = digest(reservation.reservation)
            prior = self.journal.get("direct-completion", key)
            if prior is None:
                self.journal.put("direct-completion", key, signed)
            else:
                retained_completion = SignedDirectModelUploadCompletion.model_validate_json(
                    canonical_json_bytes(prior)
                )
                if retained_completion.completion != signed.completion or identity(
                    retained_completion.signature.hotkey
                ) != identity(signed.signature.hotkey):
                    raise ValueError("direct upload completion retry differs")
            old_object = self.journal.get("direct-object", key)
            if old_object is not None:
                return DirectModelUploadObject.model_validate_json(canonical_json_bytes(old_object))

            head = await self.multipart.head(attempt.object_key, at=at)
            if head is not None and head.size_bytes != reservation.reservation.payload.total_bytes:
                raise ValueError("completed direct upload object size differs")
            if head is None:
                try:
                    provider_etag = await self.multipart.complete(
                        attempt.object_key,
                        upload_id=provider.provider_upload_id,
                        parts=signed.completion.parts,
                        at=at,
                    )
                except OSError:
                    head = await self.multipart.head(attempt.object_key, at=at)
                    if (
                        head is None
                        or head.size_bytes != reservation.reservation.payload.total_bytes
                    ):
                        raise
                    provider_etag = head.etag
            else:
                provider_etag = head.etag
            result = DirectModelUploadObject(
                schema="umi-direct-model-upload-object/1",
                reservation_sha256=key,
                generation=reservation.reservation.generation,
                object_key_sha256=sha256_hex(attempt.object_key.encode()),
                provider_etag=provider_etag,
                completed_at_unix_ms=now_unix_ms,
            )
            self.journal.put("direct-object", key, result)
            return result

    async def _verify_object(
        self,
        object_key: str,
        bundle,
        payload: DirectModelPayload,
        *,
        expected_head: R2ObjectHead | None = None,
    ) -> R2ObjectHead:
        observed = await self.multipart.head(object_key)
        if observed is None:
            raise DirectModelUploadPending("direct upload object is unavailable")
        head = R2ObjectHead(size_bytes=observed.size_bytes, etag=observed.etag)
        if head.size_bytes != payload.total_bytes or (
            expected_head is not None
            and (head.size_bytes, head.etag) != (expected_head.size_bytes, expected_head.etag)
        ):
            raise ValueError("direct upload object metadata changed")
        stream_hash = hashlib.sha256()
        offset = 0
        for record in bundle.files:
            file_hash = hashlib.sha256()
            remaining = record.size_bytes
            while remaining:
                size = min(remaining, MAXIMUM_RANGE_BYTES)
                data = await self.multipart.read_range(object_key, offset=offset, size_bytes=size)
                if len(data) != size:
                    raise ValueError("direct upload verification range differs")
                stream_hash.update(data)
                file_hash.update(data)
                offset += size
                remaining -= size
            if file_hash.hexdigest() != record.sha256:
                raise ValueError("direct upload file differs from its manifest")
        if offset != payload.total_bytes or stream_hash.hexdigest() != payload.payload_sha256:
            raise ValueError("direct upload payload digest differs")
        final = await self.multipart.head(object_key)
        if final is None or (final.size_bytes, final.etag) != (head.size_bytes, head.etag):
            raise ValueError("direct upload object changed while verifying")
        return head

    async def verify(
        self,
        reservation_sha256: str,
        *,
        now_unix_ms: int,
    ) -> DirectModelUploadVerification:
        """Verify the entire object and every manifest file with bounded memory."""

        _at(now_unix_ms)
        async with self._verification_mutex:
            old = self.journal.get("direct-verification", reservation_sha256)
            if old is not None:
                return DirectModelUploadVerification.model_validate_json(canonical_json_bytes(old))
            reservation = self._reservation_by_digest(reservation_sha256)
            body, payload = reservation.reservation, reservation.reservation.payload
            object_raw = self.journal.get("direct-object", reservation_sha256)
            if object_raw is None:
                raise DirectModelUploadPending("direct upload object is not complete")
            completed = DirectModelUploadObject.model_validate_json(
                canonical_json_bytes(object_raw)
            )
            attempt_raw = self.journal.get("direct-intent", body.attempt_id)
            if attempt_raw is None:
                raise ValueError("direct upload verification attempt is unavailable")
            attempt = _DirectModelUploadIntent.model_validate_json(
                canonical_json_bytes(attempt_raw)
            )
            if (
                completed.reservation_sha256 != reservation_sha256
                or completed.generation != body.generation
                or completed.object_key_sha256 != sha256_hex(attempt.object_key.encode())
            ):
                raise ValueError("completed direct upload object changed")
            request_raw = self.journal.get("direct-request", payload.upload_sha256)
            if request_raw is None:
                raise ValueError("direct upload verification request is unavailable")
            request = CohortParticipationRequest.model_validate_json(
                canonical_json_bytes(request_raw)
            )
            _, submission = self._request(request)
            bundle = submission.model_bundle
            if bundle is None or digest(bundle) != payload.model_sha256:
                raise ValueError("direct upload verification bundle changed")
            head = R2ObjectHead(size_bytes=payload.total_bytes, etag=completed.provider_etag)
            await self._verify_object(attempt.object_key, bundle, payload, expected_head=head)
            result = DirectModelUploadVerification(
                schema="umi-direct-model-upload-verification/1",
                reservation_sha256=reservation_sha256,
                generation=body.generation,
                object_key_sha256=completed.object_key_sha256,
                upload_sha256=payload.upload_sha256,
                model_sha256=payload.model_sha256,
                payload_sha256=payload.payload_sha256,
                total_bytes=payload.total_bytes,
                file_count=payload.file_count,
                verified_at_unix_ms=now_unix_ms,
            )
            self.journal.put("direct-verification", reservation_sha256, result)
            return result

    def _promotion_source(self, publication: ModelAcceptancePublication):
        publication = ModelAcceptancePublication.model_validate_json(
            canonical_json_bytes(publication)
        )
        acceptance = publication.certificate.acceptance
        artifact = acceptance.direct_artifact
        if artifact is None or artifact.reservation.cohort_sha256 != self.config.cohort_sha256:
            raise ValueError("direct model promotion acceptance differs")
        body, payload = artifact.reservation, artifact.reservation.payload
        reservation_sha256 = digest(body)
        if self._reservation_by_digest(reservation_sha256) != artifact:
            raise ValueError("direct model promotion reservation differs")
        request_raw = self.journal.get("direct-request", payload.upload_sha256)
        if request_raw is None:
            raise ValueError("direct model promotion request is unavailable")
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request_raw))
        upload_sha256, submission = self._request(request)
        bundle = submission.model_bundle
        if (
            bundle is None
            or upload_sha256 != payload.upload_sha256
            or digest(submission) != acceptance.submission_sha256
            or digest(bundle) != acceptance.model_sha256
            or payload.model_sha256 != acceptance.model_sha256
            or identity(submission.hotkey) != identity(acceptance.recipient_hotkey)
        ):
            raise ValueError("direct model promotion model differs")
        if (
            publication.inputs.model_sha256 != payload.model_sha256
            or digest(publication.inputs.rights_evidence) != acceptance.rights_evidence_sha256
            or digest(publication.inputs.reconstruction_evidence)
            != acceptance.reconstruction_evidence_sha256
        ):
            raise ValueError("direct model promotion evidence differs")
        self.require_payload(request)
        if self.config.admission_reviews_directory is not None:
            retained = read_private_model(
                Path(self.config.admission_reviews_directory) / (payload.model_sha256 + ".json"),
                ModelArtifactReviewInputs,
                maximum_bytes=MAX_PUBLICATION_BYTES,
            )
            if (
                publication.inputs != retained
                or digest(retained.rights_evidence) != acceptance.rights_evidence_sha256
                or digest(retained.reconstruction_evidence)
                != acceptance.reconstruction_evidence_sha256
            ):
                raise ValueError("direct model promotion review differs")
        attempt_raw = self.journal.get("direct-intent", body.attempt_id)
        completed_raw = self.journal.get("direct-object", reservation_sha256)
        verification_raw = self.journal.get("direct-verification", reservation_sha256)
        if attempt_raw is None or completed_raw is None or verification_raw is None:
            raise DirectModelUploadPending("direct model promotion source is incomplete")
        attempt = _DirectModelUploadIntent.model_validate_json(canonical_json_bytes(attempt_raw))
        completed = DirectModelUploadObject.model_validate_json(canonical_json_bytes(completed_raw))
        verification = DirectModelUploadVerification.model_validate_json(
            canonical_json_bytes(verification_raw)
        )
        source_key = direct_model_object_key(
            body.cohort_sha256, payload.upload_sha256, body.attempt_id
        )
        if (
            attempt.object_key != source_key
            or body.object_key_sha256 != sha256_hex(source_key.encode())
            or completed.object_key_sha256 != body.object_key_sha256
            or verification.reservation_sha256 != reservation_sha256
            or verification.payload_sha256 != payload.payload_sha256
            or verification.total_bytes != payload.total_bytes
        ):
            raise ValueError("direct model promotion source binding differs")
        return acceptance, bundle, payload, reservation_sha256, source_key, completed

    async def promote(
        self,
        publication: ModelAcceptancePublication,
        *,
        now_unix_ms: int,
    ) -> DirectModelPromotion:
        """Promote one certified artifact by server-side copy before admission publication."""

        _at(now_unix_ms)
        async with self._promotion_mutex:
            acceptance, bundle, payload, reservation_sha256, source_key, completed = (
                self._promotion_source(publication)
            )
            acceptance_sha256 = digest(acceptance)
            preserved_key = preserved_model_object_key(
                acceptance.cohort_sha256,
                payload.model_sha256,
                payload.payload_sha256,
            )
            expected_source = R2ObjectHead(
                size_bytes=payload.total_bytes, etag=completed.provider_etag
            )
            raw = self.journal.get("direct-promotion", acceptance_sha256)
            if raw is not None:
                retained = DirectModelPromotion.model_validate_json(canonical_json_bytes(raw))
                expected = retained.model_copy(
                    update={
                        "acceptance_sha256": acceptance_sha256,
                        "reservation_sha256": reservation_sha256,
                        "source_object_key_sha256": sha256_hex(source_key.encode()),
                        "preserved_object_key_sha256": sha256_hex(preserved_key.encode()),
                        "model_sha256": payload.model_sha256,
                        "payload_sha256": payload.payload_sha256,
                        "total_bytes": payload.total_bytes,
                    }
                )
                if retained != expected:
                    raise ValueError("direct model promotion receipt differs")
                head = await self.multipart.head(preserved_key)
                if head is None or (head.size_bytes, head.etag) != (
                    payload.total_bytes,
                    retained.provider_etag,
                ):
                    raise ValueError("preserved direct model changed after promotion")
                source_head = await self.multipart.head(source_key)
                if source_head is not None:
                    if (source_head.size_bytes, source_head.etag) != (
                        expected_source.size_bytes,
                        expected_source.etag,
                    ):
                        raise ValueError("direct model staging source changed after promotion")
                    await self.multipart.delete_object(source_key)
                if await self.multipart.head(source_key) is not None:
                    raise OSError("direct model staging cleanup is incomplete")
                return retained

            source_head = await self.multipart.head(source_key)
            if source_head is None or (source_head.size_bytes, source_head.etag) != (
                expected_source.size_bytes,
                expected_source.etag,
            ):
                raise ValueError("direct model staging source changed before promotion")
            preserved_head = await self.multipart.head(preserved_key)
            if preserved_head is None:
                upload_id = await self.multipart.create(preserved_key)
                try:
                    parts: list[DirectModelUploadPart] = []
                    offset = 0
                    for part_number in range(1, payload.total_parts + 1):
                        size = min(payload.part_size_bytes, payload.total_bytes - offset)
                        parts.append(
                            await self.multipart.copy_part(
                                preserved_key,
                                source_key=source_key,
                                upload_id=upload_id,
                                part_number=part_number,
                                offset=offset,
                                size_bytes=size,
                                source_size_bytes=payload.total_bytes,
                            )
                        )
                        offset += size
                    if offset != payload.total_bytes:
                        raise ValueError("direct model promotion part geometry differs")
                    provider_etag = await self.multipart.complete(
                        preserved_key, upload_id=upload_id, parts=tuple(parts)
                    )
                except BaseException:
                    with suppress(OSError, ValueError):
                        await self.multipart.abort(preserved_key, upload_id=upload_id)
                    raise
                preserved_head = R2ObjectHead(size_bytes=payload.total_bytes, etag=provider_etag)
            verified_head = await self._verify_object(
                preserved_key,
                bundle,
                payload,
                expected_head=preserved_head,
            )
            receipt = DirectModelPromotion(
                schema="umi-direct-model-promotion/1",
                acceptance_sha256=acceptance_sha256,
                reservation_sha256=reservation_sha256,
                source_object_key_sha256=sha256_hex(source_key.encode()),
                preserved_object_key_sha256=sha256_hex(preserved_key.encode()),
                model_sha256=payload.model_sha256,
                payload_sha256=payload.payload_sha256,
                total_bytes=payload.total_bytes,
                provider_etag=verified_head.etag,
                promoted_at_unix_ms=now_unix_ms,
            )
            self.journal.put("direct-promotion", acceptance_sha256, receipt)
            await self.multipart.delete_object(source_key)
            if await self.multipart.head(source_key) is not None:
                raise OSError("direct model staging cleanup is incomplete")
            return receipt

    async def _cleanup_rejected_object(
        self,
        reservation_sha256: str,
        reason_code: str,
        *,
        now_unix_ms: int,
        execute: bool,
    ) -> str:
        """Retain a terminal rejection, then delete only its exact staging object."""

        receipt_raw = self.journal.get("direct-rejected-cleanup-receipt", reservation_sha256)
        if receipt_raw is not None:
            receipt = _DirectModelRejectedCleanupReceipt.model_validate_json(
                canonical_json_bytes(receipt_raw)
            )
            if receipt.reservation_sha256 != reservation_sha256:
                raise ValueError("rejected object cleanup receipt changed")
            return "complete"
        reservation = self._reservation_by_digest(reservation_sha256)
        body = reservation.reservation
        completed_raw = self.journal.get("direct-object", reservation_sha256)
        attempt_raw = self.journal.get("direct-intent", body.attempt_id)
        if completed_raw is None or attempt_raw is None:
            raise ValueError("rejected object cleanup source is incomplete")
        completed = DirectModelUploadObject.model_validate_json(canonical_json_bytes(completed_raw))
        attempt = _DirectModelUploadIntent.model_validate_json(canonical_json_bytes(attempt_raw))
        expected_key_sha256 = sha256_hex(attempt.object_key.encode())
        if (
            completed.reservation_sha256 != reservation_sha256
            or completed.generation != body.generation
            or completed.object_key_sha256 != expected_key_sha256
        ):
            raise ValueError("rejected object cleanup source changed")
        intent_raw = self.journal.get("direct-rejected-cleanup-intent", reservation_sha256)
        if intent_raw is None:
            intent = _DirectModelRejectedCleanupIntent(
                schema="umi-direct-model-rejected-cleanup-intent/1",
                reservation_sha256=reservation_sha256,
                object_key_sha256=expected_key_sha256,
                provider_etag=completed.provider_etag,
                total_bytes=body.payload.total_bytes,
                reason_code=reason_code,
                created_at_unix_ms=now_unix_ms,
                retain_until_unix_ms=(
                    now_unix_ms + self.config.rejected_object_retention_seconds * 1000
                ),
            )
            self.journal.put("direct-rejected-cleanup-intent", reservation_sha256, intent)
        else:
            intent = _DirectModelRejectedCleanupIntent.model_validate_json(
                canonical_json_bytes(intent_raw)
            )
            expected = intent.model_copy(
                update={
                    "reservation_sha256": reservation_sha256,
                    "object_key_sha256": expected_key_sha256,
                    "provider_etag": completed.provider_etag,
                    "total_bytes": body.payload.total_bytes,
                    "reason_code": reason_code,
                }
            )
            if intent != expected:
                raise ValueError("rejected object cleanup intent changed")
        if now_unix_ms < intent.retain_until_unix_ms or not execute:
            return "retained"
        head = await self.multipart.head(attempt.object_key, at=_at(now_unix_ms))
        if head is not None:
            if (head.size_bytes, head.etag) != (intent.total_bytes, intent.provider_etag):
                raise ValueError("rejected object changed before cleanup")
            await self.multipart.delete_object(attempt.object_key, at=_at(now_unix_ms))
            if await self.multipart.head(attempt.object_key, at=_at(now_unix_ms)) is not None:
                raise OSError("rejected object cleanup is incomplete")
        receipt = _DirectModelRejectedCleanupReceipt(
            schema="umi-direct-model-rejected-cleanup-receipt/1",
            intent_sha256=digest(intent),
            reservation_sha256=reservation_sha256,
            object_key_sha256=intent.object_key_sha256,
            deleted_at_unix_ms=now_unix_ms,
        )
        self.journal.put("direct-rejected-cleanup-receipt", reservation_sha256, receipt)
        return "cleaned"

    def _rejected_cleanup_due(self, reservation_sha256: str, now_unix_ms: int) -> bool:
        if self.journal.get("direct-rejected-cleanup-receipt", reservation_sha256) is not None:
            return False
        raw = self.journal.get("direct-rejected-cleanup-intent", reservation_sha256)
        if raw is None:
            return False
        intent = _DirectModelRejectedCleanupIntent.model_validate_json(canonical_json_bytes(raw))
        if intent.reservation_sha256 != reservation_sha256:
            raise ValueError("rejected object cleanup intent changed")
        return now_unix_ms >= intent.retain_until_unix_ms

    async def poll_once(self, *, now_unix_ms: int) -> dict[str, int | str]:
        """Advance bounded object verification without holding up public requests."""

        _at(now_unix_ms)
        ready = pending = failed = reviews_ready = reviews_held = 0
        cleaned = retained_for_cleanup = cleanup_examined = 0
        last_error = ""
        examined = 0
        for reservation_sha256 in self.journal.keys("direct-object"):
            verified = self.journal.get("direct-verification", reservation_sha256) is not None
            reservation = self._reservation_by_digest(reservation_sha256)
            model_sha256 = reservation.reservation.payload.model_sha256
            verification_hold = self.journal.get("direct-verification-hold", reservation_sha256)
            review_hold = self.journal.get("direct-review-hold", model_sha256)
            reviewed = self.config.standing_review_policy is None
            if self.config.admission_reviews_directory is not None:
                try:
                    retained = read_private_model(
                        Path(self.config.admission_reviews_directory) / (model_sha256 + ".json"),
                        ModelArtifactReviewInputs,
                        maximum_bytes=MAX_PUBLICATION_BYTES,
                    )
                    if retained.model_sha256 != model_sha256:
                        raise ValueError("direct model review changed")
                    reviewed = True
                    reviews_ready += 1
                except FileNotFoundError:
                    pass
            if verified:
                ready += 1
            if verified and reviewed:
                continue
            if verification_hold is not None:
                failed += 1
                last_error = verification_hold["reason_code"]
                try:
                    execute = self._rejected_cleanup_due(reservation_sha256, now_unix_ms) and (
                        cleanup_examined < self.config.cleanup_batch_size
                    )
                    if execute:
                        cleanup_examined += 1
                    state = await self._cleanup_rejected_object(
                        reservation_sha256,
                        last_error,
                        now_unix_ms=now_unix_ms,
                        execute=execute,
                    )
                    if state == "cleaned":
                        cleaned += 1
                    elif state == "retained":
                        retained_for_cleanup += 1
                except (OSError, ValueError) as error:
                    retained_for_cleanup += 1
                    last_error = (
                        "direct_model_rejected_cleanup_failed"
                        if isinstance(error, ValueError)
                        else type(error).__name__
                    )
                continue
            if review_hold is not None:
                reviews_held += 1
                last_error = review_hold["reason_code"]
                try:
                    execute = self._rejected_cleanup_due(reservation_sha256, now_unix_ms) and (
                        cleanup_examined < self.config.cleanup_batch_size
                    )
                    if execute:
                        cleanup_examined += 1
                    state = await self._cleanup_rejected_object(
                        reservation_sha256,
                        last_error,
                        now_unix_ms=now_unix_ms,
                        execute=execute,
                    )
                    if state == "cleaned":
                        cleaned += 1
                    elif state == "retained":
                        retained_for_cleanup += 1
                except (OSError, ValueError) as error:
                    retained_for_cleanup += 1
                    last_error = (
                        "direct_model_rejected_cleanup_failed"
                        if isinstance(error, ValueError)
                        else type(error).__name__
                    )
                continue
            if examined >= self.config.verification_batch_size:
                pending += 1
                continue
            examined += 1
            if not verified:
                try:
                    await self.verify(reservation_sha256, now_unix_ms=now_unix_ms)
                    ready += 1
                except ValueError:
                    reason_code = "direct_model_verification_failed"
                    self.journal.put(
                        "direct-verification-hold",
                        reservation_sha256,
                        {"reason_code": reason_code},
                    )
                    failed += 1
                    last_error = reason_code
                    try:
                        await self._cleanup_rejected_object(
                            reservation_sha256,
                            reason_code,
                            now_unix_ms=now_unix_ms,
                            execute=False,
                        )
                    except (OSError, ValueError) as error:
                        last_error = (
                            "direct_model_rejected_cleanup_failed"
                            if isinstance(error, ValueError)
                            else type(error).__name__
                        )
                    retained_for_cleanup += 1
                    continue
                except OSError as error:
                    failed += 1
                    last_error = type(error).__name__
                    continue
            try:
                if await self.review(reservation_sha256, now_unix_ms=now_unix_ms) is not None:
                    reviews_ready += 1
            except StaticModelReviewHeld as error:
                reviews_held += 1
                last_error = error.reason_code
                try:
                    await self._cleanup_rejected_object(
                        reservation_sha256,
                        error.reason_code,
                        now_unix_ms=now_unix_ms,
                        execute=False,
                    )
                except (OSError, ValueError) as cleanup_error:
                    last_error = (
                        "direct_model_rejected_cleanup_failed"
                        if isinstance(cleanup_error, ValueError)
                        else type(cleanup_error).__name__
                    )
                retained_for_cleanup += 1
            except ValueError:
                reason_code = "direct_model_review_failed"
                self.journal.put(
                    "direct-review-hold",
                    model_sha256,
                    {"reason_code": reason_code},
                )
                reviews_held += 1
                last_error = reason_code
                try:
                    await self._cleanup_rejected_object(
                        reservation_sha256,
                        reason_code,
                        now_unix_ms=now_unix_ms,
                        execute=False,
                    )
                except (OSError, ValueError) as cleanup_error:
                    last_error = (
                        "direct_model_rejected_cleanup_failed"
                        if isinstance(cleanup_error, ValueError)
                        else type(cleanup_error).__name__
                    )
                retained_for_cleanup += 1
            except OSError as error:
                failed += 1
                last_error = type(error).__name__
        return {
            "status": "direct_model_upload_poll",
            "objects_verified": ready,
            "objects_pending": pending,
            "objects_failed": failed,
            "reviews_ready": reviews_ready,
            "reviews_held": reviews_held,
            "objects_cleaned": cleaned,
            "objects_retained_for_cleanup": retained_for_cleanup,
            "last_error_type": last_error,
        }


class DirectModelUploadOwners:
    """Route multiple signed cohort profiles through one long-lived service."""

    def __init__(self, owners: Mapping[str, DirectModelUploadOwner]):
        self.owners = dict(owners)
        if (
            not self.owners
            or any(key != owner.config.cohort_sha256 for key, owner in self.owners.items())
            or len({id(owner) for owner in self.owners.values()}) != len(self.owners)
        ):
            raise ValueError("direct model owners require unique cohort bindings")

    def require_payload(self, request: CohortParticipationRequest) -> None:
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        try:
            owner = self.owners[request.consent.consent.cohort_sha256]
        except KeyError as error:
            raise DirectModelUploadPending("direct model cohort is unavailable") from error
        owner.require_payload(request)

    def review_artifact(
        self, request: CohortParticipationRequest
    ) -> SignedDirectModelUploadReservation:
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        try:
            owner = self.owners[request.consent.consent.cohort_sha256]
        except KeyError as error:
            raise DirectModelUploadPending("direct model cohort is unavailable") from error
        return owner.review_artifact(request)

    async def promote(self, publication: ModelAcceptancePublication) -> DirectModelPromotion | None:
        """Route one independently certified acceptance to its bound R2 owner."""

        publication = ModelAcceptancePublication.model_validate_json(
            canonical_json_bytes(publication)
        )
        artifact = publication.certificate.acceptance.direct_artifact
        if artifact is None:
            return None
        try:
            owner = self.owners[artifact.reservation.cohort_sha256]
        except KeyError as error:
            raise DirectModelUploadPending(
                "direct model promotion cohort is unavailable"
            ) from error
        return await owner.promote(publication, now_unix_ms=time.time_ns() // 1_000_000)

    async def poll_once(self, *, now_unix_ms: int | None = None) -> dict:
        current = time.time_ns() // 1_000_000 if now_unix_ms is None else now_unix_ms
        reports = {}
        for cohort, owner in self.owners.items():
            reports[cohort] = await owner.poll_once(now_unix_ms=current)
        return {
            "status": "direct_model_upload_owners_polled",
            "cohorts": reports,
            "chain_submission_authorized": False,
        }
