"""Typed, size-bounded offline rehearsal bundles using the Section 12 layout."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes

AUDIT_BUNDLE_SCHEMA = "umi-shadow-rehearsal-bundle/2"
SHADOW_TERMINAL = "shadow_rehearsal_no_weight"
SHADOW_INCIDENT_TERMINAL = "shadow_rehearsal_window_void"
STAGE_IDS = (
    "pool_and_selection",
    "assignment",
    "request_transcript",
    "sealed_response",
    "reveal_and_score",
    "weight_build",
    "commit_and_terminal_state",
)
MAX_AUDIT_BUNDLE_BYTES = 384 * 1024 * 1024
MAX_AUDIT_OBJECT_BYTES = 64 * 1024 * 1024


class AuditObject(StrictProtocolModel):
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    media_type: Annotated[str, Field(min_length=1)]
    size_bytes: Annotated[int, Field(ge=0)]

    @classmethod
    def from_ref(cls, reference: ObjectRef) -> AuditObject:
        return cls.model_validate(reference.as_dict())


class StageRecord(StrictProtocolModel):
    stage_id: Literal[
        "pool_and_selection",
        "assignment",
        "request_transcript",
        "sealed_response",
        "reveal_and_score",
        "weight_build",
        "commit_and_terminal_state",
    ]
    status: Literal["reached", "not_reached"]
    objects: list[AuditObject]
    reason_code: str | None

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status == "reached":
            if self.reason_code is not None:
                raise ValueError("reached audit stage cannot carry a not-reached reason")
        else:
            if self.objects:
                raise ValueError("not-reached audit stage cannot contain fabricated objects")
            if self.reason_code is None or not self.reason_code.strip():
                raise ValueError("not-reached audit stage requires a prior-stage reason")
        digests = [bytes.fromhex(item.sha256) for item in self.objects]
        if digests != sorted(digests) or len(set(digests)) != len(digests):
            raise ValueError("stage objects must be unique and sorted by raw digest")
        return self


class AuditBundleManifest(StrictProtocolModel):
    schema_: Literal[AUDIT_BUNDLE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    bundle_mode: Literal["shadow_rehearsal"]
    translation_weights_active: Literal[False]
    protocol_conformance: Literal[False]
    activation_evidence: Literal[False]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    software_revisions: dict[str, str]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    highest_stage: Literal[
        "pool_and_selection",
        "assignment",
        "request_transcript",
        "sealed_response",
        "reveal_and_score",
        "weight_build",
        "commit_and_terminal_state",
    ]
    terminal_classification: Literal[SHADOW_TERMINAL, SHADOW_INCIDENT_TERMINAL]
    audit_release_block: Literal[0]
    reason_codes: list[Annotated[str, Field(min_length=1)]]
    stages: Annotated[list[StageRecord], Field(min_length=7, max_length=7)]
    objects: list[AuditObject]
    audit_bundle_bytes: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_stage_graph(self) -> Self:
        if [stage.stage_id for stage in self.stages] != list(STAGE_IDS):
            raise ValueError("audit stages must appear once in protocol order")
        reached = [stage.status == "reached" for stage in self.stages]
        seen_not_reached = False
        for is_reached in reached:
            if seen_not_reached and is_reached:
                raise ValueError("an audit stage cannot be reached after a skipped stage")
            seen_not_reached = seen_not_reached or not is_reached
        if not any(reached):
            raise ValueError("audit bundle must reach at least the pool-and-selection stage")
        highest_index = max(index for index, value in enumerate(reached) if value)
        if self.highest_stage != STAGE_IDS[highest_index]:
            raise ValueError("highest_stage does not match the reached-stage prefix")
        if self.stages[-1].status != "not_reached":
            raise ValueError("an offline rehearsal cannot reach chain terminal state")
        if self.terminal_classification == SHADOW_INCIDENT_TERMINAL and reached[5]:
            raise ValueError("a void rehearsal cannot reach weight build")
        digests = [bytes.fromhex(item.sha256) for item in self.objects]
        if digests != sorted(digests) or len(set(digests)) != len(digests):
            raise ValueError("bundle object table must be unique and sorted by raw digest")
        stage_objects = {item.sha256: item for stage in self.stages for item in stage.objects}
        table = {item.sha256: item for item in self.objects}
        if stage_objects != table:
            raise ValueError("bundle object table is not the union of reached-stage objects")
        if self.reason_codes != sorted(set(self.reason_codes)):
            raise ValueError("reason codes must be unique and sorted")
        stage_reasons = sorted(
            {
                stage.reason_code
                for stage in self.stages
                if stage.status == "not_reached" and stage.reason_code is not None
            }
        )
        if self.reason_codes != stage_reasons:
            raise ValueError("reason codes must equal the not-reached stage reasons")
        if not self.software_revisions or any(
            not key.strip() or not value.strip() for key, value in self.software_revisions.items()
        ):
            raise ValueError("software revisions must contain non-empty names and values")
        return self


@dataclass(frozen=True)
class BundleObjectInput:
    data: bytes
    media_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("bundle object data must be exact bytes")
        if not self.media_type:
            raise ValueError("bundle object media type must not be empty")


@dataclass(frozen=True)
class StageInput:
    stage_id: str
    objects: tuple[BundleObjectInput, ...] = ()
    not_reached_reason: str | None = None


def write_audit_bundle(
    root: Path,
    *,
    scoring_policy_hash: str,
    software_revisions: Mapping[str, str],
    window_id: str,
    terminal_classification: str,
    audit_release_block: int,
    reason_codes: Sequence[str],
    stages: Sequence[StageInput],
    maximum_bundle_bytes: int = MAX_AUDIT_BUNDLE_BYTES,
) -> Path:
    if terminal_classification not in {SHADOW_TERMINAL, SHADOW_INCIDENT_TERMINAL}:
        raise ValueError("offline bundles cannot claim a protocol terminal classification")
    if audit_release_block != 0:
        raise ValueError("offline rehearsal bundles have no chain audit-release block")
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise FileExistsError("audit bundle output must be an empty directory")
    if [stage.stage_id for stage in stages] != list(STAGE_IDS):
        raise ValueError("audit stage inputs must appear once in protocol order")
    reached_prefix = True
    reached_count = 0
    for stage in stages:
        is_reached = stage.not_reached_reason is None
        if is_reached and not reached_prefix:
            raise ValueError("an audit stage cannot be reached after a skipped stage")
        reached_count += int(is_reached)
        reached_prefix = reached_prefix and is_reached
    if reached_count == 0:
        raise ValueError("audit bundle must reach at least the pool-and-selection stage")
    if stages[-1].not_reached_reason is None:
        raise ValueError("an offline rehearsal cannot reach chain terminal state")
    if terminal_classification == SHADOW_INCIDENT_TERMINAL and stages[5].not_reached_reason is None:
        raise ValueError("a void rehearsal cannot reach weight build")
    expected_reasons = sorted(
        {stage.not_reached_reason for stage in stages if stage.not_reached_reason is not None}
    )
    supplied_reasons = sorted(set(reason_codes))
    if supplied_reasons != expected_reasons:
        raise ValueError("reason codes must equal the not-reached stage reasons")
    store = EvidenceStore(
        root,
        maximum_object_bytes=MAX_AUDIT_OBJECT_BYTES,
        maximum_manifest_bytes=4 * 1024 * 1024,
        maximum_total_object_bytes=maximum_bundle_bytes,
    )
    stage_records: list[StageRecord] = []
    all_objects: dict[str, AuditObject] = {}
    for stage in stages:
        if stage.not_reached_reason is not None:
            record = StageRecord(
                stage_id=stage.stage_id,
                status="not_reached",
                objects=[],
                reason_code=stage.not_reached_reason,
            )
        else:
            refs = [store.add_bytes(item.data, item.media_type) for item in stage.objects]
            audit_objects = sorted(
                (AuditObject.from_ref(reference) for reference in refs),
                key=lambda item: bytes.fromhex(item.sha256),
            )
            for item in audit_objects:
                previous = all_objects.get(item.sha256)
                if previous is not None:
                    raise ValueError("one object digest is referenced by more than one stage")
                all_objects[item.sha256] = item
            record = StageRecord(
                stage_id=stage.stage_id,
                status="reached",
                objects=audit_objects,
                reason_code=None,
            )
        stage_records.append(record)
    reached = [record for record in stage_records if record.status == "reached"]
    if not reached:
        raise ValueError("audit bundle must reach at least the pool-and-selection stage")
    object_table = sorted(all_objects.values(), key=lambda item: bytes.fromhex(item.sha256))
    base = {
        "schema": AUDIT_BUNDLE_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "bundle_mode": "shadow_rehearsal",
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "scoring_policy_hash": scoring_policy_hash,
        "software_revisions": dict(sorted(software_revisions.items())),
        "window_id": window_id,
        "highest_stage": reached[-1].stage_id,
        "terminal_classification": terminal_classification,
        "audit_release_block": audit_release_block,
        "reason_codes": supplied_reasons,
        "stages": [record.model_dump(mode="json") for record in stage_records],
        "objects": [item.model_dump(mode="json") for item in object_table],
    }
    object_bytes = sum(item.size_bytes for item in object_table)
    manifest_size = _fixed_point_manifest_size(base, object_bytes=object_bytes)
    total_bytes = manifest_size + object_bytes
    if total_bytes > maximum_bundle_bytes:
        raise ValueError("audit bundle exceeds its policy-pinned byte ceiling")
    manifest = AuditBundleManifest.model_validate({**base, "audit_bundle_bytes": total_bytes})
    encoded = canonical_json_bytes(manifest)
    if len(encoded) != manifest_size:
        raise RuntimeError("audit manifest size fixed point did not converge")
    return store.write_manifest(manifest.model_dump(mode="json", by_alias=True))


def verify_audit_bundle(
    root: Path,
    *,
    maximum_bundle_bytes: int = MAX_AUDIT_BUNDLE_BYTES,
) -> AuditBundleManifest:
    store = EvidenceStore(
        root,
        maximum_object_bytes=MAX_AUDIT_OBJECT_BYTES,
        maximum_manifest_bytes=4 * 1024 * 1024,
        maximum_total_object_bytes=maximum_bundle_bytes,
    )
    raw_manifest, manifest_bytes = store.load_manifest_with_bytes()
    manifest = AuditBundleManifest.model_validate(raw_manifest)
    for item in manifest.objects:
        store.read(item.model_dump(mode="json"))
    calculated = len(manifest_bytes) + sum(item.size_bytes for item in manifest.objects)
    if calculated != manifest.audit_bundle_bytes:
        raise ValueError("audit bundle byte accounting does not reproduce")
    if calculated > maximum_bundle_bytes:
        raise ValueError("audit bundle exceeds its policy-pinned byte ceiling")
    return manifest


def _fixed_point_manifest_size(base: dict[str, Any], *, object_bytes: int) -> int:
    size = 1
    for _ in range(32):
        encoded = canonical_json_bytes({**base, "audit_bundle_bytes": object_bytes + size})
        next_size = len(encoded)
        if next_size == size:
            return size
        size = next_size
    raise RuntimeError("audit manifest size did not reach a fixed point")


__all__ = [
    "AUDIT_BUNDLE_SCHEMA",
    "MAX_AUDIT_BUNDLE_BYTES",
    "SHADOW_INCIDENT_TERMINAL",
    "SHADOW_TERMINAL",
    "STAGE_IDS",
    "AuditBundleManifest",
    "AuditObject",
    "BundleObjectInput",
    "StageInput",
    "StageRecord",
    "verify_audit_bundle",
    "write_audit_bundle",
]
