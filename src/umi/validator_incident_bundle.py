"""Signed, replayable bundles for shadow windows that terminate before success.

An incident bundle is the fail-closed counterpart to a seven-stage
``calibration_no_weight`` bundle.  It contains the complete reached journal
prefix, explicit ``not_reached`` markers for every later stage, and the same raw
announcement-to-release proof-bearing no-weight scan used by successful shadow
windows.  A skipped or void window therefore cannot disappear merely because it
did not reach weight construction.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, JsonValue, model_validator
from typing_extensions import Self

from .audit import EvidenceStore
from .calibration_bundle import (
    CALIBRATION_POLICY_MEDIA_TYPE,
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CALIBRATION_SCAN_MEDIA_TYPE,
    CALIBRATION_SCAN_SCHEMA,
    CALIBRATION_STAGE_MEDIA_TYPE,
    MAX_CALIBRATION_BUNDLE_BYTES,
    MAX_CALIBRATION_MANIFEST_BYTES,
    MAX_CALIBRATION_OBJECT_BYTES,
    STAGE_IDS,
    CalibrationObject,
    CalibrationStageEvidence,
    CalibrationStageInput,
    CalibrationVerificationPorts,
    FinalizedNoWeightScanObject,
    ValidatorManifestSignature,
    _assert_live_policy_bindings,
    _encode_block_evidence,
    _fixed_point_manifest_size,
    _parse_canonical,
    _require_exact_bundle_paths,
    calibration_stage_replay_hook_id,
    replay_finalized_no_weight_scan,
)
from .chain_evidence import FinalizedSnapshotRef
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_chain_scan import DecodedNoWeightInterval, ScanLimits
from .validator_journal import StageReceipt

INCIDENT_BUNDLE_SCHEMA = "umi-validator-incident-bundle/1"
INCIDENT_TERMINAL_SCHEMA = "umi-validator-incident-terminal/1"
INCIDENT_BUNDLE_MODE = "live_shadow_incident"
INCIDENT_TERMINAL_MEDIA_TYPE = "application/vnd.umi.validator-incident-terminal-v1+json"

_MANIFEST_DOMAIN = b"umi-validator-incident-bundle-manifest-v1\0"
_REASON_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")

Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Hex64 = Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]
BlockHash = Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
NonNegative = Annotated[int, Field(ge=0)]
PositiveBlock = Annotated[int, Field(gt=0)]
NonEmpty = Annotated[str, Field(min_length=1)]
StageId = Literal[
    "pool_and_selection",
    "assignment",
    "request_transcript",
    "sealed_response",
    "reveal_and_score",
    "weight_build",
    "commit_and_terminal_state",
]
IncidentOutcome = Literal["skipped", "void", "failed"]


class IncidentSpecObject(StrictProtocolModel):
    incident_id: NonEmpty
    reason_code: NonEmpty
    metadata: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_reason(self) -> Self:
        _reason(self.reason_code)
        return self


class IncidentTerminalEvidence(StrictProtocolModel):
    schema_: Literal[INCIDENT_TERMINAL_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    bundle_mode: Literal[INCIDENT_BUNDLE_MODE]
    terminal_classification: IncidentOutcome
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    weight_submission_performed: Literal[False]
    activation_evidence: Literal[False]
    overall_activation_ready: Literal[False]
    validator_account_id32: Hex32
    window_id: Hex32
    scoring_policy_hash: Hex32
    terminal_stage: StageId
    reason_code: NonEmpty
    incident: IncidentSpecObject | None
    announcement_block: PositiveBlock
    audit_release_snapshot: dict[str, JsonValue]
    no_weight_scan_object: CalibrationObject

    @model_validator(mode="after")
    def validate_terminal(self) -> Self:
        _reason(self.reason_code)
        _snapshot_from_json(self.audit_release_snapshot)
        if self.incident is not None and self.incident.reason_code != self.reason_code:
            raise ValueError("incident and terminal reason codes disagree")
        if self.no_weight_scan_object.media_type != CALIBRATION_SCAN_MEDIA_TYPE:
            raise ValueError("incident terminal references an incorrectly typed scan")
        return self

    @property
    def audit_release(self) -> FinalizedSnapshotRef:
        return _snapshot_from_json(self.audit_release_snapshot)


class IncidentStageRecord(StrictProtocolModel):
    stage_id: StageId
    status: Literal["reached", "not_reached"]
    evidence_object: CalibrationObject | None
    prior_terminal_stage: StageId | None
    prior_stage_reason_code: str | None

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        reached = self.status == "reached"
        if reached != (self.evidence_object is not None):
            raise ValueError("incident stage status and evidence reference disagree")
        if reached:
            if self.evidence_object is None or (
                self.evidence_object.media_type != CALIBRATION_STAGE_MEDIA_TYPE
            ):
                raise ValueError("reached incident stage has the wrong evidence type")
            if self.prior_terminal_stage is not None or self.prior_stage_reason_code is not None:
                raise ValueError("a reached stage cannot carry a not-reached marker")
        else:
            if self.prior_terminal_stage is None or self.prior_stage_reason_code is None:
                raise ValueError("a not-reached stage must name its terminal predecessor")
            _reason(self.prior_stage_reason_code)
        return self


class IncidentBundleManifest(StrictProtocolModel):
    schema_: Literal[INCIDENT_BUNDLE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    bundle_mode: Literal[INCIDENT_BUNDLE_MODE]
    terminal_classification: IncidentOutcome
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    weight_submission_performed: Literal[False]
    activation_evidence: Literal[False]
    overall_activation_ready: Literal[False]
    validator_account_id32: Hex32
    window_id: Hex32
    window_index: NonNegative
    scoring_policy_hash: Hex32
    policy_object: CalibrationObject
    software_revisions: dict[str, str]
    highest_stage: StageId
    terminal_stage: StageId
    announcement_block: PositiveBlock
    audit_release_block: PositiveBlock
    audit_release_block_hash: BlockHash
    reason_codes: Annotated[list[NonEmpty], Field(min_length=1)]
    terminal_evidence_object: CalibrationObject
    no_weight_scan_object: CalibrationObject
    stages: Annotated[list[IncidentStageRecord], Field(min_length=7, max_length=7)]
    objects: Annotated[list[CalibrationObject], Field(min_length=8)]
    audit_bundle_bytes: Annotated[int, Field(gt=0)]
    validator_signature: ValidatorManifestSignature

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if [item.stage_id for item in self.stages] != list(STAGE_IDS):
            raise ValueError("incident stages are not in complete protocol order")
        terminal_index = STAGE_IDS.index(self.terminal_stage)
        if self.highest_stage != self.terminal_stage:
            raise ValueError("incident highest stage must be its terminal stage")
        expected_statuses = [
            "reached" if index <= terminal_index else "not_reached"
            for index in range(len(STAGE_IDS))
        ]
        if [item.status for item in self.stages] != expected_statuses:
            raise ValueError("incident stages are not one reached prefix")
        for item in self.stages[terminal_index + 1 :]:
            if (
                item.prior_terminal_stage != self.terminal_stage
                or item.prior_stage_reason_code not in self.reason_codes
            ):
                raise ValueError("not-reached stage does not name the terminal reason")
        reasons = [_reason(value) for value in self.reason_codes]
        if reasons != sorted(set(reasons)):
            raise ValueError("incident reason codes must be unique and sorted")
        if self.validator_signature.account_id32 != self.validator_account_id32:
            raise ValueError("incident manifest signature belongs to another validator")
        if self.validator_signature.signed_digest != _manifest_digest(self).hex():
            raise ValueError("incident manifest signature digest does not reproduce")
        if self.policy_object.media_type != CALIBRATION_POLICY_MEDIA_TYPE:
            raise ValueError("incident manifest policy has the wrong media type")
        if self.terminal_evidence_object.media_type != INCIDENT_TERMINAL_MEDIA_TYPE:
            raise ValueError("incident manifest terminal has the wrong media type")
        if self.no_weight_scan_object.media_type != CALIBRATION_SCAN_MEDIA_TYPE:
            raise ValueError("incident manifest scan has the wrong media type")
        table = [bytes.fromhex(item.sha256) for item in self.objects]
        if table != sorted(table) or len(set(table)) != len(table):
            raise ValueError("incident object table must be unique and sorted")
        if not self.software_revisions or any(
            not key.strip() or not value.strip() for key, value in self.software_revisions.items()
        ):
            raise ValueError("software revisions must contain non-empty names and values")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedIncidentBundle:
    manifest: IncidentBundleManifest
    policy: ScoringPolicy
    terminal: IncidentTerminalEvidence
    no_weight_scan: FinalizedNoWeightScanObject
    replayed_interval: DecodedNoWeightInterval
    reached_stages: tuple[CalibrationStageEvidence, ...]


@dataclass(slots=True)
class _PayloadTable:
    maximum_object_bytes: int
    values: dict[str, tuple[CalibrationObject, bytes]]

    def add(self, data: bytes, media_type: str) -> CalibrationObject:
        if not isinstance(data, bytes):
            raise TypeError("incident payload must be exact bytes")
        if len(data) > self.maximum_object_bytes:
            raise ValueError("incident object exceeds its byte ceiling")
        reference = CalibrationObject.from_bytes(data, media_type)
        previous = self.values.setdefault(reference.sha256, (reference, data))
        if previous != (reference, data):
            raise RuntimeError("one incident digest has conflicting bytes or media type")
        return reference


def write_incident_bundle(
    root: Path,
    *,
    policy: ScoringPolicy,
    window_id: str,
    window_index: int,
    software_revisions: Mapping[str, str],
    validator_account: str | bytes,
    audit_release_snapshot: FinalizedSnapshotRef,
    no_weight_scan: DecodedNoWeightInterval,
    stages: Sequence[CalibrationStageInput],
    terminal_classification: IncidentOutcome,
    reason_code: str,
    incident: Mapping[str, Any] | None,
    signature_scheme: Literal["sr25519", "ed25519"],
    manifest_signer: Callable[[bytes], bytes],
    maximum_object_bytes: int = MAX_CALIBRATION_OBJECT_BYTES,
    maximum_bundle_bytes: int = MAX_CALIBRATION_BUNDLE_BYTES,
) -> Path:
    """Write one exact early-terminal live-shadow incident bundle."""

    _validate_write_inputs(
        root=root,
        policy=policy,
        audit_release_snapshot=audit_release_snapshot,
        maximum_object_bytes=maximum_object_bytes,
        maximum_bundle_bytes=maximum_bundle_bytes,
    )
    if terminal_classification not in {"skipped", "void", "failed"}:
        raise ValueError("incident terminal classification is unsupported")
    reason_code = _reason(reason_code)
    if signature_scheme not in {"sr25519", "ed25519"}:
        raise ValueError("incident signature scheme is unsupported")
    if not callable(manifest_signer):
        raise TypeError("incident manifest signer must be callable")
    if isinstance(window_index, bool) or not isinstance(window_index, int) or window_index < 0:
        raise ValueError("incident window index must be nonnegative")
    policy_hash = scoring_policy_hash(policy)
    revisions = dict(software_revisions)
    _assert_live_policy_bindings(policy, revisions, no_weight_scan.evidence)
    announcement = policy.activation_block + window_index * policy.clock.window_stride_blocks
    account = account_id32(validator_account)
    if not isinstance(no_weight_scan, DecodedNoWeightInterval) or not no_weight_scan.evidence:
        raise TypeError("incident bundle requires proof-bearing no-weight evidence")
    if (
        no_weight_scan.scan.start_snapshot.block_number != announcement
        or no_weight_scan.scan.end_snapshot != audit_release_snapshot
        or no_weight_scan.scan.scanned_blocks < 2
    ):
        raise ValueError("incident no-weight scan does not cover announcement through release")

    stage_inputs = tuple(stages)
    if not 1 <= len(stage_inputs) <= len(STAGE_IDS):
        raise ValueError("incident bundle requires one nonempty reached-stage prefix")

    payloads = _PayloadTable(maximum_object_bytes, {})
    policy_ref = payloads.add(canonical_json_bytes(policy), CALIBRATION_POLICY_MEDIA_TYPE)
    block_objects = [_encode_block_evidence(item, payloads) for item in no_weight_scan.evidence]
    scan = FinalizedNoWeightScanObject.model_validate(
        {
            "schema": CALIBRATION_SCAN_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "netuid": 78,
            "mechanism_id": 0,
            "validator_account_id32": account.hex(),
            "window_id": window_id,
            "window_index": window_index,
            "scoring_policy_hash": policy_hash,
            "policy_object": policy_ref.model_dump(mode="json"),
            "announcement_block": announcement,
            "start_block": no_weight_scan.scan.start_snapshot.block_number,
            "start_block_hash": no_weight_scan.scan.start_snapshot.block_hash,
            "end_block": no_weight_scan.scan.end_snapshot.block_number,
            "end_block_hash": no_weight_scan.scan.end_snapshot.block_hash,
            "scanned_blocks": no_weight_scan.scan.scanned_blocks,
            "scanned_calls": no_weight_scan.scan.scanned_calls,
            "scanned_events": no_weight_scan.scan.scanned_events,
            "blocks": [item.model_dump(mode="json") for item in block_objects],
        }
    )
    scan_ref = payloads.add(canonical_json_bytes(scan), CALIBRATION_SCAN_MEDIA_TYPE)

    stage_records: list[IncidentStageRecord] = []
    previous_stage_digest: str | None = None
    receipts: list[StageReceipt] = []
    for expected_stage, stage_input in zip(STAGE_IDS, stage_inputs, strict=False):
        if stage_input.replay_hook_id != calibration_stage_replay_hook_id(policy, expected_stage):
            raise ValueError("incident stage replay hook is not policy-pinned")
        receipt = _parse_canonical(stage_input.receipt_bytes, StageReceipt, "stage receipt")
        if not isinstance(receipt, StageReceipt):
            raise RuntimeError("stage receipt parser returned another model")
        if receipt.window_id != window_id or receipt.stage != expected_stage:
            raise ValueError("incident stage receipts are not the exact canonical prefix")
        receipt_ref = payloads.add(stage_input.receipt_bytes, CALIBRATION_RECEIPT_MEDIA_TYPE)
        supplied: dict[str, CalibrationObject] = {}
        for item in stage_input.objects:
            reference = payloads.add(item.data, item.media_type)
            if reference.sha256 in supplied:
                raise ValueError("incident stage repeats a payload object")
            supplied[reference.sha256] = reference
        expected_payloads = {item.sha256: item for item in receipt.objects}
        if {key: value.model_dump(mode="json") for key, value in supplied.items()} != {
            key: value.model_dump(mode="json") for key, value in expected_payloads.items()
        }:
            raise ValueError("incident stage objects do not reproduce their receipt")
        evidence = CalibrationStageEvidence.model_validate(
            {
                "schema": "umi-calibration-stage-evidence/2",
                "protocol": PROTOCOL_VERSION,
                "window_id": window_id,
                "scoring_policy_hash": policy_hash,
                "stage_id": expected_stage,
                "replay_hook_id": stage_input.replay_hook_id,
                "previous_stage_evidence_sha256": previous_stage_digest,
                "receipt_object": receipt_ref.model_dump(mode="json"),
                "payload_objects": [
                    item.model_dump(mode="json")
                    for item in sorted(supplied.values(), key=lambda ref: bytes.fromhex(ref.sha256))
                ],
            }
        )
        evidence_ref = payloads.add(canonical_json_bytes(evidence), CALIBRATION_STAGE_MEDIA_TYPE)
        stage_records.append(
            IncidentStageRecord(
                stage_id=expected_stage,
                status="reached",
                evidence_object=evidence_ref,
                prior_terminal_stage=None,
                prior_stage_reason_code=None,
            )
        )
        previous_stage_digest = evidence_ref.sha256
        receipts.append(receipt)

    terminal_receipt = receipts[-1]
    terminal = _terminal_receipt(terminal_receipt)
    if (
        terminal["outcome"] != terminal_classification
        or terminal["reason_code"] != reason_code
        or terminal["audit_release_block"] != audit_release_snapshot.block_number
    ):
        raise ValueError("incident terminal receipt disagrees with requested classification")
    if any(_terminal_receipt_or_none(item) is not None for item in receipts[:-1]):
        raise ValueError("incident reached prefix contains an earlier terminal receipt")
    terminal_stage = terminal_receipt.stage
    if terminal_stage != STAGE_IDS[len(receipts) - 1]:
        raise ValueError("incident terminal receipt is not the highest reached stage")
    canonical_incident = _canonical_incident(incident, reason_code=reason_code)
    if terminal["incident"] != canonical_incident:
        raise ValueError("incident object does not reproduce terminal receipt metadata")
    reasons = sorted(
        {
            reason_code,
            *([canonical_incident["reason_code"]] if canonical_incident is not None else []),
        }
    )
    for later_stage in STAGE_IDS[len(receipts) :]:
        stage_records.append(
            IncidentStageRecord(
                stage_id=later_stage,
                status="not_reached",
                evidence_object=None,
                prior_terminal_stage=terminal_stage,
                prior_stage_reason_code=reason_code,
            )
        )

    terminal_evidence = IncidentTerminalEvidence.model_validate(
        {
            "schema": INCIDENT_TERMINAL_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "bundle_mode": INCIDENT_BUNDLE_MODE,
            "terminal_classification": terminal_classification,
            "netuid": 78,
            "mechanism_id": 0,
            "translation_weights_active": False,
            "weight_submission_performed": False,
            "activation_evidence": False,
            "overall_activation_ready": False,
            "validator_account_id32": account.hex(),
            "window_id": window_id,
            "scoring_policy_hash": policy_hash,
            "terminal_stage": terminal_stage,
            "reason_code": reason_code,
            "incident": canonical_incident,
            "announcement_block": announcement,
            "audit_release_snapshot": _snapshot_json(audit_release_snapshot),
            "no_weight_scan_object": scan_ref.model_dump(mode="json"),
        }
    )
    terminal_ref = payloads.add(
        canonical_json_bytes(terminal_evidence), INCIDENT_TERMINAL_MEDIA_TYPE
    )
    object_table = sorted(
        (value[0] for value in payloads.values.values()),
        key=lambda item: bytes.fromhex(item.sha256),
    )
    base: dict[str, Any] = {
        "schema": INCIDENT_BUNDLE_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "bundle_mode": INCIDENT_BUNDLE_MODE,
        "terminal_classification": terminal_classification,
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "weight_submission_performed": False,
        "activation_evidence": False,
        "overall_activation_ready": False,
        "validator_account_id32": account.hex(),
        "window_id": window_id,
        "window_index": window_index,
        "scoring_policy_hash": policy_hash,
        "policy_object": policy_ref.model_dump(mode="json"),
        "software_revisions": dict(sorted(revisions.items())),
        "highest_stage": terminal_stage,
        "terminal_stage": terminal_stage,
        "announcement_block": announcement,
        "audit_release_block": audit_release_snapshot.block_number,
        "audit_release_block_hash": audit_release_snapshot.block_hash,
        "reason_codes": reasons,
        "terminal_evidence_object": terminal_ref.model_dump(mode="json"),
        "no_weight_scan_object": scan_ref.model_dump(mode="json"),
        "stages": [item.model_dump(mode="json") for item in stage_records],
        "objects": [item.model_dump(mode="json") for item in object_table],
    }
    object_bytes = sum(item.size_bytes for item in object_table)
    placeholder = {
        "scheme": signature_scheme,
        "account_id32": account.hex(),
        "signed_digest": "00" * 32,
        "signature": "0x" + "00" * 64,
    }
    manifest_size = _fixed_point_manifest_size(
        base,
        object_bytes=object_bytes,
        signature=placeholder,
    )
    total_bytes = manifest_size + object_bytes
    if manifest_size > MAX_CALIBRATION_MANIFEST_BYTES or total_bytes > maximum_bundle_bytes:
        raise ValueError("incident bundle exceeds its byte ceiling")
    unsigned = {**base, "audit_bundle_bytes": total_bytes}
    digest = hashlib.sha256(_MANIFEST_DOMAIN + canonical_json_bytes(unsigned)).digest()
    signature = manifest_signer(digest)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("incident signer must return an exact 64-byte signature")
    manifest = IncidentBundleManifest.model_validate(
        {
            **unsigned,
            "validator_signature": {
                "scheme": signature_scheme,
                "account_id32": account.hex(),
                "signed_digest": digest.hex(),
                "signature": "0x" + signature.hex(),
            },
        }
    )
    encoded_manifest = canonical_json_bytes(manifest)
    if len(encoded_manifest) != manifest_size:
        raise RuntimeError("signed incident manifest size did not converge")

    store = EvidenceStore(
        root,
        maximum_object_bytes=maximum_object_bytes,
        maximum_manifest_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
        maximum_total_object_bytes=maximum_bundle_bytes,
    )
    for reference, data in payloads.values.values():
        stored = CalibrationObject.from_ref(store.add_bytes(data, reference.media_type))
        if stored != reference:
            raise RuntimeError("stored incident object reference changed")
    return store.write_manifest(manifest.model_dump(mode="json", by_alias=True))


async def verify_incident_bundle(
    root: Path,
    *,
    ports: CalibrationVerificationPorts,
    scan_limits: ScanLimits | None = None,
    maximum_object_bytes: int = MAX_CALIBRATION_OBJECT_BYTES,
    maximum_bundle_bytes: int = MAX_CALIBRATION_BUNDLE_BYTES,
) -> VerifiedIncidentBundle:
    """Verify signature, stage prefix, terminal receipt, and raw no-weight scan."""

    _validate_ceiling(maximum_object_bytes, MAX_CALIBRATION_OBJECT_BYTES, "object")
    _validate_ceiling(maximum_bundle_bytes, MAX_CALIBRATION_BUNDLE_BYTES, "bundle")
    if not isinstance(ports, CalibrationVerificationPorts):
        raise TypeError("ports must be CalibrationVerificationPorts")
    if not isinstance(root, Path) or not root.exists() or root.is_symlink() or not root.is_dir():
        raise ValueError("incident bundle root must be a real existing directory")
    store = EvidenceStore(
        root,
        maximum_object_bytes=maximum_object_bytes,
        maximum_manifest_bytes=MAX_CALIBRATION_MANIFEST_BYTES,
        maximum_total_object_bytes=maximum_bundle_bytes,
    )
    raw_manifest, manifest_bytes = store.load_manifest_with_bytes()
    manifest = IncidentBundleManifest.model_validate(raw_manifest)
    object_bytes = {
        item.sha256: store.read(item.model_dump(mode="json")) for item in manifest.objects
    }
    _require_exact_bundle_paths(root, set(object_bytes))
    calculated = len(manifest_bytes) + sum(item.size_bytes for item in manifest.objects)
    if calculated != manifest.audit_bundle_bytes or calculated > maximum_bundle_bytes:
        raise ValueError("incident bundle byte accounting does not reproduce")
    digest = _manifest_digest(manifest)
    signature = bytes.fromhex(manifest.validator_signature.signature[2:])
    try:
        signature_ok = ports.signature_verifier(
            account_id32=bytes.fromhex(manifest.validator_account_id32),
            scheme=manifest.validator_signature.scheme,
            digest=digest,
            signature=signature,
        )
    except Exception as error:
        raise ValueError("incident manifest signature verification failed") from error
    if signature_ok is not True:
        raise ValueError("incident manifest signature verification failed")

    policy = _parse_canonical(
        object_bytes[manifest.policy_object.sha256], ScoringPolicy, "incident scoring policy"
    )
    if not isinstance(policy, ScoringPolicy) or policy.translation_weights_active:
        raise ValueError("incident bundle does not contain the inactive scoring policy")
    if scoring_policy_hash(policy) != manifest.scoring_policy_hash:
        raise ValueError("incident scoring-policy hash does not reproduce")
    _assert_live_policy_bindings(policy, manifest.software_revisions, (), ports=ports)
    announcement = policy.activation_block + (
        manifest.window_index * policy.clock.window_stride_blocks
    )
    if announcement != manifest.announcement_block:
        raise ValueError("incident announcement block is not policy-derived")

    scan = _parse_canonical(
        object_bytes[manifest.no_weight_scan_object.sha256],
        FinalizedNoWeightScanObject,
        "incident no-weight scan",
    )
    terminal = _parse_canonical(
        object_bytes[manifest.terminal_evidence_object.sha256],
        IncidentTerminalEvidence,
        "incident terminal evidence",
    )
    if not isinstance(scan, FinalizedNoWeightScanObject) or not isinstance(
        terminal, IncidentTerminalEvidence
    ):
        raise RuntimeError("incident typed-object parser returned another model")
    _verify_cross_bindings(manifest, policy, scan, terminal)

    reached: list[CalibrationStageEvidence] = []
    receipts: list[StageReceipt] = []
    previous_digest: str | None = None
    for stage_record in manifest.stages:
        if stage_record.status == "not_reached":
            continue
        if stage_record.evidence_object is None:
            raise RuntimeError("reached incident stage lost its evidence reference")
        evidence = _parse_canonical(
            object_bytes[stage_record.evidence_object.sha256],
            CalibrationStageEvidence,
            "incident stage evidence",
        )
        if not isinstance(evidence, CalibrationStageEvidence):
            raise RuntimeError("incident stage parser returned another model")
        if (
            evidence.stage_id != stage_record.stage_id
            or evidence.window_id != manifest.window_id
            or evidence.scoring_policy_hash != manifest.scoring_policy_hash
            or evidence.previous_stage_evidence_sha256 != previous_digest
            or evidence.replay_hook_id
            != calibration_stage_replay_hook_id(policy, evidence.stage_id)
        ):
            raise ValueError("incident stage evidence chain or policy binding is invalid")
        receipt = _parse_canonical(
            object_bytes[evidence.receipt_object.sha256], StageReceipt, "incident stage receipt"
        )
        if not isinstance(receipt, StageReceipt):
            raise RuntimeError("incident receipt parser returned another model")
        if receipt.window_id != manifest.window_id or receipt.stage != evidence.stage_id:
            raise ValueError("incident receipt binds another stage or window")
        expected_payloads = {item.sha256: item for item in receipt.objects}
        supplied_payloads = {item.sha256: item for item in evidence.payload_objects}
        if {key: value.model_dump(mode="json") for key, value in expected_payloads.items()} != {
            key: value.model_dump(mode="json") for key, value in supplied_payloads.items()
        }:
            raise ValueError("incident stage payloads do not reproduce their receipt")
        hook = ports.stage_replay_hooks.get(evidence.replay_hook_id)
        if hook is None:
            raise ValueError("incident stage replay hook is unavailable")
        try:
            replayed = hook(
                policy=policy,
                evidence=evidence,
                receipt=receipt,
                objects={digest: object_bytes[digest] for digest in supplied_payloads},
            )
        except Exception as error:
            raise ValueError("incident stage evidence replay failed") from error
        if replayed is not True:
            raise ValueError("incident stage evidence replay failed")
        reached.append(evidence)
        receipts.append(receipt)
        previous_digest = stage_record.evidence_object.sha256

    if not receipts or receipts[-1].stage != manifest.terminal_stage:
        raise ValueError("incident terminal receipt is not the highest reached stage")
    if any(_terminal_receipt_or_none(item) is not None for item in receipts[:-1]):
        raise ValueError("incident prefix contains an earlier terminal receipt")
    receipt_terminal = _terminal_receipt(receipts[-1])
    expected_incident = (
        terminal.incident.model_dump(mode="json") if terminal.incident is not None else None
    )
    if (
        receipt_terminal["outcome"] != manifest.terminal_classification
        or receipt_terminal["reason_code"] != terminal.reason_code
        or receipt_terminal["audit_release_block"] != manifest.audit_release_block
        or receipt_terminal["incident"] != expected_incident
    ):
        raise ValueError("incident terminal receipt does not reproduce its manifest")

    replayed_interval = await replay_finalized_no_weight_scan(
        scan,
        object_bytes=object_bytes,
        policy=policy,
        ports=ports,
        scan_limits=scan_limits,
    )
    _require_exact_references(manifest, scan, terminal, tuple(reached))
    return VerifiedIncidentBundle(
        manifest=manifest,
        policy=policy,
        terminal=terminal,
        no_weight_scan=scan,
        replayed_interval=replayed_interval,
        reached_stages=tuple(reached),
    )


def _verify_cross_bindings(
    manifest: IncidentBundleManifest,
    policy: ScoringPolicy,
    scan: FinalizedNoWeightScanObject,
    terminal: IncidentTerminalEvidence,
) -> None:
    common = (
        manifest.validator_account_id32,
        manifest.window_id,
        manifest.scoring_policy_hash,
        manifest.netuid,
        manifest.mechanism_id,
    )
    if common != (
        scan.validator_account_id32,
        scan.window_id,
        scan.scoring_policy_hash,
        scan.netuid,
        scan.mechanism_id,
    ) or common != (
        terminal.validator_account_id32,
        terminal.window_id,
        terminal.scoring_policy_hash,
        terminal.netuid,
        terminal.mechanism_id,
    ):
        raise ValueError("incident manifest, scan, and terminal bindings disagree")
    if manifest.policy_object != scan.policy_object or manifest.scoring_policy_hash != (
        scoring_policy_hash(policy)
    ):
        raise ValueError("incident scan references another scoring policy")
    if (
        scan.window_index != manifest.window_index
        or scan.announcement_block != manifest.announcement_block
        or terminal.announcement_block != manifest.announcement_block
    ):
        raise ValueError("incident policy-derived boundaries disagree")
    if (scan.end_block, scan.end_block_hash) != (
        manifest.audit_release_block,
        manifest.audit_release_block_hash,
    ) or terminal.audit_release != scan.blocks[-1].snapshot.to_evidence():
        raise ValueError("incident scan does not end at finalized audit release")
    if (
        terminal.no_weight_scan_object != manifest.no_weight_scan_object
        or terminal.terminal_stage != manifest.terminal_stage
        or terminal.terminal_classification != manifest.terminal_classification
        or terminal.reason_code not in manifest.reason_codes
    ):
        raise ValueError("incident terminal and manifest disagree")


def _require_exact_references(
    manifest: IncidentBundleManifest,
    scan: FinalizedNoWeightScanObject,
    terminal: IncidentTerminalEvidence,
    stages: tuple[CalibrationStageEvidence, ...],
) -> None:
    references = {
        manifest.policy_object.sha256,
        manifest.no_weight_scan_object.sha256,
        manifest.terminal_evidence_object.sha256,
        terminal.no_weight_scan_object.sha256,
        scan.policy_object.sha256,
    }
    references.update(
        item.evidence_object.sha256 for item in manifest.stages if item.evidence_object is not None
    )
    for stage in stages:
        references.add(stage.receipt_object.sha256)
        references.update(item.sha256 for item in stage.payload_objects)
    for block in scan.blocks:
        references.update(item.sha256 for item in block.referenced_objects())
    if references != {item.sha256 for item in manifest.objects}:
        raise ValueError("incident object table is not the exact referenced-object union")


def _terminal_receipt(receipt: StageReceipt) -> dict[str, Any]:
    result = _terminal_receipt_or_none(receipt)
    if result is None:
        raise ValueError("highest reached incident receipt is not terminal")
    return result


def _terminal_receipt_or_none(receipt: StageReceipt) -> dict[str, Any] | None:
    metadata = receipt.metadata
    if metadata.get("schema") != "umi-validator-adapter-result/1":
        raise ValueError("stage receipt lacks canonical adapter metadata")
    kind = metadata.get("kind")
    terminal = metadata.get("terminal")
    if kind == "completion":
        if terminal is not None:
            raise ValueError("completion receipt carries terminal metadata")
        return None
    if kind != "terminal" or not isinstance(terminal, Mapping):
        raise ValueError("stage receipt has invalid terminal metadata")
    required = {"outcome", "reason_code", "audit_release_block", "incident", "pause_scopes"}
    if set(terminal) != required:
        raise ValueError("terminal receipt has an unexpected shape")
    outcome = terminal.get("outcome")
    reason = terminal.get("reason_code")
    release = terminal.get("audit_release_block")
    if outcome not in {"skipped", "void", "failed"}:
        raise ValueError("incident receipt has a non-incident outcome")
    if not isinstance(reason, str):
        raise ValueError("incident receipt lacks a reason code")
    _reason(reason)
    if isinstance(release, bool) or not isinstance(release, int) or release <= 0:
        raise ValueError("incident receipt has an invalid audit-release block")
    incident = terminal.get("incident")
    if incident is not None:
        incident = _canonical_incident(incident, reason_code=reason)
    scopes = terminal.get("pause_scopes")
    if not isinstance(scopes, list) or any(not isinstance(item, str) for item in scopes):
        raise ValueError("incident receipt pause scopes are invalid")
    return {
        "outcome": outcome,
        "reason_code": reason,
        "audit_release_block": release,
        "incident": incident,
        "pause_scopes": list(scopes),
    }


def _canonical_incident(
    value: Mapping[str, Any] | None,
    *,
    reason_code: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "incident_id",
        "reason_code",
        "metadata",
    }:
        raise ValueError("incident metadata has an unexpected shape")
    model = IncidentSpecObject.model_validate(value)
    if model.reason_code != reason_code:
        raise ValueError("incident and terminal reason codes disagree")
    return model.model_dump(mode="json")


def _manifest_digest(value: IncidentBundleManifest | Mapping[str, Any]) -> bytes:
    unsigned = (
        value.model_dump(mode="json", by_alias=True)
        if isinstance(value, IncidentBundleManifest)
        else dict(value)
    )
    unsigned.pop("validator_signature", None)
    return hashlib.sha256(_MANIFEST_DOMAIN + canonical_json_bytes(unsigned)).digest()


def _snapshot_json(snapshot: FinalizedSnapshotRef) -> dict[str, JsonValue]:
    if not isinstance(snapshot, FinalizedSnapshotRef):
        raise TypeError("snapshot must be FinalizedSnapshotRef")
    return {
        "block_number": snapshot.block_number,
        "block_hash": snapshot.block_hash,
        "parent_hash": snapshot.parent_hash,
        "state_root": snapshot.state_root,
    }


def _snapshot_from_json(value: Mapping[str, JsonValue]) -> FinalizedSnapshotRef:
    if not isinstance(value, Mapping) or set(value) != {
        "block_number",
        "block_hash",
        "parent_hash",
        "state_root",
    }:
        raise ValueError("incident release snapshot is malformed")
    return FinalizedSnapshotRef(
        block_number=value["block_number"],
        block_hash=value["block_hash"],
        parent_hash=value["parent_hash"],
        state_root=value["state_root"],
    )


def _reason(value: str) -> str:
    if not isinstance(value, str) or _REASON_RE.fullmatch(value) is None:
        raise ValueError("incident reason code is not canonical")
    return value


def _validate_write_inputs(
    *,
    root: Path,
    policy: ScoringPolicy,
    audit_release_snapshot: FinalizedSnapshotRef,
    maximum_object_bytes: int,
    maximum_bundle_bytes: int,
) -> None:
    _validate_ceiling(maximum_object_bytes, MAX_CALIBRATION_OBJECT_BYTES, "object")
    _validate_ceiling(maximum_bundle_bytes, MAX_CALIBRATION_BUNDLE_BYTES, "bundle")
    if not isinstance(root, Path):
        raise TypeError("incident bundle root must be a Path")
    if root.exists() and (root.is_symlink() or not root.is_dir() or any(root.iterdir())):
        raise FileExistsError("incident bundle output must be an empty directory")
    if not isinstance(policy, ScoringPolicy) or policy.translation_weights_active:
        raise ValueError("incident bundle requires the inactive scoring policy")
    if not isinstance(audit_release_snapshot, FinalizedSnapshotRef):
        raise TypeError("incident audit release must be a finalized snapshot")


def _validate_ceiling(value: int, maximum: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"incident {label} ceiling must be an integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"incident {label} ceiling exceeds its hard protocol bound")


__all__ = [
    "INCIDENT_BUNDLE_MODE",
    "INCIDENT_BUNDLE_SCHEMA",
    "INCIDENT_TERMINAL_MEDIA_TYPE",
    "INCIDENT_TERMINAL_SCHEMA",
    "IncidentBundleManifest",
    "IncidentSpecObject",
    "IncidentStageRecord",
    "IncidentTerminalEvidence",
    "VerifiedIncidentBundle",
    "verify_incident_bundle",
    "write_incident_bundle",
]
