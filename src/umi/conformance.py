"""Executable, fail-closed conformance fixtures for a live-shadow release.

Fixture files are inputs, never attestations.  This module accepts only seven
versioned canonical schemas, executes the production primitives and pinned
executables named by the release, and emits a deterministic report only after
every required positive and negative case passes.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, ValidationError, model_validator
from typing_extensions import Self

from .chain_evidence import (
    CoreObservation,
    CorePin,
    FinalizedBlockRecord,
    FinalizedCallRecord,
    FinalizedSnapshotRef,
    RuntimeSpecObservation,
    RuntimeSpecPin,
    assert_shadow_no_weight_interval,
    build_sha256_commitment_call,
    require_core_pin,
    require_runtime_spec_pin,
)
from .crypto import parse_sealed_response
from .media import MediaConformanceError, frame_digest, inspect_media_pinned
from .pinned_artifact import PinnedArtifact, PinnedArtifactError, staged_pinned_artifacts
from .protocol import Hex32, StrictProtocolModel, base64url_decode, canonical_json_bytes
from .scoring import grapheme_clusters, normalization_trace
from .substrate_proof import SubprocessStorageProofVerifier, SubstrateProofVerifierError
from .validator_chain import FinalizedProofCollector, FinalizedRuntimePin
from .validator_chain_scan import (
    VerifiedFinalizedBlockIdentity,
    finalized_block_body_sha256,
)
from .validator_chain_scan_port import (
    LiveFinalizedBlockScanPort,
    LiveFinalizedBlockScanPortError,
)
from .window import WindowClock, ceil_div

NORMALIZATION_SCHEMA = "umi-normalization-conformance-fixtures/1"
MEDIA_SCHEMA = "umi-media-conformance-fixtures/1"
TIMELOCK_SCHEMA = "umi-timelock-conformance-fixtures/1"
CHAIN_SCHEMA = "umi-chain-conformance-fixtures/1"
LIVE_CHAIN_SCHEMA = "umi-live-chain-conformance-fixtures/1"
STORAGE_PROOF_SCHEMA = "umi-storage-proof-conformance-fixtures/1"
FINALITY_SCHEMA = "umi-grandpa-finality-fixtures/1"
REPORT_SCHEMA = "umi-conformance-execution-report/1"
FINALITY_RESULT_SCHEMA = "umi-grandpa-finality-conformance-result/1"

_CATEGORIES = (
    "normalization",
    "media",
    "timelock",
    "chain",
    "live_chain",
    "storage_proof",
    "finality",
)
_MAX_FIXTURE_BYTES = 20 * 1024 * 1024
_MAX_TEXT_BYTES = 16 * 1024
_MAX_MEDIA_BYTES = 16 * 1024 * 1024
_MAX_FINALITY_OUTPUT_BYTES = 64 * 1024
_MAX_BINARY_BYTES = 512 * 1024 * 1024
_FINNEY_CHECKPOINT_CANONICAL_SHA256 = (
    "b3f2191587a21b57fbe9f56e3a8245e852c06cdebb0a4dd0b878a5242d9a8311"
)
_FINNEY_SOURCE_REVISION = "da06f033663896ef2fdbbfc3ecc68ca908fba0f5"

_NORMALIZATION_CASES = (
    "combining-grapheme-positive",
    "nfkc-tokenization-positive",
    "apostrophe-boundary-positive",
    "non-string-input-negative",
)
_MEDIA_CASES = (
    "pinned-decode-positive",
    "truncated-video-negative",
    "wrong-ffmpeg-pin-negative",
    "wrong-rgb-frame-size-negative",
)
_TIMELOCK_CASES = (
    "strict-portable-positive",
    "wrong-round-negative",
    "wrong-digest-negative",
    "trailing-byte-negative",
    "padded-base64-negative",
)
_CHAIN_CASES = (
    "window-schedule-positive",
    "sha256-call-positive",
    "huge-ceil-div-positive",
    "wrong-netuid-negative",
)
_LIVE_CHAIN_CASES = (
    "rpc-block-binding-positive",
    "runtime-pin-positive",
    "no-weight-scan-positive",
    "header-mismatch-negative",
    "weight-call-negative",
)
_STORAGE_CASES = (
    "finney-membership-positive",
    "empty-extrinsics-root-positive",
    "wrong-value-negative",
    "missing-node-negative",
    "changed-node-negative",
    "wrong-extrinsics-root-negative",
)
_FINALITY_CASES = (
    "checkpoint-header-positive",
    "contiguous-first-positive",
    "contiguous-second-positive",
    "finney-checkpoint-positive",
    "missing-prefix-negative",
    "truncated-header-negative",
)


class ConformanceError(RuntimeError):
    """A stable failure at the fixture execution boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _bounded_text(value: str) -> str:
    if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise ValueError("fixture text exceeds its byte limit")
    return value


BoundedText = Annotated[
    str,
    Field(max_length=_MAX_TEXT_BYTES),
    AfterValidator(_bounded_text),
]
CaseId = Annotated[str, Field(min_length=1, max_length=128)]
HexBytes = Annotated[
    str,
    Field(pattern=r"^0x(?:[0-9a-f]{2})*$", max_length=4 * 1024 * 1024 + 2),
]
BlockHash = Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]


class NormalizationExpected(StrictProtocolModel):
    normalized: BoundedText
    tokens: Annotated[list[BoundedText], Field(max_length=512)]
    graphemes_without_whitespace: Annotated[list[BoundedText], Field(max_length=4_096)]


class NormalizationCase(StrictProtocolModel):
    case_id: Literal["nfkc-tokenization-positive", "apostrophe-boundary-positive"]
    text: BoundedText
    expected: NormalizationExpected


class SegmentationCase(StrictProtocolModel):
    case_id: Literal["combining-grapheme-positive"]
    text: BoundedText
    expected_graphemes: Annotated[list[BoundedText], Field(min_length=1, max_length=4_096)]


class NormalizationFixtures(StrictProtocolModel):
    schema_: Literal[NORMALIZATION_SCHEMA] = Field(alias="schema")
    required_case_ids: Annotated[list[CaseId], Field(min_length=4, max_length=4)]
    normalization_cases: Annotated[list[NormalizationCase], Field(min_length=2, max_length=2)]
    segmentation_cases: Annotated[list[SegmentationCase], Field(min_length=1, max_length=1)]

    @model_validator(mode="after")
    def validate_cases(self) -> Self:
        _require_case_ids(self.required_case_ids, _NORMALIZATION_CASES)
        ids = [case.case_id for case in self.normalization_cases]
        if ids != ["apostrophe-boundary-positive", "nfkc-tokenization-positive"]:
            raise ValueError("normalization cases must be complete and sorted")
        return self


class MediaExpected(StrictProtocolModel):
    video_sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_MEDIA_BYTES)]
    duration_numerator: Annotated[int, Field(gt=0)]
    duration_denominator: Annotated[int, Field(gt=0)]
    width: Annotated[int, Field(gt=0, le=1_280)]
    height: Annotated[int, Field(gt=0, le=720)]
    frame_rate_numerator: Annotated[int, Field(gt=0)]
    frame_rate_denominator: Annotated[int, Field(gt=0)]
    frame_digest: Hex32
    frame_count: Annotated[int, Field(gt=0, le=450)]


class MediaFixtures(StrictProtocolModel):
    schema_: Literal[MEDIA_SCHEMA] = Field(alias="schema")
    required_case_ids: Annotated[list[CaseId], Field(min_length=4, max_length=4)]
    video_base64url: Annotated[str, Field(min_length=1, max_length=24 * 1024 * 1024)]
    expected: MediaExpected

    @model_validator(mode="after")
    def validate_media(self) -> Self:
        _require_case_ids(self.required_case_ids, _MEDIA_CASES)
        raw = base64url_decode(self.video_base64url)
        if not raw or len(raw) > _MAX_MEDIA_BYTES:
            raise ValueError("fixture video exceeds its byte limit")
        if len(raw) != self.expected.size_bytes:
            raise ValueError("fixture video size does not match its expectation")
        if hashlib.sha256(raw).hexdigest() != self.expected.video_sha256:
            raise ValueError("fixture video digest does not match its expectation")
        return self


class TimelockFixtures(StrictProtocolModel):
    schema_: Literal[TIMELOCK_SCHEMA] = Field(alias="schema")
    required_case_ids: Annotated[list[CaseId], Field(min_length=5, max_length=5)]
    portable_base64url: Annotated[str, Field(min_length=1, max_length=2 * 1024 * 1024)]
    portable_sha256: Hex32
    reveal_round: Annotated[int, Field(gt=0, le=(1 << 64) - 1)]

    @model_validator(mode="after")
    def validate_portable(self) -> Self:
        _require_case_ids(self.required_case_ids, _TIMELOCK_CASES)
        raw = base64url_decode(self.portable_base64url)
        if not raw or len(raw) > 1024 * 1024:
            raise ValueError("portable timelock exceeds its byte limit")
        if hashlib.sha256(raw).hexdigest() != self.portable_sha256:
            raise ValueError("portable timelock digest does not match")
        return self


class ClockFixture(StrictProtocolModel):
    activation_block: Annotated[int, Field(ge=0)]
    window_stride_blocks: Annotated[int, Field(gt=0)]
    proposal_blocks: Annotated[int, Field(gt=0)]
    anchor_blocks: Annotated[int, Field(gt=0)]
    target_block_interval_seconds: Annotated[int, Field(gt=0)]
    selection_finality_buffer_seconds: Annotated[int, Field(gt=0)]
    issue_allowance_seconds: Annotated[int, Field(gt=0)]
    response_window_seconds: Annotated[int, Field(gt=0)]
    delivery_grace_seconds: Annotated[int, Field(gt=0)]
    reveal_margin_seconds: Annotated[int, Field(gt=0)]


class WindowInputFixture(StrictProtocolModel):
    index: Annotated[int, Field(ge=0)]
    netuid: Literal[78]
    announcement_block_hash: BlockHash
    announcement_timestamp_ms: Annotated[int, Field(gt=0)]
    scoring_policy_hash: Hex32


class ExpectedWindowFixture(StrictProtocolModel):
    index: Annotated[int, Field(ge=0)]
    announcement_block: Annotated[int, Field(ge=0)]
    proposal_close_block: Annotated[int, Field(gt=0)]
    closing_block: Annotated[int, Field(gt=0)]
    selection_round: Annotated[int, Field(gt=0, le=(1 << 64) - 1)]
    issue_close_round: Annotated[int, Field(gt=0, le=(1 << 64) - 1)]
    response_close_round: Annotated[int, Field(gt=0, le=(1 << 64) - 1)]
    response_deadline_blocks: Annotated[int, Field(gt=0)]
    reveal_round: Annotated[int, Field(gt=0, le=(1 << 64) - 1)]
    window_id: Hex32


class ChainFixtures(StrictProtocolModel):
    schema_: Literal[CHAIN_SCHEMA] = Field(alias="schema")
    required_case_ids: Annotated[list[CaseId], Field(min_length=4, max_length=4)]
    clock: ClockFixture
    window_input: WindowInputFixture
    expected_window: ExpectedWindowFixture
    commitment_sha256: Hex32
    huge_ceil_numerator: Annotated[int, Field(gt=0)]
    huge_ceil_denominator: Annotated[int, Field(gt=0)]
    huge_ceil_expected: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_cases(self) -> Self:
        _require_case_ids(self.required_case_ids, _CHAIN_CASES)
        return self


class LiveChainFixtures(StrictProtocolModel):
    schema_: Literal[LIVE_CHAIN_SCHEMA] = Field(alias="schema")
    required_case_ids: Annotated[list[CaseId], Field(min_length=5, max_length=5)]
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    parent_hash: BlockHash
    parent_parent_hash: BlockHash
    state_root: BlockHash
    extrinsics_root: BlockHash
    extrinsics: Annotated[list[HexBytes], Field(min_length=1, max_length=32)]
    expected_body_sha256: Hex32
    finality_verifier_sha256: Hex32
    finality_evidence_sha256: Hex32
    validator_account_id32: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    runtime_spec_version: Annotated[int, Field(gt=0)]
    metadata_sha256: Hex32
    core_revision: Annotated[str, Field(min_length=1, max_length=128)]
    core_content_sha256: Hex32

    @model_validator(mode="after")
    def validate_fixture(self) -> Self:
        _require_case_ids(self.required_case_ids, _LIVE_CHAIN_CASES)
        if self.block_hash == self.parent_hash or self.parent_hash == self.parent_parent_hash:
            raise ValueError("live-chain fixture headers are not distinct")
        extrinsics = tuple(bytes.fromhex(value[2:]) for value in self.extrinsics)
        if finalized_block_body_sha256(extrinsics) != self.expected_body_sha256:
            raise ValueError("live-chain body digest expectation is wrong")
        return self


class StorageItemFixture(StrictProtocolModel):
    key: HexBytes
    value: HexBytes | None


class StorageVectorFixture(StrictProtocolModel):
    schema_: Literal["umi-substrate-proof-fixture/1"] = Field(alias="schema")
    source: Annotated[str, Field(min_length=1, max_length=512)]
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    state_version: Literal[1]
    state_root: BlockHash
    items: Annotated[list[StorageItemFixture], Field(min_length=1, max_length=64)]
    proof: Annotated[list[HexBytes], Field(min_length=2, max_length=4_096)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        keys = [bytes.fromhex(item.key[2:]) for item in self.items]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("storage fixture items must be unique and sorted")
        nodes = [bytes.fromhex(item[2:]) for item in self.proof]
        if any(not node or len(node) > 2 * 1024 * 1024 for node in nodes):
            raise ValueError("storage fixture proof node is invalid")
        if len(set(nodes)) != len(nodes) or sum(map(len, nodes)) > 32 * 1024 * 1024:
            raise ValueError("storage fixture proof is duplicated or oversized")
        return self


class StorageProofFixtures(StrictProtocolModel):
    schema_: Literal[STORAGE_PROOF_SCHEMA] = Field(alias="schema")
    required_case_ids: Annotated[list[CaseId], Field(min_length=6, max_length=6)]
    vector: StorageVectorFixture
    empty_extrinsics_root: BlockHash

    @model_validator(mode="after")
    def validate_cases(self) -> Self:
        _require_case_ids(self.required_case_ids, _STORAGE_CASES)
        return self


class FinalityHeaderFixture(StrictProtocolModel):
    hash: BlockHash
    number: Annotated[int, Field(gt=0)]
    scale_header: HexBytes


class FinalityContiguousFixture(StrictProtocolModel):
    first: FinalityHeaderFixture
    first_timestamp_ms: Annotated[int, Field(gt=0)]
    second: FinalityHeaderFixture
    second_timestamp_ms: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_continuity_shape(self) -> Self:
        if self.second.number != self.first.number + 1:
            raise ValueError("finality headers must use consecutive block numbers")
        if self.second_timestamp_ms < self.first_timestamp_ms:
            raise ValueError("finality fixture timestamp rolls back")
        return self


class FinalityCheckpointReference(StrictProtocolModel):
    path: Literal["finney-grandpa-checkpoint-v1.json"]
    sha256: Literal[_FINNEY_CHECKPOINT_CANONICAL_SHA256]
    source_revision: Literal[_FINNEY_SOURCE_REVISION]


class FinalityFixtures(StrictProtocolModel):
    schema_: Literal[FINALITY_SCHEMA] = Field(alias="schema")
    checkpoint: FinalityHeaderFixture
    malformed_headers: Annotated[list[BoundedText], Field(min_length=2, max_length=2)]
    valid_contiguous: FinalityContiguousFixture
    finney_checkpoint_fixture: FinalityCheckpointReference

    @model_validator(mode="after")
    def validate_cases(self) -> Self:
        if self.malformed_headers != ["0x00", "00"]:
            raise ValueError("finality negative header cases are incomplete or out of order")
        return self


class FinalitySelfTestReport(StrictProtocolModel):
    schema_: Literal[FINALITY_RESULT_SCHEMA] = Field(alias="schema")
    case_ids: Annotated[list[CaseId], Field(min_length=6, max_length=6)]
    fixture_canonical_sha256: Hex32
    finney_checkpoint_canonical_sha256: Hex32
    ok: Literal[True]

    @model_validator(mode="after")
    def validate_cases(self) -> Self:
        _require_case_ids(self.case_ids, _FINALITY_CASES)
        return self


class ConformanceCaseResult(StrictProtocolModel):
    category: Literal[
        "normalization",
        "media",
        "timelock",
        "chain",
        "live_chain",
        "storage_proof",
        "finality",
    ]
    case_id: Annotated[str, Field(min_length=1, max_length=128)]
    output_sha256: Hex32


class ConformanceExecutionReport(StrictProtocolModel):
    schema_: Literal[REPORT_SCHEMA] = Field(alias="schema")
    verified: Literal[True]
    fixture_sha256_by_category: dict[str, Hex32]
    binary_sha256_by_name: dict[str, Hex32]
    cases: Annotated[list[ConformanceCaseResult], Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def validate_complete(self) -> Self:
        if tuple(sorted(self.fixture_sha256_by_category)) != tuple(sorted(_CATEGORIES)):
            raise ValueError("execution report does not cover every fixture category")
        if tuple(sorted(self.binary_sha256_by_name)) != (
            "ffmpeg",
            "ffprobe",
            "finality_verifier",
            "storage_proof_verifier",
        ):
            raise ValueError("execution report does not cover every executable")
        expected = _all_case_keys()
        actual = tuple((item.category, item.case_id) for item in self.cases)
        if actual != expected:
            raise ValueError("execution report case coverage is incomplete or out of order")
        return self


@dataclass(frozen=True, slots=True)
class ConformanceFixturePaths:
    normalization: Path
    media: Path
    timelock: Path
    chain: Path
    live_chain: Path
    storage_proof: Path
    finality: Path

    def __post_init__(self) -> None:
        paths = tuple(getattr(self, category) for category in _CATEGORIES)
        if any(
            not isinstance(path, Path)
            or not path.is_absolute()
            or path != Path(os.path.normpath(path))
            for path in paths
        ):
            raise ValueError("conformance fixture paths must be absolute normalized Path values")
        if len(set(paths)) != len(paths):
            raise ValueError("conformance fixture paths must be distinct")


@dataclass(frozen=True, slots=True)
class ConformanceBinaryPins:
    ffmpeg_path: Path
    ffmpeg_sha256: str
    ffprobe_path: Path
    ffprobe_sha256: str
    storage_proof_verifier_path: Path
    storage_proof_verifier_sha256: str
    finality_verifier_path: Path
    finality_verifier_sha256: str

    def __post_init__(self) -> None:
        paths: list[Path] = []
        for name in (
            "ffmpeg",
            "ffprobe",
            "storage_proof_verifier",
            "finality_verifier",
        ):
            path = getattr(self, f"{name}_path")
            digest = getattr(self, f"{name}_sha256")
            if (
                not isinstance(path, Path)
                or not path.is_absolute()
                or path != Path(os.path.normpath(path))
            ):
                raise ValueError(f"{name}_path must be an absolute normalized Path")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError(f"{name}_sha256 must be lowercase SHA-256 hexadecimal")
            paths.append(path)
        if len(set(paths)) != len(paths):
            raise ValueError("conformance executable paths must be distinct")


@dataclass(frozen=True, slots=True)
class ConformanceExecution:
    report: ConformanceExecutionReport
    canonical_report_bytes: bytes
    report_sha256: str

    @property
    def verified(self) -> bool:
        return self.report.verified


def execute_conformance_suite(
    fixture_paths: ConformanceFixturePaths,
    *,
    binaries: ConformanceBinaryPins,
) -> ConformanceExecution:
    """Execute all required fixtures or raise :class:`ConformanceError`."""

    if not isinstance(fixture_paths, ConformanceFixturePaths):
        raise TypeError("fixture_paths must be ConformanceFixturePaths")
    if not isinstance(binaries, ConformanceBinaryPins):
        raise TypeError("binaries must be ConformanceBinaryPins")
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise ConformanceError("async_context_unsupported")

    models: dict[str, StrictProtocolModel] = {}
    fixture_digests: dict[str, str] = {}
    schema_by_category: dict[str, type[StrictProtocolModel]] = {
        "normalization": NormalizationFixtures,
        "media": MediaFixtures,
        "timelock": TimelockFixtures,
        "chain": ChainFixtures,
        "live_chain": LiveChainFixtures,
        "storage_proof": StorageProofFixtures,
        "finality": FinalityFixtures,
    }
    for category in _CATEGORIES:
        raw, model = _read_canonical_model(
            getattr(fixture_paths, category),
            schema_by_category[category],
            label=category,
        )
        models[category] = model
        fixture_digests[category] = hashlib.sha256(raw).hexdigest()

    _verify_all_binary_pins(binaries)
    observed: dict[tuple[str, str], Mapping[str, Any]] = {}
    _execute_normalization(_model(models, "normalization", NormalizationFixtures), observed)
    _execute_media(_model(models, "media", MediaFixtures), binaries, observed)
    _execute_timelock(_model(models, "timelock", TimelockFixtures), observed)
    _execute_chain(_model(models, "chain", ChainFixtures), observed)
    _execute_live_chain(_model(models, "live_chain", LiveChainFixtures), observed)
    _execute_storage(_model(models, "storage_proof", StorageProofFixtures), binaries, observed)
    _execute_finality(_model(models, "finality", FinalityFixtures), binaries, observed)

    expected = _all_case_keys()
    if tuple(observed) != expected:
        raise ConformanceError("case_execution_incomplete")
    case_results = [
        ConformanceCaseResult(
            category=category,
            case_id=case_id,
            output_sha256=hashlib.sha256(
                canonical_json_bytes(
                    {
                        "category": category,
                        "case_id": case_id,
                        "observed": observed[(category, case_id)],
                    }
                )
            ).hexdigest(),
        )
        for category, case_id in expected
    ]
    report = ConformanceExecutionReport(
        schema=REPORT_SCHEMA,
        verified=True,
        fixture_sha256_by_category=fixture_digests,
        binary_sha256_by_name={
            "ffmpeg": binaries.ffmpeg_sha256,
            "ffprobe": binaries.ffprobe_sha256,
            "finality_verifier": binaries.finality_verifier_sha256,
            "storage_proof_verifier": binaries.storage_proof_verifier_sha256,
        },
        cases=case_results,
    )
    encoded = canonical_json_bytes(report)
    return ConformanceExecution(
        report=report,
        canonical_report_bytes=encoded,
        report_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _model(
    values: Mapping[str, StrictProtocolModel],
    category: str,
    expected: type[Any],
) -> Any:
    value = values[category]
    if not isinstance(value, expected):
        raise AssertionError("validated fixture model changed type")
    return value


def _require_case_ids(actual: list[str], expected: tuple[str, ...]) -> None:
    if tuple(actual) != expected:
        raise ValueError("required fixture case IDs are incomplete or out of order")


def _all_case_keys() -> tuple[tuple[str, str], ...]:
    groups = (
        ("normalization", _NORMALIZATION_CASES),
        ("media", _MEDIA_CASES),
        ("timelock", _TIMELOCK_CASES),
        ("chain", _CHAIN_CASES),
        ("live_chain", _LIVE_CHAIN_CASES),
        ("storage_proof", _STORAGE_CASES),
        ("finality", _FINALITY_CASES),
    )
    return tuple((category, case_id) for category, ids in groups for case_id in ids)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_canonical_model(
    path: Path,
    model_type: type[StrictProtocolModel],
    *,
    label: str,
) -> tuple[bytes, StrictProtocolModel]:
    raw = _read_owned_file(path, maximum_bytes=_MAX_FIXTURE_BYTES, executable=False, label=label)
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
        model = model_type.model_validate(document)
    except (UnicodeDecodeError, ValueError, ValidationError) as error:
        raise ConformanceError(f"{label}_fixture_invalid") from error
    if canonical_json_bytes(model) != raw:
        raise ConformanceError(f"{label}_fixture_noncanonical")
    return raw, model


def _read_owned_file(path: Path, *, maximum_bytes: int, executable: bool, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConformanceError(f"{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > maximum_bytes
            or (executable and not before.st_mode & stat.S_IXUSR)
        ):
            raise ConformanceError(f"{label}_unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ConformanceError(f"{label}_size_limit")
        after = os.fstat(descriptor)
        identity = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns")
        if total != before.st_size or any(
            getattr(before, name) != getattr(after, name) for name in identity
        ):
            raise ConformanceError(f"{label}_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_all_binary_pins(pins: ConformanceBinaryPins) -> None:
    for name in ("ffmpeg", "ffprobe", "storage_proof_verifier", "finality_verifier"):
        raw = _read_owned_file(
            getattr(pins, f"{name}_path"),
            maximum_bytes=_MAX_BINARY_BYTES,
            executable=True,
            label=name,
        )
        if hashlib.sha256(raw).hexdigest() != getattr(pins, f"{name}_sha256"):
            raise ConformanceError(f"{name}_digest_mismatch")


def _record(
    observed: dict[tuple[str, str], Mapping[str, Any]],
    category: str,
    case_id: str,
    value: Mapping[str, Any],
) -> None:
    key = (category, case_id)
    if key in observed:
        raise AssertionError("conformance case executed twice")
    canonical_json_bytes(dict(value))
    observed[key] = dict(value)


def _require_expected_output(actual: Any, expected: Any, *, reason_code: str) -> None:
    if actual != expected:
        raise ConformanceError(reason_code)


def _execute_normalization(
    fixture: NormalizationFixtures,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    segment = fixture.segmentation_cases[0]
    actual_graphemes = list(grapheme_clusters(segment.text))
    _require_expected_output(
        actual_graphemes,
        segment.expected_graphemes,
        reason_code="normalization_output_mismatch",
    )
    _record(
        observed,
        "normalization",
        segment.case_id,
        {"graphemes": actual_graphemes},
    )

    results: dict[str, dict[str, Any]] = {}
    for case in fixture.normalization_cases:
        trace = normalization_trace(case.text)
        result = {
            "normalized": trace.normalized,
            "tokens": list(trace.tokens),
            "graphemes_without_whitespace": list(trace.graphemes_without_whitespace),
        }
        expected = case.expected.model_dump(mode="json")
        _require_expected_output(
            result,
            expected,
            reason_code="normalization_output_mismatch",
        )
        results[case.case_id] = result

    for case_id in ("nfkc-tokenization-positive", "apostrophe-boundary-positive"):
        _record(observed, "normalization", case_id, results[case_id])

    try:
        normalization_trace(None)  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise ConformanceError("normalization_negative_case_failed")
    _record(
        observed,
        "normalization",
        "non-string-input-negative",
        {"rejected": True, "reason": "text_must_be_str"},
    )


def _execute_media(
    fixture: MediaFixtures,
    pins: ConformanceBinaryPins,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    raw = base64url_decode(fixture.video_base64url)
    with tempfile.TemporaryDirectory(prefix="umi-conformance-media-") as directory:
        path = Path(directory) / "fixture.mp4"
        path.write_bytes(raw)
        result = inspect_media_pinned(
            path,
            expected_ffmpeg_sha256=pins.ffmpeg_sha256,
            expected_ffprobe_sha256=pins.ffprobe_sha256,
            ffmpeg=os.fspath(pins.ffmpeg_path),
            ffprobe=os.fspath(pins.ffprobe_path),
            maximum_clip_size=_MAX_MEDIA_BYTES,
        )
        actual = {
            "video_sha256": result.video_sha256,
            "size_bytes": result.profile.size_bytes,
            "duration_numerator": result.profile.duration.numerator,
            "duration_denominator": result.profile.duration.denominator,
            "width": result.profile.width,
            "height": result.profile.height,
            "frame_rate_numerator": result.profile.frame_rate.numerator,
            "frame_rate_denominator": result.profile.frame_rate.denominator,
            "frame_digest": result.frames.frame_digest,
            "frame_count": result.frames.frame_count,
        }
        if actual != fixture.expected.model_dump(mode="json"):
            raise ConformanceError("media_output_mismatch")
        if (
            not result.frames.executables_content_pinned
            or result.frames.decoder_sha256 != pins.ffmpeg_sha256
            or result.frames.probe_sha256 != pins.ffprobe_sha256
        ):
            raise ConformanceError("media_binary_binding_mismatch")
        _record(observed, "media", "pinned-decode-positive", actual)

        truncated = Path(directory) / "truncated.mp4"
        truncated.write_bytes(raw[: max(1, len(raw) // 2)])
        try:
            inspect_media_pinned(
                truncated,
                expected_ffmpeg_sha256=pins.ffmpeg_sha256,
                expected_ffprobe_sha256=pins.ffprobe_sha256,
                ffmpeg=os.fspath(pins.ffmpeg_path),
                ffprobe=os.fspath(pins.ffprobe_path),
                maximum_clip_size=_MAX_MEDIA_BYTES,
            )
        except MediaConformanceError:
            pass
        else:
            raise ConformanceError("media_negative_case_failed")
        _record(
            observed,
            "media",
            "truncated-video-negative",
            {"rejected": True, "reason": "media_conformance_error"},
        )

        wrong_digest = ("0" if pins.ffmpeg_sha256[0] != "0" else "1") + pins.ffmpeg_sha256[1:]
        try:
            inspect_media_pinned(
                path,
                expected_ffmpeg_sha256=wrong_digest,
                expected_ffprobe_sha256=pins.ffprobe_sha256,
                ffmpeg=os.fspath(pins.ffmpeg_path),
                ffprobe=os.fspath(pins.ffprobe_path),
                maximum_clip_size=_MAX_MEDIA_BYTES,
            )
        except MediaConformanceError:
            pass
        else:
            raise ConformanceError("media_negative_case_failed")
        _record(
            observed,
            "media",
            "wrong-ffmpeg-pin-negative",
            {"rejected": True, "reason": "binary_digest_mismatch"},
        )

    try:
        frame_digest(2, 2, (b"too-short",))
    except ValueError:
        pass
    else:
        raise ConformanceError("media_negative_case_failed")
    _record(
        observed,
        "media",
        "wrong-rgb-frame-size-negative",
        {"rejected": True, "reason": "rgb24_frame_size"},
    )


def _execute_timelock(
    fixture: TimelockFixtures,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    sealed = parse_sealed_response(
        fixture.portable_base64url,
        reveal_round=fixture.reveal_round,
        sha256_hex=fixture.portable_sha256,
    )
    _record(
        observed,
        "timelock",
        "strict-portable-positive",
        {
            "portable_sha256": sealed.sha256_hex,
            "portable_size_bytes": len(sealed.portable_bytes),
            "reveal_round": sealed.reveal_round,
        },
    )
    mutations: tuple[tuple[str, Any], ...] = (
        (
            "wrong-round-negative",
            lambda: parse_sealed_response(
                fixture.portable_base64url,
                reveal_round=fixture.reveal_round + 1,
                sha256_hex=fixture.portable_sha256,
            ),
        ),
        (
            "wrong-digest-negative",
            lambda: parse_sealed_response(
                fixture.portable_base64url,
                reveal_round=fixture.reveal_round,
                sha256_hex=("0" if fixture.portable_sha256[0] != "0" else "1")
                + fixture.portable_sha256[1:],
            ),
        ),
        (
            "trailing-byte-negative",
            lambda: parse_sealed_response(
                _base64url(sealed.portable_bytes + b"\x00"),
                reveal_round=fixture.reveal_round,
            ),
        ),
        (
            "padded-base64-negative",
            lambda: parse_sealed_response(
                fixture.portable_base64url + "=",
                reveal_round=fixture.reveal_round,
            ),
        ),
    )
    for case_id, operation in mutations:
        try:
            operation()
        except (TypeError, ValueError):
            pass
        else:
            raise ConformanceError("timelock_negative_case_failed")
        _record(
            observed,
            "timelock",
            case_id,
            {"rejected": True, "reason": case_id.removesuffix("-negative")},
        )


def _execute_chain(
    fixture: ChainFixtures,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    clock = WindowClock(**fixture.clock.model_dump(mode="python"))
    window = clock.derive(**fixture.window_input.model_dump(mode="python"))
    actual = asdict(window)
    _require_expected_output(
        actual,
        fixture.expected_window.model_dump(mode="python"),
        reason_code="chain_schedule_output_mismatch",
    )
    _record(observed, "chain", "window-schedule-positive", actual)

    call = build_sha256_commitment_call(fixture.commitment_sha256)
    expected_params = {
        "netuid": 78,
        "info": {"fields": [{"Sha256": bytes.fromhex(fixture.commitment_sha256)}]},
    }
    if (
        call.module != "Commitments"
        or call.function != "set_commitment"
        or call.params != expected_params
    ):
        raise ConformanceError("chain_call_output_mismatch")
    _record(
        observed,
        "chain",
        "sha256-call-positive",
        {
            "module": call.module,
            "function": call.function,
            "netuid": call.params["netuid"],
            "field_sha256": call.params["info"]["fields"][0]["Sha256"].hex(),
        },
    )

    huge = ceil_div(fixture.huge_ceil_numerator, fixture.huge_ceil_denominator)
    if huge != fixture.huge_ceil_expected:
        raise ConformanceError("chain_integer_output_mismatch")
    _record(observed, "chain", "huge-ceil-div-positive", {"quotient": huge})

    try:
        build_sha256_commitment_call(fixture.commitment_sha256, netuid=77)
    except ValueError:
        pass
    else:
        raise ConformanceError("chain_negative_case_failed")
    _record(
        observed,
        "chain",
        "wrong-netuid-negative",
        {"rejected": True, "reason": "netuid_pin"},
    )


class _FixtureRpc:
    def __init__(self, block_response: Mapping[str, Any]) -> None:
        self.block_response = block_response

    async def request(self, method: str, _params: Any) -> Any:
        if method != "chain_getBlock":
            raise AssertionError("live-chain fixture made an unexpected RPC request")
        return self.block_response


class _UnusedFinality:
    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        raise AssertionError("live-chain block binding must not select finality")


def _live_identity(fixture: LiveChainFixtures) -> VerifiedFinalizedBlockIdentity:
    parent = FinalizedSnapshotRef(
        block_number=fixture.block_number - 1,
        block_hash=fixture.parent_hash,
        parent_hash=fixture.parent_parent_hash,
        state_root="0x" + "44" * 32,
    )
    snapshot = FinalizedSnapshotRef(
        block_number=fixture.block_number,
        block_hash=fixture.block_hash,
        parent_hash=fixture.parent_hash,
        state_root=fixture.state_root,
    )
    return VerifiedFinalizedBlockIdentity(
        snapshot=snapshot,
        parent_snapshot=parent,
        extrinsics_root=fixture.extrinsics_root,
        finality_verifier_sha256=fixture.finality_verifier_sha256,
        finality_evidence_sha256=fixture.finality_evidence_sha256,
    )


def _block_response(fixture: LiveChainFixtures, *, state_root: str | None = None) -> dict[str, Any]:
    return {
        "block": {
            "header": {
                "number": hex(fixture.block_number),
                "parentHash": fixture.parent_hash,
                "stateRoot": fixture.state_root if state_root is None else state_root,
                "extrinsicsRoot": fixture.extrinsics_root,
                "digest": {"logs": []},
            },
            "extrinsics": list(fixture.extrinsics),
        },
        "justifications": None,
    }


def _scan_port(
    fixture: LiveChainFixtures,
    response: Mapping[str, Any],
) -> LiveFinalizedBlockScanPort:
    rpc = _FixtureRpc(response)
    proofs = FinalizedProofCollector(
        rpc,
        finality=_UnusedFinality(),
        verifier=lambda **_kwargs: True,
    )
    return LiveFinalizedBlockScanPort(
        rpc=rpc,
        proofs=proofs,
        runtime_pin=FinalizedRuntimePin(
            metadata_sha256=fixture.metadata_sha256,
            spec_version=fixture.runtime_spec_version,
            transaction_version=1,
        ),
    )


def _execute_live_chain(
    fixture: LiveChainFixtures,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    identity = _live_identity(fixture)
    try:
        body = asyncio.run(_scan_port(fixture, _block_response(fixture)).block_body_at(identity))
    except RuntimeError as error:
        if "asyncio.run()" in str(error):
            raise ConformanceError("async_context_unsupported") from error
        raise
    if body is None or body.body_sha256 != fixture.expected_body_sha256:
        raise ConformanceError("live_chain_body_binding_mismatch")
    _record(
        observed,
        "live_chain",
        "rpc-block-binding-positive",
        {
            "block_hash": body.block_hash,
            "body_sha256": body.body_sha256,
            "extrinsic_count": len(body.extrinsics),
        },
    )

    runtime_pin = RuntimeSpecPin(
        spec_version=fixture.runtime_spec_version,
        metadata_sha256=fixture.metadata_sha256,
    )
    runtime_observation = RuntimeSpecObservation(
        snapshot=identity.snapshot,
        spec_version=fixture.runtime_spec_version,
        metadata_sha256=fixture.metadata_sha256,
        mechanism_count=1,
        commit_reveal_enabled=True,
        commit_reveal_version=4,
    )
    require_runtime_spec_pin(runtime_observation, runtime_pin)
    require_core_pin(
        CoreObservation(
            revision=fixture.core_revision,
            content_sha256=fixture.core_content_sha256,
        ),
        CorePin(
            revision=fixture.core_revision,
            content_sha256=fixture.core_content_sha256,
        ),
    )
    _record(
        observed,
        "live_chain",
        "runtime-pin-positive",
        {
            "commit_reveal_version": runtime_observation.commit_reveal_version,
            "mechanism_count": runtime_observation.mechanism_count,
            "spec_version": runtime_observation.spec_version,
        },
    )

    harmless = FinalizedCallRecord(
        snapshot=identity.snapshot,
        extrinsic_index=0,
        call_hash="0x" + "55" * 32,
        module="Timestamp",
        function="set",
        successful=True,
        recursive_decode_complete=True,
        declared_child_count=0,
        call_path=(),
        signer_account_id32=None,
    )
    block = FinalizedBlockRecord(
        snapshot=identity.snapshot,
        extrinsic_count=1,
        event_count=0,
        calls=(harmless,),
        events=(),
    )
    scan = assert_shadow_no_weight_interval(
        (block,),
        start_block=fixture.block_number,
        end_block=fixture.block_number,
        validator_account=bytes.fromhex(fixture.validator_account_id32),
    )
    _record(
        observed,
        "live_chain",
        "no-weight-scan-positive",
        {
            "scanned_blocks": scan.scanned_blocks,
            "scanned_calls": scan.scanned_calls,
            "scanned_events": scan.scanned_events,
        },
    )

    wrong_root = "0x" + ("00" if fixture.state_root[2:4] != "00" else "01") + fixture.state_root[4:]
    try:
        asyncio.run(
            _scan_port(fixture, _block_response(fixture, state_root=wrong_root)).block_body_at(
                identity
            )
        )
    except LiveFinalizedBlockScanPortError as error:
        if error.reason_code != "block_header_state_root_mismatch":
            raise ConformanceError("live_chain_negative_reason_mismatch") from error
    else:
        raise ConformanceError("live_chain_negative_case_failed")
    _record(
        observed,
        "live_chain",
        "header-mismatch-negative",
        {"rejected": True, "reason": "block_header_state_root_mismatch"},
    )

    weight_call = FinalizedCallRecord(
        snapshot=identity.snapshot,
        extrinsic_index=0,
        call_hash="0x" + "66" * 32,
        module="SubtensorModule",
        function="set_weights",
        successful=True,
        recursive_decode_complete=True,
        declared_child_count=0,
        call_path=(),
        signer_account_id32=bytes.fromhex(fixture.validator_account_id32),
        netuid=78,
        mechanism_id=0,
    )
    injected = FinalizedBlockRecord(
        snapshot=identity.snapshot,
        extrinsic_count=1,
        event_count=0,
        calls=(weight_call,),
        events=(),
    )
    try:
        assert_shadow_no_weight_interval(
            (injected,),
            start_block=fixture.block_number,
            end_block=fixture.block_number,
            validator_account=bytes.fromhex(fixture.validator_account_id32),
        )
    except ValueError as error:
        if "weight call" not in str(error):
            raise ConformanceError("live_chain_negative_reason_mismatch") from error
    else:
        raise ConformanceError("live_chain_negative_case_failed")
    _record(
        observed,
        "live_chain",
        "weight-call-negative",
        {"rejected": True, "reason": "validator_weight_call"},
    )


def _storage_material(
    fixture: StorageProofFixtures,
) -> tuple[bytes, tuple[tuple[bytes, bytes | None], ...], tuple[bytes, ...]]:
    vector = fixture.vector
    root = bytes.fromhex(vector.state_root[2:])
    items = tuple(
        (
            bytes.fromhex(item.key[2:]),
            None if item.value is None else bytes.fromhex(item.value[2:]),
        )
        for item in vector.items
    )
    proof = tuple(bytes.fromhex(item[2:]) for item in vector.proof)
    return root, items, proof


def _expect_proof_rejection(operation: Any, *, expected_reason: str) -> None:
    try:
        operation()
    except SubstrateProofVerifierError as error:
        if error.reason_code != expected_reason:
            raise ConformanceError("storage_proof_negative_reason_mismatch") from error
    else:
        raise ConformanceError("storage_proof_negative_case_failed")


def _execute_storage(
    fixture: StorageProofFixtures,
    pins: ConformanceBinaryPins,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    verifier = SubprocessStorageProofVerifier(
        binary_path=pins.storage_proof_verifier_path,
        expected_sha256=pins.storage_proof_verifier_sha256,
        timeout_seconds=30,
    )
    root, items, proof = _storage_material(fixture)
    try:
        verified = verifier.verify_many(state_root=root, items=items, proof=proof)
    except SubstrateProofVerifierError as error:
        raise ConformanceError("storage_proof_positive_case_failed") from error
    if verified is not True:
        raise ConformanceError("storage_proof_positive_case_failed")
    _record(
        observed,
        "storage_proof",
        "finney-membership-positive",
        {
            "item_count": len(items),
            "proof_node_count": len(proof),
            "state_root": root.hex(),
        },
    )

    empty_root = bytes.fromhex(fixture.empty_extrinsics_root[2:])
    if (
        verifier.verify_extrinsics_root(
            expected_root=empty_root,
            extrinsics=(),
            state_version=1,
        )
        is not True
    ):
        raise ConformanceError("storage_extrinsics_root_positive_case_failed")
    _record(
        observed,
        "storage_proof",
        "empty-extrinsics-root-positive",
        {"extrinsic_count": 0, "root": empty_root.hex()},
    )

    first_key, first_value = items[0]
    wrong_value = b"\x00" if first_value is None else bytes([first_value[0] ^ 1]) + first_value[1:]
    wrong_items = ((first_key, wrong_value), *items[1:])
    _expect_proof_rejection(
        lambda: verifier.verify_many(state_root=root, items=wrong_items, proof=proof),
        expected_reason="invalid_proof",
    )
    _record(
        observed,
        "storage_proof",
        "wrong-value-negative",
        {"rejected": True, "reason": "invalid_proof"},
    )

    _expect_proof_rejection(
        lambda: verifier.verify_many(state_root=root, items=items, proof=proof[:-1]),
        expected_reason="invalid_proof",
    )
    _record(
        observed,
        "storage_proof",
        "missing-node-negative",
        {"rejected": True, "reason": "invalid_proof"},
    )

    changed_first = bytes([proof[0][0] ^ 1]) + proof[0][1:]
    _expect_proof_rejection(
        lambda: verifier.verify_many(
            state_root=root,
            items=items,
            proof=(changed_first, *proof[1:]),
        ),
        expected_reason="invalid_proof",
    )
    _record(
        observed,
        "storage_proof",
        "changed-node-negative",
        {"rejected": True, "reason": "invalid_proof"},
    )

    wrong_root = bytes([empty_root[0] ^ 1]) + empty_root[1:]
    _expect_proof_rejection(
        lambda: verifier.verify_extrinsics_root(
            expected_root=wrong_root,
            extrinsics=(),
            state_version=1,
        ),
        expected_reason="invalid_extrinsics_root",
    )
    _record(
        observed,
        "storage_proof",
        "wrong-extrinsics-root-negative",
        {"rejected": True, "reason": "invalid_extrinsics_root"},
    )


def _execute_finality(
    fixture: FinalityFixtures,
    pins: ConformanceBinaryPins,
    observed: dict[tuple[str, str], Mapping[str, Any]],
) -> None:
    try:
        with staged_pinned_artifacts(
            (
                PinnedArtifact(
                    name="finality",
                    source=pins.finality_verifier_path,
                    expected_sha256=pins.finality_verifier_sha256,
                    maximum_bytes=_MAX_BINARY_BYTES,
                    executable=True,
                ),
            )
        ) as staged:
            process = subprocess.run(
                [os.fspath(staged["finality"]), "--conformance-self-test"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
                env={"LANG": "C", "LC_ALL": "C"},
            )
    except (OSError, subprocess.TimeoutExpired, PinnedArtifactError) as error:
        raise ConformanceError("finality_self_test_failed") from error
    if process.returncode != 0 or not process.stdout.endswith(b"\n"):
        raise ConformanceError("finality_self_test_failed")
    if process.stdout.count(b"\n") != 1 or len(process.stdout) > _MAX_FINALITY_OUTPUT_BYTES:
        raise ConformanceError("finality_self_test_output_invalid")
    raw = process.stdout[:-1]
    try:
        report = FinalitySelfTestReport.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise ConformanceError("finality_self_test_output_invalid") from error
    if canonical_json_bytes(report) != raw:
        raise ConformanceError("finality_self_test_output_noncanonical")
    expected_fixture_sha256 = hashlib.sha256(canonical_json_bytes(fixture)).hexdigest()
    if (
        report.fixture_canonical_sha256 != expected_fixture_sha256
        or report.finney_checkpoint_canonical_sha256 != fixture.finney_checkpoint_fixture.sha256
    ):
        raise ConformanceError("finality_fixture_binding_mismatch")
    for case_id in _FINALITY_CASES:
        _record(
            observed,
            "finality",
            case_id,
            {
                "binary_self_test": True,
                "fixture_canonical_sha256": report.fixture_canonical_sha256,
            },
        )


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


__all__ = [
    "CHAIN_SCHEMA",
    "FINALITY_SCHEMA",
    "LIVE_CHAIN_SCHEMA",
    "MEDIA_SCHEMA",
    "NORMALIZATION_SCHEMA",
    "REPORT_SCHEMA",
    "STORAGE_PROOF_SCHEMA",
    "TIMELOCK_SCHEMA",
    "ConformanceBinaryPins",
    "ConformanceError",
    "ConformanceExecution",
    "ConformanceExecutionReport",
    "ConformanceFixturePaths",
    "execute_conformance_suite",
]
