"""Canonical version 0.1 scoring-policy schemas and digests.

The policy document is deliberately made only from JSON-native scalar values and
strict nested models.  This keeps its RFC 8785 representation independent of the
Python process that validates it.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import math
import platform
import shutil
import unicodedata
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .encoding import account_id32
from .protocol import (
    PROTOCOL_VERSION,
    Hex32,
    NonEmptyText,
    StrictProtocolModel,
    canonical_json_bytes,
)

SCORING_POLICY_SCHEMA = "umi-scoring-policy/1"


def _installed_version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeError(f"required distribution is unavailable: {distribution}") from error


def _distribution_file_paths(distribution: str) -> frozenset[Path]:
    try:
        installed = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeError(f"required distribution is unavailable: {distribution}") from error
    paths = frozenset(
        Path(installed.locate_file(relative)).resolve()
        for relative in (installed.files or ())
        if Path(installed.locate_file(relative)).is_file()
    )
    if not paths:
        raise RuntimeError(f"distribution exposes no installed files: {distribution}")
    return paths


def _require_loaded_module_from_distribution(module_name: str, distribution: str) -> None:
    """Reject import shadowing outside the exact installed distribution file set."""

    module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None)
    specification = getattr(module, "__spec__", None)
    origin = getattr(specification, "origin", None)
    if not isinstance(module_file, str) or not isinstance(origin, str):
        raise RuntimeError(f"loaded module has no verifiable file origin: {module_name}")
    resolved_file = Path(module_file).resolve()
    resolved_origin = Path(origin).resolve()
    if resolved_file != resolved_origin:
        raise RuntimeError(f"loaded module file and import origin disagree: {module_name}")
    if resolved_file not in _distribution_file_paths(distribution):
        raise RuntimeError(f"loaded module is outside the pinned distribution: {module_name}")


def _distribution_content_sha256(distribution: str) -> str:
    """Hash installed distribution files by relative name and exact content."""

    try:
        installed = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeError(f"required distribution is unavailable: {distribution}") from error
    files = sorted(
        (
            file
            for file in (installed.files or ())
            if not str(file).endswith((".pyc", ".pyo"))
            and "__pycache__" not in file.parts
            and not str(file).endswith(".dist-info/RECORD")
        ),
        key=str,
    )
    if not files:
        raise RuntimeError(f"distribution exposes no hashable files: {distribution}")
    digest = hashlib.sha256(b"umi-installed-distribution-v1\0")
    for relative in files:
        path = Path(installed.locate_file(relative))
        if not path.is_file():
            continue
        content_digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                content_digest.update(chunk)
        encoded_name = str(relative).encode()
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(content_digest.digest())
    return digest.hexdigest()


def _executable_sha256(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"required policy-pinned executable is unavailable: {name}")
    digest = hashlib.sha256()
    with Path(executable).resolve().open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _placeholder_digest(label: str) -> str:
    """Hash an explicit rehearsal placeholder that cannot qualify for activation."""

    return hashlib.sha256(("umi-rehearsal-placeholder-v1\0" + label).encode()).hexdigest()


def umi_source_tree_sha256() -> str:
    """Hash every shipped UMI Python module by relative path and exact bytes."""

    root = Path(__file__).resolve().parent
    digest = hashlib.sha256(b"umi-source-tree-v1\0")
    paths = sorted(root.rglob("*.py"), key=lambda path: path.relative_to(root).as_posix())
    if not paths:
        raise RuntimeError("UMI source tree contains no Python modules")
    for path in paths:
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


class ExactRatio(StrictProtocolModel):
    """A reduced, exact rational value suitable for canonical JSON."""

    numerator: Annotated[int, Field(ge=0)]
    denominator: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_reduced(self) -> Self:
        if math.gcd(self.numerator, self.denominator) != 1:
            raise ValueError("exact ratios must be reduced")
        return self

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)

    @classmethod
    def from_fraction(cls, value: Fraction) -> ExactRatio:
        if not isinstance(value, Fraction):
            raise TypeError("value must be a Fraction")
        return cls(numerator=value.numerator, denominator=value.denominator)


class PolicyClock(StrictProtocolModel):
    window_stride_blocks: Annotated[int, Field(gt=0)]
    proposal_blocks: Annotated[int, Field(gt=0)]
    anchor_blocks: Annotated[int, Field(gt=0)]
    target_block_interval_seconds: Annotated[int, Field(gt=0)]
    selection_finality_buffer_seconds: Annotated[int, Field(gt=0)]
    issue_allowance_seconds: Annotated[int, Field(gt=0)]
    response_window_seconds: Annotated[int, Field(gt=0)]
    delivery_grace_seconds: Annotated[int, Field(gt=0)]
    reveal_margin_seconds: Annotated[int, Field(gt=0)]
    weight_commit_buffer_blocks: Annotated[int, Field(gt=0)]
    weight_commit_submission_blocks: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_clock(self) -> Self:
        if not self.proposal_blocks < self.anchor_blocks < self.window_stride_blocks:
            raise ValueError(
                "clock requires proposal_blocks < anchor_blocks < window_stride_blocks"
            )
        if self.weight_commit_submission_blocks >= self.window_stride_blocks:
            raise ValueError("weight submission interval must be shorter than a window stride")
        lifecycle_seconds = (
            self.anchor_blocks * self.target_block_interval_seconds
            + self.selection_finality_buffer_seconds
            + self.issue_allowance_seconds
            + self.response_window_seconds
            + self.reveal_margin_seconds
        )
        stride_seconds = self.window_stride_blocks * self.target_block_interval_seconds
        if lifecycle_seconds >= stride_seconds:
            raise ValueError("challenge lifecycle must finish before the next window opens")
        return self

    @classmethod
    def launch(cls) -> PolicyClock:
        return cls(
            window_stride_blocks=360,
            proposal_blocks=30,
            anchor_blocks=45,
            target_block_interval_seconds=12,
            selection_finality_buffer_seconds=300,
            issue_allowance_seconds=60,
            response_window_seconds=60,
            delivery_grace_seconds=60,
            reveal_margin_seconds=300,
            weight_commit_buffer_blocks=30,
            weight_commit_submission_blocks=30,
        )


class PolicyLimits(StrictProtocolModel):
    emission_bearing_clips_per_batch: Annotated[int, Field(gt=0)]
    batches_selected_per_window: Annotated[int, Field(gt=0)]
    max_active_publishers: Annotated[int, Field(gt=0)]
    max_active_control_groups: Annotated[int, Field(gt=0)]
    max_candidate_batches_per_publisher: Annotated[int, Field(gt=0)]
    max_candidate_batches_per_group: Annotated[int, Field(gt=0)]
    max_candidate_batches_total: Annotated[int, Field(gt=0)]
    maximum_unused_batches_per_valid_window: Annotated[int, Field(ge=0)]
    minimum_availability_signers: Annotated[int, Field(gt=0)]
    miner_panel_size: Annotated[int, Field(gt=0)]
    rolling_batch_count: Annotated[int, Field(gt=0)]
    score_max_age_windows: Annotated[int, Field(gt=0)]
    minimum_assigned_clips: Annotated[int, Field(gt=0)]
    minimum_clips_per_stratum: Annotated[int, Field(gt=0)]
    minimum_accepted_references: Annotated[int, Field(gt=0)]
    maximum_accepted_references: Annotated[int, Field(gt=0)]
    maximum_reference_utf8_bytes: Annotated[int, Field(gt=0)]
    maximum_reference_tokens: Annotated[int, Field(gt=0)]
    maximum_reference_graphemes: Annotated[int, Field(gt=0)]
    maximum_hypothesis_utf8_bytes: Annotated[int, Field(gt=0)]
    maximum_hypothesis_tokens: Annotated[int, Field(gt=0)]
    maximum_hypothesis_graphemes: Annotated[int, Field(gt=0)]
    maximum_request_body_bytes: Annotated[int, Field(gt=0)]
    maximum_response_body_bytes: Annotated[int, Field(gt=0)]
    maximum_http_header_bytes: Annotated[int, Field(gt=0)]
    maximum_request_transmissions_per_assignment: Annotated[int, Field(gt=0)]
    maximum_response_bodies_per_assignment: Annotated[int, Field(gt=0)]
    maximum_video_fetch_attempts_per_actor: Annotated[int, Field(gt=0)]
    maximum_assignment_wire_bytes: Annotated[int, Field(gt=0)]
    maximum_validator_window_wire_bytes: Annotated[int, Field(gt=0)]
    maximum_audit_bundle_bytes: Annotated[int, Field(gt=0)]
    maximum_manifest_bytes: Annotated[int, Field(gt=0)]
    maximum_ground_truth_envelope_bytes: Annotated[int, Field(gt=0)]
    minimum_clip_duration_ms: Annotated[int, Field(gt=0)]
    maximum_clip_duration_ms: Annotated[int, Field(gt=0)]
    maximum_clip_size_bytes: Annotated[int, Field(gt=0)]
    maximum_clip_width: Annotated[int, Field(gt=0)]
    maximum_clip_height: Annotated[int, Field(gt=0)]
    maximum_clip_fps: Annotated[int, Field(gt=0)]
    publisher_monitoring_batches: Annotated[int, Field(gt=0)]
    divergence_minimum_clips_per_side_and_stratum: Annotated[int, Field(gt=0)]
    challenge_supply_runway_days: Annotated[int, Field(gt=0)]
    minimum_economics_price_sources: Annotated[int, Field(gt=0)]
    minimum_soak_duration_seconds: Annotated[int, Field(gt=0)]
    minimum_soak_windows: Annotated[int, Field(gt=0)]
    publisher_fault_cooldown_windows: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_limits(self) -> Self:
        if self.minimum_accepted_references > self.maximum_accepted_references:
            raise ValueError("minimum references must not exceed maximum references")
        if self.minimum_clip_duration_ms > self.maximum_clip_duration_ms:
            raise ValueError("minimum clip duration must not exceed maximum clip duration")
        if self.batches_selected_per_window > self.max_candidate_batches_total:
            raise ValueError("selected batches cannot exceed the candidate-pool limit")
        if self.max_active_control_groups > self.max_active_publishers:
            raise ValueError("control-group count cannot exceed publisher count")
        return self

    @classmethod
    def launch(cls) -> PolicyLimits:
        mib = 1024 * 1024
        gib = 1024 * mib
        return cls(
            emission_bearing_clips_per_batch=12,
            batches_selected_per_window=2,
            max_active_publishers=3,
            max_active_control_groups=3,
            max_candidate_batches_per_publisher=1,
            max_candidate_batches_per_group=1,
            max_candidate_batches_total=3,
            maximum_unused_batches_per_valid_window=1,
            minimum_availability_signers=3,
            miner_panel_size=32,
            rolling_batch_count=4,
            score_max_age_windows=4,
            minimum_assigned_clips=12,
            minimum_clips_per_stratum=2,
            minimum_accepted_references=3,
            maximum_accepted_references=5,
            maximum_reference_utf8_bytes=4 * 1024,
            maximum_reference_tokens=128,
            maximum_reference_graphemes=512,
            maximum_hypothesis_utf8_bytes=4 * 1024,
            maximum_hypothesis_tokens=128,
            maximum_hypothesis_graphemes=512,
            maximum_request_body_bytes=64 * 1024,
            maximum_response_body_bytes=64 * 1024,
            maximum_http_header_bytes=16 * 1024,
            maximum_request_transmissions_per_assignment=2,
            maximum_response_bodies_per_assignment=2,
            maximum_video_fetch_attempts_per_actor=2,
            maximum_assignment_wire_bytes=34 * mib,
            maximum_validator_window_wire_bytes=40 * gib,
            maximum_audit_bundle_bytes=384 * mib,
            maximum_manifest_bytes=256 * 1024,
            maximum_ground_truth_envelope_bytes=mib,
            minimum_clip_duration_ms=2_000,
            maximum_clip_duration_ms=15_000,
            maximum_clip_size_bytes=16 * mib,
            maximum_clip_width=1280,
            maximum_clip_height=720,
            maximum_clip_fps=30,
            publisher_monitoring_batches=12,
            divergence_minimum_clips_per_side_and_stratum=6,
            challenge_supply_runway_days=90,
            minimum_economics_price_sources=3,
            minimum_soak_duration_seconds=2_592_000,
            minimum_soak_windows=30,
            publisher_fault_cooldown_windows=4,
        )


class PolicyThresholds(StrictProtocolModel):
    fingerspelling_share: ExactRatio
    short_utterance_share: ExactRatio
    continuous_share: ExactRatio
    canary_fraction: ExactRatio
    canary_separation_score: ExactRatio
    canary_cer_hit_threshold: ExactRatio
    canary_wer_hit_threshold: ExactRatio
    quality_floor: ExactRatio
    utility_exponent: Annotated[int, Field(gt=0)]
    median_pairwise_validator_tv_limit: ExactRatio
    maximum_pairwise_validator_tv_limit: ExactRatio
    minimum_pairwise_top_k_overlap: ExactRatio
    source_divergence_alert_threshold: ExactRatio
    validator_cost_coverage: ExactRatio
    validator_quote_percentile: ExactRatio
    validator_alpha_value_haircut: ExactRatio
    minimum_soak_valid_window_rate: ExactRatio
    resource_utilization_percentile: ExactRatio
    maximum_soak_resource_utilization: ExactRatio

    @model_validator(mode="after")
    def validate_thresholds(self) -> Self:
        unit_fields = (
            "fingerspelling_share",
            "short_utterance_share",
            "continuous_share",
            "canary_fraction",
            "canary_separation_score",
            "canary_cer_hit_threshold",
            "canary_wer_hit_threshold",
            "quality_floor",
            "median_pairwise_validator_tv_limit",
            "maximum_pairwise_validator_tv_limit",
            "minimum_pairwise_top_k_overlap",
            "source_divergence_alert_threshold",
            "validator_quote_percentile",
            "validator_alpha_value_haircut",
            "minimum_soak_valid_window_rate",
            "resource_utilization_percentile",
            "maximum_soak_resource_utilization",
        )
        for name in unit_fields:
            value = getattr(self, name).fraction
            if not 0 <= value <= 1:
                raise ValueError(f"{name} must be in the unit interval")
        if (
            self.fingerspelling_share.fraction
            + self.short_utterance_share.fraction
            + self.continuous_share.fraction
            != 1
        ):
            raise ValueError("stratum shares must sum exactly to one")
        if (
            self.median_pairwise_validator_tv_limit.fraction
            > self.maximum_pairwise_validator_tv_limit.fraction
        ):
            raise ValueError("median TV limit must not exceed the maximum TV limit")
        if self.validator_cost_coverage.fraction < 1:
            raise ValueError("validator cost coverage must be at least one")
        return self

    @classmethod
    def launch(cls) -> PolicyThresholds:
        ratio = ExactRatio.from_fraction
        return cls(
            fingerspelling_share=ratio(Fraction(3, 20)),
            short_utterance_share=ratio(Fraction(7, 20)),
            continuous_share=ratio(Fraction(1, 2)),
            canary_fraction=ratio(Fraction(1, 10)),
            canary_separation_score=ratio(Fraction(1, 10)),
            canary_cer_hit_threshold=ratio(Fraction(1, 2)),
            canary_wer_hit_threshold=ratio(Fraction(1, 2)),
            quality_floor=ratio(Fraction(1, 10)),
            utility_exponent=2,
            median_pairwise_validator_tv_limit=ratio(Fraction(1, 10)),
            maximum_pairwise_validator_tv_limit=ratio(Fraction(1, 5)),
            minimum_pairwise_top_k_overlap=ratio(Fraction(4, 5)),
            source_divergence_alert_threshold=ratio(Fraction(3, 20)),
            validator_cost_coverage=ratio(Fraction(5, 4)),
            validator_quote_percentile=ratio(Fraction(1, 10)),
            validator_alpha_value_haircut=ratio(Fraction(1, 2)),
            minimum_soak_valid_window_rate=ratio(Fraction(19, 20)),
            resource_utilization_percentile=ratio(Fraction(19, 20)),
            maximum_soak_resource_utilization=ratio(Fraction(3, 4)),
        )


class PublisherControlGroup(StrictProtocolModel):
    control_group_id: Hex32
    administrator: NonEmptyText

    @model_validator(mode="after")
    def validate_account(self) -> Self:
        account_id32(self.administrator)
        return self


class PublisherRegistryEntry(StrictProtocolModel):
    publisher_hotkey: NonEmptyText
    owner_coldkey: NonEmptyText
    control_group_id: Hex32

    @model_validator(mode="after")
    def validate_accounts(self) -> Self:
        publisher = account_id32(self.publisher_hotkey)
        owner = account_id32(self.owner_coldkey)
        if publisher == owner:
            raise ValueError("publisher hotkey must be dedicated and distinct from its coldkey")
        return self


class ValidatorRegistryEntry(StrictProtocolModel):
    validator_hotkey: NonEmptyText
    administrator_id: Hex32

    @model_validator(mode="after")
    def validate_account(self) -> Self:
        account_id32(self.validator_hotkey)
        return self


class ScoringRuntimePin(StrictProtocolModel):
    python_implementation: Literal["CPython"]
    python_version: NonEmptyText
    unicode_data_version: NonEmptyText
    regex_distribution_version: NonEmptyText
    regex_distribution_content_sha256: Hex32
    rfc8785_distribution_version: NonEmptyText
    rfc8785_distribution_content_sha256: Hex32
    pydantic_distribution_version: NonEmptyText
    pydantic_distribution_content_sha256: Hex32
    pydantic_core_distribution_version: NonEmptyText
    pydantic_core_distribution_content_sha256: Hex32
    scoring_source_sha256: Hex32
    normalization_fixture_set_sha256: Hex32


class MediaRuntimePin(StrictProtocolModel):
    ffmpeg_binary_sha256: Hex32
    ffprobe_binary_sha256: Hex32
    frame_digest_fixture_set_sha256: Hex32


class TimelockRuntimePin(StrictProtocolModel):
    bittensor_distribution_version: NonEmptyText
    bittensor_distribution_content_sha256: Hex32
    bittensor_core_distribution_version: NonEmptyText
    bittensor_core_distribution_content_sha256: Hex32
    py_ecc_distribution_version: NonEmptyText
    py_ecc_distribution_content_sha256: Hex32
    portable_envelope_fixture_set_sha256: Hex32
    beacon_id: Literal["quicknet"]
    chain_hash: Literal["52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"]
    scheme_id: Literal["bls-unchained-g1-rfc9380"]
    period_seconds: Literal[3]
    genesis_time: Literal[1692803367]
    public_key: Literal[
        "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
    ]


class ChainRuntimePin(StrictProtocolModel):
    reference_runtime_spec: Literal[449]
    subtensor_revision: Literal["71136ad1098a661c0d5477338b21557b9f9118e2"]
    commit_reveal_version: Literal[4]
    mechanism_count: Literal[1]
    mechanism_id: Literal[0]
    chain_fixture_set_sha256: Hex32


class PolicyReasonCode(StrictProtocolModel):
    name: NonEmptyText
    code: Annotated[int, Field(ge=0, le=65535)]


class ProtocolRulePins(StrictProtocolModel):
    btauth_profile: Literal["btauth/1"]
    mirror_discovery_rule_sha256: Hex32
    mirror_authentication_profile: NonEmptyText
    outer_disposition_codes: list[
        Literal["sealed", "missing", "late", "outer_invalid", "resource_limit"]
    ]
    miner_error_codes: list[
        Literal[
            "video_fetch_failed",
            "inference_failed",
            "hypothesis_invalid",
            "response_deadline_exceeded",
        ]
    ]
    publisher_fault_reason_codes: Annotated[list[PolicyReasonCode], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_codebooks(self) -> Self:
        expected_outer = ["sealed", "missing", "late", "outer_invalid", "resource_limit"]
        expected_errors = [
            "video_fetch_failed",
            "inference_failed",
            "hypothesis_invalid",
            "response_deadline_exceeded",
        ]
        if self.outer_disposition_codes != expected_outer:
            raise ValueError("outer disposition codebook must use the canonical order")
        if self.miner_error_codes != expected_errors:
            raise ValueError("miner error codebook must use the canonical order")
        fault_names = [item.name for item in self.publisher_fault_reason_codes]
        fault_codes = [item.code for item in self.publisher_fault_reason_codes]
        if not fault_names or len(set(fault_names)) != len(fault_names):
            raise ValueError("publisher fault reason names must be nonempty and unique")
        if fault_codes != sorted(fault_codes) or len(set(fault_codes)) != len(fault_codes):
            raise ValueError("publisher fault reason codes must be unique and sorted")
        return self


class ResourceDeadlineRule(StrictProtocolModel):
    stage_id: Literal[
        "pool_qualification",
        "assignment_issuance",
        "response_anchoring",
        "reveal_and_weight_build",
        "audit_release",
    ]
    start_rule: NonEmptyText
    deadline_rule: NonEmptyText
    completion_rule: NonEmptyText


class PolicyImplementationPins(StrictProtocolModel):
    pin_profile: Literal["local_rehearsal"]
    conformance_fixtures_verified: Literal[False]
    umi_source_tree_sha256: Hex32
    scoring: ScoringRuntimePin
    media: MediaRuntimePin
    timelock: TimelockRuntimePin
    chain: ChainRuntimePin
    rules: ProtocolRulePins
    resource_deadline_stages: Annotated[
        list[ResourceDeadlineRule], Field(min_length=5, max_length=5)
    ]

    @model_validator(mode="after")
    def validate_deadline_stages(self) -> Self:
        expected = (
            "pool_qualification",
            "assignment_issuance",
            "response_anchoring",
            "reveal_and_weight_build",
            "audit_release",
        )
        if tuple(stage.stage_id for stage in self.resource_deadline_stages) != expected:
            raise ValueError("resource deadline stages must use the canonical order")
        return self

    @classmethod
    def local_rehearsal(cls) -> PolicyImplementationPins:
        """Pin this machine for reproducible offline rehearsal, never activation by itself."""

        from .scoring import scoring_environment

        scoring = scoring_environment()
        common_rule = {
            "start_rule": "schedule-derived integer millisecond start",
            "deadline_rule": "schedule-derived exclusive integer millisecond deadline",
            "completion_rule": "bundle-evidenced first finalized completion instant",
        }
        return cls(
            pin_profile="local_rehearsal",
            conformance_fixtures_verified=False,
            umi_source_tree_sha256=umi_source_tree_sha256(),
            scoring=ScoringRuntimePin(
                python_implementation=platform.python_implementation(),
                python_version=platform.python_version(),
                unicode_data_version=unicodedata.unidata_version,
                regex_distribution_version=scoring["regex_distribution_version"],
                regex_distribution_content_sha256=_distribution_content_sha256("regex"),
                rfc8785_distribution_version=_installed_version("rfc8785"),
                rfc8785_distribution_content_sha256=_distribution_content_sha256("rfc8785"),
                pydantic_distribution_version=_installed_version("pydantic"),
                pydantic_distribution_content_sha256=_distribution_content_sha256("pydantic"),
                pydantic_core_distribution_version=_installed_version("pydantic-core"),
                pydantic_core_distribution_content_sha256=_distribution_content_sha256(
                    "pydantic-core"
                ),
                scoring_source_sha256=scoring["scoring_source_sha256"],
                normalization_fixture_set_sha256=_placeholder_digest("normalization"),
            ),
            media=MediaRuntimePin(
                ffmpeg_binary_sha256=_executable_sha256("ffmpeg"),
                ffprobe_binary_sha256=_executable_sha256("ffprobe"),
                frame_digest_fixture_set_sha256=_placeholder_digest("frame-digest"),
            ),
            timelock=TimelockRuntimePin(
                bittensor_distribution_version=_installed_version("bittensor"),
                bittensor_distribution_content_sha256=_distribution_content_sha256("bittensor"),
                bittensor_core_distribution_version=_installed_version("bittensor-core"),
                bittensor_core_distribution_content_sha256=_distribution_content_sha256(
                    "bittensor-core"
                ),
                py_ecc_distribution_version=_installed_version("py-ecc"),
                py_ecc_distribution_content_sha256=_distribution_content_sha256("py-ecc"),
                portable_envelope_fixture_set_sha256=_placeholder_digest("portable-timelock"),
                beacon_id="quicknet",
                chain_hash=("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"),
                scheme_id="bls-unchained-g1-rfc9380",
                period_seconds=3,
                genesis_time=1692803367,
                public_key=(
                    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183"
                    "c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4"
                    "bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
                ),
            ),
            chain=ChainRuntimePin(
                reference_runtime_spec=449,
                subtensor_revision="71136ad1098a661c0d5477338b21557b9f9118e2",
                commit_reveal_version=4,
                mechanism_count=1,
                mechanism_id=0,
                chain_fixture_set_sha256=_placeholder_digest("chain-schedule-and-calls"),
            ),
            rules=ProtocolRulePins(
                btauth_profile="btauth/1",
                mirror_discovery_rule_sha256=_placeholder_digest("authenticated-content-mirror"),
                mirror_authentication_profile="umi-authenticated-content-mirror/1",
                outer_disposition_codes=[
                    "sealed",
                    "missing",
                    "late",
                    "outer_invalid",
                    "resource_limit",
                ],
                miner_error_codes=[
                    "video_fetch_failed",
                    "inference_failed",
                    "hypothesis_invalid",
                    "response_deadline_exceeded",
                ],
                publisher_fault_reason_codes=[
                    PolicyReasonCode(name="timelock_decryption_failed", code=1),
                    PolicyReasonCode(name="ground_truth_schema_invalid", code=2),
                    PolicyReasonCode(name="committed_binding_mismatch", code=3),
                    PolicyReasonCode(name="spent_script_duplicate", code=4),
                ],
            ),
            resource_deadline_stages=[
                ResourceDeadlineRule(stage_id=stage, **common_rule)
                for stage in (
                    "pool_qualification",
                    "assignment_issuance",
                    "response_anchoring",
                    "reveal_and_weight_build",
                    "audit_release",
                )
            ],
        )


class ScoringPolicy(StrictProtocolModel):
    """Canonical policy accepted by the offline rehearsal; active mode is unavailable."""

    schema_: Literal[SCORING_POLICY_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    translation_weights_active: Literal[False]
    activation_block: Annotated[int, Field(ge=0)]
    minimum_publisher_collateral_alpha_rao: Annotated[int, Field(gt=0)]
    soak_start_window_index: Annotated[int, Field(ge=0)]
    validator_capacity_set_root: Hex32
    validator_cost_schedule_hash: Hex32
    implementation_pins: PolicyImplementationPins
    clock: PolicyClock
    limits: PolicyLimits
    thresholds: PolicyThresholds
    validator_registry: Annotated[list[ValidatorRegistryEntry], Field(min_length=4)]
    control_group_registry: Annotated[list[PublisherControlGroup], Field(min_length=1)]
    publisher_registry: Annotated[list[PublisherRegistryEntry], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_launch_registry_and_profile(self) -> Self:
        limits = self.limits
        validator_accounts = [
            account_id32(item.validator_hotkey) for item in self.validator_registry
        ]
        if validator_accounts != sorted(validator_accounts) or len(set(validator_accounts)) != len(
            validator_accounts
        ):
            raise ValueError("validator registry must be unique and sorted by hotkey account")
        validator_administrators = [
            bytes.fromhex(item.administrator_id) for item in self.validator_registry
        ]
        if len(set(validator_administrators)) != len(validator_administrators):
            raise ValueError("launch validators must have distinct administrator IDs")
        if len(self.publisher_registry) != limits.max_active_publishers:
            raise ValueError("publisher registry must match max_active_publishers")
        if len(self.control_group_registry) != limits.max_active_control_groups:
            raise ValueError("control-group registry must match max_active_control_groups")

        group_ids = [bytes.fromhex(item.control_group_id) for item in self.control_group_registry]
        if group_ids != sorted(group_ids) or len(set(group_ids)) != len(group_ids):
            raise ValueError("control-group registry must be unique and sorted by raw ID")
        administrators = [account_id32(item.administrator) for item in self.control_group_registry]
        if len(set(administrators)) != len(administrators):
            raise ValueError("control groups must have distinct administrators")

        publisher_accounts = [
            account_id32(item.publisher_hotkey) for item in self.publisher_registry
        ]
        if publisher_accounts != sorted(publisher_accounts) or len(set(publisher_accounts)) != len(
            publisher_accounts
        ):
            raise ValueError("publisher registry must be unique and sorted by hotkey account")
        owner_accounts = [account_id32(item.owner_coldkey) for item in self.publisher_registry]
        if len(set(owner_accounts)) != len(owner_accounts):
            raise ValueError("launch publisher entries must have distinct owning coldkeys")
        if set(publisher_accounts).intersection(owner_accounts + administrators):
            raise ValueError("publisher hotkeys must not also be coldkeys or administrators")

        known_groups = set(group_ids)
        publisher_groups = [
            bytes.fromhex(item.control_group_id) for item in self.publisher_registry
        ]
        if any(group not in known_groups for group in publisher_groups):
            raise ValueError("publisher references an unknown control group")
        if set(publisher_groups) != known_groups:
            raise ValueError("every launch control group must have a publisher")
        if len(publisher_groups) == len(group_ids) and len(set(publisher_groups)) != len(
            publisher_groups
        ):
            raise ValueError("launch requires exactly one publisher per control group")

        _validate_initial_launch_profile(self.clock, limits, self.thresholds)
        return self

    @classmethod
    def launch(
        cls,
        *,
        translation_weights_active: Literal[False],
        activation_block: int,
        minimum_publisher_collateral_alpha_rao: int,
        soak_start_window_index: int,
        validator_capacity_set_root: str,
        validator_cost_schedule_hash: str,
        implementation_pins: PolicyImplementationPins,
        validator_registry: list[ValidatorRegistryEntry],
        control_group_registry: list[PublisherControlGroup],
        publisher_registry: list[PublisherRegistryEntry],
    ) -> ScoringPolicy:
        return cls(
            schema=SCORING_POLICY_SCHEMA,
            protocol=PROTOCOL_VERSION,
            netuid=78,
            mechanism_id=0,
            translation_weights_active=translation_weights_active,
            activation_block=activation_block,
            minimum_publisher_collateral_alpha_rao=minimum_publisher_collateral_alpha_rao,
            soak_start_window_index=soak_start_window_index,
            validator_capacity_set_root=validator_capacity_set_root,
            validator_cost_schedule_hash=validator_cost_schedule_hash,
            implementation_pins=implementation_pins,
            clock=PolicyClock.launch(),
            limits=PolicyLimits.launch(),
            thresholds=PolicyThresholds.launch(),
            validator_registry=validator_registry,
            control_group_registry=control_group_registry,
            publisher_registry=publisher_registry,
        )


def _validate_initial_launch_profile(
    clock: PolicyClock,
    limits: PolicyLimits,
    thresholds: PolicyThresholds,
) -> None:
    expected_clock = PolicyClock.launch()
    expected_limits = PolicyLimits.launch()
    expected_thresholds = PolicyThresholds.launch()
    if clock != expected_clock:
        raise ValueError("clock does not match the version 0.1 initial launch profile")
    if limits != expected_limits:
        raise ValueError("limits do not match the version 0.1 initial launch profile")
    if thresholds != expected_thresholds:
        raise ValueError("thresholds do not match the version 0.1 initial launch profile")


def scoring_policy_hash(policy: ScoringPolicy) -> str:
    """Return SHA-256 of the complete RFC 8785 policy document."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    return hashlib.sha256(canonical_json_bytes(policy)).hexdigest()


def activation_equivalence_digest(policy: ScoringPolicy) -> str:
    """Hash the policy after removing only the two activation fields."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    document = policy.model_dump(mode="json", by_alias=True)
    del document["translation_weights_active"]
    del document["activation_block"]
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def validate_scoring_runtime(policy: ScoringPolicy) -> None:
    """Fail closed when local normalization inputs differ from the policy bytes."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    from .scoring import scoring_environment

    expected = policy.implementation_pins.scoring
    actual = scoring_environment()
    comparisons = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "unicode_data_version": unicodedata.unidata_version,
        "regex_distribution_version": actual["regex_distribution_version"],
        "regex_distribution_content_sha256": _distribution_content_sha256("regex"),
        "rfc8785_distribution_version": _installed_version("rfc8785"),
        "rfc8785_distribution_content_sha256": _distribution_content_sha256("rfc8785"),
        "pydantic_distribution_version": _installed_version("pydantic"),
        "pydantic_distribution_content_sha256": _distribution_content_sha256("pydantic"),
        "pydantic_core_distribution_version": _installed_version("pydantic-core"),
        "pydantic_core_distribution_content_sha256": _distribution_content_sha256("pydantic-core"),
        "scoring_source_sha256": actual["scoring_source_sha256"],
    }
    for field, value in comparisons.items():
        if getattr(expected, field) != value:
            raise RuntimeError(f"scoring runtime does not match policy pin: {field}")
    for module_name, distribution in (
        ("regex", "regex"),
        ("rfc8785", "rfc8785"),
        ("pydantic", "pydantic"),
        ("pydantic_core", "pydantic-core"),
    ):
        _require_loaded_module_from_distribution(module_name, distribution)


def validate_rehearsal_runtime(policy: ScoringPolicy) -> None:
    """Validate every package and beacon input exercised by the offline runner."""

    validate_scoring_runtime(policy)
    if policy.implementation_pins.umi_source_tree_sha256 != umi_source_tree_sha256():
        raise RuntimeError("rehearsal runtime does not match policy pin: umi_source_tree_sha256")
    expected = policy.implementation_pins.timelock
    package_comparisons = {
        "bittensor_distribution_version": _installed_version("bittensor"),
        "bittensor_distribution_content_sha256": _distribution_content_sha256("bittensor"),
        "bittensor_core_distribution_version": _installed_version("bittensor-core"),
        "bittensor_core_distribution_content_sha256": _distribution_content_sha256(
            "bittensor-core"
        ),
        "py_ecc_distribution_version": _installed_version("py-ecc"),
        "py_ecc_distribution_content_sha256": _distribution_content_sha256("py-ecc"),
    }
    for field, value in package_comparisons.items():
        if getattr(expected, field) != value:
            raise RuntimeError(f"rehearsal runtime does not match policy pin: {field}")
    for module_name, distribution in (
        ("bittensor", "bittensor"),
        ("bittensor.intents.weights", "bittensor"),
        ("bittensor_core", "bittensor-core"),
        ("py_ecc", "py-ecc"),
        ("py_ecc.bls.hash_to_curve", "py-ecc"),
        ("py_ecc.bls.point_compression", "py-ecc"),
        ("py_ecc.optimized_bls12_381", "py-ecc"),
    ):
        _require_loaded_module_from_distribution(module_name, distribution)

    from .drand import (
        QUICKNET_BEACON_ID,
        QUICKNET_CHAIN_HASH,
        QUICKNET_PUBLIC_KEY,
        QUICKNET_SCHEME_ID,
    )
    from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

    beacon_comparisons = {
        "beacon_id": QUICKNET_BEACON_ID,
        "chain_hash": QUICKNET_CHAIN_HASH,
        "scheme_id": QUICKNET_SCHEME_ID,
        "period_seconds": QUICKNET_PERIOD_MS // 1000,
        "genesis_time": QUICKNET_GENESIS_MS // 1000,
        "public_key": QUICKNET_PUBLIC_KEY,
    }
    for field, value in beacon_comparisons.items():
        if getattr(expected, field) != value:
            raise RuntimeError(f"rehearsal beacon does not match policy pin: {field}")


__all__ = [
    "SCORING_POLICY_SCHEMA",
    "ExactRatio",
    "PolicyClock",
    "PolicyImplementationPins",
    "PolicyLimits",
    "PolicyReasonCode",
    "PolicyThresholds",
    "ProtocolRulePins",
    "PublisherControlGroup",
    "PublisherRegistryEntry",
    "ResourceDeadlineRule",
    "ScoringPolicy",
    "ScoringRuntimePin",
    "ValidatorRegistryEntry",
    "activation_equivalence_digest",
    "scoring_policy_hash",
    "umi_source_tree_sha256",
    "validate_rehearsal_runtime",
    "validate_scoring_runtime",
]
