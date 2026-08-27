"""Strict publisher artifact schemas for the version 0.1 launch profile."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .canary import canary_count, validate_canary_pair, wer_canary_stratum
from .encoding import account_id32
from .policy import ScoringPolicy, activation_equivalence_digest, scoring_policy_hash
from .protocol import (
    GROUND_TRUTH_TLE_PROFILE,
    PROTOCOL_VERSION,
    BlockHash,
    GroundTruthPayload,
    Hex32,
    NonEmptyText,
    OpaqueId,
    StrictProtocolModel,
    base64url_decode,
    canonical_json_bytes,
)

PUBLIC_BATCH_MANIFEST_SCHEMA = "umi-public-batch-manifest/1"
PUBLISHER_CAPACITY_SCHEMA = "umi-publisher-capacity/1"


class MediaCommitment(StrictProtocolModel):
    """Public commitment to one policy-conforming, metadata-stripped clip."""

    sha256: Hex32
    frame_digest: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=16 * 1024 * 1024)]
    duration_ms: Annotated[int, Field(ge=2_000, le=15_000)]
    width: Annotated[int, Field(gt=0, le=1280)]
    height: Annotated[int, Field(gt=0, le=720)]
    frame_rate_numerator: Annotated[int, Field(gt=0)]
    frame_rate_denominator: Annotated[int, Field(gt=0)]
    media_type: Literal["video/mp4"]
    container: Literal["mp4"]
    video_codec: Literal["h264"]
    audio_track_count: Literal[0]
    metadata_stripped: Literal[True]

    @model_validator(mode="after")
    def validate_frame_rate(self) -> Self:
        if self.frame_rate_numerator > 30 * self.frame_rate_denominator:
            raise ValueError("frame rate must not exceed 30 frames per second")
        return self


class PublicBatchItem(StrictProtocolModel):
    challenge_id: OpaqueId
    metric: Literal["cer", "wer"]
    stratum: Literal["fingerspelling", "short_utterance", "continuous"]
    media: MediaCommitment
    signer_id_sha256: Hex32
    consent_manifest_sha256: Hex32
    provenance_manifest_sha256: Hex32

    @model_validator(mode="after")
    def validate_metric(self) -> Self:
        expected_metric = "cer" if self.stratum == "fingerspelling" else "wer"
        if self.metric != expected_metric:
            raise ValueError("fingerspelling uses CER and every other launch stratum uses WER")
        return self


class PublicBatchManifest(StrictProtocolModel):
    schema_: Literal[PUBLIC_BATCH_MANIFEST_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    batch_id: OpaqueId
    publisher_hotkey: NonEmptyText
    scoring_policy_hash: Hex32
    tle_profile: Literal[GROUND_TRUTH_TLE_PROFILE]
    response_close_round: Annotated[int, Field(gt=0)]
    reveal_round: Annotated[int, Field(gt=0)]
    ciphertext_sha256: Hex32
    items: Annotated[list[PublicBatchItem], Field(min_length=14, max_length=14)]

    @model_validator(mode="after")
    def validate_launch_batch(self) -> Self:
        account_id32(self.publisher_hotkey)
        if self.reveal_round <= self.response_close_round:
            raise ValueError("reveal_round must be greater than response_close_round")

        challenge_ids = [base64url_decode(item.challenge_id) for item in self.items]
        if challenge_ids != sorted(challenge_ids) or len(set(challenge_ids)) != len(challenge_ids):
            raise ValueError("batch items must be unique and sorted by decoded challenge ID")
        video_hashes = [item.media.sha256 for item in self.items]
        frame_hashes = [item.media.frame_digest for item in self.items]
        if len(set(video_hashes)) != len(video_hashes):
            raise ValueError("batch video hashes must be unique")
        if len(set(frame_hashes)) != len(frame_hashes):
            raise ValueError("batch frame digests must be unique")

        expected_wer_stratum = wer_canary_stratum(self.window_id, self.batch_id)
        expected_strata = Counter(
            {
                "fingerspelling": 3,
                "short_utterance": 4 + int(expected_wer_stratum == "short_utterance"),
                "continuous": 6 + int(expected_wer_stratum == "continuous"),
            }
        )
        if Counter(item.stratum for item in self.items) != expected_strata:
            raise ValueError("public batch strata do not match the launch batch and canary mix")

        signer_counts = Counter(item.signer_id_sha256 for item in self.items)
        if len(signer_counts) < 7:
            raise ValueError("the full launch batch requires at least seven signers")
        if max(signer_counts.values(), default=0) > 2:
            raise ValueError("a signer may supply at most two launch-batch items")
        return self


class CapacityCadence(StrictProtocolModel):
    window_stride_blocks: Annotated[int, Field(gt=0)]
    target_block_interval_seconds: Annotated[int, Field(gt=0)]
    scheduled_windows: Annotated[int, Field(gt=0)]


class PerWindowCapacity(StrictProtocolModel):
    candidate_batches: Annotated[int, Field(gt=0)]
    emission_bearing_clips: Annotated[int, Field(gt=0)]
    canary_clips: Annotated[int, Field(gt=0)]
    delivered_clips: Annotated[int, Field(gt=0)]
    maximum_retired_script_groups: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_arithmetic(self) -> Self:
        if self.delivered_clips != self.emission_bearing_clips + self.canary_clips:
            raise ValueError("delivered clips must equal scored clips plus canaries")
        if self.maximum_retired_script_groups != (
            self.emission_bearing_clips + 2 * self.canary_clips
        ):
            raise ValueError(
                "maximum retired script groups must count one ordinary and two per canary"
            )
        return self


class RunwayTotals(StrictProtocolModel):
    candidate_batches: Annotated[int, Field(gt=0)]
    delivered_clips: Annotated[int, Field(gt=0)]
    maximum_retired_script_groups: Annotated[int, Field(gt=0)]


class OneGroupLoss(StrictProtocolModel):
    minimum_remaining_groups: Literal[2]
    this_group_continues_at_declared_capacity: Literal[True]


class PublisherCapacityStatement(StrictProtocolModel):
    schema_: Literal[PUBLISHER_CAPACITY_SCHEMA] = Field(alias="schema")
    control_group_id: Hex32
    administrator: NonEmptyText
    publisher_hotkeys: Annotated[list[NonEmptyText], Field(min_length=1)]
    scoring_policy_hash: Hex32
    activation_equivalence_digest: Hex32
    issued_block: Annotated[int, Field(ge=0)]
    issued_block_hash: BlockHash
    valid_from_block: Annotated[int, Field(ge=0)]
    valid_through_block: Annotated[int, Field(ge=0)]
    cadence: CapacityCadence
    per_window_capacity: PerWindowCapacity
    runway_totals: RunwayTotals
    one_group_loss: OneGroupLoss
    control_disclosure_sha256: Hex32

    @model_validator(mode="after")
    def validate_statement(self) -> Self:
        account_id32(self.administrator)
        accounts = [account_id32(value) for value in self.publisher_hotkeys]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("publisher hotkeys must be unique and sorted by decoded account")
        if not self.issued_block <= self.valid_from_block <= self.valid_through_block:
            raise ValueError("capacity statement validity blocks are not ordered")

        windows = self.cadence.scheduled_windows
        expected_totals = (
            self.per_window_capacity.candidate_batches * windows,
            self.per_window_capacity.delivered_clips * windows,
            self.per_window_capacity.maximum_retired_script_groups * windows,
        )
        actual_totals = (
            self.runway_totals.candidate_batches,
            self.runway_totals.delivered_clips,
            self.runway_totals.maximum_retired_script_groups,
        )
        if actual_totals != expected_totals:
            raise ValueError("runway totals do not reproduce from per-window capacity")
        return self


def public_batch_manifest_hash(manifest: PublicBatchManifest) -> str:
    if not isinstance(manifest, PublicBatchManifest):
        raise TypeError("manifest must be a PublicBatchManifest")
    return hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


def validate_public_batch_manifest(
    manifest: PublicBatchManifest,
    policy: ScoringPolicy,
) -> None:
    """Bind a structurally valid launch manifest to one canonical policy."""

    if not isinstance(manifest, PublicBatchManifest):
        raise TypeError("manifest must be a PublicBatchManifest")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if manifest.scoring_policy_hash != scoring_policy_hash(policy):
        raise ValueError("public batch manifest names a different scoring policy")
    registered_publishers = {
        account_id32(entry.publisher_hotkey) for entry in policy.publisher_registry
    }
    if account_id32(manifest.publisher_hotkey) not in registered_publishers:
        raise ValueError("public batch publisher is not in the active policy registry")

    limits = policy.limits
    if limits.emission_bearing_clips_per_batch != 12:
        raise ValueError("manifest shape and policy scored-clip count disagree")
    expected_canaries = canary_count(
        limits.emission_bearing_clips_per_batch,
        policy.thresholds.canary_fraction.fraction,
    )
    if expected_canaries != 2:
        raise ValueError("manifest shape and policy canary count disagree")
    for item in manifest.items:
        media = item.media
        if (
            not limits.minimum_clip_duration_ms
            <= media.duration_ms
            <= (limits.maximum_clip_duration_ms)
        ):
            raise ValueError("clip duration exceeds policy bounds")
        if media.size_bytes > limits.maximum_clip_size_bytes:
            raise ValueError("clip size exceeds the policy bound")
        if media.width > limits.maximum_clip_width or media.height > limits.maximum_clip_height:
            raise ValueError("clip dimensions exceed policy bounds")
        if media.frame_rate_numerator > (limits.maximum_clip_fps * media.frame_rate_denominator):
            raise ValueError("clip frame rate exceeds the policy bound")
    if len(canonical_json_bytes(manifest)) > limits.maximum_manifest_bytes:
        raise ValueError("public batch manifest exceeds the policy byte ceiling")


def validate_revealed_batch_shape(
    manifest: PublicBatchManifest,
    ground_truth: GroundTruthPayload,
    policy: ScoringPolicy,
) -> None:
    """Bind hidden canary labels to the public manifest after the reveal round."""

    validate_public_batch_manifest(manifest, policy)
    if not isinstance(ground_truth, GroundTruthPayload):
        raise TypeError("ground_truth must be a GroundTruthPayload")
    if (
        ground_truth.window_id != manifest.window_id
        or ground_truth.batch_id != manifest.batch_id
        or ground_truth.scoring_policy_hash != manifest.scoring_policy_hash
        or ground_truth.tle_profile != manifest.tle_profile
        or ground_truth.response_close_round != manifest.response_close_round
        or ground_truth.reveal_round != manifest.reveal_round
    ):
        raise ValueError("revealed ground truth does not bind the public batch manifest")

    public_by_challenge = {item.challenge_id: item for item in manifest.items}
    revealed_by_challenge = {item.challenge_id: item for item in ground_truth.items}
    if public_by_challenge.keys() != revealed_by_challenge.keys():
        raise ValueError("revealed items are not a bijection with public batch items")
    for challenge_id, revealed in revealed_by_challenge.items():
        public = public_by_challenge[challenge_id]
        if public.metric != revealed.metric:
            raise ValueError("revealed metric disagrees with the public batch item")
        if public.consent_manifest_sha256 != revealed.consent_manifest_sha256:
            raise ValueError("revealed consent commitment disagrees with the public batch item")

    ordinary = [item for item in ground_truth.items if not item.canary]
    canaries = [item for item in ground_truth.items if item.canary]
    if len(ordinary) != 12 or len(canaries) != 2:
        raise ValueError("launch batches require exactly 12 scored clips and two canaries")
    ordinary_strata = Counter(public_by_challenge[item.challenge_id].stratum for item in ordinary)
    if ordinary_strata != {
        "fingerspelling": 2,
        "short_utterance": 4,
        "continuous": 6,
    }:
        raise ValueError("launch scored clips require the exact 2/4/6 stratum allocation")

    cer_canaries = [item for item in canaries if item.metric == "cer"]
    wer_canaries = [item for item in canaries if item.metric == "wer"]
    if len(cer_canaries) != 1 or len(wer_canaries) != 1:
        raise ValueError("launch batches require one CER and one WER canary")
    cer_public = public_by_challenge[cer_canaries[0].challenge_id]
    if cer_public.stratum != "fingerspelling":
        raise ValueError("the CER canary must use the fingerspelling stratum")
    wer_public = public_by_challenge[wer_canaries[0].challenge_id]
    if wer_public.stratum != wer_canary_stratum(manifest.window_id, manifest.batch_id):
        raise ValueError("the WER canary stratum does not match the policy-derived value")
    for item in canaries:
        validate_canary_pair(
            item,
            separation_score=policy.thresholds.canary_separation_score.fraction,
        )


def publisher_capacity_digest(statement: PublisherCapacityStatement) -> bytes:
    """Return the raw digest signed by a control-group administrator."""

    if not isinstance(statement, PublisherCapacityStatement):
        raise TypeError("statement must be a PublisherCapacityStatement")
    return hashlib.sha256(b"umi-publisher-capacity-v1\0" + canonical_json_bytes(statement)).digest()


def validate_publisher_capacity_statement(
    statement: PublisherCapacityStatement,
    policy: ScoringPolicy,
) -> None:
    """Verify registry binding, cadence, runway arithmetic, and policy digests."""

    if not isinstance(statement, PublisherCapacityStatement):
        raise TypeError("statement must be a PublisherCapacityStatement")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if statement.scoring_policy_hash != scoring_policy_hash(policy):
        raise ValueError("capacity statement names a different scoring policy")
    if statement.activation_equivalence_digest != activation_equivalence_digest(policy):
        raise ValueError("capacity statement activation-equivalence digest does not reproduce")

    groups = {item.control_group_id: item for item in policy.control_group_registry}
    group = groups.get(statement.control_group_id)
    if group is None:
        raise ValueError("capacity statement names an unknown control group")
    if account_id32(statement.administrator) != account_id32(group.administrator):
        raise ValueError("capacity statement administrator does not match policy")
    expected_publishers = sorted(
        (
            entry.publisher_hotkey
            for entry in policy.publisher_registry
            if entry.control_group_id == statement.control_group_id
        ),
        key=account_id32,
    )
    if statement.publisher_hotkeys != expected_publishers:
        raise ValueError("capacity statement publisher set does not match policy")

    clock = policy.clock
    if statement.cadence.window_stride_blocks != clock.window_stride_blocks or (
        statement.cadence.target_block_interval_seconds != clock.target_block_interval_seconds
    ):
        raise ValueError("capacity statement cadence does not match policy")
    runway_seconds = policy.limits.challenge_supply_runway_days * 86_400
    window_seconds = clock.window_stride_blocks * clock.target_block_interval_seconds
    required_windows = (runway_seconds + window_seconds - 1) // window_seconds
    if statement.cadence.scheduled_windows != required_windows:
        raise ValueError("capacity statement scheduled-window count does not cover exact runway")

    expected_canaries = canary_count(
        policy.limits.emission_bearing_clips_per_batch,
        policy.thresholds.canary_fraction.fraction,
    )
    per_window = statement.per_window_capacity
    expected_per_window = (
        policy.limits.max_candidate_batches_per_group,
        policy.limits.emission_bearing_clips_per_batch,
        expected_canaries,
        policy.limits.emission_bearing_clips_per_batch + expected_canaries,
        policy.limits.emission_bearing_clips_per_batch + 2 * expected_canaries,
    )
    actual_per_window = (
        per_window.candidate_batches,
        per_window.emission_bearing_clips,
        per_window.canary_clips,
        per_window.delivered_clips,
        per_window.maximum_retired_script_groups,
    )
    if actual_per_window != expected_per_window:
        raise ValueError("capacity statement per-window values do not match policy")

    if statement.valid_from_block > policy.activation_block:
        raise ValueError("capacity validity begins after the policy activation block")
    required_valid_through = policy.activation_block + required_windows * clock.window_stride_blocks
    if statement.valid_through_block < required_valid_through:
        raise ValueError("capacity validity does not cover the complete runway")


__all__ = [
    "PUBLIC_BATCH_MANIFEST_SCHEMA",
    "PUBLISHER_CAPACITY_SCHEMA",
    "CapacityCadence",
    "MediaCommitment",
    "OneGroupLoss",
    "PerWindowCapacity",
    "PublicBatchItem",
    "PublicBatchManifest",
    "PublisherCapacityStatement",
    "RunwayTotals",
    "public_batch_manifest_hash",
    "publisher_capacity_digest",
    "validate_public_batch_manifest",
    "validate_publisher_capacity_statement",
    "validate_revealed_batch_shape",
]
