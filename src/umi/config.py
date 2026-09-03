"""Fail-closed settings for the initial UMI component-test runtime."""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .policy import ScoringPolicy


@dataclass(frozen=True)
class Limits:
    maximum_request_body_bytes: int = 64 * 1024
    maximum_response_body_bytes: int = 64 * 1024
    maximum_response_plaintext_bytes: int = 40 * 1024
    maximum_http_header_bytes: int = 16 * 1024
    maximum_clip_size_bytes: int = 16 * 1024 * 1024
    maximum_hypothesis_utf8_bytes: int = 4 * 1024
    maximum_hypothesis_tokens: int = 128
    maximum_hypothesis_graphemes: int = 512
    maximum_request_transmissions_per_assignment: int = 2
    maximum_response_bodies_per_assignment: int = 2
    maximum_video_fetch_attempts_per_actor: int = 2
    maximum_assignment_wire_bytes: int = 34 * 1024 * 1024
    maximum_assignments_per_validator_window: int = 28
    maximum_total_assignments_per_window: int = 112
    maximum_unique_videos_per_validator_window: int = 28
    maximum_retained_video_bytes_per_validator_window: int = 28 * 16 * 1024 * 1024
    maximum_unique_videos_per_window: int = 112
    maximum_retained_video_bytes: int = 112 * 16 * 1024 * 1024
    maximum_active_windows: int = 1
    maximum_nonce_rows_per_validator: int = 128
    maximum_nonce_rows_total: int = 512
    maximum_nonce_database_bytes: int = 1024 * 1024
    btauth_max_age_seconds: float = 120.0
    btauth_allowed_skew_seconds: float = 2.0
    request_body_timeout_seconds: float = 5.0
    video_fetch_timeout_seconds: float = 30.0
    backend_lifecycle_timeout_seconds: float = 60.0
    inference_admission_timeout_seconds: float = 10.0
    inference_timeout_seconds: float = 120.0
    response_seal_margin_seconds: float = 1.0
    maximum_inference_concurrency: int = 1

    def __post_init__(self) -> None:
        for field_name in (
            "maximum_request_body_bytes",
            "maximum_response_body_bytes",
            "maximum_response_plaintext_bytes",
            "maximum_http_header_bytes",
            "maximum_clip_size_bytes",
            "maximum_hypothesis_utf8_bytes",
            "maximum_hypothesis_tokens",
            "maximum_hypothesis_graphemes",
            "maximum_request_transmissions_per_assignment",
            "maximum_response_bodies_per_assignment",
            "maximum_video_fetch_attempts_per_actor",
            "maximum_assignment_wire_bytes",
            "maximum_assignments_per_validator_window",
            "maximum_total_assignments_per_window",
            "maximum_unique_videos_per_validator_window",
            "maximum_retained_video_bytes_per_validator_window",
            "maximum_unique_videos_per_window",
            "maximum_retained_video_bytes",
            "maximum_active_windows",
            "maximum_nonce_rows_per_validator",
            "maximum_nonce_rows_total",
            "maximum_nonce_database_bytes",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be positive")
        if self.maximum_nonce_rows_total < self.maximum_nonce_rows_per_validator:
            raise ValueError("maximum_nonce_rows_total must be at least the per-validator ceiling")
        if (
            isinstance(self.video_fetch_timeout_seconds, bool)
            or not isinstance(self.video_fetch_timeout_seconds, (int, float))
            or not math.isfinite(self.video_fetch_timeout_seconds)
            or self.video_fetch_timeout_seconds <= 0
        ):
            raise ValueError("video_fetch_timeout_seconds must be positive")
        if (
            isinstance(self.btauth_max_age_seconds, bool)
            or not isinstance(self.btauth_max_age_seconds, (int, float))
            or not math.isfinite(self.btauth_max_age_seconds)
            or self.btauth_max_age_seconds <= 0
        ):
            raise ValueError("btauth_max_age_seconds must be positive")
        if (
            isinstance(self.btauth_allowed_skew_seconds, bool)
            or not isinstance(self.btauth_allowed_skew_seconds, (int, float))
            or not math.isfinite(self.btauth_allowed_skew_seconds)
            or self.btauth_allowed_skew_seconds < 0
        ):
            raise ValueError("btauth_allowed_skew_seconds must be non-negative")
        if self.btauth_allowed_skew_seconds >= self.btauth_max_age_seconds:
            raise ValueError("btauth_allowed_skew_seconds must be less than max age")
        if (
            isinstance(self.request_body_timeout_seconds, bool)
            or not isinstance(self.request_body_timeout_seconds, (int, float))
            or not math.isfinite(self.request_body_timeout_seconds)
            or self.request_body_timeout_seconds <= 0
        ):
            raise ValueError("request_body_timeout_seconds must be positive")
        if (
            isinstance(self.inference_timeout_seconds, bool)
            or not isinstance(self.inference_timeout_seconds, (int, float))
            or not math.isfinite(self.inference_timeout_seconds)
            or self.inference_timeout_seconds <= 0
        ):
            raise ValueError("inference_timeout_seconds must be positive")
        for field_name in (
            "backend_lifecycle_timeout_seconds",
            "inference_admission_timeout_seconds",
        ):
            value = getattr(self, field_name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{field_name} must be positive")
        if (
            isinstance(self.response_seal_margin_seconds, bool)
            or not isinstance(self.response_seal_margin_seconds, (int, float))
            or not math.isfinite(self.response_seal_margin_seconds)
            or self.response_seal_margin_seconds <= 0
        ):
            raise ValueError("response_seal_margin_seconds must be positive")
        if (
            isinstance(self.maximum_inference_concurrency, bool)
            or not isinstance(self.maximum_inference_concurrency, int)
            or self.maximum_inference_concurrency <= 0
        ):
            raise ValueError("maximum_inference_concurrency must be a positive integer")

    @classmethod
    def from_policy(
        cls,
        policy: ScoringPolicy,
        *,
        inference_timeout_seconds: float = 120.0,
        backend_lifecycle_timeout_seconds: float = 60.0,
        inference_admission_timeout_seconds: float = 10.0,
        maximum_inference_concurrency: int = 1,
        request_body_timeout_seconds: float = 5.0,
    ) -> Limits:
        """Derive every protocol ceiling from one canonical scoring policy."""

        from .policy import ScoringPolicy

        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be a ScoringPolicy")
        limits = policy.limits
        canary_fraction = policy.thresholds.canary_fraction.fraction
        canaries = max(
            1,
            _ceil_fraction(
                limits.emission_bearing_clips_per_batch * canary_fraction,
            ),
        )
        assignments = limits.batches_selected_per_window * (
            limits.emission_bearing_clips_per_batch + canaries
        )
        registered_validators = len(policy.validator_registry)
        maximum_nonce_rows_per_validator = max(
            64,
            2 * assignments * limits.maximum_request_transmissions_per_assignment,
        )
        maximum_nonce_rows_total = maximum_nonce_rows_per_validator * registered_validators
        return cls(
            maximum_request_body_bytes=limits.maximum_request_body_bytes,
            maximum_response_body_bytes=limits.maximum_response_body_bytes,
            maximum_response_plaintext_bytes=min(
                40 * 1024,
                limits.maximum_response_body_bytes,
            ),
            maximum_http_header_bytes=limits.maximum_http_header_bytes,
            maximum_clip_size_bytes=limits.maximum_clip_size_bytes,
            maximum_hypothesis_utf8_bytes=limits.maximum_hypothesis_utf8_bytes,
            maximum_hypothesis_tokens=limits.maximum_hypothesis_tokens,
            maximum_hypothesis_graphemes=limits.maximum_hypothesis_graphemes,
            maximum_request_transmissions_per_assignment=(
                limits.maximum_request_transmissions_per_assignment
            ),
            maximum_response_bodies_per_assignment=(limits.maximum_response_bodies_per_assignment),
            maximum_video_fetch_attempts_per_actor=(limits.maximum_video_fetch_attempts_per_actor),
            maximum_assignment_wire_bytes=limits.maximum_assignment_wire_bytes,
            maximum_assignments_per_validator_window=assignments,
            maximum_total_assignments_per_window=assignments * registered_validators,
            maximum_unique_videos_per_validator_window=assignments,
            maximum_retained_video_bytes_per_validator_window=(
                assignments * limits.maximum_clip_size_bytes
            ),
            maximum_unique_videos_per_window=assignments * registered_validators,
            maximum_retained_video_bytes=(
                assignments * registered_validators * limits.maximum_clip_size_bytes
            ),
            maximum_active_windows=1,
            maximum_nonce_rows_per_validator=maximum_nonce_rows_per_validator,
            maximum_nonce_rows_total=maximum_nonce_rows_total,
            maximum_nonce_database_bytes=max(
                1024 * 1024,
                maximum_nonce_rows_total * 512,
            ),
            btauth_max_age_seconds=float(limits.btauth_max_age_seconds),
            btauth_allowed_skew_seconds=float(limits.btauth_allowed_skew_seconds),
            request_body_timeout_seconds=request_body_timeout_seconds,
            backend_lifecycle_timeout_seconds=backend_lifecycle_timeout_seconds,
            inference_admission_timeout_seconds=inference_admission_timeout_seconds,
            inference_timeout_seconds=inference_timeout_seconds,
            maximum_inference_concurrency=maximum_inference_concurrency,
        )


def _ceil_fraction(value: Fraction) -> int:
    return (value.numerator + value.denominator - 1) // value.denominator


@dataclass(frozen=True)
class SafetyBoundary:
    """What this initial slice is allowed to claim and do."""

    netuid: int = 78
    mechanism_id: int = 0
    translation_weights_active: bool = False
    protocol_conformance: bool = False
    activation_evidence: bool = False
    terminal_code: str = "component_test_no_weight"

    def __post_init__(self) -> None:
        if self.netuid != 78:
            raise ValueError("the version 0.1 component profile is pinned to SN78")
        if self.mechanism_id != 0:
            raise ValueError("the version 0.1 launch profile uses MechId 0")
        if self.translation_weights_active:
            raise ValueError("the initial component runtime cannot activate or submit weights")
        if self.protocol_conformance or self.activation_evidence:
            raise ValueError("component tests cannot claim conformance or activation evidence")
        if self.terminal_code != "component_test_no_weight":
            raise ValueError("component tests must use the component_test_no_weight terminal code")


SAFETY_BOUNDARY = SafetyBoundary()
