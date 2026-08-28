"""Fail-closed settings for the initial UMI component-test runtime."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    maximum_request_body_bytes: int = 64 * 1024
    maximum_response_body_bytes: int = 64 * 1024
    maximum_response_plaintext_bytes: int = 40 * 1024
    maximum_http_header_bytes: int = 16 * 1024
    maximum_clip_size_bytes: int = 16 * 1024 * 1024
    maximum_hypothesis_utf8_bytes: int = 4 * 1024
    video_fetch_timeout_seconds: float = 30.0
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
        ):
            if getattr(self, field_name) <= 0:
                raise ValueError(f"{field_name} must be positive")
        if self.video_fetch_timeout_seconds <= 0:
            raise ValueError("video_fetch_timeout_seconds must be positive")
        if self.inference_timeout_seconds <= 0:
            raise ValueError("inference_timeout_seconds must be positive")
        if self.response_seal_margin_seconds <= 0:
            raise ValueError("response_seal_margin_seconds must be positive")
        if (
            isinstance(self.maximum_inference_concurrency, bool)
            or self.maximum_inference_concurrency <= 0
        ):
            raise ValueError("maximum_inference_concurrency must be a positive integer")


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
