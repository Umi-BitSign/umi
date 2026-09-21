"""Pure validation for the off-host public intake monitor.

This module has no network, wallet, chain, or filesystem access.  It validates a
fenced capture of the public intake and observer routes, reconstructs the
independent submission checkpoint, and advances monotonic monitor state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import pairwise
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .competition_client import AdmissionReceipt
from .competition_launch import PublicIntakeDeployment, PublicRoundSchedule
from .competition_service import RetainedIntakeState
from .competition_submission_checkpoint import build_submission_checkpoint
from .observer_models import ParticipantsResponse
from .open_competition import (
    CompetitionPolicy,
    Hex32,
    SignedSubmission,
    StrictProtocolModel,
    digest,
    identity,
    validate_admission,
)
from .protocol import BlockHash, canonical_json_bytes

Severity = Literal["ok", "warning", "investigate", "critical", "stale"]
_SEVERITY_ORDER: dict[Severity, int] = {
    "ok": 0,
    "warning": 1,
    "investigate": 2,
    "critical": 3,
    "stale": 4,
}


class PublicIntakeMonitorError(ValueError):
    """A stable, operator-visible validation failure."""


def _fail(code: str) -> None:
    raise PublicIntakeMonitorError(code)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def document_sha256(value: Any) -> str:
    """Hash an exact JSON document without adding protocol digest framing."""

    return _sha256(canonical_json_bytes(value))


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("origin is invalid") from error
    canonical_host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not canonical_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
    ):
        raise ValueError("origin must be one credential-free HTTPS origin without a path")
    rendered_host = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    rendered = f"https://{rendered_host}" + ("" if port in {None, 443} else f":{port}")
    if value != rendered:
        raise ValueError("origin must use its canonical HTTPS form")
    return value


class ExpectedIntakeIdentity(StrictProtocolModel):
    """One explicitly reviewed policy and deployment pair in rollover order."""

    schema_: Literal["umi-public-intake-monitor-identity/1"] = Field(alias="schema")
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    policy_sha256: Hex32
    deployment_document_sha256: Hex32
    expected_baseline_promotion_sha256: Hex32
    not_before_checked_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    acceptance_not_before_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    minimum_accepted_submission_count: Annotated[int, Field(ge=0, le=65_536)]
    required_submission_count: Annotated[int, Field(ge=0, le=65_536)]
    required_submission_set_sha256: Hex32
    admission_writer_generation: Annotated[int, Field(ge=1, le=2**31 - 1)] = 2


class ValidatorAgeThresholds(StrictProtocolModel):
    schema_: Literal["umi-validator-age-thresholds/1"] = Field(alias="schema")
    warning_blocks: Literal[200] = 200
    investigate_blocks: Literal[240] = 240
    critical_blocks: Literal[300] = 300
    stale_blocks: Literal[360] = 360


class ReviewedBootstrapCheckpoint(StrictProtocolModel):
    schema_: Literal["umi-public-intake-monitor-bootstrap/1"] = Field(alias="schema")
    identity_name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    accepted_submission_count: Annotated[int, Field(ge=0, le=65_536)]
    retained_head_sha256: Hex32


class PublicIntakeMonitorConfig(StrictProtocolModel):
    schema_: Literal["umi-public-intake-monitor-config/1"] = Field(alias="schema")
    competition_origin: Annotated[str, Field(min_length=1, max_length=2048)]
    observer_origin: Annotated[str, Field(min_length=1, max_length=2048)]
    expected_identities: Annotated[
        tuple[ExpectedIntakeIdentity, ...], Field(min_length=1, max_length=32)
    ]
    reviewed_bootstrap: ReviewedBootstrapCheckpoint
    watched_validator_uids: tuple[Literal[0, 54], Literal[54, 0]] = (0, 54)
    validator_age_thresholds: ValidatorAgeThresholds = Field(
        default_factory=lambda: ValidatorAgeThresholds(schema="umi-validator-age-thresholds/1")
    )
    maximum_checked_block_stall_seconds: Annotated[int, Field(ge=30, le=3600)] = 180
    maximum_observer_age_seconds: Annotated[int, Field(ge=15, le=600)] = 120
    maximum_observer_block_lag: Annotated[int, Field(ge=0, le=120)] = 20
    submission_page_size: Literal[100] = 100
    participant_page_size: Literal[512] = 512
    record_request_workers: Annotated[int, Field(ge=1, le=16)] = 8
    request_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 20
    maximum_poll_seconds: Annotated[int, Field(ge=30, le=3600)] = 240
    request_attempts: Annotated[int, Field(ge=1, le=5)] = 3
    snapshot_attempts: Annotated[int, Field(ge=1, le=5)] = 3
    maximum_response_bytes: Annotated[int, Field(ge=65_536, le=16 * 1024**2)] = 4 * 1024**2
    maximum_capture_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)] = 512 * 1024**2
    maximum_accepted_submission_count: Annotated[int, Field(ge=1, le=65_536)] = 4096

    @field_validator("competition_origin", "observer_origin")
    @classmethod
    def canonical_origin(cls, value: str) -> str:
        return _origin(value)

    @model_validator(mode="after")
    def ordered_identity_schedule(self) -> Self:
        names = [item.name for item in self.expected_identities]
        pairs = [
            (item.policy_sha256, item.deployment_document_sha256)
            for item in self.expected_identities
        ]
        blocks = [item.not_before_checked_block for item in self.expected_identities]
        acceptance_blocks = [item.acceptance_not_before_block for item in self.expected_identities]
        floors = [item.minimum_accepted_submission_count for item in self.expected_identities]
        if len(set(names)) != len(names) or len(set(pairs)) != len(pairs):
            raise ValueError("expected intake identities must be unique")
        if self.reviewed_bootstrap.identity_name != names[0]:
            raise ValueError("reviewed bootstrap must bind the first expected identity")
        if (
            self.reviewed_bootstrap.accepted_submission_count
            != self.expected_identities[0].minimum_accepted_submission_count
        ):
            raise ValueError("reviewed bootstrap count must equal the first identity floor")
        if any(later <= earlier for earlier, later in pairwise(blocks)):
            raise ValueError("expected identity observation blocks must strictly increase")
        if any(later <= earlier for earlier, later in pairwise(acceptance_blocks)):
            raise ValueError("expected identity acceptance blocks must strictly increase")
        if any(
            acceptance > observation
            for acceptance, observation in zip(acceptance_blocks, blocks, strict=True)
        ):
            raise ValueError("identity acceptance cannot begin after its observation floor")
        if floors != sorted(floors):
            raise ValueError("expected identity accepted-count floors cannot decrease")
        if set(self.watched_validator_uids) != {0, 54}:
            raise ValueError("the monitor must inspect validator UIDs 0 and 54")
        if self.maximum_capture_bytes < self.maximum_response_bytes:
            raise ValueError("capture byte bound must cover one maximum response")
        return self


class BaselineSummary(StrictProtocolModel):
    sequence: Annotated[int, Field(ge=0, le=2**53 - 1)]
    promotion_sha256: Hex32
    model_sha256: Hex32
    contributor_account_id32: Hex32 | None
    held_for_conflict: bool


class RetainedSubmissionHead(StrictProtocolModel):
    schema_: Literal["umi-competition-submission-head/1"] = Field(alias="schema")
    policy_sha256: Hex32
    record_count: Annotated[int, Field(ge=0, le=65_536)]
    submission_set_sha256: Hex32
    head_sha256: Hex32
    public_launch_sha256: Hex32
    external_checkpoint_sha256: Hex32
    external_checkpoint_durable: bool


class HistoricalIntakeArchiveSummary(StrictProtocolModel):
    schema_: Literal["umi-competition-intake-archive-summary/1"] = Field(alias="schema")
    policy_sha256: Hex32
    public_launch_sha256: Hex32
    manifest_sha256: Hex32
    record_count: Annotated[int, Field(ge=1, le=65_536)]
    submission_set_sha256: Hex32
    source_head_sha256: Hex32
    source_checkpoint_sha256: Hex32


class RegistrationProvenance(StrictProtocolModel):
    schema_: Literal["umi-competition-registration-provenance/1"] = Field(alias="schema")
    evidence_class: Literal["verifier_attested_finality"]
    offline_finality_proof: Literal[False]
    genesis_block_hash: BlockHash
    block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    block_hash: BlockHash
    state_root: BlockHash
    timestamp_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    snapshot_sha256: Hex32
    evidence_sha256: Hex32
    metadata_sha256: Hex32
    finality_evidence_sha256: Hex32
    finality_verifier_sha256: Hex32
    storage_proof_verifier_sha256: Hex32
    chain_submission_authorized: Literal[False]


class CompetitionStatus(StrictProtocolModel):
    schema_: Literal["umi-competition-status/2"] = Field(alias="schema")
    mode: Literal["intake_no_weight"]
    registration_source: Literal["verifier_attested_finality"]
    policy_sha256: Hex32
    policy: dict[str, JsonValue]
    baseline: BaselineSummary
    accepted_submission_count: Annotated[int, Field(ge=0, le=65_536)]
    retained_submission_head: RetainedSubmissionHead
    historical_intake_archives: Annotated[
        tuple[HistoricalIntakeArchiveSummary, ...], Field(max_length=8)
    ]
    admission_accepting_new: bool
    admission_capacity_available: bool
    admission_phase: Literal["not_open", "open", "closed", "capacity_exhausted", "unverified"]
    admission_checked_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    chain_submission_authorized: Literal[False]
    # Deal-preserving predecessors whose signed submissions the intake still admits
    # (competition_policy_lineage). Absent from statuses published before this field.
    honored_policy_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=16)] | None = None
    deal_sha256: Hex32 | None = None
    deployment: dict[str, JsonValue]
    round_schedule: PublicRoundSchedule
    continuous_intake: Literal[True] | None = None
    next_intake_schedule: PublicRoundSchedule | None = None
    assignment_delivery_ready: bool
    model_intake_ready: bool
    evaluation_ready: bool
    rewards_active: Literal[False]


class CompetitionReadiness(StrictProtocolModel):
    schema_: Literal["umi-competition-readiness/2"] = Field(alias="schema")
    mode: Literal["intake_no_weight"]
    ready_for: Literal[
        "first_round_intake_not_open",
        "first_round_intake",
        "first_round_intake_closed",
        "continuous_intake",
    ]
    policy_sha256: Hex32
    deployment: dict[str, JsonValue]
    round_schedule: PublicRoundSchedule
    continuous_intake: Literal[True] | None = None
    next_intake_schedule: PublicRoundSchedule | None = None
    retained_state: RetainedIntakeState
    retained_submission_head: RetainedSubmissionHead
    assignment_delivery_ready: bool
    model_intake_ready: bool
    admission_accepting_new: bool
    admission_phase: Literal["not_open", "open", "closed", "capacity_exhausted"]
    admission_checked_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    registration_count: Annotated[int, Field(ge=0, le=256)]
    registration_source: RegistrationProvenance
    evaluation_ready: bool
    rewards_active: Literal[False]
    chain_submission_authorized: Literal[False]


class AdmissionSummary(StrictProtocolModel):
    submission_sha256: Hex32
    hotkey_account_id32: Hex32
    track: Literal["endpoint", "model"]
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    accepted_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    valid_through_block: Annotated[int, Field(ge=0, le=2**53 - 1)]


class AdmissionPage(StrictProtocolModel):
    items: tuple[AdmissionSummary, ...]
    offset: Annotated[int, Field(ge=0, le=1_000_000)]
    limit: Literal[100]


class SubmissionRecordState(StrictProtocolModel):
    submission_sha256: Hex32
    policy_sha256: Hex32
    hotkey_account_id32: Hex32
    track: Literal["endpoint", "model"]
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    accepted_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    admission_identity_name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")] | None
    admission_writer_generation: Annotated[int, Field(ge=1, le=2**31 - 1)]
    record_sha256: Hex32


class RetainedCompetitionPolicy(StrictProtocolModel):
    policy_sha256: Hex32
    policy: dict[str, JsonValue]

    @model_validator(mode="after")
    def digest_matches_body(self) -> Self:
        try:
            policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(self.policy))
        except (ValidationError, ValueError) as error:
            raise ValueError("retained monitor policy is invalid") from error
        if digest(policy) != self.policy_sha256:
            raise ValueError("retained monitor policy digest differs from its body")
        return self


class RetainedIntakeDeployment(StrictProtocolModel):
    identity_name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    deployment_document_sha256: Hex32
    deployment: dict[str, JsonValue]

    @model_validator(mode="after")
    def digest_matches_body(self) -> Self:
        try:
            PublicIntakeDeployment.model_validate_json(canonical_json_bytes(self.deployment))
        except (ValidationError, ValueError) as error:
            raise ValueError("retained monitor deployment is invalid") from error
        if document_sha256(self.deployment) != self.deployment_document_sha256:
            raise ValueError("retained monitor deployment digest differs from its body")
        return self


class PublicIntakeMonitorState(StrictProtocolModel):
    schema_: Literal["umi-public-intake-monitor-state/1"] = Field(alias="schema")
    active_identity_name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    policy_sha256: Hex32
    deployment_document_sha256: Hex32
    accepted_submission_count: Annotated[int, Field(ge=0, le=65_536)]
    admission_checked_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    retained_head_sha256: Hex32
    last_checked_block_advanced_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    last_success_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    identity_history: Annotated[
        tuple[ExpectedIntakeIdentity, ...], Field(min_length=1, max_length=32)
    ]
    policies: Annotated[tuple[RetainedCompetitionPolicy, ...], Field(min_length=1, max_length=32)]
    deployments: Annotated[tuple[RetainedIntakeDeployment, ...], Field(min_length=1, max_length=32)]
    submissions: tuple[SubmissionRecordState, ...]

    @model_validator(mode="after")
    def canonical_submissions(self) -> Self:
        keys = [item.submission_sha256 for item in self.submissions]
        if keys != sorted(set(keys)) or len(keys) != self.accepted_submission_count:
            raise ValueError("monitor state submissions must be complete, sorted, and unique")
        policy_keys = [item.policy_sha256 for item in self.policies]
        if policy_keys != sorted(set(policy_keys)) or self.policy_sha256 not in policy_keys:
            raise ValueError("monitor state policies must be complete, sorted, and unique")
        if any(item.policy_sha256 not in policy_keys for item in self.submissions):
            raise ValueError("monitor state lacks a submission policy")
        identity_names = {item.name for item in self.identity_history}
        deployment_names = [item.identity_name for item in self.deployments]
        if deployment_names != [item.name for item in self.identity_history]:
            raise ValueError("monitor state deployments must match identity history")
        if any(
            deployment.deployment_document_sha256 != identity_.deployment_document_sha256
            for deployment, identity_ in zip(self.deployments, self.identity_history, strict=True)
        ):
            raise ValueError("monitor state deployment identity differs from its history")
        if any(
            item.admission_identity_name is not None
            and item.admission_identity_name not in identity_names
            for item in self.submissions
        ):
            raise ValueError("monitor state submission refers to an unknown identity")
        generations = {
            item.name: item.admission_writer_generation for item in self.identity_history
        }
        if any(
            item.admission_identity_name is not None
            and item.admission_writer_generation != generations[item.admission_identity_name]
            for item in self.submissions
        ):
            raise ValueError("monitor state submission writer generation differs from identity")
        if (
            self.identity_history[-1].name != self.active_identity_name
            or self.identity_history[-1].policy_sha256 != self.policy_sha256
            or self.identity_history[-1].deployment_document_sha256
            != self.deployment_document_sha256
        ):
            raise ValueError("monitor state active identity differs from its history")
        if self.last_checked_block_advanced_at_unix_ms > self.last_success_at_unix_ms:
            raise ValueError("monitor state progress time is in the future")
        return self


class MonitorIssue(StrictProtocolModel):
    schema_: Literal["umi-public-intake-monitor-issue/1"] = Field(alias="schema")
    severity: Literal["warning", "investigate", "critical", "stale"]
    code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_]{0,95}$")]
    uid: Annotated[int, Field(ge=0, le=255)] | None = None
    age_blocks: Annotated[int, Field(ge=0, le=2**53 - 1)] | None = None


class ValidatorAgeObservation(StrictProtocolModel):
    uid: Literal[0, 54]
    hotkey: Annotated[str, Field(min_length=1, max_length=128)]
    finalized_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    last_update_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    age_blocks: Annotated[int, Field(ge=0, le=2**53 - 1)]
    severity: Severity


@dataclass(frozen=True, slots=True)
class PublicRouteCapture:
    status_before: dict[str, Any]
    readiness_before: dict[str, Any]
    submission_pages: tuple[dict[str, Any], ...]
    submission_records: dict[str, dict[str, Any]]
    participant_pages: tuple[dict[str, Any], ...]
    readiness: dict[str, Any]
    status: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ValidatedPublicCapture:
    identity: ExpectedIntakeIdentity
    identity_index: int
    policy: CompetitionPolicy
    deployment: PublicIntakeDeployment
    status: CompetitionStatus
    readiness: CompetitionReadiness
    validator_observations: tuple[ValidatorAgeObservation, ...]
    issues: tuple[MonitorIssue, ...]
    severity: Severity
    observer_finalized_block: int
    next_state: PublicIntakeMonitorState


def _parse(model, value: Any, code: str):
    try:
        return model.model_validate_json(canonical_json_bytes(value))
    except (TypeError, ValidationError, ValueError):
        _fail(code)


def parse_status(value: Any) -> CompetitionStatus:
    return _parse(CompetitionStatus, value, "invalid_competition_status")


def parse_readiness(value: Any) -> CompetitionReadiness:
    return _parse(CompetitionReadiness, value, "invalid_competition_readiness")


def capture_fence(capture: PublicRouteCapture) -> tuple[str, str, str, int]:
    """Return the immutable admission fence or reject a moving capture."""

    before_status = parse_status(capture.status_before)
    after_status = parse_status(capture.status)
    before_readiness = parse_readiness(capture.readiness_before)
    after_readiness = parse_readiness(capture.readiness)
    status_values = (
        before_status.policy_sha256,
        document_sha256(capture.status_before["deployment"]),
        before_status.retained_submission_head.head_sha256,
        before_status.accepted_submission_count,
    )
    if (
        status_values
        != (
            after_status.policy_sha256,
            document_sha256(capture.status["deployment"]),
            after_status.retained_submission_head.head_sha256,
            after_status.accepted_submission_count,
        )
        or status_values
        != (
            before_readiness.policy_sha256,
            document_sha256(capture.readiness_before["deployment"]),
            before_readiness.retained_submission_head.head_sha256,
            before_readiness.retained_submission_head.record_count,
        )
        or status_values
        != (
            after_readiness.policy_sha256,
            document_sha256(capture.readiness["deployment"]),
            after_readiness.retained_submission_head.head_sha256,
            after_readiness.retained_submission_head.record_count,
        )
        or before_status.baseline != after_status.baseline
        or before_status.baseline.promotion_sha256
        != before_readiness.retained_state.baseline_promotion_sha256
        or after_status.baseline.promotion_sha256
        != after_readiness.retained_state.baseline_promotion_sha256
    ):
        _fail("capture_admission_fence_changed")
    return status_values


def _expected_identity(
    config: PublicIntakeMonitorConfig,
    state: PublicIntakeMonitorState | None,
    *,
    policy_sha256: str,
    deployment_sha256: str,
    checked_block: int,
    policy: CompetitionPolicy,
) -> tuple[int, ExpectedIntakeIdentity]:
    matches = [
        (index, item)
        for index, item in enumerate(config.expected_identities)
        if (item.policy_sha256, item.deployment_document_sha256)
        == (policy_sha256, deployment_sha256)
    ]
    if len(matches) != 1:
        _fail("unexpected_policy_or_deployment_identity")
    index, expected = matches[0]
    if checked_block < expected.not_before_checked_block:
        _fail("identity_observed_before_configured_block")
    if state is None:
        return index, expected
    retained_count = len(state.identity_history)
    if tuple(config.expected_identities[:retained_count]) != state.identity_history:
        _fail("configured_identity_history_dropped_or_changed")
    prior_index = retained_count - 1
    prior_identity = state.identity_history[-1]
    if index < prior_index:
        _fail("public_identity_regressed")
    if index > prior_index + 1:
        _fail("public_identity_skipped_configured_rollover")
    if (
        index > prior_index
        and policy_sha256 != prior_identity.policy_sha256
        and policy.predecessor_sha256 != prior_identity.policy_sha256
    ):
        _fail("policy_rollover_predecessor_mismatch")
    return index, expected


def _phase(
    status: CompetitionStatus, deployment: PublicIntakeDeployment, policy: CompetitionPolicy
) -> tuple[str, str, bool]:
    schedule = status.round_schedule
    block = status.admission_checked_block
    if block < schedule.intake_opened_block:
        return "not_open", "first_round_intake_not_open", False
    if not deployment.launch_identity().accepts_at(block) or block > policy.valid_through_block:
        return "closed", "first_round_intake_closed", False
    if deployment.round_stride_blocks is not None:
        return "open", "continuous_intake", True
    return "open", "first_round_intake", True


def _validate_status_readiness(
    capture: PublicRouteCapture,
    status: CompetitionStatus,
    readiness: CompetitionReadiness,
    policy: CompetitionPolicy,
    deployment: PublicIntakeDeployment,
) -> list[MonitorIssue]:
    capture_fence(capture)
    if status.policy_sha256 != digest(policy):
        _fail("status_policy_digest_mismatch")
    if status.policy_sha256 != readiness.policy_sha256:
        _fail("status_readiness_policy_mismatch")
    if canonical_json_bytes(capture.status["deployment"]) != canonical_json_bytes(
        capture.readiness["deployment"]
    ):
        _fail("status_readiness_deployment_mismatch")
    schedule_bytes = canonical_json_bytes(deployment.round_schedule)
    if (
        canonical_json_bytes(status.round_schedule) != schedule_bytes
        or canonical_json_bytes(readiness.round_schedule) != schedule_bytes
    ):
        _fail("public_round_schedule_mismatch")
    if status.retained_submission_head != readiness.retained_submission_head:
        _fail("status_readiness_checkpoint_mismatch")
    head = status.retained_submission_head
    if not head.external_checkpoint_durable:
        _fail("external_submission_checkpoint_not_durable")
    if (
        head.policy_sha256 != status.policy_sha256
        or status.accepted_submission_count != head.record_count
    ):
        _fail("submission_checkpoint_count_or_policy_mismatch")
    if readiness.retained_state.baseline_promotion_sha256 != status.baseline.promotion_sha256:
        _fail("retained_baseline_mismatch")
    if (
        readiness.admission_checked_block != status.admission_checked_block
        or readiness.registration_source.block != readiness.admission_checked_block
    ):
        _fail("admission_checked_block_mismatch")
    if (
        status.assignment_delivery_ready != deployment.assignment_delivery_ready
        or readiness.assignment_delivery_ready != deployment.assignment_delivery_ready
        or status.model_intake_ready != deployment.model_intake_ready
        or readiness.model_intake_ready != deployment.model_intake_ready
        or status.evaluation_ready != deployment.evaluation_ready
        or readiness.evaluation_ready != deployment.evaluation_ready
    ):
        _fail("deployment_readiness_flag_mismatch")
    expected_phase, expected_ready_for, expected_accepting = _phase(status, deployment, policy)
    continuous = deployment.round_stride_blocks is not None
    expected_next = (
        deployment.launch_identity().next_intake_schedule(status.admission_checked_block)
        if continuous and status.admission_accepting_new
        else None
    )
    if any(
        value.continuous_intake != (True if continuous else None)
        or value.next_intake_schedule != expected_next
        for value in (status, readiness)
    ):
        _fail("continuous_intake_schedule_mismatch")
    issues: list[MonitorIssue] = []
    if status.baseline.held_for_conflict:
        issues.append(
            MonitorIssue(
                schema="umi-public-intake-monitor-issue/1",
                severity="critical",
                code="baseline_held_for_conflict",
            )
        )
    if status.admission_phase == "capacity_exhausted" or readiness.admission_phase == (
        "capacity_exhausted"
    ):
        if (
            status.admission_phase != "capacity_exhausted"
            or readiness.admission_phase != "capacity_exhausted"
            or status.admission_accepting_new
            or readiness.admission_accepting_new
            or status.admission_capacity_available
            or expected_phase != "open"
            or not expected_accepting
            or readiness.ready_for != expected_ready_for
        ):
            _fail("admission_phase_or_capacity_mismatch")
        issues.append(
            MonitorIssue(
                schema="umi-public-intake-monitor-issue/1",
                severity="critical",
                code="admission_capacity_exhausted",
            )
        )
    elif (
        status.admission_phase != expected_phase
        or readiness.admission_phase != expected_phase
        or readiness.ready_for != expected_ready_for
        or status.admission_accepting_new != expected_accepting
        or readiness.admission_accepting_new != expected_accepting
        or status.admission_capacity_available is not True
    ):
        _fail("admission_phase_or_capacity_mismatch")
    return issues


def _submission_summaries(
    capture: PublicRouteCapture, expected_count: int
) -> tuple[AdmissionSummary, ...]:
    expected_page_count = max(1, (expected_count + 99) // 100)
    if len(capture.submission_pages) != expected_page_count:
        _fail("submission_page_count_does_not_match_checkpoint")
    summaries: list[AdmissionSummary] = []
    offset = 0
    for raw in capture.submission_pages:
        page = _parse(AdmissionPage, raw, "invalid_submission_page")
        if page.offset != offset:
            _fail("submission_page_offset_regressed_or_skipped")
        expected_items = min(page.limit, expected_count - offset)
        if len(page.items) != expected_items:
            _fail("submission_page_length_mismatch")
        summaries.extend(page.items)
        offset += len(page.items)
    if len(summaries) != expected_count:
        _fail("submission_page_count_mismatch")
    keys = [item.submission_sha256 for item in summaries]
    if len(set(keys)) != len(keys):
        _fail("duplicate_submission_digest")
    ordering = [(item.accepted_block, item.submission_sha256) for item in summaries]
    if ordering != sorted(ordering):
        _fail("submission_log_order_regressed")
    sequences: dict[tuple[str, str], tuple[int, int]] = {}
    for item in summaries:
        key = (item.hotkey_account_id32, item.track)
        prior = sequences.get(key)
        if prior is not None and (item.sequence <= prior[0] or item.accepted_block < prior[1]):
            _fail("submission_sequence_regressed_or_duplicated")
        sequences[key] = (item.sequence, item.accepted_block)
    return tuple(summaries)


def _validated_record(
    raw: dict[str, Any],
    summary: AdmissionSummary,
    policies: dict[str, CompetitionPolicy],
) -> tuple[str, str, dict[str, Any], CompetitionPolicy]:
    if not isinstance(raw, dict) or set(raw) != {"signed_submission", "receipt"}:
        _fail("invalid_submission_record_envelope")
    signed = _parse(SignedSubmission, raw["signed_submission"], "invalid_signed_submission")
    receipt = _parse(AdmissionReceipt, raw["receipt"], "invalid_submission_receipt_envelope")
    snapshot = receipt.registration_snapshot
    submission = signed.submission
    submission_id = digest(submission)
    policy = policies.get(submission.policy_sha256)
    if policy is None:
        _fail("submission_policy_not_retained_or_current")
    try:
        observed_uid = validate_admission(signed, policy, snapshot, summary.accepted_block)
    except (TypeError, ValidationError, ValueError):
        _fail("submission_admission_replay_failed")
    if (
        submission_id != summary.submission_sha256
        or identity(submission.hotkey) != summary.hotkey_account_id32
        or submission.track != summary.track
        or submission.sequence != summary.sequence
        or submission.valid_through_block != summary.valid_through_block
        or receipt.policy_sha256 != submission.policy_sha256
        or receipt.submission_sha256 != submission_id
        or receipt.accepted_block != summary.accepted_block
        or receipt.registration_snapshot_sha256 != digest(snapshot)
        or receipt.observed_uid != observed_uid
    ):
        _fail("submission_record_or_summary_mismatch")
    body = canonical_json_bytes(signed)
    receipt_body = canonical_json_bytes(receipt)
    commitment = {
        "schema": "umi-competition-admission-record-commitment/1",
        "submission_sha256": submission_id,
        "hotkey": identity(submission.hotkey),
        "track": submission.track,
        "sequence": submission.sequence,
        "accepted_block": summary.accepted_block,
        "expires_block": submission.valid_through_block,
        "body_sha256": _sha256(body),
        "receipt_sha256": _sha256(receipt_body),
        # Filled by the caller because writer generation belongs to the reviewed
        # deployment identity, not to the public record itself.
        "writer_generation": 0,
    }
    return document_sha256(raw), submission.policy_sha256, commitment, policy


def _validate_records_and_checkpoint(
    capture: PublicRouteCapture,
    summaries: tuple[AdmissionSummary, ...],
    current_policy: CompetitionPolicy,
    policies: dict[str, CompetitionPolicy],
    deployment: PublicIntakeDeployment,
    expected: ExpectedIntakeIdentity,
    head: RetainedSubmissionHead,
    admission_checked_block: int,
    required_submission_ids: set[str],
    previous_state: PublicIntakeMonitorState | None,
    identity_history: tuple[ExpectedIntakeIdentity, ...],
    configured_identities: tuple[ExpectedIntakeIdentity, ...],
    deployments: dict[str, PublicIntakeDeployment],
) -> tuple[SubmissionRecordState, ...]:
    summary_ids = {item.submission_sha256 for item in summaries}
    if set(capture.submission_records) != summary_ids:
        _fail("full_submission_record_set_mismatch")
    state_rows: list[SubmissionRecordState] = []
    admission_record_ids: dict[str, str] = {}
    prior_by_identity: dict[tuple[str, str], tuple[int, int]] = {}
    prior_state_records = {
        item.submission_sha256: item
        for item in (previous_state.submissions if previous_state else ())
    }
    for summary in summaries:
        record_hash, record_policy_sha256, commitment, record_policy = _validated_record(
            capture.submission_records[summary.submission_sha256],
            summary,
            policies,
        )
        replacement_key = (summary.hotkey_account_id32, summary.track)
        prior = prior_by_identity.get(replacement_key)
        if prior is not None and (
            summary.sequence <= prior[0]
            or summary.accepted_block - prior[1] < record_policy.minimum_submission_interval_blocks
        ):
            _fail("submission_replacement_interval_or_sequence_invalid")
        prior_by_identity[replacement_key] = (summary.sequence, summary.accepted_block)
        if summary.accepted_block > admission_checked_block:
            _fail("submission_accepted_after_public_checked_block")
        prior_state_record = prior_state_records.get(summary.submission_sha256)
        if prior_state_record is not None:
            admission_identity_name = prior_state_record.admission_identity_name
            writer_generation = prior_state_record.admission_writer_generation
        elif summary.submission_sha256 in required_submission_ids:
            # Required retained anchors can predate the first public deployment.
            admission_identity_name = None
            writer_generation = expected.admission_writer_generation
        else:
            matching_identities: list[ExpectedIntakeIdentity] = []
            for index, candidate in enumerate(identity_history):
                candidate_deployment = deployments[candidate.name]
                schedule = candidate_deployment.round_schedule
                next_acceptance_block = (
                    configured_identities[index + 1].acceptance_not_before_block
                    if index + 1 < len(configured_identities)
                    else None
                )
                if (
                    candidate.policy_sha256 == record_policy_sha256
                    and summary.track in candidate_deployment.eligible_tracks
                    and candidate.acceptance_not_before_block <= summary.accepted_block
                    and (
                        next_acceptance_block is None
                        or summary.accepted_block < next_acceptance_block
                    )
                    and schedule.intake_opened_block
                    <= summary.accepted_block
                    <= schedule.roster_close_latest_block
                ):
                    matching_identities.append(candidate)
            if not matching_identities:
                _fail("new_submission_outside_active_deployment_rules")
            attributed_identity = matching_identities[-1]
            admission_identity_name = attributed_identity.name
            writer_generation = attributed_identity.admission_writer_generation
        commitment["writer_generation"] = writer_generation
        admission_record_ids[summary.submission_sha256] = document_sha256(commitment)
        state_rows.append(
            SubmissionRecordState(
                submission_sha256=summary.submission_sha256,
                policy_sha256=record_policy_sha256,
                hotkey_account_id32=summary.hotkey_account_id32,
                track=summary.track,
                sequence=summary.sequence,
                accepted_block=summary.accepted_block,
                admission_identity_name=admission_identity_name,
                admission_writer_generation=writer_generation,
                record_sha256=record_hash,
            )
        )
    ordered_ids = tuple(sorted(summary_ids))
    checkpoint = build_submission_checkpoint(
        policy_sha256=digest(current_policy),
        public_launch_sha256=digest(deployment.launch_identity()),
        submission_sha256s=ordered_ids,
        admission_record_sha256s=tuple(admission_record_ids[item] for item in ordered_ids),
    )
    exact = {
        "schema": "umi-competition-submission-head/1",
        "policy_sha256": checkpoint.policy_sha256,
        "record_count": checkpoint.record_count,
        "submission_set_sha256": checkpoint.submission_set_sha256,
        "head_sha256": checkpoint.head_sha256,
        "public_launch_sha256": checkpoint.public_launch_sha256,
        "external_checkpoint_sha256": document_sha256(checkpoint),
        "external_checkpoint_durable": True,
    }
    if canonical_json_bytes(head) != canonical_json_bytes(exact):
        _fail("public_submission_checkpoint_reconstruction_failed")
    return tuple(sorted(state_rows, key=lambda item: item.submission_sha256))


def _age_severity(age: int, thresholds: ValidatorAgeThresholds) -> Severity:
    if age >= thresholds.stale_blocks:
        return "stale"
    if age >= thresholds.critical_blocks:
        return "critical"
    if age >= thresholds.investigate_blocks:
        return "investigate"
    if age >= thresholds.warning_blocks:
        return "warning"
    return "ok"


def _validate_participants(
    capture: PublicRouteCapture,
    config: PublicIntakeMonitorConfig,
    admission_checked_block: int,
) -> tuple[tuple[ValidatorAgeObservation, ...], list[MonitorIssue], int]:
    if not capture.participant_pages:
        _fail("participant_pages_missing")
    pages = [
        _parse(ParticipantsResponse, raw, "invalid_participant_page")
        for raw in capture.participant_pages
    ]
    first = pages[0]
    chain_sources = [
        source
        for source in first.sources
        if source.source_kind == "chain_finalized" and source.block is not None
    ]
    if len(chain_sources) != 1:
        _fail("participant_finalized_source_missing")
    finalized_block = int(chain_sources[0].block.number)
    participants = []
    total = first.page.total
    for index, page in enumerate(pages):
        page_sources = [
            source
            for source in page.sources
            if source.source_kind == "chain_finalized" and source.block is not None
        ]
        if (
            page.page.role != "all"
            or page.page.limit != config.participant_page_size
            or page.page.total != total
            or len(page_sources) != 1
            or page.sources != first.sources
            or page.protocol_state != first.protocol_state
            or page.generated_at != first.generated_at
            or page.freshness != first.freshness
            or page.snapshot_age_seconds != first.snapshot_age_seconds
            or page.finalized_head_age_seconds != first.finalized_head_age_seconds
            or (index + 1 < len(pages) and page.page.next_cursor is None)
            or (index + 1 == len(pages) and page.page.next_cursor is not None)
        ):
            _fail("participant_page_snapshot_mismatch")
        participants.extend(page.participants)
    if len(participants) != total:
        _fail("participant_page_count_mismatch")
    uids = [item.uid for item in participants]
    hotkeys = [item.hotkey for item in participants]
    participant_order = [(item.uid, item.hotkey) for item in participants]
    if (
        len(set(uids)) != len(uids)
        or len(set(hotkeys)) != len(hotkeys)
        or participant_order != sorted(participant_order)
    ):
        _fail("duplicate_participant_identity")
    if (
        first.protocol_state.netuid != 78
        or first.protocol_state.mechanism_id != 0
        or not first.protocol_state.chain_identity_matches_expected
        or first.protocol_state.validator_input_eligible
    ):
        _fail("observer_protocol_identity_mismatch")
    issues: list[MonitorIssue] = []
    if (
        first.freshness != "fresh"
        or first.snapshot_age_seconds > config.maximum_observer_age_seconds
        or first.finalized_head_age_seconds > config.maximum_observer_age_seconds
    ):
        issues.append(
            MonitorIssue(
                schema="umi-public-intake-monitor-issue/1",
                severity="stale",
                code="observer_snapshot_stale",
            )
        )
    if admission_checked_block - finalized_block > config.maximum_observer_block_lag:
        issues.append(
            MonitorIssue(
                schema="umi-public-intake-monitor-issue/1",
                severity="critical",
                code="observer_block_lags_intake",
            )
        )
    by_uid = {item.uid: item for item in participants}
    observations: list[ValidatorAgeObservation] = []
    for uid in sorted(config.watched_validator_uids):
        participant = by_uid.get(uid)
        if (
            participant is None
            or not participant.validator_permit
            or participant.role != "validator"
        ):
            _fail(f"watched_validator_uid_{uid}_missing_or_not_permitted")
        last_update = int(participant.last_update_block)
        age = int(participant.last_update_age_blocks)
        if last_update > finalized_block or finalized_block - last_update != age:
            _fail(f"watched_validator_uid_{uid}_age_mismatch")
        severity = _age_severity(age, config.validator_age_thresholds)
        observations.append(
            ValidatorAgeObservation(
                uid=uid,
                hotkey=participant.hotkey,
                finalized_block=finalized_block,
                last_update_block=last_update,
                age_blocks=age,
                severity=severity,
            )
        )
        if severity != "ok":
            issues.append(
                MonitorIssue(
                    schema="umi-public-intake-monitor-issue/1",
                    severity=severity,
                    code="validator_last_update_age",
                    uid=uid,
                    age_blocks=age,
                )
            )
    return tuple(observations), issues, finalized_block


def _next_state(
    *,
    state: PublicIntakeMonitorState | None,
    now_unix_ms: int,
    identity_: ExpectedIntakeIdentity,
    status: CompetitionStatus,
    records: tuple[SubmissionRecordState, ...],
    policies: tuple[RetainedCompetitionPolicy, ...],
    deployments: tuple[RetainedIntakeDeployment, ...],
    identity_index: int,
    config: PublicIntakeMonitorConfig,
) -> tuple[PublicIntakeMonitorState, list[MonitorIssue]]:
    if now_unix_ms < 0:
        _fail("monitor_clock_invalid")
    issues: list[MonitorIssue] = []
    if state is None:
        advanced_at = now_unix_ms
    else:
        if now_unix_ms <= state.last_success_at_unix_ms:
            _fail("monitor_clock_did_not_advance")
        if status.accepted_submission_count < state.accepted_submission_count:
            _fail("accepted_submission_count_regressed")
        if status.admission_checked_block < state.admission_checked_block:
            _fail("admission_checked_block_regressed")
        prior_records = {item.submission_sha256: item.record_sha256 for item in state.submissions}
        current_records = {item.submission_sha256: item.record_sha256 for item in records}
        if any(current_records.get(key) != value for key, value in prior_records.items()):
            _fail("submission_record_removed_or_changed")
        prior_ids = set(prior_records)
        if any(
            item.accepted_block < state.admission_checked_block
            for item in records
            if item.submission_sha256 not in prior_ids
        ):
            _fail("new_submission_backfilled_before_prior_checked_block")
        advanced_at = (
            now_unix_ms
            if status.admission_checked_block > state.admission_checked_block
            else state.last_checked_block_advanced_at_unix_ms
        )
        if now_unix_ms - advanced_at > config.maximum_checked_block_stall_seconds * 1000:
            issues.append(
                MonitorIssue(
                    schema="umi-public-intake-monitor-issue/1",
                    severity="critical",
                    code="admission_checked_block_stalled",
                )
            )
    return (
        PublicIntakeMonitorState(
            schema="umi-public-intake-monitor-state/1",
            active_identity_name=identity_.name,
            policy_sha256=status.policy_sha256,
            deployment_document_sha256=identity_.deployment_document_sha256,
            accepted_submission_count=status.accepted_submission_count,
            admission_checked_block=status.admission_checked_block,
            retained_head_sha256=status.retained_submission_head.head_sha256,
            last_checked_block_advanced_at_unix_ms=advanced_at,
            last_success_at_unix_ms=now_unix_ms,
            identity_history=tuple(config.expected_identities[: identity_index + 1]),
            policies=policies,
            deployments=deployments,
            submissions=records,
        ),
        issues,
    )


def validate_public_capture(
    capture: PublicRouteCapture,
    config: PublicIntakeMonitorConfig,
    *,
    previous_state: PublicIntakeMonitorState | None,
    now_unix_ms: int,
) -> ValidatedPublicCapture:
    """Validate one stable public capture and derive the next monotonic state."""

    status = parse_status(capture.status)
    readiness = parse_readiness(capture.readiness)
    try:
        policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(status.policy))
        deployment = PublicIntakeDeployment.model_validate_json(
            canonical_json_bytes(capture.status["deployment"])
        )
    except (TypeError, ValidationError, ValueError):
        _fail("invalid_public_policy_or_deployment")
    deployment_sha = document_sha256(capture.status["deployment"])
    identity_index, expected = _expected_identity(
        config,
        previous_state,
        policy_sha256=status.policy_sha256,
        deployment_sha256=deployment_sha,
        checked_block=status.admission_checked_block,
        policy=policy,
    )
    if status.baseline.promotion_sha256 != expected.expected_baseline_promotion_sha256:
        _fail("retained_baseline_differs_from_expected_identity")
    if status.accepted_submission_count < expected.minimum_accepted_submission_count:
        _fail("accepted_submission_count_below_configured_floor")
    if status.accepted_submission_count > config.maximum_accepted_submission_count:
        _fail("accepted_submission_count_exceeds_monitor_bound")
    if previous_state is None and (
        expected.name != config.reviewed_bootstrap.identity_name
        or status.accepted_submission_count != config.reviewed_bootstrap.accepted_submission_count
        or status.retained_submission_head.head_sha256
        != config.reviewed_bootstrap.retained_head_sha256
    ):
        _fail("public_head_differs_from_reviewed_bootstrap")
    configured_policy_digests = {item.policy_sha256 for item in config.expected_identities}
    retained_policies = {
        item.policy_sha256: item.policy
        for item in (previous_state.policies if previous_state else ())
    }
    if not set(retained_policies).issubset(configured_policy_digests):
        _fail("configured_policy_history_dropped")
    retained_policies[status.policy_sha256] = status.policy
    parsed_policies = {
        policy_sha256: _parse(CompetitionPolicy, body, "invalid_retained_competition_policy")
        for policy_sha256, body in retained_policies.items()
    }
    if any(digest(body) != policy_sha256 for policy_sha256, body in parsed_policies.items()):
        _fail("retained_competition_policy_digest_mismatch")
    policy_state = tuple(
        RetainedCompetitionPolicy(
            policy_sha256=policy_sha256, policy=retained_policies[policy_sha256]
        )
        for policy_sha256 in sorted(retained_policies)
    )
    identity_history = tuple(config.expected_identities[: identity_index + 1])
    retained_deployments = {
        item.identity_name: item.deployment
        for item in (previous_state.deployments if previous_state else ())
    }
    retained_deployments[expected.name] = capture.status["deployment"]
    if set(retained_deployments) != {item.name for item in identity_history}:
        _fail("retained_deployment_history_incomplete_or_unexpected")
    parsed_deployments = {
        name: _parse(
            PublicIntakeDeployment,
            body,
            "invalid_retained_intake_deployment",
        )
        for name, body in retained_deployments.items()
    }
    deployment_state = tuple(
        RetainedIntakeDeployment(
            identity_name=identity_.name,
            deployment_document_sha256=identity_.deployment_document_sha256,
            deployment=retained_deployments[identity_.name],
        )
        for identity_ in identity_history
    )
    issues = _validate_status_readiness(capture, status, readiness, policy, deployment)
    summaries = _submission_summaries(capture, status.accepted_submission_count)
    required = set(readiness.retained_state.required_submission_sha256s)
    if (
        len(required) != expected.required_submission_count
        or document_sha256(list(sorted(required))) != expected.required_submission_set_sha256
    ):
        _fail("required_retained_submission_set_differs_from_expected_identity")
    if not required.issubset(item.submission_sha256 for item in summaries):
        _fail("required_retained_submission_missing")
    records = _validate_records_and_checkpoint(
        capture,
        summaries,
        policy,
        parsed_policies,
        deployment,
        expected,
        status.retained_submission_head,
        status.admission_checked_block,
        required,
        previous_state,
        identity_history,
        config.expected_identities,
        parsed_deployments,
    )
    observations, participant_issues, observer_block = _validate_participants(
        capture, config, status.admission_checked_block
    )
    issues.extend(participant_issues)
    next_state, state_issues = _next_state(
        state=previous_state,
        now_unix_ms=now_unix_ms,
        identity_=expected,
        status=status,
        records=records,
        policies=policy_state,
        deployments=deployment_state,
        identity_index=identity_index,
        config=config,
    )
    issues.extend(state_issues)
    issues = sorted(
        issues,
        key=lambda item: (_SEVERITY_ORDER[item.severity], item.code, item.uid or -1),
    )
    severity: Severity = max(
        (item.severity for item in issues),
        default="ok",
        key=lambda item: _SEVERITY_ORDER[item],
    )
    return ValidatedPublicCapture(
        identity=expected,
        identity_index=identity_index,
        policy=policy,
        deployment=deployment,
        status=status,
        readiness=readiness,
        validator_observations=observations,
        issues=tuple(issues),
        severity=severity,
        observer_finalized_block=observer_block,
        next_state=next_state,
    )


def severity_exit_code(severity: Severity) -> int:
    if severity == "ok":
        return 0
    if severity in {"warning", "investigate"}:
        return 1
    return 2


__all__ = (
    "AdmissionPage",
    "CompetitionReadiness",
    "CompetitionStatus",
    "ExpectedIntakeIdentity",
    "MonitorIssue",
    "PublicIntakeMonitorConfig",
    "PublicIntakeMonitorError",
    "PublicIntakeMonitorState",
    "PublicRouteCapture",
    "RetainedCompetitionPolicy",
    "ReviewedBootstrapCheckpoint",
    "ValidatedPublicCapture",
    "ValidatorAgeObservation",
    "capture_fence",
    "document_sha256",
    "parse_readiness",
    "parse_status",
    "severity_exit_code",
    "validate_public_capture",
)
