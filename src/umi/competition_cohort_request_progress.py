"""Native phase-progress binding for a complete retained request manifest."""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_availability import (
    CohortAvailabilityObservation,
    pending_availability_progress,
)
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    replay_cohort_decisions,
)
from .competition_cohort_endpoint_archive import JournalEndpointObjects, read_endpoint_object
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_recovery import CohortRecoveryState
from .competition_cohort_request_tail import RequestTailObservation
from .competition_execution import ExecutionBoundary
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RequestCompletion(Protocol):
    observation: ExecutionBoundary
    recovery_tip_sha256: str


class RequestClosureProgressEvidence(StrictProtocolModel):
    schema_: Literal[
        "umi-request-closure-progress-evidence/1", "umi-request-closure-progress-evidence/2"
    ] = Field(alias="schema")
    closure_sha256: Hex32
    service: CohortAvailabilityObservation
    request_tail_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.request_tail_sha256 is None:
            value.pop("request_tail_sha256", None)
        return value

    @model_validator(mode="after")
    def tail_binding(self):
        if (self.schema_ == "umi-request-closure-progress-evidence/2") != (
            self.request_tail_sha256 is not None
        ):
            raise ValueError("request closure progress version differs from its tail binding")
        return self


def request_closure_progress(
    closure: RequestCompletion,
    service: CohortAvailabilityObservation,
    state: CohortRecoveryState,
    *,
    tail: RequestTailObservation | None = None,
) -> tuple[CohortPhaseProgress, RequestClosureProgressEvidence]:
    """The owning service must replay service history and full closure first.

    This binds both retained sources to the vote. Independent signers still
    need their native service/proof review; a peer's service JSON is not proof.
    """
    service = CohortAvailabilityObservation.model_validate_json(canonical_json_bytes(service))
    pending = pending_availability_progress(state, service)
    if (
        state.phase != "requests"
        or (not service.serving and tail is None)
        or service.observation != closure.observation
        or closure.recovery_tip_sha256 != state.tip_sha256
    ):
        raise ValueError("request completion differs from its retained service observation")
    if tail is not None:
        tail = RequestTailObservation.model_validate_json(canonical_json_bytes(tail))
        if tail.observation != closure.observation:
            raise ValueError("request completion differs from its original tail observation")
    tail_sha = None if tail is None else digest(tail)
    evidence = RequestClosureProgressEvidence(
        schema="umi-request-closure-progress-evidence/1"
        if tail is None
        else "umi-request-closure-progress-evidence/2",
        closure_sha256=digest(closure),
        service=service,
        request_tail_sha256=tail_sha,
    )
    return pending.model_copy(
        update={
            "schema_": "umi-cohort-phase-progress/1"
            if tail is None
            else "umi-cohort-phase-progress/2",
            "request_tail_sha256": tail_sha,
            "completion": "complete",
            "phase_result_sha256": digest(closure),
            "evidence_sha256": digest(evidence),
        }
    ), evidence


def retain_request_closure_progress(
    closure: RequestCompletion,
    service: CohortAvailabilityObservation,
    state: CohortRecoveryState,
    objects: JournalEndpointObjects,
    *,
    tail: RequestTailObservation | None = None,
) -> CohortPhaseProgress:
    """Persist complete immutable inputs before returning a body for attestation.

    Capacity or acknowledgement failures retry the same records. The caller
    performs full closure and service review before invoking this owner port.
    """
    progress, evidence = request_closure_progress(closure, service, state, tail=tail)
    objects.put(closure)
    objects.put(evidence)
    return progress


def certified_request_prefix(
    closure,
    objects,
    policy,
    history,
    *,
    decision_source,
    expected_tip_sha256,
    current_block,
    tail: RequestTailObservation | None = None,
):
    """Bind either closure version to native phase and availability evidence.

    Callers must then replay that version's complete manifest using this prefix.
    This shared check never interprets a result digest as sufficient completion.
    """
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if view.state.phase == "revoked":
        raise ValueError("request closure authority is revoked")
    closed = view.closure("requests")
    decision = CohortDecisionInput.model_validate_json(
        canonical_json_bytes(decision_source(closed.evidence_sha256))
    )
    progress = decision.progress.progress
    tail_sha = None if tail is None else digest(tail)
    if (
        digest(decision) != closed.evidence_sha256
        or progress.completion != "complete"
        or progress.phase_result_sha256 != digest(closure)
        or progress.observed_at_block != closure.observation.block
        or closure.recovery_tip_sha256 != closed.predecessor_sha256
        or progress.request_tail_sha256 != tail_sha
        or closed.request_tail_sha256 != tail_sha
    ):
        raise ValueError("certified requests do not bind this exact closure manifest")
    # Replay the full native decisions, including request-window compensation.
    replay_cohort_decisions(history, policy, decision_source)
    index = next(i for i, s in enumerate(history.transitions) if s.transition == closed)
    prefix = history.model_copy(update={"transitions": history.transitions[:index]})
    service_evidence = RequestClosureProgressEvidence.model_validate_json(
        read_endpoint_object(objects, progress.evidence_sha256)
    )
    if (
        service_evidence.closure_sha256 != digest(closure)
        or service_evidence.request_tail_sha256 != tail_sha
    ):
        raise ValueError("request progress substituted its completion manifest")
    state = verify_cohort_history(
        prefix,
        policy,
        expected_tip_sha256=history_tip(prefix),
        current_block=closure.observation.block,
    ).state
    expected, _ = request_closure_progress(closure, service_evidence.service, state, tail=tail)
    if expected != progress:
        raise ValueError("certified request progress changed its retained service evidence")
    return prefix
