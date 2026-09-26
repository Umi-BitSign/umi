"""Native phase-progress binding for a complete retained request manifest."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field

from .competition_cohort_availability import (
    CohortAvailabilityObservation,
    pending_availability_progress,
)
from .competition_cohort_coordinator import CohortPhaseProgress
from .competition_cohort_endpoint_archive import JournalEndpointObjects
from .competition_cohort_recovery import CohortRecoveryState
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_cohort_request_closure import CohortRequestClosure


class RequestClosureProgressEvidence(StrictProtocolModel):
    schema_: Literal["umi-request-closure-progress-evidence/1"] = Field(alias="schema")
    closure_sha256: Hex32
    service: CohortAvailabilityObservation


def request_closure_progress(
    closure: CohortRequestClosure,
    service: CohortAvailabilityObservation,
    state: CohortRecoveryState,
) -> tuple[CohortPhaseProgress, RequestClosureProgressEvidence]:
    """The owning service must replay service history and full closure first.

    This binds both retained sources to the vote. Independent signers still
    need their native service/proof review; a peer's service JSON is not proof.
    """
    service = CohortAvailabilityObservation.model_validate_json(canonical_json_bytes(service))
    pending = pending_availability_progress(state, service)
    if (
        state.phase != "requests"
        or not service.serving
        or service.observation != closure.observation
        or closure.recovery_tip_sha256 != state.tip_sha256
    ):
        raise ValueError("request completion differs from its retained service observation")
    evidence = RequestClosureProgressEvidence(
        schema="umi-request-closure-progress-evidence/1",
        closure_sha256=digest(closure),
        service=service,
    )
    return pending.model_copy(
        update={
            "completion": "complete",
            "phase_result_sha256": digest(closure),
            "evidence_sha256": digest(evidence),
        }
    ), evidence


def retain_request_closure_progress(
    closure: CohortRequestClosure,
    service: CohortAvailabilityObservation,
    state: CohortRecoveryState,
    objects: JournalEndpointObjects,
) -> CohortPhaseProgress:
    """Persist complete immutable inputs before returning a body for attestation.

    Capacity or acknowledgement failures retry the same records. The caller
    performs full closure and service review before invoking this owner port.
    """
    progress, evidence = request_closure_progress(closure, service, state)
    objects.put(closure)
    objects.put(evidence)
    return progress
