"""Replay locally retained consent and registration observations.

These bytes come from the private intake ledger. A decoded observation is not
an independently verified finality proof or an admission certificate.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_participation import (
    CohortParticipantAdmission,
    CohortParticipationRequest,
    admit_recovery_participant,
)
from .competition_execution import ExecutionBoundary
from .open_competition import CompetitionPolicy, RegistrationSnapshot, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class RetainedCohortParticipation(StrictProtocolModel):
    schema_: Literal["umi-retained-cohort-participation/1"] = Field(alias="schema")
    request: CohortParticipationRequest
    proposed_admission: CohortParticipantAdmission
    snapshot: RegistrationSnapshot
    observation: ExecutionBoundary


def read_participation(raw: bytes) -> RetainedCohortParticipation:
    if type(raw) is not bytes or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise ValueError("retained cohort participation exceeds its byte bound")
    retained = RetainedCohortParticipation.model_validate_json(raw)
    if canonical_json_bytes(retained) != raw:
        raise ValueError("retained cohort consent is not canonical")
    return retained


def replay_participation(
    retained: RetainedCohortParticipation,
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
) -> CohortParticipantAdmission:
    proposed = retained.proposed_admission
    tips = [digest(history.genesis), *(digest(s.transition) for s in history.transitions)]
    if proposed.recovery_tip_sha256 not in tips:
        raise ValueError("retained cohort consent is not in the published history")
    index = tips.index(proposed.recovery_tip_sha256)
    if (
        index < len(history.transitions)
        and proposed.admitted_at_block > history.transitions[index].transition.observed_at_block
    ):
        raise ValueError("retained cohort consent used a superseded intake observation")
    original = history.model_copy(update={"transitions": history.transitions[:index]})
    expected = admit_recovery_participant(
        retained.request.signed_submission,
        retained.request.consent,
        original,
        policy,
        retained.snapshot,
        expected_tip_sha256=proposed.recovery_tip_sha256,
        current_block=proposed.admitted_at_block,
    )
    if (
        expected != proposed
        or retained.observation.block != proposed.admitted_at_block
        or retained.observation.snapshot_sha256 != digest(retained.snapshot)
        or retained.observation.block != retained.snapshot.block
        or retained.observation.block_hash != retained.snapshot.block_hash
    ):
        raise ValueError("retained cohort consent registration evidence differs")
    return proposed
