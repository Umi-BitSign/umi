"""Replay locally retained consent and registration observations.

These bytes come from the private intake ledger. A decoded observation is not
an independently verified finality proof or an admission certificate.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import Field

from .canonical_reuse import canonical_json_reuse
from .competition_assignment_reuse import AssignmentVerificationReuse
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


_participation_decode_reuse = AssignmentVerificationReuse(64 * 1024**2, 1024)


def read_participation(raw: bytes) -> RetainedCohortParticipation:
    if type(raw) is not bytes or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise ValueError("retained cohort participation exceeds its byte bound")
    # Only canonical decoding is reusable here. Callers still read the ledger
    # and check its current indexes, authority and registration separately.
    key = hashlib.sha256(raw).digest()
    cached = _participation_decode_reuse.lookup(key, key)
    if cached is not None:
        return cached
    retained = RetainedCohortParticipation.model_validate_json(raw)
    if canonical_json_bytes(retained) != raw:
        raise ValueError("retained cohort consent is not canonical")
    _participation_decode_reuse.remember(key, key, retained)
    return retained


_historical_participation_reuse = AssignmentVerificationReuse(8 * 1024**2, 4096)


@canonical_json_reuse()
def replay_participation(
    retained: RetainedCohortParticipation,
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
) -> CohortParticipantAdmission:
    # This is historical replay over exact supplied inputs, never current
    # registration, availability, finality or authority. Read changed bytes
    # normally; only successful native results enter bounded private reuse.
    key = (digest(retained), digest(history), digest(policy))
    cached = _historical_participation_reuse.lookup(key, key)
    if cached is not None:
        return cached
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
    _historical_participation_reuse.remember(key, key, proposed)
    return proposed
