"""Recheck retained cohort consent with owned historical registration proofs.

This supplies verified inputs to an independent admission signer. It does not
sign, infer a quorum from a local receipt, or authorize rewards.
"""

from __future__ import annotations

from dataclasses import dataclass

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_participation import CohortParticipantAdmission
from .competition_historical_registration import (
    HistoricalRegistration,
    HistoricalRegistrationProvider,
)
from .open_competition import CompetitionPolicy
from .protocol import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class ReviewedCohortParticipation:
    admission: CohortParticipantAdmission
    registration: HistoricalRegistration


async def review_cohort_participation(
    raw: bytes,
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    provider: HistoricalRegistrationProvider,
    *,
    expected_tip_sha256: str,
    registration_archive: tuple[bytes, bytes] | None = None,
) -> ReviewedCohortParticipation:
    """Use a monotonic published tip supplied by the service owner, never the miner.

    A peer may supply the original archive and metadata bytes. They gain no
    authority from their source: this provider replays them against its own
    historical header. The signing service must durably retain that evidence
    before issuing an attestation.
    """
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if provider.policy != policy:
        raise ValueError("historical reviewer belongs to another cohort policy")
    retained = read_participation(raw)
    if registration_archive is None:
        registration = await provider.review_retained(retained.observation)
    else:
        registration = await provider.review_archive(retained.observation, *registration_archive)
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=registration.replayed_at.block_number,
    )
    if view.state.phase == "revoked":
        raise ValueError("cohort recovery has been revoked")
    admission = replay_participation(retained, history, policy)
    if registration.snapshot != retained.snapshot:
        raise ValueError("cohort admission snapshot differs from verified historical membership")
    return ReviewedCohortParticipation(admission, registration)
