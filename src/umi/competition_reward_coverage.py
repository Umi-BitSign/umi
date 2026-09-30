"""Join native historical selection, package replay, eligibility and stored rows.

A verified endpoint is evidence at one finalized block. It neither credits time
nor proves an emission payment. Interval accounting must also prove adjacency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .competition_cohort_reward_allocation import CohortRewardProjection, project_reward_allocation
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_decisions import DecisionSource
from .competition_reward_eligibility_archive import (
    OwnedHistoricalRewardEligibility,
    validate_historical_reward_eligibility,
)
from .competition_reward_history import OwnedRewardControlHistory
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .open_competition import RegistrationSnapshot, digest, identity
from .weight_storage import subtensor_stored_weights

_ISSUER = object()


@dataclass(frozen=True, slots=True)
class OwnedRewardCoverageEndpoint:
    prepared: PreparedStandingReward
    eligibility: OwnedHistoricalRewardEligibility
    projection: CohortRewardProjection
    row_matches: bool
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def covered(self) -> bool:
        return self.row_matches and self.eligibility.eligible


def _binding(value: OwnedRewardCoverageEndpoint) -> str:
    return digest(
        {
            "prepared": value.prepared._binding,
            "series": value.prepared.series_sha256,
            "activation": digest(value.prepared.activation),
            "requirement": value.prepared.requirement_sha256,
            "allocation": digest(value.prepared.allocation),
            "reviewed_at_block": value.prepared.reviewed_at_block,
            "eligibility": value.eligibility._binding,
            "projection": digest(value.projection),
            "row_matches": value.row_matches,
        }
    )


def validate_reward_coverage(
    value: OwnedRewardCoverageEndpoint,
    *,
    expected_series_sha256: str,
    expected_runtime_profile_sha256: str,
) -> None:
    if (
        type(value) is not OwnedRewardCoverageEndpoint
        or value._issuer is not _ISSUER
        or type(value.prepared) is not PreparedStandingReward
        or type(value.eligibility) is not OwnedHistoricalRewardEligibility
        or value.chain_submission_authorized is not False
        or value.prepared.chain_submission_authorized is not False
        or value.prepared.series_sha256 != expected_series_sha256
        or value._binding != _binding(value)
    ):
        raise ValueError("reward coverage lacks selected native provenance")
    control = value.eligibility.control
    validate_historical_reward_eligibility(
        value.eligibility,
        expected_control_hotkey=control.control_hotkey,
        expected_chain_config_sha256=control.chain_config_sha256,
        expected_runtime_profile_sha256=expected_runtime_profile_sha256,
        expected_policy_sha256=value.prepared.allocation.policy_sha256,
    )


async def review_reward_coverage(
    preparation: StandingRewardPreparation,
    package: CohortRewardPackage,
    *,
    eligibility: OwnedHistoricalRewardEligibility,
    history: OwnedRewardControlHistory,
    source: DecisionSource,
    expected_runtime_profile_sha256: str,
) -> OwnedRewardCoverageEndpoint:
    """Reconstruct one endpoint without a fresh lease or current-state substitution.

    The preparation owner selects the effective activation from complete native
    control history and independently replays its package. Caller assertions of
    selection, registration, eligibility or successful replay are insufficient.
    """
    if type(preparation) is not StandingRewardPreparation:
        raise ValueError("reward coverage requires native preparation")
    reader = preparation.reader
    validate_historical_reward_eligibility(
        eligibility,
        expected_control_hotkey=reader.series.control_hotkey,
        expected_chain_config_sha256=reader.admission_chain_config_sha256,
        expected_runtime_profile_sha256=expected_runtime_profile_sha256,
        expected_policy_sha256=preparation.policy_sha256,
    )
    subject = eligibility.subject
    hotkey = subject.registrations[subject.validator_uid].hotkey
    if identity(hotkey) not in {identity(k) for k in reader.series.validators}:
        raise ValueError("reward coverage validator is not designated by the series")
    prepared = await preparation.prepare_historical(
        package, control=eligibility.control, history=history, source=source
    )
    preparation._authority()
    preparation._check_prepared(prepared)
    snapshot = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=subject.block,
        block_hash=eligibility.control.snapshot.block_hash,
        registrations=subject.registrations,
        burn_destination=eligibility.burn_destination,
    )
    projection = project_reward_allocation(
        prepared.allocation, snapshot, reader.policy, current_block=subject.block
    )
    amounts = dict(zip(projection.uids, projection.weights, strict=True))
    expected = subtensor_stored_weights(
        tuple(amounts.get(uid, 0) for uid in range(subject.registered_uid_count))
    )
    stored = dict(subject.validator_row)
    # Missing zero entries are equivalent. Every nonzero recipient and amount
    # must match; matching a subset or the pre-conversion call is insufficient.
    matches = expected == tuple(stored.get(uid, 0) for uid in range(len(expected)))
    result = OwnedRewardCoverageEndpoint(
        prepared, eligibility, projection, matches, _issuer=_ISSUER
    )
    object.__setattr__(result, "_binding", _binding(result))
    validate_reward_coverage(
        result,
        expected_series_sha256=preparation.series_sha256,
        expected_runtime_profile_sha256=expected_runtime_profile_sha256,
    )
    return result
