"""Retain signed standing decisions and their packages for private replication.

This is a delivery boundary, not a signer or chain writer. The coordinator
supplies its complete certified decision prefix. Validators still replay the
package, opportunity and current chain control independently.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_adoption import RewardAdoptionSelection, verify_reward_adoption
from .competition_reward_decisions import (
    SignedRewardControlDecision,
    StandingRewardSeries,
    verify_reward_decisions,
)
from .competition_reward_files import StandingRewardFiles
from .competition_verification_snapshot import VerifiedPackageSnapshot, verified_package_digest
from .open_competition import CompetitionPolicy, digest
from .private_files import lock_private_file
from .protocol import canonical_json_bytes


def retain_standing_reward_inputs(
    files: StandingRewardFiles,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    decisions: tuple[SignedRewardControlDecision, ...],
    packages: Callable[[str], CohortRewardPackage | VerifiedPackageSnapshot],
    *,
    reward_adoptions: RewardAdoptionSelection | None = None,
) -> str:
    """Publish packages before decisions; retry without changing retained bytes.

    Missing packages hold delivery without expiring the original decision.
    Completed outputs can recover with the package source unavailable. The
    first valid signature envelope is retained for each immutable decision body.
    The returned digest does not establish remote availability or permission to
    commit it on-chain. Recurring replication and native control signing are
    separate owners.
    """
    prefix = verify_reward_decisions(series, policy, decisions, reward_adoptions=reward_adoptions)
    for signed in prefix:
        admission = signed.decision.admission_adoption_sha256
        if admission is not None:
            files.retain_adoption(reward_adoptions.get(admission))
        activation = signed.decision.activation
        if activation is None:
            continue
        try:
            package = files.verified_package(activation.package_sha256)
            retained_package = True
        except FileNotFoundError:
            package = packages(activation.package_sha256)
            retained_package = False
        if type(package) is not VerifiedPackageSnapshot:
            package = CohortRewardPackage.model_validate_json(canonical_json_bytes(package))
        history = package.inputs.history
        tip = digest(history.transitions[-1].transition if history.transitions else history.genesis)
        if (
            verified_package_digest(package) != activation.package_sha256
            or package.policy_sha256 != digest(policy)
            or digest(history.plan) != activation.cohort_sha256
            or digest(package.allocation) != activation.allocation_sha256
            or tip != activation.recovery_tip_sha256
        ):
            raise ValueError("reward delivery package differs from its certified decision")
        if not retained_package:
            files.retain_package(package)
        if activation.reward_adoption_sha256 is not None:
            verify_reward_adoption(
                reward_adoptions,
                activation.reward_adoption_sha256,
                series=series,
                policy=policy,
                activation=activation,
                package=package,
            )
            files.retain_adoption(reward_adoptions.get(activation.reward_adoption_sha256))
        del package, history  # Do not retain this graph while loading the next item.
    # Per-file publication has its own lock. This outer lock serializes the
    # choice of the first signature envelope, including competing exact retries.
    lock = lock_private_file(files.root / ".decision-publication.lock")
    try:
        for signed in prefix:
            sha = digest(signed.decision)
            try:
                retained = SignedRewardControlDecision.model_validate_json(files.decision(sha))
            except FileNotFoundError:
                retained = signed
            verify_recovery_quorum(retained.decision, retained.signatures, policy)
            if retained.decision != signed.decision:
                raise ValueError("retained reward delivery changes the certified decision")
            files.retain_decision(retained)
    finally:
        os.close(lock)
    return digest(prefix[-1].decision)
