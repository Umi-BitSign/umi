"""Bound package discovery to admitted cohorts and refresh signed release selection."""

from .competition_cohort_recovery import verify_recovery_authority
from .competition_reward_adoption_consumer import (
    RewardAdoptionConsumer,
    open_reward_adoption_feed,
)
from .competition_reward_decisions import StandingRewardSeries
from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes


class RewardPackageSelection(RewardAdoptionConsumer):
    def __init__(
        self, root, *, series, policy, initial, source=None, allow_completed_successors=False
    ):
        if type(allow_completed_successors) is not bool:
            raise TypeError("completed successor discovery requires an explicit boolean")
        self._completed_names = None
        if allow_completed_successors:
            if source is None:
                raise ValueError("completed successor discovery requires its signed adoption feed")
            # A producer needs the completed package before it can obtain the
            # first adoption. The selected recovery authority already admits
            # these exact cohorts; transport grants no activation or signature.
            series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
            policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
            if series.policy_sha256 != digest(policy):
                raise ValueError("completed successor discovery changes the selected policy")
            verify_recovery_authority(series.recovery, policy)
            self._completed_names = frozenset(
                digest(plan) + ".json" for plan in series.cohorts if plan.sequence >= 6
            )
        self.series = series
        self._configure_reward_adoptions(
            initial,
            series=series,
            policy=policy,
            feed=open_reward_adoption_feed(
                root, source=source, series=series, policy=policy, initial=initial, deferred=True
            ),
        )

    def __call__(self):
        selected = self.refresh_reward_adoptions()
        # Feed damage still stops discovery. Unchanged polls read no package,
        # proof or directory inventory and do not repeat authority verification.
        if self._completed_names is not None:
            return self._completed_names
        return frozenset(
            digest(plan) + ".json"
            for plan in self.series.cohorts
            if plan.sequence >= 6
            and selected is not None
            and selected.latest(digest(plan)) is not None
        )
