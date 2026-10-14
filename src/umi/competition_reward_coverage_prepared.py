"""Process-owned coverage reuse without keeping a complete reward package resident."""

from dataclasses import dataclass
from functools import partial

from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .concurrency import run_owned_thread
from .open_competition import digest


class CoveragePackageReplayRequired(Exception):
    """Original private bytes are needed to review an earlier block or model assets."""


@dataclass(frozen=True, slots=True)
class RetainedCoveragePackage:
    prepared: PreparedStandingReward


def retained_package_sha256(preparation, retained):
    if (
        type(preparation) is not StandingRewardPreparation
        or type(retained) is not RetainedCoveragePackage
    ):
        raise ValueError("coverage package lacks native preparation owner")
    preparation._authority()
    preparation._check_prepared(retained.prepared)
    return retained.prepared.activation.package_sha256


def _reuse(preparation, retained, control, history, source):
    retained_package_sha256(preparation, retained)
    selected = preparation.reader.review_history(control, source, history).effective_selection
    if selected is None or selected.state != "selected" or selected.activation is None:
        raise ValueError("historical control has no effective reward package")
    if any(
        getattr(selected.activation, name) != getattr(retained.prepared.activation, name)
        for name in (
            "cohort_sha256",
            "allocation_sha256",
            "package_sha256",
            "recovery_tip_sha256",
            "prior_opportunity_sha256",
        )
    ):
        raise ValueError("retained coverage package differs from historical activation")
    cached = preparation._prepared.get(digest(selected.activation))
    if cached is None:
        raise CoveragePackageReplayRequired
    preparation._check_prepared(cached)
    if cached.activation != selected.activation:
        raise ValueError("native preparation cache changed its activation")
    if control.snapshot.block_number < cached.reviewed_at_block:
        raise CoveragePackageReplayRequired
    # Existing prepare_historical always refreshes direct-model artifacts. Retain
    # that behavior by reloading its original participant selection when enabled.
    if preparation.model_artifacts is not None:
        raise CoveragePackageReplayRequired
    return cached


async def prepare_retained_coverage(preparation, retained, *, control, history, source):
    retained_package_sha256(preparation, retained)
    async with preparation._lock:
        return await run_owned_thread(
            partial(_reuse, preparation, retained, control, history, source)
        )
