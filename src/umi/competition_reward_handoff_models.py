"""First-activation migration selection and a scoped stopped-writer result."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field

from .competition_reward_decisions import (
    StandingRewardSeries,
    StandingRewardSeriesPredecessor,
)
from .open_competition import Hotkey, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_HANDOFF_BYTES = 8192
_ISSUER = object()


class LegacyRewardHandoffPlan(StrictProtocolModel):
    """Common migration selection bound by the first signed activation.

    Each designated validator drains its own predecessor independently. The
    plan does not claim a C4 opportunity minimum or certify another host's stop.
    """

    schema_: Literal["umi-legacy-reward-handoff-plan/1"] = Field(alias="schema")
    series_sha256: Hex32
    cohort_sha256: Hex32
    legacy_policy_sha256: Hex32
    legacy_round_sha256: Hex32
    legacy_package_sha256: Hex32


class StandingRewardHandoffPlan(StrictProtocolModel):
    """Select the exact prior standing series replaced by this series.

    The eventual first activation separately binds the natively replayed prior
    opportunity certificate. This plan can therefore be installed before that
    unbounded work completes without weakening the handoff.
    """

    schema_: Literal["umi-standing-reward-handoff-plan/1"] = Field(alias="schema")
    series_sha256: Hex32
    cohort_sha256: Hex32
    predecessor: StandingRewardSeriesPredecessor


RewardHandoffPlan = LegacyRewardHandoffPlan | StandingRewardHandoffPlan


def verify_handoff_plan(plan: RewardHandoffPlan, series: StandingRewardSeries):
    """Bind the selected migration kind to the signed series boundary."""
    series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
    expected = series.predecessor
    if expected is None:
        if type(plan) is not LegacyRewardHandoffPlan:
            raise ValueError("initial standing series requires its legacy handoff plan")
        checked = LegacyRewardHandoffPlan.model_validate_json(canonical_json_bytes(plan))
    else:
        if type(plan) is not StandingRewardHandoffPlan:
            raise ValueError("successor standing series requires its standing handoff plan")
        checked = StandingRewardHandoffPlan.model_validate_json(canonical_json_bytes(plan))
        if checked.predecessor != expected:
            raise ValueError("standing handoff differs from the signed predecessor boundary")
    if (
        checked.series_sha256 != digest(series)
        or checked.cohort_sha256 != digest(series.cohorts[0])
    ):
        raise ValueError("reward handoff differs from the selected successor series")
    return checked


class LegacyRewardHandoffIntent(StrictProtocolModel):
    schema_: Literal["umi-legacy-reward-handoff-intent/1"] = Field(alias="schema")
    plan: LegacyRewardHandoffPlan
    activation_sha256: Hex32
    installation_receipt_sha256: Hex32
    validator_hotkey: Hotkey


@dataclass(frozen=True, slots=True)
class VerifiedLegacyRewardHandoff:
    intent: LegacyRewardHandoffIntent
    inventory_sha256: str
    through_block: int
    chain_submission_authorized: Literal[False] = False
    _recheck: Callable[[], None] | None = field(default=None, repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: VerifiedLegacyRewardHandoff) -> str:
    return digest(
        {
            "intent": digest(value.intent),
            "inventory": value.inventory_sha256,
            "through": value.through_block,
            "recheck": id(value._recheck),
        }
    )


def _issue_legacy_handoff(intent, inventory_sha256, through_block, recheck):
    # Only the native host inventory consumer calls this, while its old process
    # and journal locks remain continuously held. It is not a persisted result.
    checked = LegacyRewardHandoffIntent.model_validate_json(canonical_json_bytes(intent))
    recheck()
    value = VerifiedLegacyRewardHandoff(
        checked,
        inventory_sha256,
        through_block,
        _recheck=recheck,
        _issuer=_ISSUER,
    )
    object.__setattr__(value, "_binding", _binding(value))
    return value


def validate_legacy_handoff(value, *, series, activation, validator_hotkey, block):
    """Recheck the local writer fence on every first-cohort projection."""
    if (
        type(value) is not VerifiedLegacyRewardHandoff
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.chain_submission_authorized is not False
        or not callable(value._recheck)
        or value.intent.plan.series_sha256 != digest(series)
        or value.intent.plan.cohort_sha256 != digest(series.cohorts[0])
        or value.intent.plan.cohort_sha256 != activation.cohort_sha256
        or value.intent.activation_sha256 != digest(activation)
        or digest(value.intent.plan) != activation.prior_opportunity_sha256
        or identity(value.intent.validator_hotkey) != identity(validator_hotkey)
        or identity(validator_hotkey) not in {identity(k) for k in series.validators}
        or type(block) is not int
        or block < value.through_block
    ):
        raise ValueError("first standing activation requires qualified legacy handoff evidence")
    value._recheck()
