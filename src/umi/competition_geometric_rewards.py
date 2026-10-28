"""Versioned exact geometric model reward parameters and normalization.

Decay is the multiplier between successive occupied ranks. Zero selects the
first rank; 10000 assigns equal weights. Neither boundary needs a limiting
approximation. Parameters carry no authority until selected by signed terms.
"""

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .protocol import StrictProtocolModel

GEOMETRIC_MODEL_REWARD_RULE = "baseline_or_better_geometric_bands_first_complete/1"


class GeometricRewardParameters(StrictProtocolModel):
    schema_: Literal[
        "umi-geometric-reward-parameters/1",
        "umi-geometric-reward-parameters/2",
        "umi-geometric-reward-parameters/3",
    ] = Field(default="umi-geometric-reward-parameters/2", alias="schema")
    band_width_bps: Annotated[int, Field(ge=1, le=10000)] = 500
    band_decay_bps: Annotated[int, Field(ge=0, le=10000)] = 7500
    within_band_decay_bps: Annotated[int, Field(ge=0, le=10000)] = 7500
    score_duplicate_tolerance_bps: Annotated[int, Field(ge=0, le=10000)] | None = 1
    baseline_grace_bps: Annotated[int, Field(ge=0, le=10000)] | None = None

    @model_validator(mode="before")
    @classmethod
    def retain_original_parameters(cls, value):
        if isinstance(value, dict) and value.get("schema", value.get("schema_")) == (
            "umi-geometric-reward-parameters/3"
        ):
            return {
                "band_width_bps": 250,
                "band_decay_bps": 8500,
                "within_band_decay_bps": 8500,
                "baseline_grace_bps": 100,
                **value,
            }
        if isinstance(value, dict) and value.get("schema", value.get("schema_")) == (
            "umi-geometric-reward-parameters/1"
        ):
            return {"score_duplicate_tolerance_bps": None, **value}
        return value

    @model_validator(mode="after")
    def selected_score_rule(self):
        if (self.schema_ == "umi-geometric-reward-parameters/3") != (
            self.baseline_grace_bps is not None
        ):
            raise ValueError("baseline grace requires geometric parameter version three")
        if (self.schema_ == "umi-geometric-reward-parameters/1") != (
            self.score_duplicate_tolerance_bps is None
        ):
            raise ValueError("geometric parameter version differs from its score duplicate rule")
        return self

    @model_serializer(mode="wrap")
    def preserve_original_bytes(self, handler):
        value = handler(self)
        if self.score_duplicate_tolerance_bps is None:
            value.pop("score_duplicate_tolerance_bps", None)
        if self.baseline_grace_bps is None:
            value.pop("baseline_grace_bps", None)
        return value


def baseline_eligibility_threshold(
    baseline: Fraction, parameters: GeometricRewardParameters
) -> Fraction:
    """Exact relative reward threshold; the measured reference remains unchanged."""
    if not isinstance(baseline, Fraction) or not 0 <= baseline <= 1:
        raise ValueError("baseline threshold requires normalized exact quality")
    return baseline * Fraction(10000 - (parameters.baseline_grace_bps or 0), 10000)


def validate_cohort_reward_parameters(parameters: GeometricRewardParameters, sequence: int):
    if parameters.baseline_grace_bps is not None and sequence < 7:
        raise ValueError("relative baseline grace is prospective for C7 and later cohorts")


def cohort_reward_parameters(sequence: int) -> GeometricRewardParameters:
    """Announced defaults for new proposals; never reinterpret signed parameters.

    C6 retains its finalized 25% decay. C7 and subsequent cohorts use 15%
    decay at both levels and a one-percent relative eligibility grace. Historical
    schema defaults above remain unchanged.
    """
    if type(sequence) is not int or sequence < 1:
        raise ValueError("reward parameters require a positive cohort sequence")
    decay = 8500 if sequence >= 7 else 7500
    return GeometricRewardParameters(
        schema=(
            "umi-geometric-reward-parameters/3"
            if sequence >= 7
            else "umi-geometric-reward-parameters/2"
        ),
        band_width_bps=250,
        band_decay_bps=decay,
        within_band_decay_bps=decay,
        score_duplicate_tolerance_bps=1,
        baseline_grace_bps=100 if sequence >= 7 else None,
    )


def normalized_geometric_weights(count: int, decay_bps: int) -> tuple[Fraction, ...]:
    """Normalize finite rank weights exactly, with no artificial rank cap."""
    if type(count) is not int or count < 0:
        raise ValueError("geometric rank count must be a nonnegative integer")
    if type(decay_bps) is not int or not 0 <= decay_bps <= 10000:
        raise ValueError("geometric decay must be an integer from 0 through 10000")
    if not count:
        return ()
    ratio = Fraction(decay_bps, 10000)
    weights = [Fraction(1)]
    for _ in range(1, count):
        weights.append(weights[-1] * ratio)
    total = sum(weights, Fraction())
    return tuple(weight / total for weight in weights)
