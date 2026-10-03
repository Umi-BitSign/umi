"""Minimum reward opportunity and its link to the next signed activation.

Certificates name original interval evidence. Stored totals and signatures on
the next control decision do not replace native replay of that evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_reward_decisions import (
    RewardActivation,
    SignedRewardControlDecision,
    StandingRewardControlReader,
    StandingRewardSelection,
    StandingRewardSeries,
)
from .competition_reward_handoff_models import VerifiedLegacyRewardHandoff, validate_legacy_handoff
from .competition_reward_manifest import (
    RewardManifest,
    StandingRewardOpportunityManifest,
    verify_reward_manifest,
)
from .open_competition import CompetitionPolicy, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

Positive = Annotated[int, Field(ge=1, le=2**53 - 1)]
_ISSUER = object()


class RewardCoverageRule(StrictProtocolModel):
    schema_: Literal["umi-reward-coverage-rule/1"] = Field(alias="schema")
    series_sha256: Hex32
    runtime_profile_sha256: Hex32
    maximum_interval_ms: Positive


def opportunity_rule(
    manifest: RewardManifest, series: StandingRewardSeries, policy: CompetitionPolicy
) -> RewardCoverageRule:
    checked = verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
    if not isinstance(checked, StandingRewardOpportunityManifest):
        raise ValueError("reward manifest has no approved opportunity terms")
    return RewardCoverageRule(
        schema="umi-reward-coverage-rule/1",
        series_sha256=digest(series),
        runtime_profile_sha256=checked.opportunity.runtime_profile_sha256,
        maximum_interval_ms=checked.opportunity.maximum_interval_ms,
    )


class RewardOpportunityWitness(StrictProtocolModel):
    """Chronological interval references; transport and host byte bounds apply."""

    schema_: Literal["umi-reward-opportunity-witness/1"] = Field(alias="schema")
    rule_sha256: Hex32
    activation_sha256: Hex32
    validator_account_id: Hex32
    interval_keys: Annotated[tuple[Hex32, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def unique_intervals(self):
        if len(set(self.interval_keys)) != len(self.interval_keys):
            raise ValueError("opportunity witness repeats an interval")
        return self


class RewardOpportunityContribution(StrictProtocolModel):
    validator_account_id: Hex32
    witness_sha256: Hex32
    credited_ms: Positive
    through_block: Positive


class RewardOpportunityCertificate(StrictProtocolModel):
    """Content-addressed completion evidence, bound by the next control vote."""

    schema_: Literal["umi-reward-opportunity-certificate/1"] = Field(alias="schema")
    series_sha256: Hex32
    manifest_sha256: Hex32
    rule_sha256: Hex32
    activation_sha256: Hex32
    contributions: Annotated[
        tuple[RewardOpportunityContribution, ...], Field(min_length=1, max_length=256)
    ]

    @model_validator(mode="after")
    def ordered(self):
        keys = [c.validator_account_id for c in self.contributions]
        if keys != sorted(set(keys)):
            raise ValueError("opportunity contributions must be unique and ordered")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedRewardOpportunity:
    certificate: RewardOpportunityCertificate
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _issue_opportunity(certificate: RewardOpportunityCertificate) -> VerifiedRewardOpportunity:
    # Called only after the native producer/reviewer has checked every interval.
    checked = RewardOpportunityCertificate.model_validate_json(canonical_json_bytes(certificate))
    return VerifiedRewardOpportunity(checked, _issuer=_ISSUER, _binding=digest(checked))


def validate_opportunity(value: VerifiedRewardOpportunity) -> RewardOpportunityCertificate:
    """Require original native replay, including after reconstructing archived evidence."""
    if (
        type(value) is not VerifiedRewardOpportunity
        or value._issuer is not _ISSUER
        or value._binding != digest(value.certificate)
        or value.chain_submission_authorized is not False
    ):
        raise ValueError("reward opportunity lacks native replay provenance")
    return value.certificate


def check_opportunity_claim(
    certificate: RewardOpportunityCertificate,
    *,
    manifest: RewardManifest,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    activation: RewardActivation,
) -> RewardCoverageRule:
    """Static binding checks only; these do not authenticate claimed coverage."""
    rule = opportunity_rule(manifest, series, policy)
    checked = RewardOpportunityCertificate.model_validate_json(canonical_json_bytes(certificate))
    if (
        checked.series_sha256 != digest(series)
        or checked.manifest_sha256 != digest(manifest)
        or checked.rule_sha256 != digest(rule)
        or checked.activation_sha256 != digest(activation)
        or activation.cohort_sha256 not in {digest(p) for p in series.cohorts}
        or tuple(c.validator_account_id for c in checked.contributions)
        != tuple(identity(k) for k in series.validators)
    ):
        raise ValueError("opportunity certificate changes its authority or designated validators")
    assert isinstance(manifest, StandingRewardOpportunityManifest)
    if any(
        c.credited_ms < manifest.opportunity.minimum_validator_ms for c in checked.contributions
    ):
        raise ValueError("designated validator has not completed its minimum reward opportunity")
    return rule


def require_previous_opportunity(
    value: object | None,
    *,
    reader: StandingRewardControlReader,
    manifest: RewardManifest,
    selection: StandingRewardSelection,
    validator_hotkey: str | None = None,
    current_block: int | None = None,
) -> None:
    """Require the exact predecessor's completed opportunity before handoff.

    Call after native current-control/history selection. The first activation
    needs separate qualified legacy migration evidence and cannot use a made-up
    minimum certificate as a substitute. No submission authority is issued here.
    """
    if not isinstance(manifest, StandingRewardOpportunityManifest):
        raise ValueError("reward manifest has no approved opportunity terms")
    if selection.activation is None or selection.series_sha256 != reader.series_sha256:
        raise ValueError("opportunity handoff lacks the selected series activation")
    index = tuple(digest(p) for p in reader.series.cohorts).index(
        selection.activation.cohort_sha256
    )
    if index == 0:
        if (
            reader.series.predecessor is None
            and (type(value) is not VerifiedLegacyRewardHandoff or validator_hotkey is None)
        ):
            raise ValueError(
                "first standing activation requires qualified legacy handoff evidence"
            )
        first = SignedRewardControlDecision.model_validate_json(
            canonical_json_bytes(reader.journal.get("reward_control_decision", "0001"))
        ).decision
        if (
            first.kind != "activate"
            or first.sequence != 1
            or digest(first) != selection.decision_sha256
            or first.activation != selection.activation
        ):
            raise ValueError("first handoff changes the selected first activation")
        if reader.series.predecessor is None:
            validate_legacy_handoff(
                value,
                series=reader.series,
                activation=selection.activation,
                validator_hotkey=validator_hotkey,
                block=current_block,
            )
        else:
            # Local import keeps the opportunity primitives independent of the
            # native predecessor coverage owner that issues this process result.
            from .competition_reward_handoff_models import StandingRewardHandoffPlan
            from .competition_reward_series_handoff import (
                validate_standing_predecessor_opportunity,
            )

            plan = StandingRewardHandoffPlan(
                schema="umi-standing-reward-handoff-plan/1",
                series_sha256=digest(reader.series),
                cohort_sha256=digest(reader.series.cohorts[0]),
                predecessor=reader.series.predecessor,
            )
            validate_standing_predecessor_opportunity(
                value,
                plan=plan,
                activation=selection.activation,
                block=current_block,
            )
        return
    validate_opportunity(value)
    prior = SignedRewardControlDecision.model_validate_json(
        canonical_json_bytes(reader.journal.get("reward_control_decision", f"{index:04d}"))
    ).decision
    current = SignedRewardControlDecision.model_validate_json(
        canonical_json_bytes(reader.journal.get("reward_control_decision", f"{index + 1:04d}"))
    ).decision
    if (
        prior.activation is None
        or prior.kind != "activate"
        or prior.activation.cohort_sha256 != digest(reader.series.cohorts[index - 1])
        or current.predecessor_sha256 != digest(prior)
        or digest(current) != selection.decision_sha256
        or current.activation != selection.activation
        or current.activation.prior_opportunity_sha256 != digest(value.certificate)
        or max(c.through_block for c in value.certificate.contributions) > current.observed_at_block
    ):
        raise ValueError("reward handoff changes its predecessor, certificate or evidence cutoff")
    check_opportunity_claim(
        value.certificate,
        manifest=manifest,
        series=reader.series,
        policy=reader.policy,
        activation=prior.activation,
    )
