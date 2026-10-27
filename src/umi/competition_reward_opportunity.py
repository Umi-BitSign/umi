"""Minimum reward opportunity and its link to the next signed activation.

Certificates name original interval evidence. Stored totals and signatures on
the next control decision do not replace native replay of that evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_geometric_rewards import GeometricRewardParameters
from .competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardEarlyRelease,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    prepare_initial_reward_adoption,
    verify_adoption_selection,
)
from .competition_reward_decisions import (
    RewardActivation,
    RewardControlDecision,
    StandingRewardControlReader,
    StandingRewardSelection,
    StandingRewardSeries,
    effective_activation_decision,
    original_activation_decision,
    retained_reward_decisions,
)
from .competition_reward_handoff_models import VerifiedLegacyRewardHandoff, validate_legacy_handoff
from .competition_reward_manifest import (
    RewardManifest,
    StandingRewardOpportunityManifest,
    verify_reward_manifest,
)
from .competition_verification_snapshot import VerifiedPackageSnapshot
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


def check_early_release_boundary(
    adoption: RewardModelAdoption,
    *,
    series: StandingRewardSeries,
    manifest: RewardManifest,
    predecessor: RewardControlDecision,
    current_block: int | None = None,
) -> RewardEarlyRelease:
    """One boundary check shared by signed adoption handoff and native readers."""
    release = adoption.early_release
    if release is None:
        raise ValueError("early release is absent from the signed adoption")
    cohorts = tuple(digest(c) for c in series.cohorts)
    try:
        index = cohorts.index(adoption.cohort_sha256)
    except ValueError:
        raise ValueError("early release successor is outside the signed series") from None
    if (
        index == 0
        or predecessor.activation is None
        or predecessor.activation.cohort_sha256 != cohorts[index - 1]
        or release.predecessor_decision_sha256 != digest(predecessor)
        or release.predecessor_activation_sha256 != digest(predecessor.activation)
        or release.successor_cohort_sha256 != adoption.cohort_sha256
        or release.successor_package_sha256 != adoption.package_sha256
        or release.manifest_sha256 != digest(manifest)
        or (current_block is not None and current_block < adoption.issued_at_block)
    ):
        raise ValueError("early release differs from its signed predecessor or successor")
    return release


def verify_signed_early_release(
    selection: RewardAdoptionSelection | None,
    *,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    manifest: RewardManifest,
    predecessor: RewardControlDecision,
    successor: RewardActivation,
    current_block: int | None = None,
) -> bool:
    """Check the explicit quorum-signed alternative to a completed minimum.

    A missing release returns False so the ordinary native opportunity path
    remains mandatory. A malformed selected release is an error, never a hint.
    """
    selected = verify_adoption_selection(selection, series, policy)
    if selected is None or successor.reward_adoption_sha256 is None:
        return False
    adoption = selected.get(successor.reward_adoption_sha256).adoption
    release = adoption.early_release
    if release is None:
        return False
    check_early_release_boundary(
        adoption,
        series=series,
        manifest=manifest,
        predecessor=predecessor,
        current_block=current_block,
    )
    if (
        successor.prior_opportunity_sha256 != digest(release)
        or adoption.cohort_sha256 != successor.cohort_sha256
        or adoption.package_sha256 != successor.package_sha256
    ):
        raise ValueError("early release differs from its signed predecessor or successor")
    return True


def prepare_early_release_revision(
    selection: RewardAdoptionSelection,
    *,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    manifest: RewardManifest,
    predecessor: RewardControlDecision,
    successor_cohort_sha256: str,
    issued_at_block: int,
    reason: str,
) -> RewardModelAdoption:
    """Build an unsigned, exact-package operator proposal for quorum review.

    The caller must obtain ``issued_at_block`` from authenticated finalized
    state. This builder has no signing, selection or transaction authority.
    """
    selected = verify_adoption_selection(selection, series, policy)
    if selected is None:
        raise ValueError("early release lacks a selected reward adoption")
    verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
    cohorts = tuple(digest(c) for c in series.cohorts)
    try:
        index = cohorts.index(successor_cohort_sha256)
    except ValueError:
        raise ValueError("early release successor is outside the signed series") from None
    latest = selected.latest(successor_cohort_sha256)
    if (
        index == 0
        or latest is None
        or latest.adoption.early_release is not None
        or predecessor.activation is None
        or predecessor.activation.cohort_sha256 != cohorts[index - 1]
        or type(issued_at_block) is not int
        or issued_at_block < max(latest.adoption.issued_at_block, predecessor.observed_at_block)
    ):
        raise ValueError("early release lacks an eligible signed predecessor or issuance")
    release = RewardEarlyRelease(
        schema="umi-reward-early-release/1",
        predecessor_decision_sha256=digest(predecessor),
        predecessor_activation_sha256=digest(predecessor.activation),
        successor_cohort_sha256=successor_cohort_sha256,
        successor_package_sha256=latest.adoption.package_sha256,
        manifest_sha256=digest(manifest),
        reason=reason,
    )
    return RewardModelAdoption.model_validate_json(
        canonical_json_bytes(
            latest.adoption.model_copy(
                update={
                    "schema_": "umi-standing-model-reward-adoption/5",
                    "revision": latest.adoption.revision + 1,
                    "predecessor_adoption_sha256": digest(latest.adoption),
                    "issued_at_block": issued_at_block,
                    "early_release": release,
                }
            )
        )
    )


def prepare_initial_early_release_adoption(
    package: VerifiedPackageSnapshot,
    *,
    selection: RewardAdoptionSelection | None,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    manifest: RewardManifest,
    predecessor: RewardControlDecision,
    parameters: GeometricRewardParameters,
    issued_at_block: int,
    reason: str,
) -> RewardModelAdoption:
    """Include the ordinary operator release in a future cohort's first vote."""
    verify_reward_manifest(canonical_json_bytes(manifest), series, policy)
    initial = prepare_initial_reward_adoption(
        package,
        series=series,
        policy=policy,
        parameters=parameters,
        issued_at_block=issued_at_block,
        previous=selection,
    )
    cohorts = tuple(digest(c) for c in series.cohorts)
    index = cohorts.index(initial.cohort_sha256)
    if (
        index == 0
        or predecessor.activation is None
        or predecessor.activation.cohort_sha256 != cohorts[index - 1]
        or issued_at_block < predecessor.observed_at_block
    ):
        raise ValueError("initial early release lacks its selected predecessor")
    release = RewardEarlyRelease(
        schema="umi-reward-early-release/1",
        predecessor_decision_sha256=digest(predecessor),
        predecessor_activation_sha256=digest(predecessor.activation),
        successor_cohort_sha256=initial.cohort_sha256,
        successor_package_sha256=initial.package_sha256,
        manifest_sha256=digest(manifest),
        reason=reason,
    )
    return RewardModelAdoption.model_validate_json(
        canonical_json_bytes(
            initial.model_copy(
                update={
                    "schema_": "umi-standing-model-reward-adoption/5",
                    "early_release": release,
                }
            )
        )
    )


def select_signed_early_release_revision(
    selection: RewardAdoptionSelection,
    signed: SignedRewardModelAdoption,
    *,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    manifest: RewardManifest,
    predecessor: RewardControlDecision,
) -> RewardAdoptionSelection:
    """Append one quorum-signed release, or reuse the exact existing append."""
    selected = verify_adoption_selection(selection, series, policy)
    signed = SignedRewardModelAdoption.model_validate_json(canonical_json_bytes(signed))
    release = signed.adoption.early_release
    if release is None:
        raise ValueError("signed revision lacks an early release")
    current = selected.latest(signed.adoption.cohort_sha256)
    if current is not None and digest(current.adoption) == digest(signed.adoption):
        if current != signed:
            raise ValueError("early release repeat changes its signed bytes")
        return selected
    expected = prepare_early_release_revision(
        selected,
        series=series,
        policy=policy,
        manifest=manifest,
        predecessor=predecessor,
        successor_cohort_sha256=signed.adoption.cohort_sha256,
        issued_at_block=signed.adoption.issued_at_block,
        reason=release.reason,
    )
    if signed.adoption != expected:
        raise ValueError("signed early release differs from its qualified proposal")
    candidate = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=tuple(
            sorted(
                (*selected.adoptions, signed),
                key=lambda v: (v.adoption.cohort_sha256, v.adoption.revision),
            )
        ),
        maximum_decisions=selected.maximum_decisions,
    )
    return verify_adoption_selection(candidate, series, policy)


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
    if (
        index == 0
        and reader.series.predecessor is None
        and (type(value) is not VerifiedLegacyRewardHandoff or validator_hotkey is None)
    ):
        raise ValueError("first standing activation requires qualified legacy handoff evidence")
    prefix = retained_reward_decisions(reader)
    original = original_activation_decision(prefix, selection.activation.cohort_sha256)
    current = effective_activation_decision(
        prefix, selection.activation.cohort_sha256, through_sequence=selection.sequence
    )
    if (
        original is None
        or current is None
        or digest(current) != selection.decision_sha256
        or current.activation != selection.activation
    ):
        raise ValueError("reward handoff differs from its selected activation revision")
    if index == 0:
        if original.sequence != 1:
            raise ValueError("first handoff changes the selected first activation")
        if reader.series.predecessor is None:
            validate_legacy_handoff(
                value,
                series=reader.series,
                activation=original.activation,
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
                activation=original.activation,
                block=current_block,
            )
        return
    prior = effective_activation_decision(
        prefix, digest(reader.series.cohorts[index - 1]), through_sequence=original.sequence - 1
    )
    if prior is not None and verify_signed_early_release(
        reader.reward_adoptions,
        series=reader.series,
        policy=reader.policy,
        manifest=manifest,
        predecessor=prior,
        successor=current.activation,
        current_block=current_block,
    ):
        if original.predecessor_sha256 != digest(prior):
            raise ValueError("early reward release changes the selected predecessor")
        return
    validate_opportunity(value)
    if (
        prior is None
        or prior.activation is None
        or prior.activation.cohort_sha256 != digest(reader.series.cohorts[index - 1])
        or original.predecessor_sha256 != digest(prior)
        or current.activation.prior_opportunity_sha256 != digest(value.certificate)
        or max(c.through_block for c in value.certificate.contributions)
        > original.observed_at_block
    ):
        raise ValueError("reward handoff changes its predecessor, certificate or evidence cutoff")
    check_opportunity_claim(
        value.certificate,
        manifest=manifest,
        series=reader.series,
        policy=reader.policy,
        activation=prior.activation,
    )
