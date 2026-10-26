"""Explicit forward reward economics; original cohort consent remains unchanged.

These quorum signatures authorize a separately selected forward allocation.
They cannot rewrite a certified package, replace a retained decision, or prove
that an earlier allocation never reached the chain. Revision clearance belongs
to the native finalized-history owner.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_recovery import Block, verify_recovery_quorum
from .competition_cohort_reward_allocation import derive_effective_reward_allocation
from .competition_geometric_rewards import GeometricRewardParameters
from .competition_reward_bootstrap import BootstrapRewardPredecessor
from .competition_reward_timing import RewardActivationAge
from .competition_verification_snapshot import VerifiedPackageSnapshot, verified_package_digest
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_REWARD_ADOPTION_BYTES = 256 * 1024
MAX_REWARD_DECISIONS = 10000


class RewardModelAdoption(StrictProtocolModel):
    schema_: Literal[
        "umi-standing-model-reward-adoption/1",
        "umi-standing-model-reward-adoption/2",
        "umi-standing-model-reward-adoption/3",
    ] = Field(alias="schema")
    series_sha256: Hex32
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    package_sha256: Hex32
    allocation_sha256: Hex32
    service_certificate_sha256: Hex32
    quality_manifest_sha256: Hex32
    effective_allocation_sha256: Hex32
    parameters: GeometricRewardParameters
    revision: Annotated[int, Field(ge=1, le=MAX_REWARD_DECISIONS)]
    predecessor_adoption_sha256: Hex32 | None
    issued_at_block: Block
    lifetime: Literal["until_first_verified_live_reward_then_locked"]
    original_signed_inputs_unchanged: Literal[True] = True

    activation_age: RewardActivationAge | None = None
    bootstrap_predecessor: BootstrapRewardPredecessor | None = None

    @model_serializer(mode="wrap")
    def preserve_original_adoption(self, handler):
        value = handler(self)
        if self.activation_age is None:
            value.pop("activation_age", None)
        if self.bootstrap_predecessor is None:
            value.pop("bootstrap_predecessor", None)
        return value

    @model_validator(mode="after")
    def lineage(self):
        bootstrap = self.schema_ == "umi-standing-model-reward-adoption/3"
        if bootstrap != (self.bootstrap_predecessor is not None):
            raise ValueError("bootstrap admission requires an explicit versioned adoption")
        if not bootstrap and (self.schema_ == "umi-standing-model-reward-adoption/2") != (
            self.activation_age is not None
        ):
            raise ValueError("reward timing requires an explicit versioned adoption")
        if self.activation_age is not None and (
            self.activation_age.observed_at_block > self.issued_at_block
        ):
            raise ValueError("reward timing observation is ahead of adoption issuance")
        if (self.revision == 1) != (self.predecessor_adoption_sha256 is None):
            raise ValueError("reward adoption requires its exact revision predecessor")
        return self


class SignedRewardModelAdoption(StrictProtocolModel):
    adoption: RewardModelAdoption
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class RewardAdoptionSelection(StrictProtocolModel):
    """Explicit host selection, retaining every immutable signed revision."""

    schema_: Literal["umi-standing-reward-adoption-selection/1"] = Field(alias="schema")
    adoptions: Annotated[
        tuple[SignedRewardModelAdoption, ...], Field(min_length=1, max_length=4096)
    ]
    maximum_decisions: Annotated[int, Field(ge=3, le=MAX_REWARD_DECISIONS)] = 1024

    @model_validator(mode="after")
    def ordered(self):
        keys = [(v.adoption.cohort_sha256, v.adoption.revision) for v in self.adoptions]
        if keys != sorted(set(keys)):
            raise ValueError("reward adoption selection must retain ordered unique revisions")
        preceding = {}
        immutable = (
            "series_sha256",
            "policy_sha256",
            "cohort_sha256",
            "authority_sha256",
            "package_sha256",
            "allocation_sha256",
            "service_certificate_sha256",
            "quality_manifest_sha256",
        )
        for signed in self.adoptions:
            value = signed.adoption
            prior = preceding.get(value.cohort_sha256)
            if prior is None:
                if value.revision != 1:
                    raise ValueError("reward adoption selection omits its original revision")
            elif (
                value.revision != prior.revision + 1
                or value.predecessor_adoption_sha256 != digest(prior)
                or value.issued_at_block < prior.issued_at_block
                or any(getattr(value, k) != getattr(prior, k) for k in immutable)
            ):
                raise ValueError("reward adoption revision changed its original evidence or parent")
            preceding[value.cohort_sha256] = value
        return self

    def latest(self, cohort: str) -> SignedRewardModelAdoption | None:
        return next(
            (v for v in reversed(self.adoptions) if v.adoption.cohort_sha256 == cohort), None
        )

    def get(self, sha: str) -> SignedRewardModelAdoption:
        for value in self.adoptions:
            if digest(value.adoption) == sha:
                return value
        raise ValueError("reward adoption is absent from the independently selected lineage")


def verify_adoption_selection(selection, series, policy: CompetitionPolicy):
    if selection is None:
        return None
    value = RewardAdoptionSelection.model_validate_json(canonical_json_bytes(selection))
    if value.maximum_decisions < len(series.cohorts) + 2:
        raise ValueError("reward decision capacity cannot contain the admitted cohorts")
    cohorts = {digest(c): c for c in series.cohorts}
    for signed in value.adoptions:
        body = signed.adoption
        if (
            body.series_sha256 != digest(series)
            or body.policy_sha256 != digest(policy)
            or body.authority_sha256 != digest(series.recovery.authority)
            or body.cohort_sha256 not in cohorts
            or body.issued_at_block < series.recovery.authority.issued_at_block
        ):
            raise ValueError("reward adoption differs from the selected standing authority")
        if body.activation_age is not None:
            body.activation_age.check_plan(cohorts[body.cohort_sha256])
        if body.bootstrap_predecessor is not None:
            if body.cohort_sha256 != digest(series.cohorts[0]):
                raise ValueError("bootstrap adoption must bind the first standing cohort")
            body.bootstrap_predecessor.check_series(series)
        # The original policy selects the independent quorum, not new economics.
        # This distinct forward contract is selected explicitly by every host.
        verify_recovery_quorum(body, signed.signatures, policy)
    bootstrap_admission(value)
    return value


def bootstrap_admission(selection):
    """Return the immutable first authorization, retaining it through revisions.

    Callers must already have authenticated the host's full adoption selection.
    Later economic revisions cannot replace the original admission anchor.
    """
    anchor = None
    if selection is not None:
        for signed in selection.adoptions:
            body = signed.adoption
            if body.bootstrap_predecessor is None:
                continue
            if anchor is None:
                if body.revision != 1:
                    raise ValueError("bootstrap admission requires the original adoption revision")
                anchor = (digest(body), body.bootstrap_predecessor)
            elif body.bootstrap_predecessor != anchor[1]:
                raise ValueError("reward revision changed its original bootstrap predecessor")
    return anchor


def initial_reward_boundary(series, selection):
    """Shared boundary for production, review, traversal and publication."""
    anchor = bootstrap_admission(selection)
    if anchor is not None:
        if series.predecessor is not None:
            raise ValueError("standing successor cannot replace its predecessor with bootstrap")
        sha, value = anchor
        return value.control_sha256, value.committed_at_block, sha
    if series.predecessor is not None:
        prior = series.predecessor
        return prior.decision_sha256, prior.decision_committed_at_block, None
    return None, 0, None


def prepare_initial_reward_adoption(
    package: VerifiedPackageSnapshot,
    *,
    series,
    policy: CompetitionPolicy,
    parameters: GeometricRewardParameters,
    issued_at_block: Block,
    previous: RewardAdoptionSelection | None,
) -> RewardModelAdoption:
    """Derive one unsigned forward proposal from an owner-imported package.

    The caller must supply an independently verified finalized issuance block.
    This method reads only the compact package envelope. The snapshot proves
    retained byte identity, not semantic certification. Independent native
    review remains required before signing and again before activation. This
    method neither signs nor selects the adoption and grants no transaction
    authority.
    """
    if type(package) is not VerifiedPackageSnapshot:
        raise TypeError("reward adoption proposal requires a native verified package snapshot")
    if type(parameters) is not GeometricRewardParameters:
        raise TypeError("reward adoption proposal requires explicit geometric parameters")
    if type(issued_at_block) is not int:
        raise TypeError("reward adoption issuance requires a finalized block number")
    package_sha = verified_package_digest(package)
    verified = verify_adoption_selection(previous, series, policy)
    cohort = digest(package.inputs.history.plan)
    if (
        package.inputs.history.plan not in series.cohorts
        or package.policy_sha256 != digest(policy)
        or series.policy_sha256 != digest(policy)
        or digest(package.inputs.history.authority.authority)
        != digest(series.recovery.authority)
        or issued_at_block < series.recovery.authority.issued_at_block
        or (verified is not None and verified.latest(cohort) is not None)
    ):
        raise ValueError("reward adoption package, lineage or initial revision differs")
    effective = derive_effective_reward_allocation(package, parameters)
    return RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(series),
        policy_sha256=digest(policy),
        cohort_sha256=cohort,
        authority_sha256=digest(series.recovery.authority),
        package_sha256=package_sha,
        allocation_sha256=digest(package.allocation),
        service_certificate_sha256=digest(package.service),
        quality_manifest_sha256=digest(package.benchmark),
        effective_allocation_sha256=digest(effective),
        parameters=parameters,
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=issued_at_block,
        lifetime="until_first_verified_live_reward_then_locked",
    )


def verify_reward_adoption(
    selection, sha, *, series, policy, activation=None, package=None, current_block=None
) -> RewardModelAdoption:
    selected = verify_adoption_selection(selection, series, policy)
    if selected is None:
        raise ValueError("forward reward economics lack explicit host adoption")
    body = selected.get(sha).adoption
    if current_block is not None and body.issued_at_block > current_block:
        raise ValueError("reward adoption is ahead of its original finalized observation")
    if activation is not None and (
        activation.cohort_sha256 != body.cohort_sha256
        or activation.allocation_sha256 != body.allocation_sha256
        or activation.package_sha256 != body.package_sha256
        or activation.effective_allocation_sha256 != body.effective_allocation_sha256
        or activation.reward_adoption_sha256 != digest(body)
    ):
        raise ValueError("reward activation changed its adopted evidence or effective allocation")
    if package is not None and (
        verified_package_digest(package) != body.package_sha256
        or digest(package.allocation) != body.allocation_sha256
        or digest(package.service) != body.service_certificate_sha256
        or digest(package.benchmark) != body.quality_manifest_sha256
        or digest(package.inputs.history.plan) != body.cohort_sha256
        or digest(package.inputs.history.authority.authority) != body.authority_sha256
        or package.policy_sha256 != body.policy_sha256
    ):
        raise ValueError("reward adoption changes the original certified package inputs")
    if (
        package is not None
        and digest(derive_effective_reward_allocation(package, body.parameters))
        != body.effective_allocation_sha256
    ):
        raise ValueError("reward adoption differs from deterministic effective allocation")
    return body


def effective_adoption_binding(activation) -> str:
    """Compact cache binding; never a substitute for signature/native review."""
    return digest(
        {
            "activation": digest(activation),
            "adoption": activation.reward_adoption_sha256,
            "effective_allocation": activation.effective_allocation_sha256
            or activation.allocation_sha256,
        }
    )
