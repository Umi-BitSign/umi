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
from .competition_cohort_score_correction import (
    ModelScoreCorrectionEvidence,
    SignedModelScoreCorrection,
    verify_signed_score_correction,
)
from .competition_geometric_rewards import (
    GeometricRewardParameters,
    cohort_reward_parameters,
    validate_cohort_reward_parameters,
)
from .competition_reward_bootstrap import BootstrapRewardPredecessor
from .competition_reward_timing import RewardActivationAge
from .competition_reward_transition_timing import RewardPredecessorLiveAge
from .competition_verification_snapshot import VerifiedPackageSnapshot, verified_package_digest
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_REWARD_ADOPTION_BYTES = 256 * 1024
MAX_REWARD_DECISIONS = 10000


class RewardEarlyRelease(StrictProtocolModel):
    """Quorum-signed operator choice to advance one exact successor early.

    This is embedded in a signed reward adoption. It authorizes skipping only
    the predecessor's minimum opportunity; it supplies no coverage evidence.
    """

    schema_: Literal["umi-reward-early-release/1"] = Field(alias="schema")
    predecessor_decision_sha256: Hex32
    predecessor_activation_sha256: Hex32
    successor_cohort_sha256: Hex32
    successor_package_sha256: Hex32
    manifest_sha256: Hex32
    reason: Annotated[str, Field(min_length=8, max_length=1024)]


class RewardAutomaticRelease(RewardEarlyRelease):
    """Quorum-reviewed elapsed-time alternative; never fabricated opportunity."""

    schema_: Literal["umi-reward-early-release/2"] = Field(alias="schema")
    trigger: Literal["predecessor_live_for_24h"]
    live_age: RewardPredecessorLiveAge

    @model_validator(mode="after")
    def completed_live_wait(self):
        if (
            not self.live_age.ready
            or self.live_age.predecessor_activation_sha256 != self.predecessor_activation_sha256
        ):
            raise ValueError("automatic reward release requires 24 hours of predecessor live age")
        return self


class RewardModelAdoption(StrictProtocolModel):
    schema_: Literal[
        "umi-standing-model-reward-adoption/1",
        "umi-standing-model-reward-adoption/2",
        "umi-standing-model-reward-adoption/3",
        "umi-standing-model-reward-adoption/4",
        "umi-standing-model-reward-adoption/5",
        "umi-standing-model-reward-adoption/6",
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
    score_correction_evidence: ModelScoreCorrectionEvidence | None = None
    signed_score_correction: SignedModelScoreCorrection | None = None
    early_release: (
        Annotated[RewardEarlyRelease | RewardAutomaticRelease, Field(discriminator="schema_")]
        | None
    ) = None

    @model_serializer(mode="wrap")
    def preserve_original_adoption(self, handler):
        value = handler(self)
        if self.activation_age is None:
            value.pop("activation_age", None)
        if self.bootstrap_predecessor is None:
            value.pop("bootstrap_predecessor", None)
        if self.score_correction_evidence is None:
            value.pop("score_correction_evidence", None)
        if self.signed_score_correction is None:
            value.pop("signed_score_correction", None)
        if self.early_release is None:
            value.pop("early_release", None)
        return value

    @model_validator(mode="after")
    def lineage(self):
        bootstrap = self.schema_ == "umi-standing-model-reward-adoption/3"
        correction = self.schema_ == "umi-standing-model-reward-adoption/4"
        early = self.schema_ in {
            "umi-standing-model-reward-adoption/5",
            "umi-standing-model-reward-adoption/6",
        }
        automatic = self.schema_ == "umi-standing-model-reward-adoption/6"
        if bootstrap != (self.bootstrap_predecessor is not None):
            raise ValueError("bootstrap admission requires an explicit versioned adoption")
        if (self.score_correction_evidence is None) != (self.signed_score_correction is None):
            raise ValueError("score correction requires complete versioned evidence")
        if correction and self.score_correction_evidence is None:
            raise ValueError("score correction requires complete versioned evidence")
        if early != (self.early_release is not None):
            raise ValueError("early release requires an explicit versioned adoption")
        if automatic != isinstance(self.early_release, RewardAutomaticRelease):
            raise ValueError("automatic reward release requires its explicit versioned adoption")
        if automatic and self.early_release.live_age.observed_at_block > self.issued_at_block:
            raise ValueError("automatic release observation is ahead of adoption issuance")
        if not correction and not early and self.score_correction_evidence is not None:
            raise ValueError("score correction requires an explicit versioned adoption")
        if (
            not bootstrap
            and not correction
            and not early
            and (self.schema_ == "umi-standing-model-reward-adoption/2")
            != (self.activation_age is not None)
        ):
            raise ValueError("reward timing requires an explicit versioned adoption")
        if self.score_correction_evidence is not None and (
            self.score_correction_evidence.cohort_sha256 != self.cohort_sha256
            or self.score_correction_evidence.original_package_sha256 != self.package_sha256
            or self.score_correction_evidence.original_allocation_sha256 != self.allocation_sha256
            or self.score_correction_evidence.original_quality_manifest_sha256
            != self.quality_manifest_sha256
            or self.score_correction_evidence.parameters != self.parameters
            or self.signed_score_correction.statement.issued_at_block > self.issued_at_block
        ):
            raise ValueError("score correction differs from adopted original evidence")
        if self.activation_age is not None and (
            self.activation_age.observed_at_block > self.issued_at_block
        ):
            raise ValueError("reward timing observation is ahead of adoption issuance")
        if self.early_release is not None and (
            self.early_release.successor_cohort_sha256 != self.cohort_sha256
            or self.early_release.successor_package_sha256 != self.package_sha256
        ):
            raise ValueError("early release differs from the adopted successor package")
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
            "score_correction_evidence",
            "signed_score_correction",
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
                or (prior.early_release is not None and value.early_release != prior.early_release)
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
        validate_cohort_reward_parameters(body.parameters, cohorts[body.cohort_sha256].sequence)
        if body.bootstrap_predecessor is not None:
            if body.cohort_sha256 != digest(series.cohorts[0]):
                raise ValueError("bootstrap adoption must bind the first standing cohort")
            body.bootstrap_predecessor.check_series(series)
        if body.early_release is not None:
            index = tuple(digest(c) for c in series.cohorts).index(body.cohort_sha256)
            if index == 0 or body.early_release.manifest_sha256 != series.manifest_sha256:
                raise ValueError("early release requires a successor and the signed manifest")
        # The original policy selects the independent quorum, not new economics.
        # This distinct forward contract is selected explicitly by every host.
        verify_recovery_quorum(body, signed.signatures, policy)
        if body.signed_score_correction is not None:
            statement = body.signed_score_correction.statement
            evidence = body.score_correction_evidence
            if (
                statement.cohort_sha256 != body.cohort_sha256
                or statement.policy_sha256 != body.policy_sha256
                or statement.authority_sha256 != body.authority_sha256
                or statement.original_package_sha256 != body.package_sha256
                or statement.original_allocation_sha256 != body.allocation_sha256
                or statement.original_package_bytes_sha256 != evidence.original_package_bytes_sha256
                or statement.evidence_sha256 != digest(evidence)
                or statement.corrected_allocation_sha256 != body.effective_allocation_sha256
            ):
                raise ValueError("adopted score correction differs from signed evidence")
            verify_recovery_quorum(statement, body.signed_score_correction.signatures, policy)
    bootstrap_admission(value)
    return value


def prepare_activation_age_revision(
    selection: RewardAdoptionSelection,
    *,
    series,
    policy: CompetitionPolicy,
    cohort_sha256: str,
    activation_age: RewardActivationAge,
    issued_at_block: int,
) -> RewardModelAdoption:
    """Propose a later timing attestation without changing signed reward terms.

    The caller obtains ``activation_age`` from native finalized timestamp proofs.
    An existing adoption and control decision retain their original bytes; the
    coordinator must sign a separate revision decision before this takes effect.
    """
    selected = verify_adoption_selection(selection, series, policy)
    if selected is None or type(activation_age) is not RewardActivationAge:
        raise ValueError("activation age revision requires selected native facts")
    latest = selected.latest(cohort_sha256)
    plan = next((p for p in series.cohorts if digest(p) == cohort_sha256), None)
    if (
        latest is None
        or plan is None
        or latest.adoption.activation_age is not None
        or not activation_age.skips_activation_delay
        or type(issued_at_block) is not int
        or issued_at_block < max(latest.adoption.issued_at_block, activation_age.observed_at_block)
    ):
        raise ValueError("activation age revision lacks an eligible signed predecessor")
    activation_age.check_plan(plan)
    prior = latest.adoption
    schema = (
        "umi-standing-model-reward-adoption/2"
        if prior.schema_ == "umi-standing-model-reward-adoption/1"
        else prior.schema_
    )
    return RewardModelAdoption.model_validate_json(
        canonical_json_bytes(
            prior.model_copy(
                update={
                    "schema_": schema,
                    "revision": prior.revision + 1,
                    "predecessor_adoption_sha256": digest(prior),
                    "issued_at_block": issued_at_block,
                    "activation_age": activation_age,
                }
            )
        )
    )


def select_signed_activation_age_revision(
    selection: RewardAdoptionSelection,
    signed: SignedRewardModelAdoption,
    *,
    series,
    policy: CompetitionPolicy,
) -> RewardAdoptionSelection:
    """Append the exact quorum-signed age revision, or reuse its exact bytes."""
    selected = verify_adoption_selection(selection, series, policy)
    signed = SignedRewardModelAdoption.model_validate_json(canonical_json_bytes(signed))
    age = signed.adoption.activation_age
    if selected is None or age is None:
        raise ValueError("signed revision lacks an activation age")
    current = selected.latest(signed.adoption.cohort_sha256)
    if current == signed:
        return selected
    expected = prepare_activation_age_revision(
        selected,
        series=series,
        policy=policy,
        cohort_sha256=signed.adoption.cohort_sha256,
        activation_age=age,
        issued_at_block=signed.adoption.issued_at_block,
    )
    if signed.adoption != expected:
        raise ValueError("signed activation age differs from its qualified proposal")
    candidate = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=tuple(
            sorted(
                (*selected.adoptions, signed),
                key=lambda value: (value.adoption.cohort_sha256, value.adoption.revision),
            )
        ),
        maximum_decisions=selected.maximum_decisions,
    )
    return verify_adoption_selection(candidate, series, policy)


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
    parameters: GeometricRewardParameters | None = None,
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
    if parameters is None:
        parameters = cohort_reward_parameters(package.inputs.history.plan.sequence)
    if type(parameters) is not GeometricRewardParameters:
        raise TypeError("reward adoption proposal requires explicit geometric parameters")
    validate_cohort_reward_parameters(parameters, package.inputs.history.plan.sequence)
    if type(issued_at_block) is not int:
        raise TypeError("reward adoption issuance requires a finalized block number")
    package_sha = verified_package_digest(package)
    verified = verify_adoption_selection(previous, series, policy)
    cohort = digest(package.inputs.history.plan)
    if (
        package.inputs.history.plan not in series.cohorts
        or package.policy_sha256 != digest(policy)
        or series.policy_sha256 != digest(policy)
        or digest(package.inputs.history.authority.authority) != digest(series.recovery.authority)
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


def select_signed_initial_reward_adoption(
    previous: RewardAdoptionSelection | None,
    signed: SignedRewardModelAdoption,
    *,
    series,
    policy: CompetitionPolicy,
) -> RewardAdoptionSelection:
    """Idempotently extend an authenticated selection with one signed cohort body.

    This pure selection does not install a host config or activate rewards.
    Repeating the exact signed body reuses the existing immutable selection;
    replacing a revision requires the separate native revision procedure.
    """
    old = verify_adoption_selection(previous, series, policy)
    signed = SignedRewardModelAdoption.model_validate_json(canonical_json_bytes(signed))
    body = signed.adoption
    if body.revision != 1:
        raise ValueError("initial reward selection requires revision one")
    retained = None if old is None else old.latest(body.cohort_sha256)
    if retained is not None:
        if retained != signed:
            raise ValueError("reward adoption already selected different signed bytes")
        return old
    selected = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=tuple(
            sorted(
                (*(() if old is None else old.adoptions), signed),
                key=lambda value: (value.adoption.cohort_sha256, value.adoption.revision),
            )
        ),
        maximum_decisions=1024 if old is None else old.maximum_decisions,
    )
    verify_adoption_selection(selected, series, policy)
    return selected


def verify_reward_adoption(
    selection,
    sha,
    *,
    series,
    policy,
    activation=None,
    package=None,
    current_block=None,
    include_effective_allocation=False,
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
    effective = None if package is None else derive_adopted_reward_allocation(package, body, policy)
    if effective is not None and digest(effective) != body.effective_allocation_sha256:
        raise ValueError("reward adoption differs from deterministic effective allocation")
    if include_effective_allocation:
        if effective is None:
            raise ValueError("effective reward allocation requires the original package")
        return body, effective
    return body


def derive_adopted_reward_allocation(package, adoption, policy):
    """One allocation derivation for reviewer, coordinator and publisher."""
    if adoption.signed_score_correction is None:
        return derive_effective_reward_allocation(package, adoption.parameters)
    evidence = adoption.score_correction_evidence
    return verify_signed_score_correction(
        adoption.signed_score_correction,
        evidence=evidence,
        original=package.allocation,
        service=package.service,
        original_package_bytes_sha256=evidence.original_package_bytes_sha256,
        original_package_sha256=verified_package_digest(package),
        authority_sha256=adoption.authority_sha256,
        policy=policy,
        current_block=adoption.issued_at_block,
    )


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
