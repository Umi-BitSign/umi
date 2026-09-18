"""Versioned open-competition contracts and deterministic no-weight replay.

This module has no network, wallet loading, model execution or chain submission
capability. Signatures authenticate claims; callers still need verified chain
snapshots, protected evaluation data and independently executed inference.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from fractions import Fraction
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, Field, field_validator, model_serializer, model_validator
from typing_extensions import Self

from .competition_dependence import (
    DependenceCaseProfile,
    DependenceReport,
    MatchedSwapPair,
    matched_swap_report,
    validate_matched_swap_pairs,
)
from .competition_launch import PublicRoundSchedule
from .competition_scoring import score_single_reference
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .protocol import (
    BlockHash,
    Hex32,
    ReferenceText,
    StrictProtocolModel,
    canonical_json_bytes,
)
from .scoring import STRATUM_WEIGHTS, score_cer, score_wer

Block = Annotated[int, Field(ge=0, le=2**53 - 1)]
Bps = Annotated[int, Field(ge=0, le=10_000)]
Stratum = Literal["fingerspelling", "short_utterance", "continuous"]
Track = Literal["endpoint", "model"]
TWO_TASK_POLICY_SCHEMA = "umi-open-competition-policy/2"
BURN_POLICY_SCHEMA = "umi-open-competition-policy/3"
DEPENDENCE_POLICY_SCHEMA = "umi-open-competition-policy/4"
TWO_TASK_SUITE_SCHEMA = "umi-competition-suite/2"
DEPENDENCE_SUITE_SCHEMA = "umi-competition-suite/3"
TWO_TASK_WEIGHTS = MappingProxyType(
    {"fingerspelling": Fraction(3, 13), "continuous": Fraction(10, 13)}
)


def _hotkey(value: str) -> str:
    account_id32(value)
    return value


Hotkey = Annotated[str, Field(min_length=46, max_length=64), AfterValidator(_hotkey)]


def identity(hotkey: str) -> str:
    return account_id32(hotkey).hex()


def digest(value: StrictProtocolModel) -> str:
    """Bind object type, network and all fields through the canonical body."""
    return hashlib.sha256(b"umi-open-competition-v1\0" + canonical_json_bytes(value)).hexdigest()


class Evaluator(StrictProtocolModel):
    hotkey: Hotkey
    control_group: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]


class BurnDestination(StrictProtocolModel):
    """Registered subnet-owner hotkey whose miner incentive is burned by Subtensor."""

    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: Hotkey
    mode: Literal["Burn"] = "Burn"


class CompetitionPolicy(StrictProtocolModel):
    schema_: Literal[
        "umi-open-competition-policy/1",
        "umi-open-competition-policy/2",
        "umi-open-competition-policy/3",
        "umi-open-competition-policy/4",
    ] = Field(alias="schema")
    network: Literal["finney"]
    netuid: Literal[78]
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    predecessor_sha256: Hex32 | None
    valid_from_block: Block
    valid_through_block: Block
    endpoint_reward_bps: Bps
    model_reward_bps: Bps
    minimum_score_bps: Annotated[int, Field(ge=1, le=10_000)]
    promotion_margin_bps: Annotated[int, Field(ge=1, le=10_000)]
    minimum_cases_per_stratum: Annotated[int, Field(ge=1, le=512)]
    maximum_inference_ms: Annotated[int, Field(ge=1, le=3_600_000)]
    maximum_output_bytes: Annotated[int, Field(ge=1, le=4096)]
    maximum_bundle_bytes: Annotated[int, Field(ge=1, le=1024**4)]
    maximum_bundle_files: Annotated[int, Field(ge=7, le=4096)]
    minimum_submission_interval_blocks: Annotated[int, Field(ge=1, le=100_000)]
    maximum_submission_lifetime_blocks: Annotated[int, Field(ge=1, le=1_000_000)]
    maximum_snapshot_age_blocks: Annotated[int, Field(ge=0, le=360)]
    maximum_uids: Annotated[int, Field(ge=1, le=256)]
    evaluators: Annotated[tuple[Evaluator, ...], Field(min_length=1, max_length=64)]
    required_evaluator_groups: Annotated[int, Field(ge=1, le=64)]
    contribution_terms_sha256: Hex32
    accepted_model_licenses: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    evaluation_runtime_sha256: Hex32
    unallocated_model_burn: BurnDestination | None = None
    minimum_continuous_observed_margin_bps: Annotated[int, Field(ge=1, le=10_000)] | None = None
    continuous_dependence_lower_bound_floor_bps: Bps | None = None
    minimum_continuous_dependence_pairs: Annotated[int, Field(ge=3, le=1024)] | None = None
    continuous_dependence_duration_bins: Annotated[int, Field(ge=1, le=512)] | None = None
    maximum_counterfactual_duration_delta_ms: Annotated[int, Field(ge=0, le=3_600_000)] | None = (
        None
    )
    continuous_dependence_bootstrap_replicates: Annotated[int, Field(ge=100, le=65_536)] | None = (
        None
    )
    continuous_dependence_confidence_bps: Annotated[int, Field(ge=5_000, le=9_999)] | None = None
    positive_control_model_sha256: Hex32 | None = None
    minimum_positive_control_dependence_bps: Annotated[int, Field(ge=1, le=10_000)] | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.unallocated_model_burn is None:
            value.pop("unallocated_model_burn", None)
        if self.minimum_continuous_observed_margin_bps is None:
            value.pop("minimum_continuous_observed_margin_bps", None)
        if self.continuous_dependence_lower_bound_floor_bps is None:
            value.pop("continuous_dependence_lower_bound_floor_bps", None)
        if self.minimum_continuous_dependence_pairs is None:
            value.pop("minimum_continuous_dependence_pairs", None)
        if self.continuous_dependence_duration_bins is None:
            value.pop("continuous_dependence_duration_bins", None)
        if self.maximum_counterfactual_duration_delta_ms is None:
            value.pop("maximum_counterfactual_duration_delta_ms", None)
        if self.continuous_dependence_bootstrap_replicates is None:
            value.pop("continuous_dependence_bootstrap_replicates", None)
        if self.continuous_dependence_confidence_bps is None:
            value.pop("continuous_dependence_confidence_bps", None)
        if self.positive_control_model_sha256 is None:
            value.pop("positive_control_model_sha256", None)
        if self.minimum_positive_control_dependence_bps is None:
            value.pop("minimum_positive_control_dependence_bps", None)
        return value

    @property
    def stratum_weights(self) -> Mapping[str, Fraction]:
        return (
            STRATUM_WEIGHTS if self.schema_ == "umi-open-competition-policy/1" else TWO_TASK_WEIGHTS
        )

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        burn_schemas = {BURN_POLICY_SCHEMA, DEPENDENCE_POLICY_SCHEMA}
        if (self.schema_ in burn_schemas) != (self.unallocated_model_burn is not None):
            raise ValueError("unallocated model burn requires explicit policy version 3 or 4")
        dependence_values = (
            self.minimum_continuous_observed_margin_bps,
            self.continuous_dependence_lower_bound_floor_bps,
            self.minimum_continuous_dependence_pairs,
            self.continuous_dependence_duration_bins,
            self.maximum_counterfactual_duration_delta_ms,
            self.continuous_dependence_bootstrap_replicates,
            self.continuous_dependence_confidence_bps,
            self.positive_control_model_sha256,
            self.minimum_positive_control_dependence_bps,
        )
        if (self.schema_ == DEPENDENCE_POLICY_SCHEMA) != all(
            value is not None for value in dependence_values
        ):
            raise ValueError("continuous dependence controls require policy version 4")
        if (
            self.schema_ == DEPENDENCE_POLICY_SCHEMA
            and self.continuous_dependence_lower_bound_floor_bps != 0
        ):
            raise ValueError("dependence policy version 4 requires a strictly positive lower bound")
        if self.unallocated_model_burn is not None and (
            not self.model_reward_bps or self.unallocated_model_burn.uid >= self.maximum_uids
        ):
            raise ValueError("model burn destination or allocation is outside policy bounds")
        if self.endpoint_reward_bps + self.model_reward_bps != 10_000:
            raise ValueError("reward allocations must sum to 10000 basis points")
        if self.valid_through_block <= self.valid_from_block:
            raise ValueError("policy interval is empty")
        keys = [identity(e.hotkey) for e in self.evaluators]
        if len(set(keys)) != len(keys):
            raise ValueError("evaluator identities must be unique")
        groups = {e.control_group for e in self.evaluators}
        if self.required_evaluator_groups > len(groups):
            raise ValueError("evaluator quorum exceeds independent control groups")
        if len(set(self.accepted_model_licenses)) != len(self.accepted_model_licenses):
            raise ValueError("duplicate model license")
        if any(not re.fullmatch(r"[A-Za-z0-9.+-]{1,64}", x) for x in self.accepted_model_licenses):
            raise ValueError("invalid model license identifier")
        return self


class Signature(StrictProtocolModel):
    hotkey: Hotkey
    scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


def sign_object(value: StrictProtocolModel, wallet: Any) -> Signature:
    """Sign with the caller's explicitly supplied hotkey; never open a wallet."""
    import bittensor as bt

    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme, signature = sign_response_digest(wallet, digest(value))
    return Signature(hotkey=signer.ss58_address, scheme=scheme, signature=signature)


def verify_signature(value: StrictProtocolModel, signature: Signature) -> None:
    if not verify_response_signature(
        digest(value),
        hotkey_ss58=signature.hotkey,
        scheme=signature.scheme,
        signature=signature.signature,
    ):
        raise ValueError("invalid competition signature")


class BundleFile(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=240)]
    role: Literal[
        "weights",
        "config",
        "processor",
        "inference",
        "environment",
        "license",
        "provenance",
        "dependency",
    ]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=0, le=1024**4)]

    @field_validator("path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            str(path) != value
            or path.is_absolute()
            or ".." in path.parts
            or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", p) for p in path.parts)
        ):
            raise ValueError("artifact path must be canonical and relative")
        return value


class ModelBundle(StrictProtocolModel):
    schema_: Literal["umi-model-bundle/1"] = Field(alias="schema")
    profile: Literal["offline_bundle/1"]
    parent_baseline_sha256: Hex32 | None
    license_id: Annotated[str, Field(min_length=1, max_length=64)]
    files: Annotated[tuple[BundleFile, ...], Field(min_length=7, max_length=4096)]

    @model_validator(mode="after")
    def complete_bundle(self) -> Self:
        names = [f.path for f in self.files]
        if names != sorted(names) or len({x.casefold() for x in names}) != len(names):
            raise ValueError("bundle paths must be sorted and unique including case")
        if any(
            any(str(p) in names for p in PurePosixPath(n).parents if str(p) != ".") for n in names
        ):
            raise ValueError("artifact path cannot also be a directory")
        roles = {f.role for f in self.files}
        if not {
            "weights",
            "config",
            "processor",
            "inference",
            "environment",
            "license",
            "provenance",
        }.issubset(roles):
            raise ValueError("bundle lacks a required artifact role")
        return self


def validate_bundle_policy(bundle: ModelBundle, policy: CompetitionPolicy) -> None:
    if (
        len(bundle.files) > policy.maximum_bundle_files
        or sum(f.size_bytes for f in bundle.files) > policy.maximum_bundle_bytes
    ):
        raise ValueError("bundle exceeds policy resource limits")
    if bundle.license_id not in policy.accepted_model_licenses:
        raise ValueError("model license is outside the accepted policy")


def model_content_digest(bundle: ModelBundle) -> str:
    """Ignore path, parent and licensing-only changes when detecting exact copies.

    This detects byte-identical runnable payloads, not semantic model plagiarism.
    """
    payload = sorted(
        {
            (f.role, f.sha256, f.size_bytes)
            for f in bundle.files
            if f.role not in {"license", "provenance"}
        }
    )
    return hashlib.sha256(b"umi-model-content-v1\0" + canonical_json_bytes(payload)).hexdigest()


class Submission(StrictProtocolModel):
    schema_: Literal["umi-competition-submission/1"] = Field(alias="schema")
    network: Literal["finney"]
    netuid: Literal[78]
    policy_sha256: Hex32
    hotkey: Hotkey
    track: Track
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    valid_from_block: Block
    valid_through_block: Block
    model_revision: Hex32
    endpoint_url: Annotated[str, Field(max_length=2048)] | None
    model_bundle: ModelBundle | None
    accepted_terms_sha256: Hex32

    @model_validator(mode="after")
    def validate_track(self) -> Self:
        if self.valid_through_block <= self.valid_from_block:
            raise ValueError("submission interval is empty")
        if self.track == "model":
            if self.endpoint_url is not None or self.model_bundle is None:
                raise ValueError("model submission must contain only a complete bundle")
            if self.model_revision != digest(self.model_bundle):
                raise ValueError("model revision must bind the complete bundle")
        else:
            if self.model_bundle is not None or self.endpoint_url is None:
                raise ValueError("endpoint submission must name an endpoint only")
            parsed = urlsplit(self.endpoint_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
                or parsed.query
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("endpoint must be a credential-free HTTPS origin")
            # Evaluation transport, not the registry, must enforce public-IP and
            # chain-announced serving bindings before making any connection.
            try:
                _ = parsed.port
            except ValueError as error:
                raise ValueError("invalid endpoint port") from error
        return self


class SignedSubmission(StrictProtocolModel):
    submission: Submission
    signature: Signature

    @model_validator(mode="after")
    def verify(self) -> Self:
        if identity(self.signature.hotkey) != identity(self.submission.hotkey):
            raise ValueError("submission signer does not control the named hotkey")
        verify_signature(self.submission, self.signature)
        return self


class Registration(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: Hotkey


class RegistrationSnapshot(StrictProtocolModel):
    """A caller-verified snapshot; these bytes alone are not a finality proof."""

    network: Literal["finney"]
    netuid: Literal[78]
    block: Block
    block_hash: BlockHash
    registrations: Annotated[tuple[Registration, ...], Field(max_length=256)]
    burn_destination: BurnDestination | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.burn_destination is None:
            value.pop("burn_destination", None)
        return value

    @model_validator(mode="after")
    def unique_registrations(self) -> Self:
        uids = [r.uid for r in self.registrations]
        keys = [identity(r.hotkey) for r in self.registrations]
        if len(set(uids)) != len(uids) or len(set(keys)) != len(keys):
            raise ValueError("registration snapshot has duplicate identity or UID")
        if self.burn_destination is not None and not any(
            r.uid == self.burn_destination.uid
            and identity(r.hotkey) == identity(self.burn_destination.hotkey)
            for r in self.registrations
        ):
            raise ValueError("burn destination lacks its exact registered identity")
        return self


def validate_admission(
    signed: SignedSubmission,
    policy: CompetitionPolicy,
    snapshot: RegistrationSnapshot,
    current_block: int,
) -> int:
    # Revalidate models constructed using unsafe Pydantic copy/construct helpers.
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    sub = signed.submission
    if sub.policy_sha256 != digest(policy):
        raise ValueError("submission belongs to another policy")
    if not policy.valid_from_block <= current_block <= policy.valid_through_block:
        raise ValueError("policy is not current")
    if not sub.valid_from_block <= current_block <= sub.valid_through_block:
        raise ValueError("submission is not current")
    if (
        sub.valid_from_block < policy.valid_from_block
        or sub.valid_through_block > policy.valid_through_block
        or sub.valid_through_block - sub.valid_from_block
        > policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("submission lifetime is outside the policy")
    if not 0 <= current_block - snapshot.block <= policy.maximum_snapshot_age_blocks:
        raise ValueError("registration snapshot is stale or from the future")
    if sub.accepted_terms_sha256 != policy.contribution_terms_sha256:
        raise ValueError("submission has not accepted the current terms")
    if sub.model_bundle is not None:
        validate_bundle_policy(sub.model_bundle, policy)
    matches = [r.uid for r in snapshot.registrations if identity(r.hotkey) == identity(sub.hotkey)]
    if len(matches) != 1 or matches[0] >= policy.maximum_uids:
        raise ValueError("hotkey is not registered in this policy's UID range")
    return matches[0]


class EvaluationCase(StrictProtocolModel):
    case_id: Hex32
    video_sha256: Hex32
    stratum: Stratum
    references: Annotated[tuple[ReferenceText, ...], Field(min_length=3, max_length=5)]


class SingleReferenceEvaluationCase(EvaluationCase):
    stratum: Literal["fingerspelling", "continuous"]
    references: Annotated[tuple[ReferenceText, ...], Field(min_length=1, max_length=1)]


class DependenceEvaluationCase(SingleReferenceEvaluationCase):
    duration_ms: Annotated[int, Field(ge=1, le=3_600_000)]
    role: Literal["scored", "matched_swap"]


class EvaluationSuite(StrictProtocolModel):
    """Revealed replay input; never mount this object into a model sandbox."""

    schema_: Literal[
        "umi-competition-suite/1",
        "umi-competition-suite/2",
        "umi-competition-suite/3",
    ] = Field(alias="schema")
    policy_sha256: Hex32
    cases: Annotated[
        tuple[EvaluationCase | SingleReferenceEvaluationCase | DependenceEvaluationCase, ...],
        Field(min_length=3, max_length=2048),
    ]
    matched_swap_pairs: (
        Annotated[tuple[MatchedSwapPair, ...], Field(min_length=3, max_length=1024)] | None
    ) = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.matched_swap_pairs is None:
            value.pop("matched_swap_pairs", None)
        return value

    @model_validator(mode="after")
    def unique_cases(self) -> Self:
        if self.schema_ in {TWO_TASK_SUITE_SCHEMA, DEPENDENCE_SUITE_SCHEMA}:
            if any(len(c.references) != 1 or c.stratum not in TWO_TASK_WEIGHTS for c in self.cases):
                raise ValueError("two-task suite requires one reference and only its two strata")
        elif any(not 3 <= len(c.references) <= 5 for c in self.cases):
            raise ValueError("v1 suite requires three to five references per case")
        if self.schema_ == DEPENDENCE_SUITE_SCHEMA:
            if self.matched_swap_pairs is None or any(
                not isinstance(case, DependenceEvaluationCase) for case in self.cases
            ):
                raise ValueError("v3 suite requires duration metadata and matched-swap pairs")
        elif self.matched_swap_pairs is not None:
            raise ValueError("matched-swap pairs require suite version 3")
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("evaluation case IDs must be unique")
        if self.schema_ != DEPENDENCE_SUITE_SCHEMA and len(
            {c.video_sha256 for c in self.cases}
        ) != len(self.cases):
            raise ValueError("duplicate evaluation video")
        return self


def has_case_coverage(cases: Sequence[Any], policy: CompetitionPolicy) -> bool:
    """Check reference-free coverage without accepting extra, unscored strata."""
    scored = [case for case in cases if getattr(case, "role", "scored") == "scored"]
    return {c.stratum for c in scored} == set(policy.stratum_weights) and all(
        sum(c.stratum == stratum for c in scored) >= policy.minimum_cases_per_stratum
        for stratum in policy.stratum_weights
    )


def validate_suite_profile(suite: EvaluationSuite, policy: CompetitionPolicy) -> None:
    if policy.schema_ == DEPENDENCE_POLICY_SCHEMA:
        expected = DEPENDENCE_SUITE_SCHEMA
    elif policy.schema_ in {TWO_TASK_POLICY_SCHEMA, BURN_POLICY_SCHEMA}:
        expected = TWO_TASK_SUITE_SCHEMA
    else:
        expected = "umi-competition-suite/1"
    if suite.schema_ != expected or suite.policy_sha256 != digest(policy):
        raise ValueError("evaluation suite scoring profile or policy binding mismatch")
    if not has_case_coverage(suite.cases, policy):
        raise ValueError("insufficient evaluation coverage in a required stratum")
    if policy.schema_ == DEPENDENCE_POLICY_SCHEMA:
        if any(case.role != "scored" for case in suite.cases if case.stratum == "fingerspelling"):
            raise ValueError("fingerspelling cases cannot be matched-swap controls")
        scored_videos = [case.video_sha256 for case in suite.cases if case.role == "scored"]
        if len(set(scored_videos)) != len(scored_videos):
            raise ValueError("scored evaluation videos must be unique")
        continuous = {
            case.case_id: DependenceCaseProfile(
                role=case.role,
                video_sha256=case.video_sha256,
                duration_ms=case.duration_ms,
                reference=case.references[0],
            )
            for case in suite.cases
            if case.stratum == "continuous"
        }
        validate_matched_swap_pairs(
            profiles=continuous,
            pairs=suite.matched_swap_pairs or (),
            minimum_pairs=policy.minimum_continuous_dependence_pairs,
            duration_bin_count=policy.continuous_dependence_duration_bins,
            maximum_duration_delta_ms=policy.maximum_counterfactual_duration_delta_ms,
        )


class EvaluationRound(StrictProtocolModel):
    schema_: Literal["umi-competition-round/2"] = Field(alias="schema")
    policy_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    suite_sha256: Hex32
    incumbent_model_sha256: Hex32
    runtime_sha256: Hex32
    public_schedule: PublicRoundSchedule
    eligible_tracks: Annotated[tuple[Track, ...], Field(min_length=1, max_length=2)]
    roster: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    submission_close_block: Block
    evaluation_close_block: Block
    reveal_block: Block
    valid_through_block: Block

    @model_validator(mode="after")
    def validate_round(self) -> Self:
        schedule = self.public_schedule
        if not (
            schedule.roster_close_earliest_block
            <= self.submission_close_block
            <= schedule.roster_close_latest_block
            and self.evaluation_close_block == schedule.evaluation_close_block
            and self.reveal_block == schedule.protected_reference_reveal_block
            and self.valid_through_block == schedule.round_valid_through_block
        ):
            raise ValueError("round deadlines differ from the committed public schedule")
        if tuple(sorted(set(self.eligible_tracks))) != self.eligible_tracks:
            raise ValueError("eligible tracks must be sorted and unique")
        if list(self.roster) != sorted(set(self.roster)):
            raise ValueError("round roster must be sorted and unique")
        return self


class CaseOutput(StrictProtocolModel):
    case_id: Hex32
    status: Literal["ok", "miner_failure", "infrastructure_failure"]
    hypothesis: Annotated[str, Field(max_length=4096)]
    elapsed_ms: Annotated[int, Field(ge=0, le=86_400_000)]

    @model_validator(mode="after")
    def failures_have_no_answer(self) -> Self:
        if self.status != "ok" and self.hypothesis:
            raise ValueError("failure output must not carry a hypothesis")
        return self


class DependenceCalibration(StrictProtocolModel):
    """Known-dependent execution through the exact protected suite and runtime."""

    schema_: Literal["umi-continuous-dependence-calibration/1"] = Field(alias="schema")
    policy_sha256: Hex32
    suite_sha256: Hex32
    runtime_sha256: Hex32
    model_sha256: Hex32
    execution_evidence_sha256: Hex32
    evaluated_block: Block
    outputs: Annotated[tuple[CaseOutput, ...], Field(min_length=3, max_length=2048)]

    @model_validator(mode="after")
    def require_retained_execution_evidence(self) -> Self:
        if self.execution_evidence_sha256 == "0" * 64:
            raise ValueError("positive control requires retained execution evidence")
        return self


class AttestedDependenceCalibration(StrictProtocolModel):
    calibration: DependenceCalibration
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class EvaluationResult(StrictProtocolModel):
    schema_: Literal["umi-competition-result/1"] = Field(alias="schema")
    round_sha256: Hex32
    submission_sha256: Hex32
    model_revision: Hex32
    incumbent_model_sha256: Hex32
    runtime_sha256: Hex32
    finished_block: Block
    candidate: Annotated[tuple[CaseOutput, ...], Field(min_length=3, max_length=2048)]
    incumbent: Annotated[tuple[CaseOutput, ...], Field(min_length=3, max_length=2048)]


class AttestedResult(StrictProtocolModel):
    result: EvaluationResult
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def verify_quorum(attested: AttestedResult, policy: CompetitionPolicy) -> None:
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen_keys: set[str] = set()
    seen_groups: set[str] = set()
    for sig in attested.signatures:
        key = identity(sig.hotkey)
        if key not in groups or key in seen_keys or groups[key] in seen_groups:
            raise ValueError("duplicate or unauthorized evaluator control group")
        verify_signature(attested.result, sig)
        seen_keys.add(key)
        seen_groups.add(groups[key])
    if len(seen_groups) < policy.required_evaluator_groups:
        raise ValueError("insufficient independent evaluator agreement")


def _quality(
    outputs: tuple[CaseOutput, ...],
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    incumbent: bool = False,
) -> dict[str, Fraction]:
    validate_suite_profile(suite, policy)
    expected_ids = [c.case_id for c in suite.cases]
    if [o.case_id for o in outputs] != expected_ids:
        raise ValueError("outputs must cover the complete suite in canonical order")
    strata: dict[str, list[Fraction]] = defaultdict(list)
    valid_hypotheses: dict[str, str | None] = {}
    for case, output in zip(suite.cases, outputs, strict=True):
        if output.status == "infrastructure_failure":
            raise ValueError("infrastructure failure voids evaluation")
        valid = (
            output.status == "ok"
            and output.elapsed_ms <= policy.maximum_inference_ms
            and len(output.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes
        )
        if incumbent and not valid:
            raise ValueError("incumbent execution failed; evaluation is void")
        if case.stratum == "continuous" and policy.schema_ == DEPENDENCE_POLICY_SCHEMA:
            valid_hypotheses[case.case_id] = output.hypothesis if valid else None
        if getattr(case, "role", "scored") == "matched_swap":
            continue
        scorer = score_cer if case.stratum == "fingerspelling" else score_wer
        if not valid:
            score = Fraction(0)
        elif policy.schema_ in {
            TWO_TASK_POLICY_SCHEMA,
            BURN_POLICY_SCHEMA,
            DEPENDENCE_POLICY_SCHEMA,
        }:
            score = score_single_reference(
                "cer" if case.stratum == "fingerspelling" else "wer",
                output.hypothesis,
                case.references[0],
            )
        else:
            score = scorer(output.hypothesis, case.references)
        strata[case.stratum].append(score)
    quality = {s: sum(strata[s], Fraction(0)) / len(strata[s]) for s in policy.stratum_weights}
    if policy.schema_ == DEPENDENCE_POLICY_SCHEMA:
        profiles = {
            case.case_id: DependenceCaseProfile(
                role=case.role,
                video_sha256=case.video_sha256,
                duration_ms=case.duration_ms,
                reference=case.references[0],
            )
            for case in suite.cases
            if case.stratum == "continuous"
        }
        report = matched_swap_report(
            hypotheses=valid_hypotheses,
            profiles=profiles,
            pairs=suite.matched_swap_pairs or (),
            seed_sha256=digest(suite),
            bootstrap_replicates=policy.continuous_dependence_bootstrap_replicates,
            confidence_bps=policy.continuous_dependence_confidence_bps,
        )
        observed_minimum = Fraction(policy.minimum_continuous_observed_margin_bps, 10_000)
        lower_bound_floor = Fraction(policy.continuous_dependence_lower_bound_floor_bps, 10_000)
        if not incumbent and (
            not report.complete
            or report.observed_margin < observed_minimum
            or report.bootstrap_lower_bound <= lower_bound_floor
        ):
            return {stratum: Fraction(0) for stratum in policy.stratum_weights}
    return quality


def continuous_dependence_report(
    outputs: tuple[CaseOutput, ...], suite: EvaluationSuite, policy: CompetitionPolicy
) -> DependenceReport:
    """Replay the public matched-swap diagnostics without assigning rewards."""

    validate_suite_profile(suite, policy)
    if policy.schema_ != DEPENDENCE_POLICY_SCHEMA:
        raise ValueError("matched-swap reporting requires dependence policy version 4")
    if [output.case_id for output in outputs] != [case.case_id for case in suite.cases]:
        raise ValueError("outputs must cover the complete suite in canonical order")
    hypotheses: dict[str, str | None] = {}
    profiles: dict[str, DependenceCaseProfile] = {}
    for case, output in zip(suite.cases, outputs, strict=True):
        if case.stratum != "continuous":
            continue
        if output.status == "infrastructure_failure":
            raise ValueError("infrastructure failure voids evaluation")
        valid = (
            output.status == "ok"
            and output.elapsed_ms <= policy.maximum_inference_ms
            and len(output.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes
        )
        hypotheses[case.case_id] = output.hypothesis if valid else None
        profiles[case.case_id] = DependenceCaseProfile(
            role=case.role,
            video_sha256=case.video_sha256,
            duration_ms=case.duration_ms,
            reference=case.references[0],
        )
    return matched_swap_report(
        hypotheses=hypotheses,
        profiles=profiles,
        pairs=suite.matched_swap_pairs or (),
        seed_sha256=digest(suite),
        bootstrap_replicates=policy.continuous_dependence_bootstrap_replicates,
        confidence_bps=policy.continuous_dependence_confidence_bps,
    )


def validate_dependence_calibration(
    attested: AttestedDependenceCalibration,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    latest_block: int,
) -> DependenceReport:
    """Require a quorum-signed known-dependent run before settlement is possible."""

    attested = AttestedDependenceCalibration.model_validate_json(canonical_json_bytes(attested))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    report = validate_dependence_calibration_body(
        attested.calibration,
        suite,
        policy,
        latest_block=latest_block,
    )
    if policy.schema_ != DEPENDENCE_POLICY_SCHEMA:
        raise ValueError("positive dependence calibration requires policy version 4")
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen_keys: set[str] = set()
    seen_groups: set[str] = set()
    for signature in attested.signatures:
        key = identity(signature.hotkey)
        if key not in groups or key in seen_keys or groups[key] in seen_groups:
            raise ValueError("duplicate or unauthorized calibration control group")
        verify_signature(attested.calibration, signature)
        seen_keys.add(key)
        seen_groups.add(groups[key])
    if len(seen_groups) < policy.required_evaluator_groups:
        raise ValueError("insufficient independent calibration agreement")
    return report


def validate_dependence_calibration_body(
    calibration: DependenceCalibration,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    latest_block: int,
) -> DependenceReport:
    """Replay one unsigned body before a nominated evaluator signs it."""

    calibration = DependenceCalibration.model_validate_json(canonical_json_bytes(calibration))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if policy.schema_ != DEPENDENCE_POLICY_SCHEMA:
        raise ValueError("positive dependence calibration requires policy version 4")
    if (
        calibration.policy_sha256 != digest(policy)
        or calibration.suite_sha256 != digest(suite)
        or calibration.runtime_sha256 != policy.evaluation_runtime_sha256
        or calibration.model_sha256 != policy.positive_control_model_sha256
    ):
        raise ValueError("positive dependence calibration binding mismatch")
    if type(latest_block) is not int or not (
        policy.valid_from_block <= calibration.evaluated_block <= latest_block
    ):
        raise ValueError("positive dependence calibration block is outside its usable window")
    report = continuous_dependence_report(calibration.outputs, suite, policy)
    minimum = Fraction(policy.minimum_positive_control_dependence_bps, 10_000)
    if not report.complete or report.bootstrap_lower_bound < minimum:
        raise ValueError("positive control did not prove the dependence harness")
    return report


def aggregate_quality(
    strata: dict[str, Fraction], policy: CompetitionPolicy | None = None
) -> Fraction:
    weights = STRATUM_WEIGHTS if policy is None else policy.stratum_weights
    if set(strata) != set(weights):
        raise ValueError("quality strata do not match the scoring profile")
    return sum((strata[s] * w for s, w in weights.items()), Fraction(0))


def authenticate_evaluation(
    attested: AttestedResult,
    signed: SignedSubmission,
    round_: EvaluationRound,
    policy: CompetitionPolicy,
) -> None:
    """Authenticate historical evidence without requiring it to be payable now.

    A failed inference or expired replay window cannot erase proof of two
    contradictory statements. Current eligibility and scoring are separate.
    """
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    attested = AttestedResult.model_validate_json(canonical_json_bytes(attested))
    round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
    verify_quorum(attested, policy)
    if any(
        identity(sig.hotkey) == identity(signed.submission.hotkey) for sig in attested.signatures
    ):
        raise ValueError("a submitting hotkey cannot attest its own evaluation")
    verify_signature(signed.submission, signed.signature)
    result, sub = attested.result, signed.submission
    if (
        round_.policy_sha256 != digest(policy)
        or sub.policy_sha256 != digest(policy)
        or result.round_sha256 != digest(round_)
        or result.submission_sha256 != digest(sub)
        or digest(sub) not in round_.roster
        or result.model_revision != sub.model_revision
        or result.incumbent_model_sha256 != round_.incumbent_model_sha256
        or result.runtime_sha256 != round_.runtime_sha256
        or result.runtime_sha256 != policy.evaluation_runtime_sha256
    ):
        raise ValueError("evaluation identity, policy or runtime binding mismatch")
    if not (
        policy.valid_from_block
        <= round_.submission_close_block
        < result.finished_block
        <= round_.evaluation_close_block
        < round_.reveal_block
        <= round_.valid_through_block
        <= policy.valid_through_block
    ):
        raise ValueError("evaluation historical interval is outside its policy")
    if not (
        sub.valid_from_block <= round_.submission_close_block
        and sub.valid_through_block >= round_.evaluation_close_block
    ):
        raise ValueError("submission was not valid for the complete round")
    candidate_ids = [o.case_id for o in result.candidate]
    if len(set(candidate_ids)) != len(candidate_ids) or candidate_ids != [
        o.case_id for o in result.incumbent
    ]:
        raise ValueError("paired outputs must cover the same unique cases in order")


def validate_evaluation_suite(
    attested: AttestedResult,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
) -> None:
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    validate_suite_profile(suite, policy)
    if suite.policy_sha256 != digest(policy) or round_.suite_sha256 != digest(suite):
        raise ValueError("evaluation suite binding mismatch")
    expected = [case.case_id for case in suite.cases]
    if any(
        [output.case_id for output in outputs] != expected
        for outputs in (attested.result.candidate, attested.result.incumbent)
    ):
        raise ValueError("outputs must cover the complete suite in canonical order")


def replay_evaluation(
    attested: AttestedResult,
    signed: SignedSubmission,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    current_block: int,
) -> tuple[dict[str, Fraction], dict[str, Fraction]]:
    # Recompute scores from authenticated outputs and the committed suite.
    authenticate_evaluation(attested, signed, round_, policy)
    validate_evaluation_suite(attested, round_, suite, policy)
    if not round_.reveal_block <= current_block <= round_.valid_through_block:
        raise ValueError("evaluation is premature or expired")
    return (
        _quality(attested.result.candidate, suite, policy),
        _quality(attested.result.incumbent, suite, policy, incumbent=True),
    )


def qualifies_for_promotion(
    candidate: dict[str, Fraction],
    incumbent: dict[str, Fraction],
    policy: CompetitionPolicy,
) -> bool:
    return (
        aggregate_quality(candidate, policy) >= Fraction(policy.minimum_score_bps, 10_000)
        and aggregate_quality(candidate, policy) - aggregate_quality(incumbent, policy)
        >= Fraction(policy.promotion_margin_bps, 10_000)
        and all(candidate[s] >= incumbent[s] for s in policy.stratum_weights)
    )


class Allocation(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: Hotkey
    numerator: Annotated[str, Field(pattern=r"^[0-9]+$", max_length=4096)]
    denominator: Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=4096)]
    raw_weight: Annotated[int, Field(ge=0, le=65535)]


class WeightProjection(StrictProtocolModel):
    schema_: Literal["umi-competition-weight-projection/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    snapshot_sha256: Hex32
    allocations: tuple[Allocation, ...]
    uids: tuple[int, ...]
    weights: tuple[int, ...]
    chain_submission_authorized: Literal[False] = False


def project_weights(
    *,
    policy: CompetitionPolicy,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    evaluations: tuple[tuple[SignedSubmission, AttestedResult], ...],
    snapshot: RegistrationSnapshot,
    current_block: int,
    promoted_model_sha256: str | None,
    promoted_hotkey: str | None,
    voids: tuple = (),
) -> WeightProjection:
    """Rehearse an exact row. The caller must supply verified promotion attribution.

    This intentionally returns no signed transaction or activation authority.
    Every frozen roster member requires a scored result or a replayable void.
    """
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
    if not 0 <= current_block - snapshot.block <= policy.maximum_snapshot_age_blocks:
        raise ValueError("weight snapshot is stale or from the future")
    # Lazy imports avoid a cycle through the execution contract. An exclusion
    # is accepted only with its complete, independently signed observations.
    from .competition_void import replay_void_evidence

    excluded = []
    for evidence in voids:
        evidence = replay_void_evidence(
            evidence, suite=suite, policy=policy, current_block=current_block
        )
        if evidence.order.order.round != round_:
            raise ValueError("void projection evidence belongs to another round")
        excluded.append(evidence.order.order.submission)
    supplied = [digest(s.submission) for s, _ in evaluations] + [
        digest(s.submission) for s in excluded
    ]
    if sorted(supplied) != list(round_.roster):
        raise ValueError("weight projection requires the exact complete round roster")
    by_key = {identity(r.hotkey): r for r in snapshot.registrations if r.uid < policy.maximum_uids}
    endpoint_scores: dict[str, Fraction] = {}
    model_recipient: str | None = None
    seen: set[tuple[str, str]] = set()
    for signed in excluded:
        key = (identity(signed.submission.hotkey), signed.submission.track)
        if key in seen:
            raise ValueError("multiple submissions for the same hotkey and track")
        seen.add(key)
    for signed, attested in evaluations:
        sub = signed.submission
        key = identity(sub.hotkey)
        if (key, sub.track) in seen:
            raise ValueError("multiple submissions for the same hotkey and track")
        seen.add((key, sub.track))
        candidate, incumbent = replay_evaluation(
            attested,
            signed,
            round_,
            suite,
            policy,
            current_block=current_block,
        )
        if (
            promoted_hotkey is not None
            and identity(promoted_hotkey) in by_key
            and round_.incumbent_model_sha256 == promoted_model_sha256
            and aggregate_quality(incumbent, policy) >= Fraction(policy.minimum_score_bps, 10_000)
        ):
            # Preserved baseline inference remains possible without the original
            # contributor running a server or renewing its old upload receipt.
            model_recipient = identity(promoted_hotkey)
        if key not in by_key:
            continue  # Deregistration never transfers a score to a reused UID.
        quality = aggregate_quality(candidate, policy)
        if quality < Fraction(policy.minimum_score_bps, 10_000):
            continue
        if sub.track == "endpoint":
            endpoint_scores[key] = quality
        elif (
            sub.model_revision == promoted_model_sha256
            and promoted_hotkey is not None
            and key == identity(promoted_hotkey)
        ):
            model_recipient = key
    if policy.endpoint_reward_bps and not endpoint_scores:
        raise ValueError("endpoint allocation has no qualifying recipient")
    if policy.unallocated_model_burn is not None:
        burn_key = identity(policy.unallocated_model_burn.hotkey)
        if burn_key in endpoint_scores or (
            promoted_hotkey is not None and identity(promoted_hotkey) == burn_key
        ):
            raise ValueError("burn destination cannot receive miner or contributor rewards")
    if policy.model_reward_bps and model_recipient is None:
        destination = policy.unallocated_model_burn
        # This fallback covers an unawarded model pool only. A previously awarded
        # contributor becoming stale or deregistered retains the legacy hold.
        if destination is None or promoted_hotkey is not None:
            raise ValueError("model allocation lacks a freshly evaluated promoted contributor")
        if (
            snapshot.burn_destination != destination
            or identity(destination.hotkey) not in by_key
            or by_key[identity(destination.hotkey)].uid != destination.uid
        ):
            raise ValueError("unallocated model share lacks its verified burn destination")
        model_recipient = identity(destination.hotkey)
    amounts: dict[str, Fraction] = defaultdict(Fraction)
    total_quality = sum(endpoint_scores.values(), Fraction(0))
    for key, score in endpoint_scores.items():
        amounts[key] += Fraction(policy.endpoint_reward_bps, 10_000) * score / total_quality
    if model_recipient is not None:
        amounts[model_recipient] += Fraction(policy.model_reward_bps, 10_000)
    amounts = {k: v for k, v in amounts.items() if v > 0}
    if sum(amounts.values(), Fraction(0)) != 1:
        raise ValueError("incomplete reward allocation")
    # Largest-remainder apportionment sums to exactly 65535; ties use UID.
    raw = {k: int(v * 65535) for k, v in amounts.items()}
    remaining = 65535 - sum(raw.values())
    order = sorted(amounts, key=lambda k: (-(amounts[k] * 65535 - raw[k]), by_key[k].uid))
    for key in order[:remaining]:
        raw[key] += 1
    allocations = tuple(
        Allocation(
            uid=by_key[k].uid,
            hotkey=by_key[k].hotkey,
            numerator=str(amounts[k].numerator),
            denominator=str(amounts[k].denominator),
            raw_weight=raw[k],
        )
        for k in sorted(amounts, key=lambda k: by_key[k].uid)
    )
    row = dict((a.uid, a.raw_weight) for a in allocations)
    return WeightProjection(
        schema="umi-competition-weight-projection/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        snapshot_sha256=digest(snapshot),
        allocations=allocations,
        uids=tuple(range(policy.maximum_uids)),
        weights=tuple(row.get(uid, 0) for uid in range(policy.maximum_uids)),
    )
