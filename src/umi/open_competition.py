"""Versioned open-competition contracts and deterministic no-weight replay.

This module has no network, wallet loading, model execution or chain submission
capability. Signatures authenticate claims; callers still need verified chain
snapshots, protected evaluation data and independently executed inference.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from fractions import Fraction
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, Field, field_validator, model_validator
from typing_extensions import Self

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


class CompetitionPolicy(StrictProtocolModel):
    schema_: Literal["umi-open-competition-policy/1"] = Field(alias="schema")
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

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
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

    @model_validator(mode="after")
    def unique_registrations(self) -> Self:
        uids = [r.uid for r in self.registrations]
        keys = [identity(r.hotkey) for r in self.registrations]
        if len(set(uids)) != len(uids) or len(set(keys)) != len(keys):
            raise ValueError("registration snapshot has duplicate identity or UID")
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


class EvaluationSuite(StrictProtocolModel):
    """Revealed replay input; never mount this object into a model sandbox."""

    schema_: Literal["umi-competition-suite/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cases: Annotated[tuple[EvaluationCase, ...], Field(min_length=3, max_length=2048)]

    @model_validator(mode="after")
    def unique_cases(self) -> Self:
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("evaluation case IDs must be unique")
        if len({c.video_sha256 for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate evaluation video")
        return self


class EvaluationRound(StrictProtocolModel):
    schema_: Literal["umi-competition-round/1"] = Field(alias="schema")
    policy_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    suite_sha256: Hex32
    incumbent_model_sha256: Hex32
    runtime_sha256: Hex32
    roster: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    submission_close_block: Block
    evaluation_close_block: Block
    reveal_block: Block
    valid_through_block: Block

    @model_validator(mode="after")
    def validate_round(self) -> Self:
        if not (
            self.submission_close_block
            < self.evaluation_close_block
            < self.reveal_block
            <= self.valid_through_block
        ):
            raise ValueError("round deadlines are not ordered")
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
    expected_ids = [c.case_id for c in suite.cases]
    if [o.case_id for o in outputs] != expected_ids:
        raise ValueError("outputs must cover the complete suite in canonical order")
    strata: dict[str, list[Fraction]] = defaultdict(list)
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
        scorer = score_cer if case.stratum == "fingerspelling" else score_wer
        strata[case.stratum].append(
            scorer(output.hypothesis, case.references) if valid else Fraction(0)
        )
    if any(len(strata[s]) < policy.minimum_cases_per_stratum for s in STRATUM_WEIGHTS):
        raise ValueError("insufficient evaluation coverage in a required stratum")
    return {s: sum(strata[s], Fraction(0)) / len(strata[s]) for s in STRATUM_WEIGHTS}


def aggregate_quality(strata: dict[str, Fraction]) -> Fraction:
    return sum((strata[s] * w for s, w in STRATUM_WEIGHTS.items()), Fraction(0))


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
    if suite.policy_sha256 != digest(policy) or round_.suite_sha256 != digest(suite):
        raise ValueError("evaluation suite binding mismatch")
    expected = [case.case_id for case in suite.cases]
    if any(
        [output.case_id for output in outputs] != expected
        for outputs in (attested.result.candidate, attested.result.incumbent)
    ):
        raise ValueError("outputs must cover the complete suite in canonical order")
    if any(
        sum(case.stratum == stratum for case in suite.cases) < policy.minimum_cases_per_stratum
        for stratum in STRATUM_WEIGHTS
    ):
        raise ValueError("insufficient evaluation coverage in a required stratum")


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
        aggregate_quality(candidate) >= Fraction(policy.minimum_score_bps, 10_000)
        and aggregate_quality(candidate) - aggregate_quality(incumbent)
        >= Fraction(policy.promotion_margin_bps, 10_000)
        and all(candidate[s] >= incumbent[s] for s in STRATUM_WEIGHTS)
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
            and aggregate_quality(incumbent) >= Fraction(policy.minimum_score_bps, 10_000)
        ):
            # Preserved baseline inference remains possible without the original
            # contributor running a server or renewing its old upload receipt.
            model_recipient = identity(promoted_hotkey)
        if key not in by_key:
            continue  # Deregistration never transfers a score to a reused UID.
        quality = aggregate_quality(candidate)
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
    if policy.model_reward_bps and model_recipient is None:
        raise ValueError("model allocation lacks a freshly evaluated promoted contributor")
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
