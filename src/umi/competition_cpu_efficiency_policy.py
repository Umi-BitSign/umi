"""Prospective authority for CPU-efficiency measurements and reward weights.

This contract does not replace cohort consent, the evaluation suite, the CPU
runtime or permission to execute. Its runtime digest binds the actual signed
CPU and memory allowances. Existing cohorts without a contract retain their
original scoring and serialization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_recovery import Block, verify_recovery_quorum
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()


class CohortCpuEfficiencyAdoption(StrictProtocolModel):
    """A fixed measurement protocol, approved before the first prepared round."""

    schema_: Literal["umi-cohort-cpu-efficiency-adoption/1"] = Field(alias="schema")
    policy_sha256: Hex32
    authority_sha256: Hex32
    cohort_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=1024)]
    first_cohort_sequence: Annotated[int, Field(ge=8, le=2**32 - 1)]
    runtime_sha256: Hex32
    issued_at_block: Block
    reason: Annotated[str, Field(min_length=8, max_length=1024)]
    reward_rule: Literal["cold_cpu_relative_latency/1"] = "cold_cpu_relative_latency/1"
    timing_rule: Literal["cold_model_exec_to_validated_result/1"] = (
        "cold_model_exec_to_validated_result/1"
    )
    aggregation_rule: Literal["task_weighted_per_case_slowdown/1"] = (
        "task_weighted_per_case_slowdown/1"
    )
    slowdown_precision: Literal[1000000000] = 1000000000
    slowdown_rounding_rule: Literal["ceil_per_evaluator/1"] = "ceil_per_evaluator/1"
    multiplier_precision_ppm: Literal[1000000] = 1000000
    multiplier_rounding_rule: Literal["floor_integer_tenth_root/1"] = "floor_integer_tenth_root/1"
    elapsed_floor_ms: Literal[1] = 1
    measurement_semantics: Literal["umi-exclusive-cold-model-cpu-timing/1"] = (
        "umi-exclusive-cold-model-cpu-timing/1"
    )
    bundle_cache_rule: Literal["verified_bundle_pagecache_eviction/1"] = (
        "verified_bundle_pagecache_eviction/1"
    )
    partition_mode: Literal["root"] = "root"
    condition_probe_rule: Literal["parallel_sha256_4096x65536_load_balanced/1"] = (
        "parallel_sha256_4096x65536_load_balanced/1"
    )
    pressure_rule: Literal["disjoint_external_cgroup_siblings_full_pressure/1"] = (
        "disjoint_external_cgroup_siblings_full_pressure/1"
    )
    maximum_probe_variation_bps: Literal[1000] = 1000
    maximum_observer_lateness_us: Literal[100000] = 100000
    maximum_external_pressure_bps: Literal[100] = 100
    maximum_probe_boundary_gap_us: Literal[1000000] = 1000000
    maximum_pressure_snapshot_us: Literal[50000] = 50000
    maximum_external_busy_bps: Literal[100] = 100
    maximum_steal_bps: Literal[50] = 50
    maximum_snapshot_ms: Literal[50] = 50
    maximum_boundary_overhead_ms: Literal[100] = 100
    maximum_clock_disagreement_bps: Literal[100] = 100
    minimum_multiplier_ppm: Literal[850000] = 850000
    maximum_multiplier_ppm: Literal[1150000] = 1150000
    speed_power_numerator: Literal[1] = 1
    speed_power_denominator: Literal[10] = 10
    candidate_failure_rule: Literal["charge_deadline_and_forbid_model_bonus/1"] = (
        "charge_deadline_and_forbid_model_bonus/1"
    )
    reference_failure_rule: Literal["neutral_case_speed_only/1"] = "neutral_case_speed_only/1"
    invalid_timing_rule: Literal["refuse_missing_or_incomparable_measurement/1"] = (
        "refuse_missing_or_incomparable_measurement/1"
    )

    @model_validator(mode="after")
    def canonical_scope(self):
        if self.cohort_sha256s != tuple(sorted(set(self.cohort_sha256s))):
            raise ValueError("CPU efficiency cohort scope must be sorted and unique")
        return self


class SignedCohortCpuEfficiencyAdoption(StrictProtocolModel):
    adoption: CohortCpuEfficiencyAdoption
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def default_cpu_efficiency_proposal(
    *, policy, authority, runtime_sha256, reason, issued_at_block=None
):
    """Prepare the CPU contract in a new authority's existing quorum batch.

    This creates unsigned canonical content only. The caller selects the actual
    effective runtime, obtains the configured quorum, and verifies that selection
    before installation. Retained authorities, rounds and signatures are unchanged.
    """
    issued = authority.issued_at_block if issued_at_block is None else issued_at_block
    if (
        authority.policy_sha256 != digest(policy)
        or type(issued) is not int
        or not authority.issued_at_block <= issued <= policy.valid_through_block
    ):
        raise ValueError("CPU efficiency proposal differs from its authority or issuance window")
    return CohortCpuEfficiencyAdoption(
        schema="umi-cohort-cpu-efficiency-adoption/1",
        policy_sha256=digest(policy),
        authority_sha256=digest(authority),
        cohort_sha256s=authority.cohort_sha256s,
        first_cohort_sequence=8,
        runtime_sha256=runtime_sha256,
        issued_at_block=issued,
        reason=reason,
    )


def require_cpu_efficiency_for_new_round(*, sequence, eligible_tracks, adoption):
    """Fail before new C8+ model work if its prospective contract is absent.

    Retained round decoding and replay do not call this producer-only requirement.
    Signature/runtime/scope verification remains the existing authorization path;
    this presence check does not repeat it or grant measurement authority.
    """
    if (
        sequence >= 8
        and "model" in eligible_tracks
        and (adoption is None or sequence < adoption.adoption.first_cohort_sequence)
    ):
        raise ValueError(
            "cpu_efficiency_measurement_policy_missing: new C8+ model preparation "
            "and challenge start require the selected signed CPU contract"
        )


@dataclass(frozen=True, slots=True)
class AuthorizedCpuEfficiency:
    """Process-local capability; serialized flags and bare digests confer no authority."""

    policy_sha256: str
    authority_sha256: str
    cohort_sha256: str
    sequence: int
    runtime_sha256: str
    prepared_at_block: int
    adoption_sha256: str
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value):
    return digest(
        [
            value.policy_sha256,
            value.authority_sha256,
            value.cohort_sha256,
            value.sequence,
            value.runtime_sha256,
            value.prepared_at_block,
            value.adoption_sha256,
        ]
    )


def _authorized(body, *, cohort_sha256, sequence, prepared_at_block):
    value = AuthorizedCpuEfficiency(
        body.policy_sha256,
        body.authority_sha256,
        cohort_sha256,
        sequence,
        body.runtime_sha256,
        prepared_at_block,
        digest(body),
        _ISSUER,
    )
    object.__setattr__(value, "_binding", _binding(value))
    return value


@lru_cache(maxsize=64)
def _verified_contract(raw, raw_policy):
    """Reuse only the compact signature check, keyed by all authenticated bytes."""
    signed = SignedCohortCpuEfficiencyAdoption.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(raw_policy)
    if signed.adoption.policy_sha256 != digest(policy):
        raise ValueError("CPU efficiency contract differs from its signed policy")
    verify_recovery_quorum(signed.adoption, signed.signatures, policy)


def verify_cpu_efficiency_adoption_selection(adoption, *, policy, authority, runtime_sha256):
    """Check configured selection before intake closure without changing old cohorts.

    The caller derives runtime_sha256 from its separately authenticated original
    runtime or runtime adoption. A future selection may share an authority with
    C7; first_cohort_sequence prevents applying it to those historical rounds.
    """
    if adoption is None:
        return
    signed = SignedCohortCpuEfficiencyAdoption.model_validate_json(canonical_json_bytes(adoption))
    body = signed.adoption
    if (
        authority.policy_sha256 != digest(policy)
        or body.policy_sha256 != digest(policy)
        or body.authority_sha256 != digest(authority)
        or body.cohort_sha256s != authority.cohort_sha256s
        or body.runtime_sha256 != runtime_sha256
        or body.issued_at_block < authority.issued_at_block
    ):
        raise ValueError("CPU efficiency contract differs from configured authority or runtime")
    _verified_contract(canonical_json_bytes(signed), canonical_json_bytes(policy))


def authorize_cpu_efficiency(adoption, *, policy, authority, plan, runtime_sha256, current_block):
    if adoption is None:
        return None
    signed = SignedCohortCpuEfficiencyAdoption.model_validate_json(canonical_json_bytes(adoption))
    verify_cpu_efficiency_adoption_selection(
        signed, policy=policy, authority=authority, runtime_sha256=runtime_sha256
    )
    body = signed.adoption
    if (
        type(current_block) is not int
        or plan.policy_sha256 != digest(policy)
        or digest(plan) not in body.cohort_sha256s
        or plan.sequence < body.first_cohort_sequence
        or not authority.issued_at_block <= body.issued_at_block <= current_block
    ):
        raise ValueError("CPU efficiency contract differs from its cohort or preparation clock")
    return _authorized(
        body,
        cohort_sha256=digest(plan),
        sequence=plan.sequence,
        prepared_at_block=current_block,
    )


def prepared_cpu_efficiency_authorization(round_, policy):
    """Authenticate the embedded measurement contract, not execution permission.

    The outer native round consumer independently verifies its history authority
    and preparation certificate. This low-level boundary checks signed scope,
    runtime and original preparation clock before consuming timing evidence.
    """
    signed = round_.cpu_efficiency_adoption
    if signed is None:
        return None
    from .competition_evaluation_runtime import prepared_runtime_authorization

    prepared_runtime_authorization(round_, policy)
    signed = SignedCohortCpuEfficiencyAdoption.model_validate_json(canonical_json_bytes(signed))
    body = signed.adoption
    runtime_adoption = round_.runtime_adoption
    if (
        round_.policy_sha256 != digest(policy)
        or body.policy_sha256 != digest(policy)
        or round_.cohort_sha256 not in body.cohort_sha256s
        or round_.sequence < body.first_cohort_sequence
        or round_.runtime_sha256 != body.runtime_sha256
        or body.issued_at_block > round_.prepared_at_block
        or (
            runtime_adoption is not None
            and (
                body.authority_sha256 != runtime_adoption.adoption.authority_sha256
                or body.cohort_sha256s != runtime_adoption.adoption.cohort_sha256s
            )
        )
    ):
        raise ValueError("prepared CPU efficiency contract differs from its signed scope")
    _verified_contract(canonical_json_bytes(signed), canonical_json_bytes(policy))
    return _authorized(
        body,
        cohort_sha256=round_.cohort_sha256,
        sequence=round_.sequence,
        prepared_at_block=round_.prepared_at_block,
    )


def validate_cpu_efficiency_authorization(
    value,
    *,
    policy,
    runtime_sha256,
    cohort_sha256,
    sequence,
    prepared_at_block,
    adoption_sha256=None,
):
    if (
        type(value) is not AuthorizedCpuEfficiency
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.policy_sha256 != digest(policy)
        or value.runtime_sha256 != runtime_sha256
        or value.cohort_sha256 != cohort_sha256
        or value.sequence != sequence
        or sequence < 8
        or value.prepared_at_block != prepared_at_block
        or (adoption_sha256 is not None and value.adoption_sha256 != adoption_sha256)
    ):
        raise ValueError("CPU efficiency measurement lacks native cohort authorization")
    return value


def round_cpu_efficiency_authorization(round_, policy, history):
    """Bind efficiency to the same full history checked by preparation and replay."""
    if round_.cpu_efficiency_adoption is None:
        return None
    from .competition_evaluation_runtime import round_runtime_authorization

    round_runtime_authorization(round_, policy, history)
    if (
        round_.cohort_sha256 != digest(history.plan)
        or round_.sequence != history.plan.sequence
        or round_.policy_sha256 != digest(policy)
    ):
        raise ValueError("CPU efficiency round differs from its original history")
    return authorize_cpu_efficiency(
        round_.cpu_efficiency_adoption,
        policy=policy,
        authority=history.authority.authority,
        plan=history.plan,
        runtime_sha256=round_.runtime_sha256,
        current_block=round_.prepared_at_block,
    )
