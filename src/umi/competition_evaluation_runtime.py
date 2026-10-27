"""Explicit prospective process-capacity amendment for cohort CPU execution.

The original policy and already certified execution bytes remain unchanged.
Only a recovery-quorum signature can select the 256-PID runtime for a future
prepared round. CPU, memory, image, scratch and inference budgets are identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_recovery import Block, verify_recovery_quorum
from .competition_runner import OfflineCpuRuntime
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()


class CohortEvaluationRuntimeAdoption(StrictProtocolModel):
    schema_: Literal["umi-cohort-evaluation-runtime-adoption/1"] = Field(alias="schema")
    policy_sha256: Hex32
    authority_sha256: Hex32
    cohort_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=1024)]
    first_cohort_sequence: Annotated[int, Field(ge=7, le=2**32 - 1)]
    original_runtime: OfflineCpuRuntime
    runtime: OfflineCpuRuntime
    issued_at_block: Block
    reason: Annotated[str, Field(min_length=8, max_length=1024)]

    @model_validator(mode="after")
    def exact_resource_change(self):
        if self.cohort_sha256s != tuple(sorted(set(self.cohort_sha256s))):
            raise ValueError("cohort runtime amendment scope must be sorted and unique")
        before = self.original_runtime.model_dump(mode="json", by_alias=True)
        after = self.runtime.model_dump(mode="json", by_alias=True)
        if (
            self.original_runtime.pids_limit != 128
            or self.runtime.pids_limit != 256
            or {key for key in before if before[key] != after[key]} != {"pids_limit"}
        ):
            raise ValueError("cohort runtime amendment changes more than 128 to 256 process slots")
        return self


class SignedCohortEvaluationRuntimeAdoption(StrictProtocolModel):
    adoption: CohortEvaluationRuntimeAdoption
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


@dataclass(frozen=True, slots=True)
class AuthorizedEvaluationRuntime:
    policy_sha256: str
    original_runtime_sha256: str
    runtime: OfflineCpuRuntime
    adoption_sha256: str
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value):
    return digest(
        [
            value.policy_sha256,
            value.original_runtime_sha256,
            digest(value.runtime),
            value.adoption_sha256,
        ]
    )


@lru_cache(maxsize=64)
def _verified_profile(raw, raw_policy):
    """Bounded metadata-only signature reuse, keyed by every signed input byte."""
    signed = SignedCohortEvaluationRuntimeAdoption.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(raw_policy)
    if (
        signed.adoption.policy_sha256 != digest(policy)
        or digest(signed.adoption.original_runtime) != policy.evaluation_runtime_sha256
    ):
        raise ValueError("cohort runtime amendment differs from its signed policy")
    verify_recovery_quorum(signed.adoption, signed.signatures, policy)


def verify_runtime_adoption_selection(adoption, *, policy, authority):
    """Fail configured scope/signatures at startup, before intake can be closed."""
    if adoption is None:
        return
    signed = SignedCohortEvaluationRuntimeAdoption.model_validate_json(
        canonical_json_bytes(adoption)
    )
    body = signed.adoption
    if (
        authority.policy_sha256 != digest(policy)
        or body.authority_sha256 != digest(authority)
        or body.cohort_sha256s != authority.cohort_sha256s
        or body.issued_at_block < authority.issued_at_block
    ):
        raise ValueError("cohort runtime amendment differs from configured authority")
    _verified_profile(canonical_json_bytes(signed), canonical_json_bytes(policy))


def authorize_evaluation_runtime(adoption, *, policy, authority, plan, current_block):
    if adoption is None:
        return None
    signed = SignedCohortEvaluationRuntimeAdoption.model_validate_json(
        canonical_json_bytes(adoption)
    )
    body = signed.adoption
    if (
        body.policy_sha256 != digest(policy)
        or authority.policy_sha256 != digest(policy)
        or body.authority_sha256 != digest(authority)
        or body.cohort_sha256s != authority.cohort_sha256s
        or digest(plan) not in authority.cohort_sha256s
        or plan.sequence < body.first_cohort_sequence
        or digest(body.original_runtime) != policy.evaluation_runtime_sha256
        or not authority.issued_at_block <= body.issued_at_block <= current_block
    ):
        raise ValueError("cohort runtime amendment differs from its policy, authority or phase")
    _verified_profile(canonical_json_bytes(signed), canonical_json_bytes(policy))
    result = AuthorizedEvaluationRuntime(
        digest(policy), policy.evaluation_runtime_sha256, body.runtime, digest(body), _ISSUER
    )
    object.__setattr__(result, "_binding", _binding(result))
    return result


def prepared_runtime_authorization(round_, policy):
    """Authenticate only the resource amendment, never permission to execute.

    The order/preparation consumer separately authenticates the original cohort
    authority and certified round. Embedded signed scope lets sandbox and retained
    output readers enforce the same limit without loading full chain history.
    """
    signed = round_.runtime_adoption
    if signed is None:
        validate_evaluation_runtime_authorization(
            None, policy=policy, runtime_sha256=round_.runtime_sha256
        )
        return None
    signed = SignedCohortEvaluationRuntimeAdoption.model_validate_json(canonical_json_bytes(signed))
    body = signed.adoption
    if (
        body.policy_sha256 != digest(policy)
        or round_.policy_sha256 != digest(policy)
        or round_.cohort_sha256 not in body.cohort_sha256s
        or round_.sequence < body.first_cohort_sequence
        or body.issued_at_block > round_.prepared_at_block
        or digest(body.original_runtime) != policy.evaluation_runtime_sha256
        or digest(body.runtime) != round_.runtime_sha256
    ):
        raise ValueError("prepared runtime amendment differs from its signed cohort scope")
    _verified_profile(canonical_json_bytes(signed), canonical_json_bytes(policy))
    result = AuthorizedEvaluationRuntime(
        digest(policy), policy.evaluation_runtime_sha256, body.runtime, digest(body), _ISSUER
    )
    object.__setattr__(result, "_binding", _binding(result))
    return result


def validate_evaluation_runtime_authorization(value, *, policy, runtime_sha256):
    """Low-level native boundary; plain digests and serialized booleans cannot opt in."""
    if value is None:
        if runtime_sha256 != policy.evaluation_runtime_sha256:
            raise ValueError("execution runtime differs from the original signed policy")
        return None
    if (
        type(value) is not AuthorizedEvaluationRuntime
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.policy_sha256 != digest(policy)
        or value.original_runtime_sha256 != policy.evaluation_runtime_sha256
        or digest(value.runtime) != runtime_sha256
    ):
        raise ValueError("execution runtime lacks its native quorum authorization")
    return value.runtime


def round_runtime_authorization(round_, policy, history):
    result = authorize_evaluation_runtime(
        round_.runtime_adoption,
        policy=policy,
        authority=history.authority.authority,
        plan=history.plan,
        current_block=round_.prepared_at_block,
    )
    validate_evaluation_runtime_authorization(
        result, policy=policy, runtime_sha256=round_.runtime_sha256
    )
    return result
