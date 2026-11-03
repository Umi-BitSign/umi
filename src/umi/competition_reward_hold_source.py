"""Read hold authority from owner-selected config bytes without opening its stores.

The mirror publisher/startup owner validates the complete service configuration.
A reward reviewer needs its full series, policy, manifest, intake authority and
hold set, but has neither permission nor reason to traverse another owner's
private storage paths. This view is never a runnable service configuration.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal, get_args

from pydantic import Field, model_validator

from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_lifecycle_host import LifecycleHostConfig
from .competition_cohort_recovery import verify_recovery_authority
from .competition_cohort_service_host import ServiceAdmissionHostConfig
from .competition_cohort_settlement_config import SettlementServiceConfig
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import RewardManifest, verify_reward_manifest
from .competition_service import CompetitionServiceConfig
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

Bindings = Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]


class _ExecutionAuthority(StrictProtocolModel):
    signer: Hotkey
    policy_sha256: Hex32
    cohorts: Bindings


class RewardHoldSource(StrictProtocolModel):
    role: Literal["admission", "settlement"]
    series: StandingRewardSeries
    manifest: RewardManifest
    policy_sha256: Hex32
    chain_policy_sha256: Hex32
    policy: CompetitionPolicy | None = None
    signer_hotkey: Hotkey | None = None
    proposer_hotkey: Hotkey | None = None
    intake: Bindings | None = None
    lifecycle_intake: Bindings | None = None
    executions: (
        Annotated[tuple[_ExecutionAuthority, ...], Field(min_length=1, max_length=512)] | None
    ) = None
    holds: Annotated[tuple[Hex32, ...], Field(max_length=512)] = ()

    @model_validator(mode="after")
    def bindings(self):
        cohorts = {digest(plan) for plan in self.series.cohorts}
        if (
            self.policy_sha256 != self.series.policy_sha256
            or self.chain_policy_sha256 != self.policy_sha256
            or len(self.holds) != len(set(self.holds))
            or not set(self.holds) <= cohorts
        ):
            raise ValueError("hold source changed its selected policy or configured hold cohorts")
        for entries in (self.intake, self.lifecycle_intake):
            if entries is not None:
                keys = tuple(entry.cohort_sha256 for entry in entries)
                if keys != tuple(sorted(set(keys))):
                    raise ValueError("hold source intake bindings must be unique and sorted")
        if self.role == "admission" and (
            self.intake is None or self.lifecycle_intake is None or self.policy is not None
        ):
            raise ValueError("admission hold source lacks both intake authorities")
        if self.role == "settlement" and (
            self.policy is None
            or digest(self.policy) != self.policy_sha256
            or self.signer_hotkey is None
            or self.proposer_hotkey is None
            or identity(self.signer_hotkey) != identity(self.proposer_hotkey)
            or identity(self.signer_hotkey)
            not in {identity(e.hotkey) for e in self.policy.evaluators}
            or self.executions is None
        ):
            raise ValueError("settlement hold source changed its coordinator authority")
        if self.role == "settlement":
            authority = digest(self.series.recovery.authority)
            if (
                self.intake is not None
                and (
                    {entry.cohort_sha256 for entry in self.intake} != cohorts
                    or any(entry.authority_sha256 != authority for entry in self.intake)
                )
            ) or any(
                identity(execution.signer) != identity(self.signer_hotkey)
                or execution.policy_sha256 != self.policy_sha256
                or any(
                    entry.cohort_sha256 not in cohorts or entry.authority_sha256 != authority
                    for entry in execution.cohorts
                )
                for execution in self.executions
            ):
                raise ValueError("settlement hold source changed its intake or execution authority")
        return self

    def verify(self, policy):
        if digest(policy) != self.policy_sha256:
            raise ValueError("hold source differs from selected reward policy")
        verify_recovery_authority(self.series.recovery, policy)
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, policy)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("hold source contains a duplicate JSON field")
        result[key] = value
    return result


def _mapping(value):
    if not isinstance(value, dict):
        raise ValueError("hold source lacks its selected owner configuration")
    return value


def _schema(value, model):
    # Share the supported wire versions with the actual startup reader without
    # instantiating its Directory validators or any storage-dependent config.
    if value.get("schema") not in get_args(model.model_fields["schema_"].annotation):
        raise ValueError("hold source has an unsupported owner configuration schema")


def parse_reward_hold_source(raw: bytes, role: Literal["admission", "settlement"]):
    value = _mapping(json.loads(raw, object_pairs_hook=_object))
    chain = _mapping(value.get("chain"))
    if role == "admission":
        _schema(value, CompetitionServiceConfig)
        if (
            value.get("mode") != "intake_no_weight"
            or value["schema"] != "umi-competition-service-config/3"
        ):
            raise ValueError("hold source is not the selected service-work admission owner")
        service = _mapping(value.get("recoverable_service"))
        lifecycle = _mapping(service.get("lifecycle"))
        _schema(service, ServiceAdmissionHostConfig)
        _schema(lifecycle, LifecycleHostConfig)
        intake = _mapping(value.get("recoverable_intake"))
        sources = _mapping(lifecycle.get("sources"))
        lifecycle_intake = _mapping(sources.get("intake"))
        projected = dict(
            role=role,
            series=service.get("series"),
            manifest=service.get("manifest"),
            policy_sha256=value.get("policy_sha256"),
            chain_policy_sha256=chain.get("policy_sha256"),
            intake=intake.get("cohorts"),
            lifecycle_intake=lifecycle_intake.get("cohorts"),
            holds=lifecycle.get("automatic_progression_hold_cohorts", []),
        )
    elif role == "settlement":
        _schema(value, SettlementServiceConfig)
        if value.get("role") != "coordinator" or canonical_json_bytes(value) != raw:
            raise ValueError("hold source is not the canonical selected settlement coordinator")
        policy = value.get("policy")
        executions = value.get("executions")
        if not isinstance(executions, list):
            raise ValueError("settlement hold source lacks its execution authorities")
        sources = value.get("original_sources")
        intake = (
            None if sources is None else _mapping(_mapping(sources).get("intake")).get("cohorts")
        )
        projected = dict(
            role=role,
            series=value.get("series"),
            manifest=value.get("manifest"),
            policy_sha256=digest(policy),
            chain_policy_sha256=chain.get("policy_sha256"),
            policy=policy,
            signer_hotkey=value.get("signer_hotkey"),
            proposer_hotkey=value.get("proposer_hotkey"),
            intake=intake,
            executions=[
                {
                    key: _mapping(execution).get(key)
                    for key in ("signer", "policy_sha256", "cohorts")
                }
                for execution in executions
            ],
            holds=value.get("automatic_progression_hold_cohorts", []),
        )
    else:
        raise ValueError("unsupported reward hold source role")
    return RewardHoldSource.model_validate_json(canonical_json_bytes(projected))
