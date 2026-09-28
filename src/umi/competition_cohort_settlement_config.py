"""Host-selected configuration for recurring native cohort settlement."""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_cohort_execution_journal import CohortExecutionConfig
from .competition_cohort_recovery import verify_recovery_authority
from .competition_host_activation import _read_root_control_path
from .competition_reward_boot import ObjectCapacity, _disjoint
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import (
    StandingRewardManifest,
    StandingRewardOpportunityManifest,
    verify_reward_manifest,
)
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes


class SettlementServiceConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-settlement-config/1"] = Field(alias="schema")
    role: Literal["coordinator", "reviewer"]
    series: StandingRewardSeries
    policy: CompetitionPolicy
    manifest: StandingRewardManifest | StandingRewardOpportunityManifest
    chain: CompetitionChainConfig
    signer_hotkey: Hotkey
    proposer_hotkey: Hotkey
    signer_key_file: Directory
    executions: Annotated[tuple[CohortExecutionConfig, ...], Field(min_length=1, max_length=512)]
    state_directory: Directory
    inputs_directory: Directory
    history_directory: Directory
    promotion_directory: Directory
    settlement_directory: Directory
    proof_import_directory: Directory
    proof_export_directory: Directory
    exchange_inbox: Directory
    exchange_outbox: Directory
    maximum_package_bytes: ObjectCapacity
    maximum_promotion_bytes: ObjectCapacity
    maximum_state_bytes: Annotated[int, Field(ge=1024 * 1024, le=16 * 1024**3)]
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    signing_timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 300

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.state_directory,
                self.chain.state_directory,
                self.inputs_directory,
                self.history_directory,
                self.promotion_directory,
                self.settlement_directory,
                self.proof_import_directory,
                self.proof_export_directory,
                self.exchange_inbox,
                self.exchange_outbox,
                *(e.directory for e in self.executions),
            )
        )

    @model_validator(mode="after")
    def bindings(self):
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, self.policy)
        verify_recovery_authority(self.series.recovery, self.policy)
        groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        who, proposer = identity(self.signer_hotkey), identity(self.proposer_hotkey)
        cohorts = {digest(p) for p in self.series.cohorts}
        if (
            who not in groups
            or proposer not in groups
            or (who == proposer) != (self.role == "coordinator")
            or self.chain.policy_sha256 != digest(self.policy)
            or len(self.chain.proof_rpc_fallback_urls) != 2
            or any(
                identity(e.signer) != who
                or e.policy_sha256 != digest(self.policy)
                or any(
                    c.cohort_sha256 not in cohorts
                    or c.authority_sha256 != digest(self.series.recovery.authority)
                    for c in e.cohorts
                )
                for e in self.executions
            )
        ):
            raise ValueError("settlement service changes its selected role or authority")
        _disjoint(self.stores())
        key = Path(self.signer_key_file)
        if any(key.is_relative_to(root) or root.is_relative_to(key) for root in self.stores()):
            raise ValueError("settlement key must be outside mutable and replicated stores")
        return self


def load_settlement_service_config(path: Path) -> SettlementServiceConfig:
    raw = _read_root_control_path(path, 8 * 1024**2, modes={0o444})
    config = SettlementServiceConfig.model_validate_json(raw)
    if canonical_json_bytes(config) != raw:
        raise ValueError("settlement service configuration is not canonical")
    return config
