"""Host-selected configuration for recurring native cohort settlement."""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_cohort_capacity import AggregateEvidenceCapacity
from .competition_cohort_direct_model_review import DirectModelReviewSourceConfig
from .competition_cohort_execution_journal import CohortExecutionConfig
from .competition_cohort_intake import CohortIntakeConfig
from .competition_cohort_legacy_model_selection import (
    LegacyModelStorageSelections,
    validate_legacy_model_selections,
)
from .competition_cohort_model_transport_selection import (
    ModelDeliveryAdoptionSelections,
    requires_direct_model_review,
)
from .competition_cohort_recovery import verify_recovery_authority
from .competition_host_activation import _read_root_control_path
from .competition_model_byte_store import shared_byte_store_paths, validate_shared_byte_stores
from .competition_remote_proof_store import ProofArchiveStores
from .competition_reward_boot import ObjectCapacity, _disjoint
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import (
    StandingRewardManifest,
    StandingRewardOpportunityManifest,
    verify_reward_manifest,
)
from .host_memory_runtime import HostMemoryAdmissionSelection
from .open_competition import CompetitionPolicy, Hotkey, Track, digest, identity
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class SettlementOriginalSources(StrictProtocolModel):
    intake: CohortIntakeConfig
    eligible_tracks: Annotated[tuple[Track, ...], Field(min_length=1, max_length=2)]
    round_directory: Directory
    objects_directory: Directory
    catalogs_directory: Directory
    transport_directory: Directory
    pulses_directory: Directory

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.intake.directory,
                self.round_directory,
                self.objects_directory,
                self.catalogs_directory,
                self.transport_directory,
                self.pulses_directory,
            )
        )


class SettlementServiceConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-cohort-settlement-config/1",
        "umi-cohort-settlement-config/2",
        "umi-cohort-settlement-config/3",
        "umi-cohort-settlement-config/4",
    ] = Field(alias="schema")
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
    proof_stores: ProofArchiveStores | None = None
    shared_registration_archives: Annotated[tuple[Directory, ...], Field(max_length=8)] = ()
    proof_export_directory: Directory
    exchange_inbox: Directory
    exchange_outbox: Directory
    maximum_package_bytes: AggregateEvidenceCapacity
    maximum_promotion_bytes: ObjectCapacity
    maximum_state_bytes: Annotated[int, Field(ge=1024 * 1024, le=16 * 1024**3)]
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    signing_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400
    original_sources: SettlementOriginalSources | None = None
    request_export_directory: Directory | None = None
    direct_model_review: DirectModelReviewSourceConfig | None = None
    model_delivery_adoptions: ModelDeliveryAdoptionSelections = ()
    legacy_model_storage: LegacyModelStorageSelections = ()
    automatic_progression_hold_cohorts: Annotated[tuple[Hex32, ...], Field(max_length=512)] = ()

    host_memory_admission: HostMemoryAdmissionSelection | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        if self.proof_stores is None:
            value.pop("proof_stores", None)
        if not self.shared_registration_archives:
            value.pop("shared_registration_archives", None)
        if self.host_memory_admission is None:
            value.pop("host_memory_admission", None)
        if self.original_sources is None:
            value.pop("original_sources", None)
        if self.request_export_directory is None:
            value.pop("request_export_directory", None)
        if self.direct_model_review is None:
            value.pop("direct_model_review", None)
        if not self.model_delivery_adoptions:
            value.pop("model_delivery_adoptions", None)
        if not self.legacy_model_storage:
            value.pop("legacy_model_storage", None)
        if not self.automatic_progression_hold_cohorts:
            value.pop("automatic_progression_hold_cohorts", None)
        return value

    def stores(self, *, include_shared=True):
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
                *self.shared_registration_archives,
                *(self.proof_stores.credential_paths() if self.proof_stores else ()),
                self.proof_export_directory,
                self.exchange_inbox,
                self.exchange_outbox,
                *(e.directory for e in self.executions),
                *(self.original_sources.stores() if self.original_sources else ()),
                *((self.request_export_directory,) if self.request_export_directory else ()),
                *(self.direct_model_review.stores() if self.direct_model_review else ()),
                *(source.directory for source in self.legacy_model_storage),
                *(shared_byte_store_paths(self.legacy_model_storage) if include_shared else ()),
            )
        )

    @model_validator(mode="after")
    def bindings(self):
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, self.policy)
        verify_recovery_authority(self.series.recovery, self.policy)
        groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        who, proposer = identity(self.signer_hotkey), identity(self.proposer_hotkey)
        cohorts = {digest(p) for p in self.series.cohorts}
        holds = self.automatic_progression_hold_cohorts
        if len(holds) != len(set(holds)) or not set(holds) <= cohorts:
            raise ValueError("settlement progression holds must name distinct configured cohorts")
        if len(self.shared_registration_archives) != len(set(self.shared_registration_archives)):
            raise ValueError("shared registration archives must be distinct")
        sources = self.original_sources
        if self.schema_ in {
            "umi-cohort-settlement-config/1",
            "umi-cohort-settlement-config/2",
        } and (self.schema_ == "umi-cohort-settlement-config/2") != (sources is not None):
            raise ValueError("automatic settlement sources require configuration version 2")
        if (
            self.schema_
            in {
                "umi-cohort-settlement-config/3",
                "umi-cohort-settlement-config/4",
            }
        ) != (self.request_export_directory is not None):
            raise ValueError("automatic request exports require configuration version 3")
        validate_legacy_model_selections(
            self.legacy_model_storage,
            series=self.series,
            policy=self.policy,
            model_delivery_adoptions=self.model_delivery_adoptions,
        )
        direct = self.direct_model_review
        if (
            self.legacy_model_storage
            and direct is not None
            and direct.materialization_boot_disk_cache is not None
        ):
            _disjoint(
                (
                    Path(direct.materialization_boot_disk_cache.directory),
                    *(Path(source.directory) for source in self.legacy_model_storage),
                )
            )
        direct_selected = requires_direct_model_review(
            self.series, self.policy, self.model_delivery_adoptions
        )
        if (self.schema_ == "umi-cohort-settlement-config/4") != direct_selected or (
            direct_selected != (self.direct_model_review is not None)
        ):
            raise ValueError("direct model settlement requires configuration version four")
        if sources is not None and (
            self.role != "coordinator"
            or len(set(sources.eligible_tracks)) != len(sources.eligible_tracks)
            or {c.cohort_sha256 for c in sources.intake.cohorts} != cohorts
            or any(
                c.authority_sha256 != digest(self.series.recovery.authority)
                for c in sources.intake.cohorts
            )
        ):
            raise ValueError("original settlement sources differ from coordinator authority")
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
        validate_shared_byte_stores(
            self.legacy_model_storage,
            (
                *self.stores(include_shared=False),
                *(p for p in (self.signer_key_file,) if p is not None),
                *(
                    (direct.materialization_boot_disk_cache.directory,)
                    if direct is not None and direct.materialization_boot_disk_cache is not None
                    else ()
                ),
            ),
        )
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
