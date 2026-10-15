"""Immutable host selection for private, independently verified phase votes."""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_cohort_admission_journal import CohortAdmissionSignerConfig
from .competition_cohort_benchmark_host import BenchmarkHostConfig
from .competition_cohort_capacity import (
    LEGACY_AGGREGATE_REPLAY_BYTES,
    AggregateEvidenceCapacity,
    request_evidence_bytes,
)
from .competition_cohort_direct_model_review import DirectModelReviewSourceConfig
from .competition_cohort_endpoint_host import EndpointHostConfig
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_legacy_model_selection import (
    LegacyModelStorageSelections,
    validate_legacy_model_selections,
)
from .competition_cohort_model_review import ModelReviewConfig
from .competition_cohort_model_static_review import verify_standing_review_policy
from .competition_cohort_model_transport_selection import (
    ModelDeliveryAdoptionSelections,
    requires_direct_model_review,
)
from .competition_cohort_progress_signer import CohortProgressSignerConfig
from .competition_cohort_recovery import verify_recovery_authority
from .competition_cohort_review_budget import PhaseReviewBudget, checked_budget
from .competition_cohort_review_origin import private_review_origin
from .competition_cohort_service_budget import service_execution_budget
from .competition_cohort_service_review import ServiceReviewConfig
from .competition_host_activation import _read_root_control_path
from .competition_remote_proof_store import ProofArchiveStores
from .competition_reward_boot import _disjoint
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import RewardManifest, verify_reward_manifest
from .host_memory_runtime import HostMemoryAdmissionSelection
from .open_competition import CompetitionPolicy, Hotkey, Track, digest, identity
from .private_files import Directory, private_path
from .protocol import StrictProtocolModel, canonical_json_bytes


class PhaseReviewServiceConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-cohort-phase-review-service/1",
        "umi-cohort-phase-review-service/2",
        "umi-cohort-phase-review-service/3",
        "umi-cohort-phase-review-service/4",
        "umi-cohort-phase-review-service/5",
        "umi-cohort-phase-review-service/6",
        "umi-cohort-phase-review-service/7",
    ] = Field(alias="schema")
    series: StandingRewardSeries
    policy: CompetitionPolicy
    manifest: RewardManifest
    chain: CompetitionChainConfig
    signing: CohortProgressSignerConfig
    signer_key_file: Directory
    owner_hotkey: Hotkey
    owner_origin: Annotated[str, Field(min_length=1, max_length=2048)]
    owner_token_file: Directory
    vote_token_file: Directory
    inputs_directory: Directory
    promotion_directory: Directory
    proof_import_directory: Directory
    proof_stores: ProofArchiveStores | None = None
    eligible_tracks: Annotated[tuple[Track, ...], Field(min_length=1, max_length=2)]
    listen_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1024, le=65535)]
    maximum_export_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**2)] = 64 * 1024**2
    maximum_aggregate_evidence_bytes: AggregateEvidenceCapacity | None = None
    maximum_promotion_bytes: Annotated[int, Field(ge=1, le=16 * 1024**2)] = 16 * 1024**2
    maximum_sample_gap_blocks: Annotated[int, Field(ge=1, le=300)] = 10
    review_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400
    phase_review_budget: PhaseReviewBudget | None = None
    service_signing: ServiceReviewConfig | None = None
    admission_signing: CohortAdmissionSignerConfig | None = None
    model_signing: ModelReviewConfig | None = None
    benchmark: BenchmarkHostConfig | None = None
    endpoint: EndpointHostConfig | None = None
    direct_model_review: DirectModelReviewSourceConfig | None = None
    model_delivery_adoptions: ModelDeliveryAdoptionSelections = ()
    legacy_model_storage: LegacyModelStorageSelections = ()

    host_memory_admission: HostMemoryAdmissionSelection | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        if self.proof_stores is None:
            value.pop("proof_stores", None)
        if self.host_memory_admission is None:
            value.pop("host_memory_admission", None)
        if self.phase_review_budget is None:
            value.pop("phase_review_budget", None)
        if self.maximum_aggregate_evidence_bytes is None:
            value.pop("maximum_aggregate_evidence_bytes", None)
        if self.service_signing is None:
            value.pop("service_signing", None)
        if self.admission_signing is None:
            value.pop("admission_signing", None)
        if self.model_signing is None:
            value.pop("model_signing", None)
        if self.benchmark is None:
            value.pop("benchmark", None)
        if self.endpoint is None:
            value.pop("endpoint", None)
        if self.direct_model_review is None:
            value.pop("direct_model_review", None)
        if not self.model_delivery_adoptions:
            value.pop("model_delivery_adoptions", None)
        if not self.legacy_model_storage:
            value.pop("legacy_model_storage", None)
        return value

    @property
    def request_evidence_bytes(self) -> int:
        return request_evidence_bytes(
            self.maximum_aggregate_evidence_bytes, self.maximum_export_bytes
        )

    @property
    def request_replay_bytes(self) -> int:
        return request_evidence_bytes(
            self.maximum_aggregate_evidence_bytes, LEGACY_AGGREGATE_REPLAY_BYTES
        )

    def stores(self) -> tuple[Path, ...]:
        return tuple(
            Path(p)
            for p in (
                self.chain.state_directory,
                self.signing.directory,
                self.inputs_directory,
                self.promotion_directory,
                self.proof_import_directory,
                *(source.directory for source in self.legacy_model_storage),
                *(self.proof_stores.credential_paths() if self.proof_stores else ()),
                *((self.service_signing.directory,) if self.service_signing else ()),
                *((self.admission_signing.directory,) if self.admission_signing else ()),
                *(
                    (
                        self.model_signing.directory,
                        self.model_signing.approvals_directory,
                        self.model_signing.archive_directory,
                    )
                    if self.model_signing
                    else ()
                ),
                *(
                    (
                        p
                        for p in self.endpoint.stores()
                        if self.benchmark is None
                        or p != Path(self.endpoint.clips.videos_directory)
                        or p != Path(self.benchmark.videos_directory)
                    )
                    if self.endpoint
                    else ()
                ),
                *(
                    (
                        p
                        for p in self.benchmark.stores()
                        # Artifact review and execution intentionally read the
                        # same immutable retained model archive when selected.
                        if self.model_signing is None
                        or p != Path(self.benchmark.archive_directory)
                        or p != Path(self.model_signing.archive_directory)
                    )
                    if self.benchmark
                    else ()
                ),
            )
        )

    @model_validator(mode="after")
    def selection(self):
        if self.proof_stores is not None and self.proof_stores.exported is not None:
            raise ValueError("phase reviewer accepts only an imported proof transport")
        checked_budget(
            self.phase_review_budget,
            self.policy,
            self.request_evidence_bytes,
            signing_seconds=self.signing.signing_timeout_seconds,
        )
        if self.schema_ in (
            "umi-cohort-phase-review-service/1",
            "umi-cohort-phase-review-service/2",
        ) and (
            (self.schema_ == "umi-cohort-phase-review-service/2")
            != (self.service_signing is not None)
        ):
            raise ValueError("service review signing requires version two host configuration")
        if (
            self.schema_
            in (
                "umi-cohort-phase-review-service/3",
                "umi-cohort-phase-review-service/4",
                "umi-cohort-phase-review-service/5",
                "umi-cohort-phase-review-service/6",
                "umi-cohort-phase-review-service/7",
            )
        ) != (self.admission_signing is not None):
            raise ValueError("admission signing requires version three host configuration")
        if (
            self.schema_
            in (
                "umi-cohort-phase-review-service/4",
                "umi-cohort-phase-review-service/5",
                "umi-cohort-phase-review-service/6",
                "umi-cohort-phase-review-service/7",
            )
        ) != (self.model_signing is not None):
            raise ValueError("model signing requires version four host configuration")
        if (
            self.schema_
            in (
                "umi-cohort-phase-review-service/5",
                "umi-cohort-phase-review-service/6",
                "umi-cohort-phase-review-service/7",
            )
        ) != (self.benchmark is not None):
            raise ValueError("benchmark execution requires version five host configuration")
        endpoint_selected = self.schema_ == "umi-cohort-phase-review-service/6" or (
            self.schema_ == "umi-cohort-phase-review-service/7"
            and "endpoint" in self.eligible_tracks
        )
        if endpoint_selected != (self.endpoint is not None):
            raise ValueError("endpoint execution differs from the selected host tracks")
        if (self.schema_ == "umi-cohort-phase-review-service/7") != (
            self.direct_model_review is not None
        ):
            raise ValueError("direct model review requires version seven host configuration")
        if self.endpoint is not None:
            if self.service_signing is None:
                raise ValueError("complete evaluator startup requires service review signing")
            self.endpoint.check_scope(self)
        private_path(self.chain.state_directory)
        verify_reward_manifest(canonical_json_bytes(self.manifest), self.series, self.policy)
        verify_recovery_authority(self.series.recovery, self.policy)
        expected = tuple(
            CohortIntakeBinding(
                cohort_sha256=k, authority_sha256=digest(self.series.recovery.authority)
            )
            for k in sorted(digest(p) for p in self.series.cohorts)
        )
        authorized = {identity(e.hotkey) for e in self.policy.evaluators}
        if self.benchmark is not None and (
            self.benchmark.orders.cohorts != expected
            or self.benchmark.orders.policy_sha256 != digest(self.policy)
            or identity(self.benchmark.orders.signer) != identity(self.signing.signer)
        ):
            raise ValueError("benchmark execution changes host signer or scope")
        model = self.model_signing
        if model is not None and (
            model.cohorts != expected
            or model.policy_sha256 != digest(self.policy)
            or identity(model.signer) != identity(self.signing.signer)
            or "model" not in self.eligible_tracks
        ):
            raise ValueError("model review changes host signer, tracks or scope")
        direct = self.direct_model_review
        direct_selected = requires_direct_model_review(
            self.series, self.policy, self.model_delivery_adoptions
        )
        if self.model_delivery_adoptions and model is None:
            raise ValueError("model transport adoption requires independent model signing")
        if direct_selected and direct is None and model is not None:
            raise ValueError("direct model cohort requires the independent R2 review source")
        if direct is not None:
            if model is None:
                raise ValueError("direct model review requires model signing")
            verify_standing_review_policy(direct.standing_review_policy, self.policy)
        validate_legacy_model_selections(
            self.legacy_model_storage,
            series=self.series,
            policy=self.policy,
            model_delivery_adoptions=self.model_delivery_adoptions,
        )
        if self.legacy_model_storage and (model is None or direct is None):
            raise ValueError("legacy R2 model review requires private signing and bounded reader")
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
        admission = self.admission_signing
        if admission is not None and (
            admission.cohorts != expected
            or admission.policy_sha256 != digest(self.policy)
            or identity(admission.signer) != identity(self.signing.signer)
        ):
            raise ValueError("admission review changes host signer or scope")
        service = self.service_signing
        if service is not None:
            checked_budget(
                self.phase_review_budget,
                self.policy,
                self.request_evidence_bytes,
                signing_seconds=service.signing_timeout_seconds,
            )
            service_execution_budget(
                self.phase_review_budget,
                read_seconds=service.read_timeout_seconds,
                signing_seconds=service.signing_timeout_seconds,
                vote_seconds=self.review_timeout_seconds,
            )
        if service is not None and (
            service.cohorts != expected
            or service.policy_sha256 != digest(self.policy)
            or identity(service.signer) != identity(self.signing.signer)
            or identity(service.owner) != identity(self.owner_hotkey)
        ):
            raise ValueError("service review changes host signer, owner or scope")
        if (
            self.signing.cohorts != expected
            or self.signing.policy_sha256 != digest(self.policy)
            or self.chain.policy_sha256 != digest(self.policy)
            or len(self.chain.proof_rpc_fallback_urls) != 2
            or identity(self.signing.signer) not in authorized
            or identity(self.owner_hotkey) not in authorized
            or self.eligible_tracks != tuple(sorted(set(self.eligible_tracks)))
        ):
            raise ValueError("phase review service changes its selected authority or scope")
        private_review_origin(self.owner_origin)
        secrets = tuple(
            Path(p)
            for p in (
                self.signer_key_file,
                self.owner_token_file,
                self.vote_token_file,
                *(
                    (self.direct_model_review.r2_credentials_file,)
                    if self.direct_model_review
                    else ()
                ),
            )
        )
        _disjoint((*self.stores(), *secrets))
        return self


def load_phase_review_config(path: Path) -> PhaseReviewServiceConfig:
    raw = _read_root_control_path(path, 8 * 1024**2, modes={0o444})
    value = PhaseReviewServiceConfig.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("phase review configuration must be canonical")
    return value
