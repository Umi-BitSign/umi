"""Immutable host selection for private, independently verified phase votes."""

from pathlib import Path
from typing import Annotated, Literal

import httpx
from pydantic import Field, model_serializer, model_validator

from .competition_chain import CompetitionChainConfig
from .competition_cohort_admission_journal import CohortAdmissionSignerConfig
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_progress_signer import CohortProgressSignerConfig
from .competition_cohort_recovery import verify_recovery_authority
from .competition_cohort_service_review import ServiceReviewConfig
from .competition_host_activation import _read_root_control_path
from .competition_reward_boot import _disjoint
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import RewardManifest, verify_reward_manifest
from .open_competition import CompetitionPolicy, Hotkey, Track, digest, identity
from .private_files import Directory, private_path
from .protocol import StrictProtocolModel, canonical_json_bytes


class PhaseReviewServiceConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-cohort-phase-review-service/1",
        "umi-cohort-phase-review-service/2",
        "umi-cohort-phase-review-service/3",
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
    eligible_tracks: Annotated[tuple[Track, ...], Field(min_length=1, max_length=2)]
    listen_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1024, le=65535)]
    maximum_export_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**2)] = 64 * 1024**2
    maximum_promotion_bytes: Annotated[int, Field(ge=1, le=16 * 1024**2)] = 16 * 1024**2
    maximum_sample_gap_blocks: Annotated[int, Field(ge=1, le=300)] = 10
    review_timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 1200
    service_signing: ServiceReviewConfig | None = None
    admission_signing: CohortAdmissionSignerConfig | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        if self.service_signing is None:
            value.pop("service_signing", None)
        if self.admission_signing is None:
            value.pop("admission_signing", None)
        return value

    def stores(self) -> tuple[Path, ...]:
        return tuple(
            Path(p)
            for p in (
                self.chain.state_directory,
                self.signing.directory,
                self.inputs_directory,
                self.promotion_directory,
                self.proof_import_directory,
                *((self.service_signing.directory,) if self.service_signing else ()),
                *((self.admission_signing.directory,) if self.admission_signing else ()),
            )
        )

    @model_validator(mode="after")
    def selection(self):
        if self.schema_ != "umi-cohort-phase-review-service/3" and (
            (self.schema_ == "umi-cohort-phase-review-service/2")
            != (self.service_signing is not None)
        ):
            raise ValueError("service review signing requires version two host configuration")
        if (self.schema_ == "umi-cohort-phase-review-service/3") != (
            self.admission_signing is not None
        ):
            raise ValueError("admission signing requires version three host configuration")
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
        admission = self.admission_signing
        if admission is not None and (
            admission.cohorts != expected
            or admission.policy_sha256 != digest(self.policy)
            or identity(admission.signer) != identity(self.signing.signer)
        ):
            raise ValueError("admission review changes host signer or scope")
        service = self.service_signing
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
        url = httpx.URL(self.owner_origin)
        if (
            url.scheme != "https"
            or not url.host
            or url.userinfo
            or url.query
            or url.fragment
            or url.path not in ("", "/")
        ):
            raise ValueError("phase review owner must be an explicit HTTPS origin")
        secrets = tuple(
            Path(p) for p in (self.signer_key_file, self.owner_token_file, self.vote_token_file)
        )
        _disjoint((*self.stores(), *secrets))
        return self


def load_phase_review_config(path: Path) -> PhaseReviewServiceConfig:
    raw = _read_root_control_path(path, 8 * 1024**2, modes={0o444})
    value = PhaseReviewServiceConfig.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("phase review configuration must be canonical")
    return value
