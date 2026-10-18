"""Explicit local bindings for the owned automatic reference publisher."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, model_serializer, model_validator

from .competition_chain_resources import CompetitionChainResources
from .competition_cohort_reward_allocation import CohortRewardAllocation
from .competition_reward_control import FinalizedRewardControlProvider
from .competition_reward_coordinator_boot import load_reward_coordinator_config
from .competition_reward_decisions import StandingRewardControlReader
from .open_competition import digest
from .private_files import Directory, _read_private_bytes, private_path
from .protocol import Hex32, StrictProtocolModel
from .r2_evidence import R2EvidenceClient
from .r2_sigv4 import R2Credentials, R2SigV4
from .translation_reference_channel import TranslationReferenceChannelPublisher, channel_page_key
from .translation_reference_channel_store import R2ReferenceChannelStore
from .translation_reference_gateway import (
    REFERENCE_GATEWAY_R2_ENDPOINT,
    R2ReferenceGatewayClient,
    validate_gateway_origin,
)
from .translation_reference_publication import TranslationReferenceApprovalPublisher
from .translation_reference_service import TranslationReferencePublisherService
from .validator_supervisor import (
    COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
)


class ReferenceChannelSelection(StrictProtocolModel):
    config: ValidatorSupervisorConfig
    release: SupervisorReleaseTarget


class ReferencePublisherCredentials(StrictProtocolModel):
    access_key_id: str
    secret_access_key: str = Field(repr=False)


class ReferenceGatewayCredentials(StrictProtocolModel):
    token: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", repr=False)]


class ReferencePublisherConfig(StrictProtocolModel):
    schema_: Literal["umi-reference-publisher-config/1", "umi-reference-publisher-config/2"] = (
        Field(alias="schema")
    )
    coordinator_config: Directory
    state_directory: Directory
    resources: CompetitionChainResources
    maximum_cache_bytes: Annotated[int, Field(ge=64 * 1024**2, le=16 * 1024**3)]
    maximum_journal_bytes: Annotated[int, Field(ge=1024**2, le=1024**3)]
    credentials_file: Directory
    endpoint: str
    bucket: str
    gateway_origin: str | None = None
    wallet_path: Directory
    wallet_name: Annotated[str, Field(min_length=1, max_length=256)]
    wallet_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    reference_hotkey: str
    channels: Annotated[list[ReferenceChannelSelection], Field(min_length=1, max_length=2)]
    allocations: dict[Hex32, Directory]
    horizons: dict[Hex32, Annotated[int, Field(ge=1, le=2**53 - 1)]]
    poll_seconds: Annotated[int, Field(ge=1, le=3600)] = 30

    @model_serializer(mode="wrap")
    def preserve_s3_configuration(self, handler):
        value = handler(self)
        if self.gateway_origin is None:
            value.pop("gateway_origin", None)
        return value

    @model_validator(mode="after")
    def local_bindings(self):
        root = Path(self.state_directory)
        if Path(self.resources.state_directory) != root / "proofs":
            raise ValueError("reference proofs must use the publication owner's private root")
        if len({c.config.channel_id for c in self.channels}) != len(self.channels):
            raise ValueError("reference publisher has duplicate channels")
        for channel in self.channels:
            config, release = channel.config, channel.release
            if (
                config.signature_threshold != 1
                or len(config.trusted_authorities) != 1
                or config.trusted_authorities[0].hotkey != COMMON_SUPERVISOR_AUTHORITY_HOTKEY
                or release.release_authority_hotkey != COMMON_SUPERVISOR_AUTHORITY_HOTKEY
                or release.target_platform != config.target_platform
                or release.entrypoint_profile != "umi-translation-validator/1"
            ):
                raise ValueError("reference channel differs from the common authority/profile")
        # Validate the account endpoint/bucket without opening credentials.
        R2SigV4(self.endpoint, self.bucket, R2Credentials("a" * 32, "b" * 64))
        if (self.schema_ == "umi-reference-publisher-config/2") != (
            self.gateway_origin is not None
        ):
            raise ValueError(
                "reference gateway transport requires its explicit configuration version"
            )
        if self.gateway_origin is not None:
            validate_gateway_origin(self.gateway_origin)
            if (
                self.bucket != "umi-public-evidence"
                or self.endpoint != REFERENCE_GATEWAY_R2_ENDPOINT
            ):
                raise ValueError("reference gateway cannot select a different R2 binding")
        return self


def read_input(path: Path, maximum: int, *, producer_uid: int | None = None) -> bytes:
    """Stable, bounded, read-only access to original decision/allocation files."""
    private_path(str(path))
    owners = {0, os.geteuid()}
    if producer_uid is not None:
        if type(producer_uid) is not int or not 0 <= producer_uid < 2**32:
            raise ValueError("reference input producer identity is invalid")
        owners.add(producer_uid)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in owners
            or before.st_mode & 0o022
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("reference input must be an owned bounded regular file")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in fields
    ):
        raise ValueError("reference input changed during read")
    return raw


def selected_inputs(config: ReferencePublisherConfig):
    selected = load_reward_coordinator_config(Path(config.coordinator_config))
    root = Path(config.state_directory)
    protected = [
        config.coordinator_config,
        selected.state_directory,
        selected.chain.state_directory,
        selected.files_directory,
        config.wallet_path,
        config.credentials_file,
        *config.allocations.values(),
        *(
            str(value)
            for name in CompetitionChainResources.model_fields
            if name != "state_directory" and (value := getattr(config.resources, name)) is not None
        ),
    ]
    for name in protected:
        path = Path(name)
        if root == path or root in path.parents or path in root.parents:
            raise ValueError("reference state overlaps retained inputs or another owner")
    chain = selected.chain.model_copy(
        update={
            "state_directory": config.resources.state_directory,
            "maximum_cache_bytes": config.maximum_cache_bytes,
        }
    )
    config.resources.check(chain)
    if set(config.horizons) != {digest(c) for c in selected.series.cohorts} or any(
        config.horizons[digest(c)] < c.not_before_block for c in selected.series.cohorts
    ):
        raise ValueError("reference publication needs every signed cohort horizon")
    if config.reference_hotkey not in selected.series.validators:
        raise ValueError("reference is outside the selected signed standing series")
    return selected, chain


def build_reference_service(config: ReferencePublisherConfig, *, progress=None):
    selected, chain = selected_inputs(config)
    root = Path(config.state_directory)
    raw_credentials = _read_private_bytes(Path(config.credentials_file), maximum_bytes=16 * 1024)
    if config.gateway_origin is None:
        values = ReferencePublisherCredentials.model_validate_json(raw_credentials)
        client = R2EvidenceClient(
            R2SigV4(
                config.endpoint,
                config.bucket,
                R2Credentials(values.access_key_id, values.secret_access_key),
            )
        )
    else:
        gateway = ReferenceGatewayCredentials.model_validate_json(raw_credentials)
        client = R2ReferenceGatewayClient(config.gateway_origin, gateway.token)

    def signer():
        wallet = bt.Wallet(
            path=config.wallet_path, name=config.wallet_name, hotkey=config.wallet_hotkey
        )
        return bt.resolve_signer(wallet, role="hotkey")

    def decisions(sha):
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError("invalid reference decision identity")
        source = Path(selected.files_directory)
        producer = source.lstat()
        if not stat.S_ISDIR(producer.st_mode) or producer.st_mode & 0o022:
            raise ValueError("configured decision producer directory must be protected")
        # A coordinator and its publication owner normally use different
        # service accounts. The root-controlled source selection identifies the
        # producer; native commitments and signatures still authenticate bytes.
        return read_input(
            source / "decisions" / (sha + ".json"), 128 * 1024, producer_uid=producer.st_uid
        )

    def allocations(sha):
        if sha not in config.allocations:
            raise FileNotFoundError("current signed allocation has not been replicated")
        allocation = CohortRewardAllocation.model_validate_json(
            read_input(Path(config.allocations[sha]), 1024 * 1024)
        )
        if digest(allocation) != sha:
            raise ValueError("replicated allocation differs from signed selection")
        return allocation

    reader = StandingRewardControlReader(
        root / "control",
        selected.series,
        selected.policy,
        expected_series_sha256=digest(selected.series),
        expected_chain_config_sha256=digest(chain),
        maximum_bytes=config.maximum_journal_bytes,
        reward_adoptions=selected.reward_adoptions,
    )
    channels, stores = [], []
    for selection in config.channels:
        prefix = channel_page_key(selection.config, 0, None).removesuffix("0/initial.json")
        store = R2ReferenceChannelStore(client, channel_prefix=prefix)
        stores.append(store)
        channels.append(
            TranslationReferenceChannelPublisher(
                root / "channels" / selection.config.channel_id,
                config=selection.config,
                release=selection.release,
                store=store,
                signer_loader=signer,
                maximum_bytes=config.maximum_journal_bytes,
                progress=progress,
            )
        )
    approval = TranslationReferenceApprovalPublisher(
        root / "approvals",
        reader,
        reference_hotkey=config.reference_hotkey,
        signer_loader=signer,
        publish_immutable=stores[0].publish_approval,
        maximum_bytes=config.maximum_journal_bytes,
        progress=progress,
    )
    provider = FinalizedRewardControlProvider(
        chain, selected.policy, runtime_proof_reads=True, resources=config.resources
    )
    return TranslationReferencePublisherService(
        root=root,
        reader=reader,
        provider=provider,
        approval=approval,
        channels=tuple(channels),
        decisions=decisions,
        allocations=allocations,
        horizons=config.horizons,
        poll_seconds=config.poll_seconds,
        progress=progress,
    )
