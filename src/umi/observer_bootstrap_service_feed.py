"""Immutable publication of current-state-verified bootstrap service weights."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef, _read_bounded_regular_file
from .bootstrap_direct_weights import (
    DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
    DirectBootstrapCallMaterial,
    DirectBootstrapSubmissionJournal,
    DirectBootstrapSubmissionReceipt,
    DirectBootstrapTransitionAuthorization,
    OwnerFenceReceipt,
    verify_direct_transition_authorization,
)
from .bootstrap_weights import (
    U16_MAX,
    SignedBootstrapEligibilityManifest,
    verify_signed_bootstrap_eligibility_manifest,
)
from .encoding import account_id32
from .observer_pilot_feed import ObserverPilotFeed
from .protocol import PROTOCOL_VERSION, Hex32, StrictProtocolModel, canonical_json_bytes
from .simple_bootstrap_validator import (
    SignedSimpleBootstrapLease,
    verify_simple_bootstrap_lease,
)

BOOTSTRAP_SERVICE_FEED_CONFIG_SCHEMA = "umi-observer-bootstrap-service-feed-config/1"
SIMPLE_BOOTSTRAP_FEED_CONFIG_SCHEMA = "umi-observer-simple-bootstrap-feed-config/1"
BOOTSTRAP_SERVICE_PUBLICATION_SCHEMA = "umi-bootstrap-direct-publication/2"
SIMPLE_BOOTSTRAP_PUBLICATION_SCHEMA = "umi-simple-bootstrap-observer-publication/1"
BOOTSTRAP_SERVICE_MECHANISM = "bootstrap_service_binary"
MAX_BOOTSTRAP_PUBLICATIONS = 256
MAX_BOOTSTRAP_CONFIG_BYTES = 64 * 1024
MAX_BOOTSTRAP_MANIFEST_BYTES = 64 * 1024
MAX_BOOTSTRAP_OBJECT_BYTES = 32 * 1024 * 1024
MAX_BOOTSTRAP_FEED_BYTES = 128 * 1024 * 1024


class BootstrapServiceObjectRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal["application/json"]
    size_bytes: Annotated[int, Field(gt=0, le=MAX_BOOTSTRAP_OBJECT_BYTES)]


class BootstrapServicePublicationManifest(StrictProtocolModel):
    """Public index for the exact terminal evidence behind one applied row."""

    schema_: Literal[BOOTSTRAP_SERVICE_PUBLICATION_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mechanism: Literal[BOOTSTRAP_SERVICE_MECHANISM]
    service_weights_active: Literal[True]
    translation_weights_active: Literal[False]
    activation_evidence: Literal[False]
    validator_input_eligible: Literal[False]
    storage_proofs_verified: Literal[False]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    submission_id: Hex32
    policy_sha256: Hex32
    eligibility_manifest_sha256: Hex32
    weight_call_block: Annotated[int, Field(gt=0)]
    active_through_block: Annotated[int, Field(gt=0)]
    hard_sunset_block: Annotated[int, Field(gt=0)]
    expected_row_sha256: Hex32
    owner_fence_receipt: BootstrapServiceObjectRef
    signed_eligibility_manifest: BootstrapServiceObjectRef
    transition_authorization: BootstrapServiceObjectRef
    call_material: BootstrapServiceObjectRef
    submission_receipt: BootstrapServiceObjectRef
    submission_journal: BootstrapServiceObjectRef

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if not self.weight_call_block <= self.active_through_block < self.hard_sunset_block:
            raise ValueError("bootstrap publication active interval is invalid")
        references = self.object_references()
        if len({item.sha256 for item in references}) != len(references):
            raise ValueError("bootstrap publication roles must name distinct objects")
        return self

    def object_references(self) -> tuple[BootstrapServiceObjectRef, ...]:
        return (
            self.owner_fence_receipt,
            self.signed_eligibility_manifest,
            self.transition_authorization,
            self.call_material,
            self.submission_receipt,
            self.submission_journal,
        )


class SimpleBootstrapPublicationManifest(StrictProtocolModel):
    """Public, immutable inputs used to recognize a bootstrap row on chain."""

    schema_: Literal[SIMPLE_BOOTSTRAP_PUBLICATION_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mechanism: Literal[BOOTSTRAP_SERVICE_MECHANISM]
    chain_state_required: Literal[True]
    service_weights_active_claimed: Literal[False]
    translation_weights_active: Literal[False]
    activation_evidence: Literal[False]
    validator_input_eligible: Literal[False]
    storage_proofs_verified: Literal[False]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    policy_sha256: Hex32
    eligibility_manifest_sha256: Hex32
    valid_from_block: Annotated[int, Field(gt=0)]
    hard_sunset_block: Annotated[int, Field(gt=0)]
    expected_row_sha256: Hex32
    signed_eligibility_manifest: BootstrapServiceObjectRef
    signed_lease: BootstrapServiceObjectRef

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.valid_from_block >= self.hard_sunset_block:
            raise ValueError("simple bootstrap publication interval is invalid")
        if self.signed_eligibility_manifest.sha256 == self.signed_lease.sha256:
            raise ValueError("simple bootstrap publication roles must name distinct objects")
        return self

    def object_references(self) -> tuple[BootstrapServiceObjectRef, ...]:
        return (self.signed_eligibility_manifest, self.signed_lease)


class BootstrapServiceFeedConfig(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_SERVICE_FEED_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[BOOTSTRAP_SERVICE_MECHANISM]
    public_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    bundle_roots: Annotated[list[str], Field(min_length=1, max_length=MAX_BOOTSTRAP_PUBLICATIONS)]

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        _normalized_https_origin(self.public_origin)
        paths: list[Path] = []
        for raw in self.bundle_roots:
            path = Path(raw)
            if not path.is_absolute() or os.path.normpath(raw) != str(path):
                raise ValueError("bootstrap bundle roots must be normalized absolute paths")
            if len(raw.encode("utf-8")) > 4_096:
                raise ValueError("bootstrap bundle root is too long")
            paths.append(path)
        if len(paths) != len(set(paths)):
            raise ValueError("bootstrap bundle roots must be unique")
        return self


class SimpleBootstrapServiceFeedConfig(StrictProtocolModel):
    schema_: Literal[SIMPLE_BOOTSTRAP_FEED_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[BOOTSTRAP_SERVICE_MECHANISM]
    public_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    bundle_roots: Annotated[list[str], Field(max_length=MAX_BOOTSTRAP_PUBLICATIONS)]
    simple_bootstrap_signed_manifest_path: str
    simple_bootstrap_lease_path: str

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        _normalized_https_origin(self.public_origin)
        raw_paths = (
            *self.bundle_roots,
            self.simple_bootstrap_signed_manifest_path,
            self.simple_bootstrap_lease_path,
        )
        paths: list[Path] = []
        for raw in raw_paths:
            path = Path(raw)
            if not path.is_absolute() or os.path.normpath(raw) != str(path):
                raise ValueError("bootstrap evidence paths must be normalized absolute paths")
            if len(raw.encode("utf-8")) > 4_096:
                raise ValueError("bootstrap evidence path is too long")
            paths.append(path)
        if len(paths) != len(set(paths)):
            raise ValueError("bootstrap evidence paths must be unique")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedBootstrapServiceObject:
    sha256: str
    media_type: str
    data: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.data)


@dataclass(frozen=True, slots=True)
class VerifiedBootstrapServicePublication:
    publication_id: str
    public_origin: str
    manifest: BootstrapServicePublicationManifest
    manifest_bytes: bytes
    objects: Mapping[str, VerifiedBootstrapServiceObject]
    owner_fence_receipt: OwnerFenceReceipt
    signed_manifest: SignedBootstrapEligibilityManifest
    authorization: DirectBootstrapTransitionAuthorization
    call_material: DirectBootstrapCallMaterial
    receipt: DirectBootstrapSubmissionReceipt
    journal: DirectBootstrapSubmissionJournal


@dataclass(frozen=True, slots=True)
class VerifiedSimpleBootstrapConfiguration:
    publication_id: str
    public_origin: str
    manifest: SimpleBootstrapPublicationManifest
    manifest_bytes: bytes
    objects: Mapping[str, VerifiedBootstrapServiceObject]
    signed_manifest: SignedBootstrapEligibilityManifest
    signed_lease: SignedSimpleBootstrapLease
    expected_row: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class ObserverBootstrapServiceFeed:
    publications: tuple[VerifiedBootstrapServicePublication, ...]
    simple_bootstrap: VerifiedSimpleBootstrapConfiguration | None = None

    def get(
        self,
        publication_id: str,
    ) -> VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration | None:
        publication = next(
            (item for item in self.publications if item.publication_id == publication_id),
            None,
        )
        if publication is not None:
            return publication
        if (
            self.simple_bootstrap is not None
            and self.simple_bootstrap.publication_id == publication_id
        ):
            return self.simple_bootstrap
        return None

    def evidence_items(
        self,
    ) -> tuple[VerifiedBootstrapServicePublication | VerifiedSimpleBootstrapConfiguration, ...]:
        if self.simple_bootstrap is None:
            return self.publications
        return (*self.publications, self.simple_bootstrap)


@dataclass(frozen=True, slots=True)
class _VerifiedTerminalBindings:
    expected_row_sha256: str
    active_through_block: int


def _normalized_https_origin(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("bootstrap public origin contains a control character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("bootstrap public origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or not parsed.hostname.isascii()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
        or value != f"{parsed.scheme}://{parsed.netloc}"
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("bootstrap public origin must be one normalized HTTPS origin")
    return value


def _require_safe_owned_path(
    path: Path,
    *,
    directory: bool,
    require_single_link: bool = False,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"bootstrap evidence path is unavailable: {path.name}") from error
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if path.is_symlink() or not expected(metadata.st_mode):
        raise ValueError(f"bootstrap evidence path has an unsafe type: {path.name}")
    if metadata.st_uid != os.geteuid():
        raise ValueError(f"bootstrap evidence path has a different owner: {path.name}")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"bootstrap evidence path is group/world writable: {path.name}")
    if require_single_link and metadata.st_nlink != 1:
        raise ValueError(f"bootstrap evidence file must have one hard link: {path.name}")


def _load_canonical_model(
    data: bytes,
    model: type[StrictProtocolModel],
    *,
    label: str,
) -> Any:
    try:
        value = model.model_validate_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"bootstrap {label} is invalid") from error
    if canonical_json_bytes(value) != data:
        raise ValueError(f"bootstrap {label} must be RFC 8785 canonical JSON")
    return value


def _parse_config(
    path: Path,
) -> BootstrapServiceFeedConfig | SimpleBootstrapServiceFeedConfig:
    if not path.is_absolute():
        raise ValueError("bootstrap feed config path must be absolute")
    _require_safe_owned_path(path, directory=False, require_single_link=True)
    data = _read_bounded_regular_file(path, MAX_BOOTSTRAP_CONFIG_BYTES)
    try:
        decoded = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bootstrap feed config is invalid") from error
    schema = decoded.get("schema") if isinstance(decoded, dict) else None
    model: type[StrictProtocolModel]
    if schema == BOOTSTRAP_SERVICE_FEED_CONFIG_SCHEMA:
        model = BootstrapServiceFeedConfig
    elif schema == SIMPLE_BOOTSTRAP_FEED_CONFIG_SCHEMA:
        model = SimpleBootstrapServiceFeedConfig
    else:
        raise ValueError("bootstrap feed config schema is unsupported")
    return _load_canonical_model(data, model, label="feed config")


def _as_object_ref(value: BootstrapServiceObjectRef) -> ObjectRef:
    return ObjectRef(value.sha256, value.media_type, value.size_bytes)


def _validate_pilot_bindings(
    signed: SignedBootstrapEligibilityManifest,
    pilot_feed: ObserverPilotFeed,
) -> None:
    for entry in signed.manifest.entries:
        pilot = pilot_feed.get(entry.pilot_id)
        if pilot is None or pilot.public_endpoint is None:
            raise ValueError("bootstrap eligibility entry lacks a replayed public endpoint pilot")
        attestation = pilot.public_endpoint.attestation
        if attestation.outcome_classification != "ok":
            raise ValueError("bootstrap eligibility entry pilot did not complete successfully")
        if (
            account_id32(pilot.miner_hotkey) != account_id32(entry.miner_hotkey)
            or attestation.expected_miner_uid != entry.uid
            or attestation.announced_origin != entry.origin
            or attestation.contacted_origin != entry.origin
            or attestation.chain_observation.block_number != entry.pilot_block
        ):
            raise ValueError("bootstrap eligibility entry does not match its replayed pilot")


def _verify_terminal_bindings(
    owner_fence: OwnerFenceReceipt,
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
    material: DirectBootstrapCallMaterial,
    receipt: DirectBootstrapSubmissionReceipt,
    journal: DirectBootstrapSubmissionJournal,
) -> _VerifiedTerminalBindings:
    """Reject inconsistent terminal records before any publication is written."""

    verify_signed_bootstrap_eligibility_manifest(signed)
    verify_direct_transition_authorization(
        signed,
        authorization,
        current_block=receipt.weight_call.block_number,
    )
    if material.manifest_anchor is None:
        raise ValueError("bootstrap call material lacks its finalized manifest anchor")
    anchor = material.manifest_anchor.anchor
    material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    authorization_sha256 = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
    expected_row_sha256 = hashlib.sha256(
        canonical_json_bytes(material.expected_applied_row)
    ).hexdigest()
    expected_active_through = min(
        receipt.weight_call.block_number
        + material.operational_preflight.chain.snapshot.activity_cutoff_blocks,
        signed.manifest.policy.hard_sunset_block - 1,
    )
    positive_uids = {item.uid for item in signed.manifest.entries}
    expected_row = [[uid, U16_MAX if uid in positive_uids else 0] for uid in range(256)]
    if material.dests != list(range(256)) or material.expected_applied_row != expected_row:
        raise ValueError("bootstrap call material is not the exact binary full row")
    if material.weights != [item[1] for item in expected_row]:
        raise ValueError("bootstrap call weights do not match the expected full row")
    direct_snapshot = material.operational_preflight.chain.snapshot
    owner_hotkey = bytes.fromhex(
        owner_fence.call_material.preflight.subnet_owner_hotkey_account_id32[2:]
    )
    direct_owner_hotkey = bytes.fromhex(
        material.operational_preflight.chain.subnet_owner_hotkey_account_id32[2:]
    )
    expected_active_before = (
        {account_id32(authorization.validator_hotkey)}
        if material.operational_preflight.chain.prior_row_classification
        == "active_exact_direct_row"
        else set()
    )
    observed_active_before = {
        account_id32(hotkey) for hotkey in direct_snapshot.active_mechid0_row_hotkeys
    }
    if (
        owner_fence.observation_block > direct_snapshot.block_number
        or owner_fence.observed_weights_version_key != DIRECT_MINIMUM_WEIGHTS_VERSION_KEY
        or owner_fence.observed_min_allowed_weights != 256
        or owner_fence.observed_commit_reveal_enabled is not False
        or owner_hotkey != direct_owner_hotkey
    ):
        raise ValueError("bootstrap owner fence does not establish the direct-call precondition")
    if (
        material.operational_preflight.signed_manifest != signed
        or material.manifest_sha256 != signed.manifest_sha256
        or material.operational_preflight.chain.transition_authorization != authorization
        or direct_snapshot.commit_reveal_version != 4
        or direct_snapshot.reveal_period_epochs != 1
        or direct_snapshot.tempo != 360
        or direct_snapshot.activity_cutoff_blocks != 360
        or direct_snapshot.block_time_seconds != 12.0
        or direct_snapshot.total_pending_commit_count != 0
        or direct_snapshot.validator_has_pending_commit
        or observed_active_before != expected_active_before
        or receipt.classification != "applied"
        or receipt.observation_block < receipt.weight_call.block_number
        or receipt.observation_block > expected_active_through
        or receipt.call_material_sha256 != material_sha256
        or receipt.manifest_sha256 != signed.manifest_sha256
        or receipt.anchor != anchor
        or receipt.anchor.block_number > receipt.weight_call.block_number
        or receipt.expected_applied_row != material.expected_applied_row
        or receipt.observed_applied_row != material.expected_applied_row
        or receipt.observed_last_update != receipt.weight_call.block_number
        or journal.phase != "applied"
        or journal.submission_id != authorization.submission_id
        or journal.manifest_sha256 != signed.manifest_sha256
        or journal.transition_authorization_sha256 != authorization_sha256
        or account_id32(journal.validator_hotkey) != account_id32(receipt.validator_hotkey)
        or journal.anchor != receipt.anchor
        or journal.call_material_sha256 != material_sha256
        or journal.weight_call != receipt.weight_call
        or journal.receipt_sha256 != receipt_sha256
        or receipt.validator_uid != authorization.validator_uid
        or account_id32(receipt.validator_hotkey) != account_id32(authorization.validator_hotkey)
    ):
        raise ValueError("bootstrap terminal evidence is not consistently cross-bound")
    return _VerifiedTerminalBindings(
        expected_row_sha256=expected_row_sha256,
        active_through_block=expected_active_through,
    )


def _load_publication(
    root: Path,
    public_origin: str,
    pilot_feed: ObserverPilotFeed,
    *,
    remaining_bytes: int,
) -> VerifiedBootstrapServicePublication:
    _require_safe_owned_path(root, directory=True)
    _require_safe_owned_path(root / "objects", directory=True)
    manifest_path = root / "manifest.json"
    _require_safe_owned_path(manifest_path, directory=False, require_single_link=True)
    manifest_bytes = _read_bounded_regular_file(manifest_path, MAX_BOOTSTRAP_MANIFEST_BYTES)
    manifest = _load_canonical_model(
        manifest_bytes,
        BootstrapServicePublicationManifest,
        label="publication manifest",
    )
    declared_bytes = len(manifest_bytes) + sum(
        reference.size_bytes for reference in manifest.object_references()
    )
    if declared_bytes > remaining_bytes:
        raise ValueError("bootstrap feed exceeds its aggregate byte ceiling")
    store = EvidenceStore(
        root,
        maximum_object_bytes=MAX_BOOTSTRAP_OBJECT_BYTES,
        maximum_manifest_bytes=MAX_BOOTSTRAP_MANIFEST_BYTES,
        maximum_total_object_bytes=MAX_BOOTSTRAP_FEED_BYTES,
    )
    objects: dict[str, VerifiedBootstrapServiceObject] = {}
    for reference in manifest.object_references():
        path = root / "objects" / reference.sha256
        _require_safe_owned_path(path, directory=False, require_single_link=True)
        data = store.read(_as_object_ref(reference))
        objects[reference.sha256] = VerifiedBootstrapServiceObject(
            sha256=reference.sha256,
            media_type=reference.media_type,
            data=data,
        )

    def parse(reference: BootstrapServiceObjectRef, model: type[StrictProtocolModel], name: str):
        return _load_canonical_model(objects[reference.sha256].data, model, label=name)

    owner_fence = parse(manifest.owner_fence_receipt, OwnerFenceReceipt, "owner fence receipt")
    signed = parse(
        manifest.signed_eligibility_manifest,
        SignedBootstrapEligibilityManifest,
        "signed eligibility manifest",
    )
    authorization = parse(
        manifest.transition_authorization,
        DirectBootstrapTransitionAuthorization,
        "transition authorization",
    )
    material = parse(manifest.call_material, DirectBootstrapCallMaterial, "call material")
    receipt = parse(
        manifest.submission_receipt,
        DirectBootstrapSubmissionReceipt,
        "submission receipt",
    )
    journal = parse(
        manifest.submission_journal,
        DirectBootstrapSubmissionJournal,
        "submission journal",
    )
    bindings = _verify_terminal_bindings(
        owner_fence,
        signed,
        authorization,
        material,
        receipt,
        journal,
    )
    _validate_pilot_bindings(signed, pilot_feed)
    if (
        manifest.umi_git_revision != authorization.umi_git_revision
        or manifest.submission_id != authorization.submission_id
        or manifest.policy_sha256 != signed.manifest.policy_sha256
        or manifest.eligibility_manifest_sha256 != signed.manifest_sha256
        or manifest.weight_call_block != receipt.weight_call.block_number
        or manifest.active_through_block != bindings.active_through_block
        or manifest.hard_sunset_block != signed.manifest.policy.hard_sunset_block
        or manifest.expected_row_sha256 != bindings.expected_row_sha256
    ):
        raise ValueError("bootstrap publication summary does not match terminal evidence")

    publication_id = hashlib.sha256(manifest_bytes).hexdigest()
    return VerifiedBootstrapServicePublication(
        publication_id=publication_id,
        public_origin=public_origin,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        objects=MappingProxyType(objects),
        owner_fence_receipt=owner_fence,
        signed_manifest=signed,
        authorization=authorization,
        call_material=material,
        receipt=receipt,
        journal=journal,
    )


def _load_simple_bootstrap_configuration(
    config: BootstrapServiceFeedConfig | SimpleBootstrapServiceFeedConfig,
    pilot_feed: ObserverPilotFeed,
    *,
    remaining_bytes: int,
) -> VerifiedSimpleBootstrapConfiguration | None:
    if not isinstance(config, SimpleBootstrapServiceFeedConfig):
        return None
    manifest_name = config.simple_bootstrap_signed_manifest_path
    lease_name = config.simple_bootstrap_lease_path

    manifest_path = Path(manifest_name)
    lease_path = Path(lease_name)
    for path in (manifest_path, lease_path):
        _require_safe_owned_path(path, directory=False, require_single_link=True)
    signed_manifest_bytes = _read_bounded_regular_file(
        manifest_path,
        MAX_BOOTSTRAP_OBJECT_BYTES,
    )
    signed_lease_bytes = _read_bounded_regular_file(
        lease_path,
        MAX_BOOTSTRAP_OBJECT_BYTES,
    )
    signed_manifest = _load_canonical_model(
        signed_manifest_bytes,
        SignedBootstrapEligibilityManifest,
        label="simple signed eligibility manifest",
    )
    signed_lease = _load_canonical_model(
        signed_lease_bytes,
        SignedSimpleBootstrapLease,
        label="simple bootstrap lease",
    )
    verify_simple_bootstrap_lease(
        signed_lease,
        signed_manifest=signed_manifest,
        expected_revision=signed_lease.body.umi_git_revision,
        current_block=signed_lease.body.valid_from_block,
    )
    if config.public_origin != signed_manifest.manifest.policy.public_evidence_origin:
        raise ValueError("simple bootstrap public origin does not match the signed policy")
    _validate_pilot_bindings(signed_manifest, pilot_feed)

    eligible_uids = {entry.uid for entry in signed_manifest.manifest.entries}
    expected_row = tuple((uid, U16_MAX if uid in eligible_uids else 0) for uid in range(256))
    expected_row_sha256 = hashlib.sha256(canonical_json_bytes(expected_row)).hexdigest()
    objects: dict[str, VerifiedBootstrapServiceObject] = {}
    references: dict[str, BootstrapServiceObjectRef] = {}
    for name, data in (
        ("signed_eligibility_manifest", signed_manifest_bytes),
        ("signed_lease", signed_lease_bytes),
    ):
        digest = hashlib.sha256(data).hexdigest()
        if digest in objects:
            raise ValueError("simple bootstrap evidence roles must name distinct objects")
        objects[digest] = VerifiedBootstrapServiceObject(
            sha256=digest,
            media_type="application/json",
            data=data,
        )
        references[name] = BootstrapServiceObjectRef(
            sha256=digest,
            media_type="application/json",
            size_bytes=len(data),
        )
    publication_manifest = SimpleBootstrapPublicationManifest(
        schema=SIMPLE_BOOTSTRAP_PUBLICATION_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mechanism=BOOTSTRAP_SERVICE_MECHANISM,
        chain_state_required=True,
        service_weights_active_claimed=False,
        translation_weights_active=False,
        activation_evidence=False,
        validator_input_eligible=False,
        storage_proofs_verified=False,
        umi_git_revision=signed_lease.body.umi_git_revision,
        policy_sha256=signed_lease.body.policy_sha256,
        eligibility_manifest_sha256=signed_manifest.manifest_sha256,
        valid_from_block=signed_lease.body.valid_from_block,
        hard_sunset_block=signed_lease.body.hard_sunset_block,
        expected_row_sha256=expected_row_sha256,
        signed_eligibility_manifest=references["signed_eligibility_manifest"],
        signed_lease=references["signed_lease"],
    )
    publication_bytes = canonical_json_bytes(publication_manifest)
    declared_bytes = len(publication_bytes) + sum(len(item.data) for item in objects.values())
    if declared_bytes > remaining_bytes:
        raise ValueError("bootstrap feed exceeds its aggregate byte ceiling")
    return VerifiedSimpleBootstrapConfiguration(
        publication_id=hashlib.sha256(publication_bytes).hexdigest(),
        public_origin=config.public_origin,
        manifest=publication_manifest,
        manifest_bytes=publication_bytes,
        objects=MappingProxyType(objects),
        signed_manifest=signed_manifest,
        signed_lease=signed_lease,
        expected_row=expected_row,
    )


def build_observer_bootstrap_service_feed(
    config_path: str | Path,
    *,
    pilot_feed: ObserverPilotFeed,
) -> ObserverBootstrapServiceFeed:
    """Load and freeze each schema-checked direct-bootstrap publication."""

    if not isinstance(pilot_feed, ObserverPilotFeed):
        raise TypeError("bootstrap service feed requires a verified pilot feed")
    config = _parse_config(Path(config_path))
    loaded: list[VerifiedBootstrapServicePublication] = []
    total = 0
    for root in config.bundle_roots:
        publication = _load_publication(
            Path(root),
            config.public_origin,
            pilot_feed,
            remaining_bytes=MAX_BOOTSTRAP_FEED_BYTES - total,
        )
        total += len(publication.manifest_bytes) + sum(
            obj.size_bytes for obj in publication.objects.values()
        )
        loaded.append(publication)
    simple_bootstrap = _load_simple_bootstrap_configuration(
        config,
        pilot_feed,
        remaining_bytes=MAX_BOOTSTRAP_FEED_BYTES - total,
    )
    publications = tuple(
        sorted(
            loaded,
            key=lambda item: (item.receipt.weight_call.block_number, item.publication_id),
        )
    )
    if len({item.publication_id for item in publications}) != len(publications):
        raise ValueError("bootstrap feed contains the same publication more than once")
    authorization_hashes = [
        hashlib.sha256(canonical_json_bytes(item.authorization)).hexdigest()
        for item in publications
    ]
    if len(set(authorization_hashes)) != len(authorization_hashes):
        raise ValueError("bootstrap feed reuses a direct transition authorization")
    submission_ids = [item.authorization.submission_id for item in publications]
    if len(set(submission_ids)) != len(submission_ids):
        raise ValueError("bootstrap feed reuses a direct transition submission ID")
    calls = [
        (item.receipt.weight_call.block_number, account_id32(item.receipt.validator_hotkey))
        for item in publications
    ]
    if len(set(calls)) != len(calls):
        raise ValueError("bootstrap feed contains ambiguous publications for one weight call")
    evidence_ids = [item.publication_id for item in publications]
    if simple_bootstrap is not None:
        evidence_ids.append(simple_bootstrap.publication_id)
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("bootstrap feed contains an ambiguous evidence identifier")
    return ObserverBootstrapServiceFeed(
        publications=publications,
        simple_bootstrap=simple_bootstrap,
    )


def build_bootstrap_service_publication(
    *,
    owner_fence_receipt: OwnerFenceReceipt,
    signed_manifest: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
    call_material: DirectBootstrapCallMaterial,
    submission_receipt: DirectBootstrapSubmissionReceipt,
    submission_journal: DirectBootstrapSubmissionJournal,
    output_root: Path,
) -> Path:
    """Write one immutable publication bundle from canonical terminal records."""

    if output_root.exists():
        raise FileExistsError("bootstrap publication output root already exists")
    bindings = _verify_terminal_bindings(
        owner_fence_receipt,
        signed_manifest,
        authorization,
        call_material,
        submission_receipt,
        submission_journal,
    )
    store = EvidenceStore(
        output_root,
        maximum_object_bytes=MAX_BOOTSTRAP_OBJECT_BYTES,
        maximum_manifest_bytes=MAX_BOOTSTRAP_MANIFEST_BYTES,
        maximum_total_object_bytes=MAX_BOOTSTRAP_FEED_BYTES,
    )
    refs = {
        "owner_fence_receipt": store.add_json(owner_fence_receipt),
        "signed_eligibility_manifest": store.add_json(signed_manifest),
        "transition_authorization": store.add_json(authorization),
        "call_material": store.add_json(call_material),
        "submission_receipt": store.add_json(submission_receipt),
        "submission_journal": store.add_json(submission_journal),
    }
    manifest = BootstrapServicePublicationManifest(
        schema=BOOTSTRAP_SERVICE_PUBLICATION_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mechanism=BOOTSTRAP_SERVICE_MECHANISM,
        service_weights_active=True,
        translation_weights_active=False,
        activation_evidence=False,
        validator_input_eligible=False,
        storage_proofs_verified=False,
        umi_git_revision=authorization.umi_git_revision,
        submission_id=authorization.submission_id,
        policy_sha256=signed_manifest.manifest.policy_sha256,
        eligibility_manifest_sha256=signed_manifest.manifest_sha256,
        weight_call_block=submission_receipt.weight_call.block_number,
        active_through_block=bindings.active_through_block,
        hard_sunset_block=signed_manifest.manifest.policy.hard_sunset_block,
        expected_row_sha256=bindings.expected_row_sha256,
        **{name: ref.as_dict() for name, ref in refs.items()},
    )
    return store.write_manifest(manifest.model_dump(mode="json", by_alias=True))


def _read_cli_model(path: str, model: type[StrictProtocolModel], label: str):
    source = Path(path)
    data = _read_bounded_regular_file(source, MAX_BOOTSTRAP_OBJECT_BYTES)
    return _load_canonical_model(data, model, label=label)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build immutable bootstrap service evidence")
    parser.add_argument("--owner-fence-receipt", required=True)
    parser.add_argument("--signed-manifest", required=True)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--call-material", required=True)
    parser.add_argument("--submission-receipt", required=True)
    parser.add_argument("--submission-journal", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    path = build_bootstrap_service_publication(
        owner_fence_receipt=_read_cli_model(
            args.owner_fence_receipt, OwnerFenceReceipt, "owner fence receipt"
        ),
        signed_manifest=_read_cli_model(
            args.signed_manifest, SignedBootstrapEligibilityManifest, "signed manifest"
        ),
        authorization=_read_cli_model(
            args.authorization, DirectBootstrapTransitionAuthorization, "authorization"
        ),
        call_material=_read_cli_model(
            args.call_material, DirectBootstrapCallMaterial, "call material"
        ),
        submission_receipt=_read_cli_model(
            args.submission_receipt, DirectBootstrapSubmissionReceipt, "submission receipt"
        ),
        submission_journal=_read_cli_model(
            args.submission_journal, DirectBootstrapSubmissionJournal, "submission journal"
        ),
        output_root=Path(args.output_root),
    )
    print(path)


__all__ = [
    "BOOTSTRAP_SERVICE_FEED_CONFIG_SCHEMA",
    "BOOTSTRAP_SERVICE_MECHANISM",
    "BOOTSTRAP_SERVICE_PUBLICATION_SCHEMA",
    "SIMPLE_BOOTSTRAP_FEED_CONFIG_SCHEMA",
    "SIMPLE_BOOTSTRAP_PUBLICATION_SCHEMA",
    "BootstrapServiceFeedConfig",
    "BootstrapServicePublicationManifest",
    "ObserverBootstrapServiceFeed",
    "SimpleBootstrapPublicationManifest",
    "SimpleBootstrapServiceFeedConfig",
    "VerifiedBootstrapServicePublication",
    "VerifiedSimpleBootstrapConfiguration",
    "build_bootstrap_service_publication",
    "build_observer_bootstrap_service_feed",
]


if __name__ == "__main__":
    main()
