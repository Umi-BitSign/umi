"""Installed legacy R2 metadata selection without rewriting signed cohort inputs.

Each private source directory holds ``legacy-inventory.json``,
``preservation-inventory.json`` and exact raw originals in ``objects/<sha>.json``.
The root configuration selects baseline and incumbent identities independently
of the inventories. Neither these paths nor replica metadata grant authority.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from .competition_cohort_legacy_model_storage import (
    MAX_INVENTORY_BYTES,
    AuthenticatedLegacyModelStorage,
    LegacyModelStorageRepairRequired,
    authenticate_legacy_storage_inventories,
    verify_legacy_storage_originals,
)
from .competition_cohort_model_transport_selection import effective_model_deliveries
from .competition_model_byte_store import (
    ModelByteStoreConfig,
    qualify_shared_byte_stores,
    validate_shared_byte_stores,
)
from .competition_transport_verification import TransferProgress
from .open_competition import CompetitionPolicy, digest
from .private_files import Directory, _read_private_bytes
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex


class LegacyModelStorageSourceConfig(StrictProtocolModel):
    schema_: Literal["umi-legacy-model-storage-source/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    directory: Directory
    baseline_model_sha256: Hex32
    incumbent_model_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=65536)] = ()
    shared_byte_store: ModelByteStoreConfig | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        value = handler(self)
        if self.shared_byte_store is None:
            value.pop("shared_byte_store", None)
        return value

    @model_validator(mode="after")
    def unique_incumbents(self):
        if self.incumbent_model_sha256s != tuple(sorted(set(self.incumbent_model_sha256s))):
            raise ValueError("legacy storage incumbent selection must be unique and sorted")
        validate_shared_byte_stores((self,), (self.directory,))
        return self


LegacyModelStorageSelections = Annotated[
    tuple[LegacyModelStorageSourceConfig, ...], Field(max_length=512)
]


def validate_legacy_model_selections(sources, *, series, policy, model_delivery_adoptions):
    """Pure scope validation; older omitted configurations retain local storage."""
    selected = tuple(
        LegacyModelStorageSourceConfig.model_validate_json(canonical_json_bytes(value))
        for value in sources
    )
    effective_model_deliveries(series, policy, model_delivery_adoptions)
    cohorts = tuple(value.cohort_sha256 for value in selected)
    if cohorts != tuple(sorted(set(cohorts))) or (
        selected
        and set(cohorts) != {digest(value.history.plan) for value in model_delivery_adoptions}
    ):
        raise ValueError("legacy model sources must exactly cover committed adopted cohorts")
    paths = tuple(Path(value.directory) for value in selected)
    validate_shared_byte_stores(selected, paths)
    if any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(paths)
        for right in paths[index + 1 :]
    ):
        raise ValueError("legacy model source directories must be disjoint")
    return selected


@dataclass(frozen=True)
class AuthenticatedLegacyModelSources:
    policy: CompetitionPolicy
    authenticated: dict[str, AuthenticatedLegacyModelStorage]
    original_paths: dict[str, tuple[Path, ...]]
    byte_stores: dict[str, ModelByteStoreConfig] = field(default_factory=dict)

    def load_original(self, raw_sha256):
        paths = self.original_paths.get(raw_sha256)
        if not paths:
            raise LegacyModelStorageRepairRequired(
                "legacy original is outside selected inventories"
            )
        try:
            raw = _read_private_bytes(paths[0], maximum_bytes=MAX_INVENTORY_BYTES)
        except (FileNotFoundError, ValueError) as error:
            raise LegacyModelStorageRepairRequired(
                "selected legacy original requires repair"
            ) from error
        if sha256_hex(raw) != raw_sha256:
            raise LegacyModelStorageRepairRequired(
                "selected legacy original changed its raw identity"
            )
        return raw


def authenticate_legacy_model_sources(sources, *, series, policy, model_delivery_adoptions):
    """Read and qualify selected metadata before leases, signing keys or providers."""
    selected = validate_legacy_model_selections(
        sources, series=series, policy=policy, model_delivery_adoptions=model_delivery_adoptions
    )
    if not selected:
        return None
    qualify_shared_byte_stores(selected)
    selections = {digest(value.history.plan): value for value in model_delivery_adoptions}
    authenticated, paths = {}, {}
    with TransferProgress(
        "legacy_model_storage_selection",
        len(selected),
        unit="cohorts",
        planning_unit_seconds=(0.01, 10.0),
    ) as progress:
        for source in selected:
            root = Path(source.directory)
            try:
                legacy = _read_private_bytes(
                    root / "legacy-inventory.json", maximum_bytes=MAX_INVENTORY_BYTES
                )
                preservation = _read_private_bytes(
                    root / "preservation-inventory.json", maximum_bytes=MAX_INVENTORY_BYTES
                )
                value = authenticate_legacy_storage_inventories(
                    legacy,
                    preservation,
                    selection=selections[source.cohort_sha256],
                    policy=policy,
                    expected_baseline_sha256=source.baseline_model_sha256,
                    expected_incumbent_sha256s=source.incumbent_model_sha256s,
                )
            except (FileNotFoundError, ValueError) as error:
                progress.emit(
                    "repair_required", reason="legacy_storage_inventory_missing_or_damaged"
                )
                raise LegacyModelStorageRepairRequired(
                    "selected legacy inventories require repair"
                ) from error
            authenticated[source.cohort_sha256] = value
            keys = {
                value.legacy.baseline_manifest_raw_sha256,
                *(item.manifest_raw_sha256 for item in value.legacy.incumbents),
            }
            for entry in value.legacy.entries:
                keys.update(
                    key
                    for key in (
                        entry.request_raw_sha256,
                        entry.participation_raw_sha256,
                        entry.admission_raw_sha256,
                        entry.intent_raw_sha256,
                        entry.certificate_raw_sha256,
                    )
                    if key is not None
                )
            for entry in value.preservation.models:
                keys.update(
                    (
                        entry.manifest_raw_sha256,
                        entry.association_raw_sha256,
                        entry.package_raw_sha256,
                    )
                )
            for key in keys:
                paths.setdefault(key, []).append(root / "objects" / (key + ".json"))
            progress.advance(1)
    prepared = AuthenticatedLegacyModelSources(
        policy,
        authenticated,
        {key: tuple(value) for key, value in paths.items()},
        {
            value.cohort_sha256: value.shared_byte_store
            for value in selected
            if value.shared_byte_store is not None
        },
    )
    for value in authenticated.values():
        namespace = {(entry.endpoint, entry.bucket) for entry in value.preservation.models}
        if len(namespace) != 1:
            raise ValueError("legacy storage inventory changes its selected namespace")
        endpoint, bucket = next(iter(namespace))
        verify_legacy_storage_originals(
            value, load_original=prepared.load_original, endpoint=endpoint, bucket=bucket
        )
    return prepared


def selected_legacy_model_readers(prepared, *, multipart, verification_root):
    """Bind preflight metadata to the actual credentialed namespace and durable state."""
    if prepared is None:
        return None
    namespace = (multipart.signer.endpoint, multipart.signer.bucket)
    if any(
        (entry.endpoint, entry.bucket) != namespace
        for value in prepared.authenticated.values()
        for entry in value.preservation.models
    ):
        raise ValueError("legacy model source differs from the credentialed R2 namespace")
    return LegacyModelStorageReaders(
        prepared.authenticated,
        policy=prepared.policy,
        load_original=prepared.load_original,
        multipart=multipart,
        verification_root=verification_root,
        byte_stores=prepared.byte_stores,
    )
