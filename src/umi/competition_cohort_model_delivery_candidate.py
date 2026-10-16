"""Private precommit transport selection for the normal adoption issuance path.

A candidate is never a committed transport or an admission capability. Native
owner census, exact reservation and independent byte review precede any vote.
"""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from .competition_cohort_legacy_model_selection import LegacyModelStorageSourceConfig
from .competition_cohort_legacy_model_storage import (
    MAX_INVENTORY_BYTES,
    LegacyModelPreservationInventory,
    LegacyModelStorageInventory,
    LegacyModelStorageRepairRequired,
    authenticate_legacy_storage_proposal,
    verify_legacy_storage_originals,
)
from .competition_cohort_model_transport import prepare_model_delivery_adoption
from .competition_cohort_recovery import ModelDeliveryProfile
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import Directory, _read_private_bytes
from .protocol import StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_multipart import R2MultipartClient
from .r2_sigv4 import R2SigV4, load_r2_credentials


class ModelDeliveryAdoptionCandidateConfig(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-adoption-candidate/1"] = Field(alias="schema")
    source: LegacyModelStorageSourceConfig
    delivery: ModelDeliveryProfile
    r2_credentials_file: Directory
    r2_bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    verification_directory: Directory
    r2_timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60

    @model_validator(mode="after")
    def direct_only(self):
        if self.delivery.mechanism != "direct_r2_multipart_v1":
            raise ValueError("model delivery candidate requires direct R2 transport")
        paths = self.stores()
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("model delivery candidate paths must be disjoint")
        return self

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.source.directory,
                self.r2_credentials_file,
                self.verification_directory,
            )
        )


ModelDeliveryAdoptionCandidates = Annotated[
    tuple[ModelDeliveryAdoptionCandidateConfig, ...], Field(max_length=512)
]


def validate_adoption_candidates(candidates, cohorts):
    keys = tuple(c.source.cohort_sha256 for c in candidates)
    if keys != tuple(sorted(set(keys))) or not set(keys) <= set(cohorts):
        raise ValueError("model delivery candidates must name unique selected cohorts")
    roots = tuple(
        Path(path) for c in candidates for path in (c.source.directory, c.verification_directory)
    )
    if any(
        a == b or a in b.parents or b in a.parents
        for i, a in enumerate(roots)
        for b in roots[i + 1 :]
    ):
        raise ValueError(
            "model delivery candidates require separate original and verification stores"
        )
    if any(
        root == Path(c.r2_credentials_file)
        or root in Path(c.r2_credentials_file).parents
        or Path(c.r2_credentials_file) in root.parents
        for c in candidates
        for root in roots
    ):
        raise ValueError(
            "model delivery credentials overlap selected original or verification stores"
        )


class ModelDeliveryAdoptionCandidate:
    def __init__(self, config, policy, *, multipart=None):
        self.config, self.policy = config, policy
        self.root = Path(config.source.directory)
        self.multipart = multipart

    def originals(self, raw_sha256):
        # Hash values are selected by strict inventory models, not URL paths.
        if len(raw_sha256) != 64 or any(c not in "0123456789abcdef" for c in raw_sha256):
            raise ValueError("model adoption original identity is invalid")
        raw = _read_private_bytes(
            self.root / "objects" / (raw_sha256 + ".json"),
            maximum_bytes=MAX_INVENTORY_BYTES,
        )
        if sha256_hex(raw) != raw_sha256:
            raise ValueError("model adoption original changed; repair required")
        return raw

    def inventories(self):
        values = []
        with TransferProgress(
            "model_delivery_adoption_metadata",
            2,
            unit="inventories",
            planning_unit_seconds=(0.001, 1),
        ) as progress:
            for name, model in (
                ("legacy-inventory.json", LegacyModelStorageInventory),
                ("preservation-inventory.json", LegacyModelPreservationInventory),
            ):
                try:
                    raw = _read_private_bytes(self.root / name, maximum_bytes=MAX_INVENTORY_BYTES)
                    value = model.model_validate_json(raw)
                    if raw != canonical_json_bytes(value):
                        raise ValueError("model adoption inventory changed canonical bytes")
                except (OSError, ValueError) as error:
                    progress.emit(
                        "repair_required", reason="model_adoption_inventory_missing_or_damaged"
                    )
                    raise LegacyModelStorageRepairRequired(
                        "selected model adoption inventory requires repair"
                    ) from error
                values.append(value)
                progress.advance(1)
        return tuple(values)

    def prepare(self, history, block):
        legacy, preservation = self.inventories()
        predecessor = digest(
            history.transitions[-1].transition if history.transitions else history.genesis
        )
        return prepare_model_delivery_adoption(
            history,
            self.policy,
            expected_tip_sha256=predecessor,
            current_block=block,
            delivery=self.config.delivery,
            legacy_inventory_sha256=digest(legacy),
            preservation_inventory_sha256=digest(preservation),
        )

    def authenticate(self, history, transition):
        source = self.config.source
        if transition.cohort_sha256 != source.cohort_sha256:
            raise ValueError("model delivery candidate selects another cohort")
        if transition.model_delivery_adoption.delivery != self.config.delivery:
            raise ValueError("model delivery candidate selects another transport")
        legacy, preservation = self.inventories()
        authenticated = authenticate_legacy_storage_proposal(
            canonical_json_bytes(legacy),
            canonical_json_bytes(preservation),
            history=history,
            transition=transition,
            policy=self.policy,
            expected_baseline_sha256=source.baseline_model_sha256,
            expected_incumbent_sha256s=source.incumbent_model_sha256s,
        )
        namespace = {(m.endpoint, m.bucket) for m in preservation.models}
        if len(namespace) != 1:
            raise ValueError("model adoption changes its selected R2 namespace")
        endpoint, bucket = next(iter(namespace))
        if bucket != self.config.r2_bucket:
            raise ValueError("model adoption changes its selected R2 bucket")
        verify_legacy_storage_originals(
            authenticated,
            load_original=self.originals,
            endpoint=endpoint,
            bucket=bucket,
        )
        return authenticated

    async def verify(self, history, transition):
        value = await run_owned_thread(self.authenticate, history, transition)
        if self.multipart is None:
            loaded = await run_owned_thread(
                load_r2_credentials, Path(self.config.r2_credentials_file)
            )
            self.multipart = R2MultipartClient(
                R2SigV4(loaded.endpoint, self.config.r2_bucket, loaded.credentials),
                timeout_seconds=self.config.r2_timeout_seconds,
            )
        readers = LegacyModelStorageReaders(
            {transition.cohort_sha256: value},
            policy=self.policy,
            load_original=self.originals,
            multipart=self.multipart,
            verification_root=Path(self.config.verification_directory),
        )
        selectors = {value.legacy.baseline_model_sha256: {"baseline": True}}
        selectors.update(
            {v.model_sha256: {"incumbent_sha256": v.model_sha256} for v in value.legacy.incumbents}
        )
        selectors.update(
            {
                e.model_sha256: {"request_sha256": e.request_sha256}
                for e in value.legacy.entries
                if e.payload_state == "preserved"
            }
        )
        with TransferProgress(
            "model_delivery_adoption_remote_review",
            len(selectors),
            unit="models",
            planning_unit_seconds=(1, 3600),
        ) as progress:
            for model in sorted(selectors):
                resolution = await run_owned_thread(
                    lambda model=model: readers.resolve(
                        transition.cohort_sha256, **selectors[model]
                    )
                )
                reader = readers.reader(resolution)
                snapshot = await reader.verify()
                await run_owned_thread(reader.require_verified, snapshot)
                progress.advance(1)
        return value
