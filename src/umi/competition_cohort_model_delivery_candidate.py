"""Private precommit transport selection for the normal adoption issuance path.

A candidate is never a committed transport or an admission capability. Native
owner census, exact reservation and independent byte review precede any vote.
"""

from pathlib import Path
from time import monotonic
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

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
from .competition_forecast import forecast_subscope
from .competition_model_batch_progress import ModelBatchProgress, ModelWorkInventory
from .competition_model_byte_store import (
    qualify_shared_byte_stores,
    shared_byte_store_paths,
    validate_shared_byte_stores,
)
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import Directory, _read_private_bytes
from .protocol import StrictProtocolModel, canonical_json_bytes, sha256_hex
from .r2_multipart import R2MultipartClient, r2_connection_scope
from .r2_sigv4 import R2SigV4, load_r2_credentials


class ModelDeliveryAdoptionCandidateConfig(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-adoption-candidate/1"] = Field(alias="schema")
    source: LegacyModelStorageSourceConfig
    delivery: ModelDeliveryProfile
    r2_credentials_file: Directory
    r2_bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    verification_directory: Directory
    r2_timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60
    model_only: bool = False

    @model_serializer(mode="wrap")
    def preserve_transport_only_config(self, handler):
        value = handler(self)
        if not self.model_only:
            value.pop("model_only", None)
        return value

    @model_validator(mode="after")
    def direct_only(self):
        if self.delivery.mechanism != "direct_r2_multipart_v1":
            raise ValueError("model delivery candidate requires direct R2 transport")
        paths = self.stores(include_shared=False)
        validate_shared_byte_stores((self.source,), paths)
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("model delivery candidate paths must be disjoint")
        return self

    def stores(self, *, include_shared=True):
        return tuple(
            Path(p)
            for p in (
                self.source.directory,
                self.r2_credentials_file,
                self.verification_directory,
                *(shared_byte_store_paths((self.source,)) if include_shared else ()),
            )
        )


ModelDeliveryAdoptionCandidates = Annotated[
    tuple[ModelDeliveryAdoptionCandidateConfig, ...], Field(max_length=512)
]


def validate_adoption_candidates(candidates, cohorts):
    validate_shared_byte_stores(
        (c.source for c in candidates),
        tuple(p for c in candidates for p in c.stores(include_shared=False)),
    )
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
            model_only=self.config.model_only,
        )

    def authenticate(self, history, transition):
        source = self.config.source
        if transition.cohort_sha256 != source.cohort_sha256:
            raise ValueError("model delivery candidate selects another cohort")
        if transition.model_delivery_adoption.delivery != self.config.delivery:
            raise ValueError("model delivery candidate selects another transport")
        if (
            transition.model_delivery_adoption.eligible_tracks == ("model",)
        ) != self.config.model_only:
            raise ValueError("model delivery candidate selects another cohort reward profile")
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
        return await self._run(history, transition)

    async def export_completed(self, history, transition):
        """Export old native receipts through their original authenticated selection.

        This reads metadata and bounded retained documents only. Missing first-pass
        results refuse with repair telemetry; this method never fetches model bytes,
        reserves an adoption, acquires a signer or publishes cohort history.
        """
        return await self._run(history, transition, export_only=True)

    async def seed_shared_completed(self, history, transition):
        """Migrate authenticated completed file facts without payload GETs."""
        return await self._run(history, transition, completed_only=True)

    async def _run(self, history, transition, *, export_only=False, completed_only=False):
        await run_owned_thread(qualify_shared_byte_stores, (self.config.source,))
        value = await run_owned_thread(self.authenticate, history, transition)
        if self.multipart is None:
            loaded = await run_owned_thread(
                load_r2_credentials, Path(self.config.r2_credentials_file)
            )
            self.multipart = R2MultipartClient(
                R2SigV4(loaded.endpoint, self.config.r2_bucket, loaded.credentials),
                timeout_seconds=self.config.r2_timeout_seconds,
            )
        async with r2_connection_scope(self.multipart):
            return await self._verify_selected(
                transition, value, export_only=export_only, completed_only=completed_only
            )

    async def _verify_selected(self, transition, value, *, export_only, completed_only):
        readers = LegacyModelStorageReaders(
            {transition.cohort_sha256: value},
            policy=self.policy,
            load_original=self.originals,
            multipart=self.multipart,
            verification_root=Path(self.config.verification_directory),
            byte_stores={transition.cohort_sha256: self.config.source.shared_byte_store},
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
        work = []
        inventory = ModelWorkInventory()
        models = sorted(selectors)
        with TransferProgress(
            "model_delivery_work_inventory",
            len(models),
            unit="models",
            planning_unit_seconds=(0.01, 1),
        ) as preparation:
            for model in models:
                # Only bounded signed metadata is revisited for planning; no
                # payload or successful byte verdict is read or reconstructed.
                resolution = await run_owned_thread(
                    lambda model=model: readers.resolve(
                        transition.cohort_sha256, **selectors[model]
                    )
                )
                work.append(
                    inventory.add(resolution.selection, metadata_only=export_only or completed_only)
                )
                preparation.advance(1)
        exports = []
        with (
            forecast_subscope(
                cohort=transition.cohort_sha256,
                work_sha256=digest(
                    {
                        "legacy": digest(value.legacy),
                        "preservation": digest(value.preservation),
                        "policy": digest(self.policy),
                        "export_only": export_only,
                        "completed_only": completed_only,
                    }
                ),
                operation="model_delivery_byte_batch",
            ),
            ModelBatchProgress(
                "model_byte_store_authenticated_export"
                if export_only
                else "model_delivery_adoption_remote_review",
                tuple(work),
            ) as progress,
        ):
            for index, model in enumerate(models):
                started = monotonic()
                resolution = await run_owned_thread(
                    lambda model=model: readers.resolve(
                        transition.cohort_sha256, **selectors[model]
                    )
                )
                reader = readers.reader(resolution)
                report = progress.child_report(index)
                if export_only:
                    exports.append(await reader.export_completed(report=report))
                    progress.advance(index, monotonic() - started)
                    continue
                documents = tuple(
                    r.path
                    for r in resolution.selection.bundle.files
                    if r.role in {"license", "provenance"}
                )
                # Retain bounded rights documents during the first byte pass.
                # This does not grant the independent downstream rights review.
                if (
                    sum(
                        r.size_bytes
                        for r in resolution.selection.bundle.files
                        if r.path in documents
                    )
                    > 16 * 1024**2
                ):
                    documents = ()
                snapshot = await reader.verify(
                    document_paths=documents,
                    report=report,
                    completed_only=completed_only,
                )
                await run_owned_thread(reader.require_verified, snapshot)
                progress.advance(index, monotonic() - started)
        return (
            tuple(sorted(exports, key=lambda v: (v.directory, v.export_sha256)))
            if export_only
            else value
        )
