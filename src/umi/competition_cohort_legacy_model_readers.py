"""Common authenticated legacy source for review, execution and settlement.

Construction requires the operator's authenticated committed storage inventories
and the exact retained originals loader. This never grants rights approval or
manufactures a replacement acceptance. Each consumer retains its native checks.
"""

from pathlib import Path

from .competition_chunked_model_backup import ChunkedBackupSelection, ChunkedModelBackupReader
from .competition_cohort_legacy_model_storage import (
    LegacyModelStorageRepairRequired,
    resolve_legacy_model_storage,
)
from .competition_cohort_model_acceptance import (
    ModelAcceptanceIntent,
    ModelArtifactAcceptance,
    verify_model_acceptance_body,
)
from .competition_cohort_model_static_review import (
    StaticModelReviewHeld,
    build_standing_model_review_from_documents,
    verify_standing_review_policy,
)
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import ensure_private_directory, private_path
from .protocol import canonical_json_bytes, sha256_hex
from .r2_multipart import r2_connection_scope


class LegacyModelStorageReaders:
    def __init__(
        self,
        authenticated,
        *,
        policy,
        load_original,
        multipart,
        verification_root,
        byte_stores=None,
    ):
        self.authenticated = dict(authenticated)
        self.policy, self.load_original = policy, load_original
        self.multipart, self.verification_root = multipart, verification_root
        self.byte_stores = {k: v for k, v in (byte_stores or {}).items() if v is not None}
        if not set(self.byte_stores) <= set(self.authenticated):
            raise ValueError("byte stores require authenticated cohort selections")
        private_path(str(verification_root))
        if not callable(load_original) or any(
            key != digest(value.original_history.plan) or digest(value.policy) != digest(policy)
            for key, value in self.authenticated.items()
        ):
            raise ValueError("legacy model readers differ from authenticated cohort policy")

    def has_cohort(self, cohort):
        return cohort in self.authenticated

    async def review_inputs(self, cohort, bundle, standing):
        """Apply a private standing policy using completed R2 facts and documents.

        Missing byte facts require explicit repair; generating a review must
        never initiate a weight hash pass or materialize the model locally.
        Admission, private rights policy and independent quorum remain separate.
        """
        verify_standing_review_policy(standing, self.policy)
        resolution = self.preserved_reference(cohort, bundle)
        if resolution is None:
            raise ValueError("legacy standing review has no authenticated preserved bundle")
        documents = [
            (i, r) for i, r in enumerate(bundle.files) if r.role in {"license", "provenance"}
        ]
        if any(r.size_bytes > standing.maximum_document_bytes for _, r in documents):
            raise StaticModelReviewHeld("review_document_size_outside_policy")
        if sum(r.size_bytes for _, r in documents) > standing.maximum_total_document_bytes:
            raise StaticModelReviewHeld("review_documents_exceed_total_policy")
        reader = self.reader(resolution)
        contents = {}
        async with r2_connection_scope(self.multipart):
            snapshot = await reader.verify(completed_only=True)
            with TransferProgress(
                "legacy_model_static_review_documents",
                len(documents),
                unit="documents",
                planning_unit_seconds=(0.01, 5.0),
            ) as progress:
                for index, record in documents:
                    contents[record.path] = await reader.read_verified_range(
                        snapshot,
                        file_index=index,
                        offset=0,
                        size_bytes=record.size_bytes,
                    )
                    progress.advance(1)
        return build_standing_model_review_from_documents(bundle, self.policy, standing, contents)

    def resolve(self, cohort, *, request_sha256=None, baseline=False, incumbent_sha256=None):
        try:
            authenticated = self.authenticated[cohort]
        except KeyError as error:
            raise ValueError("legacy model reader has no authenticated cohort selection") from error
        return resolve_legacy_model_storage(
            authenticated,
            load_original=self.load_original,
            endpoint=self.multipart.signer.endpoint,
            bucket=self.multipart.signer.bucket,
            request_sha256=request_sha256,
            baseline=baseline,
            incumbent_sha256=incumbent_sha256,
        )

    def preserved_reference(self, cohort, bundle):
        """Resolve existing authenticated bytes; caller owns reference authority.

        A later certified baseline may already be a preserved participant in
        this frozen inventory. Reuse that exact original and association without
        inventing an incumbent or modifying the signed census. A missing or
        damaged selected original requires repair, never another source guess.
        """
        model = digest(bundle)
        entries = self.authenticated[cohort].legacy.entries
        original = next(
            (
                entry
                for entry in entries
                if entry.model_sha256 == model and entry.payload_state == "preserved"
            ),
            None,
        )
        if original is None:
            return None
        resolved = self.resolve(cohort, request_sha256=original.request_sha256)
        if resolved.selection.bundle != bundle:
            raise ValueError("preserved reference differs from its certified model")
        return resolved

    def admitted(self, cohort, *, record, admission):
        """Resolve only the exact frozen, certified, preserved original."""
        resolution = self.resolve(cohort, request_sha256=digest(record.request))
        original = resolution.originals
        for value, pin in (
            (record, original.participation_raw_sha256),
            (admission, original.admission_raw_sha256),
        ):
            if pin is None or sha256_hex(canonical_json_bytes(value)) != pin:
                raise ValueError("legacy model source changes its original admitted participant")
        return resolution

    def accepted(self, cohort, *, record, admission, acceptance):
        """Bind an accepted /1 body to preserved originals; grant no quorum.

        Consumers retain independent private review, certificate signatures and
        phase/finality checks. A genuinely new /1 intent may follow adoption for
        an already admitted original, but an existing intent is never rewritten.
        """
        acceptance = ModelArtifactAcceptance.model_validate_json(canonical_json_bytes(acceptance))
        if acceptance.schema_ != "umi-cohort-model-artifact-acceptance/1":
            raise ValueError("legacy model source requires the unchanged /1 acceptance")
        resolution = self.admitted(cohort, record=record, admission=admission)
        original, authenticated = resolution.originals, self.authenticated[cohort]
        if original.intent_raw_sha256 is not None:
            try:
                raw = self.load_original(original.intent_raw_sha256)
            except (KeyError, FileNotFoundError) as error:
                raise LegacyModelStorageRepairRequired(
                    "retained legacy acceptance intent is missing; repair required"
                ) from error
            intent = ModelAcceptanceIntent.model_validate_json(raw)
            if (
                sha256_hex(raw) != original.intent_raw_sha256
                or canonical_json_bytes(intent) != raw
                or intent.acceptance != acceptance
            ):
                raise ValueError("legacy model source changes its original acceptance intent")
        elif acceptance.accepted_at_block < authenticated.adoption_block:
            raise ValueError("new legacy acceptance predates its committed storage adoption")
        verify_model_acceptance_body(
            acceptance,
            record,
            authenticated.original_history,
            authenticated.policy,
            maximum_block=acceptance.accepted_at_block,
        )
        return resolution

    def reader(self, resolution):
        selection = ChunkedBackupSelection.model_validate_json(
            canonical_json_bytes(resolution.selection)
        )
        binding = selection.binding
        selected = (
            binding.model_sha256,
            sha256_hex(canonical_json_bytes(selection.bundle)),
            binding.association_sha256,
            selection.association.package_sha256,
            binding.endpoint,
            binding.bucket,
            binding.object_key_prefix,
        )
        matches = [
            cohort
            for cohort, value in self.authenticated.items()
            if (
                binding.provenance_sha256 == digest(value.preservation)
                and selected
                in {
                    (
                        model.model_sha256,
                        model.manifest_raw_sha256,
                        model.association_raw_sha256,
                        model.package_raw_sha256,
                        model.endpoint,
                        model.bucket,
                        model.object_key_prefix,
                    )
                    for model in value.preservation.models
                }
            )
        ]
        if not matches:
            raise ValueError("legacy model reader source is outside its authenticated inventories")
        stores = [self.byte_stores[cohort] for cohort in matches if cohort in self.byte_stores]
        if stores and any(value != stores[0] for value in stores[1:]):
            raise ValueError("authenticated model sources select conflicting byte stores")
        store = stores[0] if stores else None
        if store is not None:
            ensure_private_directory(Path(store.directory))
        return ChunkedModelBackupReader(
            selection,
            policy=self.policy,
            multipart=self.multipart,
            verification_root=self.verification_root if store is None else Path(store.directory),
            byte_store_imports=() if store is None else store.imports,
        )
