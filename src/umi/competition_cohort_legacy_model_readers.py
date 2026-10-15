"""Common authenticated legacy source for review, execution and settlement.

Construction requires the operator's authenticated committed storage inventories
and the exact retained originals loader. This never grants rights approval or
manufactures a replacement acceptance. Each consumer retains its native checks.
"""

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
from .open_competition import digest
from .private_files import private_path
from .protocol import canonical_json_bytes, sha256_hex


class LegacyModelStorageReaders:
    def __init__(self, authenticated, *, policy, load_original, multipart, verification_root):
        self.authenticated = dict(authenticated)
        self.policy, self.load_original = policy, load_original
        self.multipart, self.verification_root = multipart, verification_root
        private_path(str(verification_root))
        if not callable(load_original) or any(
            key != digest(value.original_history.plan) or digest(value.policy) != digest(policy)
            for key, value in self.authenticated.items()
        ):
            raise ValueError("legacy model readers differ from authenticated cohort policy")

    def has_cohort(self, cohort):
        return cohort in self.authenticated

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

    def accepted(self, cohort, *, record, admission, acceptance):
        """Bind an accepted /1 body to preserved originals; grant no quorum.

        Consumers retain independent private review, certificate signatures and
        phase/finality checks. A genuinely new /1 intent may follow adoption for
        an already admitted original, but an existing intent is never rewritten.
        """
        acceptance = ModelArtifactAcceptance.model_validate_json(canonical_json_bytes(acceptance))
        if acceptance.schema_ != "umi-cohort-model-artifact-acceptance/1":
            raise ValueError("legacy model source requires the unchanged /1 acceptance")
        resolution = self.resolve(cohort, request_sha256=digest(record.request))
        original, authenticated = resolution.originals, self.authenticated[cohort]
        for value, pin in (
            (record, original.participation_raw_sha256),
            (admission, original.admission_raw_sha256),
        ):
            if pin is None or sha256_hex(canonical_json_bytes(value)) != pin:
                raise ValueError("legacy model source changes its original admitted participant")
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
        )
        if not any(
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
                )
                for model in value.preservation.models
            }
            for value in self.authenticated.values()
        ):
            raise ValueError("legacy model reader source is outside its authenticated inventories")
        return ChunkedModelBackupReader(
            selection,
            policy=self.policy,
            multipart=self.multipart,
            verification_root=self.verification_root,
        )
