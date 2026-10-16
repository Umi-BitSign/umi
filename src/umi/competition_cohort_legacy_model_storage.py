"""Authenticate separate R2 storage for unchanged legacy model artifacts.

The signed transport adoption binds two native inventory digests. The first
pins exact original request, participation, admission and /1 acceptance bytes;
the second binds complete model coverage to existing chunked R2 associations.
No legacy signature is rewritten and no direct-upload reservation is invented.

This is a pure consuming boundary. The signing owner must separately establish
its fenced native census, durable remote completion, restore qualification and
consumer release. Neither inventory construction nor this resolver authorizes
admission, model rights, eviction, reservation release, or a production cutover.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chunked_model_backup import (
    ChunkedBackupBinding,
    ChunkedBackupSelection,
    validate_chunked_backup,
)
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelAcceptanceIntent,
    verify_model_acceptance,
    verify_model_acceptance_body,
)
from .competition_cohort_model_transport import prepare_model_delivery_adoption
from .competition_cohort_model_transport_selection import CommittedModelDeliveryHistory
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipationRequest,
    verify_participant_admission,
)
from .competition_cohort_recovery import Block, cohort_model_delivery
from .competition_transport_verification import TransferProgress
from .open_competition import CompetitionPolicy, ModelBundle, digest, validate_bundle_policy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex

MAX_INVENTORY_BYTES = 64 * 1024**2
MAX_ORIGINAL_BYTES = 33 * 1024**2


class LegacyModelStorageRepairRequired(ValueError):
    """Retained storage provenance is missing or damaged; never fall back silently."""


class LegacyModelUploadIncomplete(ValueError):
    """The original signed upload is retained, but has no complete remote payload."""


class LegacyModelOriginals(StrictProtocolModel):
    """Raw SHA pins are distinct from the protocol's domain-separated identities."""

    request_sha256: Hex32
    model_sha256: Hex32
    request_raw_sha256: Hex32
    payload_state: Literal["incomplete_upload", "preserved"]
    participation_raw_sha256: Hex32 | None = None
    admission_raw_sha256: Hex32 | None = None
    intent_raw_sha256: Hex32 | None = None
    certificate_raw_sha256: Hex32 | None = None

    @model_validator(mode="after")
    def original_lineage(self):
        if self.payload_state == "incomplete_upload" and any(
            value is not None
            for value in (
                self.participation_raw_sha256,
                self.admission_raw_sha256,
                self.intent_raw_sha256,
                self.certificate_raw_sha256,
            )
        ):
            raise ValueError("incomplete legacy upload cannot claim participant acceptance")
        if self.admission_raw_sha256 is not None and self.participation_raw_sha256 is None:
            raise ValueError("legacy admission requires its exact retained participation")
        if self.intent_raw_sha256 is not None and self.admission_raw_sha256 is None:
            raise ValueError("legacy acceptance intent requires certified participation")
        if self.certificate_raw_sha256 is not None and self.intent_raw_sha256 is None:
            raise ValueError("legacy acceptance certificate requires its original intent")
        return self


class LegacyModelIncumbent(StrictProtocolModel):
    """Explicit legacy execution prerequisite, never an invented participant."""

    model_sha256: Hex32
    manifest_raw_sha256: Hex32


class LegacyModelStorageInventory(StrictProtocolModel):
    schema_: Literal["umi-cohort-legacy-model-storage-inventory/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    authority_sha256: Hex32
    predecessor_sha256: Hex32
    captured_at_block: Block
    baseline_model_sha256: Hex32
    baseline_manifest_raw_sha256: Hex32
    incumbents: Annotated[tuple[LegacyModelIncumbent, ...], Field(max_length=65536)] = ()
    entries: Annotated[tuple[LegacyModelOriginals, ...], Field(max_length=65536)]

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple(entry.request_sha256 for entry in self.entries)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("legacy storage requests must be unique and identity-sorted")
        models = tuple(incumbent.model_sha256 for incumbent in self.incumbents)
        if models != tuple(sorted(set(models))):
            raise ValueError("legacy storage incumbents must be unique and identity-sorted")
        return self


class LegacyModelPreservation(StrictProtocolModel):
    model_sha256: Hex32
    manifest_raw_sha256: Hex32
    association_raw_sha256: Hex32
    package_raw_sha256: Hex32
    endpoint: Annotated[str, Field(pattern=r"^https://[0-9a-f]{32}\.r2\.cloudflarestorage\.com$")]
    bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]


class LegacyModelPreservationInventory(StrictProtocolModel):
    schema_: Literal["umi-cohort-legacy-model-preservation-inventory/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    authority_sha256: Hex32
    predecessor_sha256: Hex32
    legacy_inventory_sha256: Hex32
    models: Annotated[tuple[LegacyModelPreservation, ...], Field(min_length=1, max_length=131073)]

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple(entry.model_sha256 for entry in self.models)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("legacy preservation models must be unique and identity-sorted")
        return self


@dataclass(frozen=True)
class AuthenticatedLegacyModelStorage:
    """Derived native metadata, not an admission or deletion capability."""

    policy: CompetitionPolicy
    original_history: CohortRecoveryHistory
    adoption_block: int
    legacy: LegacyModelStorageInventory
    preservation: LegacyModelPreservationInventory


@dataclass(frozen=True)
class LegacyModelStorageResolution:
    source_kind: Literal["participant", "baseline", "incumbent"]
    selection: ChunkedBackupSelection
    originals: LegacyModelOriginals | None


def _canonical(raw, model, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise LegacyModelStorageRepairRequired("legacy storage metadata exceeds its retained bound")
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise LegacyModelStorageRepairRequired(
            "legacy storage metadata changed its canonical bytes"
        )
    return value


def authenticate_legacy_storage_inventories(
    legacy_raw: bytes,
    preservation_raw: bytes,
    *,
    selection: CommittedModelDeliveryHistory,
    policy: CompetitionPolicy,
    expected_baseline_sha256: str,
    expected_incumbent_sha256s: tuple[str, ...] = (),
) -> AuthenticatedLegacyModelStorage:
    """Bind complete model coverage to a root-selected committed adoption.

    The caller obtains ``selection`` through native committed history selection,
    and obtains ``expected_baseline_sha256`` from its actual selected baseline or
    certified round. ``expected_incumbent_sha256s`` is the signing owner's census
    of additional selected execution prerequisites at the adoption fence. An
    HTTP request cannot supply any of these authorities. Validating
    these documents does not prove their signing owner's native census complete.
    """
    selected = CommittedModelDeliveryHistory.model_validate_json(canonical_json_bytes(selection))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    history = selected.history
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=selected.committed_tip_sha256,
        current_block=selected.observed_at_block,
    )
    adoption = view.state.model_delivery_adoption
    if (
        adoption is None
        or cohort_model_delivery(history.plan).mechanism != "coordinator_chunked_v1"
    ):
        raise ValueError("legacy model storage requires its committed transport adoption")
    index, signed = next(
        (index, signed)
        for index, signed in enumerate(history.transitions)
        if signed.transition.model_delivery_adoption is not None
    )
    transition = signed.transition
    original = history.model_copy(update={"transitions": history.transitions[:index]})
    return _authenticate_inventories(
        legacy_raw,
        preservation_raw,
        original=original,
        transition=transition,
        policy=policy,
        expected_baseline_sha256=expected_baseline_sha256,
        expected_incumbent_sha256s=expected_incumbent_sha256s,
    )


def authenticate_legacy_storage_proposal(
    legacy_raw,
    preservation_raw,
    *,
    history,
    transition,
    policy,
    expected_baseline_sha256,
    expected_incumbent_sha256s=(),
):
    """Validate unsigned adoption metadata against a verified original prefix.

    Only the issuance path uses this boundary. It supplies neither a committed
    history nor authority to ordinary consumers, admission or eviction.
    """
    if transition.operation != "adopt_model_delivery":
        raise ValueError("legacy storage proposal requires model delivery adoption")
    adoption = transition.model_delivery_adoption
    expected = prepare_model_delivery_adoption(
        history,
        policy,
        expected_tip_sha256=transition.predecessor_sha256,
        current_block=transition.observed_at_block,
        delivery=adoption.delivery,
        legacy_inventory_sha256=adoption.legacy_inventory_sha256,
        preservation_inventory_sha256=adoption.preservation_inventory_sha256,
    )
    if expected != transition:
        raise ValueError("legacy storage proposal differs from native original history")
    return _authenticate_inventories(
        legacy_raw,
        preservation_raw,
        original=history,
        transition=transition,
        policy=policy,
        expected_baseline_sha256=expected_baseline_sha256,
        expected_incumbent_sha256s=expected_incumbent_sha256s,
    )


def _authenticate_inventories(
    legacy_raw,
    preservation_raw,
    *,
    original,
    transition,
    policy,
    expected_baseline_sha256,
    expected_incumbent_sha256s,
):
    history = original
    adoption = transition.model_delivery_adoption
    legacy = _canonical(legacy_raw, LegacyModelStorageInventory, MAX_INVENTORY_BYTES)
    preservation = _canonical(
        preservation_raw, LegacyModelPreservationInventory, MAX_INVENTORY_BYTES
    )
    if (
        digest(legacy) != adoption.legacy_inventory_sha256
        or digest(preservation) != adoption.preservation_inventory_sha256
        or preservation.legacy_inventory_sha256 != digest(legacy)
    ):
        raise ValueError("legacy model storage differs from its authenticated inventories")
    for inventory in (legacy, preservation):
        if (
            inventory.cohort_sha256 != digest(history.plan)
            or inventory.policy_sha256 != digest(policy)
            or inventory.authority_sha256 != digest(history.authority.authority)
            or inventory.predecessor_sha256 != transition.predecessor_sha256
        ):
            raise ValueError("legacy storage inventory has another cohort, policy or predecessor")
    if (
        legacy.baseline_model_sha256 != expected_baseline_sha256
        or not original.genesis.admitted_at_block
        <= legacy.captured_at_block
        <= transition.observed_at_block
    ):
        raise ValueError("legacy storage inventory differs from its selected baseline or clock")
    if {value.model_sha256 for value in legacy.incumbents} != set(expected_incumbent_sha256s):
        raise ValueError("legacy storage inventory differs from its selected execution incumbents")
    models = {entry.model_sha256: entry for entry in preservation.models}
    if set(models) != {
        legacy.baseline_model_sha256,
        *(incumbent.model_sha256 for incumbent in legacy.incumbents),
        *(entry.model_sha256 for entry in legacy.entries if entry.payload_state == "preserved"),
    }:
        raise ValueError("legacy preservation inventory has incomplete or unrelated model coverage")
    if (
        models[legacy.baseline_model_sha256].manifest_raw_sha256
        != legacy.baseline_manifest_raw_sha256
    ):
        raise ValueError("legacy preservation changes its explicit baseline manifest")
    if any(
        models[value.model_sha256].manifest_raw_sha256 != value.manifest_raw_sha256
        for value in legacy.incumbents
    ):
        raise ValueError("legacy preservation changes an explicit incumbent manifest")
    return AuthenticatedLegacyModelStorage(
        policy, original, transition.observed_at_block, legacy, preservation
    )


def _original(load_original: Callable[[str], bytes], key: str, *, maximum=MAX_ORIGINAL_BYTES):
    try:
        raw = load_original(key)
    except (KeyError, FileNotFoundError) as error:
        raise LegacyModelStorageRepairRequired(
            "retained legacy original is missing; repair required"
        ) from error
    if type(raw) is not bytes or not 0 < len(raw) <= maximum or sha256_hex(raw) != key:
        raise LegacyModelStorageRepairRequired(
            "retained legacy original changed identity; repair required"
        )
    return raw


def _verify_participant(authenticated, entry, load_original):
    policy, history = authenticated.policy, authenticated.original_history
    request = _canonical(
        _original(load_original, entry.request_raw_sha256, maximum=4 * 1024**2),
        CohortParticipationRequest,
        4 * 1024**2,
    )
    sub, consent = request.signed_submission.submission, request.consent.consent
    if (
        digest(request) != entry.request_sha256
        or sub.track != "model"
        or sub.model_revision != entry.model_sha256
        or sub.policy_sha256 != digest(policy)
        or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
        or consent.cohort_sha256 != digest(history.plan)
        or consent.authority_sha256 != digest(history.authority.authority)
        or not history.authority.authority.issued_at_block
        <= consent.signed_at_block
        <= authenticated.legacy.captured_at_block
        or not policy.valid_from_block
        <= sub.valid_from_block
        < sub.valid_through_block
        <= policy.valid_through_block
        or sub.valid_through_block - sub.valid_from_block
        > policy.maximum_submission_lifetime_blocks
        or sub.valid_from_block > authenticated.legacy.captured_at_block
    ):
        raise ValueError("legacy storage request differs from its original cohort or policy")
    validate_bundle_policy(sub.model_bundle, policy)
    record = admission = intent = None
    if entry.participation_raw_sha256 is not None:
        record = read_participation(_original(load_original, entry.participation_raw_sha256))
        if record.request != request:
            raise ValueError("legacy storage participation changes the original request")
        replay_participation(record, history, policy)
        if record.observation.block > authenticated.legacy.captured_at_block:
            raise ValueError("legacy storage participation is newer than its inventory")
    if entry.admission_raw_sha256 is not None:
        admission = _canonical(
            _original(load_original, entry.admission_raw_sha256),
            AttestedCohortParticipantAdmission,
            128 * 1024,
        )
        verify_participant_admission(
            admission,
            request.signed_submission,
            request.consent,
            history,
            policy,
            record.snapshot,
            expected_tip_sha256=authenticated.legacy.predecessor_sha256,
            current_block=authenticated.adoption_block,
        )
        if admission.admission != record.proposed_admission:
            raise ValueError("legacy storage admission differs from its retained participation")
    if entry.intent_raw_sha256 is not None:
        intent = _canonical(
            _original(load_original, entry.intent_raw_sha256),
            ModelAcceptanceIntent,
            MAX_ORIGINAL_BYTES,
        )
        if intent.acceptance.schema_ != "umi-cohort-model-artifact-acceptance/1":
            raise ValueError("legacy storage cannot replace a direct model acceptance")
        verify_model_acceptance_body(
            intent.acceptance,
            record,
            history,
            policy,
            maximum_block=authenticated.legacy.captured_at_block,
        )
    if entry.certificate_raw_sha256 is not None:
        certificate = _canonical(
            _original(load_original, entry.certificate_raw_sha256),
            CertifiedModelArtifactAcceptance,
            256 * 1024,
        )
        if certificate.acceptance != intent.acceptance:
            raise ValueError("legacy storage certificate changes its original acceptance intent")
        verify_model_acceptance(
            certificate,
            record,
            history,
            policy,
            maximum_block=authenticated.legacy.captured_at_block,
        )
    return sub.model_bundle


def resolve_legacy_model_storage(
    authenticated: AuthenticatedLegacyModelStorage,
    *,
    load_original: Callable[[str], bytes],
    endpoint: str,
    bucket: str,
    request_sha256: str | None = None,
    baseline: bool = False,
    incumbent_sha256: str | None = None,
) -> LegacyModelStorageResolution:
    """Read only one selected model's metadata; return no fabricated acceptance."""
    if sum((baseline, request_sha256 is not None, incumbent_sha256 is not None)) != 1:
        raise ValueError("select exactly one legacy participant, baseline or execution incumbent")
    entry = None
    if baseline or incumbent_sha256 is not None:
        if baseline:
            model = authenticated.legacy.baseline_model_sha256
            manifest_sha256 = authenticated.legacy.baseline_manifest_raw_sha256
        else:
            incumbent = next(
                (
                    value
                    for value in authenticated.legacy.incumbents
                    if value.model_sha256 == incumbent_sha256
                ),
                None,
            )
            if incumbent is None:
                raise ValueError(
                    "legacy incumbent is outside the authenticated execution inventory"
                )
            model, manifest_sha256 = incumbent.model_sha256, incumbent.manifest_raw_sha256
        bundle = _canonical(
            _original(load_original, manifest_sha256),
            ModelBundle,
            16 * 1024**2,
        )
        if digest(bundle) != model:
            raise ValueError("legacy execution manifest differs from the selected model")
    else:
        entry = next(
            (e for e in authenticated.legacy.entries if e.request_sha256 == request_sha256), None
        )
        if entry is None:
            raise ValueError("legacy storage request is outside the authenticated inventory")
        bundle = _verify_participant(authenticated, entry, load_original)
        if entry.payload_state == "incomplete_upload":
            raise LegacyModelUploadIncomplete(
                "legacy upload remains incomplete; resume its original signed request"
            )
        model = entry.model_sha256
    preserved = next(e for e in authenticated.preservation.models if e.model_sha256 == model)
    if (endpoint, bucket) != (preserved.endpoint, preserved.bucket):
        raise ValueError(
            "legacy storage provider namespace differs from its authenticated inventory"
        )
    manifest_raw = _original(load_original, preserved.manifest_raw_sha256)
    if canonical_json_bytes(bundle) != manifest_raw:
        raise ValueError("legacy backup manifest differs from the original signed model")
    binding = ChunkedBackupBinding(
        schema="umi-chunked-model-backup-binding/1",
        association_sha256=preserved.association_raw_sha256,
        model_sha256=model,
        policy_sha256=authenticated.legacy.policy_sha256,
        provenance_sha256=digest(authenticated.preservation),
        endpoint=preserved.endpoint,
        bucket=preserved.bucket,
    )
    selected = validate_chunked_backup(
        _original(load_original, preserved.association_raw_sha256),
        _original(load_original, preserved.package_raw_sha256, maximum=MAX_INVENTORY_BYTES),
        manifest_raw,
        policy=authenticated.policy,
        binding=binding,
    )
    kind = (
        "baseline" if baseline else "incumbent" if incumbent_sha256 is not None else "participant"
    )
    return LegacyModelStorageResolution(kind, selected, entry)


def verify_legacy_storage_originals(authenticated, *, load_original, endpoint, bucket, report=None):
    """Check all pinned metadata with counted progress; no R2 bytes or payloads.

    Signing-side preparation must additionally compare this complete inventory
    to the fenced native census. This function cannot prove that local census
    completeness from a caller-supplied list alone.
    """
    progress = TransferProgress(
        "legacy_model_storage_originals",
        len(authenticated.legacy.entries) + len(authenticated.legacy.incumbents) + 1,
        report,
        unit="items",
        planning_unit_seconds=(0.001, 1.0),
    )
    try:
        with progress:
            resolve_legacy_model_storage(
                authenticated,
                load_original=load_original,
                endpoint=endpoint,
                bucket=bucket,
                baseline=True,
            )
            progress.advance(1)
            for incumbent in authenticated.legacy.incumbents:
                resolve_legacy_model_storage(
                    authenticated,
                    load_original=load_original,
                    endpoint=endpoint,
                    bucket=bucket,
                    incumbent_sha256=incumbent.model_sha256,
                )
                progress.advance(1)
            for entry in authenticated.legacy.entries:
                if entry.payload_state == "incomplete_upload":
                    _verify_participant(authenticated, entry, load_original)
                else:
                    resolve_legacy_model_storage(
                        authenticated,
                        load_original=load_original,
                        endpoint=endpoint,
                        bucket=bucket,
                        request_sha256=entry.request_sha256,
                    )
                progress.advance(1)
    except LegacyModelStorageRepairRequired:
        progress.emit("repair_required", reason="retained_legacy_original_missing_or_damaged")
        raise
