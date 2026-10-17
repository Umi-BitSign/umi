"""Signed legacy originals and separate R2 provenance survive transport adoption.

Adoption authority and storage are synthetic. Originals are exact bytes retained
by the native intake/acceptance owners, not fabricated direct-upload records.
"""

import json
from types import SimpleNamespace

import pytest

from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_legacy_model_storage import (
    LegacyModelIncumbent,
    LegacyModelOriginals,
    LegacyModelPreservation,
    LegacyModelPreservationInventory,
    LegacyModelStorageInventory,
    LegacyModelStorageRepairRequired,
    LegacyModelUploadIncomplete,
    authenticate_legacy_storage_inventories,
    resolve_legacy_model_storage,
    verify_legacy_storage_originals,
)
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_model_transport_selection import CommittedModelDeliveryHistory
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import certify
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_recovery import signed_transition
from .test_open_competition import bundle_at

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]

ENDPOINT = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
BUCKET = "umi-model-artifacts"


def retain(objects, value):
    raw = value if isinstance(value, bytes) else canonical_json_bytes(value)
    key = sha256_hex(raw)
    objects[key] = raw
    return key


def backup(objects, bundle, policy):
    # These fixture files are smaller than one retained 8 MiB chunk. No remote
    # read or fabricated proof of payload completeness occurs in this test.
    assert all(f.size_bytes <= 8 * 1024**2 for f in bundle.files)
    package = {
        "schema": "umi-cohort-model-preserved-package/1",
        "model_sha256": digest(bundle),
        "native_bundle": bundle.model_dump(mode="json", by_alias=True),
        "files": [
            {"path": f.path, "chunks": [{"sha256": f.sha256, "size_bytes": f.size_bytes}]}
            for f in bundle.files
        ],
        "chunk_bytes": 8 * 1024**2,
        "policy_sha256": digest(policy),
        "source": "verified_native_c5_artifact_archive",
        "rights_approved": False,
        "benchmark_certified": False,
        "rewards_authorized": False,
    }
    package_hash = retain(objects, package)
    association = {
        "schema": "umi-cohort-model-backup-association/1",
        "model_sha256": digest(bundle),
        "package_key": f"packages/{digest(bundle)}/{package_hash}.json",
        "package_sha256": package_hash,
        "verification": "all_declared_bytes_uploaded_and_read_back",
        "artifact_acceptance_certified": False,
    }
    return LegacyModelPreservation(
        model_sha256=digest(bundle),
        manifest_raw_sha256=retain(objects, bundle),
        association_raw_sha256=retain(objects, association),
        package_raw_sha256=package_hash,
        endpoint=ENDPOINT,
        bucket=BUCKET,
    )


@pytest.fixture
def case(prepared, tmp_path):
    owner, cohort, subs, inputs = prepared
    publications = [owner.publish(certify(owner, cohort, subs[0], inputs), capture_at(220))]
    owner.prepare(cohort, digest(subs[1]), inputs, capture_at(220))
    requests = [owner.review_request(cohort, digest(sub)) for sub in subs]
    history, policy = owner.intake.history(cohort), owner.intake.policy
    objects, originals = {}, []
    for i, (sub, request) in enumerate(zip(subs, requests, strict=True)):
        with owner.intake._connection() as (db, _):
            participation = db.execute(
                "SELECT body FROM cohort_consents WHERE cohort=? AND consent=?",
                (cohort, request.record.proposed_admission.consent_sha256),
            ).fetchone()[0]
            admission = db.execute(
                "SELECT body FROM cohort_admission_certificates WHERE consent=?",
                (request.record.proposed_admission.consent_sha256,),
            ).fetchone()[0]
            intent = db.execute(
                "SELECT body FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
                (cohort, digest(sub)),
            ).fetchone()[0]
        originals.append(
            LegacyModelOriginals(
                request_sha256=digest(request.record.request),
                model_sha256=sub.model_revision,
                request_raw_sha256=retain(objects, request.record.request),
                payload_state="preserved",
                participation_raw_sha256=retain(objects, participation),
                admission_raw_sha256=retain(objects, admission),
                intent_raw_sha256=retain(objects, intent),
                certificate_raw_sha256=retain(objects, publications[0].certificate)
                if i == 0
                else None,
            )
        )
    baseline = bundle_at(tmp_path / "separate-baseline", "independent-baseline")
    common = dict(
        cohort_sha256=cohort,
        policy_sha256=digest(policy),
        authority_sha256=digest(history.authority.authority),
        predecessor_sha256=history_tip(history),
    )
    legacy = LegacyModelStorageInventory(
        schema="umi-cohort-legacy-model-storage-inventory/1",
        **common,
        captured_at_block=220,
        baseline_model_sha256=digest(baseline),
        baseline_manifest_raw_sha256=retain(objects, baseline),
        entries=tuple(sorted(originals, key=lambda x: x.request_sha256)),
    )
    models = [backup(objects, b, policy) for b in (baseline, subs[0].model_bundle)]
    preservation = LegacyModelPreservationInventory(
        schema="umi-cohort-legacy-model-preservation-inventory/1",
        **common,
        legacy_inventory_sha256=digest(legacy),
        models=tuple(sorted(models, key=lambda x: x.model_sha256)),
    )
    return SimpleNamespace(
        owner=owner,
        cohort=cohort,
        policy=policy,
        history=history,
        objects=objects,
        requests=requests,
        legacy=legacy,
        preservation=preservation,
        baseline=baseline,
        subs=subs,
    )


def adoption(case, legacy=None, preservation=None, *, block=221):
    legacy, preservation = legacy or case.legacy, preservation or case.preservation
    proposal = prepare_model_delivery_adoption(
        case.history,
        case.policy,
        expected_tip_sha256=history_tip(case.history),
        current_block=block,
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=5 * 1024**2,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        ),
        legacy_inventory_sha256=digest(legacy),
        preservation_inventory_sha256=digest(preservation),
    )
    history = case.history.model_copy(
        update={"transitions": (*case.history.transitions, signed_transition(proposal))}
    )
    # Native publication establishes the commit, rather than merely presenting
    # signatures. Preparing a pending history is tested independently below.
    case.owner.intake.publish(history, capture_at(block))
    return CommittedModelDeliveryHistory(
        schema="umi-committed-model-delivery-history/1",
        history=history,
        committed_tip_sha256=history_tip(history),
        observed_at_block=block,
    )


def authenticated(case, *, legacy=None, preservation=None, selection=None, **changes):
    legacy, preservation = legacy or case.legacy, preservation or case.preservation
    return authenticate_legacy_storage_inventories(
        canonical_json_bytes(legacy),
        canonical_json_bytes(preservation),
        selection=selection or adoption(case, legacy, preservation),
        policy=changes.get("policy", case.policy),
        expected_baseline_sha256=changes.get("baseline", digest(case.baseline)),
        expected_incumbent_sha256s=changes.get("incumbents", ()),
    )


def resolve(case, auth, **kwargs):
    return resolve_legacy_model_storage(
        auth,
        load_original=case.objects.__getitem__,
        endpoint=kwargs.pop("endpoint", ENDPOINT),
        bucket=kwargs.pop("bucket", BUCKET),
        **kwargs,
    )


def test_preserved_namespace_prefix_is_authenticated_and_resolved_without_rewriting_originals(case):
    original = canonical_json_bytes(case.preservation)
    assert b"object_key_prefix" not in original
    assert (
        canonical_json_bytes(LegacyModelPreservationInventory.model_validate_json(original))
        == original
    )
    preservation = case.preservation.model_copy(
        update={
            "models": tuple(
                model.model_copy(update={"object_key_prefix": "preservation/v1/"})
                for model in case.preservation.models
            )
        }
    )
    auth = authenticated(case, preservation=preservation)
    result = resolve(case, auth, baseline=True)
    assert result.selection.binding.object_key_prefix == "preservation/v1/"
    assert (
        canonical_json_bytes(result.selection.bundle)
        == case.objects[
            next(
                model.manifest_raw_sha256
                for model in preservation.models
                if model.model_sha256 == digest(case.baseline)
            )
        ]
    )
    with pytest.raises(ValueError):
        authenticated(case, preservation=preservation, selection=adoption(case))


def test_original_native_intents_certificates_and_signed_bytes_survive_adoption(case):
    originals = dict(case.objects)
    auth = authenticated(case)
    for entry in case.legacy.entries:
        result = resolve(case, auth, request_sha256=entry.request_sha256)
        assert result.source_kind == "participant"
        assert result.originals == entry
        assert digest(result.selection.bundle) == entry.model_sha256
        assert result.selection.binding.provenance_sha256 == digest(case.preservation)
        assert result.selection.package.rewards_authorized is False
    baseline = resolve(case, auth, baseline=True)
    assert baseline.originals is None
    assert baseline.source_kind == "baseline"
    assert digest(baseline.selection.bundle) == digest(case.baseline)
    assert digest(case.baseline) != case.subs[0].model_revision
    assert case.objects == originals
    assert canonical_json_bytes(auth.original_history) == canonical_json_bytes(case.history)
    # Reconstructed consuming boundary reuses exactly the same immutable inputs.
    restarted = authenticated(case, selection=adoption(case))
    assert resolve(case, restarted, baseline=True) == baseline


@pytest.mark.parametrize(
    "field", ["cohort_sha256", "policy_sha256", "authority_sha256", "predecessor_sha256"]
)
@pytest.mark.parametrize("target", ["legacy", "preservation"])
def test_even_signed_wrong_inventory_binding_refuses(case, target, field):
    legacy, preservation = case.legacy, case.preservation
    if target == "legacy":
        legacy = legacy.model_copy(update={field: "34" * 32})
        preservation = preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    else:
        preservation = preservation.model_copy(update={field: "34" * 32})
    with pytest.raises(ValueError, match="cohort, policy or predecessor"):
        authenticated(case, legacy=legacy, preservation=preservation)


def test_expected_baseline_is_selected_independently_of_inventory(case):
    with pytest.raises(ValueError, match="baseline or clock"):
        authenticated(case, baseline="34" * 32)


@pytest.mark.parametrize("block", [0, 222])
def test_inventory_clock_outside_authenticated_history_refuses(case, block):
    legacy = case.legacy.model_copy(update={"captured_at_block": block})
    preservation = case.preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    with pytest.raises(ValueError, match="baseline or clock"):
        authenticated(case, legacy=legacy, preservation=preservation)


@pytest.mark.parametrize("target", ["legacy", "preservation"])
def test_inventory_change_not_authorized_by_signed_adoption_refuses(case, target):
    selected = adoption(case)
    if target == "legacy":
        legacy = case.legacy.model_copy(update={"captured_at_block": 219})
        preservation = case.preservation
    else:
        legacy = case.legacy
        preservation = case.preservation.model_copy(update={"legacy_inventory_sha256": "34" * 32})
    with pytest.raises(ValueError, match="authenticated inventories"):
        authenticated(case, legacy=legacy, preservation=preservation, selection=selected)


@pytest.mark.parametrize("mode", ["missing", "extra"])
def test_association_inventory_coverage_is_exact(case, mode):
    models = list(case.preservation.models)
    if mode == "missing":
        models.pop()
    else:
        models.append(models[0].model_copy(update={"model_sha256": "34" * 32}))
    preservation = case.preservation.model_copy(
        update={"models": tuple(sorted(models, key=lambda x: x.model_sha256))}
    )
    with pytest.raises(ValueError, match="model coverage"):
        authenticated(case, preservation=preservation)


@pytest.mark.parametrize("field", ["endpoint", "bucket"])
def test_provider_namespace_must_match_the_authenticated_inventory(case, field):
    auth = authenticated(case)
    changed = {
        field: "https://fedcba9876543210fedcba9876543210.r2.cloudflarestorage.com"
        if field == "endpoint"
        else "other-model-artifacts"
    }
    with pytest.raises(ValueError, match="provider namespace"):
        resolve(case, auth, baseline=True, **changed)


@pytest.mark.parametrize(
    "field",
    [
        "request_raw_sha256",
        "participation_raw_sha256",
        "admission_raw_sha256",
        "intent_raw_sha256",
        "certificate_raw_sha256",
    ],
)
@pytest.mark.parametrize("mode", ["missing", "changed"])
def test_missing_or_corrupt_original_is_explicit_repair(case, field, mode):
    auth = authenticated(case)
    entry = next(e for e in case.legacy.entries if e.certificate_raw_sha256 is not None)
    key = getattr(entry, field)
    if mode == "missing":
        case.objects.pop(key)
    else:
        case.objects[key] += b"\n"
    with pytest.raises(LegacyModelStorageRepairRequired, match="repair required"):
        resolve(case, auth, request_sha256=entry.request_sha256)


def test_invalid_request_signature_cannot_be_hidden_inside_signed_inventory(case):
    original = case.legacy.entries[0]
    request = json.loads(case.objects[original.request_raw_sha256])
    request["consent"]["signature"]["signature"] = "0x" + "00" * 64
    entry = original.model_copy(update={"request_raw_sha256": retain(case.objects, request)})
    legacy = case.legacy.model_copy(update={"entries": (entry, *case.legacy.entries[1:])})
    preservation = case.preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    auth = authenticated(case, legacy=legacy, preservation=preservation)
    with pytest.raises(ValueError):
        resolve(case, auth, request_sha256=entry.request_sha256)


def test_incomplete_upload_is_preserved_as_pending_not_fabricated_restorable_model(case):
    entries = tuple(
        LegacyModelOriginals(
            request_sha256=e.request_sha256,
            model_sha256=e.model_sha256,
            request_raw_sha256=e.request_raw_sha256,
            payload_state="incomplete_upload",
        )
        for e in case.legacy.entries
    )
    legacy = case.legacy.model_copy(update={"entries": entries})
    preservation = case.preservation.model_copy(
        update={
            "legacy_inventory_sha256": digest(legacy),
            "models": tuple(
                m for m in case.preservation.models if m.model_sha256 == digest(case.baseline)
            ),
        }
    )
    auth = authenticated(case, legacy=legacy, preservation=preservation)
    with pytest.raises(LegacyModelUploadIncomplete, match="original signed request"):
        resolve(case, auth, request_sha256=entries[0].request_sha256)
    progress = []
    verify_legacy_storage_originals(
        auth,
        load_original=case.objects.__getitem__,
        endpoint=ENDPOINT,
        bucket=BUCKET,
        report=progress.append,
    )
    assert progress[-1]["status"] == "completed"
    assert progress[-1]["completed_units"] == 3
    assert progress[-1]["total_units"] == 3
    assert any(p.get("eta_basis") for p in progress)


def test_incomplete_upload_cannot_claim_certified_acceptance(case):
    entry = case.legacy.entries[0]
    with pytest.raises(ValueError, match="incomplete legacy upload"):
        LegacyModelOriginals.model_validate_json(
            canonical_json_bytes(entry.model_copy(update={"payload_state": "incomplete_upload"}))
        )


def test_inventory_without_committed_adoption_is_not_selectable(case):
    selection = CommittedModelDeliveryHistory(
        schema="umi-committed-model-delivery-history/1",
        history=case.history,
        committed_tip_sha256=history_tip(case.history),
        observed_at_block=220,
    )
    with pytest.raises(ValueError, match="committed transport adoption"):
        authenticated(case, selection=selection)


def test_signed_adoption_cannot_replace_older_committed_tip(case):
    selection = adoption(case).model_copy(
        update={"committed_tip_sha256": history_tip(case.history)}
    )
    with pytest.raises(ValueError):
        authenticated(case, selection=selection)


@pytest.mark.parametrize(
    "args", [{}, {"baseline": True, "request_sha256": "34" * 32}, {"request_sha256": "34" * 32}]
)
def test_no_implicit_baseline_or_unknown_participant_fallback(case, args):
    auth = authenticated(case)
    with pytest.raises(ValueError):
        resolve(case, auth, **args)


def test_explicit_incumbent_is_distinct_from_baseline_and_candidate(case, tmp_path):
    incumbent = bundle_at(tmp_path / "execution-incumbent", "different-certified-winner")
    model = digest(incumbent)
    pin = LegacyModelIncumbent(
        model_sha256=model, manifest_raw_sha256=retain(case.objects, incumbent)
    )
    legacy = case.legacy.model_copy(update={"incumbents": (pin,)})
    preservation = case.preservation.model_copy(
        update={
            "legacy_inventory_sha256": digest(legacy),
            "models": tuple(
                sorted(
                    (*case.preservation.models, backup(case.objects, incumbent, case.policy)),
                    key=lambda m: m.model_sha256,
                )
            ),
        }
    )
    auth = authenticated(case, legacy=legacy, preservation=preservation, incumbents=(model,))
    result = resolve(case, auth, incumbent_sha256=model)
    assert result.source_kind == "incumbent"
    assert result.originals is None
    assert digest(result.selection.bundle) == model
    assert model not in {digest(case.baseline), case.subs[0].model_revision}
    assert resolve(case, auth, baseline=True).selection.bundle == case.baseline
    progress = []
    verify_legacy_storage_originals(
        auth,
        load_original=case.objects.__getitem__,
        endpoint=ENDPOINT,
        bucket=BUCKET,
        report=progress.append,
    )
    assert progress[-1]["completed_units"] == 4
    with pytest.raises(ValueError, match="execution incumbents"):
        authenticated(
            case,
            legacy=legacy,
            preservation=preservation,
            selection=adoption(case, legacy, preservation),
        )
    with pytest.raises(ValueError, match="outside the authenticated execution inventory"):
        resolve(case, auth, incumbent_sha256="34" * 32)


def test_missing_selected_incumbent_never_falls_back_to_baseline(case):
    with pytest.raises(ValueError, match="execution incumbents"):
        authenticated(case, incumbents=("34" * 32,))


@pytest.mark.parametrize(
    "field", ["association_raw_sha256", "package_raw_sha256", "manifest_raw_sha256"]
)
def test_missing_backup_metadata_requires_repair_not_local_fallback(case, field):
    auth = authenticated(case)
    model = next(m for m in case.preservation.models if m.model_sha256 == digest(case.baseline))
    del case.objects[getattr(model, field)]
    with pytest.raises(LegacyModelStorageRepairRequired, match="repair required"):
        resolve(case, auth, baseline=True)


@pytest.mark.parametrize("fault", ["bad_signature", "different_body", "one_vote"])
def test_original_certificate_is_verified_not_merely_hash_matched(case, fault):
    entry = next(e for e in case.legacy.entries if e.certificate_raw_sha256 is not None)
    certificate = json.loads(case.objects[entry.certificate_raw_sha256])
    if fault == "bad_signature":
        certificate["signatures"][0]["signature"] = "0x" + "00" * 64
    elif fault == "different_body":
        certificate["acceptance"]["accepted_ordinal"] += 1
    else:
        certificate["signatures"] = certificate["signatures"][:1]
    changed = entry.model_copy(update={"certificate_raw_sha256": retain(case.objects, certificate)})
    legacy = case.legacy.model_copy(
        update={"entries": tuple(changed if e == entry else e for e in case.legacy.entries)}
    )
    preservation = case.preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    auth = authenticated(case, legacy=legacy, preservation=preservation)
    with pytest.raises(ValueError):
        resolve(case, auth, request_sha256=entry.request_sha256)


def test_direct_acceptance_cannot_be_grafted_onto_legacy_originals(case):
    from umi.competition_cohort_direct_model_upload import (
        DirectModelPayload,
        DirectModelUploadReservation,
        SignedDirectModelUploadReservation,
        direct_model_object_key,
    )
    from umi.open_competition import sign_object

    from .test_open_competition import wallet

    entry = case.legacy.entries[0]
    request = next(
        r.record.request for r in case.requests if digest(r.record.request) == entry.request_sha256
    )
    sub = request.signed_submission.submission
    attempt = "a1" * 32
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=entry.request_sha256,
        model_sha256=entry.model_sha256,
        payload_sha256="b2" * 32,
        total_bytes=sum(f.size_bytes for f in sub.model_bundle.files),
        file_count=len(sub.model_bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=case.cohort,
        hotkey=sub.hotkey,
        payload=payload,
        attempt_id=attempt,
        generation=1,
        object_key_sha256=sha256_hex(
            direct_model_object_key(case.cohort, entry.request_sha256, attempt).encode()
        ),
        provider_upload_id_sha256="c3" * 32,
        created_at_unix_ms=1_800_000_000_000,
    )
    signed = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    intent = json.loads(case.objects[entry.intent_raw_sha256])
    intent["acceptance"]["schema"] = "umi-cohort-model-artifact-acceptance/2"
    intent["acceptance"]["direct_artifact"] = signed.model_dump(mode="json", by_alias=True)
    changed = entry.model_copy(update={"intent_raw_sha256": retain(case.objects, intent)})
    legacy = case.legacy.model_copy(
        update={"entries": tuple(changed if e == entry else e for e in case.legacy.entries)}
    )
    preservation = case.preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    auth = authenticated(case, legacy=legacy, preservation=preservation)
    with pytest.raises(ValueError, match="cannot replace a direct model acceptance"):
        resolve(case, auth, request_sha256=entry.request_sha256)


def test_damaged_original_reports_repair_and_withdraws_success_eta(case):
    auth = authenticated(case)
    del case.objects[case.legacy.baseline_manifest_raw_sha256]
    progress = []
    with pytest.raises(LegacyModelStorageRepairRequired):
        verify_legacy_storage_originals(
            auth,
            load_original=case.objects.__getitem__,
            endpoint=ENDPOINT,
            bucket=BUCKET,
            report=progress.append,
        )
    assert progress[-1]["status"] == "repair_required"
    assert progress[-1]["reason_code"] == "retained_legacy_original_missing_or_damaged"
    assert progress[-1]["eta_seconds"] is None
    assert progress[-1]["eta_basis"] == "withdrawn_stalled_or_retrying"
    assert progress[-1]["completed_units"] == 0
    assert progress[-1]["total_units"] == 3
