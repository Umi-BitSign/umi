"""Real quorum signatures over cohort manifests, never per-model substitutes."""

import json
from types import SimpleNamespace

import pytest

from umi import competition_cohort_model_batch as batch_module
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelAcceptanceBatchManifest,
    model_acceptance_batch_certificates,
    verify_model_acceptance,
    verify_model_acceptance_batch_manifest,
)
from umi.competition_cohort_model_batch import (
    CertifiedModelAcceptanceBatch,
    SignedModelBatchCertificationAdoption,
    build_model_acceptance_batch,
    model_acceptance_batch_proofs,
    prepare_model_batch_certification_adoption,
    verify_model_acceptance_batch_proof,
    verify_model_batch_certification_adoption,
)
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.competition_cohort_settlement_preparation import SettlementArtifactPreparation
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import base_policy as base_policy
from .test_competition_cohort_model_acceptance import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_acceptance import policy as policy
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_acceptance import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_acceptance import recovery as recovery
from .test_competition_cohort_model_acceptance import runtime as runtime
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def batch_case(prepared):
    owner, cohort, submissions, inputs = prepared
    acceptances = tuple(
        owner.prepare(cohort, digest(sub), inputs, capture_at(220)) for sub in submissions
    )
    history = owner.intake.history(cohort)
    adoption = prepare_model_batch_certification_adoption(
        history,
        owner.intake.policy,
        expected_tip_sha256=history_tip(history),
        effective_at_block=221,
    )
    signed = SignedModelBatchCertificationAdoption(
        adoption=adoption, signatures=signatures(adoption)
    )
    body = build_model_acceptance_batch(
        acceptances,
        signed,
        history,
        owner.intake.policy,
        candidate_snapshot_sha256="18" * 32,
        roster_sha256="19" * 32,
        certified_at_block=222,
    )
    certificate = CertifiedModelAcceptanceBatch(
        batch=body, adoption=signed, signatures=signatures(body)
    )
    manifest = ModelAcceptanceBatchManifest(
        schema="umi-cohort-model-acceptance-manifest/1",
        certificate=certificate,
        acceptances=tuple(sorted(acceptances, key=lambda a: a.submission_sha256)),
    )
    return owner, history, manifest


def test_legacy_bytes_and_individual_signatures_are_preserved(batch_case):
    owner, history, manifest = batch_case
    acceptance = manifest.acceptances[0]
    legacy = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=signatures(acceptance)
    )
    expected = canonical_json_bytes(
        {
            "acceptance": acceptance.model_dump(mode="json", by_alias=True),
            "signatures": [s.model_dump(mode="json") for s in legacy.signatures],
        }
    )
    assert canonical_json_bytes(legacy) == expected
    assert (
        canonical_json_bytes(CertifiedModelArtifactAcceptance.model_validate_json(expected))
        == expected
    )
    request = owner.review_request(acceptance.cohort_sha256, acceptance.submission_sha256)
    verify_model_acceptance(legacy, request.record, history, owner.intake.policy, maximum_block=222)
    batch = model_acceptance_batch_certificates(manifest)[0]
    assert batch.signatures == () and "signatures" not in json.loads(canonical_json_bytes(batch))
    with pytest.raises(ValueError, match="exactly one"):
        CertifiedModelArtifactAcceptance(acceptance=acceptance)
    with pytest.raises(ValueError, match="exactly one"):
        CertifiedModelArtifactAcceptance(
            acceptance=acceptance, signatures=legacy.signatures, batch_proof=batch.batch_proof
        )
    fabricated = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=manifest.certificate.signatures
    )
    with pytest.raises(ValueError, match="signature"):
        verify_model_acceptance(
            fabricated, request.record, history, owner.intake.policy, maximum_block=222
        )


def test_every_member_verifies_and_shared_header_is_checked_once(batch_case, monkeypatch):
    owner, history, manifest = batch_case
    batch_module._batch_checks = batch_module.AssignmentVerificationReuse()
    calls = []
    native = batch_module.verify_recovery_quorum

    def counted(body, signatures, policy):
        calls.append(body)
        return native(body, signatures, policy)

    monkeypatch.setattr(batch_module, "verify_recovery_quorum", counted)
    certificates = model_acceptance_batch_certificates(manifest)
    for certificate in certificates:
        a = certificate.acceptance
        request = owner.review_request(a.cohort_sha256, a.submission_sha256)
        verify_model_acceptance(
            certificate, request.record, history, owner.intake.policy, maximum_block=222
        )
    assert calls.count(manifest.certificate.batch) == 1
    assert calls.count(manifest.certificate.adoption.adoption) == 1
    assert (
        verify_model_acceptance_batch_manifest(
            manifest, history, owner.intake.policy, maximum_block=222
        )
        == manifest
    )


@pytest.mark.parametrize("fault", ["member", "sibling", "index", "count", "signature", "early"])
def test_wrong_membership_or_header_is_refused(batch_case, fault):
    owner, history, manifest = batch_case
    certificate = model_acceptance_batch_certificates(manifest)[0]
    a, proof = certificate.acceptance, certificate.batch_proof
    maximum_block = 222
    if fault == "member":
        a = a.model_copy(update={"rights_evidence_sha256": "47" * 32})
    elif fault == "sibling":
        proof = proof.model_copy(update={"siblings": ("47" * 32,)})
    elif fault == "index":
        proof = proof.model_copy(update={"leaf_index": 1 - proof.leaf_index})
    elif fault == "count":
        body = proof.certificate.batch.model_copy(update={"accepted_count": 3})
        proof = proof.model_copy(
            update={
                "certificate": proof.certificate.model_copy(
                    update={"batch": body, "signatures": signatures(body)}
                )
            }
        )
    elif fault == "signature":
        proof = proof.model_copy(
            update={
                "certificate": proof.certificate.model_copy(
                    update={"signatures": proof.certificate.signatures[:1]}
                )
            }
        )
    else:
        maximum_block = 221
    with pytest.raises(ValueError):
        verify_model_acceptance_batch_proof(
            a, proof, history, owner.intake.policy, maximum_block=maximum_block
        )


@pytest.mark.parametrize("fault", ["prefix", "predecessor", "authority", "policy", "future"])
def test_even_resigned_adoption_cannot_change_original_context(batch_case, fault):
    owner, history, manifest = batch_case
    body = manifest.certificate.adoption.adoption
    field = {
        "prefix": "history_prefix_sha256",
        "predecessor": "predecessor_sha256",
        "authority": "authority_sha256",
        "policy": "policy_sha256",
        "future": "effective_at_block",
    }[fault]
    body = body.model_copy(update={field: 223 if fault == "future" else "47" * 32})
    signed = SignedModelBatchCertificationAdoption(adoption=body, signatures=signatures(body))
    with pytest.raises(ValueError):
        verify_model_batch_certification_adoption(
            signed, history, owner.intake.policy, maximum_block=222
        )


def test_history_extension_replays_original_batch_without_rewriting_it(batch_case):
    owner, history, manifest = batch_case
    state = batch_module.verify_cohort_history(
        history, owner.intake.policy, expected_tip_sha256=history_tip(history), current_block=230
    ).state
    closed = propose_recovery_transition(
        state,
        history.authority.authority,
        operation="close_phase",
        observed_at_block=300,
        evidence_sha256="48" * 32,
    )
    later = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(closed))}
    )
    before = canonical_json_bytes(manifest)
    verify_model_acceptance_batch_manifest(manifest, later, owner.intake.policy, maximum_block=222)
    assert canonical_json_bytes(manifest) == before


@pytest.mark.parametrize("count", [0, 1, 3, 512])
def test_empty_single_odd_and_maximum_merkle_geometry(batch_case, count):
    owner, history, original = batch_case
    seed = original.acceptances[0]
    acceptances = tuple(
        seed.model_copy(update={"submission_sha256": f"{i + 1:064x}", "accepted_ordinal": i + 1})
        for i in range(count)
    )
    body = build_model_acceptance_batch(
        acceptances,
        original.certificate.adoption,
        history,
        owner.intake.policy,
        candidate_snapshot_sha256="49" * 32,
        roster_sha256="50" * 32,
        certified_at_block=222,
    )
    certificate = CertifiedModelAcceptanceBatch(
        batch=body, adoption=original.certificate.adoption, signatures=signatures(body)
    )
    proofs = model_acceptance_batch_proofs(acceptances, certificate)
    assert len(proofs) == count
    if proofs:
        assert len(proofs[-1].siblings) <= 9
        assert len(canonical_json_bytes(proofs[-1])) < 16 * 1024
        for i in {0, count - 1}:
            verify_model_acceptance_batch_proof(
                acceptances[i], proofs[i], history, owner.intake.policy, maximum_block=222
            )


def test_batch_signer_cannot_review_any_of_its_own_models(batch_case):
    owner, history, original = batch_case
    acceptance = original.acceptances[0].model_copy(
        update={"recipient_hotkey": wallet("Charlie").hotkey.ss58_address}
    )
    body = build_model_acceptance_batch(
        (acceptance,),
        original.certificate.adoption,
        history,
        owner.intake.policy,
        candidate_snapshot_sha256="49" * 32,
        roster_sha256="50" * 32,
        certified_at_block=222,
    )
    certificate = CertifiedModelAcceptanceBatch(
        batch=body, adoption=original.certificate.adoption, signatures=signatures(body)
    )
    (proof,) = model_acceptance_batch_proofs((acceptance,), certificate)
    with pytest.raises(ValueError, match="own batch"):
        verify_model_acceptance_batch_proof(
            acceptance, proof, history, owner.intake.policy, maximum_block=222
        )


def test_settlement_preparation_requires_independently_selected_history(batch_case, tmp_path):
    owner, history, manifest = batch_case
    certificate = model_acceptance_batch_certificates(manifest)[0]
    a = certificate.acceptance
    request = owner.review_request(a.cohort_sha256, a.submission_sha256)
    root = tmp_path / "publication"
    request_path = (
        root / "model-reward-preparation" / a.cohort_sha256 / (a.submission_sha256 + ".json")
    )
    publish_private_model(request_path, request, maximum_bytes=16 * 1024**2)
    publish_private_model(
        root / "model-reward-acceptances" / a.cohort_sha256 / (a.submission_sha256 + ".json"),
        certificate,
    )
    config = SimpleNamespace(
        policy=owner.intake.policy,
        series=SimpleNamespace(recovery=history.authority, cohorts=(history.plan,)),
    )
    key = "accepted/" + a.cohort_sha256 + "/" + a.submission_sha256
    old = SettlementArtifactPreparation(config, SimpleNamespace(directory=root), {})
    with pytest.raises(ValueError, match="selected original history"):
        old._accepted(key, request_path)
    config.history_directory = str(tmp_path / "history")
    publish_private_model(
        tmp_path / "history" / (a.cohort_sha256 + ".json"),
        CohortOrderHistory(history=history, decisions=()),
    )
    updated = SettlementArtifactPreparation(config, SimpleNamespace(directory=root), {})
    participant, selected = updated._accepted(key, request_path)
    assert participant.record == request.record and selected == certificate
