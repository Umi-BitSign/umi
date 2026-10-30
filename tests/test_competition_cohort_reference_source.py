"""Original certified winner metadata is reusable without a local review intent."""

import asyncio
import json
from threading import Event

import pytest

from umi import competition_cohort_model_execution_source as sources
from umi.competition_cohort_baseline_review import CohortBaselineReview
from umi.competition_cohort_baseline_types import CohortBaselineCandidate
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
    direct_model_object_key,
)
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_model_acceptance import CertifiedModelArtifactAcceptance
from umi.competition_cohort_model_batch import (
    CertifiedModelAcceptanceBatch,
    SignedModelBatchCertificationAdoption,
    build_model_acceptance_batch,
    model_acceptance_batch_proofs,
    prepare_model_batch_certification_adoption,
)
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_settlement import PromotionHeadBinding
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_cohort_model_execution_source import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_execution_source import (
    certified as certified,
)
from .test_competition_cohort_model_execution_source import (
    execution as execution,
)
from .test_competition_cohort_model_execution_source import (
    harness as harness,
)
from .test_competition_cohort_model_execution_source import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_execution_source import (
    policy as policy,
)
from .test_competition_cohort_model_execution_source import (
    receipt_scenario as original_receipt_scenario,
)
from .test_competition_cohort_model_execution_source import (
    recovery as recovery,
)
from .test_competition_cohort_model_execution_source import (
    relay as relay,
)
from .test_competition_cohort_model_execution_source import (
    runtime as runtime,
)
from .test_competition_cohort_model_execution_source import (
    scenario as scenario,
)
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("scenario", ["paired_model"], indirect=True),
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def receipt_scenario(legacy_scenario, request):
    s = original_receipt_scenario.__wrapped__(legacy_scenario, request)
    history = s["intake_history"]
    adoption = prepare_model_delivery_adoption(
        history,
        s["policy"],
        expected_tip_sha256=history_tip(history),
        current_block=200,
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=5 * 1024**2,
            maximum_concurrent_parts=2,
            capability_ttl_seconds=900,
        ),
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
    )
    s["intake_history"] = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(adoption))}
    )
    return s


@pytest.fixture(params=["individual", "batch"])
def reference(certified, request):
    n = certified
    acceptance = n.value.request.acceptance
    sub = n.value.request.record.request.signed_submission.submission
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(n.value.request.record.request),
        model_sha256=acceptance.model_sha256,
        payload_sha256="d1" * 32,
        total_bytes=sum(f.size_bytes for f in sub.model_bundle.files),
        file_count=len(sub.model_bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=acceptance.cohort_sha256,
        hotkey=sub.hotkey,
        payload=payload,
        attempt_id="d2" * 32,
        generation=1,
        object_key_sha256=sha256_hex(
            direct_model_object_key(
                acceptance.cohort_sha256, payload.upload_sha256, "d2" * 32
            ).encode()
        ),
        provider_upload_id_sha256="d3" * 32,
        created_at_unix_ms=1800000000000,
    )
    artifact = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    acceptance = acceptance.model_copy(
        update={
            "schema_": "umi-cohort-model-artifact-acceptance/2",
            "direct_artifact": artifact,
        }
    )
    n.value = n.value.model_copy(
        update={
            "request": n.value.request.model_copy(
                update={
                    "schema_": "umi-cohort-model-review-request/2",
                    "acceptance": acceptance,
                    "direct_artifact": artifact,
                }
            ),
            "certificate": CertifiedModelArtifactAcceptance(
                acceptance=acceptance, signatures=signatures(acceptance)
            ),
        }
    )
    if request.param == "batch":
        history = n.value.history.history
        index = next(
            i
            for i, t in enumerate(history.transitions)
            if t.transition.phase == "intake" and t.transition.operation == "close_phase"
        )
        prefix = history.model_copy(update={"transitions": history.transitions[:index]})
        body = prepare_model_batch_certification_adoption(
            prefix,
            n.e.r.h.batch["policy"],
            expected_tip_sha256=history_tip(prefix),
            effective_at_block=220,
        )
        adoption = SignedModelBatchCertificationAdoption(adoption=body, signatures=signatures(body))
        batch = build_model_acceptance_batch(
            (acceptance,),
            adoption,
            prefix,
            n.e.r.h.batch["policy"],
            candidate_snapshot_sha256="ad" * 32,
            roster_sha256="ae" * 32,
            certified_at_block=220,
        )
        certificate = CertifiedModelAcceptanceBatch(
            batch=batch, adoption=adoption, signatures=signatures(batch)
        )
        (proof,) = model_acceptance_batch_proofs((acceptance,), certificate)
        n.value = n.value.model_copy(
            update={
                "certificate": CertifiedModelArtifactAcceptance(
                    acceptance=acceptance, batch_proof=proof
                )
            }
        )
    candidate = CohortBaselineCandidate(
        schema="umi-cohort-baseline-candidate/1",
        policy_sha256=acceptance.policy_sha256,
        authority_sha256=acceptance.authority_sha256,
        round_sha256=digest(n.e.job.round),
        model_award_sha256="a1" * 32,
        quality_manifest_sha256="a2" * 32,
        original_baseline_model_sha256=n.e.job.round.incumbent_model_sha256,
        submission_sha256=acceptance.submission_sha256,
        model_sha256=acceptance.model_sha256,
        content_sha256=acceptance.content_sha256,
        contributor_hotkey=acceptance.recipient_hotkey,
        acceptance_sha256=digest(n.value.certificate),
        accepted_ordinal=acceptance.accepted_ordinal,
        quality_sha256="a3" * 32,
        aggregate={"numerator": "1", "denominator": "1"},
        baseline_aggregate={"numerator": "0", "denominator": "1"},
        rights_evidence_sha256=acceptance.rights_evidence_sha256,
        reconstruction_evidence_sha256=acceptance.reconstruction_evidence_sha256,
    )
    source_sequence = n.value.history.history.plan.sequence
    n.review = CohortBaselineReview(
        schema="umi-cohort-baseline-review/1",
        policy_sha256=acceptance.policy_sha256,
        series_sha256="b1" * 32,
        source_cohort_sha256=acceptance.cohort_sha256,
        source_sequence=source_sequence,
        activation_sha256="b2" * 32,
        package_sha256="b3" * 32,
        allocation_sha256="b4" * 32,
        target_cohort_sha256="b5" * 32,
        target_sequence=source_sequence + 1,
        previous=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="b6" * 32,
            model_sha256=candidate.original_baseline_model_sha256,
            contributor_hotkey=None,
        ),
        candidate=candidate,
        model=n.value.request.record.request.signed_submission.submission.model_bundle,
        not_before_block=400,
        valid_through_block=450,
    )
    n.job = n.e.job.model_copy(
        update={
            "incumbent": n.review.model,
            "round": n.e.job.round.model_copy(
                update={
                    "cohort_sha256": n.review.target_cohort_sha256,
                    "sequence": n.review.target_sequence,
                    "incumbent_model_sha256": candidate.model_sha256,
                }
            ),
        }
    )
    n.slot = acceptance.cohort_sha256 + ":" + acceptance.submission_sha256
    return n


async def test_reference_single_verification_for_concurrent_candidates_and_restart(
    reference, monkeypatch, caplog
):
    n = reference
    caplog.set_level("INFO", logger="umi.competition.progress")
    checks = []
    native = sources.verify_reference_model_source

    def verify(*args):
        checks.append(1)
        return native(*args)

    monkeypatch.setattr(sources, "verify_reference_model_source", verify)
    reader = n.reader()
    # Candidate identity is deliberately unrelated to the inherited winner.
    jobs = [
        n.job.model_copy(
            update={
                "submission": n.job.submission.model_copy(
                    update={
                        "submission": n.job.submission.submission.model_copy(
                            update={"model_revision": f"{i:064x}"}
                        )
                    }
                )
            }
        )
        for i in range(1, 130)
    ]
    values = await asyncio.gather(*(reader.reference(job, n.review) for job in jobs))
    assert values == [n.value.request] * 129
    assert n.reads == len(checks) == 1
    n.unavailable = True

    def forbidden(*args):
        raise AssertionError("completed reference metadata must not fetch or replay")

    monkeypatch.setattr(sources, "verify_reference_model_source", forbidden)
    assert await n.reader().reference(jobs[-1], n.review) == n.value.request
    assert n.reads == 1
    for kind in ("model_request", "model_intent", "model_vote"):
        assert n.journal().get(kind, n.slot) is None
    assert n.journal().get("reference_execution_source_verified", n.slot) is not None
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert any(
        e.get("stage") == "reference_model_metadata"
        and e.get("planning_eta_seconds") == [0, 30]
        and e.get("eta_basis") == "planning_bounded_owner_metadata_response_excludes_retries"
        for e in events
    )
    assert any(
        e.get("stage") == "reference_model_metadata_verification"
        and e.get("completed_units") == e.get("total_units") == 1
        for e in events
    )


async def test_reference_older_than_immediate_predecessor_reuses_original_source(
    reference, monkeypatch
):
    n = reference
    await n.reader().reference(n.job, n.review)
    later = n.review.model_copy(
        update={"target_sequence": n.review.target_sequence + 2, "target_cohort_sha256": "ab" * 32}
    )
    job = n.job.model_copy(
        update={
            "round": n.job.round.model_copy(
                update={
                    "sequence": later.target_sequence,
                    "cohort_sha256": later.target_cohort_sha256,
                }
            )
        }
    )
    n.unavailable = True

    def forbidden(*args):
        raise AssertionError("later target must reuse original certified source")

    monkeypatch.setattr(sources, "verify_reference_model_source", forbidden)
    assert await n.reader().reference(job, later) == n.value.request
    assert n.reads == 1


@pytest.mark.parametrize(
    "field",
    [
        "acceptance_sha256",
        "rights_evidence_sha256",
        "accepted_ordinal",
        "content_sha256",
        "authority_sha256",
        "reconstruction_evidence_sha256",
    ],
)
async def test_reference_refuses_changed_original_binding(reference, field):
    n = reference
    value = 2 if field == "accepted_ordinal" else "dd" * 32
    review = n.review.model_copy(
        update={"candidate": n.review.candidate.model_copy(update={field: value})}
    )
    with pytest.raises(ValueError, match="original baseline source"):
        await n.reader().reference(n.job, review)
    assert n.journal().get("reference_execution_source_verified", n.slot) is None


async def test_reference_requires_full_certificate_not_acceptance_body(reference):
    n = reference
    wrong = n.review.model_copy(
        update={
            "candidate": n.review.candidate.model_copy(
                update={"acceptance_sha256": digest(n.value.certificate.acceptance)}
            )
        }
    )
    with pytest.raises(ValueError, match="original baseline source"):
        await n.reader().reference(n.job, wrong)


async def test_reference_rejects_frozen_target_or_authority_change_without_fetch(reference):
    n = reference
    with pytest.raises(ValueError, match="frozen execution"):
        await n.reader().reference(
            n.job.model_copy(update={"incumbent": n.e.job.incumbent}), n.review
        )
    assert n.reads == 0
    reader = n.reader()
    assert await reader.reference(n.job, n.review) == n.value.request
    reader.cohorts = {n.review.source_cohort_sha256: "ee" * 32}
    with pytest.raises(ValueError, match="repair required"):
        await reader.reference(n.job, n.review)
    assert n.reads == 1


@pytest.mark.parametrize("damage", ["request", "receipt"])
async def test_reference_missing_completed_record_is_explicit_repair(reference, damage, caplog):
    n = reference
    reader = n.reader()
    await reader.reference(n.job, n.review)
    kind = "reference_execution_source" + ("_verified" if damage == "receipt" else "")
    with n.journal().transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, n.slot))
    caplog.set_level("INFO", logger="umi.competition.progress")
    with pytest.raises(ValueError, match="repair required"):
        await n.reader().reference(n.job, n.review)
    assert n.reads == 1
    reason = "receipt_missing" if damage == "receipt" else "source_missing"
    assert any("completed_execution_metadata_" + reason in r.message for r in caplog.records)


async def test_reference_rejects_tampered_metadata_and_keeps_original_certificate(reference):
    n = reference
    original = canonical_json_bytes(n.value.certificate)
    await n.reader().reference(n.job, n.review)
    saved = n.journal().get("reference_execution_source", n.slot)
    assert canonical_json_bytes(saved["certificate"]) == original
    saved["request"]["acceptance"]["rights_evidence_sha256"] = "ef" * 32
    with n.journal().transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=? AND id=?",
            (
                canonical_json_bytes(saved),
                "reference_execution_source",
                n.slot,
            ),
        )
    with pytest.raises(ValueError, match="repair required"):
        await n.reader().reference(n.job, n.review)
    assert n.reads == 1


async def test_reference_cancelled_atomic_commit_remains_reusable(reference, monkeypatch):
    n = reference
    reader = n.reader()
    entered, release = Event(), Event()
    commit = reader.journal.put_many

    def blocked(records):
        entered.set()
        assert release.wait(5)
        commit(records)

    monkeypatch.setattr(reader.journal, "put_many", blocked)
    task = asyncio.create_task(reader.reference(n.job, n.review))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    n.unavailable = True

    def forbidden(*args):
        raise AssertionError("completed commit must survive cancelled caller")

    monkeypatch.setattr(sources, "verify_reference_model_source", forbidden)
    assert await n.reader().reference(n.job, n.review) == n.value.request
    assert n.reads == 1


async def test_reference_bound_certificate_still_requires_original_quorum(reference):
    n = reference
    certificate = n.value.certificate
    if certificate.batch_proof is None:
        certificate = certificate.model_copy(update={"signatures": certificate.signatures[:1]})
    else:
        proof = certificate.batch_proof
        certificate = certificate.model_copy(
            update={
                "batch_proof": proof.model_copy(
                    update={
                        "certificate": proof.certificate.model_copy(
                            update={"signatures": proof.certificate.signatures[:1]}
                        )
                    }
                )
            }
        )
    n.value = n.value.model_copy(update={"certificate": certificate})
    review = n.review.model_copy(
        update={
            "candidate": n.review.candidate.model_copy(
                update={"acceptance_sha256": digest(certificate)}
            )
        }
    )
    with pytest.raises(ValueError):
        await n.reader().reference(n.job, review)
    assert n.journal().get("reference_execution_source_verified", n.slot) is None
