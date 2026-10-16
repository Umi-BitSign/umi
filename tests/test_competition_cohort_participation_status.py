from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_participation import CohortParticipantAdmission
from umi.competition_cohort_participation_status import participation_status
from umi.competition_cohort_request_rule import prepare_request_tail_adoption
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at, request_for, seal_and_close
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_request_rule_adoption import original as original
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def queue(intake):
    return CohortAdmissionQueue(intake)


def status(queue, scenario, *, block=240, consent=None, name="Alice"):
    return participation_status(
        queue,
        digest(scenario["intake_history"].plan),
        wallet(name).hotkey.ss58_address,
        "endpoint",
        capture_at(block),
        nonce="ab" * 16,
        consent=consent,
    )


def certify(queue, request, *, block=240):
    receipt = queue.intake.receipt(request)
    admission = CohortParticipantAdmission.model_validate(receipt["proposed_admission"])
    for signature in signatures(admission):
        queue.publish_vote(
            CohortAdmissionVote(admission=admission, signature=signature), capture_at(block)
        )


def replacement(scenario, *, sequence=2, block=240):
    request = request_for(scenario, sequence=sequence, block=block)
    sub = request.signed_submission.submission.model_copy(update={"model_revision": "ca" * 32})
    signed = request.signed_submission.__class__(
        submission=sub, signature=sign_object(sub, wallet("Alice"))
    )
    consent = request.consent.consent.model_copy(update={"submission_sha256": digest(sub)})
    return request.__class__(
        signed_submission=signed,
        consent=request.consent.__class__(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )


def test_no_retained_entry_is_advisory_and_bound(queue, scenario):
    value = status(queue, scenario, consent="ff" * 32)
    assert value.latest is value.requested is None
    assert value.requested_consent_status == "not_retained"
    assert value.minimum_next_sequence == 1
    assert value.submission_not_before_block == 200
    assert value.phase == "intake" and not value.intake_fenced
    assert value.nonce == "ab" * 16 and value.observation.block == 240
    assert value.policy_sha256 == digest(queue.policy)
    assert value.advisory_only
    assert not value.runtime_migration_authorized
    assert not value.chain_submission_authorized
    assert not value.sealed_selection_verified


def test_pending_replacement_supersedes_certified_older_without_fallback(queue, scenario):
    first = request_for(scenario)
    queue.intake.retain(first, capture_at(210))
    certify(queue, first)
    second = replacement(scenario)
    queue.intake.retain(second, capture_at(240))
    value = status(queue, scenario, consent=digest(first.consent.consent))
    assert value.latest.sequence == 2 and value.latest.model_revision == "ca" * 32
    assert value.latest.submission_sha256 == digest(second.signed_submission.submission)
    assert value.latest.admission.status == "pending_attestation"
    assert value.requested_consent_status == "superseded"
    assert value.requested.sequence == 1
    assert value.requested.admission.status == "admission_certified"
    assert value.minimum_next_sequence == 3
    assert value.submission_not_before_block == 245
    latest = status(queue, scenario, consent=digest(second.consent.consent))
    assert latest.requested_consent_status == "latest"
    assert latest.requested == latest.latest
    # A consent belonging to a different account is not presented as this
    # account's superseded entry, even though its receipt is publicly readable.
    other = status(queue, scenario, name="Bob", consent=digest(first.consent.consent))
    assert other.requested_consent_status == "not_retained"


def test_certificate_can_arrive_after_seal_without_claiming_sealed_selection(queue, scenario):
    request = request_for(scenario)
    queue.intake.retain(request, capture_at(210))
    closed, evidence, _ = seal_and_close(queue.intake, scenario)
    fenced = status(queue, scenario, block=300)
    assert fenced.intake_fenced and fenced.phase == "intake"
    assert fenced.latest.admission.status == "pending_attestation"
    queue.intake.publish(closed, capture_at(300), decision_inputs=(evidence,))
    certify(queue, request, block=301)
    value = status(queue, scenario, block=301)
    assert value.phase == "preparation"
    assert value.latest.admission.status == "admission_certified"
    assert not value.sealed_selection_verified
    assert value.latest.admission.certificate == queue.certificate(
        digest(closed.plan), digest(request.consent.consent)
    )


def test_read_only_snapshot_does_not_write_enumerate_or_replay_seals(queue, scenario, monkeypatch):
    queue.intake.retain(request_for(scenario), capture_at(210))
    closed, _, _ = seal_and_close(queue.intake, scenario)
    db_path = queue.intake.directory / "intake.sqlite3"
    original = db_path.read_bytes()
    original_stat = db_path.stat()
    queries = []
    connection = queue.intake._connection

    @contextmanager
    def monitored(*, prefer_history=False):
        assert prefer_history
        with connection(prefer_history=True) as (db, store):
            assert db.execute("PRAGMA query_only").fetchone() == (1,)
            db.set_trace_callback(queries.append)
            yield db, store

    def forbidden(*_args, **_kwargs):
        raise AssertionError("status must not enumerate retained snapshots or replay a seal")

    monkeypatch.setattr(queue.intake, "_connection", monitored)
    for name in (
        "_seal",
        "_records",
        "_parsed_records",
        "export_records",
        "retained_registration_blocks",
    ):
        monkeypatch.setattr(queue.intake, name, forbidden)
    value = status(queue, scenario, block=300)
    assert value.cohort_sha256 == digest(closed.plan) and value.intake_fenced
    assert original == db_path.read_bytes()
    assert original_stat.st_mtime_ns == db_path.stat().st_mtime_ns
    consent_reads = [q for q in queries if "FROM cohort_consents" in q]
    assert len(consent_reads) == 1 and "ORDER BY sequence DESC LIMIT 1" in consent_reads[0]
    seal_reads = [q for q in queries if "FROM cohort_intake_seals" in q]
    assert len(seal_reads) == 1 and seal_reads[0].startswith("SELECT 1 ")


@pytest.mark.parametrize(
    "column,value",
    [("sequence", 10), ("observed", 211), ("recovery_tip", "ff" * 32), ("consent", "ee" * 32)],
)
def test_changed_index_fails_closed(queue, scenario, column, value):
    queue.intake.retain(request_for(scenario), capture_at(210))
    with queue.intake._connection() as (db, _):
        db.execute(f"UPDATE cohort_consents SET {column}=?", (value,))
    with pytest.raises(ValueError):
        status(queue, scenario)


@pytest.mark.parametrize("fault", ["malformed", "oversize", "signature", "certificate"])
def test_changed_retained_body_or_certificate_fails_closed(queue, scenario, fault):
    request = request_for(scenario)
    queue.intake.retain(request, capture_at(210))
    if fault == "certificate":
        certify(queue, request)
    with queue.intake._connection() as (db, _):
        table = "cohort_admission_certificates" if fault == "certificate" else "cohort_consents"
        raw = db.execute(f"SELECT body FROM {table}").fetchone()[0]
        if fault == "malformed":
            raw = b"{}"
        elif fault == "oversize":
            raw = b" " * (4 * 1024**2 + 1)
        else:
            parsed = json.loads(raw)
            if fault == "signature":
                parsed["request"]["signed_submission"]["signature"]["signature"] = "00" * 64
            else:
                parsed["signatures"][0]["signature"] = "00" * 64
            raw = canonical_json_bytes(parsed)
        db.execute(f"UPDATE {table} SET body=?", (raw,))
    with pytest.raises(ValueError):
        status(queue, scenario)


def test_interval_and_sequence_survive_reopen(queue, scenario):
    request = replacement(scenario, sequence=2**32 - 1)
    queue.intake.retain(request, capture_at(240))
    reopened = CohortIntake(queue.intake.config, queue.policy)
    value = status(CohortAdmissionQueue(reopened), scenario)
    assert value.minimum_next_sequence is None
    assert value.submission_not_before_block == 245
    with pytest.raises(ValueError, match="observation"):
        status(queue, scenario, block=239)


def test_pending_adoption_reports_fence_in_same_snapshot(original, policy, tmp_path):
    history, _ = original
    cohort = digest(history.plan)
    intake = CohortIntake(
        CohortIntakeConfig(
            directory=str(tmp_path / "adoption-intake"),
            cohorts=(
                CohortIntakeBinding(
                    cohort_sha256=cohort, authority_sha256=digest(history.authority.authority)
                ),
            ),
        ),
        policy,
        eligible_tracks=("model",),
        initialize=True,
    )
    intake.publish(history, capture_at(210))
    queue = CohortAdmissionQueue(intake)
    proposal = prepare_request_tail_adoption(history, policy, execution_boundary(capture_at(220)))
    intake.reserve_request_tail_adoption(proposal)
    result = participation_status(
        queue,
        cohort,
        wallet("Alice").hotkey.ss58_address,
        "model",
        capture_at(220),
        nonce="ab" * 16,
    )
    assert result.pending_policy_adoption == "adopt_request_tail_rule"
    assert result.phase == "intake" and result.intake_fenced
    assert result.latest is None


async def test_additive_api_validation_and_original_admissions_unchanged(queue, scenario):
    request = request_for(scenario)
    queue.intake.retain(request, capture_at(210))

    async def capture():
        return capture_at(240)

    app = FastAPI()
    app.include_router(cohort_routes(queue.intake, capture, maximum_body_bytes=4 * 1024**2))
    prefix = f"/v1/competition/cohorts/{digest(scenario['intake_history'].plan)}"
    route = prefix + "/participation-status/" + request.signed_submission.submission.hotkey
    params = {"nonce": "ab" * 16, "track": "endpoint", "consent": digest(request.consent.consent)}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        before = await client.get(prefix + "/admissions/" + params["consent"])
        # The HTTP read must complete even while this process owns the intake
        # writer gate and an unrelated uncommitted write transaction.
        with queue.intake._connection() as (db, _):
            db.execute("BEGIN IMMEDIATE")
            try:
                response = await asyncio.wait_for(client.get(route, params=params), timeout=10)
            finally:
                db.rollback()
        after = await client.get(prefix + "/admissions/" + params["consent"])
        assert before.status_code == after.status_code == response.status_code == 200
        assert before.content == after.content
        body = response.json()
        assert body["requested_consent_status"] == "latest"
        assert body["latest"]["admission"] == before.json()
        assert body["observation"]["block"] == 240
        for changed in ({"nonce": "bad"}, {"track": "unknown"}, {"consent": "no"}):
            assert (await client.get(route, params=params | changed)).status_code == 422
        assert (
            await client.get(prefix + "/participation-status/bad", params=params)
        ).status_code == 422
        with queue.intake._connection() as (db, _):
            db.execute("UPDATE cohort_consents SET observed=211")
        assert (await client.get(route, params=params)).status_code == 503
