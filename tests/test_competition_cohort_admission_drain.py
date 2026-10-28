"""Accepted direct uploads remain a membership obligation until resolved."""

import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_cohort_admission_drain import DirectAdmissionDrain
from umi.competition_cohort_direct_model_owner import DirectModelUploadPending
from umi.open_competition import digest, identity, sign_object
from umi.protocol import StrictProtocolModel

from .test_competition_cohort_admission_deadline import DEADLINE_MS, model_request, selection_for
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy
from .test_open_competition import wallet


class _Config(StrictProtocolModel):
    maximum_uploads: int = 8


class _Owner:
    def __init__(self):
        self.config = _Config()
        self.records = {}
        self.statuses = {}
        self.issued = {}
        self.issue_errors = {}
        self.request_reads = 0
        self.scans = 0
        self.status_reads = 0
        self.journal = self
        self.issuance_active = False
        self._mutex = SimpleNamespace(locked=lambda: self.issuance_active)

    def keys(self, kind):
        self.scans += 1
        return [key for record_kind, key in self.records if kind == record_kind]

    def get(self, kind, key):
        if kind == "direct-request":
            self.request_reads += 1
        return self.records.get((kind, key))

    def _latest_attempt(self, upload):
        return upload

    def _signed_reservation(self, attempt):
        return SimpleNamespace(reservation={"upload": attempt})

    def status(self, reservation):
        self.status_reads += 1
        return self.statuses[reservation]

    def admission_reservation(self, request):
        key = digest(request)
        if key in self.issue_errors:
            raise self.issue_errors[key]
        if key not in self.issued:
            raise DirectModelUploadPending("original direct reservation is incomplete")
        return self.issued[key]

    def add(self, request, created=DEADLINE_MS - 1, *, hold=None):
        upload = digest(request)
        cohort = request.consent.consent.cohort_sha256
        self.records[("direct-request", upload)] = request.model_dump(mode="json", by_alias=True)
        self.issued[upload] = SimpleNamespace(
            reservation=SimpleNamespace(
                cohort_sha256=cohort,
                created_at_unix_ms=created,
                payload=SimpleNamespace(
                    upload_sha256=upload,
                    model_sha256=request.signed_submission.submission.model_revision,
                ),
                hotkey=request.signed_submission.submission.hotkey,
            )
        )
        self.statuses[digest({"upload": upload})] = SimpleNamespace(
            upload_sha256=upload,
            hold_reason_code=hold,
            payload_verified=True,
        )
        return upload


def _replacement(request, *, sequence=2, block=200):
    sub = request.signed_submission.submission.model_copy(update={"sequence": sequence})
    signed = type(request.signed_submission)(
        submission=sub, signature=sign_object(sub, wallet("Alice"))
    )
    consent = request.consent.consent.model_copy(
        update={"submission_sha256": digest(sub), "signed_at_block": block}
    )
    return type(request)(
        signed_submission=signed,
        consent=type(request.consent)(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )


@pytest.fixture
def drain_case(intake, scenario, tmp_path):
    request = model_request(scenario, tmp_path)
    deadline = selection_for(intake, scenario)
    owner = _Owner()
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE cohort_consents "
        "(cohort TEXT,hotkey TEXT,sequence INTEGER,consent TEXT,track TEXT)"
    )
    db.execute(
        "CREATE TABLE cohort_admission_reservations (request TEXT,cohort TEXT,admitted_ms INTEGER)"
    )
    yield owner, db, request, deadline
    db.close()


def _admit(db, request, *, track="model"):
    db.execute(
        "INSERT INTO cohort_consents VALUES (?,?,?,?,?)",
        (
            request.consent.consent.cohort_sha256,
            identity(request.signed_submission.submission.hotkey),
            request.signed_submission.submission.sequence,
            digest(request.consent.consent),
            track,
        ),
    )


def test_verified_unadmitted_upload_stays_pending_and_snapshot_is_reused(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request)
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    for _ in range(3):
        report = drain(deadline.cohort_sha256, db, deadline)
        assert report["total"] == 1
        assert report["pending"] == 1
        assert report["completed"] == 0
        assert report["eta_seconds"] is None
    assert owner.scans == owner.request_reads == 1
    _admit(db, request)
    assert drain(deadline.cohort_sha256, db, deadline)["pending"] == 0
    reads = owner.status_reads
    assert drain(deadline.cohort_sha256, db, deadline)["completed"] == 1
    assert owner.status_reads == reads


def test_newer_reserved_replacement_holds_until_its_sequence_is_admitted(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request, DEADLINE_MS - 2)
    replacement = _replacement(request)
    owner.add(replacement)
    _admit(db, request)
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    report = drain(deadline.cohort_sha256, db, deadline)
    assert (report["total"], report["pending"]) == (1, 1)
    _admit(db, replacement)
    assert drain(deadline.cohort_sha256, db, deadline)["completed"] == 1


def test_terminal_upload_hold_resolves_without_rechecking_metadata(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request, hold="model_payload_invalid")
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    report = drain(deadline.cohort_sha256, db, deadline)
    assert (report["total"], report["pending"], report["failed_resolved"]) == (1, 0, 1)
    assert drain(deadline.cohort_sha256, db, deadline)["completed"] == 1
    assert owner.status_reads == 1


@pytest.mark.parametrize(
    "reason", ["direct_model_submission_superseded", "direct_model_reservation_after_cutoff"]
)
def test_advisory_scheduling_hold_never_becomes_durable_drain_failure(drain_case, reason):
    owner, db, request, deadline = drain_case
    owner.add(request, hold=reason)
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    report = drain(deadline.cohort_sha256, db, deadline)
    assert report["pending"] == 1 and report["failed_resolved"] == 0
    _admit(db, _replacement(request))
    final = drain(deadline.cohort_sha256, db, deadline)
    assert final["pending"] == 0 and final["superseded"] == 1
    assert final["failed_resolved"] == 0


def test_reservations_at_cutoff_are_not_added_to_drain(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request, DEADLINE_MS)
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert (report["total"], report["pending"]) == (0, 0)
    assert owner.status_reads == 0


def test_ingress_acknowledgement_window_is_preserved(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request, DEADLINE_MS + 5000)
    deadline = deadline.model_copy(
        update={
            "legacy_reservations_before_unix_ms": DEADLINE_MS + 5426,
            "ingress_cutoff_receipt_sha256": "b2" * 32,
        }
    )
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert (report["total"], report["pending"]) == (1, 1)


def test_missing_original_intent_requires_repair_not_silent_exclusion(drain_case):
    owner, db, request, deadline = drain_case
    upload = owner.add(request)
    owner.issue_errors[upload] = DirectModelUploadPending(
        "original direct reservation needs repair"
    )
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert report["pending"] == report["blocked_count"] == 1
    assert report["repair_required"] is True
    assert "needs repair" in report["repair_detail"]


def test_missing_owner_cannot_report_admissions_drained(drain_case):
    _, db, _, deadline = drain_case
    report = DirectAdmissionDrain({})(deadline.cohort_sha256, db, deadline)
    assert report["pending"] == 1
    assert report["reason_code"] == "admission_upload_owner_unavailable"


def test_equal_sequence_siblings_remain_pending_until_one_is_admitted(drain_case):
    owner, db, request, deadline = drain_case
    sibling = _replacement(request, sequence=1, block=201)
    owner.add(request)
    owner.add(sibling)
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    report = drain(deadline.cohort_sha256, db, deadline)
    assert (report["total"], report["pending"]) == (2, 2)
    _admit(db, request)
    report = drain(deadline.cohort_sha256, db, deadline)
    assert (report["completed"], report["pending"], report["superseded"]) == (2, 0, 1)


def test_endpoint_admission_does_not_release_model_upload_obligation(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request)
    _admit(db, request, track="endpoint")
    assert (
        DirectAdmissionDrain({deadline.cohort_sha256: owner})(deadline.cohort_sha256, db, deadline)[
            "pending"
        ]
        == 1
    )


def test_restart_reuses_snapshot_and_terminal_resolution_without_manifest_reads(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request, hold="model_payload_invalid")
    assert (
        DirectAdmissionDrain({deadline.cohort_sha256: owner})(deadline.cohort_sha256, db, deadline)[
            "completed"
        ]
        == 1
    )
    before = owner.scans, owner.request_reads, owner.status_reads
    restarted = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    assert restarted(deadline.cohort_sha256, db, deadline)["completed"] == 1
    assert (owner.scans, owner.request_reads, owner.status_reads) == before


def test_corrupt_retained_snapshot_is_repair_not_manifest_rescan(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request)
    DirectAdmissionDrain({deadline.cohort_sha256: owner})(deadline.cohort_sha256, db, deadline)
    db.execute("UPDATE cohort_admission_drain_snapshots SET body=?", (b"{}",))
    before = owner.request_reads
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert report["pending"] == report["blocked_count"] == 1
    assert report["repair_required"] is True
    assert owner.request_reads == before


def test_unsigned_authorization_does_not_freeze_membership(drain_case):
    owner, db, request, deadline = drain_case
    db.execute(
        "INSERT INTO cohort_admission_reservations VALUES (?,?,?)",
        (
            digest(request),
            deadline.cohort_sha256,
            DEADLINE_MS - 1,
        ),
    )
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    report = drain(deadline.cohort_sha256, db, deadline)
    assert (report["total"], report["pending"]) == (0, 0)


def test_unsigned_provider_intent_is_not_an_issued_reservation(drain_case):
    owner, db, request, deadline = drain_case
    upload = owner.add(request)
    del owner.issued[upload]
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert (report["total"], report["pending"]) == (0, 0)


def test_early_unsigned_intent_does_not_backdate_late_issued_reservation(drain_case):
    owner, db, request, deadline = drain_case
    upload = owner.add(request, DEADLINE_MS + 1)
    owner.records[("direct-intent", upload)] = {"created_at_unix_ms": DEADLINE_MS - 100000}
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert (report["total"], report["pending"]) == (0, 0)


def test_issued_late_reservation_with_exact_early_native_permit_stays_protected(drain_case):
    owner, db, request, deadline = drain_case
    owner.add(request, DEADLINE_MS + 1)
    db.execute(
        "INSERT INTO cohort_admission_reservations VALUES (?,?,?)",
        (digest(request), deadline.cohort_sha256, DEADLINE_MS - 1),
    )
    report = DirectAdmissionDrain({deadline.cohort_sha256: owner})(
        deadline.cohort_sha256, db, deadline
    )
    assert (report["total"], report["pending"]) == (1, 1)


def test_initial_snapshot_waits_for_inflight_reservation_issuance(drain_case):
    owner, db, request, deadline = drain_case
    owner.issuance_active = True
    drain = DirectAdmissionDrain({deadline.cohort_sha256: owner})
    waiting = drain(deadline.cohort_sha256, db, deadline)
    assert waiting["pending"] == 1
    assert waiting["reason_code"] == "reservation_issuance_in_progress"
    assert owner.scans == 0
    assert db.execute("SELECT COUNT(*) FROM cohort_admission_drain_snapshots").fetchone() == (0,)
    owner.add(request)
    owner.issuance_active = False
    assert drain(deadline.cohort_sha256, db, deadline)["pending"] == 1
    assert owner.scans == 1
