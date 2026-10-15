"""Upgrade and repair retained transport checks without repeating model bytes."""

import json

import pytest

from umi import competition_model_transport_qualification as qualification
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
    direct_model_object_key,
)
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelAcceptanceIntent,
    ModelAcceptancePublication,
    ModelArtifactVote,
)
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_cohort_model_acceptance import adopt_direct_transport
from .test_competition_cohort_model_review import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_review import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_review import (
    policy as policy,
)
from .test_competition_cohort_model_review import (
    prepared as prepared,
)
from .test_competition_cohort_model_review import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_review import (
    recovery as recovery,
)
from .test_competition_cohort_model_review import (
    reviews as reviews,
)
from .test_competition_cohort_model_review import (
    runtime as runtime,
)
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def direct(reviews):
    r = reviews
    request = r.request
    sub = request.record.request.signed_submission.submission
    bundle = sub.model_bundle
    upload, attempt = digest(request.record.request), "a1" * 32
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=upload,
        model_sha256=digest(bundle),
        payload_sha256="b2" * 32,
        total_bytes=sum(f.size_bytes for f in bundle.files),
        file_count=len(bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=r.cohort,
        hotkey=sub.hotkey,
        payload=payload,
        attempt_id=attempt,
        generation=1,
        object_key_sha256=sha256_hex(direct_model_object_key(r.cohort, upload, attempt).encode()),
        provider_upload_id_sha256="c3" * 32,
        created_at_unix_ms=1_800_000_000_000,
    )
    artifact = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    r.direct = request.model_copy(
        update={
            "schema_": "umi-cohort-model-review-request/2",
            "direct_artifact": artifact,
            "acceptance": request.acceptance.model_copy(
                update={
                    "schema_": "umi-cohort-model-artifact-acceptance/2",
                    "direct_artifact": artifact,
                }
            ),
        }
    )
    return r


def ports():
    records = {}

    def read(kind, key):
        return records.get((kind, key))

    def publish(values):
        records.update({(kind, key): body for kind, key, body in values})

    return records, read, publish


def no_work(*args, **kwargs):
    pytest.fail("reused historical authorization touched an unchanged predicate or payload")


@pytest.mark.parametrize("mode", ["unadopted", "later", "wrong_profile"])
def test_older_direct_state_requires_historical_authorization(direct, mode):
    r = direct
    if mode != "unadopted":
        adopt_direct_transport(
            r.owner.intake,
            r.cohort,
            block=221 if mode == "later" else 211,
            part_size_bytes=(6 if mode == "wrong_profile" else 5) * 1024**2,
        )
    records, read, publish = ports()
    events = []
    with pytest.raises(ValueError, match="authenticated transport profile"):
        qualification.qualify_model_transport(
            r.direct.acceptance,
            r.owner.intake.history(r.cohort),
            r.owner.intake.policy,
            read=read,
            publish=publish,
            report=events.append,
        )
    assert not records
    assert events[0]["planning_eta_seconds"] == [0, 5]
    assert events[-1]["state"] == "repair_required"


def test_valid_migration_reuses_across_extension_and_detects_damage(direct, monkeypatch):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    original = canonical_json_bytes(r.direct)
    records, read, publish = ports()
    events = []
    result = qualification.qualify_model_transport(
        r.direct.acceptance,
        history,
        r.owner.intake.policy,
        read=read,
        publish=publish,
        report=events.append,
    )
    assert events[-1]["percent"] == 100 and events[-1]["eta_seconds"] == 0
    state = verify_cohort_history(
        history, r.owner.intake.policy, expected_tip_sha256=history_tip(history), current_block=300
    ).state
    closing = signed_transition(
        propose_recovery_transition(
            state,
            history.authority.authority,
            operation="close_phase",
            observed_at_block=300,
            evidence_sha256="35" * 32,
        )
    )
    later = history.model_copy(update={"transitions": (*history.transitions, closing)})
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    assert (
        qualification.qualify_model_transport(
            r.direct.acceptance, later, r.owner.intake.policy, read=read, publish=publish
        )
        == result
    )
    assert canonical_json_bytes(r.direct) == original
    del records[(qualification.MARKER, digest(r.direct.acceptance))]
    with pytest.raises(ValueError, match="scoped repair required"):
        qualification.qualify_model_transport(
            r.direct.acceptance, later, r.owner.intake.policy, read=read, publish=publish
        )


@pytest.mark.parametrize("lost_ack", [False, True])
def test_interrupted_metadata_migration_is_idempotent(direct, lost_ack, monkeypatch):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    records, read, publish = ports()

    def interrupted(values):
        if lost_ack:
            publish(values)
        raise OSError("interrupted")

    with pytest.raises(OSError):
        qualification.qualify_model_transport(
            r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=interrupted
        )
    if lost_ack:
        monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    qualification.qualify_model_transport(
        r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=publish
    )
    assert len(records) == 3


def test_legacy_artifacts_do_not_open_new_qualification_or_change_bytes(reviews):
    original = canonical_json_bytes(reviews.request)
    assert (
        qualification.qualify_model_transport(
            reviews.request.acceptance, None, None, read=no_work, publish=no_work
        )
        is None
    )
    assert canonical_json_bytes(reviews.request) == original


@pytest.mark.parametrize("entry", ["prepare", "intent", "review_request", "publish"])
@pytest.mark.parametrize("authorized", [False, True])
def test_old_owner_early_returns_are_qualified_without_payload(
    direct, entry, authorized, monkeypatch
):
    r = direct
    if authorized:
        adopt_direct_transport(r.owner.intake, r.cohort)
    a = r.direct.acceptance
    intent = ModelAcceptanceIntent(acceptance=a, inputs=r.inputs)
    publication = ModelAcceptancePublication(
        certificate=CertifiedModelArtifactAcceptance(acceptance=a, signatures=signatures(a)),
        inputs=r.inputs,
    )
    # Simulate bytes retained by the supported older release, before this new scope existed.
    with r.owner.intake._connection() as (db, _):
        db.execute(
            "UPDATE cohort_model_acceptance_intents SET body=? WHERE cohort=? AND submission=?",
            (canonical_json_bytes(intent), r.cohort, a.submission_sha256),
        )
        if entry == "publish":
            r.owner._put(db, "cohort_model_acceptances", r.cohort, a.submission_sha256, publication)
    r.owner.verify_request = no_work
    r.owner.review_artifact = no_work

    def action():
        if entry == "prepare":
            return r.owner.prepare(r.cohort, a.submission_sha256, r.inputs, None)
        if entry == "publish":
            return r.owner.publish(publication, None)
        return getattr(r.owner, entry)(r.cohort, a.submission_sha256)

    if not authorized:
        with pytest.raises(ValueError, match="authenticated transport profile"):
            action()
        return
    first = action()
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    assert action() == first
    with r.owner.intake._connection() as (db, _):
        retained = db.execute(
            "SELECT body FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
            (r.cohort, a.submission_sha256),
        ).fetchone()[0]
    assert retained == canonical_json_bytes(intent)


@pytest.mark.parametrize("authorized", [False, True])
async def test_old_reviewer_vote_upgrade_uses_retained_history_offline(
    direct, authorized, monkeypatch
):
    r = direct
    history = (
        adopt_direct_transport(r.owner.intake, r.cohort)
        if authorized
        else r.owner.intake.history(r.cohort)
    )
    a = r.direct.acceptance
    reviewer = r.create("Charlie")
    reviewer._reserve(r.direct, ModelAcceptanceIntent(acceptance=a, inputs=r.inputs), history)
    vote = ModelArtifactVote(acceptance=a, signature=sign_object(a, wallet("Charlie")))
    reviewer.journal.put("model_vote", a.cohort_sha256 + ":" + a.submission_sha256, vote)
    r.state.online = False
    if not authorized:
        with pytest.raises(ValueError, match="authenticated transport profile"):
            await reviewer.attest(r.direct)
        return
    assert await reviewer.attest(r.direct) == vote
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    assert await r.create("Charlie").attest(r.direct) == vote
    assert not r.state.signing


def repair_ports(records):
    def read_raw(kind, key):
        value = records.get((kind, key))
        return None if value is None else canonical_json_bytes(value)

    def replace(key, observed, values):
        if tuple(read_raw(kind, key) for kind in qualification.QUALIFICATION_KINDS) != observed:
            raise ValueError("model transport qualification changed during scoped repair")
        records.update({(kind, record_key): body for kind, record_key, body in values})

    return read_raw, replace


@pytest.mark.parametrize(
    "damage", ["missing_record", "missing_marker", "changed_record", "changed_marker"]
)
def test_explicit_repair_preserves_originals_and_reuses_after_restart(direct, damage, monkeypatch):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    original = canonical_json_bytes(r.direct)
    records, read, publish = ports()
    expected = qualification.qualify_model_transport(
        r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=publish
    )
    kind = qualification.RECORD if damage.endswith("record") else qualification.MARKER
    key = digest(r.direct.acceptance)
    if damage.startswith("missing"):
        del records[(kind, key)]
    else:
        records[(kind, key)] = {"damaged": True}
    sibling = (qualification.RECORD, "12" * 32)
    records[sibling] = {"independent": True}
    read_raw, replace = repair_ports(records)
    originals = [read_raw(k, key) for k in qualification.QUALIFICATION_KINDS]
    events = []
    result = qualification.repair_model_transport(
        r.direct.acceptance,
        history,
        r.owner.intake.policy,
        reason="restore damaged supplementary pair",
        read_raw=read_raw,
        replace=replace,
        report=events.append,
    )
    assert result == expected
    assert events[0]["planning_eta_seconds"] == [0, 5]
    assert events[-1]["percent"] == 100 and events[-1]["eta_seconds"] == 0
    assert all(e["operation"] == "repair" and e["total"] == 1 for e in events)
    audit = [v for (k, _), v in records.items() if k == qualification.REPAIR]
    assert len(audit) == 1
    assert [a["body_hex"] for a in audit[0]["originals"]] == [
        None if value is None else value.hex() for value in originals
    ]
    assert records[sibling] == {"independent": True}
    assert canonical_json_bytes(r.direct) == original
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    assert (
        qualification.repair_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            reason="repeat after restart",
            read_raw=read_raw,
            replace=no_work,
        )
        == expected
    )
    assert (
        qualification.qualify_model_transport(
            r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=no_work
        )
        == expected
    )


@pytest.mark.parametrize("lost_ack", [False, True])
def test_interrupted_repair_has_one_atomic_audit(direct, lost_ack, monkeypatch):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    records, read, publish = ports()
    qualification.qualify_model_transport(
        r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=publish
    )
    key = digest(r.direct.acceptance)
    del records[(qualification.MARKER, key)]
    read_raw, replace = repair_ports(records)
    events = []

    def interrupted(*args):
        if lost_ack:
            replace(*args)
        raise OSError("interrupted repair acknowledgement")

    with pytest.raises(OSError):
        qualification.repair_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            reason="interruption recovery",
            read_raw=read_raw,
            replace=interrupted,
            report=events.append,
        )
    assert events[-1]["state"] == "retrying" and events[-1]["retrying"]
    if lost_ack:
        monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    qualification.repair_model_transport(
        r.direct.acceptance,
        history,
        r.owner.intake.policy,
        reason="interruption recovery",
        read_raw=read_raw,
        replace=replace,
    )
    assert len(records) == 4


@pytest.mark.parametrize("mode", ["unadopted", "later", "wrong_profile"])
def test_repair_cannot_authorize_historical_invalid_transport(direct, mode):
    r = direct
    history = (
        r.owner.intake.history(r.cohort)
        if mode == "unadopted"
        else adopt_direct_transport(
            r.owner.intake,
            r.cohort,
            block=221 if mode == "later" else 211,
            part_size_bytes=(6 if mode == "wrong_profile" else 5) * 1024**2,
        )
    )
    records = {(qualification.MARKER, digest(r.direct.acceptance)): {"invalid": True}}
    read_raw, _ = repair_ports(records)
    with pytest.raises(ValueError, match="authenticated transport profile"):
        qualification.repair_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            reason="attempted recovery",
            read_raw=read_raw,
            replace=no_work,
        )
    assert len(records) == 1


@pytest.mark.parametrize("reason", [None, "", "  ", "a" * 1025])
def test_repair_requires_bounded_explicit_reason(direct, reason):
    with pytest.raises(ValueError, match="explicit bounded reason"):
        qualification.repair_model_transport(
            direct.direct.acceptance, None, None, reason=reason, read_raw=no_work, replace=no_work
        )


def test_repair_refuses_absent_pair_and_legacy_scope(direct):
    r = direct
    with pytest.raises(ValueError, match="legacy model acceptance"):
        qualification.repair_model_transport(
            r.request.acceptance, None, None, reason="repair", read_raw=no_work, replace=no_work
        )
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    with pytest.raises(ValueError, match="first migration"):
        qualification.repair_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            reason="repair",
            read_raw=lambda *_: None,
            replace=no_work,
        )


def test_repair_rejects_pair_changed_between_check_and_commit(direct):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    key = digest(r.direct.acceptance)
    records = {(qualification.MARKER, key): {"damaged": True}}
    read_raw, replace = repair_ports(records)

    def changed(*args):
        records[(qualification.MARKER, key)] = {"concurrent": True}
        replace(*args)

    with pytest.raises(ValueError, match="changed during scoped repair"):
        qualification.repair_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            reason="repair",
            read_raw=read_raw,
            replace=changed,
        )
    assert len(records) == 1


@pytest.mark.parametrize("exhaust_capacity", [False, True])
def test_owner_repair_is_atomic_and_preserves_signed_binding(direct, exhaust_capacity, monkeypatch):
    r = direct
    adopt_direct_transport(r.owner.intake, r.cohort)
    acceptance = r.direct.acceptance
    intent = ModelAcceptanceIntent(acceptance=acceptance, inputs=r.inputs)
    signed = canonical_json_bytes(intent)
    publication = ModelAcceptancePublication(
        certificate=CertifiedModelArtifactAcceptance(
            acceptance=acceptance, signatures=signatures(acceptance)
        ),
        inputs=r.inputs,
    )
    signed_publication = canonical_json_bytes(publication)
    key = digest(acceptance)
    with r.owner.intake._connection() as (db, _):
        db.execute(
            "UPDATE cohort_model_acceptance_intents SET body=? WHERE cohort=? AND submission=?",
            (signed, r.cohort, acceptance.submission_sha256),
        )
        r.owner._put(
            db, "cohort_model_acceptances", r.cohort, acceptance.submission_sha256, publication
        )
    r.owner.intent(r.cohort, acceptance.submission_sha256)
    with r.owner.intake._connection() as (db, _):
        db.execute(
            "UPDATE cohort_model_transport_markers SET body=? WHERE cohort=? AND submission=?",
            (b"damaged JSON", r.cohort, key),
        )
    if exhaust_capacity:
        monkeypatch.setattr(
            r.owner.intake,
            "capacity",
            r.owner.intake.capacity.model_copy(update={"maximum_bytes": 1}),
        )
        with pytest.raises(ValueError, match="durable capacity"):
            r.owner.repair_transport_qualification(
                r.cohort, acceptance.submission_sha256, reason="repair damaged marker"
            )
    else:
        r.owner.repair_transport_qualification(
            r.cohort, acceptance.submission_sha256, reason="repair damaged marker"
        )
        monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
        assert r.owner.intent(r.cohort, acceptance.submission_sha256) == intent
        r.owner.repair_transport_qualification(
            r.cohort, acceptance.submission_sha256, reason="repeat after restart"
        )
    with r.owner.intake._connection() as (db, _):
        retained = db.execute(
            "SELECT body FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
            (r.cohort, acceptance.submission_sha256),
        ).fetchone()[0]
        retained_publication = db.execute(
            "SELECT body FROM cohort_model_acceptances WHERE cohort=? AND submission=?",
            (r.cohort, acceptance.submission_sha256),
        ).fetchone()[0]
        marker = db.execute(
            "SELECT body FROM cohort_model_transport_markers WHERE cohort=? AND submission=?",
            (r.cohort, key),
        ).fetchone()[0]
        audits = db.execute(
            "SELECT body FROM cohort_model_transport_qualifications "
            "WHERE submission LIKE 'repair:%'"
        ).fetchall()
    assert retained == signed
    assert retained_publication == signed_publication
    if exhaust_capacity:
        assert marker == b"damaged JSON" and not audits
    else:
        assert (
            len(audits) == 1
            and json.loads(audits[0][0])["originals"][1]["body_hex"] == b"damaged JSON".hex()
        )


@pytest.mark.parametrize("reservations", [False, True])
@pytest.mark.parametrize("exhaust_capacity", [False, True])
@pytest.mark.parametrize("damaged_bytes", [b"damaged JSON", b""])
async def test_reviewer_repair_preserves_vote_and_journal_capacity(
    direct, reservations, exhaust_capacity, damaged_bytes, monkeypatch
):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    reviewer = r.create("Charlie")
    acceptance = r.direct.acceptance
    key = digest(acceptance)
    intent = ModelAcceptanceIntent(acceptance=acceptance, inputs=r.inputs)
    reviewer._reserve(r.direct, intent, history)
    vote = ModelArtifactVote(
        acceptance=acceptance, signature=sign_object(acceptance, wallet("Charlie"))
    )
    slot = r.cohort + ":" + acceptance.submission_sha256
    reviewer.journal.put("model_vote", slot, vote)
    await reviewer.attest(r.direct)
    if reservations:
        reviewer.journal.reserve_records("transport-repair-test", ())
    with reviewer.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=? AND id=?",
            (damaged_bytes, qualification.MARKER, key),
        )
    originals = {
        kind: reviewer.journal.get_raw(kind, slot)
        for kind in ("model_request", "model_intent", "model_vote")
    }
    r.state.online = False
    if exhaust_capacity:
        monkeypatch.setattr(reviewer.journal, "maximum_bytes", 1024)
        with pytest.raises(ValueError, match="capacity exhausted"):
            await reviewer.repair_transport_qualification(
                r.cohort, acceptance.submission_sha256, reason="repair damaged marker"
            )
    else:
        await reviewer.repair_transport_qualification(
            r.cohort, acceptance.submission_sha256, reason="repair damaged marker"
        )
        monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
        restarted = r.create("Charlie")
        assert await restarted.attest(r.direct) == vote
        await restarted.repair_transport_qualification(
            r.cohort, acceptance.submission_sha256, reason="repeat after restart"
        )
    assert {kind: reviewer.journal.get_raw(kind, slot) for kind in originals} == originals
    with reviewer.journal.read_transaction() as db:
        marker = db.execute(
            "SELECT body FROM records WHERE kind=? AND id=?", (qualification.MARKER, key)
        ).fetchone()[0]
        audit = db.execute(
            "SELECT body FROM records WHERE kind=?", (qualification.REPAIR,)
        ).fetchall()
    assert not r.state.signing
    if exhaust_capacity:
        assert marker == damaged_bytes and not audit
    else:
        assert (
            len(audit) == 1
            and json.loads(audit[0][0])["originals"][1]["body_hex"] == damaged_bytes.hex()
        )


@pytest.mark.parametrize("failure_kind", ["marker", "completion"])
def test_owner_initial_migration_pair_is_atomic(direct, monkeypatch, failure_kind):
    r = direct
    adopt_direct_transport(r.owner.intake, r.cohort)
    a = r.direct.acceptance
    intent = ModelAcceptanceIntent(acceptance=a, inputs=r.inputs)
    with r.owner.intake._connection() as (db, _):
        db.execute(
            "UPDATE cohort_model_acceptance_intents SET body=? WHERE cohort=? AND submission=?",
            (canonical_json_bytes(intent), r.cohort, a.submission_sha256),
        )
    original = r.owner._put

    def interrupted(db, table, *args):
        if (failure_kind == "marker" and table == "cohort_model_transport_markers") or (
            failure_kind == "completion"
            and table == "cohort_model_transport_qualifications"
            and args[1].startswith("completion:")
        ):
            raise OSError("interrupted before completion marker")
        original(db, table, *args)

    monkeypatch.setattr(r.owner, "_put", interrupted)
    with pytest.raises(OSError):
        r.owner.intent(r.cohort, a.submission_sha256)
    with r.owner.intake._connection() as (db, _):
        for table in ("cohort_model_transport_qualifications", "cohort_model_transport_markers"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    monkeypatch.setattr(r.owner, "_put", original)
    assert r.owner.intent(r.cohort, a.submission_sha256) == intent


async def test_reviewer_repair_honors_conflict_holds(direct):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    a = r.direct.acceptance
    reviewer = r.create("Charlie")
    reviewer._reserve(r.direct, ModelAcceptanceIntent(acceptance=a, inputs=r.inputs), history)
    reviewer._qualify_transport(a)
    key = digest(a)
    with reviewer.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", (qualification.MARKER, key))
        db.execute("INSERT INTO holds VALUES (?)", (key,))
    with pytest.raises(ValueError, match="conflict held"):
        await reviewer.repair_transport_qualification(
            r.cohort, a.submission_sha256, reason="repair"
        )
    with reviewer.journal.read_transaction() as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM records WHERE kind=?", (qualification.REPAIR,)
            ).fetchone()[0]
            == 0
        )


def test_failing_progress_sink_does_not_change_repair_outcome(direct):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    records = {(qualification.MARKER, digest(r.direct.acceptance)): {"damaged": True}}
    read_raw, replace = repair_ports(records)

    def broken_sink(_):
        raise OSError("telemetry temporarily unavailable")

    qualification.repair_model_transport(
        r.direct.acceptance,
        history,
        r.owner.intake.policy,
        reason="repair",
        read_raw=read_raw,
        replace=replace,
        report=broken_sink,
    )
    assert len(records) == 4


def test_simultaneous_pair_loss_requires_audited_restore_from_completion(direct, monkeypatch):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    records, read, publish = ports()
    expected = qualification.qualify_model_transport(
        r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=publish
    )
    key = digest(r.direct.acceptance)
    completion = canonical_json_bytes(records[(qualification.COMPLETION, key)])
    del records[(qualification.RECORD, key)]
    del records[(qualification.MARKER, key)]
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    events = []
    with pytest.raises(ValueError, match="scoped repair required"):
        qualification.qualify_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            read=read,
            publish=no_work,
            report=events.append,
        )
    assert events[-1]["state"] == "repair_required" and events[-1]["stalled"]
    read_raw, replace = repair_ports(records)
    assert (
        qualification.repair_model_transport(
            r.direct.acceptance,
            history,
            r.owner.intake.policy,
            reason="restore lost pair from ledger",
            read_raw=read_raw,
            replace=replace,
            report=events.append,
        )
        == expected
    )
    assert canonical_json_bytes(records[(qualification.COMPLETION, key)]) == completion
    audit = next(v for (kind, _), v in records.items() if kind == qualification.REPAIR)
    assert [v["body_hex"] for v in audit["originals"][:2]] == [None, None]
    assert audit["originals"][2]["body_hex"] == completion.hex()
    assert events[-1]["percent"] == 100 and events[-1]["eta_seconds"] == 0
    assert (
        qualification.qualify_model_transport(
            r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=no_work
        )
        == expected
    )


@pytest.mark.parametrize("damage", ["pre_ledger", "changed_ledger"])
def test_completion_migration_and_repair_recheck_only_transport(direct, damage, monkeypatch):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    records, read, publish = ports()
    qualification.qualify_model_transport(
        r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=publish
    )
    key = digest(r.direct.acceptance)
    old_pair = {
        kind: canonical_json_bytes(records[(kind, key)])
        for kind in (qualification.RECORD, qualification.MARKER)
    }
    if damage == "pre_ledger":
        del records[(qualification.COMPLETION, key)]
    else:
        records[(qualification.COMPLETION, key)] = {"damaged": True}
    original_verifier = qualification.verify_direct_model_transport
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    with pytest.raises(ValueError, match="scoped repair required"):
        qualification.qualify_model_transport(
            r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=no_work
        )
    calls = []

    def native(*args, **kwargs):
        calls.append(kwargs["accepted_at_block"])
        return original_verifier(*args, **kwargs)

    monkeypatch.setattr(qualification, "verify_direct_model_transport", native)
    read_raw, replace = repair_ports(records)
    qualification.repair_model_transport(
        r.direct.acceptance,
        history,
        r.owner.intake.policy,
        reason="qualify permanent completion ledger",
        read_raw=read_raw,
        replace=replace,
    )
    assert calls == [r.direct.acceptance.accepted_at_block]
    assert {kind: canonical_json_bytes(records[(kind, key)]) for kind in old_pair} == old_pair
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    qualification.qualify_model_transport(
        r.direct.acceptance, history, r.owner.intake.policy, read=read, publish=no_work
    )


@pytest.mark.parametrize("exhaust_capacity", [False, True])
@pytest.mark.parametrize("damage", ["pair", "pre_ledger"])
def test_owner_completion_survives_pair_loss_restart_and_failed_repair(
    direct, monkeypatch, exhaust_capacity, damage
):
    r = direct
    adopt_direct_transport(r.owner.intake, r.cohort)
    a = r.direct.acceptance
    key = digest(a)
    original = canonical_json_bytes(ModelAcceptanceIntent(acceptance=a, inputs=r.inputs))
    with r.owner.intake._connection() as (db, _):
        db.execute(
            "UPDATE cohort_model_acceptance_intents SET body=? WHERE cohort=? AND submission=?",
            (original, r.cohort, a.submission_sha256),
        )
    r.owner.intent(r.cohort, a.submission_sha256)
    with r.owner.intake._connection() as (db, _):
        completion = db.execute(
            "SELECT body FROM cohort_model_transport_qualifications "
            "WHERE cohort=? AND submission=?",
            (r.cohort, "completion:" + key),
        ).fetchone()[0]
        if damage == "pair":
            for table in (
                "cohort_model_transport_qualifications",
                "cohort_model_transport_markers",
            ):
                db.execute(f"DELETE FROM {table} WHERE cohort=? AND submission=?", (r.cohort, key))
        else:
            db.execute(
                "DELETE FROM cohort_model_transport_qualifications WHERE cohort=? AND submission=?",
                (r.cohort, "completion:" + key),
            )
    restarted = type(r.owner)(r.owner.intake, r.owner.archive)
    verifier = qualification.verify_direct_model_transport
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    with pytest.raises(ValueError, match="scoped repair required"):
        restarted.intent(r.cohort, a.submission_sha256)
    if damage == "pre_ledger":
        monkeypatch.setattr(qualification, "verify_direct_model_transport", verifier)
    if exhaust_capacity:
        monkeypatch.setattr(
            restarted.intake,
            "capacity",
            restarted.intake.capacity.model_copy(update={"maximum_bytes": 1}),
        )
        with pytest.raises(ValueError, match="durable capacity"):
            restarted.repair_transport_qualification(
                r.cohort, a.submission_sha256, reason="restore both records"
            )
    else:
        restarted.repair_transport_qualification(
            r.cohort, a.submission_sha256, reason="restore both records"
        )
        assert canonical_json_bytes(restarted.intent(r.cohort, a.submission_sha256)) == original
        restarted.repair_transport_qualification(
            r.cohort, a.submission_sha256, reason="repeat restore"
        )
    with restarted.intake._connection() as (db, _):
        retained_completion = db.execute(
            "SELECT body FROM cohort_model_transport_qualifications "
            "WHERE cohort=? AND submission=?",
            (r.cohort, "completion:" + key),
        ).fetchone()
        assert retained_completion == (
            None if damage == "pre_ledger" and exhaust_capacity else (completion,)
        )
        for table in ("cohort_model_transport_qualifications", "cohort_model_transport_markers"):
            row = db.execute(
                f"SELECT body FROM {table} WHERE cohort=? AND submission=?", (r.cohort, key)
            ).fetchone()
            assert (row is None) == (exhaust_capacity and damage == "pair")
        audits = db.execute(
            "SELECT body FROM cohort_model_transport_qualifications "
            "WHERE submission LIKE 'repair:%'"
        ).fetchall()
        assert len(audits) == (0 if exhaust_capacity else 1)


@pytest.mark.parametrize("reservations", [False, True])
@pytest.mark.parametrize("damage", ["pair", "pre_ledger"])
async def test_reviewer_completion_survives_pair_loss_and_restart(
    direct, reservations, monkeypatch, damage
):
    r = direct
    history = adopt_direct_transport(r.owner.intake, r.cohort)
    a = r.direct.acceptance
    key = digest(a)
    reviewer = r.create("Charlie")
    reviewer._reserve(r.direct, ModelAcceptanceIntent(acceptance=a, inputs=r.inputs), history)
    vote = ModelArtifactVote(acceptance=a, signature=sign_object(a, wallet("Charlie")))
    slot = r.cohort + ":" + a.submission_sha256
    reviewer.journal.put("model_vote", slot, vote)
    await reviewer.attest(r.direct)
    if reservations:
        reviewer.journal.reserve_records("transport-ledger-test", ())
    original_vote = reviewer.journal.get_raw("model_vote", slot)
    completion = reviewer.journal.get_raw(qualification.COMPLETION, key)
    with reviewer.journal.transaction() as db:
        for kind in (
            (qualification.RECORD, qualification.MARKER)
            if damage == "pair"
            else (qualification.COMPLETION,)
        ):
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, key))
    restarted = r.create("Charlie")
    r.state.online = False
    verifier = qualification.verify_direct_model_transport
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    with pytest.raises(ValueError, match="scoped repair required"):
        await restarted.attest(r.direct)
    if damage == "pre_ledger":
        monkeypatch.setattr(qualification, "verify_direct_model_transport", verifier)
    await restarted.repair_transport_qualification(
        r.cohort, a.submission_sha256, reason="restore pair from permanent ledger"
    )
    monkeypatch.setattr(qualification, "verify_direct_model_transport", no_work)
    assert await r.create("Charlie").attest(r.direct) == vote
    assert restarted.journal.get_raw("model_vote", slot) == original_vote
    assert restarted.journal.get_raw(qualification.COMPLETION, key) == completion
    assert len(restarted.journal.keys(qualification.REPAIR)) == 1
    assert not r.state.signing
