"""Scoped package migration uses original signed metadata, never model payloads."""

import json
import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_reward_transport_qualification as module
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_model_acceptance import CertifiedModelArtifactAcceptance
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_acceptance import adopt_direct_transport
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_model_transport_qualification import base_policy as base_policy
from .test_competition_model_transport_qualification import direct as direct
from .test_competition_model_transport_qualification import legacy_scenario as legacy_scenario
from .test_competition_model_transport_qualification import policy as policy
from .test_competition_model_transport_qualification import prepared as prepared
from .test_competition_model_transport_qualification import receipt_scenario as receipt_scenario
from .test_competition_model_transport_qualification import recovery as recovery
from .test_competition_model_transport_qualification import reviews as reviews
from .test_competition_model_transport_qualification import runtime as runtime

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def no_work(*args, **kwargs):
    pytest.fail("completed authorization repeated verification or read payloads")


@pytest.fixture
def package_case(direct, tmp_path, monkeypatch):
    r = direct
    p = r.owner.intake.policy
    owner = SimpleNamespace(
        verification_reuse=SimpleNamespace(directory=tmp_path / "native"),
        policy_sha256=digest(p),
        series_sha256="10" * 32,
        _authority=lambda: None,
        reader=SimpleNamespace(
            policy=p,
            chain_config_sha256="11" * 32,
            series=SimpleNamespace(
                recovery=SimpleNamespace(
                    authority=r.owner.intake.history(r.cohort).authority.authority,
                )
            ),
        ),
        manifest=SimpleNamespace(requirement=lambda cohort: {"cohort": cohort}),
    )

    def build(mode="valid"):
        history = r.owner.intake.history(r.cohort)
        if mode != "unadopted":
            history = adopt_direct_transport(
                r.owner.intake,
                r.cohort,
                block=221 if mode == "later" else 211,
                part_size_bytes=(6 if mode == "wrong_profile" else 5) * 1024**2,
            )
        state = verify_cohort_history(
            history, p, expected_tip_sha256=history_tip(history), current_block=300
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
        history = history.model_copy(update={"transitions": (*history.transitions, closing)})
        a = r.request.acceptance if mode == "legacy" else r.direct.acceptance
        cert = CertifiedModelArtifactAcceptance(acceptance=a, signatures=signatures(a))
        package = SimpleNamespace(
            policy_sha256=digest(p),
            inputs=SimpleNamespace(
                history=history,
                roster=SimpleNamespace(participants=(SimpleNamespace(record=r.direct.record),)),
            ),
            allocation=SimpleNamespace(model_award=SimpleNamespace(acceptances=(cert,))),
        )
        key = digest([digest(history), digest(cert)])

        def verified(actual):
            assert actual is package
            return key

        monkeypatch.setattr(module, "verified_package_digest", verified)
        return package, dict(package_sha256=key, cohort_sha256=r.cohort)

    return SimpleNamespace(owner=owner, build=build, request=r.direct)


def test_qualified_inventory_survives_restart_and_keeps_signed_bytes(package_case, monkeypatch):
    c = package_case
    package, context = c.build()
    original = canonical_json_bytes(c.request)
    q = module.PackageTransportQualifications(c.owner)
    assert q.load(*context.values()) is None
    result = q.qualify(package, **context)
    assert len(result["direct_acceptances"]) == 1
    monkeypatch.setattr(module, "verify_model_acceptance", no_work)
    monkeypatch.setattr(module, "verify_cohort_history", no_work)
    fresh = module.PackageTransportQualifications(c.owner)
    assert fresh.load(*context.values()) == result
    assert fresh.qualify(package, **context) == result
    assert canonical_json_bytes(c.request) == original


@pytest.mark.parametrize("mode", ["unadopted", "later", "wrong_profile"])
def test_old_direct_packages_cannot_borrow_later_transport(package_case, mode):
    c = package_case
    package, context = c.build(mode)
    q = module.PackageTransportQualifications(c.owner)
    with pytest.raises(ValueError, match="authenticated transport profile"):
        q.qualify(package, **context)
    assert q.load(*context.values()) is None


def test_legacy_package_retains_verified_empty_inventory(package_case, monkeypatch, caplog):
    c = package_case
    package, context = c.build("legacy")
    q = module.PackageTransportQualifications(c.owner)
    monkeypatch.setattr(module, "verify_model_acceptance", no_work)
    with caplog.at_level("INFO"):
        result = q.qualify(package, **context)
    assert result["direct_acceptances"] == []
    assert "package_model_transport_authorization" in caplog.text
    assert "completed" in caplog.text
    assert q.load(*context.values()) == result


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_explicit_repair_uses_completion_and_preserves_damaged_metadata(
    package_case, damage, monkeypatch
):
    c = package_case
    package, context = c.build()
    q = module.PackageTransportQualifications(c.owner)
    result = q.qualify(package, **context)
    with q.journal.transaction() as db:
        if damage == "missing":
            db.execute("DELETE FROM records WHERE kind=?", (module.KIND,))
        else:
            db.execute("UPDATE records SET body=? WHERE kind=?", (b'{"damaged":true}', module.KIND))
    with pytest.raises(module.PackageTransportRepairRequired):
        q.load(*context.values())
    monkeypatch.setattr(module, "verify_model_acceptance", no_work)
    monkeypatch.setattr(module, "verify_cohort_history", no_work)
    monkeypatch.setattr(module, "verified_package_digest", no_work)
    for _ in range(2):
        assert q.repair(*context.values(), reason="restore original completed metadata") == result
    assert module.PackageTransportQualifications(c.owner).load(*context.values()) == result
    with q.journal.read_transaction() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM records WHERE kind=?", (module.KIND + "_repair",)
        ).fetchone() == (1,)
        count, used, _ = q.journal._record_capacity(db)
        assert (count, used) == db.execute(
            "SELECT COUNT(*),SUM(LENGTH(body)) FROM records"
        ).fetchone()


def test_completed_ledger_is_immutable_and_lost_marker_is_not_legacy(package_case):
    c = package_case
    package, context = c.build()
    q = module.PackageTransportQualifications(c.owner)
    q.qualify(package, **context)
    with pytest.raises(sqlite3.IntegrityError), q.journal.transaction() as db:
        db.execute("DELETE FROM " + module.TABLE)
    q.marker.unlink()
    with pytest.raises(module.PackageTransportRepairRequired, match="marker was lost"):
        module.PackageTransportQualifications(c.owner)


@pytest.mark.parametrize("lost_ack", [False, True])
def test_interrupted_migration_retains_atomic_completion(
    package_case, lost_ack, monkeypatch, caplog
):
    c = package_case
    package, context = c.build()
    q = module.PackageTransportQualifications(c.owner)
    original = q.journal.put_many

    def interrupted(records, *, index):
        def failing(db):
            index(db)
            if not lost_ack:
                raise OSError("interrupted before commit")

        original(records, index=failing)
        raise OSError("lost acknowledgement")

    with monkeypatch.context() as patch, caplog.at_level("INFO"):
        patch.setattr(q.journal, "put_many", interrupted)
        with pytest.raises(OSError):
            q.qualify(package, **context)
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress" and record.message.startswith("{")
    ]
    final = [
        event for event in events if event.get("stage") == "package_model_transport_authorization"
    ][-1]
    assert final["status"] == "retrying" and final["eta_seconds"] is None
    if lost_ack:
        monkeypatch.setattr(module, "verify_model_acceptance", no_work)
    else:
        assert q.load(*context.values()) is None
    result = q.qualify(package, **context)
    assert q.load(*context.values()) == result


def test_corrupt_original_owner_is_an_explicit_scoped_repair(package_case):
    c = package_case
    package, context = c.build()
    q = module.PackageTransportQualifications(c.owner)
    q.qualify(package, **context)
    q.marker.write_bytes(b"{}")
    with pytest.raises(module.PackageTransportRepairRequired, match=r"owner.*repair"):
        module.PackageTransportQualifications(c.owner)


@pytest.mark.parametrize("operation", ["restore", "qualify"])
def test_required_repair_is_the_final_progress_state(package_case, operation, caplog):
    c = package_case
    package, context = c.build("unadopted" if operation == "qualify" else "valid")
    q = module.PackageTransportQualifications(c.owner)
    if operation == "restore":
        q.qualify(package, **context)
        with q.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind=?", (module.KIND,))
    caplog.clear()
    with caplog.at_level("INFO"), pytest.raises(ValueError):
        if operation == "restore":
            q.load(*context.values())
        else:
            q.qualify(package, **context)
    stage = "package_model_transport_" + ("restore" if operation == "restore" else "authorization")
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress" and record.message.startswith("{")
    ]
    final = [event for event in events if event.get("stage") == stage][-1]
    assert final["status"] == "repair_required"
    assert final["eta_seconds"] is None and final["planning_eta_seconds"] is None
