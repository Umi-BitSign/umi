"""Completed native preparation survives restart without becoming fresh work."""

import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi import competition_reward_preparation_checkpoint as module
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

ACTIVATION = "10" * 32
PACKAGE = "20" * 32
BINDING = {"policy": "30" * 32, "series": "40" * 32, "semantics": "50" * 32}


@pytest.mark.parametrize("state", ["draining", "pending"])
def test_initial_preparation_preserves_original_pending_activation_contract(state):
    from umi.competition_reward_preparation import StandingRewardPreparation

    plan = {"cohort": "initial"}
    activation = SimpleNamespace(cohort_sha256=digest(plan))
    selected = SimpleNamespace(sequence=1, activation=activation, state=state)
    reader = SimpleNamespace(
        series=SimpleNamespace(cohorts=(plan,)),
        review_history=lambda *args: SimpleNamespace(
            initial_selection=selected, effective_selection=selected
        ),
    )
    owner = SimpleNamespace(_authority=lambda: None, reader=reader)
    assert StandingRewardPreparation._activation(owner, None, None, None, "initial") is activation
    with pytest.raises(ValueError, match="no effective reward package"):
        StandingRewardPreparation._activation(owner, None, None, None, "historical")


def result(block=100, activation=ACTIVATION, package=PACKAGE):
    return {
        "activation_sha256": activation,
        "package_sha256": package,
        "reviewed_at_block": block,
        "allocation_sha256": "60" * 32,
        "binding": {"round": "70" * 32},
    }


@pytest.fixture
def checkpoints(tmp_path):
    return module.PreparationCheckpoints(tmp_path / "preparation", BINDING)


def retained(checkpoints, block=100):
    checkpoints.begin(ACTIVATION, PACKAGE)
    checkpoints.retain_native(ACTIVATION, block, result(block))
    return checkpoints.key(ACTIVATION, block)


def test_first_interrupted_and_completed_preparations_survive_restart(checkpoints):
    root = checkpoints.root
    assert checkpoints.status(ACTIVATION, 100) is None
    checkpoints.begin(ACTIVATION, PACKAGE)
    interrupted = module.PreparationCheckpoints(root, BINDING)
    assert interrupted.status(ACTIVATION, 100) is None
    interrupted.begin(ACTIVATION, PACKAGE)
    interrupted.retain_native(ACTIVATION, 100, result())
    restart = module.PreparationCheckpoints(root, BINDING)
    assert restart.status(ACTIVATION, 100) == result()
    assert restart.status(ACTIVATION, 99) is None
    key = restart.key(ACTIVATION, 100)
    assert restart.load_completion(key) is None
    value = {"models": {"mode": "empty"}, "snapshot": {"stamp": [1, 2, 3]}}
    restart.retain_completion(key, value)
    final = module.PreparationCheckpoints(root, BINDING)
    assert final.load_completion(key) == value
    final.begin(ACTIVATION, PACKAGE)
    final.retain_native(ACTIVATION, 100, result())
    final.retain_completion(key, value)
    assert final.status(ACTIVATION, 101) == result()


def test_earliest_eligible_native_fact_is_selected_without_backdating(checkpoints):
    checkpoints.begin(ACTIVATION, PACKAGE)
    for block in (130, 110, 150):
        checkpoints.retain_native(ACTIVATION, block, result(block))
    assert checkpoints.status(ACTIVATION, 109) is None
    assert checkpoints.status(ACTIVATION, 110) == result(110)
    assert checkpoints.status(ACTIVATION, 140) == result(110)
    assert checkpoints.status(ACTIVATION, 160) == result(110)
    other = "80" * 32
    assert checkpoints.status(other, 160) is None
    checkpoints.begin(other, PACKAGE)
    checkpoints.retain_native(other, 105, result(105, activation=other))
    assert checkpoints.status(other, 160) == result(105, activation=other)


def test_full_allocation_payload_keeps_room_for_native_dependency_envelope(checkpoints):
    value = result()
    value["allocation"] = {"retained_native_bytes": "x" * module.MAX_REWARD_ALLOCATION_BYTES}
    checkpoints.begin(ACTIVATION, PACKAGE)
    checkpoints.retain_native(ACTIVATION, 100, value)
    reopened = module.PreparationCheckpoints(checkpoints.root, BINDING)
    assert reopened.status(ACTIVATION, 100) == value


@pytest.mark.parametrize("damage", ["primary", "mirror", "both", "changed"])
@pytest.mark.parametrize("kind", [module.NATIVE, module.COMPLETE])
def test_missing_or_changed_completed_records_require_repair(checkpoints, damage, kind):
    key = retained(checkpoints)
    checkpoints.retain_completion(key, {"qualified": {"models": []}})
    with checkpoints.journal.transaction() as db:
        if damage in ("primary", "both"):
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, key))
        if damage in ("mirror", "both"):
            name = module.TABLE + "_delete"
            db.execute(f"DROP TRIGGER {name}")
            db.execute(f"DELETE FROM {module.TABLE} WHERE kind=? AND id=?", (kind, key))
            db.execute(module._triggers()[name])
        if damage == "changed":
            value = result() if kind == module.NATIVE else {"different": "completion"}
            value["modified"] = True
            db.execute(
                "UPDATE records SET body=? WHERE kind=? AND id=?",
                (canonical_json_bytes(value), kind, key),
            )
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.status(ACTIVATION, 100)
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        module.PreparationCheckpoints(checkpoints.root, BINDING)


@pytest.mark.parametrize("damage", ["marker", "database", "replacement", "schema", "binding"])
def test_owner_or_schema_loss_never_becomes_first_preparation(checkpoints, damage):
    retained(checkpoints)
    if damage == "marker":
        checkpoints.marker.unlink()
    elif damage == "database":
        checkpoints.journal.path.unlink()
    elif damage == "replacement":
        original = checkpoints.journal.path.with_suffix(".original")
        checkpoints.journal.path.rename(original)
        checkpoints.journal.path.write_bytes(original.read_bytes())
        checkpoints.journal.path.chmod(0o600)
    else:
        with checkpoints.journal.transaction() as db:
            if damage == "schema":
                db.execute(f"DROP INDEX {module.INDEX}")
            else:
                db.execute("UPDATE binding SET body=?", (b'{"wrong":"binding"}',))
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.status(ACTIVATION, 100)
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        module.PreparationCheckpoints(checkpoints.root, BINDING)


@pytest.mark.parametrize("action", ["UPDATE", "DELETE"])
@pytest.mark.parametrize("target", ["ledger", "owner"])
def test_completion_ledger_and_owner_are_immutable(checkpoints, action, target):
    retained(checkpoints)
    table = module.TABLE if target == "ledger" else "records"
    condition = "" if target == "ledger" else " WHERE kind='" + module.OWNER + "'"
    statement = (
        f"UPDATE {table} SET body=body{condition}"
        if action == "UPDATE"
        else f"DELETE FROM {table}{condition}"
    )
    with pytest.raises(sqlite3.IntegrityError), checkpoints.journal.transaction() as db:
        db.execute(statement)
    assert checkpoints.status(ACTIVATION, 100) == result()


def test_changed_context_and_cross_binding_are_refused(checkpoints):
    key = retained(checkpoints)
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        module.PreparationCheckpoints(checkpoints.root, {**BINDING, "semantics": "81" * 32})
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.begin(ACTIVATION, "82" * 32)
    with pytest.raises(ValueError, match="activation or reviewed block"):
        checkpoints.retain_native(ACTIVATION, 100, result(101))
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.retain_native(ACTIVATION, 100, result(package="83" * 32))
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.retain_native("84" * 32, 100, result(activation="84" * 32))
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.retain_completion(checkpoints.key(ACTIVATION, 101), {})
    checkpoints.retain_completion(key, {"status": "complete"})
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.retain_completion(key, {"status": "changed"})
    assert checkpoints.status(ACTIVATION, 100) == result()
    assert checkpoints.load_completion(key) == {"status": "complete"}


@pytest.mark.parametrize("lost_ack", [False, True])
@pytest.mark.parametrize("kind", [module.NATIVE, module.COMPLETE])
def test_native_and_completion_commits_are_atomic(checkpoints, monkeypatch, lost_ack, kind):
    checkpoints.begin(ACTIVATION, PACKAGE)
    key = checkpoints.key(ACTIVATION, 100)
    if kind == module.COMPLETE:
        checkpoints.retain_native(ACTIVATION, 100, result())
    original = checkpoints.journal.transaction

    @contextmanager
    def interrupted():
        with original() as db:
            yield db
            if not lost_ack:
                raise OSError("interrupted before commit")
        raise OSError("lost commit acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(checkpoints.journal, "transaction", interrupted)
        with pytest.raises((OSError, module.PreparationCheckpointRepairRequired)):
            if kind == module.NATIVE:
                checkpoints.retain_native(ACTIVATION, 100, result())
            else:
                checkpoints.retain_completion(key, {"dependencies": []})
    restart = module.PreparationCheckpoints(checkpoints.root, BINDING)
    if kind == module.NATIVE:
        assert restart.status(ACTIVATION, 100) == (result() if lost_ack else None)
        restart.retain_native(ACTIVATION, 100, result())
    else:
        assert restart.load_completion(key) == ({"dependencies": []} if lost_ack else None)
        restart.retain_completion(key, {"dependencies": []})


@pytest.mark.parametrize(
    "key", ["bad", ACTIVATION + ":01", ACTIVATION + ":-1", ACTIVATION + ":True"]
)
def test_malformed_native_keys_are_rejected(checkpoints, key):
    with pytest.raises(ValueError):
        checkpoints.load_completion(key)


def test_damage_is_checked_even_when_querying_unstarted_activation(checkpoints):
    retained(checkpoints)
    with checkpoints.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=?", (module.NATIVE,))
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.status("90" * 32, 100)
    with pytest.raises(module.PreparationCheckpointRepairRequired):
        checkpoints.begin("90" * 32, PACKAGE)


@pytest.mark.parametrize("mode", ["native_required", "not_selected"])
async def test_interrupted_dependency_capture_cannot_drop_model_checks(
    checkpoints, monkeypatch, mode
):
    """Native replay completion alone does not complete mutable model dependencies."""
    from umi import competition_reward_coverage_models as models
    from umi.competition_reward_decisions import RewardActivation
    from umi.competition_reward_preparation_reuse import PreparationReuse

    activation = RewardActivation(
        cohort_sha256="80" * 32,
        allocation_sha256="81" * 32,
        package_sha256=PACKAGE,
        recovery_tip_sha256="82" * 32,
        prior_opportunity_sha256="83" * 32,
    )
    activation_sha = digest(activation)
    checkpoints.begin(activation_sha, PACKAGE)
    checkpoints.retain_native(activation_sha, 100, result(activation=activation_sha))
    key = checkpoints.key(activation_sha, 100)
    prepared = SimpleNamespace(activation=activation, reviewed_at_block=100, allocation=object())
    package = SimpleNamespace(allocation=prepared.allocation)
    events = []
    owner = SimpleNamespace(
        model_artifacts=None,
        cohort_sha256s=frozenset({activation.cohort_sha256}),
        model_deliveries={
            activation.cohort_sha256: SimpleNamespace(mechanism="direct_r2_multipart_v1")
        },
        _check_prepared=lambda value: events.append("checked"),
        _export_allocations=lambda *args: events.append("exported"),
        _prepared={},
    )
    reuse = object.__new__(PreparationReuse)
    reuse.preparation, reuse.store, reuse.models_checked = owner, checkpoints, {}

    async def capture(*args):
        return {"schema": models.ABI, "mode": mode, "context": None, "items": []}

    async def native_assets(*args):
        events.append("native_assets_checked")

    monkeypatch.setattr(models, "capture_coverage_model_dependencies", capture)
    monkeypatch.setattr(reuse, "_refresh_legacy_models", native_assets)
    if mode == "not_selected":
        with pytest.raises(
            models.CoverageModelDependencyRepairRequired, match="direct model cohort"
        ):
            await reuse.finish(package, prepared)
        assert checkpoints.load_completion(key) is None and events == []
    else:
        await reuse.finish(package, prepared)
        assert events == ["native_assets_checked", "checked", "exported"]
        assert checkpoints.load_completion(key)["models"]["mode"] == mode
