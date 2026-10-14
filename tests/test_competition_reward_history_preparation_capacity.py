"""Preserving capacity transition with real controls, anchor and kernel mutexes."""

import fcntl
import hashlib
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_preparation as preparation
from umi import competition_reward_history_preparation_capacity as capacity
from umi import competition_reward_history_preparation_runtime as runtime
from umi import competition_reward_writer_broker as broker
from umi.competition_reward_host import StandingRewardHostApproval
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_history_preparation import (  # noqa: F401
    activation_case,
    anchor_case,
    boot_inputs,
    case,
    chain,
    chain_config,
    control,
    explicit,
    installed_case,
    launch_case,
    limits,
    package_case,
    package_limits,
    policy,
    release_identity,
    replay_limits,
    series_case,
    successor_release,
    trusted_ports,
    worker_capacity,
)


@pytest.fixture
def migration(launch_case, monkeypatch):  # noqa: F811
    item, c = launch_case, launch_case.case
    # Bind the unchanged ordinary host approval to the genuine installed anchor.
    ordinary = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/1",
        source_config_sha256=digest(c.anchor.config),
        installation_receipt_sha256=c.anchor.receipt_sha256,
        host_manifest_sha256=c.anchor.receipt.host_manifest_sha256,
        validator_hotkey=c.anchor.config.validator_hotkey,
        series_sha256=digest(c.config.series),
        policy_sha256=digest(c.config.policy),
        manifest_sha256=digest(c.config.manifest),
        chain_config_sha256=digest(c.config.chain),
        legacy_handoff_plan_sha256=digest(c.config.handoff),
    )
    c.save(c.held, canonical_json_bytes(ordinary))
    with c.open():
        pass
    native = c.root / "history"
    db = sqlite3.connect(native / "rounds.sqlite3")
    db.execute("CREATE TABLE binding (body BLOB)")
    db.execute("INSERT INTO binding VALUES (?)", (b"original native binding",))
    db.execute("CREATE TABLE records (kind TEXT, id TEXT, body BLOB)")
    db.execute("INSERT INTO records VALUES ('checkpoint','100',?)", (b"unchanged signed input",))
    db.commit()
    db.close()
    (native / "rounds.lock").write_bytes(b"")
    for path in native.iterdir():
        path.chmod(0o600)
        if os.getgid() == 0:
            os.chown(path, os.getuid(), c.approval.service_gid)
    new_config = c.config.model_copy(update={"maximum_history_bytes": 64 * 1024**3})
    new_boot = c.boot.with_name("larger-boot.json")
    c.save(new_boot, canonical_json_bytes(new_config))
    new_approval = c.approval.model_copy(
        update={
            "standing_boot_raw_sha256": hashlib.sha256(canonical_json_bytes(new_config)).hexdigest()
        }
    )
    approval_path = c.path.with_name("larger-approval.json")
    c.save(approval_path, canonical_json_bytes(new_approval))
    new_launch = item.launch.model_copy(
        update={"preparation_approval_sha256": digest(new_approval)}
    )
    launch_path = item.path.with_name("larger-launch.json")
    c.save(launch_path, canonical_json_bytes(new_launch))
    # Systemd is the explicit fixture boundary; no real service is changed.
    monkeypatch.setattr(capacity, "stopped_preparation_service", lambda *a, **k: ("stopped",))
    args = dict(
        old_boot=c.boot,
        new_boot=new_boot,
        old_approval=c.path,
        new_approval=approval_path,
        preparation_launch=(item.path, launch_path),
        writer_launch=(item.path, launch_path),
        preparation_unit="umi-isolated-preparation.service",
        installed_unit="umi-validator@54.service",
        config_path=Path("/etc/umi/validator-supervisor.json"),
        held_approval=c.held,
    )
    return SimpleNamespace(
        c=c,
        args=args,
        config=new_config,
        approval=new_approval,
        launch=new_launch,
        run=lambda: capacity.migrate_preparation_capacity(c.anchor, **args),
    )


def record(migration, completed=False):
    return capacity._migration_paths(migration.c.root, migration.approval.standing_boot_raw_sha256)[
        int(completed)
    ]


def snapshot(c):
    return {
        str(p): (p.stat().st_ino, p.stat().st_nlink, p.read_bytes() if p.is_file() else None)
        for p in (
            c.root,
            c.root / "history",
            c.root / "history/rounds.sqlite3",
            c.root / "history/rounds.lock",
            c.held,
            c.writer_lock,
        )
    }


def test_preserving_increase_repeat_and_both_native_launch_consumers(
    migration, monkeypatch, caplog
):
    m, c = migration, migration.c
    before = snapshot(c)
    inode = (c.root / "preparation.lock").stat().st_ino
    caplog.set_level("INFO", logger="umi.competition.progress")
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: pytest.fail("migration opened SQLite"))
    result = m.run()
    assert m.run() == result
    assert snapshot(c) == before
    assert (c.root / "preparation.lock").stat().st_ino == inode
    assert result["maximum_history_bytes"] == 64 * 1024**3
    with preparation.hold_history_preparation_lease(
        c.anchor, standing_boot=m.args["new_boot"], approval_path=m.args["new_approval"]
    ) as lease:
        assert lease.config.maximum_history_bytes == 64 * 1024**3
        command, selected = runtime.preparation_command(
            lease, launch_path=m.args["preparation_launch"][1], standing_boot=m.args["new_boot"]
        )
        assert str(m.args["new_boot"]) in command and selected == m.launch
    args = SimpleNamespace(
        standing_boot=m.args["new_boot"],
        held_approval=c.held,
        launch=m.args["writer_launch"][1],
        preparation_approval=m.args["new_approval"],
        history="current",
        unit=m.args["installed_unit"],
        config=m.args["config_path"],
        readiness_only=True,
    )
    command, approval, _ = broker.writer_broker_command(c.anchor, args, 100)
    assert command[command.index("--standing-boot") + 1] == str(m.args["new_boot"])
    assert approval == m.approval
    assert '"completed":4' in caplog.text and '"eta_seconds":0' in caplog.text
    assert '"planning_eta_seconds"' in caplog.text
    with pytest.raises(ValueError, match="cannot change scope"), c.open():
        pytest.fail("old launcher accepted migrated scope")


@pytest.mark.parametrize("phase", ["before_truncate", "after_truncate", "prefix", "after_write"])
def test_same_inode_recovery_after_scope_interruption(migration, monkeypatch, phase, caplog):
    m, c = migration, migration.c
    before = snapshot(c)
    inode = (c.root / "preparation.lock").stat().st_ino
    original = capacity._rewrite_scope

    def crash(fd, raw):
        if phase != "before_truncate":
            os.ftruncate(fd, 0)
        if phase in {"prefix", "after_write"}:
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, raw if phase == "after_write" else raw[:37])
            os.fsync(fd)
        raise RuntimeError("injected crash")

    monkeypatch.setattr(capacity, "_rewrite_scope", crash)
    with pytest.raises(RuntimeError, match="injected"):
        m.run()
    assert record(m).is_file()
    assert snapshot(c) == before
    monkeypatch.setattr(capacity, "_rewrite_scope", original)
    caplog.set_level("INFO", logger="umi.competition.progress")
    m.run()
    assert snapshot(c) == before
    assert (c.root / "preparation.lock").stat().st_ino == inode
    if phase != "after_write":
        assert '"state":"repairing"' in caplog.text


@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("prefix", [0, 29])
def test_interrupted_intent_and_completion_publication(migration, monkeypatch, completed, prefix):
    m, c = migration, migration.c
    original = capacity._publish_exact

    def interrupted(path, raw, **kwargs):
        if path == record(m, completed):
            path.with_suffix(".pending").write_bytes(raw[:prefix])
            path.with_suffix(".pending").chmod(0o600)
            raise RuntimeError("injected publication")
        return original(path, raw, **kwargs)

    monkeypatch.setattr(capacity, "_publish_exact", interrupted)
    with pytest.raises(RuntimeError, match="injected"):
        m.run()
    monkeypatch.setattr(capacity, "_publish_exact", original)
    m.run()
    assert not list(c.root.glob("*.pending"))


@pytest.mark.parametrize("path", ["preparation.lock", "history/rounds.lock"])
def test_live_mutex_owner_prevents_migration(migration, path):
    m, c = migration, migration.c
    before = (c.root / "preparation.lock").read_bytes()
    descriptor = os.open(c.root / path, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            m.run()
    finally:
        os.close(descriptor)
    assert (c.root / "preparation.lock").read_bytes() == before
    assert not record(m).exists()


@pytest.mark.parametrize(
    "fault",
    [
        "lower",
        "other_boot",
        "other_approval",
        "other_launch",
        "selection",
        "sidecar",
        "wrong_scope",
        "running",
    ],
)
def test_unsupported_transition_refuses_before_mutating_scope(migration, monkeypatch, fault):
    m, c = migration, migration.c
    before = (c.root / "preparation.lock").read_bytes()
    if fault in {"lower", "other_boot"}:
        update = (
            {"maximum_history_bytes": c.config.maximum_history_bytes}
            if fault == "lower"
            else {
                "maximum_header_bytes": c.config.maximum_header_bytes + 1024,
            }
        )
        value = m.config.model_copy(update=update)
        c.save(m.args["new_boot"], canonical_json_bytes(value))
        c.save(
            m.args["new_approval"],
            canonical_json_bytes(
                m.approval.model_copy(
                    update={
                        "standing_boot_raw_sha256": hashlib.sha256(
                            canonical_json_bytes(value)
                        ).hexdigest()
                    }
                )
            ),
        )
    elif fault == "other_approval":
        c.save(
            m.args["new_approval"],
            canonical_json_bytes(m.approval.model_copy(update={"through_block": 201})),
        )
    elif fault == "other_launch":
        c.save(
            m.args["writer_launch"][1],
            canonical_json_bytes(m.launch.model_copy(update={"through_block": 199})),
        )
    elif fault == "selection":
        (c.root / "history-selection-existing.json").write_bytes(b"retained")
    elif fault == "sidecar":
        (c.root / "history/rounds.sqlite3-journal").write_bytes(b"unfinished transaction")
    elif fault == "wrong_scope":
        (c.root / "preparation.lock").write_bytes(b"unrelated")
        before = b"unrelated"
    else:
        monkeypatch.setattr(
            capacity,
            "stopped_preparation_service",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("running")),
        )
    with pytest.raises(ValueError):
        m.run()
    assert (c.root / "preparation.lock").read_bytes() == before
    assert not record(m).exists()


@pytest.mark.parametrize(
    "fault", ["lock_inode", "unrelated_bytes", "database_changed", "lost_intent"]
)
def test_durable_recovery_refuses_unrelated_repair(migration, monkeypatch, fault):
    m, c = migration, migration.c
    original = capacity._rewrite_scope
    monkeypatch.setattr(
        capacity, "_rewrite_scope", lambda *a: (_ for _ in ()).throw(RuntimeError("crash"))
    )
    with pytest.raises(RuntimeError):
        m.run()
    monkeypatch.setattr(capacity, "_rewrite_scope", original)
    lock = c.root / "preparation.lock"
    if fault == "lock_inode":
        prior = lock.read_bytes()
        lock.rename(c.root / "retained-original-lock")
        lock.write_bytes(prior)
        lock.chmod(0o600)
    elif fault == "unrelated_bytes":
        lock.write_bytes(b"unrelated")
    elif fault == "database_changed":
        with (c.root / "history/rounds.sqlite3").open("ab") as output:
            output.write(b"unexpected")
    else:
        record(m).unlink()
        lock.write_bytes(b"")
    with pytest.raises(ValueError):
        m.run()


def test_later_capacity_increase_retains_completed_migration_and_native_data(migration):
    m, c = migration, migration.c
    m.run()
    completed = record(m).read_bytes(), record(m, True).read_bytes()
    before = snapshot(c)
    larger = m.config.model_copy(update={"maximum_history_bytes": 128 * 1024**3})
    boot = m.args["new_boot"].with_name("second-larger-boot.json")
    approval_path = m.args["new_approval"].with_name("second-larger-approval.json")
    launch_path = m.args["preparation_launch"][1].with_name("second-larger-launch.json")
    approval = m.approval.model_copy(
        update={
            "standing_boot_raw_sha256": hashlib.sha256(canonical_json_bytes(larger)).hexdigest(),
        }
    )
    launch = m.launch.model_copy(update={"preparation_approval_sha256": digest(approval)})
    for path, value in ((boot, larger), (approval_path, approval), (launch_path, launch)):
        c.save(path, canonical_json_bytes(value))
    m.args.update(
        old_boot=m.args["new_boot"],
        new_boot=boot,
        old_approval=m.args["new_approval"],
        new_approval=approval_path,
        preparation_launch=(m.args["preparation_launch"][1], launch_path),
        writer_launch=(m.args["writer_launch"][1], launch_path),
    )
    assert m.run()["maximum_history_bytes"] == 128 * 1024**3
    assert snapshot(c) == before
    assert (record(m).read_bytes(), record(m, True).read_bytes()) == completed
    assert len(list(c.root.glob("capacity-migration-*.completed.json"))) == 2


def test_another_unfinished_migration_is_not_bypassed(migration):
    m, c = migration, migration.c
    (c.root / ("capacity-migration-" + "ab" * 32 + ".json")).write_bytes(b"retained")
    with pytest.raises(ValueError, match="lacks durable completion"):
        m.run()
    assert not record(m).exists()


def test_private_boot_parent_cannot_strand_dropped_writer(tmp_path):
    tmp_path.chmod(0o700)
    with pytest.raises(ValueError, match="cannot traverse"):
        capacity._writer_can_read_boot(tmp_path / "boot.json", os.getuid() + 10, os.getgid() + 10)
