from __future__ import annotations

import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_exchange import ExchangeConfig, ExchangeJournal
from umi.competition_exchange_migration import (
    TABLE,
    exchange_binding,
    launch_fences,
    migrate_exchange_launch,
)
from umi.competition_policy_lineage import register_lineage
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .competition_checkpoint import bind_submission_checkpoint
from .test_competition_chain import chain_config as chain_config
from .test_competition_continuous_launch import future_amendment
from .test_competition_round_preparation import setup as setup
from .test_open_competition import policy as policy


@pytest.fixture
def transition(setup, chain_config, tmp_path):
    previous, replacement, signed = future_amendment(setup)
    checkpoint = tmp_path / "checkpoint"
    store = bind_submission_checkpoint(setup.store, previous, checkpoint)
    store.prepare_round(**setup.options)
    old = ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(setup.policy),
        public_launch=previous,
        chain=chain_config.model_copy(
            update={"collection_timeout_seconds": 10, "state_directory": str(tmp_path / "chain")}
        ),
        state_directory=str(tmp_path / "exchange"),
        order_directory=str(tmp_path / "orders"),
        reveal_directory=str(tmp_path / "reveals"),
        intake_directory=str(store.directory),
        submission_head_checkpoint_directory=str(checkpoint),
    )
    new = old.model_copy(update={"public_launch": replacement})
    journal = ExchangeJournal(old, setup.policy)
    event = journal.append("a1" * 32, "suite", None, setup.options["suite"], 150)
    with journal.transaction() as db:
        db.execute("INSERT INTO audience VALUES (?,?)", ("a1" * 32, "fixture-account"))
        db.execute("INSERT INTO collected VALUES (?)", (event,))
    journal.observe(190)
    return SimpleNamespace(
        setup=setup,
        store=store,
        old=old,
        new=new,
        signed=signed,
        journal=journal,
        checkpoint=checkpoint,
        policy=setup.policy,
    )


def commit_intake(t):
    t.store = CompetitionStore(
        t.store.directory,
        t.policy,
        public_launch=t.new.public_launch,
        submission_head_checkpoint_directory=t.checkpoint,
        launch_amendment=t.signed,
        amendment_observed_block=200,
        migrate_writer_generation=True,
    )


def migrate(t, *, confirmed=True, replacement=None):
    return migrate_exchange_launch(t.old, replacement or t.new, t.policy, confirmed=confirmed)


def snapshot(path, tables=None):
    with sqlite3.connect(path) as db:
        if tables is None:
            tables = [
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ]
        return {
            table: db.execute(f'SELECT * FROM "{table}" ORDER BY 1').fetchall() for table in tables
        }


def test_committed_future_amendment_preserves_history_reopens_and_retries(transition):
    t = transition
    commit_intake(t)
    tables = ("events", "audience", "collected", "highwater", "sqlite_sequence")
    before = snapshot(t.journal.path, tables)
    intake_before = snapshot(t.store.path)
    checkpoint_before = (t.checkpoint / "submission-head.json").read_bytes()
    with pytest.raises(ValueError, match="configuration changed"):
        ExchangeJournal(t.new, t.policy)
    result = migrate(t)
    assert result["status"] == "migrated"
    assert result["intake_history_sequence"] == 2
    assert result["signed_amendment"] == t.signed.model_dump(mode="json", by_alias=True)
    assert snapshot(t.journal.path, tables) == before
    assert snapshot(t.store.path) == intake_before
    assert (t.checkpoint / "submission-head.json").read_bytes() == checkpoint_before
    all_before_retry = snapshot(t.journal.path)
    assert migrate(t)["status"] == "already_migrated"
    assert snapshot(t.journal.path) == all_before_retry
    reopened = ExchangeJournal(t.new, t.policy)
    assert reopened.object("a1" * 32, "suite") == t.setup.options["suite"]
    assert reopened.append("a1" * 32, "suite", None, t.setup.options["suite"], 201) == 1
    assert reopened.append("a2" * 32, "suite", None, t.setup.options["suite"], 201) == 2
    reopened.observe(201)
    assert snapshot(t.journal.path, ("collected",))["collected"] == [(1,)]


@pytest.mark.parametrize("confirmed", [False, None, 1, "yes"])
def test_requires_explicit_quiesced_backup_confirmation(transition, confirmed):
    before = snapshot(transition.journal.path)
    with pytest.raises(ValueError, match="quiesced"):
        migrate(transition, confirmed=confirmed)
    assert snapshot(transition.journal.path) == before


def test_signed_document_alone_does_not_authorize_exchange(transition):
    before = snapshot(transition.journal.path)
    with pytest.raises(ValueError, match="intake has not committed"):
        migrate(transition)
    assert snapshot(transition.journal.path) == before


@pytest.mark.parametrize(
    "field",
    [
        "port",
        "maximum_orders",
        "maximum_events",
        "maximum_bytes",
        "state_directory",
        "order_directory",
        "reveal_directory",
        "intake_directory",
        "submission_head_checkpoint_directory",
        "legacy_policy_sha256",
        "chain",
    ],
)
def test_refuses_every_unrelated_config_change(transition, field):
    t = transition
    commit_intake(t)
    value = getattr(t.new, field)
    if field == "chain":
        value = value.model_copy(update={"rpc_url": "wss://other.example"})
    elif field == "legacy_policy_sha256":
        value = "b1" * 32
    elif isinstance(value, int):
        value += 1
    else:
        value += "-other"
    before = snapshot(t.journal.path)
    with pytest.raises(ValueError, match="only an existing public launch"):
        migrate(t, replacement=t.new.model_copy(update={field: value}))
    assert snapshot(t.journal.path) == before


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_amendment",
        "bad_quorum",
        "noncanonical_amendment",
        "wrong_history",
        "wrong_policy",
        "wrong_role",
        "stale_checkpoint",
        "wrong_checkpoint_binding",
    ],
)
def test_rejects_uncommitted_or_corrupt_intake_proof(transition, corruption):
    t = transition
    checkpoint_before = (t.checkpoint / "submission-head.json").read_bytes()
    commit_intake(t)
    with t.store._connection() as db:
        if corruption == "missing_amendment":
            db.execute("DELETE FROM public_launch_amendments")
        elif corruption in {"bad_quorum", "noncanonical_amendment"}:
            body = canonical_json_bytes(t.signed)
            if corruption == "bad_quorum":
                body = canonical_json_bytes(
                    t.signed.model_copy(update={"signatures": t.signed.signatures[:1]})
                )
            else:
                body += b"\n"
            db.execute("UPDATE public_launch_amendments SET body=?", (body,))
        elif corruption == "wrong_history":
            db.execute("UPDATE public_launch_history SET schedule=? WHERE sequence=2", ("e1" * 32,))
        elif corruption == "stale_checkpoint":
            (t.checkpoint / "submission-head.json").write_bytes(checkpoint_before)
        else:
            key = {
                "wrong_policy": "policy",
                "wrong_role": "role",
                "wrong_checkpoint_binding": "submission_head_checkpoint_binding",
            }[corruption]
            db.execute("UPDATE metadata SET value=? WHERE key=?", ("invalid", key))
    before = snapshot(t.journal.path)
    with pytest.raises((ValueError, RuntimeError)):
        migrate(t)
    assert snapshot(t.journal.path) == before


def test_stale_instance_old_config_and_legacy_connection_cannot_write(transition):
    t = transition
    commit_intake(t)
    # Keep an actual SQLite connection open across migration, as an old process could.
    legacy = sqlite3.connect(t.journal.path, isolation_level=None)
    try:
        migrate(t)
        before = snapshot(t.journal.path)
        with pytest.raises(ValueError, match="stale exchange launch"):
            t.journal.observe(201)
        with pytest.raises(ValueError, match="stale exchange launch"):
            ExchangeJournal(t.old, t.policy)
        for statement in (
            "UPDATE binding SET body=body",
            "DELETE FROM events",
            "DELETE FROM audience",
            "DELETE FROM collected",
            "DELETE FROM highwater",
            f"INSERT INTO {TABLE} SELECT * FROM {TABLE}",
        ):
            with pytest.raises(sqlite3.OperationalError, match="umi_exchange_launch_writer"):
                legacy.execute(statement)
        assert snapshot(t.journal.path) == before
    finally:
        legacy.close()


def test_migration_rollback_is_atomic_if_fence_install_fails(transition, monkeypatch):
    from umi import competition_exchange_migration as module

    t = transition
    commit_intake(t)
    before = snapshot(t.journal.path)
    monkeypatch.setattr(module, "launch_fences", lambda: {"bad": "invalid SQL"})
    with pytest.raises(sqlite3.OperationalError):
        migrate(t)
    assert snapshot(t.journal.path) == before


def test_receipts_immutable_and_missing_fence_rejected(transition):
    t = transition
    commit_intake(t)
    migrate(t)
    new = ExchangeJournal(t.new, t.policy)
    for operation in (f"UPDATE {TABLE} SET body=body", f"DELETE FROM {TABLE}"):
        with (
            pytest.raises(sqlite3.IntegrityError, match="immutable exchange launch"),
            new.transaction() as db,
        ):
            db.execute(operation)
    with sqlite3.connect(t.journal.path) as db:
        db.execute(f"DROP TRIGGER {next(iter(launch_fences()))}")
    with pytest.raises(ValueError, match="fences changed"):
        ExchangeJournal(t.new, t.policy)


def test_rollback_and_mismatched_retry_refused(transition):
    t = transition
    commit_intake(t)
    migrate(t)
    before = snapshot(t.journal.path)
    with pytest.raises(ValueError):
        migrate_exchange_launch(t.new, t.old, t.policy, confirmed=True)
    changed = t.signed.model_copy(update={"signatures": tuple(reversed(t.signed.signatures))})
    with t.store._connection() as db:
        db.execute("UPDATE public_launch_amendments SET body=?", (canonical_json_bytes(changed),))
    with pytest.raises(ValueError, match="retry differs"):
        migrate(t)
    assert snapshot(t.journal.path) == before


def test_policy_lineage_reopen_remains_supported_after_launch_migration(transition):
    t = transition
    commit_intake(t)
    migrate(t)
    successor = t.policy.model_copy(
        update={
            "sequence": t.policy.sequence + 1,
            "predecessor_sha256": digest(t.policy),
        }
    )
    register_lineage(successor, [t.policy])
    config = t.new.model_copy(
        update={
            "policy_sha256": digest(successor),
            "chain": t.new.chain.model_copy(update={"policy_sha256": digest(successor)}),
        }
    )
    journal = ExchangeJournal(config, successor)
    journal.observe(201)
    assert snapshot(journal.path, ("binding",))["binding"] == [(exchange_binding(config),)]


def test_second_native_future_amendment_keeps_both_receipts(transition):
    t = transition
    commit_intake(t)
    migrate(t)
    t.old = t.new
    _, replacement, t.signed = future_amendment(
        t.setup, previous=t.old.public_launch, effective=400
    )
    t.new = t.old.model_copy(update={"public_launch": replacement})
    t.store = CompetitionStore(
        t.store.directory,
        t.policy,
        public_launch=replacement,
        submission_head_checkpoint_directory=t.checkpoint,
        launch_amendment=t.signed,
        amendment_observed_block=400,
        migrate_writer_generation=True,
    )
    tables = ("events", "audience", "collected", "highwater", "sqlite_sequence")
    before = snapshot(t.journal.path, tables)
    assert migrate(t)["status"] == "migrated"
    assert migrate(t)["status"] == "already_migrated"
    assert len(snapshot(t.journal.path, (TABLE,))[TABLE]) == 2
    assert snapshot(t.journal.path, tables) == before
    ExchangeJournal(t.new, t.policy).observe(401)


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "public"])
def test_unsafe_exchange_database_refused(transition, unsafe):
    t = transition
    commit_intake(t)
    path = t.journal.path
    original = path.read_bytes()
    if unsafe == "symlink":
        preserved = path.with_name("preserved.sqlite3")
        path.rename(preserved)
        path.symlink_to(preserved)
    elif unsafe == "hardlink":
        path.with_name("retained-link.sqlite3").hardlink_to(path)
    else:
        path.chmod(0o644)
    with pytest.raises(ValueError):
        migrate(t)
    assert path.read_bytes() == original


@pytest.mark.parametrize("which", ["intake", "exchange"])
def test_missing_database_is_not_created(transition, which):
    t = transition
    commit_intake(t)
    path = t.store.path if which == "intake" else t.journal.path
    path.unlink()
    with pytest.raises(FileNotFoundError):
        migrate(t)
    assert not path.exists()


def test_cli_outputs_only_identifiers_and_uses_retained_authorization(transition, tmp_path, capsys):
    from umi.competition_exchange_migration_cli import main

    t = transition
    commit_intake(t)
    args = []
    for option, value in (
        ("policy", t.policy),
        ("previous-config", t.old),
        ("replacement-config", t.new),
    ):
        path = tmp_path / f"{option}.json"
        path.write_bytes(canonical_json_bytes(value))
        args.extend([f"--{option}", str(path)])
    main([*args, "--confirm-quiesced-backup"])
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "migrated"
    assert "signed_amendment" not in output
    assert (
        output["replacement_binding_sha256"] == hashlib.sha256(exchange_binding(t.new)).hexdigest()
    )
