from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from umi import competition_exchange_rpc_migration as migration
from umi.competition_exchange import ExchangeJournal
from umi.competition_exchange_migration import exchange_binding, migrate_exchange_launch
from umi.competition_policy_lineage import register_lineage
from umi.open_competition import digest

from .test_competition_exchange_migration import (
    chain_config as chain_config,
)
from .test_competition_exchange_migration import (
    commit_intake,
    snapshot,
)
from .test_competition_exchange_migration import (
    policy as policy,
)
from .test_competition_exchange_migration import (
    setup as setup,
)
from .test_competition_exchange_migration import (
    transition as transition,
)

BACKUPS = ("wss://backup-a.example", "wss://backup-b.example")
HISTORY = ("events", "audience", "collected", "highwater", "sqlite_sequence")


def with_backups(config):
    return config.model_copy(
        update={"chain": config.chain.model_copy(update={"proof_rpc_fallback_urls": BACKUPS})}
    )


def test_reopen_adds_only_transport_history_and_preserves_delivery(transition):
    t = transition
    before = snapshot(t.journal.path, HISTORY)
    selected = with_backups(t.old)
    reopened = ExchangeJournal(selected, t.policy)
    assert snapshot(reopened.path, HISTORY) == before
    assert snapshot(reopened.path, ("binding", migration.TABLE)) == {
        "binding": [(exchange_binding(selected),)],
        migration.TABLE: [(1, exchange_binding(t.old), exchange_binding(selected))],
    }
    all_rows = snapshot(reopened.path)
    ExchangeJournal(selected, t.policy)
    assert snapshot(reopened.path) == all_rows
    assert reopened.append("a1" * 32, "suite", None, t.setup.options["suite"], 201) == 1
    assert reopened.append("a2" * 32, "suite", None, t.setup.options["suite"], 201) == 2
    reopened.observe(201)


def test_old_config_instance_and_old_binary_are_fenced(transition):
    t = transition
    legacy = sqlite3.connect(t.journal.path, isolation_level=None)
    # The predecessor knows the launch fence, but not the new RPC writer fence.
    legacy.create_function("umi_exchange_launch_writer", 1, lambda _: 1)
    try:
        ExchangeJournal(with_backups(t.old), t.policy)
        before = snapshot(t.journal.path)
        with pytest.raises(ValueError, match="stale exchange RPC"):
            ExchangeJournal(t.old, t.policy)
        with pytest.raises(ValueError, match="stale exchange RPC"):
            t.journal.observe(201)
        for table in ("binding", *HISTORY[:-1]):
            with pytest.raises(sqlite3.OperationalError, match="umi_exchange_rpc_writer"):
                legacy.execute(f"DELETE FROM {table}")
        assert snapshot(t.journal.path) == before
    finally:
        legacy.close()


def test_concurrent_reopen_retains_one_exact_addition(transition):
    t = transition
    before = snapshot(t.journal.path, HISTORY)
    selected = with_backups(t.old)
    with ThreadPoolExecutor(max_workers=2) as pool:
        journals = list(pool.map(lambda _: ExchangeJournal(selected, t.policy), range(2)))
    assert all(journal.path == t.journal.path for journal in journals)
    assert snapshot(t.journal.path, HISTORY) == before
    assert snapshot(t.journal.path, (migration.TABLE,))[migration.TABLE] == [
        (1, exchange_binding(t.old), exchange_binding(selected))
    ]


@pytest.mark.parametrize("order", ["rpc_then_launch", "launch_then_rpc"])
def test_signed_committed_launch_and_rpc_migration_both_orders(transition, order):
    t = transition
    before = snapshot(t.journal.path, HISTORY)
    commit_intake(t)
    if order == "rpc_then_launch":
        selected = with_backups(t.old)
        stale = ExchangeJournal(selected, t.policy)
        replacement = with_backups(t.new)
        result = migrate_exchange_launch(selected, replacement, t.policy, confirmed=True)
        assert result["status"] == "migrated"
        assert (
            migrate_exchange_launch(selected, replacement, t.policy, confirmed=True)["status"]
            == "already_migrated"
        )
    else:
        migrate_exchange_launch(t.old, t.new, t.policy, confirmed=True)
        stale = ExchangeJournal(t.new, t.policy)
        replacement = with_backups(t.new)
    reopened = ExchangeJournal(replacement, t.policy)
    assert snapshot(reopened.path, HISTORY) == before
    with pytest.raises(ValueError, match="stale exchange"):
        stale.observe(201)
    with pytest.raises(ValueError):
        ExchangeJournal(t.old, t.policy)
    reopened.observe(201)


def test_rpc_addition_never_authorizes_an_uncommitted_launch(transition):
    t = transition
    before = snapshot(t.journal.path)
    with pytest.raises(ValueError, match="configuration changed"):
        ExchangeJournal(with_backups(t.new), t.policy)
    assert snapshot(t.journal.path) == before
    selected = with_backups(t.old)
    ExchangeJournal(selected, t.policy)
    before = snapshot(t.journal.path)
    with pytest.raises(ValueError, match="intake has not committed"):
        migrate_exchange_launch(selected, with_backups(t.new), t.policy, confirmed=True)
    assert snapshot(t.journal.path) == before


@pytest.mark.parametrize(
    "field",
    [
        "rpc_url",
        "minimum_finalized_block",
        "maximum_head_age_ms",
        "finality_binary",
        "proof_binary_sha256",
        "state_directory",
        "storage_codec_metadata_path",
    ],
)
def test_rejects_unrelated_chain_changes_atomically(transition, field):
    t = transition
    config = with_backups(t.old)
    value = getattr(config.chain, field)
    if field == "proof_binary_sha256":
        value = "fd" * 32
    elif field == "rpc_url":
        value = "wss://changed-primary.example"
    elif isinstance(value, int):
        value += 1
    else:
        value = (value or "/changed") + "-changed"
    config = config.model_copy(update={"chain": config.chain.model_copy(update={field: value})})
    before = snapshot(t.journal.path)
    with pytest.raises(ValueError):
        ExchangeJournal(config, t.policy)
    assert snapshot(t.journal.path) == before


@pytest.mark.parametrize(
    "field",
    [
        "order_directory",
        "reveal_directory",
        "intake_directory",
        "submission_head_checkpoint_directory",
        "legacy_policy_sha256",
    ],
)
def test_rejects_unrelated_immutable_exchange_changes(transition, field):
    t = transition
    config = with_backups(t.old)
    value = "ab" * 32 if field == "legacy_policy_sha256" else getattr(config, field) + "-changed"
    before = snapshot(t.journal.path)
    with pytest.raises(ValueError):
        ExchangeJournal(config.model_copy(update={field: value}), t.policy)
    assert snapshot(t.journal.path) == before


@pytest.mark.parametrize(
    "backups",
    [
        (),
        BACKUPS[:1],
        (*BACKUPS, "wss://third.example"),
        (BACKUPS[0], BACKUPS[0]),
        ("https://not-websocket.example", BACKUPS[1]),
    ],
)
def test_invalid_backup_change_never_mutates_journal(transition, backups):
    t = transition
    selected = with_backups(t.old)
    ExchangeJournal(selected, t.policy)
    before = snapshot(t.journal.path)
    bad = selected.model_copy(
        update={"chain": selected.chain.model_copy(update={"proof_rpc_fallback_urls": backups})}
    )
    with pytest.raises(ValueError):
        ExchangeJournal(bad, t.policy)
    assert snapshot(t.journal.path) == before


def test_reordering_or_replacing_backups_requires_new_authorization(transition):
    t = transition
    selected = with_backups(t.old)
    ExchangeJournal(selected, t.policy)
    before = snapshot(t.journal.path)
    for backups in (tuple(reversed(BACKUPS)), ("wss://third.example", BACKUPS[1])):
        changed = selected.model_copy(
            update={"chain": selected.chain.model_copy(update={"proof_rpc_fallback_urls": backups})}
        )
        with pytest.raises(ValueError, match="stale exchange RPC"):
            ExchangeJournal(changed, t.policy)
    assert snapshot(t.journal.path) == before


@pytest.mark.parametrize("failure", ["fence_install", "after_binding_update"])
def test_migration_failure_rolls_back_every_table_and_binding(transition, monkeypatch, failure):
    t = transition
    before = snapshot(t.journal.path)
    if failure == "fence_install":
        monkeypatch.setattr(migration, "rpc_fences", lambda: {"bad": "invalid SQL"})
        expected = sqlite3.OperationalError
    else:
        original = migration.check_rpc_history

        def failed(db):
            result = original(db)
            if result:
                raise RuntimeError("synthetic crash before commit")
            return result

        monkeypatch.setattr(migration, "check_rpc_history", failed)
        expected = RuntimeError
    with pytest.raises(expected):
        ExchangeJournal(with_backups(t.old), t.policy)
    assert snapshot(t.journal.path) == before


def test_history_is_append_only_single_addition_and_missing_fence_holds(transition):
    t = transition
    selected = with_backups(t.old)
    journal = ExchangeJournal(selected, t.policy)
    before = snapshot(journal.path)
    for operation in (
        f"UPDATE {migration.TABLE} SET current=current",
        f"DELETE FROM {migration.TABLE}",
        f"INSERT INTO {migration.TABLE} SELECT 2,previous,current FROM {migration.TABLE}",
    ):
        with pytest.raises(sqlite3.IntegrityError), journal.transaction() as db:
            db.execute(operation)
    assert snapshot(journal.path) == before
    with sqlite3.connect(journal.path) as db:
        db.execute(f"DROP TRIGGER {next(iter(migration.rpc_fences()))}")
    with pytest.raises(ValueError, match="writer fences changed"):
        ExchangeJournal(selected, t.policy)


def test_policy_lineage_reopen_preserves_transport_receipt(transition):
    t = transition
    selected = with_backups(t.old)
    journal = ExchangeJournal(selected, t.policy)
    before = snapshot(journal.path, (*HISTORY, migration.TABLE))
    successor = t.policy.model_copy(
        update={
            "sequence": t.policy.sequence + 1,
            "predecessor_sha256": digest(t.policy),
        }
    )
    register_lineage(successor, [t.policy])
    config = selected.model_copy(
        update={
            "policy_sha256": digest(successor),
            "chain": selected.chain.model_copy(update={"policy_sha256": digest(successor)}),
        }
    )
    reopened = ExchangeJournal(config, successor)
    assert snapshot(reopened.path, (*HISTORY, migration.TABLE)) == before
    reopened.observe(201)
