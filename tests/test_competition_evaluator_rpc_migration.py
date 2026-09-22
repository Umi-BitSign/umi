from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from umi.competition_evaluator import EvaluatorConfig, EvaluatorJournal
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator_capacity import (
    chain_config as chain_config,
)
from .test_competition_evaluator_capacity import (
    model_setup as model_setup,
)
from .test_competition_evaluator_capacity import (
    policy as policy,
)
from .test_competition_evaluator_capacity import (
    runtime as runtime,
)
from .test_competition_evaluator_capacity import (
    setup as setup,
)
from .test_competition_evaluator_capacity import (
    spec,
)

BACKUPS = ("wss://backup-one.example", "wss://backup-two.example")


def upgraded(config, field="chain"):
    return EvaluatorConfig.model_validate_json(
        canonical_json_bytes(
            config.model_copy(
                update={
                    field: getattr(config, field).model_copy(
                        update={"proof_rpc_fallback_urls": BACKUPS}
                    )
                }
            )
        )
    )


def snapshot(path):
    with closing(sqlite3.connect(path)) as db:
        return {
            name: db.execute(f'SELECT * FROM "{name}" ORDER BY 1').fetchall()
            for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }


def test_rpc_addition_preserves_actual_orders_artifacts_and_capacity_receipt(setup):
    old = setup.drivers[0].journal
    reservation = spec(setup)
    batch = "ab" * 32
    receipt = old.reserve_orders(batch, [reservation])
    old.admit(setup.order, reservation.slot)
    old.put(reservation.slot, "announcement_intent", {"message": "reserved"})
    before = snapshot(old.path)
    new = EvaluatorJournal(upgraded(old.config))
    after = snapshot(old.path)
    assert {k: after[k] for k in before} == before
    assert len(after["evaluator_rpc_transport_changes"]) == 1
    assert new.reservation(batch) == receipt
    new.put(reservation.slot, "announcement_intent", {"message": "reserved"})
    assert EvaluatorJournal(new.config).reservation(batch) == receipt
    assert snapshot(old.path) == after
    with pytest.raises(ValueError, match="configuration changed"):
        EvaluatorJournal(old.config)
    assert snapshot(old.path) == after


@pytest.mark.parametrize(
    "field",
    [
        "rpc_url",
        "minimum_finalized_block",
        "collection_timeout_seconds",
        "proof_binary_sha256",
        "state_directory",
    ],
)
def test_backup_addition_cannot_change_any_other_chain_binding(setup, field):
    old = setup.drivers[0].journal
    before = snapshot(old.path)
    config = upgraded(old.config)
    value = getattr(config.chain, field)
    value = (
        value + 1
        if isinstance(value, int)
        else (
            "wss://different-primary.example"
            if field == "rpc_url"
            else value + "-other"
            if field == "state_directory"
            else "fe" * 32
        )
    )
    config = config.model_copy(update={"chain": config.chain.model_copy(update={field: value})})
    with pytest.raises(ValueError, match="configuration changed"):
        EvaluatorJournal(config)
    assert snapshot(old.path) == before


def test_sequential_work_and_main_backups_preserve_original_binding(setup, tmp_path):
    base = setup.drivers[0].config
    config = base.model_copy(
        update={
            "state_directory": str(tmp_path / "two-provider-evaluator"),
            "round_coordinator_origin": "https://round.example",
            "legacy_policy_sha256": "cd" * 32,
            "dispatch_directory": str(tmp_path / "dispatch"),
            "work_signing_chain": base.chain.model_copy(
                update={"state_directory": str(tmp_path / "work-chain")}
            ),
            "work_minimum_issue_ms": 60000,
        }
    )
    config = EvaluatorConfig.model_validate_json(canonical_json_bytes(config))
    old = EvaluatorJournal(config)
    before = snapshot(old.path)["binding"]
    main = EvaluatorJournal(upgraded(config))
    both = EvaluatorJournal(upgraded(main.config, "work_signing_chain"))
    rows = snapshot(old.path)
    assert rows["binding"] == before
    assert [r[0] for r in rows["evaluator_rpc_transport_changes"]] == [1, 2]
    assert (
        rows["evaluator_rpc_transport_changes"][0][2]
        == rows["evaluator_rpc_transport_changes"][1][1]
    )
    EvaluatorJournal(both.config)
    with pytest.raises(ValueError):
        EvaluatorJournal(main.config)
    assert snapshot(old.path) == rows


def test_changed_transport_history_is_rejected(setup):
    old = setup.drivers[0].journal
    config = upgraded(old.config)
    EvaluatorJournal(config)
    with closing(sqlite3.connect(old.path)) as db:
        db.execute("UPDATE evaluator_rpc_transport_changes SET previous=?", (b"{}",))
        db.commit()
    with pytest.raises(ValueError, match="history changed"):
        EvaluatorJournal(config)


@pytest.mark.parametrize(
    "backups", [("wss://same.example",) * 2, ("ws://insecure.example", "wss://secure.example")]
)
def test_direct_journal_caller_cannot_skip_backup_model_validation(setup, backups):
    old = setup.drivers[0].journal
    before = snapshot(old.path)
    config = old.config.model_copy(
        update={"chain": old.config.chain.model_copy(update={"proof_rpc_fallback_urls": backups})}
    )
    with pytest.raises(ValueError):
        EvaluatorJournal(config)
    assert snapshot(old.path) == before
