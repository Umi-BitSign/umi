from __future__ import annotations

import copy
import json
import sqlite3

import pytest

from umi.competition_round_journal import RecordReservation, RoundJournal
from umi.competition_rounds import RoundCoordinator, RoundCoordinatorConfig
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_round_capacity import state
from .test_competition_rounds import policy as policy
from .test_competition_rounds import preparation as preparation
from .test_competition_rounds import setup as setup

BACKUPS = ("wss://backup-one.example", "wss://backup-two.example")


def test_native_coordinator_restart_preserves_capacity_and_round_records(setup):
    old = setup.coordinator.journal
    receipt = old.reserve_records("transport-test", [RecordReservation("vote", "sample", 4096)])
    old.put("vote", "sample", {"signed": "retained"})
    before = state(old)
    config = RoundCoordinatorConfig.model_validate_json(
        canonical_json_bytes(
            setup.config.model_copy(
                update={
                    "chain": setup.config.chain.model_copy(
                        update={"proof_rpc_fallback_urls": BACKUPS}
                    )
                }
            )
        )
    )
    upgraded = RoundCoordinator(config, setup.policy, setup.provider).journal
    after = state(upgraded)
    assert {k: after["tables"][k] for k in before["tables"]} == before["tables"]
    assert after["version"] == before["version"]
    assert upgraded.reservation("transport-test") == receipt
    assert len(after["tables"]["round_rpc_transport_changes"]) == 1
    RoundCoordinator(config, setup.policy, setup.provider)
    assert state(upgraded) == after
    with pytest.raises(ValueError, match="configuration changed"):
        RoundCoordinator(setup.config, setup.policy, setup.provider)
    assert state(upgraded) == after


@pytest.fixture
def binding(chain_config):
    chain = chain_config.model_dump(mode="json", by_alias=True)
    return {
        "schema": "umi-round-coordinator-config/2",
        "chain": chain,
        "work": {"transport_chain": copy.deepcopy(chain), "minimum_issue_ms": 60000},
        "settlement_delivery": {"release_identity": "unchanged"},
    }


def add(binding, path):
    result = copy.deepcopy(binding)
    parent = result
    for name in path[:-1]:
        parent = parent[name]
    parent[path[-1]]["proof_rpc_fallback_urls"] = list(BACKUPS)
    return result


def test_sequential_transports_and_retry_preserve_original_capacity_binding(binding, tmp_path):
    old = RoundJournal(tmp_path, binding)
    receipt = old.reserve_records("batch", [RecordReservation("vote", "id", 4096)])
    original = state(old)["tables"]["binding"]
    main = add(binding, ("chain",))
    both = add(main, ("work", "transport_chain"))
    for config in (main, both, both):
        journal = RoundJournal(tmp_path, config)
        assert journal.reservation("batch") == receipt
        assert state(journal)["tables"]["binding"] == original
    before = state(journal)
    for config in (binding, main):
        with pytest.raises(ValueError):
            RoundJournal(tmp_path, config)
        assert state(journal) == before
    assert len(before["tables"]["round_rpc_transport_changes"]) == 2


@pytest.mark.parametrize(
    "change",
    ["primary", "pin", "timeout", "work", "release", "schema", "policy", "duplicate", "insecure"],
)
def test_other_changes_roll_back(binding, tmp_path, change):
    old = RoundJournal(tmp_path, binding)
    before = state(old)
    selected = add(binding, ("chain",))
    if change == "primary":
        selected["chain"]["rpc_url"] = "wss://changed.example"
    elif change == "pin":
        selected["chain"]["proof_binary_sha256"] = "af" * 32
    elif change == "timeout":
        selected["chain"]["collection_timeout_seconds"] += 1
    elif change == "work":
        selected["work"]["minimum_issue_ms"] += 1
    elif change == "release":
        selected["settlement_delivery"]["release_identity"] = "changed"
    elif change == "schema":
        selected["schema"] = "umi-round-coordinator-config/99"
    elif change == "policy":
        selected["chain"]["policy_sha256"] = "fe" * 32
    elif change == "duplicate":
        selected["chain"]["proof_rpc_fallback_urls"] = [BACKUPS[0]] * 2
    else:
        selected["chain"]["proof_rpc_fallback_urls"] = ["ws://insecure.example", BACKUPS[1]]
    with pytest.raises(ValueError):
        RoundJournal(tmp_path, selected)
    assert state(old) == before


@pytest.mark.parametrize("corruption", ["previous", "sequence", "current", "extra"])
def test_damaged_history_cannot_be_used(binding, tmp_path, corruption):
    old = RoundJournal(tmp_path, binding)
    upgraded = add(binding, ("chain",))
    RoundJournal(tmp_path, upgraded)
    with sqlite3.connect(old.path) as db:
        if corruption == "previous":
            db.execute("UPDATE round_rpc_transport_changes SET previous=?", (b"{}",))
        elif corruption == "sequence":
            db.execute("UPDATE round_rpc_transport_changes SET sequence=2")
        elif corruption == "current":
            body = json.loads(
                db.execute("SELECT current FROM round_rpc_transport_changes").fetchone()[0]
            )
            body["work"]["minimum_issue_ms"] += 1
            db.execute(
                "UPDATE round_rpc_transport_changes SET current=?", (canonical_json_bytes(body),)
            )
        else:
            for sequence in (2, 3):
                db.execute(
                    "INSERT INTO round_rpc_transport_changes VALUES (?,?,?)",
                    (sequence, b"{}", b"{}"),
                )
    with pytest.raises(ValueError):
        RoundJournal(tmp_path, upgraded)
