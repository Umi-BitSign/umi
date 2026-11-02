"""Completion telemetry binds a fresh operation without changing native success."""

import hashlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import host_productive_operation as telemetry
from umi.protocol import canonical_json_bytes


@pytest.fixture
def events(monkeypatch, caplog):
    monkeypatch.setattr(
        telemetry,
        "_SOURCE",
        Path(
            "/opt/umi-validator-supervisor-hosts/"
            + "a" * 40
            + "/src/umi/host_productive_operation.py"
        ),
    )
    monkeypatch.setattr(telemetry, "selected_workload", lambda: SimpleNamespace(sha256="b" * 64))
    monkeypatch.setenv("INVOCATION_ID", "c" * 32)
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    return lambda: [
        json.loads(row.message)
        for row in caplog.records
        if row.name == "umi.competition.progress" and row.message.startswith('{"completed":')
    ]


def test_event_has_exact_compact_identities_and_requires_selected_runtime(events, monkeypatch):
    inputs, result = {"native_slot": "d" * 64}, {"original_signed_result": "e" * 64}
    assert telemetry.productive_operation_completed("model_vote", inputs=inputs, result=result)
    (event,) = events()
    assert event["inputs"] == inputs and event["result"] == result
    assert event["inputs_sha256"] == hashlib.sha256(canonical_json_bytes(inputs)).hexdigest()
    assert event["result_sha256"] == hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    assert event["source_revision"] == "a" * 40
    assert event["profile_sha256"] == "b" * 64
    assert event["invocation_id"] == "c" * 32
    assert event["completed"] == event["total"] == 1
    monkeypatch.delenv("INVOCATION_ID")
    assert not telemetry.productive_operation_completed("model_vote", inputs=inputs, result=result)
    monkeypatch.setenv("INVOCATION_ID", "c" * 32)
    monkeypatch.setattr(telemetry, "selected_workload", lambda: None)
    assert not telemetry.productive_operation_completed("model_vote", inputs=inputs, result=result)
    assert len(events()) == 1


def test_owner_event_waits_for_native_return_and_does_not_mask_failure(events, monkeypatch):
    class Owner:
        fail = True

        @telemetry.productive_model_operation("model_preparation")
        def prepare(self, cohort, submission):
            assert not events()
            if self.fail:
                raise OSError("durable commit unavailable")
            return {"cohort_sha256": cohort, "submission_sha256": submission}

    owner = Owner()
    with pytest.raises(OSError, match="durable commit"):
        owner.prepare("d" * 64, "e" * 64)
    assert not events()
    owner.fail = False
    result = owner.prepare("d" * 64, "e" * 64)
    assert events()[0]["result"] == result
    monkeypatch.setattr(
        telemetry._LOG, "info", lambda *_: (_ for _ in ()).throw(OSError("log full"))
    )
    assert not telemetry.productive_operation_completed("model_vote", inputs={}, result={})


async def test_settlement_counts_completed_current_operation_not_idle_or_failed_poll(events):
    class Node:
        cohort = "d" * 64
        config = SimpleNamespace(role="reviewer")
        package_reference = (Path("/private/original.json"), "e" * 64)
        terminal_certification_sha256 = "f" * 64
        reviewed_terminal_tip = "1" * 64
        status = None

        def __init__(self):
            self.completed_requests = {("certification", "progress"): "2" * 64}

        @telemetry.productive_settlement_operation
        async def maintain(self):
            if self.status == "failed":
                raise OSError("native peer delivery failed")
            return self.status

    node = Node()
    assert await node.maintain() is None and not events()
    node.status = "failed"
    with pytest.raises(OSError, match="native peer"):
        await node.maintain()
    assert not events()
    node.status = "reviewing"
    assert await node.maintain() == "reviewing"
    assert await node.maintain() == "reviewing"
    (event,) = events()
    assert event["kind"] == "settlement_maintain"
    assert event["result"]["history_tip_sha256"] == "1" * 64
    assert event["result"]["reviewed_requests"] == [
        {"phase": "certification", "kind": "progress", "request_sha256": "2" * 64}
    ]


def test_oversized_event_does_not_claim_or_change_native_result(events):
    assert not telemetry.productive_operation_completed(
        "model_vote", inputs={}, result={"unexpected_payload": "x" * (64 * 1024)}
    )
    assert not events()
