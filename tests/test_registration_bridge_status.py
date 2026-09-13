from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from umi import registration_bridge_status as status


def snapshot(**changes):
    result = dict(
        block=1000,
        timestamp_ms=1_000_000,
        now_ms=1_000_000,
        values={
            "Tempo": 360,
            "ActivityCutoffFactorMilli": 1000,
            "WeightsSetRateLimit": 100,
            "LastUpdate": [900, 0, 950],
            "ValidatorPermit": [True, False, True],
            "Consensus": [0, 65535, 0],
            "Incentive": [0, 65535, 0],
        },
        rows={0: [[0, 0], [1, 65535], [2, 0]], 2: [[1, 65535]]},
        hotkeys={0: "validator-a", 2: "validator-b"},
        expected={0: "validator-a", 2: "validator-b"},
    )
    result.update(changes)
    return result


def test_fresh_rows_are_not_policy_or_payment_proofs():
    result = status.summarize_rows(**snapshot())
    assert result["status"] == "fresh"
    assert result["positive_incentive_count"] == 1
    assert result["validators"][0]["age_blocks"] == 100
    assert result["validators"][0]["rate_ready_block"] == 1000
    assert not result["bridge_policy_verified"]
    assert not result["independent_finality_verified"]
    assert not result["chain_submission_authorized"]


@pytest.mark.parametrize("age,expected", [(359, "fresh"), (360, "fresh"), (361, "alert")])
def test_activity_cutoff_boundary(age, expected):
    data = snapshot()
    data["values"]["LastUpdate"][0] = 1000 - age
    assert status.summarize_rows(**data)["status"] == expected


@pytest.mark.parametrize("kind", ["hotkey_changed", "validator_permit_missing", "empty_row"])
def test_running_process_cannot_mask_changed_identity_or_empty_row(kind):
    data = snapshot()
    if kind == "hotkey_changed":
        data["hotkeys"][0] = "replacement"
    elif kind == "validator_permit_missing":
        data["values"]["ValidatorPermit"][0] = False
    else:
        data["rows"][0] = [[1, 0]]
    result = status.summarize_rows(**data)
    assert result["status"] == "alert"
    assert result["validators"][0]["reason_code"] == kind


@pytest.mark.parametrize("delta", [-30_001, 120_001])
def test_stale_or_future_rpc_read_is_not_healthy(delta):
    with pytest.raises(ValueError, match="timestamp"):
        status.summarize_rows(**snapshot(now_ms=1_000_000 + delta))


@pytest.mark.parametrize(
    "kind", ["short", "future_update", "permit_int", "bad_weight", "duplicate", "missing"]
)
def test_incomplete_or_malformed_readback_is_unknown(kind):
    data = snapshot()
    if kind == "short":
        data["values"]["Incentive"].pop()
    elif kind == "future_update":
        data["values"]["LastUpdate"][0] = 1001
    elif kind == "permit_int":
        data["values"]["ValidatorPermit"][0] = 1
    elif kind == "bad_weight":
        data["rows"][0] = [[1, 65536]]
    elif kind == "duplicate":
        data["rows"][0] = [[1, 1], [1, 2]]
    else:
        del data["rows"][0]
    with pytest.raises(ValueError):
        status.summarize_rows(**data)


async def test_all_queries_use_one_finalized_snapshot_and_close_subscription():
    from bittensor._generated import storage

    data = snapshot()
    calls = []
    closed = []
    mapping = {getattr(storage.SubtensorModule, k): v for k, v in data["values"].items()}

    class Pinned:
        async def query(self, item, params):
            calls.append((item, params))
            if item == storage.SubtensorModule.Weights:
                return data["rows"][params[1]]
            if item == storage.SubtensorModule.Keys:
                return data["hotkeys"][params[1]]
            return SimpleNamespace(value=mapping[item])

        async def timestamp(self):
            return datetime.fromtimestamp(1000, tz=timezone.utc)

    class Client:
        async def blocks(self, *, finalized):
            assert finalized is True
            try:
                yield SimpleNamespace(number=1000)
            finally:
                closed.append(True)

        async def at(self, block):
            assert block == 1000
            return Pinned()

    result = await status.collect_status(
        Client(), expected=data["expected"], clock_ms=lambda: 1_000_000
    )
    assert result["status"] == "fresh"
    assert len(calls) == 11
    assert all(params[0] == 78 for _, params in calls)
    assert closed == [True]


def test_read_failure_has_nonzero_exit_and_no_exception_text(monkeypatch, capsys):
    async def fail():
        raise RuntimeError("secret in upstream error")

    monkeypatch.setattr(status, "_check", fail)
    assert status.run_cli([]) == 2
    assert capsys.readouterr().out == '{"reason_code":"chain_read_failed","status":"unknown"}\n'
