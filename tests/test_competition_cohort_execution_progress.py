"""Actual private export layouts, restart reuse and advisory counting boundaries."""

import asyncio
from contextlib import closing
from types import SimpleNamespace as NS

import pytest
from pydantic import BaseModel

from umi import competition_cohort_execution_progress as module
from umi.competition_cohort_evaluation import RecoverableEvaluationRound
from umi.competition_cohort_execution_progress import ExecutionExportProgress
from umi.open_competition import digest, identity
from umi.private_files import publish_private_model

from .test_open_competition import wallet

E1 = wallet("Charlie").hotkey.ss58_address
E2 = wallet("Dave").hotkey.ss58_address


class Submission(BaseModel):
    track: str = "model"
    nonce: int


@pytest.fixture
def exported(tmp_path):
    submissions = [Submission(nonce=i) for i in range(2)]
    selected = sorted(digest(s) for s in submissions)
    round_ = RecoverableEvaluationRound(
        schema="umi-recoverable-evaluation-round/1",
        policy_sha256="11" * 32,
        cohort_sha256="22" * 32,
        intake_closure_sha256="33" * 32,
        sequence=6,
        suite_sha256="44" * 32,
        incumbent_model_sha256="55" * 32,
        runtime_sha256="66" * 32,
        eligible_tracks=("model",),
        participants=tuple(dict(submission_sha256=s, admission_sha256=s) for s in selected),
        prepared_at_block=100,
    )
    roster = NS(
        round=round_,
        participants=[
            NS(record=NS(request=NS(signed_submission=NS(submission=s)))) for s in submissions
        ],
    )
    root = tmp_path / "exports"
    root.mkdir(mode=0o700)

    def save(path, value):
        publish_private_model(root / path, module._Facts(value), maximum_bytes=16 * 1024**2)

    def obj(value):
        key = digest(value)
        save(f"objects/{key}.json", dict(sha256=key, value=value))
        return key

    def order(
        index=0,
        evaluators=(E1,),
        cases=3,
    ):
        value = dict(
            order=dict(
                round=round_.model_dump(mode="json", by_alias=True),
                submission=dict(submission=submissions[index].model_dump()),
                cases=[{}] * cases,
                evaluators=list(evaluators),
            )
        )
        key = obj(value)
        save(f"orders/{digest(round_)}/{digest(submissions[index])}.json", dict(sha256=key))
        return key

    def partial(
        indices,
        index=0,
        evaluator=E1,
        number=1,
    ):
        key = obj(dict(steps=[dict(index=i, sha256="88" * 32) for i in indices]))
        save(
            f"partials/{digest(round_)}/{digest(submissions[index])}/{identity(evaluator)}/{number:05d}.json",
            dict(sha256=key),
        )
        return key

    def terminal(
        order_key,
        count=6,
        evaluator=E1,
    ):
        archive = obj(dict(steps=["99" * 32] * count))
        key = obj(dict(terminal=dict(execution_archive_sha256=archive)))
        save(f"terminals/{order_key}/{identity(evaluator)}.json", dict(sha256=key))
        return key

    return NS(
        root=root,
        roster=roster,
        save=save,
        order=order,
        partial=partial,
        terminal=terminal,
        obj=obj,
    )


def test_counts_partial_terminal_overlap_and_undelivered_models(exported):
    h = exported
    meter = ExecutionExportProgress(h.root, h.roster)
    empty = meter.sample()
    assert (empty["completed"], empty["total"], empty["projected_executions"]) == (0, 2, None)
    key = h.order()
    h.partial([0, 1, 4])
    partial = meter.sample()
    assert partial["exported_executions"] == 3 and partial["exported_comparisons"] == 1
    assert partial["completed"] == 0 and partial["percent"] == 0
    assert partial["projected_executions"] == 12
    assert partial["eta_seconds"] is None and partial["delivered_orders"] == 1
    h.terminal(key)
    completed = meter.sample()
    assert completed["exported_executions"] == 6 and completed["exported_comparisons"] == 3
    assert completed["completed"] == 1 and completed["percent"] == 50
    assert meter.sample()["exported_executions"] == completed["exported_executions"]


def test_restart_reuses_unchanged_export_facts_without_payload_reads(exported, monkeypatch):
    h = exported
    h.order()
    h.partial([0, 1])
    before = ExecutionExportProgress(h.root, h.roster).sample()

    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged export metadata must not be reread")

    monkeypatch.setattr(module, "_read_private_bytes", forbidden)
    restarted = ExecutionExportProgress(h.root, h.roster)
    after = restarted.sample()
    assert after["exported_executions"] == before["exported_executions"] == 2
    assert restarted.read_bytes == 0


def test_changed_latest_partial_only_reads_changed_metadata(exported):
    h = exported
    h.order()
    h.partial([0])
    meter = ExecutionExportProgress(h.root, h.roster)
    assert meter.sample()["exported_executions"] == 1
    h.partial([0, 1, 2, 3], number=2)
    assert meter.sample()["exported_comparisons"] == 2
    assert meter.read_bytes < 2048


def test_all_evaluators_are_required_and_totals_cover_heterogeneous_orders(exported):
    h = exported
    a = h.order(
        evaluators=(
            E1,
            E2,
        )
    )
    h.terminal(a)
    meter = ExecutionExportProgress(h.root, h.roster)
    assert meter.sample()["completed"] == 0
    h.terminal(a, evaluator=E2)
    b = h.order(index=1, cases=4)
    h.terminal(b, count=8)
    result = meter.sample()
    assert result["completed"] == 2 and result["percent"] == 100
    assert result["exported_executions"] == result["projected_executions"] == 20
    assert result["eta_seconds"] == 0


@pytest.mark.parametrize("damage", ["checkpoint", "duplicate", "out_of_range", "missing_archive"])
def test_corrupt_or_missing_metadata_is_visible_and_never_completed(exported, damage):
    h = exported
    key = h.order()
    meter = ExecutionExportProgress(h.root, h.roster)
    if damage == "checkpoint":
        meter.sample()
        meter.checkpoint.write_text("not json")
        meter = ExecutionExportProgress(h.root, h.roster)
    elif damage == "duplicate":
        h.partial([0, 0])
    elif damage == "out_of_range":
        h.partial([6])
    else:
        archive = h.obj(dict(steps=["99" * 32] * 6))
        h.terminal(key)
        (h.root / "objects" / (archive + ".json")).unlink()
    result = meter.sample()
    assert result["repair_required"] and result["stalled_or_retrying"]
    assert result["completed"] is None and result["eta_seconds"] is None


def test_unexpected_model_disappearance_does_not_count_as_completion(exported):
    h = exported
    key = h.order()
    h.terminal(key)
    meter = ExecutionExportProgress(h.root, h.roster)
    assert meter.sample()["completed"] == 1
    (h.root / f"objects/{key}.json").unlink()
    assert meter.sample()["repair_required"]


def test_missing_initialized_checkpoint_is_repair_on_restart(exported):
    meter = ExecutionExportProgress(exported.root, exported.roster)
    meter.sample()
    meter.checkpoint.unlink()
    assert ExecutionExportProgress(exported.root, exported.roster).sample()["repair_required"]


def test_rate_scope_stall_and_restart_do_not_reuse_a_previous_process_forecast(
    exported, monkeypatch
):
    clock = [0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    meter = ExecutionExportProgress(exported.root, exported.roster)
    meter.required_producers = {identity(E1)}
    epochs = {identity(E1): "11" * 32}
    count = [0]

    def counts():
        return dict(completed=count[0], total=5, exported_executions=12 * count[0])

    monkeypatch.setattr(meter, "_sample", counts)
    assert meter.sample(producer_epochs=epochs)["eta_seconds"] is None
    clock[0], count[0] = 300, 3
    measured = meter.sample(producer_epochs=epochs)
    assert measured["eta_seconds"] == 200 and measured["rate_completed_models"] == 3
    clock[0] = 1200
    assert meter.sample(producer_epochs=epochs)["eta_seconds"] is None
    assert meter.sample(producer_epochs=epochs)["stalled_or_retrying"]
    restarted = ExecutionExportProgress(exported.root, exported.roster)
    monkeypatch.setattr(restarted, "_sample", counts)
    assert restarted.sample()["eta_seconds"] is None


def test_producer_rollout_or_missing_epoch_resets_rate_without_resetting_work(
    exported, monkeypatch
):
    clock, count = [0], [0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    meter = ExecutionExportProgress(exported.root, exported.roster)
    meter.required_producers = {identity(E1)}
    monkeypatch.setattr(meter, "_sample", lambda: dict(
        completed=count[0], total=10, exported_executions=12 * count[0],
    ))
    a, b = {identity(E1): "11" * 32}, {identity(E1): "22" * 32}
    meter.sample(producer_epochs=a)
    clock[0], count[0] = 300, 3
    before = meter.sample(producer_epochs=a)
    assert before["eta_seconds"] == 700 and before["rate_completed_models"] == 3
    clock[0], count[0] = 360, 4
    changed = meter.sample(producer_epochs=b)
    assert changed["completed"] == 4 and changed["rate_completed_models"] == 0
    assert changed["rate_epoch_sha256"] != before["rate_epoch_sha256"]
    assert changed["eta_seconds"] is None
    clock[0], count[0] = 660, 7
    assert meter.sample(producer_epochs=b)["eta_seconds"] == 300
    clock[0], count[0] = 700, 8
    missing = meter.sample(producer_epochs={})
    assert missing["completed"] == 8 and missing["rate_epoch_sha256"] is None
    assert missing["eta_basis"] == "awaiting_current_execution_producer_epochs"
    assert meter.sample(producer_epochs=b)["rate_completed_models"] == 0
    assert not meter.sample(producer_epochs=b)["repair_required"]


async def test_background_progress_and_forecast_accounting_continue_during_blocked_native_tick(
    exported, monkeypatch
):
    from umi import competition_cohort_lifecycle_host as host_module
    from umi.competition_cohort_public_progress import CohortProgressSnapshots
    from umi.competition_forecast import ForecastLedger

    h = exported
    h.terminal(h.order())
    stop = asyncio.Event()
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(host_module, "PUBLIC_COHORT_PROGRESS", snapshots)
    monkeypatch.setattr(host_module, "requests_stage_policy", lambda: None)
    monkeypatch.setattr(host_module, "digest", lambda value: value)

    class Node:
        async def run(self, event, **kwargs):
            await event.wait()
            return dict(status="stopped")

    async def node(_):
        return Node()

    producer = ["11" * 32]

    async def epochs(_):
        return {identity(E1): producer[0]}

    with closing(ForecastLedger(h.root / "forecast-accounting")) as ledger:
        cohort = h.roster.round.cohort_sha256
        host = NS(
            config=NS(automatic_progression_hold_cohorts=(), poll_seconds=0.01, sample_seconds=1),
            service=NS(config=NS(series=NS(cohorts=(cohort,)))),
            files=NS(root=h.root),
            requests={cohort: NS(roster=h.roster)},
            execution_progress={},
            producer_epochs=NS(sample=epochs, diagnostics=lambda _: {}),
            forecast_ledger=ledger,
            last_reports={},
            node=node,
        )
        running = asyncio.create_task(host_module.LifecycleHost.run(host, stop))

        async def wait_for_count(expected):
            for _ in range(100):
                progress = snapshots.snapshot(cohort)["components"].get("execution", {})
                if progress.get("completed") == expected:
                    return progress
                await asyncio.sleep(0.01)
            raise AssertionError("background execution sampler did not update")

        try:
            first = await wait_for_count(1)
            assert first["total"] == 2
            producer[0] = "22" * 32
            for _ in range(100):
                changed = snapshots.snapshot(cohort)["components"]["execution"]
                if changed["rate_epoch_sha256"] != first["rate_epoch_sha256"]:
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("producer rollout did not reset the advisory rate")
            assert changed["completed"] == 1 and changed["rate_completed_models"] == 0
            h.terminal(h.order(index=1))
            await wait_for_count(2)
            await asyncio.sleep(0.05)
            meter = host.execution_progress[cohort]
            assert meter.forecast_closed
            records = ledger.records(meter.forecast.scope)
            terminals = [r for r in records if r["kind"] == "attempt_terminal"]
            assert len(terminals) == 2
            assert sorted(r["state"] for r in terminals) == ["completed", "interrupted"]
        finally:
            stop.set()
            await running
    with closing(ForecastLedger(h.root / "forecast-accounting")) as restored:
        assert restored.records(meter.forecast.scope) == records
