"""Bounded serial scheduling and whole-visit progress, without payload work."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from umi import competition_cohort_reserved_participation as module
from umi.competition_cohort_public_progress import CohortProgressSnapshots
from umi.competition_cohort_reserved_participation import ReservedParticipationWorker


def worker():
    return ReservedParticipationWorker(
        SimpleNamespace(owners={"a": None, "b": None, "c": None, "d": None, "e": None}),
        SimpleNamespace(capture_timeout_seconds=120),
        batch_size=8,
        poll_seconds=5,
    )


def progress(subject, done, total=125, error=None):
    return subject._progress(
        "a",
        done,
        total,
        stage="ready_reserved_participation",
        scope="selected_ready_participation_checkpoints",
        error=error,
    )


def test_batch_eight_shares_bounded_allowance_and_rotates_both_lanes():
    subject = worker()
    selected = [f"s{i}" for i in range(10)]
    historical = [f"h{i}" for i in range(10)]
    first = subject._batch("a", selected, historical)
    assert first == [
        (lane, f"{lane[0]}{i}") for i in range(4) for lane in ("selected", "historical")
    ]
    for lane, key in first:
        subject._after[("a", lane)] = key
    assert subject._batch("a", selected, historical) == [
        (lane, f"{lane[0]}{i}") for i in range(4, 8) for lane in ("selected", "historical")
    ]
    assert len(subject._batch("a", selected, [])) == 8
    subject.batch_size = 1
    assert subject._batch("b", selected, historical)[0][0] == "selected"
    assert subject._batch("b", selected, historical)[0][0] == "historical"


@pytest.mark.parametrize("batch", [1, 8, 16])
async def test_actual_poll_keeps_serial_cohort_fairness_and_two_separate_budgets(
    monkeypatch, batch
):
    calls, done, recovered = [], {"a": set(), "b": set()}, {"a": set(), "b": set()}
    selected = [f"s{i:02}" for i in range(20)]
    historical = [f"h{i:02}" for i in range(20)]
    owners = {}
    busy = False

    async def complete(signed, *, now_unix_ms):
        assert not busy
        cohort, key = signed
        calls.append((cohort, "recovery", key))
        recovered[cohort].add(key)

    for cohort in ("a", "b"):
        owners[cohort] = SimpleNamespace(
            config=SimpleNamespace(cohort_sha256=cohort),
            _mutex=object(),
            complete=complete,
            journal=SimpleNamespace(
                get=lambda kind, key, cohort=cohort: (cohort, key),
                put=lambda kind, key, value, cohort=cohort: done[cohort].add(key),
            ),
        )

    async def retain(request, *, before_retain, admission_lock):
        nonlocal busy
        assert not busy
        busy = True
        try:
            before_retain()
            calls.append((request.cohort, "participation", request.key))
            await asyncio.sleep(0)
            return {"record_sha256": "ab" * 32}
        finally:
            busy = False

    subject = ReservedParticipationWorker(
        SimpleNamespace(owners=owners, intake_phase=lambda _: "intake"),
        SimpleNamespace(capture_timeout_seconds=120, retain=retain),
        batch_size=batch,
    )

    def inventory(owner):
        cohort = owner.config.cohort_sha256
        return (
            ((1, "authority"), frozenset(historical)),
            set(done[cohort]),
            [key for key in selected + historical if key not in done[cohort]],
            [(f"r{i:02}", selected[i]) for i in range(20) if f"r{i:02}" not in recovered[cohort]],
        )

    monkeypatch.setattr(subject, "_inventory", inventory)
    monkeypatch.setattr(subject, "_eligible", lambda *_: None)
    monkeypatch.setattr(
        subject,
        "_request",
        lambda owner, key: SimpleNamespace(
            cohort=owner.config.cohort_sha256,
            key=key,
            signed_submission=SimpleNamespace(submission=SimpleNamespace(model_revision="cd" * 32)),
        ),
    )
    monkeypatch.setattr(
        module,
        "SignedDirectModelUploadCompletion",
        SimpleNamespace(
            model_validate_json=lambda raw: json.loads(raw),
        ),
    )
    for expected_cohort in ("a", "b", "a"):
        before = len(calls)
        await subject.poll_once()
        current = calls[before:]
        assert {row[0] for row in current} == {expected_cohort}
        assert sum(row[1] == "recovery" for row in current) == min(
            batch, 20 - (batch if expected_cohort == "a" and before else 0)
        )
        assert sum(row[1] == "participation" for row in current) == batch
        assert not busy
    for cohort in owners:
        completed = [key for c, lane, key in calls if c == cohort and lane == "participation"]
        assert len(completed) == len(set(completed)), "completed checkpoints are not repeated"


def test_cadence_includes_other_cohorts_sleep_and_recovery_not_just_item_time(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    subject = worker()
    subject._bind_cadence("a", ((1, "authority"), frozenset()), range(125))
    now[0] = 1.0
    subject._observe_cadence("a", 23)
    first = progress(subject, 23)
    assert first["eta_seconds"] is None
    assert first["planning_eta_seconds"] is not None
    assert first["eta_samples"] == 0
    # One second of work, sixty seconds in other cohorts/poll/recovery.
    now[0] = 62.0
    subject._observe_cadence("a", 24)
    measured = progress(subject, 24)
    assert measured["eta_seconds"] == 101 * 61
    assert measured["eta_samples"] == 1
    assert measured["eta_basis"] == "selected_checkpoint_wallclock_cadence"
    # Fast successive items in the same batch cannot overwrite the measured
    # cadence with their individual execution times.
    now[0] = 123.0
    assert progress(subject, 25)["eta_seconds"] == 100 * 122 / 2
    subject._observe_cadence("a", 28)
    assert progress(subject, 28)["eta_seconds"] == 97 * 122 / 5
    # Repeated progress cannot move the previously issued finish time forward.
    now[0] = 183.0
    assert progress(subject, 28)["eta_seconds"] == 97 * 122 / 5 - 60
    assert progress(subject, 28, error={"error_type": "OSError"})["eta_seconds"] is None


def test_prior_progress_cannot_hide_an_overdue_forecast(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    subject = worker()
    subject._bind_cadence("a", ((1, "authority"), frozenset()), range(4))
    subject._observe_cadence("a", 1)
    now[0] = 10.0
    subject._observe_cadence("a", 2)
    assert progress(subject, 2, 4)["eta_seconds"] == 20
    now[0] = 29.0
    subject._observe_cadence("a", 2)
    assert progress(subject, 2, 4)["eta_seconds"] == 1
    now[0] = 31.0
    subject._observe_cadence("a", 2)
    overdue = progress(subject, 2, 4)
    assert overdue["eta_seconds"] is None and overdue["stalled_or_retrying"]
    assert overdue["eta_basis"] == "selected_checkpoint_forecast_overdue"
    now[0] = 40.0
    subject._observe_cadence("a", 3)
    resumed = progress(subject, 3, 4)
    assert resumed["eta_seconds"] == 20
    assert not resumed["stalled_or_retrying"]


def test_batch_one_planning_includes_alternate_historical_visits():
    subject = worker()
    subject.batch_size = 1
    subject._bind_cadence("a", ((1, "authority"), frozenset()), range(2))
    plan = progress(subject, 0, 2)
    assert plan["planning_eta_seconds"] == [1, 4 * 5 * (5 + 2 * 150)]


@pytest.mark.parametrize("change", ["authority", "excluded", "ready", "unknown", "restart"])
def test_selection_or_process_change_does_not_reuse_cadence(monkeypatch, change):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    subject = worker()
    selection = ((1, "authority"), frozenset())
    ready = range(125)
    subject._bind_cadence("a", selection, ready)
    subject._observe_cadence("a", 23)
    now[0] = 60.0
    subject._observe_cadence("a", 24)
    assert progress(subject, 24)["eta_samples"] == 1
    if change == "authority":
        selection = ((1, "new-authority"), frozenset())
    elif change == "excluded":
        selection = ((1, "authority"), frozenset({126}))
    elif change == "ready":
        ready = range(126)
    elif change == "unknown":
        selection = None
    else:
        subject = worker()
    subject._bind_cadence("a", selection, ready)
    value = progress(subject, 24)
    assert value["eta_samples"] == 0 and value["eta_seconds"] is None


def test_zero_progress_is_idle_and_observations_are_bounded(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    subject = worker()
    selection = ((1, "authority"), frozenset())
    for _ in range(40):
        now[0] += 60.0
        subject._bind_cadence("a", selection, range(125))
        subject._observe_cadence("a", 23)
    value = progress(subject, 23)
    assert value["eta_seconds"] is None
    assert value["planning_eta_seconds"] is None
    assert value["eta_basis"] == "selected_checkpoint_completion_idle"
    assert value["stalled_or_retrying"]
    assert value["eta_samples"] == 31
    complete = progress(subject, 125)
    assert complete["eta_seconds"] == 0 and complete["status"] == "completed"


def test_cached_public_view_preserves_measured_scope_and_withdraws_overdue_eta(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    subject = worker()
    subject._bind_cadence("a", ((1, "authority"), frozenset()), range(125))
    subject._observe_cadence("a", 123)
    now[0] = 60.0
    subject._observe_cadence("a", 124)
    snapshots = CohortProgressSnapshots()
    value = progress(subject, 124)
    value["cohort_sha256"] = "aa" * 32
    snapshots.record("reserved_participation", value)
    now[0] = 70.0
    view = snapshots.snapshot("aa" * 32)["components"]["reserved_participation"]
    assert view["eta_seconds"] == 50
    assert view["eta_basis"] == "selected_checkpoint_wallclock_cadence"
    now[0] = 121.0
    overdue = snapshots.snapshot("aa" * 32)["components"]["reserved_participation"]
    assert overdue["eta_seconds"] is None and overdue["stalled_or_retrying"]
