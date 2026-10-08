from __future__ import annotations

import pytest

from umi import competition_cohort_intake_records as records
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_intake_seal import EmptyCohortIntake, build_intake_seal
from umi.competition_execution import execution_boundary

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy


def retained_inputs(intake, scenario):
    intake.retain(request_for(scenario), capture_at(210))
    history = scenario["intake_history"]
    with intake._connection() as (db, _):
        saved = tuple(intake._records(db, history))
    return history, saved


def test_unchanged_historical_participation_is_not_reverified(intake, scenario, monkeypatch):
    history, saved = retained_inputs(intake, scenario)
    original = records.read_participation(saved[0][1])
    expected = records.replay_participation(original, history, scenario["policy"])

    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged historical participation was reverified")

    monkeypatch.setattr(records, "admit_recovery_participant", unexpected)
    decoded = records.read_participation(saved[0][1])
    result = records.replay_participation(decoded, history, scenario["policy"])
    assert result == expected
    object.__setattr__(result, "admitted_at_block", 0)
    assert records.replay_participation(decoded, history, scenario["policy"]) == expected


def test_reused_history_does_not_reuse_current_registration(intake, scenario, monkeypatch):
    history, saved = retained_inputs(intake, scenario)
    first = capture_at(300)
    seal = build_intake_seal(
        history,
        scenario["policy"],
        execution_boundary(first),
        first.snapshot,
        saved,
        expected_tip_sha256=history_tip(history),
    )
    assert len(seal.selected) == 1

    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged historical participation was reverified")

    monkeypatch.setattr(records, "admit_recovery_participant", unexpected)
    current = capture_at(320)
    hotkey = records.read_participation(saved[0][1]).request.signed_submission.submission.hotkey
    snapshot = current.snapshot.model_copy(
        update={
            "registrations": tuple(r for r in current.snapshot.registrations if r.hotkey != hotkey)
        }
    )
    with pytest.raises(EmptyCohortIntake):
        build_intake_seal(
            history,
            scenario["policy"],
            execution_boundary(current),
            snapshot,
            saved,
            expected_tip_sha256=history_tip(history),
        )


@pytest.mark.parametrize("changed", ["observation", "policy", "history"])
def test_changed_historical_inputs_require_native_replay(intake, scenario, monkeypatch, changed):
    history, saved = retained_inputs(intake, scenario)
    retained = records.read_participation(saved[0][1])
    policy = scenario["policy"]
    records.replay_participation(retained, history, policy)
    if changed == "observation":
        retained = retained.model_copy(
            update={"observation": retained.observation.model_copy(update={"block": 211})}
        )
    elif changed == "policy":
        policy = policy.model_copy(update={"minimum_score_bps": policy.minimum_score_bps + 1})
    else:
        history = history.model_copy(update={"genesis_signatures": history.genesis_signatures[:1]})
    original = records.admit_recovery_participant
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(records, "admit_recovery_participant", counted)
    with pytest.raises(ValueError):
        records.replay_participation(retained, history, policy)
    assert calls == [True]
    with pytest.raises(ValueError):
        records.replay_participation(retained, history, policy)
    assert calls == [True, True]


def test_child_process_cannot_inherit_parent_replay_receipt(intake, scenario, monkeypatch):
    history, saved = retained_inputs(intake, scenario)
    retained = records.read_participation(saved[0][1])
    expected = records.replay_participation(retained, history, scenario["policy"])
    monkeypatch.setattr(records._historical_participation_reuse, "_pid", -1)
    original = records.admit_recovery_participant
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(records, "admit_recovery_participant", counted)
    assert records.replay_participation(retained, history, scenario["policy"]) == expected
    assert calls == [True]
