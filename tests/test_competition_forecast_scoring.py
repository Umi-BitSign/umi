"""Frozen predictions, uncertain outcomes and conservative comparable groups."""

import pytest

from umi import competition_forecast as module
from umi.competition_forecast import ForecastLedger, restore_forecast_snapshot
from umi.competition_forecast_io import stream_file
from umi.competition_forecast_scoring import population_sha256

POPULATION = {
    "schema": "umi-forecast-comparison-population/1",
    "policy_sha256": "a" * 64,
    "chain_config_sha256": "b" * 64,
    "verifier_semantics": "c" * 64,
    "workload_regime_sha256": "d" * 64,
    "role": "reward_writer",
    "stage": "selected_native_history_interval",
    "unit": "blocks",
    "rate_semantics": "umi-history-ordered-new-native-per-invocation-target-wall-time/1",
    "total_blocks": 20,
    "remaining_blocks": 15,
    "restored_completed": 0,
}
POOL = population_sha256(POPULATION)
SCOPE = "1" * 64
GROUP = "2" * 64


def forecast(
    ledger,
    *,
    scope=SCOPE,
    group=GROUP,
    identity=None,
    point=15000,
    window=(10000, 20000),
    issued=2000,
    origin="prospective",
    population=None,
    **extra,
):
    ledger.append(scope + ":start", scope, "scope_started", {"observed_unix_ms": 1000})
    population = dict(POPULATION if population is None else population)
    values = {
        "observed_unix_ms": issued,
        "finish_unix_ms": point,
        "finish_range_unix_ms": window,
        "comparison_population": population,
        "comparison_population_sha256": population_sha256(population),
        "comparison_outcome_unit_identity": scope,
        "comparison_correlation_group_identity": group,
        "comparison_correlation_group_basis": "shared_native_history_series",
        **extra,
    }
    if origin is not None:
        values["forecast_origin"] = origin
    return ledger.append(identity or scope + ":forecast", scope, "forecast", values)


def complete(ledger, outcome, *, scope=SCOPE, identity=None, observed=None):
    return ledger.append(
        identity or scope + ":terminal",
        scope,
        "attempt_terminal",
        {
            "state": "completed",
            "observed_unix_ms": observed or outcome[1],
            "completion_range_unix_ms": outcome,
        },
    )


@pytest.fixture
def ledger(tmp_path):
    value = ForecastLedger(tmp_path / "accounting")
    yield value
    value.close()


@pytest.mark.parametrize(
    "outcome,expected",
    [
        ((5000, 9000), "early"),
        ((10000, 10000), "inside"),
        ((10000, 20000), "inside"),
        ((20000, 20000), "inside"),
        ((21000, 22000), "late"),
        ((9000, 10000), "ambiguous"),
        ((20000, 21000), "ambiguous"),
        ((5000, 25000), "ambiguous"),
    ],
)
def test_original_range_scores_conservative_closed_completion_envelope(ledger, outcome, expected):
    forecast(ledger)
    complete(ledger, outcome)
    result = ledger.status(SCOPE)
    comparison = result["original_range_comparison"]
    assert comparison["disposition"] == expected
    assert comparison["outcome_range_unix_ms"] == outcome
    assert comparison["empirical_eligible"] is True
    assert comparison["outcome_boundary_semantics"] == "conservative_closed_envelope"
    assert result["calibration_eligible"] is False
    assert result["empirical_outcome_eligible"] is True
    report = ledger.calibration_report(POOL, metric="range")
    assert report["outcomes"][expected] == 1
    assert report["calibrated_probability_available"] is False
    assert report["independent_runs_established"] is False


def test_uncertain_outcome_never_becomes_exact_time_error_or_duration(ledger):
    forecast(ledger)
    complete(ledger, (13000, 18000), observed=19000)
    result = ledger.status(SCOPE)
    assert result["elapsed_including_gaps_seconds"] is None
    assert result["first_forecast_error_seconds"] is None
    assert result["elapsed_including_gaps_range_seconds"] == [12, 17]
    assert result["original_point_comparison"]["point_error_range_seconds"] == [-2, 3]
    assert result["original_point_comparison"]["disposition"] == "ambiguous"
    report = ledger.calibration_report(POOL, metric="point")
    assert report["mean_point_error_range_seconds"] == [-2, 3]
    assert report["observed_point_error_envelope_seconds"] == [-2, 3]
    assert report["prospective_eta_correction_selected"] is False
    # observed_unix_ms controls unfinished overdue status, never historical visibility.
    assert ledger.status(SCOPE, observed_unix_ms=1000)["outcome"] == "completed"


def test_pending_overdue_does_not_become_a_completed_miss(ledger):
    forecast(ledger, point=None)
    assert (
        ledger.status(SCOPE, observed_unix_ms=20000)["original_range_comparison"]["disposition"]
        == "pending"
    )
    result = ledger.status(SCOPE, observed_unix_ms=20001)
    assert result["original_range_comparison"]["disposition"] == "pending_overdue"
    report = ledger.calibration_report(POOL, metric="range", observed_unix_ms=20001)
    assert report["pending_correlation_groups"] == 1
    assert report["overdue_pending_correlation_groups"] == 1
    assert report["eligible_completed_correlation_groups"] == 0
    assert report["outcomes"]["late"] == 0
    complete(ledger, (21000, 22000))
    result = ledger.status(SCOPE)
    assert result["sample_kind"] == "range_prediction_outcome"
    assert result["original_range_comparison"]["disposition"] == "late"


@pytest.mark.parametrize(
    "origin,reason",
    [(None, "forecast_origin_legacy_unknown"), ("retrospective", "forecast_origin_retrospective")],
)
def test_first_original_is_frozen_even_if_later_revision_is_prospective(ledger, origin, reason):
    first = forecast(ledger, origin=origin)
    forecast(ledger, identity="prospective-revision", issued=3000)
    complete(ledger, (15000, 15000))
    result = ledger.status(SCOPE)
    assert result["original_point_comparison"]["forecast_identity"] == first["identity"]
    assert result["original_point_comparison"]["exclusion_reasons"] == [reason]
    assert result["empirical_outcome_eligible"] is False
    report = ledger.calibration_report(POOL, metric="point")
    assert report["eligible_completed_correlation_groups"] == 0
    assert report["exclusions"][reason] == 1


def test_post_completion_revisions_stay_visible_but_never_count_again(ledger):
    forecast(ledger)
    complete(ledger, (15000, 15000))
    forecast(ledger, identity="later-attempt", issued=30000)
    # A backdated repeat is still a repeat by durable sequence, not just wall time.
    forecast(ledger, identity="backdated-attempt", issued=4000)
    scores = ledger.forecast_scores(SCOPE)["scores"]
    repeats = [value for value in scores if value["forecast_identity"] != SCOPE + ":forecast"]
    assert len(repeats) == 4
    assert all("repeat_after_first_completion" in value["exclusion_reasons"] for value in repeats)
    report = ledger.calibration_report(POOL, metric="point")
    assert report["eligible_completed_correlation_groups"] == 1
    assert ledger.status(SCOPE)["completion_examples"] == 1


def test_forecast_must_precede_earliest_possible_outcome(ledger):
    forecast(ledger, issued=12000)
    complete(ledger, (12000, 15000))
    assert ledger.status(SCOPE)["original_range_comparison"]["exclusion_reasons"] == [
        "forecast_not_proven_before_outcome"
    ]


def test_earliest_pending_unit_excludes_later_completed_correlated_target(ledger):
    forecast(ledger)
    other = "3" * 64
    forecast(ledger, scope=other, issued=3000)
    complete(ledger, (15000, 15000), scope=other)
    report = ledger.calibration_report(POOL, metric="point", observed_unix_ms=21000)
    assert report["matched_outcome_units"] == 2
    assert report["selected_correlation_groups"] == 1
    assert report["eligible_completed_correlation_groups"] == 0
    assert report["pending_correlation_groups"] == 1
    assert report["correlated_outcome_unit_repeats_excluded"] == 1
    assert report["selected_units"][0]["outcome_unit_identity"] == SCOPE
    assert report["selection_exclusions"][0]["outcome_unit_identity"] == other
    assert report["selection_exclusions"][0]["reason"] == "correlated_outcome_unit_repeat"


def test_missing_group_is_distinct_from_duplicate_and_population_exclusions(ledger):
    forecast(ledger)
    complete(ledger, (15000, 15000))
    forecast(ledger, scope="3" * 64, group=None)
    forecast(
        ledger, scope="4" * 64, group="5" * 64, population={**POPULATION, "policy_sha256": "e" * 64}
    )
    report = ledger.calibration_report(POOL, metric="point")
    assert report["matched_outcome_units"] == 2
    assert report["unmatched_outcome_units"] == 1
    assert report["ungroupable_outcome_units"] == 1
    assert report["correlated_outcome_unit_repeats_excluded"] == 0
    assert {value["reason"] for value in report["selection_exclusions"]} == {
        "comparison_population_mismatch",
        "correlation_group_identity_unqualified",
    }


@pytest.mark.parametrize(
    "change",
    [
        {"schema": "arbitrary-label"},
        {"total_blocks": True},
        {"restored_completed": 10},
        {"workload_regime_sha256": None},
    ],
)
def test_incomplete_or_invalid_population_never_qualifies(ledger, change):
    forecast(ledger, population={**POPULATION, **change})
    complete(ledger, (15000, 15000))
    assert (
        "comparison_population_unqualified"
        in ledger.status(SCOPE)["original_point_comparison"]["exclusion_reasons"]
    )


def test_population_hash_and_outcome_binding_must_match(ledger):
    forecast(
        ledger, comparison_population_sha256="0" * 64, comparison_outcome_unit_identity="f" * 64
    )
    complete(ledger, (15000, 15000))
    assert set(ledger.status(SCOPE)["original_point_comparison"]["exclusion_reasons"]) == {
        "comparison_population_unqualified",
        "outcome_unit_identity_unqualified",
    }


def test_descriptive_error_bounds_use_only_matching_eligible_groups(ledger):
    forecast(ledger)
    complete(ledger, (12000, 16000))
    second = "3" * 64
    forecast(ledger, scope=second, group="4" * 64)
    complete(ledger, (17000, 20000), scope=second)
    forecast(ledger, scope="5" * 64, group="6" * 64)  # unfinished is retained, not averaged
    report = ledger.calibration_report(POOL, metric="point", observed_unix_ms=25000)
    assert report["eligible_completed_correlation_groups"] == 2
    assert report["pending_correlation_groups"] == 1
    assert report["mean_point_error_range_seconds"] == [-0.5, 3]
    assert report["observed_point_error_envelope_seconds"] == [-3, 5]
    assert not report["independent_runs_established"]


def test_restart_preserves_original_bytes_bracket_and_single_group(tmp_path):
    directory = tmp_path / "accounting"
    ledger = ForecastLedger(directory)
    forecast(ledger)
    before = ledger.records(SCOPE)
    ledger.close()
    ledger = ForecastLedger(directory)
    forecast(
        ledger,
        identity="restart-revision",
        issued=25000,
        point=30000,
        population={**POPULATION, "remaining_blocks": 10, "restored_completed": 5},
    )
    complete(ledger, (26000, 28000))
    complete(ledger, (32000, 33000), identity="repeat-outcome")
    assert ledger.records(SCOPE)[: len(before)] == before
    result = ledger.status(SCOPE)
    assert result["completion_range_unix_ms"] == (26000, 28000)
    assert result["original_point_comparison"]["comparison_population_sha256"] == POOL
    assert (
        ledger.calibration_report(POOL, metric="point")["eligible_completed_correlation_groups"]
        == 1
    )
    ledger.close()
    ledger = ForecastLedger(directory)
    assert ledger.status(SCOPE)["original_range_comparison"] == result["original_range_comparison"]
    ledger.close()


def test_restore_gap_excludes_previously_good_pair_without_rewriting_it(tmp_path):
    directory = tmp_path / "accounting"
    ledger = ForecastLedger(directory)
    forecast(ledger)
    snapshot = tmp_path / "snapshot.sqlite3"
    receipt = ledger.snapshot(snapshot)
    complete(ledger, (15000, 15000))
    ledger.close()
    previous, _ = stream_file(directory / "forecasts.sqlite3", maximum_bytes=1024**2)
    restore_forecast_snapshot(directory, snapshot, receipt, damaged_sha256=previous)
    ledger = ForecastLedger(directory)
    complete(ledger, (15000, 15000))
    comparison = ledger.status(SCOPE)["original_point_comparison"]
    assert comparison["disposition"] == "inside"
    assert comparison["exclusion_reasons"] == ["incomplete_accounting_coverage"]
    assert (
        ledger.calibration_report(POOL, metric="point")["eligible_completed_correlation_groups"]
        == 0
    )
    ledger.close()


@pytest.mark.parametrize("bracket", [(500, 15000), (16000, 15000), (14000, 16000)])
def test_invalid_completion_is_rejected_before_commit_and_reopens(ledger, bracket):
    forecast(ledger)
    head = ledger.head
    with pytest.raises(ValueError):
        complete(ledger, bracket, observed=15000)
    assert ledger.head == head
    assert ledger.status(SCOPE)["outcome"] == "unfinished"
    complete(ledger, (14000, 15000), identity="repaired-outcome")
    assert ledger.status(SCOPE)["original_range_comparison"]["exclusion_reasons"] == [
        "incomplete_accounting_coverage"
    ]
    ledger.close()
    reopened = ForecastLedger(ledger.directory)
    assert reopened.status(SCOPE)["outcome"] == "completed"
    reopened.close()


def test_old_exact_point_semantics_survive_and_origin_is_explicitly_unknown(ledger):
    forecast(ledger, origin=None)
    ledger.append("old-terminal", SCOPE, "completed", {"observed_unix_ms": 17000})
    result = ledger.status(SCOPE)
    assert result["elapsed_including_gaps_seconds"] == 16
    assert result["first_forecast_error_seconds"] == 2
    assert result["completion_range_unix_ms"] == (17000, 17000)
    assert result["original_point_comparison"]["forecast_origin"] == "legacy_unknown"
    assert result["calibration_eligible"] is False


def test_compact_reports_never_reread_decode_or_hash_prior_events(ledger, monkeypatch):
    forecast(ledger)
    complete(ledger, (15000, 15000))
    expected = ledger.calibration_report(POOL, metric="point")

    def forbidden(*args, **kwargs):
        pytest.fail("compact report revisited immutable events")

    monkeypatch.setattr(module.hashlib, "sha256", forbidden)
    monkeypatch.setattr(module.json, "loads", forbidden)
    monkeypatch.setattr(ledger, "records", forbidden)
    for _ in range(10):
        assert ledger.calibration_report(POOL, metric="point") == expected
        assert ledger.status(SCOPE)["original_range_comparison"]["empirical_eligible"]


def test_report_rejects_partial_pool_and_paging_bounds_scanned_rows(ledger):
    forecast(ledger)
    complete(ledger, (15000, 15000))
    for index in range(8):
        ledger.append(f"other-{index}", SCOPE, "diagnostic", {})
    forecast(ledger, scope="3" * 64, group="4" * 64)
    with pytest.raises(ValueError, match="no partial sample"):
        ledger.calibration_report(POOL, metric="point", maximum_scopes=1)
    cursor, pages, scores = 0, 0, []
    while True:
        page = ledger.forecast_scores(SCOPE, after_sequence=cursor, limit=2)
        if page["through_sequence"] == cursor:
            break
        assert page["through_sequence"] <= cursor + 2
        scores.extend(page["scores"])
        pages += 1
        cursor = page["through_sequence"]
    assert pages == 6
    assert {value["metric"] for value in scores} == {"point", "range"}
    assert len(scores) == 2
    with pytest.raises(ValueError):
        ledger.forecast_scores(SCOPE, limit=1001)


def test_exposed_comparison_does_not_allow_mutating_verified_summary(ledger):
    record = forecast(ledger)
    record["comparison_population"]["role"] = "mutated"
    complete(ledger, (15000, 15000))
    result = ledger.status(SCOPE)
    result["original_point_comparison"]["comparison_population"]["role"] = "mutated again"
    assert ledger.status(SCOPE)["original_point_comparison"]["comparison_population"] == POPULATION


def test_clock_regression_excludes_original_and_withdraws_error(ledger):
    forecast(ledger, issued=9000)
    complete(ledger, (8000, 8000))
    result = ledger.status(SCOPE)["original_point_comparison"]
    assert result["disposition"] == "clock_regression"
    assert result["point_error_range_seconds"] is None
    assert "clock_regression" in result["exclusion_reasons"]


@pytest.mark.parametrize("value", [None, True, -1, "2000"])
def test_invalid_new_forecast_clock_cannot_poison_committed_summary(ledger, value):
    ledger.append(SCOPE + ":start", SCOPE, "scope_started", {"observed_unix_ms": 1000})
    before = ledger.head
    with pytest.raises(ValueError, match="integer timestamp"):
        forecast(ledger, issued=value)
    assert ledger.head == before
    assert ledger.status(SCOPE)["original_point_comparison"] is None
    forecast(ledger, identity="valid-retry")
    complete(ledger, (15000, 15000))
    assert ledger.status(SCOPE)["original_point_comparison"]["exclusion_reasons"] == [
        "incomplete_accounting_coverage"
    ]


@pytest.mark.parametrize(
    "field",
    ["policy_sha256", "chain_config_sha256", "verifier_semantics", "workload_regime_sha256"],
)
def test_changed_native_binding_selects_a_different_population(ledger, field):
    changed = {**POPULATION, field: "e" * 64}
    forecast(ledger, population=changed)
    complete(ledger, (15000, 15000))
    assert (
        ledger.calibration_report(POOL, metric="point")["eligible_completed_correlation_groups"]
        == 0
    )
    report = ledger.calibration_report(population_sha256(changed), metric="point")
    assert report["eligible_completed_correlation_groups"] == 1
