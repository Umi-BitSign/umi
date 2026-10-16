"""Descriptive forecast scoring; no fitted distribution or probability claim."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy


def population_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def interval(value):
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 2
        or any(type(item) is not int or item < 0 for item in value)
        or value[0] > value[1]
    ):
        raise ValueError("forecast scoring requires an ordered nonnegative timestamp pair")
    return tuple(value)


def completion_interval(event):
    selected = event.get("completion_range_unix_ms")
    now = event["observed_unix_ms"]
    result = interval([now, now] if selected is None else selected)
    if result[1] > now:
        raise ValueError("observed completion bracket extends into the future")
    return result


def _sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _population_qualified(value, checksum):
    """Recognize declared native dimensions, not arbitrary caller-labelled pools."""
    if not isinstance(value, dict):
        return False
    digests = (
        "policy_sha256",
        "chain_config_sha256",
        "verifier_semantics",
        "workload_regime_sha256",
    )
    counts = ("total_blocks", "remaining_blocks", "restored_completed")
    return (
        value.get("schema") == "umi-forecast-comparison-population/1"
        and value.get("stage") == "selected_native_history_interval"
        and value.get("unit") == "blocks"
        and value.get("rate_semantics")
        == "umi-history-ordered-new-native-per-invocation-target-wall-time/1"
        and isinstance(value.get("role"), str)
        and bool(value["role"])
        and all(_sha256(value.get(key)) for key in digests)
        and all(type(value.get(key)) is int and value[key] >= 0 for key in counts)
        and value["remaining_blocks"] + value["restored_completed"] <= value["total_blocks"]
        and population_sha256(value) == checksum
    )


def retained_forecast(event, metric):
    value = event.get("finish_unix_ms" if metric == "point" else "finish_range_unix_ms")
    if value is None:
        return None
    predicted = interval([value, value] if metric == "point" else value)
    # This validation/hash occurs once when accepting/verifying the event, never
    # when ordinary status() reuses its compact summary.
    population = deepcopy(event.get("comparison_population"))
    checksum = event.get("comparison_population_sha256")
    group = event.get("comparison_correlation_group_identity")
    basis = event.get("comparison_correlation_group_basis")
    unit = event.get("comparison_outcome_unit_identity")
    return {
        "forecast_identity": event["identity"],
        "scope_identity": event["scope"],
        "forecast_origin": event.get("forecast_origin", "legacy_unknown"),
        "issued_unix_ms": event["observed_unix_ms"],
        "predicted_range_unix_ms": predicted,
        "range_basis": event.get("range_basis"),
        "classification": event.get("classification"),
        "comparison_population": population,
        "comparison_population_sha256": checksum,
        "population_qualified": _population_qualified(population, checksum),
        "outcome_unit_identity": unit,
        "correlation_group_identity": group,
        "correlation_group_basis": basis,
        "group_identity_qualified": _sha256(group) and basis == "shared_native_history_series",
        "outcome_unit_qualified": _sha256(unit) and unit == event["scope"],
    }


def score_forecast(
    forecast,
    outcome,
    *,
    observed_unix_ms,
    metric,
    coverage_complete=True,
    clock_regression=False,
    after_first_completion=False,
):
    """Score currently retained state, not a historical as-of/backtesting view.

    Early/late describe the outcome relative to the original predicted window.
    Poll-derived (last incomplete, first complete] outcomes use their conservative
    closed envelope; no midpoint or false exact completion is introduced.
    """
    lower, upper = forecast["predicted_range_unix_ms"]
    outcome = None if outcome is None else interval(outcome)
    if clock_regression:
        disposition = "clock_regression"
    elif outcome is None:
        disposition = "pending_overdue" if observed_unix_ms > upper else "pending"
    elif outcome[1] < lower:
        disposition = "early"
    elif outcome[0] > upper:
        disposition = "late"
    elif lower <= outcome[0] <= outcome[1] <= upper:
        disposition = "inside"
    else:
        disposition = "ambiguous"
    reasons = []
    if not coverage_complete:
        reasons.append("incomplete_accounting_coverage")
    if clock_regression:
        reasons.append("clock_regression")
    if after_first_completion:
        reasons.append("repeat_after_first_completion")
    if forecast["forecast_origin"] != "prospective":
        reasons.append("forecast_origin_" + str(forecast["forecast_origin"]))
    if outcome is None:
        reasons.append("outcome_unfinished")
    elif forecast["issued_unix_ms"] >= outcome[0]:
        reasons.append("forecast_not_proven_before_outcome")
    if not forecast["population_qualified"]:
        reasons.append("comparison_population_unqualified")
    if not forecast["outcome_unit_qualified"]:
        reasons.append("outcome_unit_identity_unqualified")
    if not forecast["group_identity_qualified"]:
        reasons.append("correlation_group_identity_unqualified")
    return {
        **deepcopy(forecast),
        "metric": metric,
        "outcome_range_unix_ms": outcome,
        "outcome_boundary_semantics": "conservative_closed_envelope",
        "disposition": disposition,
        "point_error_range_seconds": (
            [(outcome[0] - lower) / 1000, (outcome[1] - lower) / 1000]
            if outcome is not None and metric == "point" and not clock_regression
            else None
        ),
        "empirical_eligible": not reasons,
        "exclusion_reasons": reasons,
        "certification_authority": False,
    }


def _reference(value):
    return {
        key: value[key]
        for key in (
            "scope_identity",
            "forecast_identity",
            "outcome_unit_identity",
            "correlation_group_identity",
            "correlation_group_basis",
        )
    }


def empirical_report(comparisons, *, population, metric):
    """Freeze one original per correlated lineage before filtering outcomes."""
    selected, excluded, discarded = {}, {}, []
    matched = unmatched = ungroupable = 0
    for value in comparisons:
        if value["comparison_population_sha256"] != population:
            unmatched += 1
            discarded.append({**_reference(value), "reason": "comparison_population_mismatch"})
            continue
        matched += 1
        if not value["group_identity_qualified"]:
            ungroupable += 1
            discarded.append(
                {**_reference(value), "reason": "correlation_group_identity_unqualified"}
            )
            excluded["correlation_group_identity_unqualified"] = ungroupable
            continue
        group = value["correlation_group_identity"]
        prior = selected.get(group)
        order = (value["issued_unix_ms"], value["forecast_identity"])
        if prior is None:
            selected[group] = value
        else:
            if order < (prior["issued_unix_ms"], prior["forecast_identity"]):
                selected[group] = value
            else:
                prior = value
            discarded.append({**_reference(prior), "reason": "correlated_outcome_unit_repeat"})
    eligible, units = [], []
    pending = overdue = 0
    for value in selected.values():
        pending += value["outcome_range_unix_ms"] is None
        overdue += value["disposition"] == "pending_overdue"
        units.append(
            {
                **_reference(value),
                "empirical_eligible": value["empirical_eligible"],
                "exclusion_reasons": value["exclusion_reasons"],
                "disposition": value["disposition"],
            }
        )
        if value["empirical_eligible"]:
            eligible.append(value)
        else:
            for reason in value["exclusion_reasons"]:
                excluded[reason] = excluded.get(reason, 0) + 1
    dispositions = dict.fromkeys(("early", "inside", "late", "ambiguous"), 0)
    for value in eligible:
        dispositions[value["disposition"]] += 1
    errors = [v["point_error_range_seconds"] for v in eligible if metric == "point"]
    return {
        "schema": "umi-forecast-empirical-summary/1",
        "population_sha256": population,
        "metric": metric,
        "selection": "earliest_original_per_correlation_group_before_outcome_filtering",
        "state_basis": "current_retained_state_not_historical_backtest",
        "matched_outcome_units": matched,
        "unmatched_outcome_units": unmatched,
        "ungroupable_outcome_units": ungroupable,
        "selected_correlation_groups": len(selected),
        "correlated_outcome_unit_repeats_excluded": matched - ungroupable - len(selected),
        "pending_correlation_groups": pending,
        "overdue_pending_correlation_groups": overdue,
        "eligible_completed_correlation_groups": len(eligible),
        "selected_units": units,
        "selection_exclusions": discarded,
        "exclusions": excluded,
        "outcomes": dispositions,
        "mean_point_error_range_seconds": (
            [sum(v[0] for v in errors) / len(errors), sum(v[1] for v in errors) / len(errors)]
            if errors
            else None
        ),
        "observed_point_error_envelope_seconds": (
            [min(v[0] for v in errors), max(v[1] for v in errors)] if errors else None
        ),
        "interpretation": "descriptive_matching_declared_native_dimensions_only",
        "independent_runs_established": False,
        "calibrated_probability_available": False,
        "prospective_eta_correction_selected": False,
        "certification_authority": False,
    }
