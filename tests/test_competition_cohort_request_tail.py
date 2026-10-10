"""Original distinct-miner bounds and independently replayed chain clocks."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_cohort_request_tail import (
    MINIMUM_REQUEST_OPEN_MS,
    RequestTailObservation,
    original_request_miners,
    verify_request_tail_clock,
)
from umi.competition_historical_registration import HistoricalRegistration
from umi.open_competition import identity

from .test_competition_execution import boundary
from .test_open_competition import wallet


def tail(*, miners=11, unfinished=1, elapsed=MINIMUM_REQUEST_OPEN_MS):
    return RequestTailObservation(
        schema="umi-cohort-request-tail-observation/1",
        opened_observation=boundary(390),
        opened_timestamp_ms=1000,
        observation=boundary(1680),
        observed_timestamp_ms=1000 + elapsed,
        original_hotkeys=tuple(f"{i:064x}" for i in range(miners)),
        unfinished_hotkeys=tuple(f"{i:064x}" for i in range(unfinished)),
    )


@pytest.mark.parametrize(
    "miners,unfinished", [(10, 1), (11, 1), (100, 9), (100, 10), (202, 20), (1, 0)]
)
def test_at_most_tenth_distinct_original_miner_threshold(miners, unfinished):
    assert len(tail(miners=miners, unfinished=unfinished).unfinished_hotkeys) == unfinished


@pytest.mark.parametrize("miners,unfinished", [(9, 1), (100, 11), (202, 21), (1, 1)])
def test_more_than_tenth_remain_pending(miners, unfinished):
    with pytest.raises(ValueError, match="at most ten"):
        tail(miners=miners, unfinished=unfinished)


@pytest.mark.parametrize("elapsed", [0, MINIMUM_REQUEST_OPEN_MS - 1])
def test_original_twelve_hour_boundary(elapsed):
    with pytest.raises(ValueError, match="twelve hours"):
        tail(elapsed=elapsed)


def test_repeated_entries_and_paid_claims_never_increase_denominator():
    def participant(who):
        return SimpleNamespace(
            record=SimpleNamespace(
                request=SimpleNamespace(
                    signed_submission=SimpleNamespace(submission=SimpleNamespace(hotkey=who))
                )
            )
        )

    a, b = (wallet(name).hotkey.ss58_address for name in ("Alice", "Bob"))
    roster = SimpleNamespace(participants=[participant(a), participant(a), participant(b)])
    assignment = SimpleNamespace(
        admission=SimpleNamespace(submission=SimpleNamespace(submission=SimpleNamespace(hotkey=a)))
    )
    assert original_request_miners(roster, [assignment] * 256) == tuple(
        sorted((identity(a), identity(b)))
    )
    assignment.admission.submission.submission.hotkey = wallet("Charlie").hotkey.ss58_address
    with pytest.raises(ValueError, match="outside"):
        original_request_miners(roster, [assignment])


def test_tail_clock_requires_both_exact_original_native_proofs():
    value = tail()
    head = FinalizedSnapshotRef(1700, "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32)
    opening = HistoricalRegistration(None, value.opened_observation, head, 1000)
    observed = HistoricalRegistration(None, value.observation, head, value.observed_timestamp_ms)
    verify_request_tail_clock(value, opening, observed)
    for bad in (
        replace(opening, timestamp_ms=None),
        replace(opening, timestamp_ms=999),
        replace(opening, original=boundary(389)),
        SimpleNamespace(
            original=opening.original,
            replayed_at=opening.replayed_at,
            timestamp_ms=opening.timestamp_ms,
        ),
    ):
        with pytest.raises(ValueError, match="native original timestamp"):
            verify_request_tail_clock(value, bad, observed)
    with pytest.raises(ValueError, match="native original timestamp"):
        verify_request_tail_clock(value, opening, replace(observed, timestamp_ms=1000))


def test_retained_cutoff_requires_its_original_clock_and_never_restarts_grace_period():
    first = tail()
    value = first.model_copy(
        update={
            "selected_observation": first.observation,
            "selected_timestamp_ms": first.observed_timestamp_ms,
            "observation": boundary(first.observation.block + 1),
            "observed_timestamp_ms": first.observed_timestamp_ms + 12000,
            "unfinished_hotkeys": (),
        }
    )
    value = RequestTailObservation.model_validate_json(value.model_dump_json(by_alias=True))
    head = FinalizedSnapshotRef(1700, "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32)
    opening = HistoricalRegistration(None, value.opened_observation, head, 1000)
    observed = HistoricalRegistration(None, value.observation, head, value.observed_timestamp_ms)
    selected = HistoricalRegistration(None, first.observation, head, first.observed_timestamp_ms)
    verify_request_tail_clock(value, opening, observed, selected)
    with pytest.raises(ValueError, match="native original timestamp"):
        verify_request_tail_clock(value, opening, observed)
    with pytest.raises(ValueError, match="native original timestamp"):
        verify_request_tail_clock(value, opening, observed, replace(selected, timestamp_ms=1000))
    changed = value.model_copy(update={"selected_timestamp_ms": 1000 + MINIMUM_REQUEST_OPEN_MS - 1})
    with pytest.raises(ValueError, match="twelve hours"):
        RequestTailObservation.model_validate_json(changed.model_dump_json(by_alias=True))


@pytest.mark.parametrize("field", ["original_hotkeys", "unfinished_hotkeys"])
def test_duplicate_identity_claims_are_rejected(field):
    value = tail()
    duplicated = value.model_copy(update={field: getattr(value, field) * 2})
    with pytest.raises(ValueError, match="unique and ordered"):
        RequestTailObservation.model_validate_json(duplicated.model_dump_json(by_alias=True))
