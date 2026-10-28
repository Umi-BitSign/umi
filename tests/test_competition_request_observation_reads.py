"""Observation-local reads never confer authority or hide a later arrival."""

import gc
import weakref
from types import SimpleNamespace

import pytest

from umi.competition_cohort_request_phase import _observation_terminal_reader

from .test_open_competition import wallet


def test_terminal_observation_reuses_absence_but_next_observation_sees_arrival():
    evaluator = wallet("observer-evaluator").hotkey.ss58_address
    order = object()
    arrivals, calls = {}, []

    def read(selected, who):
        calls.append((selected, who))
        return arrivals.get(who)

    terminal = _observation_terminal_reader(read)
    assert terminal(order, evaluator) is None
    arrivals[evaluator] = object()
    assert terminal(order, evaluator) is None
    assert len(calls) == 1
    again = _observation_terminal_reader(read)
    assert again(order, evaluator) is arrivals[evaluator]
    assert len(calls) == 2


def test_terminal_reads_are_exact_order_and_evaluator_scoped_without_serialization():
    class Order:
        def model_dump(self, *args, **kwargs):
            raise AssertionError("observation bookkeeping serialized the complete round")

    first, other = Order(), Order()
    evaluators = [wallet(name).hotkey.ss58_address for name in ("observer-a", "observer-b")]
    calls = []

    def read(order, evaluator):
        result = object()
        calls.append((order, evaluator, result))
        return result

    terminal = _observation_terminal_reader(read)
    a, b, c = (
        terminal(first, evaluators[0]),
        terminal(first, evaluators[1]),
        terminal(other, evaluators[0]),
    )
    assert len({id(a), id(b), id(c)}) == 3
    assert terminal(first, evaluators[0]) is a
    assert len(calls) == 3
    original = weakref.ref(first)
    calls.clear()
    del first
    gc.collect()
    assert original() is not None  # Its ID cannot be reassigned within this observation.
    del terminal
    gc.collect()
    assert original() is None


def test_failed_terminal_read_is_never_retained_as_absence():
    evaluator = wallet("observer-evaluator").hotkey.ss58_address
    calls = []

    def read(*args):
        calls.append(args)
        raise ValueError("retained proof requires repair")

    terminal = _observation_terminal_reader(read)
    order = object()
    for _ in range(2):
        with pytest.raises(ValueError, match="requires repair"):
            terminal(order, evaluator)
    assert len(calls) == 2


def test_intake_scan_hashes_the_selected_plan_once_and_still_checks_each_index(monkeypatch):
    from umi import competition_cohort_intake as module

    plan, genesis = object(), object()
    hashes = []

    def digest(value):
        hashes.append(value)
        return "cohort" if value is plan else "tip"

    history = SimpleNamespace(plan=plan, genesis=genesis, transitions=())
    admission = SimpleNamespace(recovery_tip_sha256="tip", cohort_sha256="cohort")
    retained = SimpleNamespace(proposed_admission=admission)
    monkeypatch.setattr(module, "digest", digest)
    monkeypatch.setattr(module, "read_participation", lambda raw: retained)

    class Database:
        def execute(self, query, parameters):
            assert parameters == ["cohort"]
            return [(str(i), "tip", b"original") for i in range(103)]

    def records():
        return tuple(module.CohortIntake._parsed_records(None, Database(), history))

    assert len(records()) == 103
    assert sum(value is plan for value in hashes) == 1
    admission.cohort_sha256 = "another-cohort"
    with pytest.raises(ValueError, match="index differs"):
        records()
