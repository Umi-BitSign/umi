"""Preserve native request owners across unrelated intake-deadline changes.

Admission deadlines have their own authenticated intake selection. They do not
change a request roster, transport, catalog, authority or evidence namespace.
Keep the original immutable binding on compatible restart, including its old
deadline fields, so completed verification continues to use the same owner.
"""

from copy import deepcopy

from .protocol import canonical_json_bytes


def _request_semantics(kind, value):
    value = deepcopy(value)
    try:
        if kind == "request_phase_binding":
            intake = value["intake"]
        elif kind == "request_delivery_binding":
            intake = value["sources"]["intake"]
        else:
            raise ValueError("unsupported request owner binding")
        if not isinstance(intake, dict):
            raise ValueError("request owner intake binding requires repair")
        intake.pop("admission_deadlines", None)
    except (KeyError, TypeError) as error:
        raise ValueError("request owner binding requires repair") from error
    return value


def retain_request_binding(journal, kind, cohort, candidate):
    """Select exact old bytes through the native fresh conflict fence.

    Normalize only comparisons. New and existing owners keep the original record
    shape and verification identities, including unchanged-config older writers.
    Every other changed dependency follows the original immutable put/conflict
    path; held ids are never read through or reset.
    """
    expected = _request_semantics(kind, candidate)
    retained = journal.get(kind, cohort)
    if retained is None:
        journal.put(kind, cohort, candidate)
        return candidate
    if canonical_json_bytes(_request_semantics(kind, retained)) != canonical_json_bytes(expected):
        journal.put(kind, cohort, candidate)
        raise ValueError("request owner binding changed")
    return retained
