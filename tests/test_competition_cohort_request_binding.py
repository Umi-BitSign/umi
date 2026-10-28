"""Immutable request owners survive only unrelated deadline configuration drift."""

from copy import deepcopy

import pytest

from umi.competition_cohort_request_binding import retain_request_binding
from umi.competition_round_journal import RoundJournal
from umi.protocol import canonical_json_bytes


@pytest.fixture(params=["request_phase_binding", "request_delivery_binding"])
def binding(request, tmp_path):
    intake = {"directory": str(tmp_path / "intake"), "cohorts": [{"authority": "original"}]}
    if request.param == "request_phase_binding":
        value = {"intake": intake, "roster": "original", "catalogs": ["original"]}
    else:
        value = {
            "sources": {"intake": intake, "objects_directory": str(tmp_path / "objects")},
            "history_directory": str(tmp_path / "history"),
        }
    return request.param, value


def intake_of(kind, value):
    return value["intake"] if kind == "request_phase_binding" else value["sources"]["intake"]


@pytest.mark.parametrize("legacy_deadline", [False, True])
def test_native_legacy_record_and_bytes_survive_changed_deadline(
    binding, tmp_path, legacy_deadline
):
    kind, original = binding
    if legacy_deadline:
        intake_of(kind, original)["admission_deadlines"] = [{"cohort": "old", "close": 100}]
    journal = RoundJournal(tmp_path / "owner", {"owner": "unchanged"})
    journal.put(kind, "cohort", original)
    raw = journal.get_raw(kind, "cohort")
    candidate = deepcopy(original)
    intake_of(kind, candidate)["admission_deadlines"] = [{"cohort": "future", "close": 200}]
    for _ in range(2):
        reopened = RoundJournal(journal.root, {"owner": "unchanged"})
        assert retain_request_binding(reopened, kind, "cohort", candidate) == original
        assert reopened.get_raw(kind, "cohort") == raw


def test_new_native_record_preserves_older_writer_bytes_and_deadline_compatibility(
    binding, tmp_path
):
    kind, expected = binding
    candidate = deepcopy(expected)
    intake_of(kind, candidate)["admission_deadlines"] = [{"cohort": "future"}]
    journal = RoundJournal(tmp_path / "owner", {"owner": "unchanged"})
    assert retain_request_binding(journal, kind, "cohort", candidate) == candidate
    original = canonical_json_bytes(candidate)
    assert journal.get_raw(kind, "cohort") == original
    # The pre-upgrade writer can retry exactly the same configured binding.
    journal.put(kind, "cohort", candidate)
    # After a deadline selection change, the compatibility reader retains the
    # same original record rather than replacing it with a normalized schema.
    assert retain_request_binding(journal, kind, "cohort", expected) == candidate
    assert journal.get_raw(kind, "cohort") == original


@pytest.mark.parametrize("dependency", ["authority", "directory", "other"])
def test_changed_semantic_dependency_retains_native_conflict(binding, tmp_path, dependency):
    kind, original = binding
    journal = RoundJournal(tmp_path / "owner", {"owner": "unchanged"})
    journal.put(kind, "cohort", original)
    candidate = deepcopy(original)
    if dependency == "authority":
        intake_of(kind, candidate)["cohorts"][0]["authority"] = "changed"
    elif dependency == "directory":
        intake_of(kind, candidate)["directory"] = str(tmp_path / "other")
    else:
        candidate["unexpected_dependency"] = "changed"
    with pytest.raises(ValueError, match="conflict retained"):
        retain_request_binding(journal, kind, "cohort", candidate)
    with pytest.raises(ValueError, match="conflict held"):
        retain_request_binding(journal, kind, "cohort", original)


def test_cohort_hold_from_other_kind_cannot_be_read_through(binding, tmp_path):
    kind, candidate = binding
    journal = RoundJournal(tmp_path / "owner", {"owner": "unchanged"})
    journal.put("another_kind", "cohort", {"value": 1})
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put("another_kind", "cohort", {"value": 2})
    with pytest.raises(ValueError, match="conflict held"):
        retain_request_binding(journal, kind, "cohort", candidate)
