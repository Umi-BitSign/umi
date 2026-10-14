"""The inventory reader cannot acquire writable native state or migrate it."""

import sqlite3

import pytest

from umi.competition_cohort_intake import CohortIntake
from umi.open_competition import digest

from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_intake import policy as policy
from .test_competition_cohort_intake import recovery as recovery
from .test_competition_cohort_intake import scenario as scenario


def test_read_only_intake_construction_and_query_leave_native_state_unchanged(intake, scenario):
    before = {p.name: p.read_bytes() for p in intake.directory.iterdir() if p.is_file()}
    reader = CohortIntake(
        intake.config, intake.policy, eligible_tracks=intake.tracks, read_only=True
    )
    assert reader.history(digest(scenario["intake_history"].plan)) == scenario["intake_history"]
    with (
        reader._connection(prefer_history=True) as (db, _),
        pytest.raises(sqlite3.OperationalError, match="readonly"),
    ):
        db.execute("CREATE TABLE forbidden(x)")
    with pytest.raises(ValueError, match="writable"), reader._connection():
        pass
    assert before == {p.name: p.read_bytes() for p in intake.directory.iterdir() if p.is_file()}
    with pytest.raises(ValueError, match="initialize"):
        CohortIntake(intake.config, intake.policy, read_only=True, initialize=True)
