"""Existing source reads must not initialize a second reward-promotion history."""

import hashlib
import sqlite3

import pytest

from umi import competition_store
from umi.competition_store import CompetitionStore

from .test_competition_cohort_baseline_history import apply
from .test_competition_cohort_baseline_history import (
    base_policy as base_policy,
)
from .test_competition_cohort_baseline_history import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_baseline_history import (
    model_case as model_case,
)
from .test_competition_cohort_baseline_history import (
    model_parent_context as model_parent_context,
)
from .test_competition_cohort_baseline_history import (
    policy as policy,
)
from .test_competition_cohort_baseline_history import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_baseline_history import (
    recovery as recovery,
)
from .test_competition_cohort_baseline_history import (
    retained_case as retained_case,
)
from .test_competition_cohort_baseline_history import (
    review_case as review_case,
)
from .test_competition_cohort_baseline_history import (
    runtime as runtime,
)

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("model_case", [("best", 2)], indirect=True),
]


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("model_parent_context", [None, "89" * 32], indirect=True)
def test_existing_reader_follows_authenticated_head_and_preserves_originals(
    retained_case, monkeypatch
):
    source, review, original, _ = retained_case

    def no_payload(*args, **kwargs):
        raise AssertionError("reading preserved history cannot verify model payloads")

    monkeypatch.setattr(competition_store, "verify_preserved_bundle", no_payload)
    reader = CompetitionStore(source.directory, source.policy, read_only_existing=True)
    assert reader.baseline() == original
    parent = reader.reviewed_promotion_head(review.candidate.round_sha256, maximum_bytes=1_000_000)
    apply(source, review)
    before = fingerprint(source.path)
    for _ in range(2):
        reopened = CompetitionStore(source.directory, source.policy, read_only_existing=True)
        assert (
            reopened.reviewed_promotion_head(
                review.candidate.round_sha256, maximum_bytes=1_000_000
            ).model_sha256
            == review.candidate.model_sha256
        )
        assert (
            reopened.reviewed_promotion_at(
                review.candidate.round_sha256,
                parent.promotion_sha256,
                maximum_bytes=1_000_000,
            )
            == parent
        )
        with pytest.raises(ValueError, match="reader cannot mutate"), reopened._transaction():
            pytest.fail("read-only source issued a mutation transaction")
        with (
            reopened._connection() as connection,
            pytest.raises(sqlite3.OperationalError, match="readonly"),
        ):
            connection.execute("DELETE FROM promotions")
    assert fingerprint(source.path) == before
    # Existing reader objects select current committed history, not a cached head.
    assert reader.baseline()["schema"] == "umi-model-baseline/4"


def test_empty_history_refuses_without_creating_a_baseline(retained_case, tmp_path):
    source, review, _, _ = retained_case
    empty = CompetitionStore(tmp_path / "empty-reward-history", source.policy)
    before = fingerprint(empty.path)
    reader = CompetitionStore(empty.directory, source.policy, read_only_existing=True)
    with pytest.raises(ValueError, match="promotion history is missing"):
        reader.reviewed_promotion_head(review.candidate.round_sha256, maximum_bytes=1_000_000)
    assert reader.baseline() is None and fingerprint(empty.path) == before


def test_existing_reader_refuses_missing_or_migrating_state(retained_case, tmp_path):
    source, _, _, _ = retained_case
    missing = tmp_path / "missing"
    with pytest.raises(ValueError, match="requires retained"):
        CompetitionStore(missing, source.policy, read_only_existing=True)
    assert not missing.exists()
    before = fingerprint(source.path)
    with pytest.raises(ValueError, match="cannot migrate"):
        CompetitionStore(
            source.directory, source.policy, read_only_existing=True, migrate_writer_generation=True
        )
    with pytest.raises(ValueError, match="different store role"):
        CompetitionStore(
            source.directory, source.policy, role="evaluator_review", read_only_existing=True
        )
    assert fingerprint(source.path) == before


def test_existing_reader_refuses_damaged_fence_without_repair(retained_case):
    source, _, _, _ = retained_case
    with source._connection() as connection:
        connection.execute("DROP TRIGGER writer_2_insert_metadata")
    before = fingerprint(source.path)
    with pytest.raises(ValueError, match="writer fence changed"):
        CompetitionStore(source.directory, source.policy, read_only_existing=True)
    assert fingerprint(source.path) == before
