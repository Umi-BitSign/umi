from __future__ import annotations

import json

import pytest

from umi.competition_policy_lineage import clear_lineage_registry
from umi.competition_store import (
    AgreedPromotionReview,
    AttestedPromotionReview,
    CompetitionStore,
    _record_digest,
)
from umi.open_competition import Evaluator, digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from . import test_open_competition
from .test_open_competition import scenario as scenario
from .test_open_competition import snapshot, wallet

base_policy = test_open_competition.policy


@pytest.mark.parametrize("version", [1, 2])
def test_earned_history_uses_its_original_policy_after_runtime_and_quorum_change(scenario, version):
    s = scenario
    original = promote(s, s.store, s.review if version == 1 else agreed_review(s), 150)
    successor = s.policy.model_copy(
        update={
            "sequence": s.policy.sequence + 1,
            "predecessor_sha256": digest(s.policy),
            "evaluation_runtime_sha256": "df" * 32,
            "evaluators": (
                Evaluator(hotkey=wallet("Ferdie").hotkey.ss58_address, control_group="new"),
            ),
            "required_evaluator_groups": 1,
        }
    )
    with s.store._connection() as connection:
        before = {
            table: connection.execute(f"SELECT * FROM {table}").fetchall()
            for table in (
                "promotions",
                "promotion_receipts",
                "evaluation_signatures",
                "submissions",
            )
        }
    clear_lineage_registry()
    reopened = CompetitionStore(s.store.directory, successor, predecessor_policies=(s.policy,))
    assert reopened.baseline() == original
    assert (
        reopened.reviewed_promotion_head(
            digest(s.round), maximum_bytes=1_000_000
        ).contributor_hotkey
        == s.model.submission.hotkey
    )
    with reopened._connection() as connection:
        after = {table: connection.execute(f"SELECT * FROM {table}").fetchall() for table in before}
    assert before == after


@pytest.fixture
def policy(base_policy):
    return base_policy.model_copy(
        update={
            "evaluators": (
                *base_policy.evaluators,
                Evaluator(
                    hotkey=wallet("Eve").hotkey.ss58_address,
                    control_group="e",
                ),
            ),
        }
    )


def agreed_review(s):
    body = AgreedPromotionReview.model_validate(
        {
            **s.review.review.model_dump(mode="json", by_alias=True),
            "schema": "umi-model-promotion-review/2",
            "round_sha256": digest(s.round),
            "submission_sha256": digest(s.model.submission),
            "previous_promotion_sha256": _record_digest(s.store.baseline()),
            "sequence": 1,
        }
    )
    return attest(body)


def attest(body, names=("Charlie", "Dave")):
    return AttestedPromotionReview(
        review=body,
        signatures=tuple(sign_object(body, wallet(n)) for n in names),
    )


def independent_store(s, directory):
    store = CompetitionStore(directory, s.policy)
    store.initialize_baseline(s.baseline, s.archive)
    for sub in (s.model, s.endpoint):
        store.admit(sub, snapshot(), 110)
    store.close_round(s.round, current_block=120)
    return store


def promote(s, store, review, block, evaluation=None):
    return store.promote(
        signed=s.model,
        attested=evaluation or s.evaluation,
        round_=s.round,
        suite=s.suite,
        review=review,
        archive=s.archive,
        snapshot=snapshot(block),
        current_block=block,
    )


def receipt(store):
    with store._connection() as c:
        return c.execute(
            "SELECT observed_block FROM promotion_receipts WHERE sequence=1"
        ).fetchone()


def test_separate_receipt_blocks_and_certificate_sets_agree(scenario, tmp_path):
    s = scenario
    review = agreed_review(s)
    other = independent_store(s, tmp_path / "independent")
    first = promote(s, s.store, review, 150)
    extra = s.evaluation.model_copy(
        update={
            "signatures": (
                *reversed(s.evaluation.signatures),
                sign_object(s.evaluation.result, wallet("Eve")),
            ),
        }
    )
    other.record_evaluation(
        signed=s.model,
        attested=extra,
        round_=s.round,
        suite=s.suite,
        observed_block=152,
    )
    later = promote(s, other, attest(review.review, ("Eve", "Dave", "Charlie")), 153, extra)
    assert first == later
    assert first["schema"] == "umi-model-baseline/2"
    assert "promoted_at_block" not in first
    assert receipt(s.store) == (150,)
    assert receipt(other) == (153,)
    assert CompetitionStore(other.directory, s.policy).baseline() == first
    with other._connection() as c:
        assert c.execute("SELECT value FROM metadata WHERE key='observed_block'").fetchone() == (
            "153",
        )
        assert c.execute("SELECT observed_block FROM evaluation_results").fetchall() == [(152,)]
    # A real earlier local observation is retained; the agreed head never
    # fabricates a receipt at the other operator's block150.
    with pytest.raises(ValueError, match="earlier finalized"):
        promote(s, other, review, 150)


def test_agreed_retry_preserves_first_receipt_and_rejects_changed_decision(scenario):
    s = scenario
    review = agreed_review(s)
    first = promote(s, s.store, review, 150)
    assert promote(s, s.store, attest(review.review, ("Dave", "Charlie")), 154) == first
    assert receipt(s.store) == (150,)
    changed = review.review.model_copy(update={"rights_review_sha256": "df" * 32})
    with pytest.raises(ValueError, match="retry changes"):
        promote(s, s.store, attest(changed), 155)
    assert s.store.baseline() == first


@pytest.mark.parametrize(
    "field,value",
    [
        ("round_sha256", "d1" * 32),
        ("submission_sha256", "d2" * 32),
        ("previous_promotion_sha256", "d3" * 32),
        ("sequence", 2),
        ("evaluation_result_sha256", "d4" * 32),
    ],
)
def test_agreed_review_bindings_fail_closed(scenario, field, value):
    s = scenario
    before = s.store.baseline()
    review = attest(agreed_review(s).review.model_copy(update={field: value}))
    with pytest.raises(ValueError):
        promote(s, s.store, review, 150)
    assert s.store.baseline() == before
    assert receipt(s.store) is None


@pytest.mark.parametrize("mutation", ["missing", "time", "review", "parent"])
def test_restart_requires_actual_receipt_and_matching_certificates(scenario, mutation):
    s = scenario
    review = agreed_review(s)
    promote(s, s.store, review, 153)
    with s.store._transaction() as c:
        if mutation == "missing":
            c.execute("DELETE FROM promotion_receipts WHERE sequence=1")
        elif mutation == "time":
            c.execute("UPDATE promotion_receipts SET observed_block=154 WHERE sequence=1")
        elif mutation == "review":
            from umi.protocol import canonical_json_bytes

            changed = attest(review.review.model_copy(update={"rights_review_sha256": "df" * 32}))
            c.execute(
                "UPDATE promotion_receipts SET review=? WHERE sequence=1",
                (canonical_json_bytes(changed),),
            )
        else:
            c.execute("UPDATE promotions SET digest=? WHERE sequence=0", ("de" * 32,))
    with pytest.raises(ValueError):
        CompetitionStore(s.store.directory, s.policy)
    with pytest.raises(ValueError):
        s.store.reviewed_promotion_head(digest(s.round), maximum_bytes=16 * 1024**2)


def test_reading_agreed_head_bounds_local_receipt(scenario):
    from umi.protocol import canonical_json_bytes

    s = scenario
    record = promote(s, s.store, agreed_review(s), 150)
    maximum = len(canonical_json_bytes(record))
    with pytest.raises(ValueError, match="receipt exceeds its byte bound"):
        s.store.reviewed_promotion_head(digest(s.round), maximum_bytes=maximum)
    head = s.store.reviewed_promotion_head(digest(s.round), maximum_bytes=16 * 1024**2)
    assert head.promotion_sha256 == _record_digest(record)


@pytest.mark.parametrize("legacy_alias", [False, True])
def test_legacy_review_keeps_original_record_shape(scenario, legacy_alias):
    s = scenario
    first = promote(s, s.store, s.review, 150)
    assert first["schema"] == "umi-model-baseline/1"
    assert first["promoted_at_block"] == 150
    assert receipt(s.store) is None
    if legacy_alias:
        for body in (first["evaluation"]["result"], first["review"]["review"]):
            body["schema_"] = body.pop("schema")
        with s.store._transaction() as connection:
            connection.execute(
                "UPDATE promotions SET digest=?,body=? WHERE sequence=1",
                (_record_digest(first), canonical_json_bytes(first)),
            )
    retained = canonical_json_bytes(first)
    reopened = CompetitionStore(s.store.directory, s.policy)
    assert reopened.baseline() == first
    head = reopened.reviewed_promotion_head(digest(s.round), maximum_bytes=16 * 1024**2)
    assert head.promotion_sha256 == _record_digest(first)
    assert head.contributor_hotkey == s.model.submission.hotkey
    with reopened._connection() as connection:
        assert connection.execute("SELECT body FROM promotions WHERE sequence=1").fetchone() == (
            retained,
        )


@pytest.mark.parametrize("read_path", ["head", "reopen"])
@pytest.mark.parametrize(
    "mutation",
    [
        "review_signature",
        "review_binding",
        "missing_review",
        "contributor",
        "submission",
        "parent",
        "kind",
        "version",
        "observation",
    ],
)
def test_legacy_promotion_rehash_does_not_authenticate_corrupted_record(
    scenario, mutation, read_path
):
    s = scenario
    record = promote(s, s.store, s.review, 150)
    if mutation == "review_signature":
        record["review"]["signatures"][0]["signature"] = "0x" + "00" * 64
    elif mutation == "review_binding":
        changed = s.review.review.model_copy(update={"model_sha256": "df" * 32})
        record["review"] = attest(changed).model_dump(mode="json", by_alias=True)
    elif mutation == "missing_review":
        record.pop("review")
    elif mutation == "contributor":
        record["contributor_hotkey"] = wallet("Bob").hotkey.ss58_address
    elif mutation == "submission":
        record["submission_sha256"] = digest(s.endpoint.submission)
    elif mutation == "parent":
        record["previous_promotion_sha256"] = "de" * 32
    elif mutation == "kind":
        record["kind"] = "unreviewed"
    elif mutation == "version":
        record["schema"] = "umi-model-baseline/3"
    else:
        record["promoted_at_block"] = 151
    raw = canonical_json_bytes(record)
    with s.store._transaction() as connection:
        connection.execute(
            "UPDATE promotions SET digest=?,body=?,contributor=? WHERE sequence=1",
            (_record_digest(record), raw, identity(record["contributor_hotkey"])),
        )

    with pytest.raises(ValueError):
        if read_path == "head":
            s.store.reviewed_promotion_head(digest(s.round), maximum_bytes=16 * 1024**2)
        else:
            CompetitionStore(s.store.directory, s.policy)

    # Failure must not normalize, replace, or erase the retained evidence.
    with s.store._connection() as connection:
        assert connection.execute("SELECT body FROM promotions WHERE sequence=1").fetchone() == (
            raw,
        )


@pytest.mark.parametrize("read_path", ["head", "reopen"])
def test_initial_reference_cannot_gain_contributor_by_rehash(scenario, read_path):
    s = scenario
    record = json.loads(canonical_json_bytes(s.store.baseline()))
    record["contributor_hotkey"] = s.model.submission.hotkey
    with s.store._transaction() as connection:
        connection.execute(
            "UPDATE promotions SET digest=?,body=?,contributor=? WHERE sequence=0",
            (
                _record_digest(record),
                canonical_json_bytes(record),
                identity(record["contributor_hotkey"]),
            ),
        )
    with pytest.raises(ValueError):
        if read_path == "head":
            s.store.reviewed_promotion_head(digest(s.round), maximum_bytes=16 * 1024**2)
        else:
            CompetitionStore(s.store.directory, s.policy)
