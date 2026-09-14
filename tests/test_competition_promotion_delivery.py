from __future__ import annotations

import pytest

from umi.competition_promotion_delivery import (
    ReviewedPromotion,
    apply_reviewed_promotion,
    retain_delivery,
    validate_delivery,
)
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_rounds import RoundJournal, RoundQuery
from umi.open_competition import digest

from .test_competition_publication import _independent
from .test_competition_review_history import observe
from .test_competition_review_history import policy as policy
from .test_competition_review_history import scenario as scenario
from .test_competition_review_history import setup as review_fixture
from .test_competition_rounds import OwnedProvider
from .test_open_competition import wallet
from .test_promotion_agreement import agreed_review, attest

history_setup = review_fixture


@pytest.fixture
def setup(history_setup):
    s = history_setup
    observe(s)
    s.review = agreed_review(s)
    s.delivery = ReviewedPromotion(
        schema="umi-reviewed-promotion-delivery/1",
        review=s.review,
        round=s.round,
        submission=s.model,
    )
    s.independent = _independent(s.policy, s.model, s.round, s.suite, s.evaluation)
    s.reviews.record_independent_evaluation(
        signed=s.model,
        evidence=s.independent,
        round_=s.round,
        suite=s.suite,
        observed_block=150,
    )
    return s


async def apply(s, provider=None, delivery=None):
    return await apply_reviewed_promotion(
        s.reviews,
        provider or OwnedProvider(152),
        delivery or s.delivery,
        suite=s.suite,
        archive=s.archive,
    )


@pytest.mark.asyncio
async def test_actual_promotion_then_restart_late_retry_preserves_receipt(setup):
    s = setup
    result = await apply(s)
    assert result["sequence"] == 1
    assert result["contributor_hotkey"] == s.model.submission.hotkey
    s.reviews = EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    reversed_review = s.delivery.model_copy(
        update={
            "review": s.review.model_copy(
                update={"signatures": tuple(reversed(s.review.signatures))}
            )
        }
    )
    assert await apply(s, OwnedProvider(500), reversed_review) == result
    with s.reviews._connection() as c:
        assert c.execute("SELECT observed_block FROM promotion_receipts").fetchall() == [(152,)]


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing", "oversized", "identity", "late"])
async def test_delivery_cannot_replace_local_independent_evidence(setup, damage):
    s = setup
    with s.reviews._transaction() as c:
        if damage == "missing":
            c.execute("DELETE FROM independent_evaluation_evidence")
        elif damage == "oversized":
            c.execute("UPDATE independent_evaluation_evidence SET body=zeroblob(16777217)")
        elif damage == "identity":
            c.execute("UPDATE independent_evaluation_evidence SET digest=?", ("f1" * 32,))
        else:
            c.execute("UPDATE independent_evaluation_evidence SET first_observed_block=156")
    with pytest.raises(ValueError, match="independent evidence"):
        await apply(s)
    assert s.reviews.baseline()["sequence"] == 0


@pytest.mark.asyncio
async def test_elapsed_owned_window_cannot_promote(setup):
    class Advancing(OwnedProvider):
        async def collect(self):
            result = await super().collect()
            self.block += 5
            return result

    s = setup
    with pytest.raises(ValueError, match="window elapsed"):
        await apply(s, Advancing(152))
    assert s.reviews.baseline()["sequence"] == 0


@pytest.mark.asyncio
async def test_first_delivery_after_cutoff_cannot_backdate(setup):
    with pytest.raises(ValueError, match="outside its evidence window"):
        await apply(setup, OwnedProvider(156))


@pytest.mark.asyncio
async def test_changed_approved_decision_cannot_replace_accepted_promotion(setup):
    s = setup
    first = await apply(s)
    changed = s.delivery.model_copy(
        update={
            "review": attest(s.review.review.model_copy(update={"rights_review_sha256": "f5" * 32}))
        }
    )
    with pytest.raises(ValueError, match="changes an already accepted"):
        await apply(s, delivery=changed)
    assert s.reviews.baseline() == first


def test_verified_decisions_have_durable_holds_but_signature_order_is_irrelevant(setup, tmp_path):
    s = setup
    root = tmp_path / "delivery"
    journal = RoundJournal(root, {"policy": digest(s.policy)})
    retain_delivery(journal, s.delivery, s.policy)
    reversed_review = s.delivery.model_copy(
        update={
            "review": s.review.model_copy(
                update={"signatures": tuple(reversed(s.review.signatures))}
            )
        }
    )
    retain_delivery(journal, reversed_review, s.policy)
    changed = s.delivery.model_copy(
        update={
            "review": attest(s.review.review.model_copy(update={"rights_review_sha256": "f5" * 32}))
        }
    )
    with pytest.raises(ValueError, match="conflict retained"):
        retain_delivery(journal, changed, s.policy)
    reopened = RoundJournal(root, {"policy": digest(s.policy)})
    with pytest.raises(ValueError, match="conflict held"):
        reopened.get("promotion-certificate", "promotion:1")


def test_unsigned_review_never_reserves_history(setup, tmp_path):
    s = setup
    journal = RoundJournal(tmp_path / "unsigned", {})
    unsigned = s.delivery.model_copy(
        update={"review": s.review.model_copy(update={"signatures": s.review.signatures[:1]})}
    )
    with pytest.raises(ValueError, match="insufficient independent"):
        retain_delivery(journal, unsigned, s.policy)
    assert not journal.keys("promotion-decision")


def test_delivery_has_exact_model_round_and_policy_bindings(setup):
    s = setup
    bad = s.delivery.model_copy(update={"submission": s.endpoint})
    with pytest.raises(ValueError, match="does not bind"):
        validate_delivery(bad, s.policy)


def test_review_cursor_is_part_of_authenticated_round_query(setup):
    q = RoundQuery(
        schema="umi-round-query/1",
        policy_sha256=digest(setup.policy),
        hotkey=wallet("Charlie").hotkey.ss58_address,
        nonce_unix_ns="1",
        after_promotion_sequence=0,
    )
    assert digest(q) != digest(q.model_copy(update={"after_promotion_sequence": 1}))
