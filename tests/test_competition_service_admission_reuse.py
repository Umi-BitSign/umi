"""Reuse historical paid admissions without reusing current authority."""

import pytest

from umi import competition_cohort_service_work as work
from umi.competition_assignment_reuse import AssignmentVerificationReuse
from umi.competition_cohort_order_signer import remember_order_history

from .test_competition_cohort_service_queue import admit, capture, inputs, precommit, source_for
from .test_competition_cohort_service_queue import base_policy as base_policy
from .test_competition_cohort_service_queue import harness as harness
from .test_competition_cohort_service_queue import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_queue import policy as policy
from .test_competition_cohort_service_queue import queue_case as queue_case
from .test_competition_cohort_service_queue import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_queue import recovery as recovery
from .test_competition_cohort_service_queue import runtime as runtime
from .test_competition_cohort_service_queue import scenario as scenario


@pytest.fixture(autouse=True)
def cold_reuse(monkeypatch):
    if hasattr(work, "_historical_service_admission_reuse"):
        monkeypatch.setattr(
            work, "_historical_service_admission_reuse", AssignmentVerificationReuse()
        )


@pytest.mark.parametrize("precommitted", [False, True])
@pytest.mark.parametrize("receipt_scenario", ["extensions", "standing"], indirect=True)
def test_unchanged_service_queue_admission_is_not_reverified(queue_case, monkeypatch, precommitted):
    c = precommit(queue_case) if precommitted else queue_case
    if precommitted:
        c.queue.install(
            c.catalog,
            c.round,
            c.h.source,
            capture(),
            expected_tip_sha256=work.history_tip(c.h.source.history),
        )
    expected = admit(c)
    assert c.queue.entries() == (expected,)

    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged historical service admission was reverified")

    monkeypatch.setattr(work, "review_service_catalog", unexpected)
    returned = c.queue.entries()[0]
    assert returned == expected
    object.__setattr__(returned, "ordinal", 999)
    assert c.queue.lookup(inputs(c)[0]) == expected
    assert c.queue.entries() == (expected,)
    assert not expected.service_credit_authorized
    assert not expected.chain_submission_authorized


def test_reused_service_admission_does_not_allow_closed_history(queue_case, monkeypatch):
    c = queue_case
    accepted = admit(c)
    assert c.queue.entries() == (accepted,)
    original = work.review_service_catalog

    def unexpected(*args, **kwargs):
        raise AssertionError("unchanged historical service admission was reverified")

    monkeypatch.setattr(work, "review_service_catalog", unexpected)
    assert c.queue.entries() == (accepted,)
    closed = source_for(c.h.batch, c.h.batch["history"])
    remember_order_history(
        c.queue.journal,
        {c.catalog.catalog.cohort_sha256: c.catalog.catalog.authority_sha256},
        c.h.batch["policy"],
        closed,
        2000,
    )
    # A different nonce is new evidence and must perform native review before
    # the current retained head rejects its old-history admission.
    monkeypatch.setattr(work, "review_service_catalog", original)
    with pytest.raises(ValueError):
        admit(c, nonce=2)
    monkeypatch.setattr(work, "review_service_catalog", unexpected)
    assert c.queue.entries() == (accepted,)


@pytest.mark.parametrize("changed", ["value", "catalog", "round", "history", "policy", "previous"])
def test_changed_service_admission_inputs_require_native_review(queue_case, monkeypatch, changed):
    c = queue_case
    value = admit(c)
    signed, round_, source, policy = c.catalog, c.round, c.h.source, c.queue.policy
    previous = None
    work.review_service_admission(value, signed, round_, source, policy, previous=previous)
    if changed == "value":
        value = value.model_copy(
            update={"observation": value.observation.model_copy(update={"block": 401})}
        )
    elif changed == "catalog":
        signed = signed.model_copy(update={"signatures": signed.signatures[:1]})
    elif changed == "round":
        round_ = round_.model_copy(update={"policy_sha256": "ff" * 32})
    elif changed == "history":
        source = source.model_copy(
            update={"history": source.history.model_copy(update={"genesis_signatures": ()})}
        )
    elif changed == "policy":
        policy = policy.model_copy(update={"minimum_score_bps": policy.minimum_score_bps + 1})
    else:
        previous = value
    original = work.review_service_catalog
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(work, "review_service_catalog", counted)
    for _ in range(2):
        with pytest.raises(ValueError):
            work.review_service_admission(value, signed, round_, source, policy, previous=previous)
    assert calls == [True, True]


def test_child_process_cannot_inherit_service_admission_receipt(queue_case, monkeypatch):
    c = queue_case
    expected = admit(c)
    monkeypatch.setattr(work._historical_service_admission_reuse, "_pid", -1)
    original = work.review_service_catalog
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(work, "review_service_catalog", counted)
    assert c.queue.entries() == (expected,)
    assert calls == [True]
