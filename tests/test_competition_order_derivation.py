from __future__ import annotations

import pytest

from umi import competition_evaluator as evaluator
from umi import competition_work_plans as plans
from umi.competition_evaluator_capacity import order_binding
from umi.competition_execution import execution_key
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_work_plans import policy as policy
from .test_competition_work_plans import runtime as runtime
from .test_competition_work_plans import setup as _work
from .test_competition_work_plans import sign_publications
from .test_open_competition import wallet

work = _work


def _orders(work):
    publications = sign_publications(work, plans.endpoint_proposals(**work.options))
    return plans.evaluation_order_proposals(
        plan=work.plan,
        policy=work.policy,
        legacy=work.item.legacy_policy,
        publications=publications,
    )


def _derive(work, order, **changes):
    options = dict(
        plan=work.plan,
        submission=order.submission,
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
        endpoint_publication=(None if order.publication is None else order.publication.publication),
        legacy_policy=work.item.legacy_policy,
    )
    options.update(changes)
    return evaluator.order_from_unsigned_inputs(**options)


def test_unsigned_inputs_match_signed_order_bytes_and_each_evaluator_job(work, monkeypatch):
    orders = _orders(work)

    def never_sign(*args, **kwargs):
        pytest.fail("unsigned derivation must not create signatures")

    monkeypatch.setattr(evaluator, "sign_object", never_sign)
    for order in orders:
        expected = order.model_dump(mode="json", by_alias=True)
        if order.publication is not None:
            expected["publication"] = order.publication.publication.model_dump(
                mode="json", by_alias=True
            )
        keys = set()
        for hotkey in work.plan.evaluators:
            fields, job = _derive(work, order, evaluator_hotkey=hotkey)
            signed_job = evaluator.order_job(order, hotkey, work.policy, work.item.legacy_policy)
            assert canonical_json_bytes(job) == canonical_json_bytes(signed_job)
            assert canonical_json_bytes(fields) == canonical_json_bytes(expected)
            assert digest(fields) == order_binding(order)
            assert fields["no_weight"] is True
            keys.add(execution_key(job))
        assert len(keys) == len(work.plan.evaluators)


def test_unsigned_binding_excludes_only_publication_signatures(work):
    order = next(o for o in _orders(work) if o.publication is not None)
    changed = order.model_copy(
        update={
            "publication": order.publication.model_copy(
                update={"signatures": tuple(reversed(order.publication.signatures))}
            )
        }
    )
    evaluator.validate_order_body(changed, work.policy, work.item.legacy_policy)
    assert digest(changed) != digest(order)
    fields, job = _derive(work, order)
    other_fields, other_job = _derive(work, changed)
    assert fields == other_fields
    assert job == other_job
    assert order_binding(order) == order_binding(changed) == digest(fields)


def test_signed_order_still_requires_real_publication_signatures(work):
    order = next(o for o in _orders(work) if o.publication is not None)
    signatures = order.publication.signatures
    bad = order.model_copy(
        update={
            "publication": order.publication.model_copy(
                update={
                    "signatures": (
                        signatures[0].model_copy(update={"signature": "0x" + "00" * 64}),
                        *signatures[1:],
                    )
                }
            )
        }
    )
    with pytest.raises(ValueError):
        evaluator.validate_order_body(bad, work.policy, work.item.legacy_policy)
    assert _derive(work, bad) == _derive(work, order)


@pytest.mark.parametrize(
    "fault", ["submission", "evaluator", "cases", "roster", "missing", "legacy"]
)
def test_unsigned_inputs_reject_changes_outside_frozen_plan(work, fault):
    order = next(o for o in _orders(work) if o.publication is not None)
    if fault == "submission":
        changes = dict(submission=order.submission.model_copy(update={"signature": None}))
    elif fault == "evaluator":
        changes = dict(evaluator_hotkey=wallet("Alice").hotkey.ss58_address)
    elif fault == "cases":
        changes = dict(
            plan=work.plan.model_copy(update={"cases": tuple(reversed(work.plan.cases))})
        )
    elif fault == "roster":
        changes = dict(
            plan=work.plan.model_copy(update={"evaluators": tuple(reversed(work.plan.evaluators))})
        )
    elif fault == "missing":
        changes = dict(endpoint_publication=None)
    else:
        changes = dict(legacy_policy=None)
    with pytest.raises(ValueError):
        _derive(work, order, **changes)


def test_model_job_rejects_endpoint_publication(work):
    orders = _orders(work)
    model = next(o for o in orders if o.publication is None)
    endpoint = next(o for o in orders if o.publication is not None)
    with pytest.raises(ValueError):
        _derive(work, model, endpoint_publication=endpoint.publication.publication)
