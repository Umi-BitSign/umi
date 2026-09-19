"""Operation-local reuse must not bypass signed bytes or retained bindings."""

from __future__ import annotations

import pytest

from umi import competition_work_queue as queue_module
from umi import competition_work_signing as signing_module
from umi.competition_work_plans import endpoint_proposals
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_work_queue_batch import batch as batch
from .test_competition_work_queue_batch import chain_config as chain_config
from .test_competition_work_queue_batch import policy as policy
from .test_competition_work_queue_batch import runtime as runtime
from .test_competition_work_queue_batch import setup as setup
from .test_competition_work_queue_batch import signing as signing
from .test_competition_work_queue_batch import work as work


def retained(batch):
    queue = batch.queue
    queue.journal.put(
        "work-plan", batch.work.plan.cutoff.publication.round.suite_sha256, batch.work.plan
    )
    return queue._retain_many(batch.statements)


def test_queue_preserves_its_validation_export():
    assert queue_module.validate_statement is signing_module.validate_statement


@pytest.fixture
def validations(monkeypatch):
    original = signing_module.validate_work_plan
    calls = []

    def counted(plan, policy):
        calls.append(canonical_json_bytes(plan))
        return original(plan, policy)

    monkeypatch.setattr(signing_module, "validate_work_plan", counted)
    return calls


@pytest.mark.parametrize("operation", ["retain", "discover", "repair", "retained"])
def test_plan_is_authenticated_once_per_operation(batch, validations, operation):
    slots = retained(batch)
    validations.clear()
    queue = batch.queue

    def run():
        if operation == "retain":
            return queue._retain_many(batch.statements)
        if operation == "repair":
            return queue._repair_endpoints(slots)
        if operation == "retained":
            return queue._retained_endpoints(batch.work.plan)
        cursor, statements = queue._pending(
            batch.work.signers[0].hotkey.ss58_address, 0, batch.work.options["issuance"].height
        )
        assert cursor == 2
        assert {digest(s) for s in statements} == {digest(s) for s in batch.statements}

    run()
    assert len(validations) == 1
    run()
    assert len(validations) == 2  # No cache survives a batch or discovery page.


def test_invalid_later_body_rolls_back_batch(batch):
    first, second = batch.statements
    second = second.model_copy(
        update={"body": second.body.model_copy(update={"policy_sha256": "ff" * 32})}
    )
    with pytest.raises(ValueError, match="binding mismatch"):
        batch.queue._retain_many((first, second))
    assert batch.queue.journal.keys("intent") == []
    with batch.queue.journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM work_index").fetchone()[0] == 0


def validator(batch):
    return signing_module._StatementValidator(batch.work.policy, batch.work.item.legacy_policy)


def test_standalone_validation_does_not_reuse_authentication(batch, validations):
    first = batch.statements[0]
    for _ in range(2):
        result = signing_module.validate_statement(
            first, batch.work.policy, batch.work.item.legacy_policy
        )
        assert canonical_json_bytes(result) == canonical_json_bytes(first)
    assert len(validations) == 2


def test_cache_keeps_only_the_last_exact_plan(batch, validations):
    first = batch.statements[0]
    plan = first.plan.model_copy(
        update={
            "cases": (
                first.plan.cases[0].model_copy(update={"case_id": "fe" * 32}),
                *first.plan.cases[1:],
            )
        }
    )
    options = {**batch.work.options, "plan": plan}
    other = first.model_copy(update={"plan": plan, "body": endpoint_proposals(**options)[0]})
    cached = validator(batch)
    for statement in (first, first, other, other, first):
        assert canonical_json_bytes(cached.validate(statement)) == canonical_json_bytes(statement)
    assert validations == [canonical_json_bytes(s.plan) for s in (first, other, first)]
    # This is a valid publication, but its same-sized case set belongs to the
    # other plan. Reusing first's plan authentication must still reject it.
    with pytest.raises(ValueError, match="differs from its frozen plan"):
        cached.validate(first.model_copy(update={"body": other.body}))
    assert len(validations) == 3


def test_changed_signature_is_verified_even_after_valid_plan(batch, validations):
    first = batch.statements[0]
    cached = validator(batch)
    cached.validate(first)
    raw = first.model_dump(mode="json", by_alias=True)
    raw["plan"]["cutoff"]["signatures"][0]["signature"] = "0x" + "00" * 64
    with pytest.raises(ValueError, match="signature"):
        cached.validate(raw)
    assert len(validations) == 2
    assert canonical_json_bytes(cached.validate(first)) == canonical_json_bytes(first)
    assert len(validations) == 2  # Failed authentication did not replace the cache.


def test_returned_statement_cannot_mutate_cached_plan(batch):
    first = batch.statements[0]
    cached = validator(batch)
    result = cached.validate(first)
    assert result is not first
    object.__setattr__(result.plan, "cases", ())
    object.__setattr__(result.plan.cutoff, "signatures", ())
    again = cached.validate(first)
    assert canonical_json_bytes(again) == canonical_json_bytes(first)


def test_batch_policy_is_an_owned_snapshot(batch):
    policy = batch.work.policy.model_copy(deep=True)
    cached = signing_module._StatementValidator(policy, batch.work.item.legacy_policy)
    first = batch.statements[0]
    cached.validate(first)
    object.__setattr__(policy, "contribution_terms_sha256", "ff" * 32)
    assert canonical_json_bytes(cached.validate(first)) == canonical_json_bytes(first)
    with pytest.raises(ValueError):
        signing_module._StatementValidator(policy, batch.work.item.legacy_policy).validate(first)


@pytest.mark.parametrize("fault", ["intent", "plan", "hold", "slot"])
def test_cached_plan_does_not_hide_retained_corruption(batch, fault):
    first, second = retained(batch)
    cached = validator(batch)
    batch.queue._statement(first, validator=cached)
    suite = batch.work.plan.cutoff.publication.round.suite_sha256
    with batch.queue.journal.transaction() as db:
        if fault == "hold":
            db.execute("INSERT INTO holds(id) VALUES (?)", (second,))
        else:
            kind, key = ("work-plan", suite) if fault == "plan" else ("intent", second)
            value = batch.statements[0] if fault == "slot" else {}
            db.execute(
                "UPDATE records SET body=? WHERE kind=? AND id=?",
                (canonical_json_bytes(value), kind, key),
            )
    with pytest.raises(ValueError):
        batch.queue._statement(second, validator=cached)


def test_invalid_cached_body_is_not_returned_by_discovery(batch):
    slots = retained(batch)
    second = batch.statements[1]
    invalid = second.model_copy(
        update={"body": second.body.model_copy(update={"policy_sha256": "ff" * 32})}
    )
    with batch.queue.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='intent' AND id=?",
            (canonical_json_bytes(invalid), slots[1]),
        )
    cursor, statements = batch.queue._pending(
        batch.work.signers[0].hotkey.ss58_address, 0, batch.work.options["issuance"].height
    )
    assert cursor == 2
    assert tuple(digest(s) for s in statements) == (digest(batch.statements[0]),)


def test_cached_plan_does_not_hide_index_corruption(batch):
    slots = retained(batch)
    with batch.queue.journal.transaction() as db:
        db.execute("UPDATE work_index SET plan=? WHERE slot=?", ("ff" * 32, slots[1]))
    with pytest.raises(ValueError, match="index binding mismatch"):
        batch.queue._pending(
            batch.work.signers[0].hotkey.ss58_address, 0, batch.work.options["issuance"].height
        )
