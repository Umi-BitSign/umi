"""Static assignment reuse never replaces fresh journal/conflict checks."""

import asyncio
import shutil
import threading

import pytest

from umi.competition_assignment_reuse import AssignmentVerificationReuse
from umi.protocol import StrictProtocolModel, canonical_json_bytes

from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import harness as harness
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario


def unexpected_replay(*args, **kwargs):
    raise AssertionError("unchanged retained assignment was reverified")


async def test_inbox_static_reuse_keeps_private_copies(relay, monkeypatch):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    expected = canonical_json_bytes(box.assignment(r.slot))
    monkeypatch.setattr(box, "_load", unexpected_replay)
    changed = box.assignment(r.slot)
    object.__setattr__(changed.certificate, "signatures", ())
    assert canonical_json_bytes(box.assignment(r.slot)) == expected


@pytest.mark.parametrize("kind", ["intent", "certificate", "receipt"])
async def test_inbox_changed_retained_bytes_cannot_borrow_proof(relay, kind):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    box.assignment(r.slot)
    with box.journal.transaction() as db:
        db.execute("UPDATE records SET body=? WHERE kind=? AND id=?", (b"{}", kind, r.slot))
    with pytest.raises(ValueError):
        box.assignment(r.slot)


@pytest.mark.parametrize("kind", ["intent", "certificate", "receipt"])
async def test_inbox_removed_record_cannot_borrow_proof(relay, kind):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    box.assignment(r.slot)
    with box.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, r.slot))
    with pytest.raises((ValueError, FileNotFoundError)):
        box.assignment(r.slot)


async def test_inbox_conflict_hold_is_fresh_even_after_cache_hit(relay):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    box.assignment(r.slot)
    with box.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (r.slot,))
    with pytest.raises(ValueError, match="conflict held"):
        box.assignment(r.slot)


async def test_inbox_changed_recipient_cannot_borrow_proof(relay):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    box.assignment(r.slot)
    other = next(who for who in r.h.order.evaluators if who != box.config.signer)
    box.config = box.config.model_copy(update={"signer": other})
    with pytest.raises(ValueError, match="another evaluator"):
        box.assignment(r.slot)


async def test_inbox_new_database_materialization_requires_verification(relay, monkeypatch):
    r = relay
    await r.worker().poll_once()
    box = r.inbox(r.h.order.evaluators[0])
    expected = box.assignment(r.slot)
    replacement = box.journal.path.with_suffix(".copy")
    shutil.copyfile(box.journal.path, replacement)
    replacement.chmod(0o600)
    replacement.replace(box.journal.path)
    original = box._load
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(box, "_load", counted)
    assert box.assignment(r.slot) == expected
    assert calls == [1]


async def test_execution_reuses_one_validated_assignment_pair(execution, monkeypatch):
    e = execution
    journal = e.journal()
    journal.retain(e.assignment, e.r.h.source, e.r.h.block)
    expected = canonical_json_bytes(journal.assignment(e.r.slot))
    monkeypatch.setattr(journal, "validate_assignment", unexpected_replay)
    changed = journal.assignment(e.r.slot)
    object.__setattr__(changed.certificate, "signatures", ())
    assert canonical_json_bytes(journal.assignment(e.r.slot)) == expected
    assert journal.evidence(e.r.slot) is None
    with journal.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (e.r.slot,))
    with pytest.raises(ValueError, match="conflict held"):
        journal.evidence(e.r.slot)


async def test_execution_changed_retained_assignment_is_not_reused(execution):
    e = execution
    journal = e.journal()
    journal.retain(e.assignment, e.r.h.source, e.r.h.block)
    journal.assignment(e.r.slot)
    with journal.journal.transaction() as db:
        db.execute("UPDATE records SET body=? WHERE kind='assignment' AND id=?", (b"{}", e.r.slot))
    with pytest.raises(ValueError):
        journal.assignment(e.r.slot)


async def test_execution_static_validation_releases_journal_for_other_reads(execution, monkeypatch):
    e = execution
    journal = e.journal()
    journal.retain(e.assignment, e.r.h.source, e.r.h.block)
    entered, release = threading.Event(), threading.Event()
    validate = journal.validate_assignment

    def held(value):
        entered.set()
        assert release.wait(30), "fixture validation was not released"
        return validate(value)

    monkeypatch.setattr(journal, "validate_assignment", held)
    first = asyncio.create_task(asyncio.to_thread(journal.assignment, e.r.slot))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 20)
        second = asyncio.create_task(asyncio.to_thread(journal.journal.get, "assignment", e.r.slot))
        done, _ = await asyncio.wait((second,), timeout=5)
        assert second in done, "static proof validation held the shared journal lock"
        assert canonical_json_bytes(second.result()) == canonical_json_bytes(e.assignment)
    finally:
        release.set()
        await first
        if second is not None:
            await second


async def test_supplied_execution_assignment_reuses_only_static_proofs(execution, monkeypatch):
    from umi import competition_cohort_execution_journal as module

    journal = execution.journal()
    expected = journal.validate_assignment(execution.assignment)
    monkeypatch.setattr(module, "verify_recovery_quorum", unexpected_replay)
    saved = journal.validate_assignment(execution.assignment)
    assert saved == expected and saved is not expected
    object.__setattr__(saved, "cases", ())
    assert journal.validate_assignment(execution.assignment) == expected
    # A static result cannot stand in for a fresh retained record/conflict check.
    with pytest.raises(FileNotFoundError):
        journal.assignment(execution.r.slot)


async def test_supplied_execution_assignment_changed_signature_is_rejected(execution):
    journal = execution.journal()
    journal.validate_assignment(execution.assignment)
    changed = execution.assignment.model_copy(
        update={
            "certificate": execution.assignment.certificate.model_copy(update={"signatures": ()})
        }
    )
    with pytest.raises(ValueError):
        journal.validate_assignment(changed)
    assert journal.validate_assignment(execution.assignment) == execution.job


async def test_supplied_execution_assignment_changed_recipient_is_rejected(execution):
    journal = execution.journal()
    journal.validate_assignment(execution.assignment)
    other = next(who for who in execution.r.h.order.evaluators if who != journal.config.signer)
    journal.config = journal.config.model_copy(update={"signer": other})
    with pytest.raises(ValueError, match="another evaluator"):
        journal.validate_assignment(execution.assignment)


@pytest.mark.parametrize("changed_context", ["policy", "materialization", "process"])
async def test_supplied_execution_assignment_context_changes_reverify(
    execution, monkeypatch, changed_context
):
    from umi import competition_assignment_reuse as reuse
    from umi import competition_cohort_execution_journal as module

    journal = execution.journal()
    journal.validate_assignment(execution.assignment)
    if changed_context == "policy":
        journal.policy = journal.policy.model_copy(update={"evaluation_runtime_sha256": "f" * 64})
    elif changed_context == "materialization":
        replacement = journal.journal.path.with_suffix(".copy")
        shutil.copyfile(journal.journal.path, replacement)
        replacement.chmod(0o600)
        replacement.replace(journal.journal.path)
    else:
        owner = journal._supplied_assignment_reuse._pid
        monkeypatch.setattr(reuse.os, "getpid", lambda: owner + 1)
    monkeypatch.setattr(module, "verify_recovery_quorum", unexpected_replay)
    with pytest.raises(AssertionError, match="reverified"):
        journal.validate_assignment(execution.assignment)


def test_assignment_reuse_capacity_and_caller_isolation():
    cache = AssignmentVerificationReuse(maximum_bytes=32, maximum_entries=1)
    value = {"answer": "one"}
    cache.remember("a", (1,), value)
    value["answer"] = "changed"
    first = cache.lookup("a", (1,))
    assert first == {"answer": "one"}
    first["answer"] = "changed again"
    assert cache.lookup("a", (1,)) == {"answer": "one"}
    cache.remember("b", (2,), {"answer": "two"})
    assert cache.lookup("a", (1,)) is None
    assert cache.lookup("b", (2,)) == {"answer": "two"}
    cache.remember("b", (3,), {"answer": "x" * 64})
    assert cache.lookup("b", (2,)) is None
    assert cache.lookup("b", (3,)) is None


def test_assignment_reuse_rejects_other_process(monkeypatch):
    import umi.competition_assignment_reuse as reuse

    cache = AssignmentVerificationReuse()
    cache.remember("a", (1,), {"answer": "one"})
    monkeypatch.setattr(reuse.os, "getpid", lambda: cache._pid + 1)
    assert cache.lookup("a", (1,)) is None
    cache.remember("b", (2,), {"answer": "two"})
    assert cache.lookup("b", (2,)) is None


def test_assignment_pair_capacity_uses_complete_protocol_objects():
    class Item(StrictProtocolModel):
        name: str

    pair = (Item(name="assignment"), Item(name="job"))
    size = len(canonical_json_bytes([item.model_dump(mode="json") for item in pair]))
    cache = AssignmentVerificationReuse(maximum_bytes=size)
    cache.remember("pair", (1,), pair)
    saved = cache.lookup("pair", (1,))
    assert saved == pair
    assert saved[0] is not pair[0]
    object.__setattr__(saved[0], "name", "changed")
    assert cache.lookup("pair", (1,)) == pair
    undersized = AssignmentVerificationReuse(maximum_bytes=size - 1)
    undersized.remember("pair", (1,), pair)
    assert undersized.lookup("pair", (1,)) is None
