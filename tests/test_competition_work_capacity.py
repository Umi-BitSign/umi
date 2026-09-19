from __future__ import annotations

import json

import pytest

from umi import competition_work_signing as signing
from umi.competition_dispatch_capacity import DispatchTimingBudget, DispatchTimingLimits
from umi.open_competition import digest, identity

from .test_competition_work_plans import two_endpoint_work
from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as setup
from .test_competition_work_signing import work_fixture

source_work = work_fixture


@pytest.fixture
def work(source_work):
    return two_endpoint_work(source_work)


def counts(journal):
    with journal._transaction() as db:
        if db.execute("PRAGMA user_version").fetchone()[0] == 1:
            return 0, 0
        return (
            db.execute("SELECT COUNT(*) FROM reservation_publications").fetchone()[0],
            db.execute("SELECT COUNT(*) FROM reservation_assignments").fetchone()[0],
        )


def signing_probe(setup, monkeypatch):
    calls = []
    original = signing.sign_object

    def sign(body, wallet):
        calls.append(counts(setup.workers[0].dispatch))
        return original(body, wallet)

    monkeypatch.setattr(signing, "sign_object", sign)
    return calls


@pytest.mark.asyncio
async def test_full_two_endpoint_cohort_is_reserved_before_first_signature(setup, monkeypatch):
    calls = signing_probe(setup, monkeypatch)
    vote = await setup.signers[0].endorse(setup.authorization)
    assert calls == [(2, 12)]
    assert vote.statement_sha256 == digest(setup.authorization)
    with setup.workers[0].dispatch._transaction() as db:
        receipt = json.loads(
            db.execute("SELECT document FROM reservation_qualifications").fetchone()[0]
        )
    assert receipt["plan"]["assignment_count"] == 6  # Only this evaluator's timing workload.
    assert receipt["plan"]["publication_count"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", ["assignments", "publications", "bytes", "profile"])
async def test_later_endpoint_capacity_failure_prevents_any_signature(setup, monkeypatch, limit):
    journal = setup.workers[0].dispatch
    if limit == "assignments":
        journal.maximum_assignments = 6  # First endpoint fits; complete cohort does not.
    elif limit == "publications":
        journal.maximum_publications = 1
    elif limit == "bytes":
        journal.maximum_bytes = 1024
    else:
        with journal._transaction() as db:
            db.execute("DELETE FROM metadata WHERE key LIKE 'dispatch_profile:%'")
    calls = signing_probe(setup, monkeypatch)
    with pytest.raises(ValueError):
        await setup.signers[0].endorse(setup.authorization)
    assert calls == []
    assert counts(journal) == (0, 0)
    assert (
        setup.signers[0].journal.get("intent", signing.statement_slot(setup.authorization)) is None
    )


@pytest.mark.asyncio
async def test_full_cohort_timing_failure_prevents_first_signature(setup, monkeypatch):
    worker = setup.workers[0]
    with worker.dispatch._transaction() as db:
        profile = json.loads(
            db.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("dispatch_profile:" + identity(worker.config.evaluator_hotkey),),
            ).fetchone()[0]
        )
    profile["limits"]["request_timeout_seconds"] = 120
    worker.dispatch.configure_dispatch(
        evaluator_hotkey=worker.config.evaluator_hotkey,
        limits=DispatchTimingLimits(**profile["limits"]),
        budget=DispatchTimingBudget(**profile["budget"]),
        publication_directory=profile["publication_directory"],
    )
    calls = signing_probe(setup, monkeypatch)
    with pytest.raises(ValueError, match="cannot fit"):
        await setup.signers[0].endorse(setup.authorization)
    assert calls == []
    assert counts(worker.dispatch) == (0, 0)


@pytest.mark.asyncio
async def test_endpoint_order_cannot_skip_the_full_cohort_gate(setup, monkeypatch):
    setup.workers[0].dispatch.maximum_assignments = 6
    calls = signing_probe(setup, monkeypatch)
    with pytest.raises(ValueError, match="capacity exhausted"):
        await setup.signers[0].endorse(setup.endpoint)
    assert calls == []
    assert counts(setup.workers[0].dispatch) == (0, 0)
