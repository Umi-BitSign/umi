from __future__ import annotations

import sqlite3

import pytest

from umi import competition_evaluator as worker
from umi.competition_execution import execution_key
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import agree, completed, execute
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_evaluator import model_setup as model_setup
from .test_competition_evaluator import policy as policy
from .test_competition_evaluator import runtime as runtime
from .test_competition_evaluator import setup as setup


def slot_of(s, d):
    return execution_key(worker.order_job(s.order.order, d.config.evaluator_hotkey, s.policy))


def receipt_of(s, d):
    return d.journal.get(
        slot_of(s, d), "independent_observation", worker.IndependentEvidenceObservation
    )


@pytest.mark.asyncio
async def test_first_local_retention_precedes_publication_and_survives_restart(setup):
    s = setup
    await execute(s.drivers)
    await agree(s)
    for d in s.drivers:
        receipt = receipt_of(s, d)
        assert receipt.observed.block == 150
        assert not receipt.chain_submission_authorized
        final = completed(d)[0]
        assert (
            worker.validate_evidence_observation(
                receipt,
                s.order.order,
                final,
                d.config.evaluator_hotkey,
                cutoff_block=160,
            )
            == receipt
        )
        d.provider.block = 190
        fresh = worker.ContinuousEvaluator(d.config, d.policy, d.wallet, d.provider)
        assert (await fresh.poll_once())["complete"] == 1
        assert receipt_of(s, fresh) == receipt
        await fresh.aclose()


@pytest.mark.asyncio
async def test_crash_without_receipt_uses_restart_observation_not_old_execution_time(setup):
    s = setup
    await execute(s.drivers)
    await agree(s)
    d = s.drivers[0]
    final = completed(d)[0]
    with sqlite3.connect(d.journal.path) as db:
        db.execute("DELETE FROM artifacts WHERE kind='independent_observation'")
    d.provider.block = 170
    assert (await d.poll_once())["complete"] == 1
    receipt = receipt_of(s, d)
    assert receipt.observed.block == 170
    assert completed(d)[0] == final
    with pytest.raises(ValueError, match="by cutoff"):
        worker.validate_evidence_observation(
            receipt,
            s.order.order,
            final,
            d.config.evaluator_hotkey,
            cutoff_block=160,
        )


@pytest.mark.asyncio
async def test_receipt_storage_failure_does_not_publish_unobserved_evidence(setup, monkeypatch):
    s = setup
    await execute(s.drivers)
    d = s.drivers[0]
    original = d.journal.put

    def fail(slot, kind, value):
        if kind == "independent_observation":
            raise OSError("receipt write failed")
        return original(slot, kind, value)

    monkeypatch.setattr(d.journal, "put", fail)
    await agree(s)
    assert not completed(d)
    assert receipt_of(s, d) is None
    assert d.journal.get(slot_of(s, d), "independent", worker.IndependentEvaluationEvidence)
    monkeypatch.setattr(d.journal, "put", original)
    d.provider.block = 170
    assert (await d.poll_once())["complete"] == 1
    assert receipt_of(s, d).observed.block == 170


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["evidence_sha256", "policy_sha256", "order_sha256", "submission_sha256"]
)
async def test_changed_retained_receipt_cannot_be_rebound(setup, field):
    s = setup
    await execute(s.drivers)
    await agree(s)
    d = s.drivers[0]
    receipt = receipt_of(s, d).model_copy(update={field: "0" * 64})
    with sqlite3.connect(d.journal.path) as db:
        db.execute(
            "UPDATE artifacts SET body=? WHERE kind='independent_observation'",
            (canonical_json_bytes(receipt),),
        )
    assert (await d.poll_once())["held"] == 1


@pytest.mark.asyncio
async def test_wrong_local_evaluator_is_rejected(setup):
    s = setup
    await execute(s.drivers)
    await agree(s)
    first, second = s.drivers
    with pytest.raises(ValueError, match="binding mismatch"):
        worker.validate_evidence_observation(
            receipt_of(s, first),
            s.order.order,
            completed(first)[0],
            second.config.evaluator_hotkey,
        )
