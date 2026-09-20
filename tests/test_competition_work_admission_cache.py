from __future__ import annotations

import pytest

from umi import competition_work_signing as signing
from umi.open_competition import digest

from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as setup
from .test_competition_work_signing import work as work


@pytest.mark.asyncio
async def test_one_completed_derivation_serves_all_new_endorsements(setup, monkeypatch):
    signer = setup.signers[0]
    derive = signer.admission._derive
    calls = []

    def counted(*args):
        calls.append(1)
        return derive(*args)

    monkeypatch.setattr(signer.admission, "_derive", counted)
    await signer.endorse(setup.authorization)
    before = signer.admission.verify(setup.work.plan)
    await signer.endorse(setup.model)
    await signer.endorse(setup.endpoint)
    assert calls == [1]
    assert signer.admission.verify(setup.work.plan) == before


@pytest.mark.asyncio
async def test_restart_rederives_before_a_new_endorsement(setup, monkeypatch):
    old, worker = setup.signers[0], setup.workers[0]
    await old.endorse(setup.authorization)
    signer = signing.IndependentWorkSigner(
        worker,
        old.cutoffs,
        minimum_issue_ms=old.minimum_issue_ms,
        legacy=old.legacy,
        transport_provider=old.transport_provider,
    )
    assert signer.admission._completed_derivation is None
    derive = signer.admission._derive
    calls = []

    def counted(*args):
        calls.append(1)
        return derive(*args)

    monkeypatch.setattr(signer.admission, "_derive", counted)
    await signer.endorse(setup.model)
    assert calls == [1]
    assert signer.admission.verify(setup.work.plan) == old.admission.verify(setup.work.plan)


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["plan", "publication", "policy", "legacy", "config", "path"])
async def test_changed_input_cannot_reuse_completed_derivation(setup, monkeypatch, changed):
    signer, worker = setup.signers[0], setup.workers[0]
    await signer.endorse(setup.authorization)
    admission, plan = signer.admission, setup.work.plan
    publications = admission.publications(plan)
    if changed == "plan":
        plan = plan.model_copy(update={"submissions": tuple(reversed(plan.submissions))})
    elif changed == "publication":
        publications = (publications[0].model_copy(update={"cases": ()}),)
    elif changed == "policy":
        worker.policy = worker.policy.model_copy(update={"maximum_output_bytes": 4097})
    elif changed == "legacy":
        # Nested mutable content must invalidate even when the model is the
        # same object, not just when a caller replaces a top-level reference.
        worker.legacy.implementation_pins.finality_verifier.release_sha256_by_target[
            "x86_64-unknown-linux-gnu"
        ] = "ab" * 32
    elif changed == "config":
        worker.config = worker.config.model_copy(update={"maximum_orders": 1000})
    else:
        monkeypatch.setattr(admission.signing, "path", admission.signing.path.parent / "moved")

    def must_rederive(*args):
        raise RuntimeError("derivation was not reused")

    monkeypatch.setattr(admission, "_derive", must_rederive)
    with pytest.raises(RuntimeError, match="was not reused"):
        admission.reserve(plan, publications, setup.model.body)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["manifest", "complete", "native"])
async def test_warm_derivation_still_rechecks_durable_records(setup, monkeypatch, kind):
    signer, worker = setup.signers[0], setup.workers[0]
    await signer.endorse(setup.authorization)
    admission, plan = signer.admission, setup.work.plan
    publications = admission.publications(plan)
    original = admission.journal.get

    def altered(record, key, **kwargs):
        value = original(record, key, **kwargs)
        if record == kind and key == digest(plan):
            return {**value, "changed": True}
        return value

    if kind == "native":
        monkeypatch.setattr(worker.executions, "reservation", lambda key: None)
    else:
        monkeypatch.setattr(admission.journal, "get", altered)
    with pytest.raises(ValueError, match=r"manifest changed|receipt changed|native reservation"):
        admission.reserve(plan, publications, setup.model.body)
    assert signer.journal.get("intent", signing.statement_slot(setup.model)) is None


@pytest.mark.asyncio
async def test_warm_derivation_rejects_a_different_order(setup):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    plan = setup.work.plan
    # Change a real bound field; unknown model_copy keys are deliberately not
    # used because they are absent from canonical model serialization.
    wrong = setup.model.body.model_copy(update={"evaluators": tuple(reversed(plan.evaluators))})
    assert wrong != setup.model.body
    with pytest.raises(ValueError, match="order differs"):
        signer.admission.reserve(plan, signer.admission.publications(plan), wrong)


@pytest.mark.asyncio
async def test_missing_completion_forces_derivation_despite_warm_cache(setup, monkeypatch):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    admission, plan = signer.admission, setup.work.plan
    publications = admission.publications(plan)
    get = admission.journal.get

    def missing(kind, key, **kwargs):
        if kind == "complete":
            return None
        return get(kind, key, **kwargs)

    def must_rederive(*args):
        raise RuntimeError("derivation was not reused")

    monkeypatch.setattr(admission.journal, "get", missing)
    monkeypatch.setattr(admission, "_derive", must_rederive)
    with pytest.raises(RuntimeError, match="was not reused"):
        admission.reserve(plan, publications, setup.model.body)
