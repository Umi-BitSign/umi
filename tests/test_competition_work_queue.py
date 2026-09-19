from __future__ import annotations

from pathlib import Path

import pytest

from umi import competition_work_queue as queue_module
from umi.competition_evaluator import SignedEvaluationOrder, _read, validate_order
from umi.competition_work_signing import statement_slot
from umi.open_competition import digest, sign_object

from .test_competition_evaluator import Provider
from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as signing_fixture
from .test_competition_work_signing import work as work
from .test_open_competition import wallet

signing = signing_fixture


@pytest.fixture
def setup(signing, tmp_path):
    provider = Provider(signing.work.options["issuance"].height)
    arguments = dict(
        root=tmp_path / "queue",
        policy=signing.work.policy,
        provider=provider,
        order_directory=tmp_path / "orders",
        publication_directory=tmp_path / "publications",
        minimum_issue_ms=1000,
        legacy=signing.work.item.legacy_policy,
        transport_provider=signing.signers[0].transport_provider,
    )
    signing.queue = queue_module.WorkQueue(**arguments)
    signing.arguments = arguments
    signing.provider = provider
    return signing


async def prepare(setup):
    await setup.queue.prepare(setup.work.plan, videos=setup.work.options["videos"])


async def collect(setup):
    for signer in setup.signers:
        cursor, statements = await setup.queue.pending(signer.worker.config.evaluator_hotkey)
        held_model = False
        for statement in statements:
            try:
                vote = await signer.endorse(statement)
            except ValueError as error:
                # The production client continues through a held first model
                # and retries it after processing endpoint authorization.
                if (
                    str(error) != "whole-round admission requires endpoint assignments first"
                    or statement != setup.model
                    or held_model
                ):
                    raise
                held_model = True
                continue
            assert await setup.queue.accept(vote) == digest(statement)
        if held_model:
            assert signer.journal.get("vote", statement_slot(setup.authorization)) is not None
    return cursor


async def endorse_model(setup, signer):
    # Establish the local cohort reservation without giving the queue an
    # authorization vote or publishing an unrelated quorum certificate.
    await signer.endorse(setup.authorization)
    return await signer.endorse(setup.model)


@pytest.mark.asyncio
async def test_both_tracks_reach_signed_delivery_without_manual_assembly(setup):
    await prepare(setup)
    assert not list(Path(setup.arguments["order_directory"]).glob("*.json"))
    # Authorization quorum creates the endpoint order automatically.
    await collect(setup)
    await collect(setup)
    paths = list(Path(setup.arguments["order_directory"]).glob("*.json"))
    assert len(paths) == 2
    orders = [_read(p, SignedEvaluationOrder) for p in paths]
    assert sorted(o.order.submission.submission.track for o in orders) == ["endpoint", "model"]
    for order in orders:
        validate_order(order, setup.work.policy, setup.work.item.legacy_policy)
        assert order.order.no_weight and len(order.signatures) == 2
    assert len(list(Path(setup.arguments["publication_directory"]).glob("*.json"))) == 1
    before = [p.read_bytes() for p in paths]
    setup.queue = queue_module.WorkQueue(**setup.arguments)
    await prepare(setup)
    await collect(setup)
    assert before == [p.read_bytes() for p in paths]


@pytest.mark.asyncio
async def test_delivered_certificates_do_not_collect_extra_heads_on_replay(setup):
    original = setup.provider.collect
    observations = []

    async def observe():
        observations.append(1)
        return await original()

    setup.provider.collect = observe
    await prepare(setup)
    unsigned_collections = len(observations)
    await collect(setup)
    await collect(setup)
    paths = tuple(setup.queue.order_directory.glob("*.json")) + tuple(
        setup.queue.publication_directory.glob("*.json")
    )
    assert len(paths) == 3
    original_bytes = {path: path.read_bytes() for path in paths}
    observations.clear()
    await prepare(setup)
    assert len(observations) <= unsigned_collections
    assert {path: path.read_bytes() for path in paths} == original_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["bytes", "permissions", "symlink"])
async def test_replay_still_verifies_existing_delivery(setup, damage):
    await prepare(setup)
    for signer in setup.signers:
        await setup.queue.accept(await endorse_model(setup, signer))
    path = setup.queue.order_directory / (digest(setup.model.body) + ".json")
    if damage == "bytes":
        # A valid signed envelope can still differ from the immutable outbox.
        value = _read(path, SignedEvaluationOrder)
        path.write_bytes(
            queue_module.canonical_json_bytes(
                value.model_copy(update={"signatures": tuple(reversed(value.signatures))})
            )
        )
    elif damage == "permissions":
        path.chmod(0o644)
    else:
        other = path.with_suffix(".retained")
        path.rename(other)
        path.symlink_to(other)
    with pytest.raises(ValueError, match=r"different bytes|owned private|non-symlink"):
        await prepare(setup)


@pytest.mark.asyncio
async def test_one_signature_is_insufficient_and_retry_does_not_add_a_group(setup):
    await prepare(setup)
    vote = await endorse_model(setup, setup.signers[0])
    assert await setup.queue.accept(vote) == digest(setup.model)
    assert await setup.queue.accept(vote) == digest(setup.model)
    assert not list(Path(setup.arguments["order_directory"]).glob("*.json"))


@pytest.mark.asyncio
async def test_unsigned_or_unrelated_work_vote_is_rejected(setup):
    await prepare(setup)
    vote = await endorse_model(setup, setup.signers[0])
    with pytest.raises(ValueError, match="unknown work"):
        await setup.queue.accept(vote.model_copy(update={"statement_sha256": "ff" * 32}))
    with pytest.raises(ValueError, match="signer or statement"):
        await setup.queue.accept(
            vote.model_copy(update={"signature": sign_object(setup.model.body, wallet("Eve"))})
        )
    assert not list(Path(setup.arguments["order_directory"]).glob("*.json"))


@pytest.mark.asyncio
async def test_late_first_arrival_cannot_complete_quorum(setup):
    await prepare(setup)
    first, second = [await endorse_model(setup, s) for s in setup.signers]
    await setup.queue.accept(first)
    setup.provider.block = setup.model.body.round.evaluation_close_block
    with pytest.raises(ValueError, match="outside its original window"):
        await setup.queue.accept(second)
    assert await setup.queue.accept(first) == digest(setup.model)
    assert not list(Path(setup.arguments["order_directory"]).glob("*.json"))


@pytest.mark.asyncio
async def test_wallclock_deadline_prevents_endpoint_quorum_without_block_progress(setup):
    await prepare(setup)
    votes = [await s.endorse(setup.authorization) for s in setup.signers]
    await setup.queue.accept(votes[0])
    setup.clock.now = queue_module.issue_close_ms(
        setup.authorization, setup.work.item.legacy_policy
    )
    with pytest.raises(ValueError, match="outside its original window"):
        await setup.queue.accept(votes[1])
    assert not list(Path(setup.arguments["publication_directory"]).glob("*.json"))
    _, statements = await setup.queue.pending(setup.signers[1].worker.config.evaluator_hotkey)
    assert [s.body.submission.submission.track for s in statements] == ["model"]


@pytest.mark.asyncio
async def test_expired_authorization_is_retained_and_never_retimed(setup):
    await prepare(setup)
    slot = statement_slot(setup.authorization)
    original = setup.queue.journal.get("intent", slot)
    setup.clock.now += 60 * 60 * 1000
    await prepare(setup)
    assert setup.queue.journal.get("intent", slot) == original
    assert len(setup.signers[0].transport_provider.calls) == 2


@pytest.mark.asyncio
async def test_first_preparation_after_execution_close_refuses_all_work(setup):
    setup.provider.block = setup.model.body.round.evaluation_close_block
    with pytest.raises(ValueError, match="outside its execution window"):
        await prepare(setup)
    assert setup.queue.journal.keys("intent") == []


@pytest.mark.asyncio
async def test_endpoint_transport_failure_does_not_discard_model_work(setup):
    setup.queue.transport_provider = None
    with pytest.raises(ValueError, match="owned transport finality"):
        await prepare(setup)
    _, statements = await setup.queue.pending(setup.signers[0].worker.config.evaluator_hotkey)
    assert statements == (setup.model,)


@pytest.mark.asyncio
async def test_crash_after_intent_recovers_index_without_new_issuance(setup):
    await prepare(setup)
    with setup.queue.journal.transaction() as db:
        db.execute("DELETE FROM work_index")
    setup.queue = queue_module.WorkQueue(**setup.arguments)
    await prepare(setup)
    _, statements = await setup.queue.pending(setup.signers[0].worker.config.evaluator_hotkey)
    assert set(digest(s) for s in statements) == {digest(setup.model), digest(setup.authorization)}
    assert len(setup.signers[0].transport_provider.calls) == 2


@pytest.mark.asyncio
async def test_crash_after_certificate_repairs_exact_delivery_on_retry(setup, monkeypatch):
    await prepare(setup)
    votes = [await endorse_model(setup, s) for s in setup.signers]
    await setup.queue.accept(votes[0])
    original_publish = queue_module._publish

    def crash(*_):
        raise OSError("injected failure after durable certificate")

    monkeypatch.setattr(queue_module, "_publish", crash)
    with pytest.raises(OSError, match="injected"):
        await setup.queue.accept(votes[1])
    certificate = setup.queue.journal.get("certificate", statement_slot(setup.model))
    assert certificate is not None
    monkeypatch.setattr(queue_module, "_publish", original_publish)
    setup.queue = queue_module.WorkQueue(**setup.arguments)
    await setup.queue.accept(votes[1])
    path = Path(setup.arguments["order_directory"]) / (digest(setup.model.body) + ".json")
    assert _read(path, SignedEvaluationOrder).model_dump(mode="json", by_alias=True) == certificate


@pytest.mark.asyncio
async def test_expired_crash_repair_does_not_publish_a_late_job(setup, monkeypatch):
    await prepare(setup)
    votes = [await endorse_model(setup, s) for s in setup.signers]
    await setup.queue.accept(votes[0])
    original = queue_module._publish

    def crash(*_):
        raise OSError("injected delivery failure")

    monkeypatch.setattr(queue_module, "_publish", crash)
    with pytest.raises(OSError):
        await setup.queue.accept(votes[1])
    monkeypatch.setattr(queue_module, "_publish", original)
    setup.provider.block = setup.model.body.round.evaluation_close_block
    await setup.queue.accept(votes[1])
    assert setup.queue.journal.get("certificate", statement_slot(setup.model)) is not None
    assert not list(Path(setup.arguments["order_directory"]).glob("*.json"))


@pytest.mark.asyncio
async def test_conflicting_plan_blocks_prior_work_and_survives_restart(setup):
    await prepare(setup)
    with pytest.raises(ValueError, match="conflict retained"):
        setup.queue.journal.put("work-plan", setup.model.body.round.suite_sha256, {"changed": True})
    setup.queue = queue_module.WorkQueue(**setup.arguments)
    vote = await endorse_model(setup, setup.signers[0])
    with pytest.raises(ValueError, match="conflict held"):
        await setup.queue.accept(vote)
    _, statements = await setup.queue.pending(setup.signers[0].worker.config.evaluator_hotkey)
    assert statements == ()


@pytest.mark.asyncio
async def test_index_corruption_is_not_trusted_for_discovery(setup):
    await prepare(setup)
    with setup.queue.journal.transaction() as db:
        db.execute("UPDATE work_index SET closes=closes+1")
    with pytest.raises(ValueError, match="index binding mismatch"):
        await setup.queue.pending(setup.signers[0].worker.config.evaluator_hotkey)


@pytest.mark.asyncio
async def test_discovery_checks_identity_cursor_and_own_head(setup):
    await prepare(setup)
    hotkey = setup.signers[0].worker.config.evaluator_hotkey
    for after in (-1, True, 2**53):
        with pytest.raises(ValueError, match="cursor"):
            await setup.queue.pending(hotkey, after=after)
    with pytest.raises(ValueError, match="policy evaluator"):
        await setup.queue.pending(wallet("Eve").hotkey.ss58_address)
    cursor, statements = await setup.queue.pending(hotkey)
    assert cursor == 2 and len(statements) == 2
    assert await setup.queue.pending(hotkey, after=cursor) == (cursor, ())
    setup.provider.block -= 1
    with pytest.raises(ValueError, match="regressed"):
        await setup.queue.pending(hotkey)
