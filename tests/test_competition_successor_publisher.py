"""Current publication gates with real retained packages and synthetic keys."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from umi.competition_chain import RegistrationCapture
from umi.competition_successor_publication import SuccessorRoundPublicationBuilder
from umi.competition_successor_publisher import CurrentSuccessorRoundPublisher
from umi.competition_worker import CompetitionReplayWorker
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_successor_publication import (
    authority_wallets,
)
from .test_competition_successor_publication import (
    package_case as package_case,
)
from .test_competition_successor_publication import (
    package_limits as package_limits,
)
from .test_competition_successor_publication import (
    policy as policy,
)
from .test_competition_successor_publication import (
    publication_case as publication_case,
)
from .test_competition_successor_publication import (
    release_identity as release_identity,
)
from .test_competition_successor_publication import (
    replay_limits as replay_limits,
)
from .test_competition_successor_publication import (
    successor_case as successor_case,
)
from .test_competition_successor_publication import (
    successor_chain as successor_chain,
)
from .test_competition_successor_publication import (
    successor_release as successor_release,
)
from .test_competition_successor_publication import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_worker import _record_cutoff_conflict
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import snapshot


@pytest.fixture
def guarded(publication_case, package_case, chain_config, worker_capacity, tmp_path):
    case = publication_case
    weights = case.plan.weights.model_copy(
        update={
            "required_finality_verifier_sha256_by_target": {
                **case.plan.weights.required_finality_verifier_sha256_by_target,
                **chain_config.finality_pin.release_sha256_by_target,
            },
            "required_storage_proof_verifier_sha256_by_target": {
                **case.plan.weights.required_storage_proof_verifier_sha256_by_target,
                chain_config.target_triple: chain_config.proof_binary_sha256,
            },
        }
    )
    plan = case.plan.model_copy(
        update={
            "chain": case.plan.chain.model_copy(update={"chain_pin": chain_config.chain_pin}),
            "weights": weights,
        }
    )
    builder = SuccessorRoundPublicationBuilder(tmp_path / "guarded-signing", plan)
    replay = CompetitionReplayWorker(
        tmp_path / "guarded-replay", package_limits=plan.package_limits, capacity=worker_capacity
    )

    class Provider:
        config = chain_config
        policy = package_case.scenario.store.policy
        block = 160
        calls = 0
        hook = None

        async def collect(self):
            self.calls += 1
            if self.hook is not None:
                await self.hook(self.calls)
            snap = snapshot(self.block)
            return RegistrationCapture(
                snap,
                {
                    "schema": "umi-competition-registration-provenance/1",
                    "evidence_class": "verifier_attested_finality",
                    "offline_finality_proof": False,
                    "chain_submission_authorized": False,
                    "snapshot_sha256": digest(snap),
                    "block": snap.block,
                    "block_hash": snap.block_hash,
                    "state_root": "0x" + "aa" * 32,
                    "evidence_sha256": "bb" * 32,
                },
            )

    provider = Provider()
    publisher = CurrentSuccessorRoundPublisher(
        builder, package_case.scenario.store, replay, provider
    )
    return SimpleNamespace(
        builder=builder,
        publisher=publisher,
        replay=replay,
        provider=provider,
        store=package_case.scenario.store,
        package=package_case,
    )


async def publish(case):
    return await case.publisher.build(
        case.package.prepared,
        authorization_wallet=authority_wallets()[0],
        directive_wallets=authority_wallets()[:2],
    )


@pytest.mark.asyncio
async def test_current_publisher_uses_post_replay_head_and_retains_exact_retry(guarded):
    g = guarded

    async def advance(calls):
        if calls == 2:
            g.provider.block = 161

    g.provider.hook = advance
    signed = await publish(g)
    assert signed.intent.authorization.signed_at_block == 161
    assert g.provider.calls >= 6
    first = canonical_json_bytes(signed)
    g.publisher = CurrentSuccessorRoundPublisher(g.builder, g.store, g.replay, g.provider)
    assert canonical_json_bytes(await publish(g)) == first
    g.provider.block = 171
    with pytest.raises(ValueError, match="activation window"):
        await publish(g)
    assert len(g.builder.history()) == 1


@pytest.mark.asyncio
async def test_conflict_arriving_during_owned_head_read_prevents_any_signature(guarded):
    g = guarded

    async def conflict(calls):
        if calls == 2:
            with g.store._connection() as db:
                db.execute(
                    "INSERT INTO round_conflicts VALUES (?,?)",
                    (
                        digest(g.package.scenario.round),
                        161,
                    ),
                )

    g.provider.hook = conflict
    with pytest.raises(ValueError, match="conflicting quorum evidence"):
        await publish(g)
    assert not g.builder.journal.keys("authorization")
    assert not g.builder.journal.keys("intent")


@pytest.mark.asyncio
async def test_new_publication_conflict_prevents_signing(guarded, policy, replay_limits):
    g = guarded

    async def conflict(calls):
        if calls == 2:
            await asyncio.to_thread(
                _record_cutoff_conflict, g.replay, g.package, policy, replay_limits
            )

    g.provider.hook = conflict
    with pytest.raises(ValueError, match="publication journal changed"):
        await publish(g)
    assert not g.builder.journal.keys("authorization")


@pytest.mark.asyncio
async def test_expiry_during_partial_signing_leaves_audit_not_current_publication(guarded):
    g = guarded

    async def expire(calls):
        if calls == 4:
            g.provider.block = 168

    g.provider.hook = expire
    with pytest.raises(ValueError, match="activation window"):
        await publish(g)
    assert g.builder.journal.keys("authorization") == ["2:1"]
    assert not g.builder.journal.keys("directive_signature")
    assert not g.builder.history()


@pytest.mark.asyncio
async def test_cancellation_drains_replay_thread_before_releasing_lock(guarded, monkeypatch):
    g = guarded
    entered, release = threading.Event(), threading.Event()

    def replay(*args, **kwargs):
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("test release timed out")
        return object()

    monkeypatch.setattr(g.replay, "run", replay)
    task = asyncio.create_task(publish(g))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and g.publisher._serial.locked()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not g.publisher._serial.locked()
        assert not g.builder.journal.keys("intent")
    finally:
        release.set()


def test_source_configuration_change_is_not_silently_accepted(guarded):
    g = guarded
    g.provider.config = g.provider.config.model_copy(update={"rpc_url": "wss://another.example"})
    with pytest.raises(ValueError, match=r"conflict|changed"):
        CurrentSuccessorRoundPublisher(g.builder, g.store, g.replay, g.provider)


@pytest.mark.asyncio
async def test_regressed_owned_head_stops_before_authorization(guarded):
    g = guarded

    async def regress(calls):
        if calls == 2:
            g.provider.block = 159

    g.provider.hook = regress
    with pytest.raises(ValueError):
        await publish(g)
    assert not g.builder.journal.keys("authorization")
