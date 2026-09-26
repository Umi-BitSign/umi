"""Native registration/Axon collection under retained recoverable authority.

The runtime codec, RPC, finality and DNS boundaries are synthetic. No translation
request is delivered and these checks do not establish installed host readiness.
"""

import asyncio
import ipaddress
import json
import sqlite3
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_executor import CohortExecutionAuthority
from umi.competition_cohort_origin import CohortEndpointFinalityProvider, CohortEndpointOrigin
from umi.competition_cohort_origin_scope import CohortEndpointOriginScope
from umi.competition_origin import FinalizedEndpointProvider
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import _HEIGHT, _hash
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import harness as harness
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_order_signer import source_for


@pytest.fixture
def scenario(receipt_scenario, tmp_path, runtime):
    return setup_scenario(receipt_scenario, tmp_path, runtime, mode="endpoint_incumbent")


@pytest.fixture
def endpoint(execution, chain):
    e, c = execution, chain
    assert e.r.h.batch["policy"] == c.policy
    sub = e.assignment.certificate.order.submission.submission
    key = ("SubtensorModule", "Axons", (78, sub.hotkey))
    c.rpc.values[key] = {
        "block": _HEIGHT - 5,
        "version": 1,
        "ip": int(ipaddress.ip_address("8.8.8.8")),
        "port": 443,
        "ip_type": 4,
        "protocol": 0,
        "placeholder1": 0,
        "placeholder2": 0,
    }
    p = SimpleNamespace(e=e, c=c, key=key, answers=["8.8.8.8"], resolutions=[])

    async def resolve(host, port):
        p.resolutions.append((host, port))
        return p.answers

    p.config = c.config.model_copy(update={"state_directory": c.config.state_directory + "-origin"})

    def provider(**kw):
        return CohortEndpointFinalityProvider(
            p.config.model_copy(update=kw),
            c.policy,
            finality=c.finality,
            proofs=c.proofs,
            now_ms=lambda: c.clock.now,
            resolver=resolve,
        )

    def service(**kw):
        authority = CohortExecutionAuthority(e.journal(), c.provider, e.box.history)
        return CohortEndpointOrigin(authority, provider(**kw))

    p.provider, p.service = provider, service
    p.collect = lambda: service().collect(e.assignment)
    return p


def rows(p):
    with sqlite3.connect(p.provider()._path) as db:
        return db.execute("SELECT evidence FROM origins ORDER BY block").fetchall()


async def test_late_origin_retains_original_assignment_and_replays_after_restart(endpoint):
    p = endpoint
    before = canonical_json_bytes(p.e.assignment)
    capture = await p.collect()
    sub = p.e.assignment.certificate.order.submission.submission
    assert capture.block > sub.valid_through_block
    assert capture.block > p.c.policy.valid_through_block
    evidence = json.loads(capture.evidence)
    assert evidence["schema"] == "umi-cohort-endpoint-origin-evidence/1"
    saved = p.e.journal().journal.get("endpoint_origin_scope", evidence["recovery_scope_sha256"])
    scope = CohortEndpointOriginScope.model_validate_json(canonical_json_bytes(saved))
    assert scope.assignment == p.e.assignment and scope.source == p.e.r.h.source
    assert canonical_json_bytes(scope.assignment) == before
    assert capture.submission_sha256 == digest(sub)
    assert capture.origin == "https://example.com:443"
    assert capture.connection_origin == "https://8.8.8.8:443"
    assert len(evidence["storage_batches"]) == 2
    assert not evidence["chain_submission_authorized"]
    assert await p.collect() == capture
    assert rows(p) == [(capture.evidence,)]
    assert not any(method.startswith("author_") for method, _ in p.c.rpc.calls)
    # The legacy entry point retains its finite policy and submission rules.
    with pytest.raises(ValueError, match="not current"):
        await p.provider().collect_origin(p.e.assignment.certificate.order.submission)


async def test_repeated_ten_hour_gaps_recover_without_renewing_original_authority(endpoint):
    p = endpoint
    original = p.e.assignment
    for index, advance in enumerate((0, 3000, 6000, 10**6)):
        p.c.finality.ref = replace(
            p.c.finality.ref, block_number=_HEIGHT + advance, block_hash=_hash(index + 10)
        )
        capture = await p.collect()
        assert capture.block == _HEIGHT + advance
        assert p.e.journal().assignment(p.e.r.slot) == original
    assert len(rows(p)) == 4


@pytest.mark.parametrize("damage", ["receipt", "vote", "participant", "cohort_pin", "evaluator"])
async def test_invalid_authority_cannot_reach_origin_rpc(endpoint, damage):
    p = endpoint
    a = p.e.assignment
    if damage == "receipt":
        a = a.model_copy(
            update={
                "delivery": a.delivery.model_copy(
                    update={
                        "signature": a.delivery.signature.model_copy(
                            update={"signature": "0x" + "00" * 64}
                        )
                    }
                )
            }
        )
    elif damage == "vote":
        a = a.model_copy(
            update={
                "certificate": a.certificate.model_copy(
                    update={"signatures": a.certificate.signatures[:1]}
                )
            }
        )
    elif damage == "participant":
        a = a.model_copy(
            update={
                "participant": a.participant.model_copy(
                    update={
                        "admission_snapshot": a.participant.admission_snapshot.model_copy(
                            update={"block": 211}
                        )
                    }
                )
            }
        )
    elif damage == "cohort_pin":
        factory = p.e.journal
        p.e.journal = lambda: factory(
            cohorts=(p.e.cfg.cohorts[0].model_copy(update={"authority_sha256": "ee" * 32}),)
        )
    else:
        # A genuine receipt addressed to another assigned evaluator is still not ours.
        other = p.e.r.h.order.evaluators[1]
        a = a.model_copy(update={"delivery": await p.e.r.inbox(other).lookup(p.e.r.slot)})
    with pytest.raises(ValueError):
        await p.service().collect(a)
    assert not p.resolutions
    assert not any("Axons" in str(call) for call in p.c.rpc.calls)


async def test_closure_is_retained_and_cannot_be_rolled_back_on_restart(endpoint):
    p = endpoint
    await p.collect()
    old = p.e.r.h.source
    p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
    with pytest.raises(ValueError, match="open request"):
        await p.collect()
    p.e.r.h.source = old
    with pytest.raises(ValueError, match="rolled back"):
        await p.collect()
    assert len(rows(p)) == 1


async def test_closure_during_collection_retains_proof_but_does_not_return_it(
    endpoint, monkeypatch
):
    p = endpoint
    original = FinalizedEndpointProvider._save_origin

    def close(self, *args, **kw):
        result = original(self, *args, **kw)
        p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
        return result

    monkeypatch.setattr(FinalizedEndpointProvider, "_save_origin", close)
    with pytest.raises(ValueError, match="open request"):
        await p.collect()
    assert len(rows(p)) == 1


@pytest.mark.parametrize("damage", ["axon", "deregistered", "inverse", "dns", "proof", "stale"])
async def test_native_current_origin_checks_still_apply(endpoint, damage):
    p = endpoint
    sub = p.e.assignment.certificate.order.submission.submission
    if damage == "axon":
        p.c.rpc.values[p.key]["protocol"] = 1
    elif damage == "deregistered":
        del p.c.rpc.values[("SubtensorModule", "Uids", (78, sub.hotkey))]
    elif damage == "inverse":
        uid = p.c.rpc.values[("SubtensorModule", "Uids", (78, sub.hotkey))]
        p.c.rpc.values[("SubtensorModule", "Keys", (78, uid))] = "0x" + "ff" * 32
    elif damage == "dns":
        p.answers = ["8.8.8.8", "127.0.0.1"]
    elif damage == "proof":
        p.c.rpc.bad_proof = True
    else:
        p.c.clock.now += 120001
    with pytest.raises((ValueError, RuntimeError)):
        await p.collect()
    assert rows(p) == []


@pytest.mark.parametrize("damage", ["height", "hash"])
async def test_native_origin_highwater_survives_restart(endpoint, damage):
    p = endpoint
    original = await p.collect()
    p.c.finality.ref = replace(
        p.c.finality.ref,
        **({"block_number": _HEIGHT - 1} if damage == "height" else {"block_hash": _hash(88)}),
    )
    with pytest.raises(ValueError):
        await p.collect()
    assert rows(p) == [(original.evidence,)]


async def test_capacity_is_retryable_without_replacing_assignment(endpoint):
    p = endpoint
    with pytest.raises(ValueError, match="cache is full"):
        await p.service(maximum_cache_bytes=1024).collect(p.e.assignment)
    original = p.e.journal().assignment(p.e.r.slot)
    assert rows(p) == []
    assert await p.collect()
    assert p.e.journal().assignment(p.e.r.slot) == original


async def test_slow_authority_review_has_no_collection_timeout(endpoint, monkeypatch):
    p = endpoint
    from umi import competition_origin as module

    real = module.review_endpoint_origin_scope
    entered, release = threading.Event(), threading.Event()

    def slow(*args):
        entered.set()
        assert release.wait(5)
        return real(*args)

    monkeypatch.setattr(module, "review_endpoint_origin_scope", slow)
    task = asyncio.create_task(p.service(collection_timeout_seconds=1).collect(p.e.assignment))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        await asyncio.sleep(1.1)
        assert not task.done()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.result().origin == "https://example.com:443"


async def test_failed_final_authority_read_recovers_same_proof(endpoint, monkeypatch):
    p = endpoint
    real = p.e.box.history
    calls = 0

    async def fail(cohort):
        nonlocal calls
        calls += 1
        if calls > 2:
            raise OSError("history temporarily unavailable")
        return await real(cohort)

    monkeypatch.setattr(p.e.box, "history", fail)
    with pytest.raises(OSError):
        await p.collect()
    original = rows(p)
    monkeypatch.setattr(p.e.box, "history", real)
    assert (await p.collect()).evidence == original[0][0]
    assert rows(p) == original


async def test_slow_review_refreshes_native_head_without_replaying_authority(endpoint, monkeypatch):
    p = endpoint
    from umi import competition_origin as module

    real = module.review_endpoint_origin_scope
    calls = []

    def slow(*args):
        calls.append(args[-1])
        result = real(*args)
        # Advance both the controlled clock and its native finalized fixture.
        p.c.clock.now += 180000
        p.c.finality.timestamp += 180000
        p.c.rpc.values[("Timestamp", "Now", ())] = p.c.finality.timestamp
        p.c.finality.ref = replace(
            p.c.finality.ref, block_number=_HEIGHT + 15, block_hash=_hash(44)
        )
        return result

    monkeypatch.setattr(module, "review_endpoint_origin_scope", slow)
    assert (await p.collect()).block == _HEIGHT + 15
    assert calls == [_HEIGHT]


@pytest.mark.parametrize("damage", ["authority", "proof", "primary", "freshness"])
async def test_changed_security_configuration_does_not_adopt_origin_cache(endpoint, damage):
    p = endpoint
    capture = await p.collect()
    if damage == "authority":
        change = {
            "finality_pin": p.config.finality_pin.model_copy(
                update={"source_tree_sha256": "ee" * 32}
            )
        }
    elif damage == "proof":
        change = {"proof_binary_sha256": "ee" * 32}
    elif damage == "primary":
        change = {"rpc_url": "wss://another.example"}
    else:
        change = {"maximum_head_age_ms": 60000}
    with pytest.raises(ValueError):
        p.provider(**change)
    assert rows(p) == [(capture.evidence,)]


async def test_corrupt_retained_origin_is_not_overwritten(endpoint):
    p = endpoint
    await p.collect()
    with sqlite3.connect(p.provider()._path) as db:
        db.execute("UPDATE origins SET evidence=?", (b"{}",))
    with pytest.raises(ValueError, match="retained endpoint evidence is corrupt"):
        await p.collect()
    assert rows(p) == [(b"{}",)]


async def test_origin_cache_cannot_silently_adopt_legacy_state(endpoint):
    p = endpoint
    legacy_config = p.config.model_copy(
        update={"state_directory": p.config.state_directory + "-old"}
    )
    legacy = FinalizedEndpointProvider(
        legacy_config,
        p.c.policy,
        finality=p.c.finality,
        proofs=p.c.proofs,
        now_ms=lambda: p.c.clock.now,
    )
    with sqlite3.connect(legacy._path) as db:
        original = db.execute("SELECT * FROM binding").fetchall()
    with pytest.raises(ValueError, match="another chain configuration"):
        CohortEndpointFinalityProvider(
            legacy_config,
            p.c.policy,
            finality=p.c.finality,
            proofs=p.c.proofs,
            now_ms=lambda: p.c.clock.now,
        )
    with sqlite3.connect(legacy._path) as db:
        assert db.execute("SELECT * FROM binding").fetchall() == original


async def test_cancelled_authority_review_drains_before_releasing_assignment_lock(
    endpoint, monkeypatch
):
    p = endpoint
    from umi import competition_origin as module

    real = module.review_endpoint_origin_scope
    entered, release = threading.Event(), threading.Event()

    def slow(*args):
        entered.set()
        assert release.wait(5)
        return real(*args)

    monkeypatch.setattr(module, "review_endpoint_origin_scope", slow)
    task = asyncio.create_task(p.collect())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        with pytest.raises(BlockingIOError), p.e.journal().locked(p.e.r.slot):
            pytest.fail("cancelled local review released its owning lock early")
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled() and rows(p) == []
    assert await p.collect()


@pytest.mark.parametrize("stage", ["proof", "persistence"])
async def test_local_origin_verification_and_persistence_outlive_rpc_timeout(
    endpoint, monkeypatch, stage
):
    p = endpoint
    entered, release = threading.Event(), threading.Event()
    service = p.service(collection_timeout_seconds=1)
    # The assignment authority also uses this proof port. Delay only origin
    # collection so this checks the timeout around the endpoint proof itself.
    in_origin = False
    read = service.provider._read

    async def origin_read(*args):
        nonlocal in_origin
        in_origin = True
        try:
            return await read(*args)
        finally:
            in_origin = False

    monkeypatch.setattr(service.provider, "_read", origin_read)
    target, name = (
        (p.c.verifier, "verify_many")
        if stage == "proof"
        else (FinalizedEndpointProvider, "_save_origin")
    )
    real = getattr(target, name)

    def slow(*args, **kwargs):
        if stage == "persistence" or in_origin:
            entered.set()
            assert release.wait(5)
        return real(*args, **kwargs)

    monkeypatch.setattr(target, name, slow)
    task = asyncio.create_task(service.collect(p.e.assignment))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        await asyncio.sleep(1.1)
        assert not task.done()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.result().origin == "https://example.com:443"
    assert len(rows(p)) == 1


async def test_unavailable_dns_times_out_and_retries_same_assignment(endpoint, monkeypatch):
    p = endpoint
    service = p.service(collection_timeout_seconds=1)

    async def unavailable(*args):
        await asyncio.Event().wait()

    monkeypatch.setattr(service.provider, "_resolver", unavailable)
    with pytest.raises(asyncio.TimeoutError):
        await service.collect(p.e.assignment)
    assert rows(p) == []
    assert await p.collect()
