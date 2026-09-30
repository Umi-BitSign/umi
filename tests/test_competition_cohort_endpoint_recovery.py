"""Cohort inbox/origin/journal to real miner HTTP response recovery.

Native signature, admission, nonce and SQLite paths are used. Finality/RPC/proof,
DNS, model/video execution and the C5 live dispatch grant remain test boundaries.
"""

import hashlib
from dataclasses import replace

import bittensor as bt
import httpx
import pytest

from umi.auth import HotkeyAuth, RequestAuthenticator
from umi.competition_cohort_endpoint import (
    RecoverableEndpointOrder,
    SignedRecoverableEndpointOrder,
    endpoint_attempt_wire_ids,
    endpoint_obligation_sha256,
)
from umi.competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from umi.config import Limits
from umi.miner import TRANSLATE_PATH, create_app
from umi.miner_resources import SQLiteMinerResourceLedger
from umi.open_competition import digest, identity
from umi.policy import ScoringPolicy, ValidatorRegistryEntry, scoring_policy_hash
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_consumers as consumer_fixtures
from .factories import challenge_request
from .test_competition_cohort_origin import (
    base_policy as base_policy,
)
from .test_competition_cohort_origin import (
    chain as chain,
)
from .test_competition_cohort_origin import (
    chain_config as chain_config,
)
from .test_competition_cohort_origin import (
    endpoint as endpoint,
)
from .test_competition_cohort_origin import (
    execution as execution,
)
from .test_competition_cohort_origin import (
    harness as harness,
)
from .test_competition_cohort_origin import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_origin import (
    policy as policy,
)
from .test_competition_cohort_origin import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_origin import (
    recovery as recovery,
)
from .test_competition_cohort_origin import (
    relay as relay,
)
from .test_competition_cohort_origin import (
    runtime as runtime,
)
from .test_competition_cohort_origin import (
    scenario as scenario,
)
from .test_competition_cohort_recovery import signatures
from .test_competition_dispatch import dispatch_legacy_policy
from .test_miner_transport import CountingFetcher, CountingTranslator
from .test_miner_transport import runtime as miner_runtime
from .test_open_competition import wallet


@pytest.fixture(autouse=True)
def known_video_bytes(monkeypatch):
    original = consumer_fixtures.suite_for

    def suite(policy):
        value = original(policy)
        return value.model_copy(
            update={
                "cases": tuple(
                    case.model_copy(
                        update={
                            "video_sha256": hashlib.sha256(
                                ("case-video-" + case.case_id).encode()
                            ).hexdigest()
                        }
                    )
                    for case in value.cases
                )
            }
        )

    monkeypatch.setattr(consumer_fixtures, "suite_for", suite)


@pytest.fixture
async def recovery_case(endpoint, tmp_path):
    p = endpoint
    job = p.e.job
    p.validator = next(
        wallet(name)
        for name in ("Charlie", "Dave", "Eve", "Ferdie")
        if identity(wallet(name).hotkey.ss58_address) == identity(job.evaluator_hotkey)
    )
    transport = dispatch_legacy_policy()
    registry = sorted(
        [
            ValidatorRegistryEntry(
                validator_hotkey=wallet(name).hotkey.ss58_address,
                administrator_id=f"{index + 100:064x}",
            )
            for index, name in enumerate(("Charlie", "Dave", "Eve", "Ferdie"))
        ],
        key=lambda v: identity(v.validator_hotkey),
    )
    p.transport_policy = ScoringPolicy.model_validate_json(
        canonical_json_bytes(transport.model_copy(update={"validator_registry": registry}))
    )
    p.requests = []
    for case in job.cases:
        request = challenge_request(stratum=case.stratum)
        batch, challenge = endpoint_attempt_wire_ids(job, 1, case.case_id)
        p.requests.append(
            request.model_copy(
                update={
                    "batch_id": batch,
                    "challenge_id": challenge,
                    "scoring_policy_hash": scoring_policy_hash(p.transport_policy),
                    "video": request.video.model_copy(
                        update={
                            "sha256": case.video_sha256,
                            "size_bytes": len(("case-video-" + case.case_id).encode()),
                        }
                    ),
                    "issued_block": 1500,
                    "deadline_block": 1510,
                }
            )
        )
    body = RecoverableEndpointOrder(
        schema="umi-recoverable-endpoint-order/1",
        job=job,
        transport_policy_sha256=scoring_policy_hash(p.transport_policy),
        attempt_number=1,
        requests=tuple(p.requests),
    )
    p.signed = SignedRecoverableEndpointOrder(order=body, signatures=signatures(body))

    class Fetcher(CountingFetcher):
        async def fetch(self, descriptor):
            self.calls += 1
            case = next(c for c in job.cases if c.video_sha256 == descriptor.sha256)
            return ("case-video-" + case.case_id).encode()

    class Model(CountingTranslator):
        fail = False

        async def translate(self, video, request):
            self.calls += 1
            if self.fail:
                raise RuntimeError("fixture inference failure")
            return "hello world"

    p.fetcher, p.model = Fetcher(), Model()
    initial = miner_runtime(
        allowed_wallet=p.validator,
        fetcher=p.fetcher,
        translator=p.model,
        limits=Limits.from_policy(p.transport_policy),
    )
    initial.resource_ledger.close()
    miner_wallet = wallet("Bob")
    assert miner_wallet.hotkey.ss58_address == job.submission.submission.hotkey
    ledger = SQLiteMinerResourceLedger(
        tmp_path / "miner.sqlite",
        miner_hotkey=miner_wallet.hotkey.ss58_address,
        scoring_policy_sha256=scoring_policy_hash(p.transport_policy),
        limits=initial.limits,
        maximum_recovery_assignments=8,
    )
    p.miner = replace(
        initial,
        wallet=miner_wallet,
        hotkey_ss58=miner_wallet.hotkey.ss58_address,
        authenticator=RequestAuthenticator.in_memory(miner_wallet.hotkey.ss58_address),
        scoring_policy_sha256=scoring_policy_hash(p.transport_policy),
        resource_ledger=ledger,
        model_revision=job.submission.submission.model_revision,
    )
    p.http_paths = []
    inner = httpx.ASGITransport(app=create_app(p.miner))

    class Trace(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            p.http_paths.append(request.url.path)
            return await inner.handle_async_request(request)

    p.http = Trace()
    p.consumer = lambda: CohortEndpointResponseRecovery(p.service(), p.validator, transport=p.http)
    p.selection = await p.consumer().prepare(p.e.assignment, p.signed, p.transport_policy)
    p.slot = p.selection.assignment_slot
    p.case_id = job.cases[0].case_id
    yield p
    ledger.close()


async def send_original(p, index=0):
    async with httpx.AsyncClient(transport=p.http, base_url="https://example.com") as client:
        return await client.post(
            TRANSLATE_PATH,
            content=canonical_json_bytes(p.requests[index]),
            auth=HotkeyAuth(p.validator, p.miner.hotkey_ss58),
        )


@pytest.mark.parametrize("failure", [False, True])
async def test_recover_original_after_lost_reply_restart_and_expiry(
    recovery_case, monkeypatch, failure
):
    p = recovery_case
    if failure:
        p.model.fail = True
    original = await send_original(p)
    assert original.status_code == 200, original.text
    # Discard the original client reply: only the miner retains the sealed bytes.
    assert p.consumer().retained(p.slot, p.case_id) is None

    p.miner.resource_ledger.prune_closed_windows(p.requests[0].response_close_round)
    monkeypatch.setattr(bt.timelock, "current_round", lambda: p.requests[0].reveal_round + 12000)
    result = await p.consumer().recover(p.slot, p.case_id)
    assert result.status == "recovered"
    assert bytes.fromhex(result.response.envelope_hex) == original.content
    saved = p.consumer().retained(p.slot, p.case_id)
    assert not saved.original_receipt_timing_proven and not saved.chain_submission_authorized
    assert saved.selection_sha256 == digest(p.selection)
    assert p.fetcher.calls == 1
    assert p.model.calls == 1
    before = len(p.http_paths)
    # Offline reload of retained evidence needs neither fresh origin nor signing.
    p.c.finality.fail = True

    async def unavailable(*args):
        raise OSError("history offline")

    p.e.box.history = unavailable
    again = await p.consumer().recover(p.slot, p.case_id)
    assert again.response == result.response
    assert len(p.http_paths) == before


async def test_missing_response_stays_pending_without_new_miner_work(recovery_case):
    p = recovery_case
    for _ in range(3):
        result = await p.consumer().recover(p.slot, p.case_id)
        assert result.status == "pending" and result.http_status == 404
        assert p.consumer().retained(p.slot, p.case_id) is None
        assert p.consumer().selection(p.slot)[0] == p.selection
    assert p.http_paths == ["/v1/translate/response"] * 3
    assert p.model.calls == p.fetcher.calls == 0


async def test_new_attempt_cannot_replace_unknown_selection(recovery_case):
    p = recovery_case
    requests = []
    for case, request in zip(p.e.job.cases, p.requests, strict=True):
        batch, challenge = endpoint_attempt_wire_ids(p.e.job, 2, case.case_id)
        requests.append(request.model_copy(update={"batch_id": batch, "challenge_id": challenge}))
    body = p.signed.order.model_copy(update={"attempt_number": 2, "requests": tuple(requests)})
    candidate = SignedRecoverableEndpointOrder(order=body, signatures=signatures(body))
    with pytest.raises(ValueError, match="already retained"):
        await p.consumer().prepare(p.e.assignment, candidate, p.transport_policy)
    assert p.consumer().selection(p.slot)[0] == p.selection
    assert not p.http_paths and p.model.calls == 0


async def test_lost_prepare_ack_recovers_same_selection_offline(recovery_case):
    p = recovery_case

    async def unavailable(*args):
        raise OSError("coordinator offline")

    p.e.box.history = unavailable
    assert await p.consumer().prepare(p.e.assignment, p.signed, p.transport_policy) == p.selection
    assert not p.http_paths


@pytest.mark.parametrize("damage", ["signature", "job", "request", "policy", "wallet"])
async def test_changed_scope_cannot_reach_network(recovery_case, damage):
    p = recovery_case
    signed, transport = p.signed, p.transport_policy
    if damage == "signature":
        signed = signed.model_copy(update={"signatures": signed.signatures[:1]})
    elif damage == "job":
        job = signed.order.job.model_copy(
            update={"evaluator_hotkey": wallet("Ferdie").hotkey.ss58_address}
        )
        body = signed.order.model_copy(update={"job": job})
        signed = SignedRecoverableEndpointOrder(order=body, signatures=signatures(body))
    elif damage == "request":
        first = p.requests[0].model_copy(update={"scoring_policy_hash": "ff" * 32})
        body = signed.order.model_copy(update={"requests": (first, *p.requests[1:])})
        signed = SignedRecoverableEndpointOrder(order=body, signatures=signatures(body))
    elif damage == "policy":
        transport = transport.model_copy(
            update={"activation_block": transport.activation_block + 1}
        )
    with pytest.raises(ValueError):
        if damage == "wallet":
            CohortEndpointResponseRecovery(p.service(), wallet("Alice"), transport=p.http)
        else:
            await p.consumer().prepare(p.e.assignment, signed, transport)
    assert not p.http_paths


async def test_unknown_case_is_rejected_without_origin_or_network(recovery_case):
    p = recovery_case
    with pytest.raises(ValueError, match="uniquely assigned"):
        await p.consumer().recover(p.slot, "ff" * 32)
    assert not p.http_paths


async def test_response_is_durable_before_lost_ack_and_cannot_be_replaced(
    recovery_case, monkeypatch
):
    p = recovery_case
    original = await send_original(p)
    consumer = p.consumer()
    put = consumer.journal.journal.put

    def lost(kind, key, value):
        put(kind, key, value)
        if kind == "endpoint_recovered_case":
            raise OSError("acknowledgement lost after commit")

    monkeypatch.setattr(consumer.journal.journal, "put", lost)
    with pytest.raises(OSError, match="acknowledgement"):
        await consumer.recover(p.slot, p.case_id)
    count = len(p.http_paths)
    result = await p.consumer().recover(p.slot, p.case_id)
    assert bytes.fromhex(result.response.envelope_hex) == original.content
    assert len(p.http_paths) == count and p.model.calls == 1


async def test_persistence_failure_can_retry_read_without_repeating_inference(
    recovery_case, monkeypatch
):
    p = recovery_case
    original = await send_original(p)
    consumer = p.consumer()
    put = consumer.journal.journal.put

    def failed(kind, key, value):
        if kind == "endpoint_recovered_case":
            raise OSError("disk full")
        return put(kind, key, value)

    monkeypatch.setattr(consumer.journal.journal, "put", failed)
    with pytest.raises(OSError, match="disk full"):
        await consumer.recover(p.slot, p.case_id)
    assert p.consumer().retained(p.slot, p.case_id) is None
    recovered = await p.consumer().recover(p.slot, p.case_id)
    assert bytes.fromhex(recovered.response.envelope_hex) == original.content
    assert p.model.calls == p.fetcher.calls == 1


async def test_capacity_reservations_and_retry_do_not_accumulate_records(recovery_case):
    p = recovery_case
    with p.e.journal().journal.transaction() as db:
        before = db.execute("SELECT COUNT(*) FROM record_reservations").fetchone()
    await p.consumer().prepare(p.e.assignment, p.signed, p.transport_policy)
    for _ in range(3):
        await p.consumer().recover(p.slot, p.case_id)
    with p.e.journal().journal.transaction() as db:
        after = db.execute("SELECT COUNT(*) FROM record_reservations").fetchone()
    assert before == after
    assert p.consumer().retained(p.slot, p.case_id) is None


async def test_repeated_outages_preserve_selected_response(recovery_case):
    from .test_competition_chain import _hash

    p = recovery_case
    original = await send_original(p)
    original_http = p.http

    async def unavailable(wire):
        raise httpx.ReadError("disconnected after request")

    p.http = httpx.MockTransport(unavailable)
    starting = p.c.finality.ref.block_number
    for index, advance in enumerate((3000, 6000, 10**6)):
        p.c.finality.ref = replace(
            p.c.finality.ref, block_number=starting + advance, block_hash=_hash(index + 20)
        )
        result = await p.consumer().recover(p.slot, p.case_id)
        assert result.status == "pending" and result.response is None
        assert p.consumer().selection(p.slot)[0] == p.selection
    p.http = original_http
    result = await p.consumer().recover(p.slot, p.case_id)
    assert bytes.fromhex(result.response.envelope_hex) == original.content
    assert p.model.calls == p.fetcher.calls == 1


async def test_concurrent_reader_cannot_race_the_retained_response(recovery_case):
    import asyncio

    from umi.private_files import PrivateStateBusyError

    p = recovery_case
    await send_original(p)
    inner = p.http
    started, release = asyncio.Event(), asyncio.Event()

    class Paused(httpx.AsyncBaseTransport):
        async def handle_async_request(self, wire):
            started.set()
            await release.wait()
            return await inner.handle_async_request(wire)

    p.http = Paused()
    running = asyncio.create_task(p.consumer().recover(p.slot, p.case_id))
    await asyncio.wait_for(started.wait(), 5)
    try:
        with pytest.raises(PrivateStateBusyError):
            await p.consumer().recover(p.slot, p.case_id)
    finally:
        release.set()
    assert (await running).status == "recovered"
    assert p.http_paths == ["/v1/translate", "/v1/translate/response"]
    assert p.model.calls == 1


async def test_changed_origin_cannot_receive_capability_body(recovery_case):
    p = recovery_case
    p.answers = ["127.0.0.1"]
    with pytest.raises(ValueError):
        await p.consumer().recover(p.slot, p.case_id)
    assert not p.http_paths


async def test_reloaded_response_signature_is_verified_again(recovery_case, monkeypatch):
    p = recovery_case
    await send_original(p)
    assert (await p.consumer().recover(p.slot, p.case_id)).status == "recovered"
    key = endpoint_obligation_sha256(p.e.job, p.case_id)
    saved = p.consumer().retained(p.slot, p.case_id)
    damaged = saved.model_copy(
        update={"response": saved.response.model_copy(update={"signature": "0x" + "00" * 64})}
    )
    # Inject a corrupt local read after storage checks; the response consumer
    # must still perform its own native signature validation.
    consumer = p.consumer()
    read = consumer.journal.journal.get

    def corrupted(kind, record_key, **kwargs):
        if kind == "endpoint_recovered_case" and record_key == key:
            return damaged.model_dump(mode="json", by_alias=True)
        return read(kind, record_key, **kwargs)

    monkeypatch.setattr(consumer.journal.journal, "get", corrupted)
    with pytest.raises(ValueError):
        await consumer.recover(p.slot, p.case_id)
    assert p.http_paths == ["/v1/translate", "/v1/translate/response"]


async def test_worker_cursor_survives_restart_and_skips_stalled_case(recovery_case):
    from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker

    p = recovery_case
    ordered = sorted(
        (endpoint_obligation_sha256(p.e.job, c.case_id), i, c.case_id)
        for i, c in enumerate(p.e.job.cases)
    )
    for _, index, _ in ordered[1:]:
        assert (await send_original(p, index)).status_code == 200
    reports = []
    for _ in ordered:
        worker = CohortEndpointRecoveryWorker(p.consumer(), batch_size=1)
        reports.append(await worker.poll_once())
    assert reports[0]["pending"] == 1
    assert sum(r["responses_recovered"] for r in reports) == len(ordered) - 1
    assert p.consumer().retained(p.slot, ordered[0][2]) is None
    count = len(p.http_paths)
    # Only the unavailable case is polled after completed cases leave the queue.
    assert (await CohortEndpointRecoveryWorker(p.consumer()).poll_once())["considered"] == 1
    assert len(p.http_paths) == count + 1
    assert p.model.calls == len(ordered) - 1
    assert (await send_original(p, ordered[0][1])).status_code == 200
    assert (await CohortEndpointRecoveryWorker(p.consumer()).poll_once())[
        "responses_recovered"
    ] == 1
    count = len(p.http_paths)
    assert (await CohortEndpointRecoveryWorker(p.consumer()).poll_once())["considered"] == 0
    assert len(p.http_paths) == count


async def test_worker_run_stops_an_inflight_retrieval_without_losing_obligation(recovery_case):
    import asyncio

    from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker

    p = recovery_case
    started, stop = asyncio.Event(), asyncio.Event()
    inner = p.http

    class Offline(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            started.set()
            await asyncio.Event().wait()

    p.http = Offline()
    worker = CohortEndpointRecoveryWorker(p.consumer(), batch_size=1)
    run = asyncio.create_task(worker.run(stop, poll_seconds=0.01))
    await asyncio.wait_for(started.wait(), 5)
    stop.set()
    await asyncio.wait_for(run, 5)
    p.http = inner
    result = await CohortEndpointRecoveryWorker(p.consumer()).poll_once()
    assert result["considered"] == len(p.e.job.cases)
    assert result["responses_recovered"] == 0 and p.model.calls == 0


async def test_worker_retry_reports_are_bounded_and_run_continues(recovery_case, monkeypatch):
    import asyncio

    from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker

    p = recovery_case
    stop = asyncio.Event()
    reports = []
    worker = CohortEndpointRecoveryWorker(p.consumer(), batch_size=1)

    async def failed():
        raise OSError("private path and capability must not be logged")

    monkeypatch.setattr(worker, "poll_once", failed)

    def report(value):
        reports.append(value)
        if len(reports) == 2:
            stop.set()

    await asyncio.wait_for(worker.run(stop, poll_seconds=0.01, report=report), 3)
    assert len(reports) == 2 and reports[0]["last_retry_reason"] == "OSError"
    assert "private path" not in repr(reports)


async def test_capacity_exhaustion_before_network_recovers_after_growth(recovery_case, tmp_path):
    from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker
    from umi.competition_cohort_executor import CohortExecutionAuthority
    from umi.competition_cohort_origin import CohortEndpointOrigin

    p = recovery_case

    def consumer(capacity):
        journal = p.e.journal(directory=str(tmp_path / "small"), maximum_bytes=capacity)
        authority = CohortExecutionAuthority(journal, p.c.provider, p.e.box.history)
        origin = CohortEndpointOrigin(authority, p.provider())
        return CohortEndpointResponseRecovery(origin, p.validator, transport=p.http)

    small = consumer(64 * 1024)
    with pytest.raises(ValueError, match="capacity"):
        await small.prepare(p.e.assignment, p.signed, p.transport_policy)
    assert not p.http_paths and p.model.calls == 0
    assert small.journal.journal.get("endpoint_recovery_intent", p.slot) is not None
    larger = consumer(4 * 1024**2)
    result = await CohortEndpointRecoveryWorker(larger).poll_once()
    assert result["considered"] == result["pending"] == len(p.e.job.cases)
    assert larger.selection(p.slot)[0] == p.selection


async def test_response_and_comparator_workers_share_retained_assignment(recovery_case):
    from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker
    from umi.competition_cohort_executor import CohortExecutor

    p = recovery_case
    for index in range(len(p.requests)):
        assert (await send_original(p, index)).status_code == 200
    worker = CohortEndpointRecoveryWorker(p.consumer(), batch_size=1)
    comparator = CohortExecutor(p.e.journal(), p.c.provider, p.e.box.history, p.e.port)
    for _ in p.requests:
        assert (await worker.poll_once())["responses_recovered"] == 1
        await comparator.advance(p.e.assignment)
    assert p.e.journal().evidence(p.slot).job == p.e.job
    assert len(p.e.calls) == len(p.requests)
    assert (await worker.poll_once())["considered"] == 0
    assert p.model.calls == len(p.requests)


@pytest.mark.parametrize("boundary", ["intent", "reservation"])
async def test_worker_recovers_partial_preparation_without_original_caller(
    recovery_case, tmp_path, monkeypatch, boundary
):
    from umi.competition_cohort_endpoint_recovery_worker import CohortEndpointRecoveryWorker
    from umi.competition_cohort_executor import CohortExecutionAuthority
    from umi.competition_cohort_origin import CohortEndpointOrigin

    p = recovery_case
    original = await send_original(p)

    def consumer():
        journal = p.e.journal(directory=str(tmp_path / "interrupted"))
        authority = CohortExecutionAuthority(journal, p.c.provider, p.e.box.history)
        return CohortEndpointResponseRecovery(
            CohortEndpointOrigin(authority, p.provider()), p.validator, transport=p.http
        )

    interrupted = consumer()
    if boundary == "reservation":
        reserve = interrupted.journal.journal.reserve_records

        def failed(*args):
            reserve(*args)
            raise OSError("crash after reservation")

        monkeypatch.setattr(interrupted.journal.journal, "reserve_records", failed)
    else:
        put = interrupted.journal.journal.put_many

        def failed(records, **kwargs):
            put(records, **kwargs)
            if records[0][0] == "endpoint_recovery_intent":
                raise OSError("crash after intent commit")

        monkeypatch.setattr(interrupted.journal.journal, "put_many", failed)
    with pytest.raises(OSError, match="crash"):
        await interrupted.prepare(p.e.assignment, p.signed, p.transport_policy)
    restarted = consumer()
    assert restarted.journal.journal.get("endpoint_recovery_intent", p.slot) is not None
    assert restarted.journal.journal.get("endpoint_recovery_selection", p.slot) is None
    result = await CohortEndpointRecoveryWorker(restarted).poll_once()
    assert result["responses_recovered"] == 1
    assert restarted.selection(p.slot)[0] == p.selection
    assert (
        bytes.fromhex(restarted.retained(p.slot, p.case_id).response.envelope_hex)
        == original.content
    )
    assert p.model.calls == p.fetcher.calls == 1
