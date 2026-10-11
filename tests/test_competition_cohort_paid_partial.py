"""Native paid-response tail closure when the miner never supplies retirement."""

import asyncio
import errno
import json
import threading
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_request_closure import CohortRequestClosure
from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
from umi.competition_cohort_service_closure import CohortServiceRequestClosure
from umi.competition_cohort_service_grant import service_grant_slot
from umi.competition_cohort_service_partial import (
    ServicePaidPartialInventory,
    ServicePaidPartials,
    SignedServicePaidPartialInventory,
)
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistration
from umi.endpoint_protocol import COHORT_RETIRE_PATH, TRANSLATE_PATH
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError
from umi.protocol import canonical_json_bytes

from .cohort_request_closure_fixture import closure_fixture
from .cohort_tail_settlement_fixture import tail_harness
from .test_competition_cohort_endpoint import endpoint_scenario
from .test_competition_cohort_request_phase import make_request_owner
from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import capture, service_quality, service_quality_inputs
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import original_harness as original_harness
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_competition_cohort_service_worker import loop as loop
from .test_competition_reward_preparation import native_package

harness = tail_harness


@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
@pytest.mark.parametrize("retirement_before_closure", [False, True])
async def test_response_without_retirement_reaches_native_certified_package(
    loop,
    receipt_scenario,
    runtime,
    monkeypatch,
    tmp_path,
    retirement_before_closure,
    prepared_capture=False,
):
    s, c, p = loop, loop.c, loop.p

    async def retirement_unavailable(path):
        if path == COHORT_RETIRE_PATH:
            raise httpx.ConnectError("retirement endpoint remains unavailable")

    s.before_request = retirement_unavailable
    worker = s.worker()
    await worker.poll_once()
    body = worker.requests.latest(c.assignment.admission.claim, p.validator.hotkey.ss58_address)
    slot = service_grant_slot(body)
    response = worker.journal.get_raw("service_response", slot)
    assert response is not None and TRANSLATE_PATH in s.paths
    assert worker.journal.get("service_retirement", slot) is None
    assert worker.terminals.read(c.assignment) is None
    assert p.model.calls == 1
    grant = worker.requests.certificate(slot)
    benchmark_endpoint = endpoint_scenario(
        receipt_scenario, tmp_path / "benchmark-input", runtime, monkeypatch
    )
    b = await closure_fixture(benchmark_endpoint, tmp_path / "benchmark", prepared=p.e.r.h.batch)
    b["closure"] = b["closure"].model_copy(
        update={"observation": execution_boundary(capture(body.request.deadline_block + 1))}
    )
    b.update(service_case=c, transport=p.transport_policy)
    h = make_request_owner(b, tmp_path / "request-owner", monkeypatch)
    opening = h.source.request_opening(h.state)
    opened = HistoricalRegistration(None, opening, SimpleNamespace(block_number=h.block), 1000)
    clocks = {digest(opening): 1000}

    def sample():
        def collect():
            observed = capture(h.block)
            observed.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS + h.block
            clocks[digest(execution_boundary(observed))] = observed.provenance["timestamp_ms"]
            return observed

        if prepared_capture:
            # Own admissions before the sole capture, then keep them through
            # early sealing and the native paid-partial inventory below.
            with h.source.prepare(h.state) as prepared:
                return prepared(collect(), serving=False, opened=opened)
        return h.source.observe(h.state, collect(), serving=False, opened=opened)

    original_partial_read = ServicePaidPartials.read_locked
    partial_reads = []

    def read_after_seal(owner, assignment, selected_fence):
        # The merged owner must keep early native sealing ahead of potentially
        # pending paid inventory, while all original admission leases are held.
        assert owner.queue._retained_seal() is not None
        assert owner.queue._tail_admission_fence() == selected_fence
        partial_reads.append(assignment.admission.work_sha256)
        return original_partial_read(owner, assignment, selected_fence)

    with monkeypatch.context() as patch:
        patch.setattr(ServicePaidPartials, "read_locked", read_after_seal)
        assert sample().completion == "pending"
    assert partial_reads == [c.assignment.admission.work_sha256]
    fence = c.queue._tail_admission_fence()
    assert fence is not None
    assert fence.tail.unfinished_hotkeys and len(fence.tail.original_hotkeys) == 11
    original_sign, signed_bodies = s.sign, []
    lose_ack = True

    async def sign_partial(value):
        nonlocal lose_ack
        signature = await original_sign(value)
        if isinstance(value, ServicePaidPartialInventory):
            signed_bodies.append(canonical_json_bytes(value))
            if lose_ack:
                lose_ack = False
                raise OSError("lost acknowledgement after signing paid inventory")
        return signature

    s.sign = sign_partial
    p.finality.head = h.block + 1
    worker = s.worker()
    prepare, contended_at = worker.partials.prepare, []

    def contention_once(assignment, source=None, observation=None):
        if source is not None and not contended_at:
            contended_at.append(observation.block)
            p.finality.head += 1
            raise PrivateStateBusyError("round_journal_lock", "ab" * 32, errno.EAGAIN)
        return prepare(assignment, source, observation)

    with monkeypatch.context() as patch, pytest.raises(OSError, match="lost acknowledgement"):
        patch.setattr(worker.partials, "prepare", contention_once)
        await worker._advance(c.assignment.admission)
    intent = worker.partials.prepare(c.assignment)
    assert intent is not None and intent.observation.block > fence.tail.observation.block
    assert intent.observation.block > contended_at[0]
    assert intent.retirement_sha256 is None
    assert intent.response_sha256 == digest(json.loads(response))
    p.finality.head += 1
    worker = s.worker()
    original_put = worker.partials.objects.put

    def lost_export(value):
        if isinstance(value, SignedServicePaidPartialInventory):
            raise OSError("lost export after signed inventory committed")
        return original_put(value)

    with monkeypatch.context() as patch, pytest.raises(OSError, match="lost export"):
        patch.setattr(worker.partials.objects, "put", lost_export)
        await worker._advance(c.assignment.admission)
    assert signed_bodies == [canonical_json_bytes(intent)] * 2
    signed = worker.partials.retained(intent)
    assert signed.inventory == intent
    sign_count = s.signs
    assert await s.worker()._advance(c.assignment.admission) == ("pending", "paid_partial_retained")
    assert s.signs == sign_count
    assert_partial_faults(worker, c, signed, monkeypatch)
    assert worker.journal.get("service_retirement", slot) is None
    assert worker.terminals.read(c.assignment) is None
    assert canonical_json_bytes(worker.requests.certificate(slot)) == canonical_json_bytes(grant)
    # Repeated supported opens preserve all original bindings and exact intents.
    for _ in range(2):
        worker = s.worker()
        assert worker.partials.prepare(c.assignment) == intent
        assert worker.queue._tail_admission_fence() == fence
        assert worker.queue.assignment(c.assignment.admission.claim) == c.assignment
    terminal = None
    if retirement_before_closure:
        from umi.competition_cohort_service_terminal import PendingServiceTerminal

        await retain_authentic_retirement(worker, c, grant)
        h.block = p.finality.head
        with pytest.raises(PendingServiceTerminal, match="fencing and certification"):
            sample()
        assert worker.partials.prepare(c.assignment) is None
        s.before_request = None
        assert await s.worker()._advance(c.assignment.admission) == (
            "completed",
            "terminal_retained",
        )
        terminal = worker.terminals.read(c.assignment)
        assert terminal is not None
        assert terminal.terminal.response_sha256 == intent.response_sha256
        assert worker.partials.objects(digest(signed)) == canonical_json_bytes(signed)
        assert p.model.calls == 1
    h.block = p.finality.head + 1
    progress = sample()
    assert progress.completion == "complete"
    native = h.source.read(progress)
    assert native.inventory_observations == (
        () if retirement_before_closure else (intent.observation,)
    )
    original_review = h.provider.review_archive

    async def review_clock(self, observation, raw, metadata):
        checked = await original_review(observation, raw, metadata)
        return HistoricalRegistration(
            checked.snapshot,
            checked.original,
            checked.replayed_at,
            clocks.get(digest(observation), 1000 + MINIMUM_REQUEST_OPEN_MS + observation.block),
        )

    monkeypatch.setattr(type(h.provider), "review_archive", review_clock)
    assert await h.signer("Charlie").attest(progress)
    assert await h.signer("Dave").attest(progress)
    h.source = h.reopen()
    assert h.source.read(progress) == native
    objects = h.source.objects
    with h.source.journal.read_transaction() as db:
        keys = tuple(
            r[0] for r in db.execute("SELECT id FROM records WHERE kind='endpoint_replay_object'")
        )
    b["objects"].update({key: objects(key) for key in keys})
    closure = CohortServiceRequestClosure.model_validate_json(objects(progress.phase_result_sha256))
    if retirement_before_closure:
        assert closure.schema_ == "umi-cohort-request-closure/4"
        assert closure.catalogs[0].paid_partials is None
        assert closure.catalogs[0].terminals == (digest(terminal),)
        assert closure.catalogs[0].skipped_work == ()
    else:
        assert closure.schema_ == "umi-cohort-request-closure/5"
        assert closure.catalogs[0].paid_partials == (digest(signed),)
        assert closure.catalogs[0].terminals == ()
        assert closure.catalogs[0].skipped_work == (c.assignment.admission.work_sha256,)
    b.update(closure=closure, service_seal=c.queue.retained_seal())
    service_quality_inputs.__wrapped__(b)
    quality = service_quality(b)
    if retirement_before_closure:
        assert len(quality.work) == 1 and quality.skipped_work == ()
        assert quality.work[0].work_sha256 == c.assignment.admission.work_sha256
        assert quality.work[0].credit.numerator == quality.work[0].credit.denominator == "1"
    else:
        assert quality.work == () and quality.skipped_work == closure.catalogs[0].skipped_work
    prepared = await native_package.__wrapped__(b, tmp_path / "package")
    package = prepared.package
    originals = {o.sha256: canonical_json_bytes(o.value) for o in package.objects}
    assert originals[intent.response_sha256] == response
    assert originals[intent.grant_sha256] == canonical_json_bytes(grant)
    if retirement_before_closure:
        assert originals[digest(terminal)] == canonical_json_bytes(terminal)
        assert prepared.package.service.statement.allocation.recipients
    else:
        assert originals[digest(signed)] == canonical_json_bytes(signed)
        assert not prepared.package.service.statement.allocation.recipients
        await assert_portable_replay_and_proofs(b, prepared, intent, originals)
        await assert_late_retirement_cannot_cross_snapshot_or_rewrite_package(
            worker, c, grant, signed, prepared, monkeypatch
        )


async def authentic_retirement(worker, c, grant):
    from umi.endpoint_retirement import SignedEndpointRetirementReceipt

    from .test_competition_cohort_miner import request

    reply = await request(c.p, COHORT_RETIRE_PATH, grant.body.request)
    assert reply.status_code == 200
    return worker.transport._retirement(
        grant, SignedEndpointRetirementReceipt.model_validate_json(reply.content)
    )


async def retain_authentic_retirement(worker, c, grant):
    retirement = await authentic_retirement(worker, c, grant)
    await worker.transport._retain_inventory(
        "service_retirement", service_grant_slot(grant.body), retirement
    )


async def assert_late_retirement_cannot_cross_snapshot_or_rewrite_package(
    worker, c, grant, signed, prepared, monkeypatch
):
    from umi.competition_cohort_service_terminal import PendingServiceTerminal

    before = canonical_json_bytes(prepared.package)
    # A later recovery is retained evidence, never a retroactive package edit.
    retirement = await authentic_retirement(worker, c, grant)
    slot = service_grant_slot(grant.body)
    entered = threading.Event()
    original = worker.transport._retain_inventory_record

    def retaining(*args):
        entered.set()
        return original(*args)

    task = None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(worker.transport, "_retain_inventory_record", retaining)
            with worker.queue.closure_inventory():
                task = asyncio.create_task(
                    worker.transport._retain_inventory("service_retirement", slot, retirement)
                )
                assert await asyncio.to_thread(entered.wait, 5)
                assert not task.done()
                assert worker.journal.get("service_retirement", slot) is None
                assert (
                    worker.partials.read_locked(c.assignment, worker.queue._tail_admission_fence())
                    == signed
                )
            await task
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    with pytest.raises(PendingServiceTerminal, match="fencing and certification"):
        worker.terminals.read(c.assignment, preserve_completed=True, allow_partial=True)
    assert worker.partials.prepare(c.assignment) is None
    assert canonical_json_bytes(prepared.package) == before


def assert_partial_faults(worker, c, signed, monkeypatch):
    from umi.competition_cohort_service_partial import read_paid_partial
    from umi.open_competition import sign_object

    from .test_open_competition import wallet

    body = signed.inventory
    fence = worker.queue._tail_admission_fence()
    objects = worker.partials.objects
    assert (
        read_paid_partial(
            digest(signed), objects, worker.requests.policy, worker.requests.transport
        )[0]
        == signed
    )
    # Native missing records cannot be reinterpreted as an unperformed job.
    original_get = worker.journal.get

    def missing_response(kind, key, **kwargs):
        if kind == "service_response":
            return None
        return original_get(kind, key, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(worker.journal, "get", missing_response)
        with worker.journal.locked(), pytest.raises(FileNotFoundError, match="referenced native"):
            worker.partials.read_locked(c.assignment, fence)
        with pytest.raises(FileNotFoundError, match="referenced native"):
            worker.partials.prepare(c.assignment)
    # Corrupt or missing content-addressed originals fail independently.
    for missing in (body.response_sha256, body.grant_sha256, body.assignment_sha256):

        def unavailable(key, missing=missing):
            if key == missing:
                raise FileNotFoundError("missing original")
            return objects(key)

        with pytest.raises(FileNotFoundError, match="missing original"):
            read_paid_partial(
                digest(signed), unavailable, worker.requests.policy, worker.requests.transport
            )

    def corrupt(key):
        return b"{}" if key == body.response_sha256 else objects(key)

    with pytest.raises(ValueError, match="bounded identity"):
        read_paid_partial(
            digest(signed), corrupt, worker.requests.policy, worker.requests.transport
        )
    variants = [
        signed.model_copy(update={"signature": sign_object(body, wallet("Alice"))}),
    ]
    for changed in (
        body.model_copy(update={"observation": fence.tail.observation}),
        body.model_copy(update={"evaluator_hotkey": wallet("Alice").hotkey.ss58_address}),
    ):
        variants.append(
            signed.model_copy(
                update={"inventory": changed, "signature": sign_object(changed, c.p.validator)}
            )
        )
    for altered in variants:
        key, raw = digest(altered), canonical_json_bytes(altered)

        def modified(wanted, raw=raw, key=key):
            return raw if wanted == key else objects(wanted)

        with pytest.raises(ValueError):
            read_paid_partial(key, modified, worker.requests.policy, worker.requests.transport)
    assert objects(digest(signed)) == canonical_json_bytes(signed)


def test_legacy_paid_closure_bytes_remain_exact():
    from umi.competition_cohort_service_closure import ServiceCatalogClosure

    from .test_competition_execution import boundary

    legacy = CohortServiceRequestClosure(
        schema="umi-cohort-request-closure/2",
        benchmark_closure_sha256="01" * 32,
        recovery_tip_sha256="02" * 32,
        observation=boundary(20),
        catalogs=(
            ServiceCatalogClosure(catalog_sha256="03" * 32, seal_sha256="04" * 32, terminals=()),
        ),
    )
    raw = canonical_json_bytes(legacy)
    # Recorded from release 960b8f2's original serializer before this change.
    assert digest(legacy) == "7d0228fb9fdda578bb406c19d83042d6d147a567c23ca087e29012d29eceea69"
    assert b'"paid_partials"' not in raw and b'"skipped_work"' not in raw
    assert canonical_json_bytes(CohortServiceRequestClosure.model_validate_json(raw)) == raw
    tail = legacy.model_copy(
        update={
            "schema_": "umi-cohort-request-closure/4",
            "catalogs": (legacy.catalogs[0].model_copy(update={"skipped_work": ()}),),
        }
    )
    assert digest(tail) == "12d0112259feb09250381a9077a5e402fb0469f4fffab0e100d7f0d42ae5b13a"
    assert canonical_json_bytes(
        CohortServiceRequestClosure.model_validate_json(canonical_json_bytes(tail))
    ) == canonical_json_bytes(tail)
    with pytest.raises(ValueError, match="version differs"):
        CohortServiceRequestClosure.model_validate_json(
            canonical_json_bytes(
                legacy.model_copy(
                    update={
                        "catalogs": (legacy.catalogs[0].model_copy(update={"paid_partials": ()}),)
                    }
                )
            )
        )


async def assert_portable_replay_and_proofs(b, prepared, intent, originals):
    from umi.competition_cohort_reward_package import replay_reward_package
    from umi.competition_cohort_settlement_service import CohortSettlementService

    from .test_competition_cohort_consumers import tip

    package = prepared.package

    def replay(value):
        return replay_reward_package(
            value,
            b["policy"],
            prepared.store,
            package.inputs.history,
            expected_package_sha256=digest(value),
            expected_cohort_sha256=digest(package.inputs.history.plan),
            expected_tip_sha256=tip(package.inputs.history),
            current_block=2**53 - 1,
            expected_terms_sha256=prepared.requirement.terms_sha256,
            expected_catalog_sha256s=prepared.requirement.catalog_sha256s,
            maximum_promotion_bytes=1_000_000,
        )

    assert replay(package) == prepared.allocation
    for key in (
        intent.response_sha256,
        intent.grant_sha256,
        intent.fence_sha256,
        package.inputs.closure.catalogs[0].paid_partials[0],
    ):
        with pytest.raises((ValueError, KeyError, FileNotFoundError)):
            replay(
                package.model_copy(
                    update={"objects": tuple(o for o in package.objects if o.sha256 != key)}
                )
            )
    tail = CohortRequestClosure.model_validate_json(
        originals[package.inputs.closure.benchmark_closure_sha256]
    ).tail
    timestamps = {
        digest(tail.opened_observation): tail.opened_timestamp_ms,
        digest(tail.selected_observation): tail.selected_timestamp_ms,
        digest(tail.observation): tail.observed_timestamp_ms,
    }
    seen, wrong = set(), False

    async def read_proof(observation):
        seen.add(digest(observation))
        return b"proof", b"metadata"

    async def review_proof(observation, raw, metadata):
        original = observation
        if wrong and observation == intent.observation:
            original = original.model_copy(update={"block": original.block + 1})
        return HistoricalRegistration(
            None,
            original,
            SimpleNamespace(block_number=2**53 - 1),
            timestamps.get(digest(observation), 1),
        )

    host = SimpleNamespace(
        proofs=SimpleNamespace(read=read_proof),
        provider=SimpleNamespace(review_archive=review_proof),
    )
    data = SimpleNamespace(inputs=package.inputs, objects=originals.__getitem__)
    await CohortSettlementService._request_inventory_proofs(host, data)
    assert digest(intent.observation) in seen
    wrong = True
    with pytest.raises(ValueError, match="changed its original observation"):
        await CohortSettlementService._request_inventory_proofs(host, data)
