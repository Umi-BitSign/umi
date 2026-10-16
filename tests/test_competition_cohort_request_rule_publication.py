"""Adopted original plan through native request close, publication and reopen."""

import asyncio
import json
import threading
import time
from contextlib import contextmanager

import pytest

from umi import competition_cohort_request_publication as publication_module
from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_request_publication import CohortRequestSettlementPublisher
from umi.competition_cohort_request_rule import authenticated_request_tail_rule
from umi.competition_verification_reuse import VerificationReuse
from umi.competition_work_progress import check_work_cancelled
from umi.open_competition import digest
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_request_phase import base_policy as base_policy
from .test_competition_cohort_request_phase import chain as chain
from .test_competition_cohort_request_phase import chain_config as chain_config
from .test_competition_cohort_request_phase import endpoint as endpoint
from .test_competition_cohort_request_phase import execution as execution
from .test_competition_cohort_request_phase import granted as granted
from .test_competition_cohort_request_phase import harness as harness
from .test_competition_cohort_request_phase import known_video_bytes as known_video_bytes
from .test_competition_cohort_request_phase import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_phase import miner_policy as miner_policy
from .test_competition_cohort_request_phase import original_harness as original_harness
from .test_competition_cohort_request_phase import policy as policy
from .test_competition_cohort_request_phase import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_phase import recovery as recovery
from .test_competition_cohort_request_phase import recovery_case as recovery_case
from .test_competition_cohort_request_phase import relay as relay
from .test_competition_cohort_request_phase import request_controller
from .test_competition_cohort_request_phase import request_owner as request_owner
from .test_competition_cohort_request_phase import runtime as runtime
from .test_competition_cohort_request_phase import scenario as scenario
from .test_competition_cohort_request_phase import service as service
from .test_competition_cohort_request_phase import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_request_phase import service_closed as service_closed
from .test_competition_cohort_request_phase import service_owner as service_owner
from .test_competition_cohort_request_phase import shared_control_group as shared_control_group
from .test_competition_cohort_service_grants import service_quality_inputs as service_quality_inputs


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
async def test_original_adopted_history_closes_and_retries_publication(
    request_owner, tmp_path, monkeypatch, caplog
):
    h = request_owner
    original_history = h.intake.history(h.cohort)
    original_plan = canonical_json_bytes(original_history.plan)
    adoption = next(
        t
        for t in original_history.transitions
        if t.transition.operation == "adopt_request_tail_rule"
    )
    opening = h.source.request_opening(h.state)
    assert (
        authenticated_request_tail_rule(original_history, h.b["policy"])
        == "original_request_12h_with_completed_miner/1"
    )
    h.window()
    handoff = tmp_path / "adopted-handoff" / (h.cohort + ".json")
    proofs = []
    failed = False
    checked_fence = []
    deliveries = []
    native_replay = publication_module.replay_request_completion
    native_delivery = CohortRequestSettlementPublisher._objects
    native_capture = CohortRequestSettlementPublisher._capture
    native_connection = h.intake._connection
    native_publish = publication_module.publish_private_model
    local = threading.local()
    final_fences = []

    @contextmanager
    def connection(*args, **kwargs):
        with native_connection(*args, **kwargs) as current:
            previous = getattr(local, "connection", None)
            local.connection = current
            try:
                yield current
            finally:
                local.connection = previous

    def captured(publisher, block, *, connection=None):
        result = native_capture(publisher, block, connection=connection)
        if connection is not None:
            local.final_capture = connection
        return result

    def published(*args, **kwargs):
        assert local.connection is not None and local.connection is local.final_capture
        final_fences.append(True)
        return native_publish(*args, **kwargs)

    monkeypatch.setattr(h.intake, "_connection", connection)
    monkeypatch.setattr(CohortRequestSettlementPublisher, "_capture", captured)
    monkeypatch.setattr(publication_module, "publish_private_model", published)

    def delivery(publisher, exported):
        collector = exported.objects.collector
        deliveries.append((set(exported.objects), collector.used))
        return native_delivery(publisher, exported)

    monkeypatch.setattr(CohortRequestSettlementPublisher, "_objects", delivery)

    def replay_without_intake_fence(*args, **kwargs):
        completed = threading.Event()

        def preflight():
            with h.intake.fenced_read_snapshot():
                completed.set()

        thread = threading.Thread(target=preflight, daemon=True)
        thread.start()
        assert completed.wait(3), "native replay retained the upload preflight fence"
        thread.join(3)
        checked_fence.append(True)
        return native_replay(*args, **kwargs)

    monkeypatch.setattr(
        publication_module, "replay_request_completion", replay_without_intake_fence
    )
    caplog.set_level("INFO", logger="umi.competition.progress")

    async def proof(observation):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("publication interrupted after original certification")
        proofs.append(observation)

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
        )

    with request_controller(h, tmp_path, publication) as control:
        remember = VerificationReuse.remember
        checkpoints = []

        def interrupt_after_checkpoint(owner, *args):
            remember(owner, *args)
            checkpoints.append(args[0])
            raise OSError("first pass interrupted after durable semantic checkpoint")

        with monkeypatch.context() as interrupted:
            interrupted.setattr(VerificationReuse, "remember", interrupt_after_checkpoint)
            with pytest.raises(OSError, match="durable semantic checkpoint"):
                await control.reopen().tick()
        assert len(checkpoints) == 1
        assert not handoff.exists()
        control.publisher = publication(control.decision)
        with pytest.raises(OSError, match="publication interrupted"):
            await control.publisher(h.intake.history(h.cohort))
        assert control.store.status(h.cohort)[0].phase == "reference_reveal"
        assert not handoff.exists()
        h.source = h.reopen()
        control.publisher = publication(control.decision)
        closed = h.intake.history(h.cohort)

        # Restart selects durable receipts through the actual caller. No manual
        # verification scope and no reopening the original journal payloads.
        native_object = JournalEndpointObjects.__call__

        def no_native_payload(objects, key):
            if objects.journal.root == h.source.journal.root:
                pytest.fail("publisher reread unchanged request evidence")
            # Fresh queue accepted-prefix metadata retains its own native fence.
            return native_object(objects, key)

        monkeypatch.setattr(JournalEndpointObjects, "__call__", no_native_payload)
        entered = threading.Event()

        def cancellable_read(*args, **kwargs):
            entered.set()
            while True:
                check_work_cancelled()
                time.sleep(0.01)

        monkeypatch.setattr(publication_module, "replay_request_completion", cancellable_read)
        task = asyncio.create_task(control.publisher(closed))
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert not handoff.exists()
        monkeypatch.setattr(
            publication_module, "replay_request_completion", replay_without_intake_fence
        )
        await control.publisher(closed)
        raw = handoff.read_bytes()
        await control.publisher(closed)
        assert handoff.read_bytes() == raw
        assert len(deliveries) == 3 and all(value == deliveries[0] for value in deliveries)
        assert deliveries[0][1] == sum(
            len(control.publisher.files(key)) for key in deliveries[0][0]
        )

        # The actual consumer repairs a missing output from only its affected
        # original, retaining all unrelated completed semantic checkpoints.
        derived = {digest(queue.retained_seal()) for queue in h.source.queues}
        selected = next(iter(deliveries[0][0] - derived))
        control.publisher.files._path(selected).unlink()
        repaired = []

        def repair_payload(objects, key):
            if objects.journal.root == h.source.journal.root:
                assert key == selected
                repaired.append(key)
            return native_object(objects, key)

        with monkeypatch.context() as repair:
            repair.setattr(JournalEndpointObjects, "__call__", repair_payload)
            await control.publisher(closed)
        assert repaired == [selected]
        assert handoff.read_bytes() == raw
        assert deliveries[-1] == deliveries[0]

        # Missing completed semantic state is explicitly repaired, never
        # silently treated as a first verification or a reason to re-import.
        semantic = next(
            path
            for path in control.publisher.verification_reuse.directory.glob("*.json")
            if "benchmark_closure_sha256"
            in json.loads(json.loads(path.read_bytes())["result_json"])
        )
        semantic.unlink()
        await control.publisher(closed)
        assert semantic.exists()
        assert handoff.read_bytes() == raw and deliveries[-1] == deliveries[0]

        # A warm receipt still charges the complete export against its active
        # consumer's budget; changing a local bound cannot borrow old capacity.
        with monkeypatch.context() as bounded:
            bounded.setattr(h.source, "replay_bytes", deliveries[0][1] - 1)
            with pytest.raises(ValueError, match=r"bound|budget"):
                await control.publisher(closed)
        assert handoff.read_bytes() == raw
        exported = read_private_model(handoff, CohortOrderHistory, maximum_bytes=8 * 1024**2)
        assert exported.history == closed
        assert canonical_json_bytes(exported.history.plan) == original_plan
        assert adoption in exported.history.transitions
        assert adoption.transition.evidence_sha256 not in exported.inputs()
        state, _, _ = replay_cohort_decisions(
            exported.history, h.b["policy"], exported.inputs().__getitem__
        )
        assert state.phase == "reference_reveal"
        assert state.request_tail_rule == "original_request_12h_with_completed_miner/1"
        assert opening in proofs
        assert set(map(digest, proofs)) == {digest(d.observation) for d in exported.decisions}
        assert checked_fence
        assert final_fences
        events = [
            json.loads(record.message)
            for record in caplog.records
            if record.name == "umi.competition.progress"
        ]
        assert any(event.get("state") == "hit" for event in events)
        assert any(
            event.get("stage") == "verification_receipt" and event.get("state") == "repair_required"
            for event in events
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_adopted_legacy_history_survives_native_reward_package(
    service_quality_inputs, tmp_path
):
    from umi.competition_cohort_reward_package import replay_reward_package

    from .test_competition_cohort_consumers import tip
    from .test_competition_reward_preparation import native_package

    b = service_quality_inputs
    original_plan = canonical_json_bytes(b["history"].plan)
    adoption = next(
        t for t in b["history"].transitions if t.transition.operation == "adopt_request_tail_rule"
    )
    prepared = await native_package.__wrapped__(b, tmp_path / "adopted-package")
    package = prepared.package
    assert canonical_json_bytes(package.inputs.history.plan) == original_plan
    assert adoption in package.inputs.history.transitions
    assert adoption.transition.evidence_sha256 not in {obj.sha256 for obj in package.objects}
    assert (
        authenticated_request_tail_rule(package.inputs.history, b["policy"])
        == "original_request_12h_with_completed_miner/1"
    )
    replayed = replay_reward_package(
        package,
        b["policy"],
        prepared.store,
        package.inputs.history,
        expected_package_sha256=digest(package),
        expected_cohort_sha256=digest(package.inputs.history.plan),
        expected_tip_sha256=tip(package.inputs.history),
        current_block=2**53 - 1,
        expected_terms_sha256=prepared.requirement.terms_sha256,
        expected_catalog_sha256s=prepared.requirement.catalog_sha256s,
        maximum_promotion_bytes=1_000_000,
    )
    assert replayed == prepared.allocation
