"""Adopted original plan through native request close, publication and reopen."""

import asyncio
import json
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi import competition_cohort_request_publication as publication_module
from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_request_publication import CohortRequestSettlementPublisher
from umi.competition_cohort_request_rule import authenticated_request_tail_rule
from umi.competition_verification_reuse import VerificationReceiptUnavailable, VerificationReuse
from umi.competition_work_progress import check_work_cancelled
from umi.host_memory_runtime import bind_memory_controller
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
async def test_publication_reuses_one_exact_closure_review_after_restart(
    request_owner, tmp_path, monkeypatch, caplog
):
    h = request_owner
    h.window()
    handoff = tmp_path / "single-review-handoff" / (h.cohort + ".json")

    async def proof(observation):
        return None

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
        )

    caplog.set_level("INFO", logger="umi.competition.progress")
    with request_controller(h, tmp_path, publication) as control:
        await control.reopen().tick()
        original = handoff.read_bytes()
        native_prefix = publication_module.certified_request_prefix
        prefixes = []

        def prefix(*args, **kwargs):
            result = native_prefix(*args, **kwargs)
            prefixes.append(result)
            return result

        monkeypatch.setattr(publication_module, "certified_request_prefix", prefix)
        for restart in (False, True):
            if restart:
                h.source = h.reopen()
                control.publisher = publication(control.decision)
            caplog.clear()
            control.publisher._export(h.block)
            events = [
                json.loads(record.message)
                for record in caplog.records
                if record.name == "umi.competition.progress"
            ]
            reviews = [
                event
                for event in events
                if event.get("stage") == "service_request_closure"
                and event.get("state") in {"hit", "retained"}
            ]
            assert len(reviews) == 1
            assert reviews[0]["state"] == "hit"
            assert handoff.read_bytes() == original
        assert len(prefixes) == 2 and prefixes[0] == prefixes[1]

        def changed_prefix(*args, **kwargs):
            checked = native_prefix(*args, **kwargs)
            return checked.model_copy(update={"transitions": checked.transitions[:-1]})

        monkeypatch.setattr(publication_module, "certified_request_prefix", changed_prefix)
        with pytest.raises(ValueError, match="reviewed closure prefix"):
            control.publisher._export(h.block)
        assert handoff.read_bytes() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
async def test_completed_publication_reuses_native_work_and_repairs_only_damage(
    request_owner, tmp_path, monkeypatch
):
    h = request_owner
    h.window()
    handoff = tmp_path / "completed-handoff" / (h.cohort + ".json")
    proofs, calls = set(), []

    async def proof(observation):
        proofs.add(digest(observation))
        calls.append(digest(observation))

    async def proof_completed(observation):
        return digest(observation) in proofs

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
            proof_completed=proof_completed,
        )

    def forbidden(*args, **kwargs):
        pytest.fail("completed publication repeated native/payload work")

    with request_controller(h, tmp_path, publication) as control:
        await control.reopen().tick()
        original = handoff.read_bytes()
        closed = h.intake.history(h.cohort)
        completed = control.publisher.completion.load(h.block)
        first_calls = tuple(calls)
        h.source = h.reopen()
        control.publisher = publication(control.decision)
        with monkeypatch.context() as repeated:
            repeated.setattr(control.publisher, "_export", forbidden)
            repeated.setattr(control.publisher, "_objects", forbidden)
            repeated.setattr(control.publisher, "_resume", forbidden)
            repeated.setattr(control.publisher, "intake", forbidden)
            repeated.setattr(control.publisher.objects, "_read_descriptor", forbidden)
            repeated.setattr(h.intake, "_records", forbidden)
            await control.publisher(closed)
            await control.publisher(closed)
            authorized = []

            def authorize(operation, cohort, phase, *, lane):
                authorized.append((operation, cohort, phase, lane))

            controller = SimpleNamespace(
                requests_stage=True,
                policy=SimpleNamespace(bounds=None),
                authorize=authorize,
                acquire=forbidden,
            )
            with bind_memory_controller(controller):
                await control.publisher(closed)
            assert ("requests_publish", h.cohort, "requests", "transient") in authorized

            def denied(*args, **kwargs):
                raise ValueError("requests publication is not selected")

            controller.authorize = denied
            with (
                bind_memory_controller(controller),
                pytest.raises(ValueError, match="not selected"),
            ):
                await control.publisher(closed)
        assert handoff.read_bytes() == original and tuple(calls) == first_calls

        # A missing proof returns to the existing guarded delivery callback;
        # completed native evidence and unchanged descriptors remain untouched.
        proofs.remove(calls[0])
        with monkeypatch.context() as proof_repair:
            proof_repair.setattr(control.publisher, "_export", forbidden)
            proof_repair.setattr(control.publisher.objects, "_read_descriptor", forbidden)
            await control.publisher(closed)
        assert set(calls) == proofs

        selected = next(value for value in completed.outputs if value.descriptor is not None)
        path = control.publisher.files._path(selected.key)
        original_output = path.read_bytes()
        path.unlink()
        native_read, repaired = JournalEndpointObjects.__call__, []

        def repair_read(source, key):
            if source.journal.root == h.source.journal.root:
                repaired.append(key)
            return native_read(source, key)

        with monkeypatch.context() as repair:
            repair.setattr(control.publisher, "_export", forbidden)
            repair.setattr(JournalEndpointObjects, "__call__", repair_read)
            await control.publisher(closed)
        assert repaired == [selected.key]
        assert path.read_bytes() == original_output and handoff.read_bytes() == original

        native_path = control.publisher.verification_reuse.directory / (
            completed.native_identity + ".json"
        )
        native_bytes = native_path.read_bytes()
        native_path.unlink()
        with pytest.raises(VerificationReceiptUnavailable, match="original_native"):
            await control.publisher(closed)
        native_path.write_bytes(native_bytes)
        native_path.chmod(0o600)
        with monkeypatch.context() as changed:
            changed.setattr(control.publisher.verification_reuse, "runtime", {"changed": True})
            with pytest.raises(VerificationReceiptUnavailable, match="context"):
                await control.publisher(closed)

        completion_path = control.publisher.verification_reuse.directory / (
            control.publisher.completion.slot + ".json"
        )
        completion_path.unlink()
        with pytest.raises(VerificationReceiptUnavailable, match="completion_metadata"):
            await control.publisher(closed)


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
async def test_historical_completed_handoff_migrates_metadata_without_native_replay(
    request_owner, tmp_path, monkeypatch
):
    h = request_owner
    h.window()
    handoff = tmp_path / "legacy-handoff" / (h.cohort + ".json")
    proofs = set()

    async def proof(observation):
        proofs.add(digest(observation))

    async def proof_completed(observation):
        return digest(observation) in proofs

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
            proof_completed=proof_completed,
        )

    with request_controller(h, tmp_path, publication) as control:
        await control.reopen().tick()
        original = handoff.read_bytes()
        prior = control.publisher.completion.load(h.block)
        directory = control.publisher.verification_reuse.directory
        for suffix in (".json", ".complete"):
            (directory / (control.publisher.completion.slot + suffix)).unlink()
        h.source = h.reopen()
        control.publisher = publication(control.decision)

        def forbidden(*args, **kwargs):
            pytest.fail("legacy completion migration replayed native evidence")

        native_read = JournalEndpointObjects.__call__

        def no_original_payload(source, key):
            if source.journal.root == h.source.journal.root:
                forbidden()
            return native_read(source, key)

        monkeypatch.setattr(control.publisher, "_export", forbidden)
        monkeypatch.setattr(publication_module, "replay_request_completion", forbidden)
        monkeypatch.setattr(JournalEndpointObjects, "__call__", no_original_payload)
        await control.publisher(h.intake.history(h.cohort))
        migrated = control.publisher.completion.load(h.block)
        assert migrated.native_identity == prior.native_identity
        assert migrated.native_checksum == prior.native_checksum
        assert migrated.observations == prior.observations
        assert migrated.outputs == prior.outputs
        assert handoff.read_bytes() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["legacy6"], indirect=True)
@pytest.mark.parametrize("receipt_scenario", ["adopted"], indirect=True)
async def test_publication_rejects_output_or_hold_changes_during_proof_delivery(
    request_owner, tmp_path, monkeypatch
):
    h = request_owner
    h.window()
    handoff = tmp_path / "closing-fence" / (h.cohort + ".json")
    selected, changes, pending, removed = [], ["output"], [], []

    async def proof(observation):
        if not changes:
            return
        change = changes.pop()
        key = selected[-1]
        if change == "output":
            control.publisher.files._path(key).unlink()
        elif change == "native_receipt":
            path = control.publisher.verification_reuse.directory / (
                pending[-1].native_identity + ".json"
            )
            removed.append((path, path.read_bytes()))
            path.unlink()
        else:
            with h.source.journal.transaction() as db:
                db.execute("INSERT INTO holds VALUES (?)", (key,))

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
        native = control.publisher._objects

        def remember_output(exported):
            outputs = native(exported)
            pending.append(exported.completion)
            selected.append(next(value.key for value in outputs if value.descriptor is not None))
            return outputs

        monkeypatch.setattr(control.publisher, "_objects", remember_output)
        with pytest.raises(ValueError, match="outputs changed during delivery"):
            await control.reopen().tick()
        assert not handoff.exists()
        changes.append("native_receipt")
        with pytest.raises(VerificationReceiptUnavailable, match="original_native"):
            await control.publisher(h.intake.history(h.cohort))
        assert not handoff.exists()
        path, raw = removed.pop()
        path.write_bytes(raw)
        path.chmod(0o600)
        changes.append("hold")
        with pytest.raises(ValueError, match="conflict held"):
            await control.publisher(h.intake.history(h.cohort))
        assert not handoff.exists()


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
    # Observation and publication share successful semantic checkpoints. Put
    # the interruption at the actual first check, before observation completes.
    window_end = h.block + h.duration
    remember = VerificationReuse.remember
    checkpoints = []

    def interrupt_after_checkpoint(owner, *args):
        remember(owner, *args)
        checkpoints.append(args[0])
        raise OSError("first pass interrupted after durable semantic checkpoint")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(VerificationReuse, "remember", interrupt_after_checkpoint)
        with pytest.raises(OSError, match="durable semantic checkpoint"):
            h.window()
    assert len(checkpoints) == 1
    h.sample()
    while h.block < window_end:
        h.sample(min(h.block + 300, window_end))
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

    def captured(publisher, block, *, connection=None, include_records=True):
        result = native_capture(
            publisher, block, connection=connection, include_records=include_records
        )
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
        assert control.publisher.verification_reuse is h.source.verification_reuse
        assert not handoff.exists()
        with pytest.raises(OSError, match="publication interrupted"):
            await control.reopen().tick()
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
        assert len(deliveries) == 2 and all(value == deliveries[0] for value in deliveries)
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
        retained_semantic = semantic.read_bytes()
        semantic.unlink()
        with pytest.raises(VerificationReceiptUnavailable, match="original_native"):
            await control.publisher(closed)
        semantic.write_bytes(retained_semantic)
        semantic.chmod(0o600)
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
