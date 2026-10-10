"""Automatic tail closure and independent review over native synthetic-chain fixtures."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
from umi.competition_cohort_service_queue import ServiceQueueBackpressure, ServiceWorkQueue
from umi.competition_cohort_service_work import SignedServiceWorkClaim
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistration
from umi.open_competition import digest, identity, sign_object

from .cohort_tail_settlement_fixture import inventory_original, partial_original, tail_harness
from .test_competition_cohort_request_export import remote as remote
from .test_competition_cohort_request_phase import base_policy as base_policy
from .test_competition_cohort_request_phase import chain as chain
from .test_competition_cohort_request_phase import chain_config as chain_config
from .test_competition_cohort_request_phase import endpoint as endpoint
from .test_competition_cohort_request_phase import execution as execution
from .test_competition_cohort_request_phase import granted as granted
from .test_competition_cohort_request_phase import known_video_bytes as known_video_bytes
from .test_competition_cohort_request_phase import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_phase import miner_policy as miner_policy
from .test_competition_cohort_request_phase import original_harness as original_harness
from .test_competition_cohort_request_phase import policy as policy
from .test_competition_cohort_request_phase import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_phase import recovery as recovery
from .test_competition_cohort_request_phase import recovery_case as recovery_case
from .test_competition_cohort_request_phase import relay as relay
from .test_competition_cohort_request_phase import request_owner as request_owner
from .test_competition_cohort_request_phase import runtime as runtime
from .test_competition_cohort_request_phase import scenario as scenario
from .test_competition_cohort_request_phase import service as service
from .test_competition_cohort_request_phase import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_request_phase import service_closed as service_closed
from .test_competition_cohort_request_phase import service_owner as service_owner
from .test_competition_cohort_request_phase import shared_control_group as shared_control_group
from .test_competition_cohort_service_queue import capture
from .test_open_competition import wallet

harness = tail_harness


@pytest.mark.asyncio
async def test_automatic_tail_preserves_completion_and_independent_clock_across_restart(
    remote, monkeypatch
):
    h = remote
    target = h.b["orders"][-1]
    target_key = digest(target)
    original_read = h.source.terminals
    h.source.terminals = lambda order, evaluator: (
        None if digest(order) == target_key else original_read(order, evaluator)
    )
    partials = tuple(partial_original(h.b, target, who) for who in target.order.evaluators)
    h.source.partial_source = lambda _: partials
    prior_progress = h.window()
    assert prior_progress.completion == "pending"
    prior_review = h.source.read(prior_progress)
    opening = h.source.request_opening(h.state)
    opened = HistoricalRegistration(None, opening, SimpleNamespace(block_number=h.block), 1000)
    clocks = {digest(opening): 1000}
    observed = capture(h.block)
    observed.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
    clocks[digest(execution_boundary(observed))] = observed.provenance["timestamp_ms"]
    # A pre-cutoff partial cannot stand in for the evaluator's current inventory.
    assert h.source.observe(h.state, observed, serving=True, opened=opened) == prior_progress
    assert h.source.read(prior_progress) == prior_review
    h.block += 1
    inventory_observation = execution_boundary(capture(h.block))
    clocks[digest(inventory_observation)] = 1000 + MINIMUM_REQUEST_OPEN_MS + 1000
    inventories = tuple(inventory_original(h.b, key, inventory_observation) for key in partials)
    h.source.inventory_source = lambda key, **kw: inventories
    h.block += 1
    observed = capture(h.block)
    observed.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS + 2000
    clocks[digest(execution_boundary(observed))] = observed.provenance["timestamp_ms"]
    progress = h.source.observe(h.state, observed, serving=True, opened=opened)
    assert progress.completion == "complete"
    native = h.source.read(progress)
    assert native.tail.unfinished_hotkeys == (identity(target.order.submission.submission.hotkey),)
    assert len(native.tail.original_hotkeys) == 11
    assert set(native.inventory_observations) == {inventory_observation}
    original_proof = h.provider.review_archive
    corrupt = False
    corrupt_inventory = False

    async def reviewed_clock(self, observation, raw, metadata):
        checked = await original_proof(observation, raw, metadata)
        if corrupt_inventory and observation == inventory_observation:
            raise ValueError("native evaluator inventory proof invalid")
        timestamp = clocks.get(digest(observation), 1)
        if corrupt and observation == native.tail.observation:
            timestamp += 1
        return HistoricalRegistration(
            checked.snapshot, checked.original, checked.replayed_at, timestamp
        )

    monkeypatch.setattr(type(h.provider), "review_archive", reviewed_clock)
    assert await h.remote.review(progress) == native.record
    corrupt = True
    with pytest.raises(ValueError, match="native original timestamp"):
        await h.remote.review(progress)
    corrupt = False
    corrupt_inventory = True
    with pytest.raises(ValueError, match="native evaluator inventory proof"):
        await h.remote.review(progress)
    corrupt_inventory = False
    h.source = h.reopen()
    h.exporter.source = h.source
    assert h.source.read(progress) == native
    assert await h.remote.review(progress) == native.record
    assert await h.remote_signer().attest(progress)
    assert h.b["terminals"]  # Genuine withheld originals remain recoverable; no deletion/reset.


@pytest.mark.asyncio
async def test_tail_closes_uncompensated_unavailable_window_and_resumes_initial_fence(
    remote, monkeypatch, tmp_path
):
    h = remote
    original_read = h.source.terminals
    targets = h.b["orders"][-2:]
    withheld = {digest(order) for order in targets}
    partials = {
        digest(order.order.submission.submission): tuple(
            partial_original(h.b, order, who) for who in order.order.evaluators
        )
        for order in targets
    }
    published_cutoffs = []
    fail_cutoff_publication = False

    def publish_cutoff(tail):
        assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) is not None
        if fail_cutoff_publication:
            raise OSError("interrupted cutoff inventory delivery")
        published_cutoffs.append(tail)

    def connect():
        h.source.terminals = lambda order, evaluator: (
            None if digest(order) in withheld else original_read(order, evaluator)
        )
        h.source.partial_source = lambda key: partials.get(key, ())

        def inventories(key, *, selected_at_block, completed_by_block):
            if completed_by_block <= selected_at_block:
                return ()
            observation = execution_boundary(capture(completed_by_block))
            return tuple(inventory_original(h.b, ref, observation) for ref in partials.get(key, ()))

        h.source.inventory_source = inventories
        h.source.publish_inventory_cutoff = publish_cutoff
        h.exporter.source = h.source

    connect()
    opening = h.source.request_opening(h.state)
    opened = HistoricalRegistration(None, opening, SimpleNamespace(block_number=h.block), 1000)
    clocks = {digest(opening): 1000}

    def sample(*, elapsed=MINIMUM_REQUEST_OPEN_MS):
        observed = capture(h.block)
        observed.provenance["timestamp_ms"] = 1000 + elapsed
        clocks[digest(execution_boundary(observed))] = 1000 + elapsed
        return h.source.observe(h.state, observed, serving=False, opened=opened)

    assert sample(elapsed=MINIMUM_REQUEST_OPEN_MS - 1).completion == "pending"
    assert h.c.queue.retained_seal() is None
    # Two out of eleven identities cannot close admission, even after twelve hours.
    h.block += 1
    assert sample().completion == "pending"
    assert h.c.queue.retained_seal() is None
    assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) is None
    withheld.remove(digest(targets[0]))
    admission = h.c.assignment.admission

    def assert_restarted_admissions_fenced():
        queue = ServiceWorkQueue(h.c.cfg, h.b["policy"])
        claim = admission.claim.claim.model_copy(update={"nonce": "f0" * 32})
        new_claim = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, wallet("Bob")))
        args = (
            admission.submission,
            admission.participant,
            h.c.assignment.source,
            capture(h.block),
        )
        with pytest.raises(ServiceQueueBackpressure, match="tail fence"):
            queue.admit(new_claim, *args, expected_tip_sha256=h.state.tip_sha256)
        assert (
            queue.admit(admission.claim, *args, expected_tip_sha256=h.state.tip_sha256) == admission
        )
        assert queue.retained_seal() is None

    original_put = h.source.journal.put

    def interrupted_owner_ack(kind, *args, **kwargs):
        if kind == "request_tail_fence":
            raise OSError("interrupted after durable fence publication")
        return original_put(kind, *args, **kwargs)

    monkeypatch.setattr(h.source.journal, "put", interrupted_owner_ack)
    with pytest.raises(OSError, match="durable fence publication"):
        sample()
    assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) is None
    assert_restarted_admissions_fenced()
    monkeypatch.setattr(h.source.journal, "put", original_put)
    fail_cutoff_publication = True
    with pytest.raises(OSError, match="cutoff inventory delivery"):
        sample()
    assert_restarted_admissions_fenced()
    fail_cutoff_publication = False
    original_seal = h.c.queue.seal_locked

    def interrupted(*args, **kwargs):
        raise OSError("interrupted before first queue seal")

    monkeypatch.setattr(h.c.queue, "seal_locked", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        sample()
    retained_fence = h.source.journal.get("request_tail_fence", h.state.tip_sha256)
    assert retained_fence is not None and h.c.queue.retained_seal() is None
    assert_restarted_admissions_fenced()
    monkeypatch.setattr(h.c.queue, "seal_locked", original_seal)
    h.source = h.reopen()
    connect()
    h.block += 1
    progress = sample(elapsed=MINIMUM_REQUEST_OPEN_MS + 1000)
    native = h.source.read(progress)
    assert progress.completion == "complete"
    assert native.record.fence is None and native.record.tail_fence is not None
    assert not native.record.service.serving
    target = next(t.target_block for t in h.state.targets if t.phase == "requests")
    assert progress.observed_at_block < target + progress.unavailable_blocks
    assert len(native.tail.unfinished_hotkeys) == 1
    assert native.record.tail_fence.model_dump(mode="json", by_alias=True) == retained_fence
    assert published_cutoffs and all(tail == native.record.tail_fence for tail in published_cutoffs)

    # A later genuine completion survives restart and does not require a new grace period.
    withheld.clear()
    h.source = h.reopen()
    connect()
    h.block += 1
    progress = sample(elapsed=MINIMUM_REQUEST_OPEN_MS + 2000)
    final = h.source.read(progress)
    assert final.tail.unfinished_hotkeys == ()
    assert final.record.tail_fence == native.record.tail_fence
    original_proof = h.provider.review_archive

    async def reviewed_clock(self, observation, raw, metadata):
        checked = await original_proof(observation, raw, metadata)
        return HistoricalRegistration(
            checked.snapshot,
            checked.original,
            checked.replayed_at,
            clocks.get(digest(observation), 1),
        )

    monkeypatch.setattr(type(h.provider), "review_archive", reviewed_clock)
    assert await h.remote.review(progress) == final.record
    assert await h.remote_signer().attest(progress)

    # The ordinary independent controller closes and hands off this exact
    # nonserving tail, with no intermediate availability restoration vote.
    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.competition_cohort_request_publication import CohortRequestSettlementPublisher
    from umi.private_files import read_private_model

    from .test_competition_cohort_request_phase import request_controller

    handoff = tmp_path / "tail-handoff" / (h.cohort + ".json")
    proofs = []

    async def publish_proof(observation):
        proofs.append(observation)

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            publish_proof,
            sources=h.sources,
            history_directory=handoff.parent,
        )

    with request_controller(h, tmp_path, publication) as control:
        controller = control.reopen()

        async def sample_original(state, observed):
            assert state == h.state
            assert execution_boundary(observed) == final.record.service.observation
            return progress

        controller.sample_progress = sample_original
        await controller.tick()
        state, _ = control.store.status(h.cohort)
        assert state.phase == "reference_reveal"
        delivered = read_private_model(handoff, CohortOrderHistory, maximum_bytes=8 * 1024**2)
        closed = delivered.history.transitions[-1].transition
        assert closed.request_tail_sha256 == digest(final.tail)
        assert delivered.history == h.intake.history(h.cohort)
        exported = control.publisher._export(h.block)
        assert all(control.publisher.files(k) == raw for k, raw in exported.objects.items())
        original = handoff.read_bytes()
        await control.publisher(delivered.history)
        assert handoff.read_bytes() == original
        assert set(map(digest, proofs)) == set(map(digest, exported.observations))
        assert set(map(digest, final.inventory_observations)) <= set(map(digest, proofs))
        assert digest(final.record.tail_fence.observation) in set(map(digest, proofs))
