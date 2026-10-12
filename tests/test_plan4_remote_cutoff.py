"""Independent native reviewer signs the original plan4 cutoff with10/11 unfinished."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistration
from umi.open_competition import digest

from .cohort_tail_settlement_fixture import inventory_original, partial_original
from .test_competition_cohort_request_tail_phase import base_policy as base_policy
from .test_competition_cohort_request_tail_phase import chain as chain
from .test_competition_cohort_request_tail_phase import chain_config as chain_config
from .test_competition_cohort_request_tail_phase import endpoint as endpoint
from .test_competition_cohort_request_tail_phase import execution as execution
from .test_competition_cohort_request_tail_phase import granted as granted
from .test_competition_cohort_request_tail_phase import harness as harness
from .test_competition_cohort_request_tail_phase import known_video_bytes as known_video_bytes
from .test_competition_cohort_request_tail_phase import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_tail_phase import miner_policy as miner_policy
from .test_competition_cohort_request_tail_phase import original_harness as original_harness
from .test_competition_cohort_request_tail_phase import policy as policy
from .test_competition_cohort_request_tail_phase import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_tail_phase import recovery as recovery
from .test_competition_cohort_request_tail_phase import recovery_case as recovery_case
from .test_competition_cohort_request_tail_phase import relay as relay
from .test_competition_cohort_request_tail_phase import remote as remote
from .test_competition_cohort_request_tail_phase import request_owner as request_owner
from .test_competition_cohort_request_tail_phase import runtime as runtime
from .test_competition_cohort_request_tail_phase import scenario as scenario
from .test_competition_cohort_request_tail_phase import service as service
from .test_competition_cohort_request_tail_phase import (
    service_catalog_inputs as service_catalog_inputs,
)
from .test_competition_cohort_request_tail_phase import service_closed as service_closed
from .test_competition_cohort_request_tail_phase import service_owner as service_owner
from .test_competition_cohort_request_tail_phase import shared_control_group as shared_control_group
from .test_competition_cohort_service_queue import capture

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True),
    pytest.mark.parametrize("recovery", ["hard12h"], indirect=True),
]


@pytest.mark.asyncio
async def test_plan4_remote_quorum_signs_without_waiting_for_ten_unfinished_miners(
    remote, monkeypatch
):
    h = remote
    assert h.b["history"].plan.request_tail_rule == "original_request_12h_with_completed_miner/1"
    complete = h.c.assignment.admission.submission.submission
    targets = tuple(
        order for order in h.b["orders"] if order.order.submission.submission != complete
    )
    assert len(targets) == 10
    withheld = {digest(order) for order in targets}
    original_read = h.source.terminals
    partials = {
        digest(order.order.submission.submission): tuple(
            partial_original(h.b, order, who) for who in order.order.evaluators
        )
        for order in targets
    }
    h.source.terminals = lambda order, evaluator: (
        None if digest(order) in withheld else original_read(order, evaluator)
    )
    h.source.partial_source = lambda key: partials.get(key, ())
    h.source.inventory_source = lambda key, **kwargs: ()
    opening = h.source.request_opening(h.state)
    opened = HistoricalRegistration(None, opening, SimpleNamespace(block_number=h.block), 1000)
    clocks = {digest(opening): 1000}
    selected = capture(h.block)
    selected.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
    clocks[digest(execution_boundary(selected))] = selected.provenance["timestamp_ms"]
    pending = h.source.observe(h.state, selected, serving=False, opened=opened)
    assert pending.completion == "pending"
    fence = h.source.journal.get("request_tail_fence", h.state.tip_sha256)
    assert fence is not None
    h.block += 1
    inventory_observation = execution_boundary(capture(h.block))
    clocks[digest(inventory_observation)] = 1000 + MINIMUM_REQUEST_OPEN_MS + 1000
    inventories = {
        key: tuple(inventory_original(h.b, ref, inventory_observation) for ref in refs)
        for key, refs in partials.items()
    }
    h.source.inventory_source = lambda key, **kwargs: inventories.get(key, ())
    h.block += 1
    observed = capture(h.block)
    observed.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS + 2000
    clocks[digest(execution_boundary(observed))] = observed.provenance["timestamp_ms"]
    progress = h.source.observe(h.state, observed, serving=False, opened=opened)
    assert progress.completion == "complete"
    native = h.source.read(progress)
    assert len(native.tail.unfinished_hotkeys) == 10
    assert len(native.tail.original_hotkeys) == 11
    assert native.record.tail_fence.model_dump(mode="json", by_alias=True) == fence
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
    assert await h.remote.review(progress) == native.record
    assert await h.remote_signer().attest(progress)
    assert len(withheld) == 10
    h.source = h.reopen()
    h.exporter.source = h.source
    assert h.source.read(progress) == native
    assert await h.remote.review(progress) == native.record
    assert len(h.source.read(progress).tail.unfinished_hotkeys) == 10
