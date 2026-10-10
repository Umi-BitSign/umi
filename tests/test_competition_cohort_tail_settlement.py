"""Tail partitions retain genuine paid credit and ordinary independent certification."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_request_closure import CohortRequestClosure
from umi.competition_cohort_request_partial import PartialRequestManifest
from umi.competition_cohort_service_closure import CohortServiceRequestClosure
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .cohort_request_closure_fixture import build
from .cohort_tail_settlement_fixture import partial_original, tail_harness, tail_observation
from .test_competition_cohort_request_closure import certified_history, put
from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import (
    rebuild_service_closure,
    review_service_closed,
    service_quality,
)
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_closed as service_closed
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import service_quality_inputs as service_quality_inputs
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group

harness = tail_harness


def benchmark_tail(b, *, skip_benchmark=False, skip_paid=False, retain_response=False):
    original = b["closure"]
    benchmark = CohortRequestClosure.model_validate_json(
        b["objects"][original.benchmark_closure_sha256]
    )
    who = identity(b["service_case"].assignment.admission.submission.submission.hotkey)
    tail = tail_observation(b, (who,) if skip_benchmark or skip_paid else ())
    key = b["service_case"].assignment.admission.submission.submission
    partials = ()
    if skip_benchmark:
        selected = next(order for order in b["orders"] if order.order.submission.submission == key)
        partials = (
            partial_original(
                b, selected, selected.order.evaluators[-1], retain_response=retain_response
            ),
        )

    def terminals(order, evaluator):
        if (
            skip_benchmark
            and order.order.submission.submission == key
            and identity(evaluator) == identity(order.order.evaluators[-1])
        ):
            return None
        return b["terminals"].get((digest(order), identity(evaluator)))

    benchmark = build(
        b,
        tail=tail,
        observation=original.observation,
        current_block=original.observation.block,
        terminal_source=terminals,
        partial_source=lambda _: partials,
    )
    put(b, benchmark)
    return benchmark


def recertify_reveal(b, closure):
    b["closure"] = closure
    b["reveal"] = b["reveal"].model_copy(update={"request_closure_sha256": digest(closure)})
    b["history"] = certified_history(
        b, reveal_result=digest(b["reveal"]), unavailable=1_000_000, serving=False
    )


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
def test_native_tail_paid_only_and_benchmark_skips_preserve_credit(service_quality_inputs):
    b = service_quality_inputs
    old_closure, old_history = b["closure"], b["history"]
    quality = service_quality(b)
    raw = canonical_json_bytes(old_closure)
    assert b'"skipped_work"' not in raw
    assert canonical_json_bytes(CohortServiceRequestClosure.model_validate_json(raw)) == raw
    assert b'"skipped_work"' not in canonical_json_bytes(quality)
    # Building requires the still-open prefix; certified replays use all history.
    b["history"] = old_history.model_copy(update={"transitions": old_history.transitions[:2]})
    benchmark = benchmark_tail(b, skip_benchmark=True, retain_response=True)
    closure = rebuild_service_closure(b, benchmark=benchmark)
    assert closure.schema_ == "umi-cohort-request-closure/4"
    assert closure.catalogs[0].terminals == old_closure.catalogs[0].terminals
    assert closure.catalogs[0].skipped_work == ()
    assert len(benchmark.skipped) == 1 and len(benchmark.skipped[0].evaluators) == 1
    assert review_service_closed(b, closure=closure) == closure
    recertify_reveal(b, closure)
    retained = service_quality(b)
    assert retained.work == quality.work
    assert retained.skipped_work == ()

    b["history"] = old_history.model_copy(update={"transitions": old_history.transitions[:2]})
    b["closure"] = old_closure
    benchmark = benchmark_tail(b, skip_paid=True)
    closure = rebuild_service_closure(b, benchmark=benchmark, terminal_source=lambda _: None)
    skipped = b["service_case"].assignment.admission.work_sha256
    assert closure.catalogs[0].terminals == ()
    assert closure.catalogs[0].skipped_work == (skipped,)
    assert benchmark.skipped == () and len(benchmark.participants) == 11
    assert review_service_closed(b, closure=closure) == closure
    for ref in (
        closure.catalogs[0].model_copy(update={"skipped_work": ()}),
        closure.catalogs[0].model_copy(update={"skipped_work": ("ff" * 32,)}),
        closure.catalogs[0].model_copy(update={"skipped_work": (skipped, skipped)}),
        closure.catalogs[0].model_copy(update={"terminals": old_closure.catalogs[0].terminals}),
    ):
        with pytest.raises(ValueError):
            review_service_closed(b, closure=closure.model_copy(update={"catalogs": (ref,)}))
    missing_union = benchmark.model_copy(
        update={"tail": benchmark.tail.model_copy(update={"unfinished_hotkeys": ()})}
    )
    put(b, missing_union)
    with pytest.raises(ValueError, match="exact unfinished miner union"):
        review_service_closed(
            b,
            closure=closure.model_copy(update={"benchmark_closure_sha256": digest(missing_union)}),
        )
    recertify_reveal(b, closure)
    unperformed = service_quality(b)
    assert unperformed.work == () and unperformed.skipped_work == (skipped,)
    allocation = service_quality(b, allocation=True)
    assert allocation.recipients == () and allocation.burn_weight == allocation.service_budget


@pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True)
async def test_native_tail_package_replays_exact_partition_after_independent_certification(
    service_quality_inputs, tmp_path
):
    from umi.competition_cohort_request_inventory import request_inventory_observations
    from umi.competition_cohort_reward_package import replay_reward_package
    from umi.competition_cohort_settlement_service import CohortSettlementService
    from umi.competition_historical_registration import HistoricalRegistration

    from .test_competition_cohort_consumers import tip
    from .test_competition_reward_preparation import native_package

    b = service_quality_inputs
    old_history = b["history"]
    b["history"] = old_history.model_copy(update={"transitions": old_history.transitions[:2]})
    benchmark = benchmark_tail(b, skip_benchmark=True, retain_response=True)
    recertify_reveal(b, rebuild_service_closure(b, benchmark=benchmark))
    completed = {p.submission_sha256 for p in benchmark.participants}
    signable = {
        **b,
        "orders": tuple(
            order for order in b["orders"] if digest(order.order.submission.submission) in completed
        ),
    }
    prepared = await native_package.__wrapped__(signable, tmp_path / "package")
    package = prepared.package
    assert len(package.benchmark.participants) == 10
    assert package.benchmark.skipped_participants == tuple(digest(p) for p in benchmark.skipped)
    included = {o.sha256 for o in package.objects}
    assert digest(benchmark) in included
    assert all(ref.terminal_sha256 in included for ref in benchmark.skipped[0].evaluators)
    assert set(benchmark.skipped[0].retained_objects) <= included
    assert set(benchmark.skipped[0].inventory_sha256s) <= included
    preserved_responses = []
    for key in benchmark.skipped[0].retained_objects:
        manifest = PartialRequestManifest.model_validate_json(b["objects"][key])
        for response in manifest.responses:
            assert response.retirement_sha256 is None
            assert response.response_sha256 in included
            assert response.selection_sha256 in included
            preserved_responses.append(response)
    assert preserved_responses

    # The recurring settlement host authenticates every retained snapshot and
    # all three clock boundaries before retaining its package binding.
    tail = benchmark.tail
    timestamps = {
        digest(tail.opened_observation): tail.opened_timestamp_ms,
        digest(tail.selected_observation): tail.selected_timestamp_ms,
        digest(tail.observation): tail.observed_timestamp_ms,
    }
    expected = {
        *timestamps,
        *(digest(o) for o in request_inventory_observations(benchmark, b["objects"].__getitem__)),
    }
    proof_reads, unavailable = set(), set()

    async def read_proof(observation):
        key = digest(observation)
        proof_reads.add(key)
        if key in unavailable:
            raise FileNotFoundError("original snapshot proof unavailable")
        return b"native proof fixture", b"native metadata fixture"

    async def review_proof(observation, raw, metadata):
        return HistoricalRegistration(
            None,
            observation,
            SimpleNamespace(block_number=2**53 - 1),
            timestamps.get(digest(observation), tail.observed_timestamp_ms),
        )

    host = SimpleNamespace(
        proofs=SimpleNamespace(read=read_proof),
        provider=SimpleNamespace(review_archive=review_proof),
    )
    originals = {o.sha256: canonical_json_bytes(o.value) for o in package.objects}
    data = SimpleNamespace(inputs=package.inputs, objects=originals.__getitem__)
    await CohortSettlementService._request_inventory_proofs(host, data)
    assert proof_reads == expected
    unavailable.add(digest(tail.selected_observation))
    with pytest.raises(FileNotFoundError, match="original snapshot proof unavailable"):
        await CohortSettlementService._request_inventory_proofs(host, data)
    unavailable.clear()
    timestamps[digest(tail.selected_observation)] -= 1
    with pytest.raises(ValueError, match="native original timestamp proof"):
        await CohortSettlementService._request_inventory_proofs(host, data)
    timestamps[digest(tail.selected_observation)] += 1

    def replay(selected):
        return replay_reward_package(
            selected,
            b["policy"],
            prepared.store,
            package.inputs.history,
            expected_package_sha256=digest(selected),
            expected_cohort_sha256=digest(package.inputs.history.plan),
            expected_tip_sha256=tip(package.inputs.history),
            current_block=2**53 - 1,
            expected_terms_sha256=prepared.requirement.terms_sha256,
            expected_catalog_sha256s=prepared.requirement.catalog_sha256s,
            maximum_promotion_bytes=1_000_000,
        )

    assert replay(package) == prepared.allocation
    changed = package.benchmark.model_copy(update={"skipped_participants": ()})
    with pytest.raises(ValueError):
        replay(package.model_copy(update={"benchmark": changed}))
    for required in (
        benchmark.skipped[0].evaluators[0].terminal_sha256,
        *benchmark.skipped[0].inventory_sha256s,
    ):
        with pytest.raises((ValueError, KeyError, FileNotFoundError)):
            replay(
                package.model_copy(
                    update={"objects": tuple(o for o in package.objects if o.sha256 != required)}
                )
            )
