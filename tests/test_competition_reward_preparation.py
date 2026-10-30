"""Replay/projection lifecycle with native packages, signatures and state readers.

Lifecycle fault tests substitute the complete-history selection boundary. The
combined test uses native history, package replay and registration projection.
RPC/finality/trie/SCALE and miner video/inference are synthetic ports; installed
signing and chain submission are not qualified here.
"""

import asyncio
import hashlib
import json
import logging
import os
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_preparation as preparation
from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_quality import ClosedQualityReview
from umi.competition_cohort_quality_signing import build_quality_manifest
from umi.competition_cohort_reward_allocation import retain_reward_allocation
from umi.competition_cohort_reward_package import RewardReplayInputs, prepare_reward_package
from umi.competition_cohort_service_certification import (
    collect_service_allocation,
    sign_service_allocation,
)
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.competition_reward_control import FinalizedRewardControlProvider
from umi.competition_reward_decisions import (
    HistoricalStandingRewardSelection,
    HistoryVerifiedStandingRewardSelection,
    RewardActivation,
    RewardControlDecision,
    StandingRewardControlReader,
    StandingRewardSeries,
)
from umi.competition_reward_manifest import RewardReplayRequirement, StandingRewardManifest
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.competition_round_journal import RoundJournal
from umi.competition_store import CompetitionStore
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.historical_header_recovery import HistoricalHeaderRecoveryPending
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_service_grants as grant_fixtures
from . import test_open_competition as competition_tests
from .logging_helpers import json_progress_payloads
from .test_competition_cohort_consumers import tip
from .test_competition_cohort_quality import certificates_for
from .test_competition_cohort_roster import close
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import harness as harness
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
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_closed as service_closed
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import service_quality
from .test_competition_cohort_service_grants import service_quality_inputs as service_quality_inputs
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_competition_model_burn import burn_policy
from .test_competition_reward_control import commitment
from .test_competition_reward_control_archive import make_historical
from .test_competition_reward_decisions import signatures, signed
from .test_competition_reward_eligibility import configure_eligibility
from .test_competition_reward_history import make_history_case
from .test_competition_reward_history_selection import current as current_state
from .test_competition_reward_registrations import registered_case as registered_case
from .test_competition_reward_registrations import set_members
from .test_competition_two_task_profile import launch_suite
from .test_drand import pulse_record
from .test_open_competition import bundle_at, wallet

original_policy = competition_tests.policy
original_chain = grant_fixtures.chain
original_chain_config = grant_fixtures.chain_config
pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True),
]


@pytest.fixture
def service_catalog_inputs(request):
    return getattr(request, "param", True)


@pytest.fixture
def base_policy(original_policy):
    return burn_policy(original_policy, owner="Burn")


@pytest.fixture
def chain_config(original_chain_config):
    # Synthetic early bootstrap keeps complete control-history tests bounded.
    # Production pins and verified-finality checks are unchanged.
    return original_chain_config.model_copy(
        update={
            "minimum_finalized_block": 150,
            "finality_pin": original_chain_config.finality_pin.model_copy(
                update={
                    "bootstrap_block_number": 149,
                }
            ),
        }
    )


@pytest.fixture
def chain(original_chain):
    item = original_chain
    item.finality.ref = replace(item.finality.ref, block_number=2000)
    set_members(item, [wallet(n).hotkey.ss58_address for n in ("Burn", "Alice", "Bob")])
    item.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = wallet(
        "Burn"
    ).hotkey.ss58_address
    item.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))] = "Burn"
    return item


@pytest.fixture(autouse=True)
def known_video_bytes(monkeypatch):
    monkeypatch.setattr("tests.test_competition_cohort_origin._HEIGHT", 2000)

    def suite(policy):
        value = launch_suite(policy)
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

    monkeypatch.setattr("tests.test_competition_cohort_consumers.suite_for", suite)


@pytest.fixture
async def native_package(service_quality_inputs, tmp_path):
    b = service_quality_inputs
    sr = service_quality(b, review=True)
    br = ClosedQualityReview(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        suite=b["suite"],
        policy=b["policy"],
        history=b["history"],
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        pulses=lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(b["history"]),
        current_block=2**53 - 1,
        transport=b["transport"],
        expected_catalogs=(b["service_case"].assignment.catalog,),
        expected_seals=(b["service_seal"],),
    )
    certificates = await certificates_for(b, br, tmp_path)
    benchmark = build_quality_manifest(br, certificates.get)

    def journal(name):
        return RoundJournal(tmp_path / ("preparation-" + name), {"scope": "preparation-test"})

    votes = []
    for name in ("Charlie", "Dave"):

        async def sign(body, name=name):
            return sign_object(body, wallet(name))

        votes.append(
            await sign_service_allocation(journal(name), sr, wallet(name).hotkey.ss58_address, sign)
        )
    service = collect_service_allocation(journal("collector"), sr, votes)
    store = CompetitionStore(tmp_path / "promotion", b["policy"])
    bundle = bundle_at(tmp_path / "model")
    preserve_bundle(bundle, tmp_path / "model", tmp_path / "archive", b["policy"])
    store.initialize_baseline(bundle, tmp_path / "archive")
    allocation = retain_reward_allocation(
        journal("allocation"), store, service, sr, benchmark, br, maximum_promotion_bytes=1_000_000
    )
    start = b["history"].transitions[-1].transition.observed_at_block + 100
    h = close(b["history"], b["policy"], b["decisions"], start, digest(benchmark))
    h = close(h, b["policy"], b["decisions"], start + 10, digest(service))
    h = close(h, b["policy"], b["decisions"], start + 20, digest(allocation))
    c = b["service_case"]
    inputs = RewardReplayInputs(
        closure=b["closure"],
        roster=b["roster"],
        suite=b["suite"],
        transport=b["transport"],
        terms=c.terms,
        reveal=b["reveal"],
        catalogs=(c.assignment.catalog,),
        seals=(b["service_seal"],),
        history=h,
    )
    requirement = RewardReplayRequirement(
        cohort_sha256=digest(h.plan),
        terms_sha256=digest(c.terms),
        catalog_sha256s=(digest(c.assignment.catalog.catalog),),
    )
    package = prepare_reward_package(
        inputs,
        allocation,
        service,
        benchmark,
        b["policy"],
        store,
        b["objects"].__getitem__,
        b["decisions"].__getitem__,
        iter(b["records"]),
        lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(h),
        current_block=2**53 - 1,
        expected_terms_sha256=requirement.terms_sha256,
        expected_catalog_sha256s=requirement.catalog_sha256s,
        maximum_promotion_bytes=1_000_000,
    )
    return SimpleNamespace(
        package=package, store=store, requirement=requirement, allocation=allocation
    )


@pytest.fixture
async def preparation_case(native_package, registered_case, tmp_path, monkeypatch, request):
    p, item = native_package, registered_case
    h = p.package.inputs.history
    item.finality.ref = replace(
        item.finality.ref,
        block_number=max(
            item.finality.ref.block_number, h.transitions[-1].transition.observed_at_block + 100
        ),
    )
    await item.provider.aclose()
    provider = FinalizedRewardControlProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    control_hotkey = wallet("Ferdie").hotkey.ss58_address
    p.manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(item.policy),
        cohorts=(p.requirement,),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(item.policy),
        policy_epoch=1,
        manifest_sha256=digest(p.manifest),
        control_hotkey=control_hotkey,
        recovery=h.authority,
        cohorts=(h.plan,),
        validators=(item.hotkey,),
        maximum_proof_lag_blocks=2,
        maximum_transaction_lifetime_blocks=getattr(request, "param", 2),
        lifetime="until_superseded_or_revoked",
    )
    reader = StandingRewardControlReader(
        tmp_path / "standing-reader",
        series,
        item.policy,
        expected_series_sha256=digest(series),
        expected_chain_config_sha256=digest(item.config),
        maximum_bytes=8 * 1024**2,
    )
    objects = {}
    history_boundary = object()

    def history_selection(control, source, history):
        assert history is history_boundary
        selection = reader.select(control, source)
        return HistoryVerifiedStandingRewardSelection(
            selection, history, selection if selection.state == "selected" else None
        )

    monkeypatch.setattr(reader, "select_history", history_selection)
    genesis = signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/1",
            series_sha256=digest(series),
            sequence=0,
            predecessor_sha256=None,
            kind="admit_series",
            observed_at_block=160,
            activation=None,
        )
    )
    activation = RewardActivation(
        cohort_sha256=digest(h.plan),
        allocation_sha256=digest(p.allocation),
        package_sha256=digest(p.package),
        recovery_tip_sha256=tip(h),
        prior_opportunity_sha256="cc" * 32,
    )
    active = signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/1",
            series_sha256=digest(series),
            sequence=1,
            predecessor_sha256=digest(genesis.decision),
            kind="activate",
            observed_at_block=item.finality.ref.block_number - 10,
            activation=activation,
        )
    )
    for decision in (genesis, active):
        objects[digest(decision.decision)] = canonical_json_bytes(decision)

    async def control(decision=active, *, committed=None):
        item.rpc.values[("Commitments", "CommitmentOf", (78, control_hotkey))] = commitment(
            digest(decision.decision),
            decision.decision.observed_at_block if committed is None else committed,
        )
        return await provider.collect_control(control_hotkey)

    def reopen(**changes):
        options = dict(maximum_promotion_bytes=1_000_000)
        options.update(changes)
        return StandingRewardPreparation(reader, p.store, p.manifest, **options)

    async def observations():
        observed = await control()
        chain = await provider.collect_registered_weights(item.hotkey, at=observed.snapshot)
        return dict(
            control=observed,
            history=history_boundary,
            source=objects.__getitem__,
            chain=chain,
            chain_config=item.config,
        )

    p.reader, p.reopen, p.item, p.provider = reader, reopen, item, provider
    p.control, p.active, p.objects, p.observations = control, active, objects, observations
    p.history = history_boundary
    p.preparation = reopen()
    try:
        yield p
    finally:
        await provider.aclose()


def replay_args(observations):
    return {k: observations[k] for k in ("control", "history", "source")}


async def test_baseline_candidate_requires_its_native_preparation_owner(
    preparation_case, monkeypatch
):
    p = preparation_case
    observed = await p.observations()
    prepared = await p.preparation.prepare(p.package, **replay_args(observed))

    def forbid_replay(*args, **kwargs):
        raise AssertionError("candidate selection must reuse native replay without payload reads")

    monkeypatch.setattr(preparation, "_replay_detached_reward_package", forbid_replay)
    with pytest.raises(ValueError, match="native replay owner"):
        p.preparation.baseline_candidate(replace(prepared, _owner=None))
    with pytest.raises(ValueError, match="native replay owner"):
        p.reopen().baseline_candidate(prepared)
    review_options = dict(
        target_cohort_sha256="ff" * 32,
        previous=p.store.reviewed_promotion_head(
            prepared.allocation.round_sha256, maximum_bytes=1_000_000
        ),
        not_before_block=prepared.reviewed_at_block,
        valid_through_block=p.reader.policy.valid_through_block,
    )
    with pytest.raises(ValueError, match="native replay owner"):
        p.preparation.baseline_review(replace(prepared, _owner=None), **review_options)
    with pytest.raises(ValueError, match="native replay owner"):
        p.reopen().baseline_review(prepared, **review_options)
    if prepared.allocation.model_award is None:
        with pytest.raises(ValueError, match="has no cohort model award"):
            p.preparation.baseline_candidate(prepared)
        with pytest.raises(ValueError, match="has no cohort model award"):
            p.preparation.baseline_review(prepared, **review_options)
    else:
        candidate = p.preparation.baseline_candidate(prepared)
        assert candidate is None or candidate.reference_promotion_authorized is False


@pytest.fixture
async def historical_preparation_case(preparation_case, monkeypatch):
    """Package lifecycle tests substitute only historical control selection.

    The complete integration case below uses the actual historical reader.
    """
    p = preparation_case
    observed = await p.observations()
    current = p.reader.select_history(**replay_args(observed))
    control = SimpleNamespace(snapshot=observed["control"].snapshot)
    chosen = SimpleNamespace(current=current)

    def review(actual, source, history):
        assert actual is control and history is p.history
        selected = chosen.current
        return HistoricalStandingRewardSelection(
            control,
            selected.selection,
            history,
            selected.effective_selection,
            initial_selection=selected.initial_selection,
        )

    monkeypatch.setattr(p.reader, "review_history", review)
    return (
        p,
        control,
        chosen,
        dict(control=control, history=p.history, source=p.objects.__getitem__),
    )


@pytest.mark.parametrize("later", ["draining", "selected", "revoked"])
async def test_initial_package_is_recoverable_after_successor_or_revocation(
    historical_preparation_case, later
):
    p, _, chosen, args = historical_preparation_case
    original = chosen.current.selection
    successor = replace(
        original,
        sequence=2,
        state=later,
        activation=None
        if later == "revoked"
        else original.activation.model_copy(update={"cohort_sha256": "ff" * 32}),
    )
    chosen.current = replace(
        chosen.current,
        selection=successor,
        effective_selection=successor if later == "selected" else None,
        initial_selection=original,
    )
    ready = await p.preparation.prepare_initial(p.package, **args)
    assert ready.activation == original.activation
    assert ready.allocation == p.allocation
    assert not ready.chain_submission_authorized
    with pytest.raises(ValueError):
        await p.preparation.prepare_historical(p.package, **args)


async def test_historical_package_uses_effective_predecessor_during_drain(
    historical_preparation_case,
):
    p, _, chosen, args = historical_preparation_case
    chosen.current = replace(
        chosen.current,
        selection=replace(
            chosen.current.selection,
            state="draining",
            activation=p.active.decision.activation.model_copy(
                update={"package_sha256": "dd" * 32}
            ),
        ),
    )
    result = await p.preparation.prepare_historical(p.package, **args)
    assert result.activation == p.active.decision.activation
    assert result.allocation == p.allocation and not result.chain_submission_authorized


@pytest.mark.parametrize("state", ["admitted", "draining", "revoked"])
async def test_historical_package_requires_an_effective_allocation(
    historical_preparation_case,
    state,
):
    p, _, chosen, args = historical_preparation_case
    chosen.current = replace(
        chosen.current,
        selection=replace(chosen.current.selection, state=state),
        effective_selection=None,
    )
    with pytest.raises(ValueError, match="no effective reward package"):
        await p.preparation.prepare_historical(p.package, **args)


async def test_later_cached_package_cannot_backdate_certification(
    historical_preparation_case,
    monkeypatch,
):
    p, control, _, args = historical_preparation_case
    replay = preparation._replay_detached_reward_package
    blocks = []

    def checked(*a, **kw):
        blocks.append(kw["current_block"])
        return replay(*a, **kw)

    monkeypatch.setattr(preparation, "_replay_detached_reward_package", checked)
    later = await p.preparation.prepare_historical(p.package, **args)
    assert await p.preparation.prepare_historical(p.package, **args) is later
    certification = p.package.inputs.history.transitions[-1].transition.observed_at_block
    control.snapshot = replace(control.snapshot, block_number=certification - 1)
    with pytest.raises(ValueError):
        await p.preparation.prepare_historical(p.package, **args)
    control.snapshot = replace(control.snapshot, block_number=certification + 1)
    earlier = await p.preparation.prepare_historical(p.package, **args)
    assert earlier is not later and earlier.allocation == later.allocation
    assert earlier.reviewed_at_block == certification + 1
    assert await p.preparation.prepare_historical(p.package, **args) is earlier
    assert blocks == [later.reviewed_at_block, certification - 1, certification + 1]
    control.snapshot = replace(control.snapshot, block_number=later.reviewed_at_block)
    assert await p.preparation.prepare_historical(p.package, **args) is earlier


async def test_historical_preparation_rechecks_manifest_and_package_identity(
    historical_preparation_case,
):
    p, _, _, args = historical_preparation_case
    await p.preparation.prepare_historical(p.package, **args)
    with pytest.raises(ValueError, match="differs from current standing activation"):
        await p.preparation.prepare_historical(
            p.package.model_copy(update={"policy_sha256": "ee" * 32}), **args
        )
    p.preparation.manifest = p.manifest.model_copy(update={"policy_sha256": "ee" * 32})
    with pytest.raises(ValueError, match="authority changed"):
        await p.preparation.prepare_historical(p.package, **args)


@pytest.mark.parametrize("preparation_case", [4], indirect=True)
async def test_native_package_projection_retains_original_signing_inputs(
    preparation_case, tmp_path
):
    from umi.competition_reward_transactions import StandingWeightJournal

    t = preparation_case
    observations = await t.observations()
    prepared = await t.preparation.prepare(t.package, **replay_args(observations))
    observations = await t.observations()
    chain = observations["chain"]
    options = dict(
        series_sha256=digest(t.reader.series),
        validator_hotkey=chain.validator_hotkey,
        chain_config_sha256=chain.chain_config_sha256,
        maximum_bytes=32 * 1024**2,
    )
    journal = StandingWeightJournal(tmp_path / "native-transactions", **options)
    pending = await t.preparation.reserve_transaction(
        prepared, journal, mortality_period=4, **observations
    )
    assert pending.intent.activation_sha256 == digest(prepared.activation)
    assert pending.intent.projection.allocation_sha256 == digest(prepared.allocation)
    assert pending.intent.destinations == tuple(range(chain.registered_uid_count))
    assert sum(pending.intent.weights) == 65535
    assert journal._object(pending.intent.chain_evidence_sha256) == chain.evidence
    assert (
        journal._object(pending.intent.control_evidence_sha256) == observations["control"].evidence
    )
    assert pending.signed is None and pending.chain_submission_authorized is False
    assert StandingWeightJournal(journal.journal.root, **options).pending() == pending


async def test_native_package_replay_is_reused_but_projection_needs_fresh_control(
    preparation_case, monkeypatch
):
    p = preparation_case
    observations = await p.observations()
    replay = preparation._replay_detached_reward_package
    calls = []
    virtual_time = [observations["control"].captured_monotonic_ns]

    def slow(*args, **kwargs):
        calls.append(1)
        value = replay(*args, **kwargs)
        virtual_time[0] = (
            max(
                observations["control"].expires_monotonic_ns,
                observations["chain"].expires_monotonic_ns,
            )
            + 1
        )
        return value

    monkeypatch.setattr(preparation, "_replay_detached_reward_package", slow)
    with monkeypatch.context() as patch:
        patch.setattr("time.monotonic_ns", lambda: virtual_time[0])
        ready = await p.preparation.prepare(p.package, **replay_args(observations))
        assert ready.allocation == p.allocation and not ready.chain_submission_authorized
        with pytest.raises(ValueError, match="proof adapter"):
            await p.preparation.project(ready, **observations)
    fresh = await p.observations()
    assert await p.preparation.prepare(p.package, **replay_args(fresh)) is ready
    result = await p.preparation.project(ready, **fresh)
    assert sum(result.projection.weights) == 65535
    assert result.prepared is ready and not result.chain_submission_authorized
    assert calls == [1]
    with pytest.raises(ValueError, match="native replay owner"):
        await p.reopen().project(ready, **fresh)
    with pytest.raises(ValueError, match="native replay owner"):
        await p.preparation.project(replace(ready, reviewed_at_block=1), **fresh)
    # A replacement preparation owner reconstructs the review from retained
    # package/model bytes; it cannot import the old owner's success token.
    restarted = p.reopen()
    restored = await restarted.prepare(p.package, **replay_args(await p.observations()))
    assert restored is not ready and restored.allocation == ready.allocation
    assert calls == [1, 1]
    assert (
        await restarted.project(restored, **(await p.observations()))
    ).projection == result.projection
    # A cached result never turns a proven revocation into fallback rewards.
    revoke = signed(
        p.active.decision.model_copy(
            update={
                "sequence": 2,
                "predecessor_sha256": digest(p.active.decision),
                "kind": "revoke",
                "activation": None,
                "observed_at_block": p.item.finality.ref.block_number,
            }
        )
    )
    p.objects[digest(revoke.decision)] = canonical_json_bytes(revoke)
    revoked = await p.control(revoke)
    with pytest.raises(ValueError, match="no active reward package"):
        await p.preparation.project(ready, **{**fresh, "control": revoked})


async def test_cancellation_retains_completed_native_replay(preparation_case, monkeypatch):
    p = preparation_case
    started, release = threading.Event(), threading.Event()
    replay, calls = preparation._replay_detached_reward_package, []

    def delayed(*args, **kwargs):
        calls.append(1)
        started.set()
        assert release.wait(30)
        return replay(*args, **kwargs)

    monkeypatch.setattr(preparation, "_replay_detached_reward_package", delayed)
    observations = await p.observations()
    task = asyncio.create_task(p.preparation.prepare(p.package, **replay_args(observations)))
    try:
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    ready = await p.preparation.prepare(p.package, **replay_args(await p.observations()))
    assert ready.allocation == p.allocation and calls == [1]


async def test_pending_activation_can_prepare_but_cannot_project(preparation_case):
    p = preparation_case
    observations = await p.observations()
    observations["control"] = await p.control(
        committed=observations["control"].snapshot.block_number
    )
    ready = await p.preparation.prepare(p.package, **replay_args(observations))
    assert ready.allocation == p.allocation
    with pytest.raises(ValueError, match="current standing selection"):
        await p.preparation.project(ready, **observations)


@pytest.mark.parametrize("mutation", ["missing", "different_activation"])
async def test_projection_requires_selected_and_effective_allocation_to_agree(
    preparation_case, monkeypatch, mutation
):
    p = preparation_case
    observations = await p.observations()
    ready = await p.preparation.prepare(p.package, **replay_args(observations))
    select = p.reader.select_history

    def inconsistent(*args):
        value = select(*args)
        effective = None
        if mutation == "different_activation":
            effective = replace(
                value.effective_selection,
                activation=value.effective_selection.activation.model_copy(
                    update={"cohort_sha256": "dd" * 32}
                ),
            )
        return replace(value, effective_selection=effective)

    monkeypatch.setattr(p.reader, "select_history", inconsistent)
    with pytest.raises(ValueError, match="current standing selection"):
        await p.preparation.project(ready, **observations)


async def test_failed_replay_retries_and_independent_bindings_are_enforced(
    preparation_case, monkeypatch
):
    p = preparation_case
    observations = await p.observations()
    replay, calls = preparation._replay_detached_reward_package, []

    def interrupted(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("promotion archive temporarily unavailable")
        return replay(*args, **kwargs)

    monkeypatch.setattr(preparation, "_replay_detached_reward_package", interrupted)
    with pytest.raises(OSError):
        await p.preparation.prepare(p.package, **replay_args(observations))
    ready = await p.preparation.prepare(p.package, **replay_args(await p.observations()))
    assert ready.allocation == p.allocation and calls == [1, 1]
    for field, value in (("terms_sha256", "ff" * 32), ("catalog_sha256s", ("ff" * 32,))):
        changed = p.manifest.model_copy(
            update={"cohorts": (p.requirement.model_copy(update={field: value}),)}
        )
        with pytest.raises(ValueError, match="manifest differs"):
            StandingRewardPreparation(p.reader, p.store, changed, maximum_promotion_bytes=1_000_000)
    with pytest.raises(ValueError, match="differs from current standing activation"):
        await p.preparation.prepare(
            p.package.model_copy(update={"policy_sha256": "ff" * 32}),
            **replay_args(await p.observations()),
        )
    with pytest.raises(ValueError, match="byte bound"):
        await p.reopen(maximum_package_bytes=1024).prepare(
            p.package, **replay_args(await p.observations())
        )


@pytest.fixture
async def complete_preparation_case(preparation_case, tmp_path, monkeypatch, request):
    p = preparation_case
    item = p.item
    validator_hotkey = item.hotkey
    series = p.reader.series
    await p.provider.aclose()
    await configure_eligibility(item, monkeypatch, tmp_path)
    await item.provider.aclose()
    runtime_consensus = (
        request.getfixturevalue("runtime_consensus")
        if "runtime_consensus" in request.fixturenames
        else None
    )
    if runtime_consensus is not None:
        item.rpc.values[("SubtensorModule", "SubnetEpochConsensus", (78,))] = runtime_consensus
    options = getattr(request, "param", "matching")
    scale = options if isinstance(options, dict) else {}
    variant = scale.get("kind", options)
    if variant in {"opportunity", "signing_admission", "coordinator"}:
        from umi.competition_reward_manifest import (
            RewardOpportunityTerms,
            StandingRewardOpportunityManifest,
        )

        p.manifest = StandingRewardOpportunityManifest(
            **(
                p.manifest.model_dump(by_alias=True)
                | {
                    "schema": "umi-standing-reward-manifest/2",
                    "opportunity": RewardOpportunityTerms(
                        runtime_profile_sha256=digest(item.profile),
                        maximum_interval_ms=12000,
                        minimum_validator_ms=12000 * scale.get("intervals", 1),
                    ),
                }
            )
        )
        series = series.model_copy(update={"manifest_sha256": digest(p.manifest)})
        if scale:
            from umi.open_competition import identity

            series = series.model_copy(
                update={
                    "validators": tuple(sorted((validator_hotkey, item.members[1]), key=identity))
                }
            )
    if variant in {"control_publication", "coordinator"}:
        item.config = item.config.model_copy(
            update={
                "proof_rpc_fallback_urls": (
                    "wss://backup1.example.org",
                    "wss://backup2.example.org",
                ),
            }
        )
        item.rpc.values[("System", "Account", (series.control_hotkey,))] = {"nonce": 7}
    original_verify = type(item.verifier).__call__

    def verify_code(self, **kw):
        if kw["storage_key"] == b":code":
            return kw["expected_value"] == item.code and kw["proof"] == (b"proof",)
        return original_verify(self, **kw)

    monkeypatch.setattr(type(item.verifier), "__call__", verify_code)
    item.hotkey = series.control_hotkey
    item.spec = ("Commitments", "CommitmentOf", (78, item.hotkey))
    first = series.recovery.authority.issued_at_block
    activation_block = p.package.inputs.history.transitions[-1].transition.observed_at_block + 1
    end = (
        activation_block
        + series.maximum_proof_lag_blocks
        + series.maximum_transaction_lifetime_blocks
    )
    coverage_first = end
    if scale:
        end += scale["intervals"] + scale["outage_blocks"] + 256
    if variant in {"journal", "opportunity"}:
        # Both adjacent endpoints are after the activation fence. This adds
        # one block only to the retention/recovery case, not selection tests.
        end += 1
    # Seed the proved chain row from the native package using the same public
    # projection as a writer, then the pinned pallet's storage conversion.
    from umi.competition_cohort_reward_allocation import project_reward_allocation
    from umi.open_competition import BurnDestination, Registration, RegistrationSnapshot
    from umi.weight_storage import subtensor_stored_weights

    members = tuple(Registration(uid=i, hotkey=k) for i, k in enumerate(item.members))
    projection = project_reward_allocation(
        p.allocation,
        RegistrationSnapshot(
            network="finney",
            netuid=78,
            block=end,
            block_hash=item.finality.ref.block_hash,
            registrations=members,
            burn_destination=BurnDestination(uid=0, hotkey=item.members[0], mode="Burn"),
        ),
        item.policy,
        current_block=end,
    )
    weights = dict(zip(projection.uids, projection.weights, strict=True))
    stored = subtensor_stored_weights(tuple(weights.get(i, 0) for i in range(len(members))))
    row = list(enumerate(stored))
    if "coverage_test_row" in request.fixturenames:
        row = request.getfixturevalue("coverage_test_row")
    if variant == "raw_row":
        row = [(i, weights.get(i, 0)) for i in range(len(members))]
        assert tuple(v for _, v in row) != stored
    elif variant == "missing_recipient":
        dropped = next(i for i, value in row if value > 0)
        row = [(i, v) for i, v in row if i != dropped]
    elif variant == "extra_recipient":
        zero = next(i for i, value in row if value == 0)
        row[zero] = (zero, 1)
    elif variant == "sparse_zeros":
        assert any(v == 0 for _, v in row)
        row = [(i, v) for i, v in row if v]
    elif variant == "permit_missing":
        item.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))] = [False] * len(members)
    item.rpc.values[("SubtensorModule", "Weights", (78, 3))] = row
    item.rpc.values[("SubtensorModule", "LastUpdate", (78,))] = [0, 0, 0, first]
    if scale:
        item.rpc.values[("SubtensorModule", "Weights", (78, 1))] = row
        item.rpc.values[("SubtensorModule", "LastUpdate", (78,))] = [0, first, 0, first]
        item.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))] = [False, True, False, True]
    # The synthetic window spans more than the default activity cutoff.
    item.rpc.values[("SubtensorModule", "ActivityCutoffFactorMilli", (78,))] = 100_000
    item.finality.ref = replace(item.finality.ref, block_number=first)

    def reader():
        return StandingRewardControlReader(
            tmp_path / "complete-standing-reader",
            series,
            item.policy,
            expected_series_sha256=digest(series),
            expected_chain_config_sha256=digest(item.config),
            maximum_bytes=8 * 1024**2,
        )

    genesis = signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/1",
            series_sha256=digest(series),
            sequence=0,
            predecessor_sha256=None,
            kind="admit_series",
            observed_at_block=first,
            activation=None,
        )
    )
    active = signed(
        p.active.decision.model_copy(
            update={
                "series_sha256": digest(series),
                "predecessor_sha256": digest(genesis.decision),
                "observed_at_block": activation_block,
            }
        )
    )
    objects = {digest(v.decision): canonical_json_bytes(v) for v in (genesis, active)}
    writes = {n: () for n in range(first, end + 1)}
    writes[first], writes[activation_block] = (
        (digest(genesis.decision),),
        (digest(active.decision),),
    )
    if variant == "signing_admission":
        writes[first] = ()
    elif variant == "coordinator":
        writes[first + 1], writes[first] = writes[first], ()
    elif variant == "control_publication":
        writes[activation_block + 1] = writes[activation_block]
        writes[activation_block] = ()
    c = SimpleNamespace(
        control=item,
        series=series,
        reopen=reader,
        reader=reader(),
        genesis=genesis,
        active=active,
        objects=objects,
        source=objects.__getitem__,
        control_writes=writes,
        additional_state=dict(item.rpc.values),
    )
    h = await make_historical(c, "exact_runtime", monkeypatch, tmp_path)
    h = await make_history_case(h, monkeypatch, tmp_path, distance=end - first + 1)
    h.reader = h.new_reader(maximum_bytes=(256 if scale else 64) * 1024**2)
    h.package_case, h.validator_hotkey, h.variant = p, validator_hotkey, variant
    h.coverage_first, h.coverage_scale = coverage_first, scale
    try:
        yield h
    finally:
        await item.provider.aclose()


def current_control_finality(h, height):
    import json

    from umi.chain_evidence import FinalizedSnapshotRef
    from umi.finalized_ancestry import encode_rpc_header

    # Synthetic finality boundary; production proof, nonce, archive and
    # complete history consumers remain unpatched.
    w = h.source.w
    header = w.headers[w.heights[height]]
    ref = FinalizedSnapshotRef(height, w.heights[height], header["parentHash"], header["stateRoot"])
    timestamp = w.original.timestamp_ms + (height - h.old.height) * 12000
    evidence = canonical_json_bytes(
        json.loads(h.old.finality_evidence)
        | {
            "block": {"scale_header": encode_rpc_header(header)},
        }
    )
    h.blocks[height] = replace(
        h.old,
        height=height,
        block_hash=ref.block_hash,
        state_root=ref.state_root,
        timestamp_ms=timestamp,
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )

    async def after(requested_height, *, maximum_distance):
        assert requested_height <= height and maximum_distance is None
        return h.blocks[height]

    h.item.finality.verified_block_after = after
    h.item.finality.ref = ref
    h.item.clock.now = timestamp + 1000
    h.item.provider._startup_floor = h.old.height - 1
    if h.item.provider._task is None:
        h.item.provider._task = asyncio.create_task(asyncio.Event().wait())


@pytest.mark.parametrize("preparation_case", [8], indirect=True)
@pytest.mark.parametrize("complete_preparation_case", ["control_publication"], indirect=True)
async def test_native_control_publisher_recovers_original_proofs_and_finalized_history(
    complete_preparation_case, tmp_path
):
    from umi.competition_reward_control_journal import RewardControlTransactionJournal
    from umi.competition_reward_control_publisher import StandingControlPublisher
    from umi.competition_reward_control_signing import collect_control_signing_state
    from umi.competition_reward_files import StandingRewardFiles
    from umi.private_files import publish_private_model

    h, c, p = (
        complete_preparation_case,
        complete_preparation_case.c,
        complete_preparation_case.package_case,
    )
    files = StandingRewardFiles(
        tmp_path / "native-publisher-files",
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=8 * 1024**2,
    )
    for decision in (c.genesis, c.active):
        files.retain_decision(decision)
    publish_private_model(
        files.root / "packages" / (digest(p.package) + ".json"),
        p.package,
        maximum_bytes=files.maximum_package_bytes,
    )
    journal = RewardControlTransactionJournal(
        tmp_path / "native-control-transactions",
        c.series,
        config_sha256=digest(h.item.config),
        maximum_bytes=8 * 1024**2,
    )

    current_control_finality(h, c.active.decision.observed_at_block)
    # Retain original nonce proofs before the later finality observation.
    original = await collect_control_signing_state(h.item.provider, h.item.hotkey)
    reserved = journal.reserve(c.active, original, mortality_period=8)
    from umi.competition_reward_control_signing import review_control_signing_state

    current_control_finality(h, h.end)
    files_before = {
        path: path.read_bytes()
        for kind in ("packages", "decisions")
        for path in (files.root / kind).glob("*.json")
    }
    for restart in (False, True):
        if restart:
            c.reader, h.reader = c.reopen(), await h.restart()
            current_control_finality(h, h.end)
            h.offline_through = h.end - 1
        recovered = await review_control_signing_state(
            h.item.provider,
            hotkey=h.item.hotkey,
            control_evidence=original.control.evidence,
            nonce_evidence=original.nonce_evidence,
            metadata=original.runtime.metadata_bytes,
        )
        assert recovered.nonce == 7 and recovered.control.snapshot == original.control.snapshot
        publisher = StandingControlPublisher(
            reader=c.reader,
            provider=h.item.provider,
            history=h.reader,
            journal=journal,
            files=files,
            signer=wallet("Ferdie").hotkey,
            mortality_period=8,
            maximum_history_blocks=4096,
        )
        with publisher.hold_writer():
            for _ in range(100):
                try:
                    result = await publisher.step((c.genesis, c.active))
                except HistoricalHeaderRecoveryPending:
                    continue
                if result.status != "history_pending":
                    break
            else:
                pytest.fail("native control publication recovery did not converge")
            assert result.status == "control_finalized"
            assert result.decision_sha256 == digest(c.active.decision)
            with pytest.raises(ValueError, match="selected prefix"):
                await publisher.step((c.genesis,))
        assert journal.pending() == reserved
        assert {
            path: path.read_bytes()
            for kind in ("packages", "decisions")
            for path in (files.root / kind).glob("*.json")
        } == files_before


@pytest.mark.parametrize("preparation_case", [8], indirect=True)
@pytest.mark.parametrize("complete_preparation_case", ["coordinator"], indirect=True)
async def test_native_coordinator_recovers_admission_then_certifies_first_activation(
    complete_preparation_case, tmp_path, monkeypatch
):
    import shutil

    from umi.competition_cohort_reward_package import publish_reward_package
    from umi.competition_reward_control_journal import RewardControlTransactionJournal
    from umi.competition_reward_control_publisher import StandingControlPublisher
    from umi.competition_reward_coordinator import (
        StandingRewardCoordinator,
        StandingRewardDecisionReviewer,
    )
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_exchange import RewardReviewExchange
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
    from umi.competition_reward_offers import StandingRewardOffers
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner

    h = complete_preparation_case
    c, p = h.c, h.package_case
    first = c.series.recovery.authority.issued_at_block
    current_control_finality(h, first)
    primary, readback = (
        StandingRewardFiles(
            tmp_path / name,
            maximum_package_bytes=8 * 1024**2,
            maximum_witness_bytes=8 * 1024**2,
        )
        for name in ("coordinator-delivery", "independent-readback")
    )
    handoff = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(c.series),
        cohort_sha256=digest(c.series.cohorts[0]),
        legacy_policy_sha256="11" * 32,
        legacy_round_sha256="22" * 32,
        legacy_package_sha256="33" * 32,
    )
    unavailable, local_calls, peer_calls = True, [], []
    rule = opportunity_rule(p.manifest, c.series, h.item.policy)
    settlements = tmp_path / "completed-settlements"

    def offers():
        return StandingRewardOffers(
            series=c.series,
            policy=h.item.policy,
            manifest=p.manifest,
            handoff=handoff,
            settlements=settlements,
            files=primary,
            coverage=RewardCoverageJournal(
                tmp_path / "coordinator-coverage", rule, expected_rule_sha256=digest(rule)
            ),
        )

    async def no_opportunity(_):
        pytest.fail("initial activation uses the approved legacy handoff")

    def build():
        publisher = StandingControlPublisher(
            reader=c.reader,
            provider=h.item.provider,
            history=h.reader,
            journal=RewardControlTransactionJournal(
                tmp_path / "coordinator-transactions",
                c.series,
                config_sha256=digest(h.item.config),
                maximum_bytes=8 * 1024**2,
            ),
            files=primary,
            signer=wallet("Ferdie").hotkey,
            mortality_period=8,
            maximum_history_blocks=4096,
        )
        reviewer = StandingRewardDecisionReviewer(
            reader=publisher.reader,
            provider=publisher.provider,
            history=publisher.history,
            files=publisher.files,
            maximum_history_blocks=4096,
            manifest=p.manifest,
            promotion_store=p.store,
            handoff=handoff,
            opportunity=no_opportunity,
            maximum_promotion_bytes=1_000_000,
        )

        def signer(name, calls):
            async def sign(body):
                calls.append(body)
                return sign_object(body, wallet(name))

            return RewardDecisionSigner(
                RewardDecisionJournal(
                    tmp_path / ("decision-signer-" + name),
                    c.series,
                    h.item.policy,
                    wallet(name).hotkey.ss58_address,
                    expected_chain_config_sha256=digest(h.item.config),
                    maximum_bytes=8 * 1024**2,
                ),
                sign,
            )

        local = signer("Charlie", local_calls)
        peer = signer("Dave", peer_calls)
        leader_box = RewardReviewExchange(
            signer=local,
            proposer=wallet("Charlie").hotkey.ss58_address,
            inbox=tmp_path / "leader-inbox",
            outbox=tmp_path / "leader-outbox",
        )
        peer_box = RewardReviewExchange(
            signer=peer,
            proposer=wallet("Charlie").hotkey.ss58_address,
            inbox=tmp_path / "peer-inbox",
            outbox=tmp_path / "peer-outbox",
        )
        port = leader_box.vote_port(wallet("Dave").hotkey.ss58_address)

        def copy(source, target):
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source, target)

        async def vote(body, prefix):
            try:
                return await port(body, prefix)
            except FileNotFoundError:
                if unavailable:
                    raise ConnectionError("remote evaluator offline") from None
            sequence = body.sequence
            copy(
                leader_box._request_path(leader_box.outbox, sequence),
                peer_box._request_path(peer_box.inbox, sequence),
            )
            # Native message validation and separate signer journal; file copying
            # and shared fixture proof owners are not remote-host qualification.
            await peer_box.review(peer_box.request(sequence), reviewer)
            hotkey = wallet("Dave").hotkey.ss58_address
            copy(
                peer_box._vote_path(peer_box.outbox, sequence, hotkey),
                leader_box._vote_path(leader_box.inbox, sequence, hotkey),
            )
            return await port(body, prefix)

        return StandingRewardCoordinator(
            reviewer=reviewer,
            publisher=publisher,
            signer=local,
            readback=readback,
            offers=offers(),
            voters=(vote,),
        )

    async def converge(coordinator):
        with coordinator.publisher.hold_writer():
            for _ in range(100):
                try:
                    result = await coordinator.step()
                except HistoricalHeaderRecoveryPending:
                    continue
                if result.status not in {"history_pending", "review_pending"}:
                    return result
        pytest.fail("native recurring coordinator did not converge")

    coordinator = build()
    assert (await converge(coordinator)).status == "quorum_pending"
    intent = coordinator.signer.journal.load(0)
    assert intent.decision == c.genesis.decision and len(local_calls) == 1
    # Restart and remove original historical state/body access. The same reviewed
    # intent and local signature recover while the peer supplies its missing vote.
    c.reader, h.reader = c.reopen(), await h.restart()
    h.reader = h.new_reader(maximum_bytes=64 * 1024**2)
    current_control_finality(h, first)
    h.offline_through = first
    coordinator, unavailable = build(), False
    assert (await converge(coordinator)).status == "certified_delivery_pending"
    assert coordinator.signer.journal.load(0) == intent
    assert len(local_calls) == 1 and len(peer_calls) == 1
    assert (await converge(coordinator)).status == "delivery_pending"
    assert coordinator.publisher.journal.pending() is None
    admission = coordinator.signer.journal.prefix(1)[0]
    # This synthetic finalized chain includes that exact admission on the next
    # block. The native publisher must recognize it without submitting again.
    readback.retain_decision(admission)
    # Collecting a previously unseen block needs its parent's runtime proof.
    # The old-state outage above qualifies replay of the already retained prefix.
    h.offline_through = first - 1
    current_control_finality(h, first + 1)
    assert (await converge(coordinator)).status == "allocation_pending"
    assert coordinator.publisher.journal.pending() is None

    current_control_finality(h, c.active.decision.observed_at_block - 1)
    offer = c.active.decision.activation.model_copy(
        update={"prior_opportunity_sha256": digest(handoff)}
    )
    publish_reward_package(settlements / (offer.cohort_sha256 + ".json"), p.package)
    retain = primary.retain_package

    def lost_publication_reply(package):
        retain(package)
        raise OSError("package acknowledgement lost")

    monkeypatch.setattr(primary, "retain_package", lost_publication_reply)
    with pytest.raises(OSError, match="acknowledgement"):
        await converge(coordinator)
    assert coordinator.signer.journal.load(1) is None and len(local_calls) == 1
    assert primary.package(offer.package_sha256) == p.package
    monkeypatch.setattr(primary, "retain_package", retain)
    coordinator = build()
    assert (await converge(coordinator)).status == "certified_delivery_pending"
    certificate = coordinator.signer.journal.prefix(2)[1]
    assert certificate.decision.activation == offer
    assert primary.package(offer.package_sha256) == p.package
    assert len(local_calls) == 2 and len(peer_calls) == 2
    assert (await converge(coordinator)).status == "delivery_pending"
    assert coordinator.publisher.journal.pending() is None


@pytest.mark.parametrize("predecessor_revision", [None, 0, 1, 2])
async def test_offer_discovery_waits_for_bound_settlement_and_prior_opportunity(
    native_package, tmp_path, predecessor_revision, monkeypatch
):
    """Discovery only: later-slot authority and interval claims are synthetic.

    The first-activation integration above separately performs native review.
    An emitted offer carries no signature or chain permission.
    """
    from umi.competition_cohort_reward_package import publish_reward_package
    from umi.competition_geometric_rewards import GeometricRewardParameters
    from umi.competition_reward_adoption import (
        RewardAdoptionSelection,
        RewardModelAdoption,
        SignedRewardModelAdoption,
    )
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_service import CoverageCompletion, coverage_work_key
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
    from umi.competition_reward_manifest import (
        RewardOpportunityTerms,
        StandingRewardOpportunityManifest,
    )
    from umi.competition_reward_offers import StandingRewardOffers
    from umi.competition_reward_opportunity import (
        RewardOpportunityCertificate,
        RewardOpportunityContribution,
        RewardOpportunityWitness,
        opportunity_rule,
    )
    from umi.open_competition import identity

    successor = predecessor_revision is not None
    p, policy = native_package, native_package.store.policy
    history = p.package.inputs.history
    plans = (history.plan,)
    if successor:
        plans = (
            history.plan.model_copy(update={"sequence": history.plan.sequence - 1}),
            history.plan,
        )
    body = history.authority.authority.model_copy(
        update={"cohort_sha256s": tuple(sorted(digest(plan) for plan in plans))}
    )
    authority = history.authority.model_copy(
        update={
            "authority": body,
            "signatures": tuple(
                sorted(
                    (sign_object(body, wallet(n)) for n in ("Charlie", "Dave")),
                    key=lambda signature: identity(signature.hotkey),
                )
            ),
        }
    )
    package = p.package.model_copy(
        update={
            "inputs": p.package.inputs.model_copy(
                update={"history": history.model_copy(update={"authority": authority})}
            )
        }
    )
    manifest = StandingRewardOpportunityManifest(
        schema="umi-standing-reward-manifest/2",
        policy_sha256=digest(policy),
        cohorts=tuple(
            p.requirement.model_copy(update={"cohort_sha256": digest(plan)}) for plan in plans
        ),
        opportunity=RewardOpportunityTerms(
            runtime_profile_sha256="12" * 32, maximum_interval_ms=12000, minimum_validator_ms=12000
        ),
    )
    validator = wallet("Charlie").hotkey.ss58_address
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(policy),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Ferdie").hotkey.ss58_address,
        recovery=authority,
        cohorts=plans,
        validators=(validator,),
        maximum_proof_lag_blocks=2,
        maximum_transaction_lifetime_blocks=8,
        lifetime="until_superseded_or_revoked",
    )
    handoff = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(series),
        cohort_sha256=digest(plans[0]),
        legacy_policy_sha256="11" * 32,
        legacy_round_sha256="22" * 32,
        legacy_package_sha256="33" * 32,
    )
    prefix = (
        signed(
            RewardControlDecision(
                schema="umi-reward-control-decision/1",
                series_sha256=digest(series),
                sequence=0,
                predecessor_sha256=None,
                kind="admit_series",
                observed_at_block=body.issued_at_block,
                activation=None,
            )
        ),
    )
    prior = None
    reward_adoptions = None
    stale_activations = []
    if successor:
        prior = RewardActivation(
            cohort_sha256=digest(plans[0]),
            allocation_sha256="44" * 32,
            package_sha256="55" * 32,
            recovery_tip_sha256="66" * 32,
            prior_opportunity_sha256=digest(handoff),
        )
        if predecessor_revision:
            legacy_prior = prior
            stale_activations.append(legacy_prior)
            adoptions = []
            for revision in range(1, predecessor_revision + 1):
                adoption = RewardModelAdoption(
                    schema="umi-standing-model-reward-adoption/1",
                    series_sha256=digest(series),
                    policy_sha256=digest(policy),
                    cohort_sha256=prior.cohort_sha256,
                    authority_sha256=digest(body),
                    package_sha256=prior.package_sha256,
                    allocation_sha256=prior.allocation_sha256,
                    service_certificate_sha256="a1" * 32,
                    quality_manifest_sha256="a2" * 32,
                    effective_allocation_sha256=f"{revision:064x}",
                    parameters=GeometricRewardParameters(band_decay_bps=7500 + revision),
                    revision=revision,
                    predecessor_adoption_sha256=None
                    if revision == 1
                    else digest(adoptions[-1].adoption),
                    issued_at_block=body.issued_at_block + revision,
                    lifetime="until_first_verified_live_reward_then_locked",
                )
                adoptions.append(
                    SignedRewardModelAdoption(adoption=adoption, signatures=signatures(adoption))
                )
            reward_adoptions = RewardAdoptionSelection(
                schema="umi-standing-reward-adoption-selection/1", adoptions=tuple(adoptions)
            )
            prior = legacy_prior.model_copy(
                update={
                    "reward_adoption_sha256": digest(adoptions[0].adoption),
                    "effective_allocation_sha256": (
                        adoptions[0].adoption.effective_allocation_sha256
                    ),
                }
            )
        prefix += (
            signed(
                RewardControlDecision(
                    schema="umi-reward-control-decision/3"
                    if predecessor_revision
                    else "umi-reward-control-decision/1",
                    series_sha256=digest(series),
                    sequence=1,
                    predecessor_sha256=digest(prefix[-1].decision),
                    kind="activate",
                    observed_at_block=body.issued_at_block + 3,
                    activation=prior,
                )
            ),
        )
        if predecessor_revision == 2:
            stale_activations.append(prior)
            prefix += (
                signed(
                    RewardControlDecision(
                        schema="umi-reward-control-decision/3",
                        series_sha256=digest(series),
                        sequence=len(prefix),
                        predecessor_sha256=digest(prefix[-1].decision),
                        kind="suspend_activation",
                        observed_at_block=body.issued_at_block + 4,
                        activation=prior,
                    )
                ),
            )
            prior = legacy_prior.model_copy(
                update={
                    "reward_adoption_sha256": digest(adoptions[-1].adoption),
                    "effective_allocation_sha256": (
                        adoptions[-1].adoption.effective_allocation_sha256
                    ),
                }
            )
            prefix += (
                signed(
                    RewardControlDecision(
                        schema="umi-reward-control-decision/3",
                        series_sha256=digest(series),
                        sequence=len(prefix),
                        predecessor_sha256=digest(prefix[-1].decision),
                        kind="revise_activation",
                        observed_at_block=body.issued_at_block + 5,
                        activation=prior,
                        revision_clearance_sha256="ca" * 32,
                    )
                ),
            )
    files = StandingRewardFiles(
        tmp_path / "offer-files", maximum_package_bytes=8 * 1024**2, maximum_witness_bytes=1024**2
    )
    rule = opportunity_rule(manifest, series, policy)
    coverage = RewardCoverageJournal(
        tmp_path / "offer-coverage", rule, expected_rule_sha256=digest(rule)
    )
    settlements = tmp_path / "settlements"
    offers = StandingRewardOffers(
        series=series,
        policy=policy,
        manifest=manifest,
        handoff=handoff,
        settlements=settlements,
        files=files,
        coverage=coverage,
        reward_adoptions=reward_adoptions,
    )
    cohort = digest(plans[-1])
    with pytest.raises(ValueError, match="next admitted"):
        offers("ff" * 32, prefix)
    with pytest.raises(ValueError, match="next admitted"):
        offers.completed_package("ff" * 32, prefix)
    assert offers(cohort, prefix) is None
    assert offers.completed_package(cohort, prefix) is None
    path = settlements / (cohort + ".json")
    publish_reward_package(path, package)
    if successor:
        assert offers(cohort, prefix) is None
        assert not (files.root / "packages").exists()
        for stale in stale_activations:
            # A legacy completion or earlier adopted revision must not unblock
            # this revision or attempt to load its unrelated certificate.
            coverage.journal.put(
                "coverage_completion",
                coverage_work_key(stale),
                CoverageCompletion(
                    schema="umi-reward-coverage-completion/1", certificate_sha256="f3" * 32
                ),
            )
            assert offers(cohort, prefix) is None
            assert not (files.root / "packages").exists()
        witness = RewardOpportunityWitness(
            schema="umi-reward-opportunity-witness/1",
            rule_sha256=digest(rule),
            activation_sha256=digest(prior),
            validator_account_id=identity(validator),
            interval_keys=("77" * 32,),
        )
        certificate = RewardOpportunityCertificate(
            schema="umi-reward-opportunity-certificate/1",
            series_sha256=digest(series),
            manifest_sha256=digest(manifest),
            rule_sha256=digest(rule),
            activation_sha256=digest(prior),
            contributions=(
                RewardOpportunityContribution(
                    validator_account_id=identity(validator),
                    witness_sha256=digest(witness),
                    credited_ms=12000,
                    through_block=body.issued_at_block + 20,
                ),
            ),
        )
        completion = CoverageCompletion(
            schema="umi-reward-coverage-completion/1", certificate_sha256=digest(certificate)
        )
        coverage.journal.put("coverage_completion", coverage_work_key(prior), completion)
        with pytest.raises(FileNotFoundError):
            offers(cohort, prefix)
        files.retain_completion(certificate, lambda _: canonical_json_bytes(witness))
    # The adoption producer must discover the genuine completed package while
    # ordinary offers remain held for announced economics. Discovery neither
    # accesses opportunity coverage nor changes that hold.
    with monkeypatch.context() as pending:
        from umi import competition_reward_offers as offers_module
        from umi.competition_verification_snapshot import VerifiedPackageSnapshot

        pending.setattr(offers_module, "successor_reward_rule_ready", lambda *a: False)
        assert offers(cohort, prefix) is None
        assert offers.pending_reason == "reward_adoption_pending"
        pending.setattr(offers, "coverage", object())
        discovered = offers.completed_package(cohort, prefix)
        assert type(discovered) is VerifiedPackageSnapshot
        assert discovered.sha256 == digest(package)
        assert offers.pending_reason == "reward_adoption_pending"
    offer = offers(cohort, prefix)
    assert offer.package_sha256 == digest(package)
    assert offer.prior_opportunity_sha256 == (digest(certificate) if successor else digest(handoff))
    assert files.package(offer.package_sha256) == package
    if predecessor_revision == 1:
        from umi.competition_reward_adoption import RewardEarlyRelease

        release = RewardEarlyRelease(
            schema="umi-reward-early-release/1",
            predecessor_decision_sha256=digest(prefix[-1].decision),
            predecessor_activation_sha256=digest(prior),
            successor_cohort_sha256=cohort,
            successor_package_sha256=digest(package),
            manifest_sha256=digest(manifest),
            reason="Operator authorizes this certified package before opportunity completion",
        )
        parameters = GeometricRewardParameters(
            band_width_bps=250,
            band_decay_bps=7500,
            within_band_decay_bps=7500,
            score_duplicate_tolerance_bps=1,
        )
        successor_adoption = RewardModelAdoption(
            schema="umi-standing-model-reward-adoption/5",
            series_sha256=digest(series),
            policy_sha256=digest(policy),
            cohort_sha256=cohort,
            authority_sha256=digest(body),
            package_sha256=digest(package),
            allocation_sha256=digest(package.allocation),
            service_certificate_sha256=digest(package.service),
            quality_manifest_sha256=digest(package.benchmark),
            effective_allocation_sha256="a5" * 32,
            parameters=parameters,
            revision=1,
            predecessor_adoption_sha256=None,
            issued_at_block=body.issued_at_block + 6,
            lifetime="until_first_verified_live_reward_then_locked",
            early_release=release,
        )
        early_selection = RewardAdoptionSelection(
            schema="umi-standing-reward-adoption-selection/1",
            adoptions=tuple(
                sorted(
                    (
                        *reward_adoptions.adoptions,
                        SignedRewardModelAdoption(
                            adoption=successor_adoption,
                            signatures=signatures(successor_adoption),
                        ),
                    ),
                    key=lambda item: (item.adoption.cohort_sha256, item.adoption.revision),
                )
            ),
        )
        empty_coverage = RewardCoverageJournal(
            tmp_path / "early-offer-empty-coverage", rule, expected_rule_sha256=digest(rule)
        )
        early_offers = StandingRewardOffers(
            series=series,
            policy=policy,
            manifest=manifest,
            handoff=handoff,
            settlements=settlements,
            files=files,
            coverage=empty_coverage,
            reward_adoptions=early_selection,
        )
        early_offer = early_offers(cohort, prefix)
        assert early_offer.prior_opportunity_sha256 == digest(release)
        assert early_offer.package_sha256 == digest(package)
    # Restarted discovery and first downstream preparation reuse the verified
    # source/replica binding; neither parses the package nor transfers it again.
    with monkeypatch.context() as warm:
        from umi import competition_cohort_aggregate_replica as replica_module
        from umi import competition_verification_snapshot as snapshot_module

        def no_payload(*args, **kwargs):
            pytest.fail("unchanged offer reread package payload")

        warm.setattr(snapshot_module, "read_aggregate_model", no_payload)
        warm.setattr(replica_module, "_transfer", no_payload)
        reopened = StandingRewardOffers(
            series=series,
            policy=policy,
            manifest=manifest,
            handoff=handoff,
            settlements=settlements,
            files=files,
            coverage=RewardCoverageJournal(
                tmp_path / "offer-coverage", rule, expected_rule_sha256=digest(rule)
            ),
            reward_adoptions=reward_adoptions,
        )
        assert reopened(cohort, prefix) == offer
        assert reopened(cohort, prefix) == offer
        assert reopened.completed_package(cohort, prefix).sha256 == offer.package_sha256
        assert reopened.completed_package(cohort, prefix).sha256 == offer.package_sha256
        snapshot = files.verified_package(offer.package_sha256)
        assert snapshot.sha256 == offer.package_sha256
    # Replacing a completed source requires explicit repair before a native
    # consumer may inspect it. It never silently becomes a new first import.
    path.write_bytes(canonical_json_bytes(package.model_copy(update={"policy_sha256": "ee" * 32})))
    from umi.competition_verification_snapshot import VerificationSnapshotRepairRequired

    with pytest.raises(VerificationSnapshotRepairRequired):
        offers(cohort, prefix)
    with pytest.raises(VerificationSnapshotRepairRequired):
        offers.completed_package(cohort, prefix)


async def test_boot_reconstructs_initial_package_from_native_retained_history(
    complete_preparation_case,
):
    from umi.competition_reward_executor import StandingHistoryPending
    from umi.competition_reward_service import _prepare_first

    h = complete_preparation_case
    p, c = h.package_case, h.c

    def owner():
        return StandingRewardPreparation(
            c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
        )

    def package(sha):
        assert sha == digest(p.package)
        return p.package

    async def boot(preparation):
        for _ in range(100):
            try:
                return await _prepare_first(
                    preparation, h.item.provider, h.reader, package, c.source, h.end, 64
                )
            except (HistoricalHeaderRecoveryPending, StandingHistoryPending):
                continue
        pytest.fail("native boot replay did not converge")

    before = await boot(owner())
    assert before.activation == c.active.decision.activation
    assert before.allocation == p.allocation
    assert not before.chain_submission_authorized
    c.reader, h.reader = c.reopen(), await h.restart()
    c.objects.clear()  # Original coordinator decisions are now unavailable.
    h.offline_through = h.end
    h.rpc_calls.clear()
    after = await boot(owner())
    assert after.activation == before.activation and after.allocation == before.allocation
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_native_pending_activation_signs_recovers_and_delivers_after_restart(
    complete_preparation_case, tmp_path
):
    from umi.competition_reward_decision_review import review_reward_decision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
    from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner

    h = complete_preparation_case
    c, p = h.c, h.package_case
    # Review before the synthetic existing activation. Its genesis is already
    # finalized; our candidate has not been published or committed anywhere.
    observed = c.active.decision.observed_at_block - 1
    handoff = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(c.series),
        cohort_sha256=digest(c.series.cohorts[0]),
        legacy_policy_sha256="11" * 32,
        legacy_round_sha256="22" * 32,
        legacy_package_sha256="33" * 32,
    )
    body = c.active.decision.model_copy(
        update={
            "observed_at_block": observed,
            "activation": c.active.decision.activation.model_copy(
                update={
                    "prior_opportunity_sha256": digest(handoff),
                }
            ),
        }
    )

    async def history():
        for _ in range(100):
            try:
                part = await h.reader.advance(
                    h.item.provider, through_block=observed, maximum_blocks=4096
                )
            except HistoricalHeaderRecoveryPending:
                continue
            if part.history is not None:
                return part.history
        pytest.fail("native signing history did not converge")

    retained = await history()
    control = await h.reader.review_control(h.item.provider, retained.tip.block_number)
    inputs = dict(
        control=control,
        history=retained,
        package=p.package,
        promotion_store=p.store,
        approved_handoff=handoff,
        maximum_promotion_bytes=1_000_000,
    )

    def review(decision=body, **changes):
        return review_reward_decision(
            c.reader, p.manifest, (c.genesis,), decision, **(inputs | changes)
        )

    with pytest.raises(ValueError, match="original finalized"):
        review(body.model_copy(update={"observed_at_block": observed + 1}))
    with pytest.raises(ValueError, match="approved handoff"):
        review(approved_handoff=None)
    with pytest.raises(ValueError, match="native package"):
        review(package=None)
    with pytest.raises(ValueError, match="native interval"):
        review(history=replace(retained, _issuer=None))
    wrong = body.model_copy(
        update={
            "activation": body.activation.model_copy(
                update={
                    "allocation_sha256": "ff" * 32,
                }
            )
        }
    )
    with pytest.raises(ValueError, match="allocation differs"):
        review(wrong)
    accepted = review()
    assert not accepted.chain_submission_authorized

    def journal():
        return RewardDecisionJournal(
            tmp_path / "native-signing",
            c.series,
            c.control.policy,
            wallet("Charlie").hotkey.ss58_address,
            expected_chain_config_sha256=c.reader.admission_chain_config_sha256,
            maximum_bytes=16 * 1024**2,
        )

    async def unavailable(_):
        raise ConnectionError("signer temporarily unavailable")

    with pytest.raises(ConnectionError):
        await RewardDecisionSigner(journal(), unavailable).attest(accepted)
    intent = journal().load(1)
    # Restart native readers and reconstruct original evidence with historical
    # body/state RPC unavailable. Retained intent selects the original cutoff.
    h.reader = await h.restart()
    c.reader = c.reopen()
    h.offline_through = observed
    h.rpc_calls.clear()
    inputs["history"] = await history()
    inputs["control"] = await h.reader.review_control(h.item.provider, observed)
    resumed = review()
    assert resumed.intent == intent
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}

    calls = []

    async def sign(decision):
        calls.append(decision)
        return sign_object(decision, wallet("Charlie"))

    owner = RewardDecisionSigner(journal(), sign)
    vote = await owner.attest(resumed)
    owner = RewardDecisionSigner(journal(), unavailable)
    assert await owner.attest(resumed) == vote
    with pytest.raises(ValueError, match="quorum"):
        await owner.certify(1)
    await owner.collect(1, sign_object(body, wallet("Dave")))
    certificate = await owner.certify(1)
    files = StandingRewardFiles(
        tmp_path / "signed-inputs",
        maximum_package_bytes=16 * 1024**2,
        maximum_witness_bytes=1024**2,
    )

    def absent(_):
        raise FileNotFoundError("package source unavailable")

    with pytest.raises(FileNotFoundError):
        await owner.publish(1, files, absent)
    assert journal().certify(1) == certificate
    owner = RewardDecisionSigner(journal(), unavailable)
    assert await owner.publish(1, files, lambda _: p.package) == digest(body)
    # An interrupted reply can be retried even after the source is gone.
    assert await owner.publish(1, files, absent) == digest(body)
    assert files.package(body.activation.package_sha256) == p.package
    assert files.decision(digest(body)) == canonical_json_bytes(certificate)
    assert calls == [body]


@pytest.mark.parametrize("complete_preparation_case", ["signing_admission"], indirect=True)
async def test_native_admission_signs_only_an_empty_reserved_control_history(
    complete_preparation_case, tmp_path
):
    from umi.competition_reward_decision_review import review_reward_decision
    from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner

    h = complete_preparation_case
    c, p = h.c, h.package_case
    first = c.series.recovery.authority.issued_at_block
    for _ in range(100):
        try:
            part = await h.reader.advance(h.item.provider, through_block=first, maximum_blocks=1)
        except HistoricalHeaderRecoveryPending:
            continue
        if part.history is not None:
            break
    else:
        pytest.fail("native empty control history did not converge")
    control = await h.reader.review_control(h.item.provider, part.history.tip.block_number)
    assert control.control_sha256 is None and not part.history.writes
    reviewed = review_reward_decision(
        c.reader,
        p.manifest,
        (),
        c.genesis.decision,
        control=control,
        history=part.history,
        maximum_promotion_bytes=1_000_000,
    )
    journal = RewardDecisionJournal(
        tmp_path / "native-admission-signing",
        c.series,
        c.control.policy,
        wallet("Charlie").hotkey.ss58_address,
        expected_chain_config_sha256=c.reader.admission_chain_config_sha256,
        maximum_bytes=16 * 1024**2,
    )

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    vote = await RewardDecisionSigner(journal, sign).attest(reviewed)
    assert vote == journal.vote(0, wallet("Charlie").hotkey.ss58_address)
    assert journal.load(0).decision == c.genesis.decision


@pytest.mark.parametrize(
    "complete_preparation_case,parallel_history",
    [
        ("matching", False),
        ("sparse_zeros", False),
        ("raw_row", False),
        ("missing_recipient", False),
        ("extra_recipient", False),
        ("permit_missing", False),
        ("matching", True),
    ],
    indirect=["complete_preparation_case"],
)
async def test_complete_native_history_package_and_projection_restart_without_coordinator(
    complete_preparation_case,
    parallel_history,
    tmp_path,
    monkeypatch,
):
    h = complete_preparation_case
    p, c = h.package_case, h.c
    if parallel_history:
        from .test_competition_reward_history_parallel import retained_parallel_case

        await retained_parallel_case(h, tmp_path, monkeypatch)
        h.new_reader = h.open_parallel
        h.offline_through = h.end - 1

    async def history():
        for _ in range(100):
            try:
                part = await h.reader.advance(
                    h.item.provider, through_block=h.end, maximum_blocks=4096
                )
            except HistoricalHeaderRecoveryPending:
                continue
            if part.history is not None:
                return part.history
        pytest.fail("complete history did not converge")

    async def prepare(owner, retained):
        control, chain = await current_state(h, retained.tip, validator_hotkey=h.validator_hotkey)
        args = dict(control=control, history=retained, source=c.source)
        ready = await owner.prepare(p.package, **args)
        # Verification can outlive its initial observation: project with new proofs.
        control, chain = await current_state(h, retained.tip, validator_hotkey=h.validator_hotkey)
        result = await owner.project(
            ready,
            control=control,
            history=retained,
            source=c.source,
            chain=chain,
            chain_config=h.item.config,
        )
        return ready, result

    def owner():
        # Cold recovery reads the approved manifest from the reader's retained
        # journal. Neither the coordinator nor a package chooses replay inputs.
        return StandingRewardPreparation(c.reader, p.store, maximum_promotion_bytes=1_000_000)

    StandingRewardPreparation(c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000)
    captured = await history()
    if parallel_history:
        assert h.reader.progress.native_completed == h.end - h.old.height + 1
    archived_control = await h.reader.review_control(h.item.provider, captured.tip.block_number)
    ready, result = await prepare(owner(), captured)
    eligibility_control, captured_eligibility = await current_state(
        h, captured.tip, validator_hotkey=h.validator_hotkey, eligibility_profile=h.item.profile
    )
    assert ready.allocation == p.allocation
    assert result.current.selection.state == "selected"
    assert result.current.selection.committed_at_block == c.active.decision.observed_at_block
    assert result.current.selection.effective_at_block == h.end
    assert len(h.body_requests) == h.end - h.old.height + 1
    assert sum(result.projection.weights) == 65535
    assert not result.chain_submission_authorized

    # Reopen every reader/preparation owner. Historical network inputs and the
    # coordinator decision source are unavailable; only the current state is live.
    h.reader = await h.restart()
    h.reader = h.new_reader(maximum_bytes=64 * 1024**2)
    c.reader = c.reopen()
    c.objects.clear()
    h.offline_through = h.end - 1
    replayed = await history()
    if parallel_history:
        assert h.reader.progress.native_completed == 0
    # Recover the exact historical allocation natively before any fresh state
    # collection. No coordinator, historical body/state RPC or renewed control
    # publication participates in this review.
    h.offline_through = h.end
    h.rpc_calls.clear()
    reviewed_control = await h.item.provider.review_control(
        archived_control.evidence, archived_control.metadata
    )
    historical_owner = owner()
    historical_ready = await historical_owner.prepare_historical(
        p.package, control=reviewed_control, history=replayed, source=c.source
    )
    assert historical_ready.allocation == p.allocation
    assert historical_ready.activation == c.active.decision.activation
    assert historical_ready.reviewed_at_block == h.end
    assert not historical_ready.chain_submission_authorized
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}
    from umi.competition_reward_coverage import review_reward_coverage, validate_reward_coverage
    from umi.competition_reward_eligibility_archive import review_reward_eligibility

    eligibility = await review_reward_eligibility(
        h.item.provider,
        control=eligibility_control.evidence,
        chain=captured_eligibility.chain.evidence,
        eligibility=captured_eligibility.evidence,
        metadata=captured_eligibility.chain.runtime.metadata_bytes,
        validator_hotkey=h.validator_hotkey,
        control_hotkey=c.series.control_hotkey,
        profile=h.item.profile,
        expected_runtime_profile_sha256=digest(h.item.profile),
    )
    endpoint = await review_reward_coverage(
        historical_owner,
        p.package,
        eligibility=eligibility,
        history=replayed,
        source=c.source,
        expected_runtime_profile_sha256=digest(h.item.profile),
    )
    assert endpoint.covered is (h.variant in {"matching", "sparse_zeros"})
    assert endpoint.row_matches is (h.variant in {"matching", "sparse_zeros", "permit_missing"})
    if h.variant == "permit_missing":
        assert eligibility.reason == "permit_missing"
    elif h.variant != "extra_recipient":
        assert eligibility.eligible
    assert endpoint.projection == result.projection
    assert not endpoint.chain_submission_authorized
    validate_reward_coverage(
        endpoint,
        expected_series_sha256=digest(c.series),
        expected_runtime_profile_sha256=digest(h.item.profile),
    )
    for altered in (
        replace(endpoint, _issuer=None),
        replace(endpoint, row_matches=not endpoint.row_matches),
        replace(endpoint, chain_submission_authorized=True),
        replace(endpoint, eligibility=replace(eligibility, timestamp_ms=1)),
        replace(endpoint, eligibility=replace(eligibility, burn_destination=None)),
        replace(endpoint, prepared=replace(endpoint.prepared, reviewed_at_block=1)),
        replace(endpoint, projection=endpoint.projection.model_copy(update={"weights": (65535,)})),
    ):
        with pytest.raises(ValueError):
            validate_reward_coverage(
                altered,
                expected_series_sha256=digest(c.series),
                expected_runtime_profile_sha256=digest(h.item.profile),
            )
    for series_sha, runtime_sha in [
        ("ef" * 32, digest(h.item.profile)),
        (digest(c.series), "ef" * 32),
    ]:
        with pytest.raises(ValueError):
            validate_reward_coverage(
                endpoint,
                expected_series_sha256=series_sha,
                expected_runtime_profile_sha256=runtime_sha,
            )
    with pytest.raises(ValueError):
        await review_reward_coverage(
            historical_owner,
            p.package,
            eligibility=captured_eligibility,
            history=replayed,
            source=c.source,
            expected_runtime_profile_sha256=digest(h.item.profile),
        )
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}
    h.offline_through = h.end - 1
    restored, again = await prepare(owner(), replayed)
    assert restored is not ready and restored.allocation == ready.allocation
    assert again.projection == result.projection
    assert again.current.selection == result.current.selection
    assert h.body_requests == list(range(h.old.height, h.end + 1))


@pytest.mark.parametrize("complete_preparation_case", ["journal", "opportunity"], indirect=True)
async def test_native_coverage_retention_retries_and_offline_restart(
    complete_preparation_case, tmp_path, monkeypatch
):
    from umi.competition_reward_coverage import review_reward_coverage
    from umi.competition_reward_coverage_intervals import RewardCoverageRule, coverage_point
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_eligibility_archive import review_reward_eligibility

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = RewardCoverageRule(
        schema="umi-reward-coverage-rule/1",
        series_sha256=digest(c.series),
        runtime_profile_sha256=digest(h.item.profile),
        maximum_interval_ms=12000,  # Fixture choice, not an approved production parameter.
    )
    selected = dict(expected_rule_sha256=digest(rule))
    query = dict(
        activation_sha256=digest(c.active.decision.activation), validator_hotkey=h.validator_hotkey
    )

    def owner():
        return StandingRewardPreparation(c.reader, p.store, maximum_promotion_bytes=1_000_000)

    async def history(height):
        for _ in range(100):
            try:
                value = await h.reader.advance(
                    h.item.provider, through_block=height, maximum_blocks=4096
                )
            except HistoricalHeaderRecoveryPending:
                continue
            if value.history is not None:
                return value.history
        pytest.fail("complete history did not converge")

    StandingRewardPreparation(c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000)
    preparation_owner = owner()
    endpoints = []
    for height in (h.end - 1, h.end):
        retained = await history(height)
        control, captured = await current_state(
            h, retained.tip, validator_hotkey=h.validator_hotkey, eligibility_profile=h.item.profile
        )
        # current_state closes its temporary provider. Reopen the native
        # archive provider without discarding this history owner's prefix.
        await h.restart()
        eligibility = await review_reward_eligibility(
            h.item.provider,
            control=control.evidence,
            metadata=captured.chain.runtime.metadata_bytes,
            chain=captured.chain.evidence,
            eligibility=captured.evidence,
            validator_hotkey=h.validator_hotkey,
            control_hotkey=c.series.control_hotkey,
            profile=h.item.profile,
            expected_runtime_profile_sha256=digest(h.item.profile),
        )
        endpoint = await review_reward_coverage(
            preparation_owner,
            p.package,
            eligibility=eligibility,
            history=retained,
            source=c.source,
            expected_runtime_profile_sha256=digest(h.item.profile),
        )
        assert endpoint.covered
        endpoints.append(endpoint)
    left, right = endpoints

    def counts(journal):
        with journal.journal.transaction() as db:
            return db.execute(
                "SELECT COUNT(*),SUM(LENGTH(body)) FROM records WHERE kind NOT IN "
                "('coverage_verified','coverage_verified_done','coverage_checkpoint_owner',"
                "'coverage_credit_owner')"
            ).fetchone()

    # Capacity errors and interrupted transactions preserve atomicity. No
    # endpoint, interval or verified total is acknowledged before commit.
    tiny = RewardCoverageJournal(tmp_path / "tiny", rule, maximum_bytes=1024, **selected)
    with pytest.raises(ValueError, match="capacity exhausted"):
        await tiny.credit(left, right)
    assert counts(tiny) == (0, None)
    assert await tiny.verified_ms(**query) == 0
    roomy = RewardCoverageJournal(tmp_path / "tiny", rule, **selected)
    assert (await roomy.credit(left, right)).credited_ms == 12000
    assert await roomy.verified_ms(**query) == 12000

    journal = RewardCoverageJournal(tmp_path / "coverage", rule, **selected)
    original_put = journal.journal.put_many

    def interrupt_before_commit(records, *, index=None):
        def fail(db):
            assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] > 0
            if index is not None:
                index(db)
            raise OSError("simulated interrupted commit")

        original_put(records, index=fail)

    with monkeypatch.context() as m:
        m.setattr(journal.journal, "put_many", interrupt_before_commit)
        with pytest.raises(OSError, match="interrupted commit"):
            await journal.credit(left, right)
    assert counts(journal) == (0, None)
    assert await journal.verified_ms(**query) == 0

    def lost_acknowledgement(records, **kwargs):
        original_put(records, **kwargs)
        raise OSError("simulated lost acknowledgement")

    with monkeypatch.context() as m:
        m.setattr(journal.journal, "put_many", lost_acknowledgement)
        with pytest.raises(OSError, match="lost acknowledgement"):
            await journal.credit(left, right)
    assert await journal.verified_ms(**query) == 0
    committed = counts(journal)
    assert committed[0] > 0
    result = await journal.credit(left, right)
    assert result.credited_ms == 12000
    assert counts(journal) == committed
    assert await journal.credit(left, right) == result
    assert await journal.retain_endpoint(left) == result.left
    assert counts(journal) == committed
    assert await journal.verified_ms(**query) == 12000
    assert await journal.interval_keys(limit=1) == (result.key(),)
    assert await journal.interval_keys(after=result.key(), limit=1) == ()

    # Reopening restores obligations, not trusted totals. Even reading the
    # stored interval cannot give it native proof provenance.
    restarted = RewardCoverageJournal(tmp_path / "coverage", rule, **selected)
    assert await restarted.verified_ms(**query) == 0
    hint = await restarted.retained_interval(result.key())
    assert hint == result
    assert await restarted.verified_ms(**query) == 0

    h.reader = await h.restart()
    h.reader = h.new_reader(maximum_bytes=64 * 1024**2)
    c.reader = c.reopen()
    c.objects.clear()  # Coordinator decisions are available only in retained history.
    h.offline_through = h.end - 1
    histories = [await history(height) for height in (h.end - 1, h.end)]
    h.offline_through = h.end
    h.rpc_calls.clear()
    preparation_owner = owner()
    restored = []
    for key, retained in zip((hint.left, hint.right), histories, strict=True):
        restored.append(
            await restarted.review_endpoint(
                key,
                provider=h.item.provider,
                preparation=preparation_owner,
                package=p.package,
                history=retained,
                source=c.source,
                profile=h.item.profile,
            )
        )
    assert [coverage_point(e, rule) for e in restored] == [
        coverage_point(e, rule) for e in endpoints
    ]
    assert await restarted.credit(*restored) == result
    assert await restarted.credit(*restored) == result
    assert await restarted.verified_ms(**query) == 12000
    assert counts(restarted) == committed
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}
    assert h.body_requests == list(range(h.old.height, h.end + 1))

    # Caller cancellation drains the disk owner before another writer can
    # acquire its lock. A committed interval remains one interval on retry.
    cancelled = RewardCoverageJournal(tmp_path / "cancelled", rule, **selected)
    entered, release = threading.Event(), threading.Event()
    original_put = cancelled.journal.put_many

    def slow_commit(records, **kwargs):
        entered.set()
        assert release.wait(20)
        original_put(records, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(cancelled.journal, "put_many", slow_commit)
        pending = asyncio.create_task(cancelled.credit(*endpoints))
        try:
            assert await asyncio.to_thread(entered.wait, 20)
            pending.cancel()
            await asyncio.sleep(0)
            assert not pending.done()
            with pytest.raises((ValueError, BlockingIOError)), cancelled.journal.locked():
                pytest.fail("cancelled disk owner released its lock too soon")
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await pending
    assert await cancelled.verified_ms(**query) == 12000
    assert await cancelled.credit(*endpoints) == result
    assert await cancelled.verified_ms(**query) == 12000

    # Corruption is a hold, not permission to replace evidence or reset the
    # accounting journal. This operates only on the isolated fixture database.
    with restarted.journal.transaction() as db:
        sha, raw = db.execute(
            "SELECT id,body FROM records WHERE kind='coverage_object' LIMIT 1"
        ).fetchone()
        db.execute("DELETE FROM records WHERE kind='coverage_object' AND id=?", (sha,))
    damaged = counts(restarted)
    with pytest.raises(ValueError, match="explicit scoped repair"):
        await restarted.credit(*restored)
    assert counts(restarted) == damaged
    with restarted.journal.transaction() as db:
        db.execute("INSERT INTO records VALUES ('coverage_object',?,?)", (sha, raw))
    assert counts(restarted) == committed
    with pytest.raises(ValueError, match="explicit scoped repair"):
        await restarted.credit(*restored)
    # Restoring the same payload does not undo its mutation generation. Repair
    # only the two affected native endpoints, retaining their old success facts.
    restored = [
        await restarted.review_endpoint(
            key,
            provider=h.item.provider,
            preparation=owner(),
            package=p.package,
            history=retained,
            source=c.source,
            profile=h.item.profile,
            repair_reason="original evidence restored",
        )
        for key, retained in zip((hint.left, hint.right), histories, strict=True)
    ]
    assert await restarted.credit(*restored) == result

    if h.variant == "opportunity":
        from umi.competition_reward_opportunity_review import (
            prepare_opportunity_certificate,
            review_opportunity_certificate,
        )

        terms = dict(
            manifest=p.manifest,
            series=c.series,
            policy=h.item.policy,
            activation=c.active.decision.activation,
        )
        certificate = await prepare_opportunity_certificate(restarted, **terms)
        certificate_bytes = canonical_json_bytes(certificate)
        assert certificate.contributions[0].credited_ms == 12000
        assert certificate.contributions[0].through_block == h.end
        # A portable claim is never authority. Private completed results restore
        # only through selected owner, sources, policy and native history.
        fresh = RewardCoverageJournal(tmp_path / "coverage", rule, **selected)
        with pytest.raises(ValueError, match="no natively verified coverage"):
            await prepare_opportunity_certificate(fresh, **terms)
        by_key = dict(zip((hint.left, hint.right), histories, strict=True))

        async def restore(key):
            return await fresh.review_endpoint(
                key,
                provider=h.item.provider,
                preparation=owner(),
                package=p.package,
                history=by_key[key],
                source=c.source,
                profile=h.item.profile,
            )

        def witness_source(sha):
            return canonical_json_bytes(fresh.journal.get("opportunity_witness", sha))

        async def unavailable(key):
            raise ConnectionError("proof store offline")

        with pytest.raises(ConnectionError, match="proof store offline"):
            await review_opportunity_certificate(
                certificate_bytes,
                expected_sha256=digest(certificate),
                journal=fresh,
                witness_source=witness_source,
                review_endpoint=unavailable,
                **terms,
            )
        assert await fresh.verified_ms(**query) == 0
        checked = await review_opportunity_certificate(
            certificate_bytes,
            expected_sha256=digest(certificate),
            journal=fresh,
            witness_source=witness_source,
            review_endpoint=restore,
            **terms,
        )
        assert checked.certificate == certificate
        assert not checked.chain_submission_authorized
        assert await fresh.verified_ms(**query) == 12000
        assert await prepare_opportunity_certificate(fresh, **terms) == certificate
        # A validly encoded exaggerated total is rejected by native interval
        # replay, not merely by its outer content digest.
        exaggerated = certificate.model_copy(
            update={
                "contributions": (
                    certificate.contributions[0].model_copy(update={"credited_ms": 24000}),
                )
            }
        )
        with pytest.raises(ValueError, match="differs from native replay"):
            await review_opportunity_certificate(
                canonical_json_bytes(exaggerated),
                expected_sha256=digest(exaggerated),
                journal=fresh,
                witness_source=witness_source,
                review_endpoint=restore,
                **terms,
            )
        assert await fresh.verified_ms(**query) == 12000
        assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_native_historical_coverage_capture(
    complete_preparation_case, monkeypatch, record_property
):
    from time import perf_counter

    from umi.competition_reward_coverage import review_reward_coverage
    from umi.competition_reward_coverage_capture import capture_reward_eligibility
    from umi.competition_reward_eligibility_archive import review_reward_eligibility

    h = complete_preparation_case
    p, c = h.package_case, h.c
    for _ in range(100):
        try:
            progress = await h.reader.advance(
                h.item.provider, through_block=h.end, maximum_blocks=4096
            )
        except HistoricalHeaderRecoveryPending:
            continue
        if progress.history is not None:
            break
    else:
        pytest.fail("native history failed to converge")
    owner = StandingRewardPreparation(
        c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
    )
    for height in (h.end - 1, h.end):
        control = await h.item.provider.capture_control_at(c.series.control_hotkey, height)

        # Measure the predecessor's two full control/runtime replays against the
        # same native proof inputs. This is an offline fixture measurement, not
        # a claim about production RPC throughput.
        replays = 0
        original_review = h.item.provider._review_control_runtime_locked

        async def replay_control(original, review=original_review):
            nonlocal replays
            replays += 1
            return await review(original.evidence, original.metadata)

        arguments = dict(
            validator_hotkey=h.validator_hotkey,
            control_hotkey=c.series.control_hotkey,
            profile=h.item.profile,
            expected_runtime_profile_sha256=digest(h.item.profile),
        )
        started = perf_counter()
        with monkeypatch.context() as patch:
            patch.setattr(h.item.provider, "_runtime_for_owned_control_locked", replay_control)
            baseline = await capture_reward_eligibility(h.item.provider, control, **arguments)
        record_property(f"block_{height}_predecessor_capture_seconds", perf_counter() - started)
        assert replays == 2

        async def no_duplicate_control_replay(*args):
            pytest.fail("this owner's already proved control cannot repeat native replay")

        started = perf_counter()
        with monkeypatch.context() as patch:
            patch.setattr(
                h.item.provider, "_review_control_runtime_locked", no_duplicate_control_replay
            )
            captured = await capture_reward_eligibility(h.item.provider, control, **arguments)
        record_property(f"block_{height}_reused_capture_seconds", perf_counter() - started)
        assert captured == baseline

        # Retained wire bytes get no owner-local capability. Their independent
        # replay must still establish exactly the same result.
        restarted = await review_reward_eligibility(
            h.item.provider,
            control=control.evidence,
            metadata=control.metadata,
            chain=captured.chain_evidence,
            eligibility=captured.eligibility_evidence,
            **arguments,
        )
        assert restarted == captured
        assert captured.eligible
        endpoint = await review_reward_coverage(
            owner,
            p.package,
            eligibility=captured,
            history=await h.reader.verified_prefix(height),
            source=c.source,
            expected_runtime_profile_sha256=digest(h.item.profile),
        )
        assert endpoint.covered
        assert not captured.chain_submission_authorized


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_automatic_coverage_capture_lost_ack_and_offline_restart(
    complete_preparation_case, tmp_path, monkeypatch, caplog
):
    from umi.competition_reward_coverage_collector import RewardCoverageCollector
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_opportunity_review import review_opportunity_certificate

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    terms = dict(
        manifest=p.manifest,
        series=c.series,
        policy=c.reader.policy,
        activation=c.active.decision.activation,
    )
    root = tmp_path / "automatic-coverage"

    def setup():
        journal = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
        owner = StandingRewardPreparation(
            c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
        )
        source = NativeRewardCoverageSource(
            provider=h.item.provider,
            journal=journal,
            history=h.reader,
            preparation=owner,
            package=p.package,
            decisions=c.source,
            profile=h.item.profile,
            maximum_history_blocks=4096,
        )
        collector = RewardCoverageCollector(
            journal, source, **terms, first_block=h.end - 1, maximum_endpoints_per_validator=1
        )
        return journal, source, collector

    async def head():
        return h.end

    journal, source, collector = setup()
    monkeypatch.setattr(source, "finalized_height", head)
    replay_package = source.preparation.prepare_historical
    preparations = 0

    async def slow_package(*args, **kwargs):
        nonlocal preparations
        preparations += 1
        if preparations == 1:
            # Immutable work may outlast an individual RPC's configured timer.
            # It must finish once, without being cancelled and restarted.
            await asyncio.sleep(h.item.config.collection_timeout_seconds + 0.05)
        return await replay_package(*args, **kwargs)

    monkeypatch.setattr(source.preparation, "prepare_historical", slow_package)
    # Capture the left endpoint in one bounded pass. No interval exists yet.
    for _ in range(100):
        progress = await collector.step()
        if collector._left:
            break
    else:
        pytest.fail("automatic native capture failed to converge")
    assert progress.credited_ms == ((h.validator_hotkey, 0),)
    assert progress.certificate is None
    assert preparations == 1
    original_put = journal.journal.put_many

    def lose_ack(records, **kw):
        original_put(records, **kw)
        if any(kind == "coverage_interval" for kind, _, _ in records):
            raise OSError("private RPC URL must not appear in logs")

    monkeypatch.setattr(journal.journal, "put_many", lose_ack)
    lost = await collector.step()
    assert (h.validator_hotkey, "OSError") in lost.errors
    assert lost.certificate is None
    assert lost.credited_ms == ((h.validator_hotkey, 0),)
    assert len(await journal.interval_keys()) == 1
    retained_interval = await journal.retained_interval((await journal.interval_keys())[0])
    original_completion = journal.checkpoints.load(retained_interval.left)

    # A fresh process trusts neither summaries nor totals. All historical state
    # and block body RPCs are unavailable; only owned ancestry is still served.
    h.reader = await h.restart()
    h.offline_through = h.end
    c.reader = c.reopen()
    journal, source, collector = setup()

    # The same capture API now discovers this completed block from owned history
    # and restores its original durable verdict. It must not ask RPC to capture
    # the already verified proofs again, including after an offline restart.
    async def no_recapture(*args, **kwargs):
        pytest.fail("completed historical endpoint repeated native capture")

    with monkeypatch.context() as patch:
        patch.setattr(h.item.provider, "capture_control_at", no_recapture)
        patch.setattr(
            "umi.competition_reward_coverage_source.capture_reward_eligibility", no_recapture
        )
        for _ in range(100):
            try:
                restored = await source.capture(h.validator_hotkey, h.end - 1)
                break
            except CoverageHistoryPending:
                continue
        else:
            pytest.fail("completed endpoint restoration did not converge")
    from umi.competition_reward_coverage_intervals import OwnedRetainedCoverageEndpoint

    assert type(restored) is OwnedRetainedCoverageEndpoint
    assert journal.checkpoints.load(retained_interval.left) == original_completion
    assert (
        await journal.verified_ms(
            activation_sha256=digest(terms["activation"]), validator_hotkey=h.validator_hotkey
        )
        == 0
    )

    async def no_current_head():
        raise TimeoutError("private provider token must not appear in logs")

    monkeypatch.setattr(source, "finalized_height", no_current_head)
    with caplog.at_level("INFO"):
        certificate = await asyncio.wait_for(collector.run(asyncio.Event(), poll_seconds=0.001), 90)
    assert certificate is not None
    assert len(certificate.contributions) == 1
    assert certificate.contributions[0].credited_ms == 12000
    assert "coverage_complete" in caplog.text
    assert "private provider" not in caplog.text
    before = await journal.interval_keys()
    assert (await collector.step()).certificate == certificate
    assert await journal.interval_keys() == before
    reviewed = await review_opportunity_certificate(
        canonical_json_bytes(certificate),
        expected_sha256=digest(certificate),
        journal=journal,
        witness_source=lambda sha: canonical_json_bytes(
            journal.journal.get("opportunity_witness", sha)
        ),
        review_endpoint=source.replay,
        **terms,
    )
    assert reviewed.certificate == certificate


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
@pytest.mark.parametrize("interruption", ["completion_ack", "export", "none"])
async def test_installed_coverage_discovers_completes_and_recovers_without_coordinator(
    complete_preparation_case, tmp_path, monkeypatch, caplog, interruption
):
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_service import StandingRewardCoverageService
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_publication import retain_standing_reward_inputs

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    files = StandingRewardFiles(
        tmp_path / "delivery",
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=1024 * 1024,
    )
    retain_standing_reward_inputs(
        files,
        c.series,
        c.reader.policy,
        tuple(
            sorted(
                (
                    SignedRewardControlDecision.model_validate_json(raw)
                    for raw in c.objects.values()
                ),
                key=lambda value: value.decision.sequence,
            )
        ),
        lambda _: p.package,
    )
    root = tmp_path / "installed-coverage"

    collect_control = type(h.item.provider).collect_control

    async def fresh_height(hotkey):
        # Discovery and recent capture both require the selected proof adapter's
        # owned observation; a bare height is not current finality authority.
        current_control_finality(h, h.end)
        return await collect_control(h.item.provider, hotkey)

    def setup():
        journal = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
        owner = StandingRewardPreparation(
            c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
        )
        service = StandingRewardCoverageService(
            provider=h.item.provider,
            journal=journal,
            history=h.reader,
            preparation=owner,
            files=files,
            profile=h.item.profile,
            maximum_history_blocks=4096,
        )
        return journal, service

    monkeypatch.setattr(h.item.provider, "collect_control", fresh_height)
    journal, service = setup()
    original_put = journal.journal.put_many
    original_export = files.retain_completion
    failure = False

    def lose_ack(records, **kw):
        nonlocal failure
        original_put(records, **kw)
        if any(kind == "coverage_completion" for kind, _, _ in records):
            failure = True
            raise OSError("private URL must not be logged")

    def partial_export(certificate, witness_source):
        nonlocal failure
        # A fully exported record may also lose its acknowledgement. Retry
        # must neither replace the certificate nor increment credited time.
        original_export(certificate, witness_source)
        failure = True
        raise OSError("private URL must not be logged")

    if interruption == "completion_ack":
        monkeypatch.setattr(journal.journal, "put_many", lose_ack)
    if interruption == "export":
        monkeypatch.setattr(files, "retain_completion", partial_export)
    key = c.active.decision.activation.cohort_sha256
    if interruption == "none":
        for _ in range(100):
            await service.step()
            if journal.journal.get("coverage_work", key) is not None:
                break
        else:
            pytest.fail("native discovery did not converge")
        read = journal.journal.get

        def changed_start(kind, record_key, **kwargs):
            value = read(kind, record_key, **kwargs)
            if kind == "coverage_work" and value is not None:
                return {**value, "first_block": value["first_block"] + 1}
            return value

        monkeypatch.setattr(journal.journal, "get", changed_start)
        with pytest.raises(ValueError, match="original effective control"):
            await service._collect()
        assert journal.journal.get("coverage_completion", key) is None
        monkeypatch.setattr(journal.journal, "get", read)
    with caplog.at_level("INFO"):
        for _ in range(100):
            await service.step()
            if failure or key in service._completed:
                break
        else:
            pytest.fail("automatic installed collection did not finish: " + caplog.text)
    completion = journal.journal.get("coverage_completion", key)
    assert completion is not None
    if interruption != "none":
        assert key not in service._completed
    assert "private URL" not in caplog.text
    interval_keys = await journal.interval_keys()
    assert len(interval_keys) == 1

    # Reopen all native owners with no trusted totals. Coordinator decisions,
    # current-head discovery and historical state/body RPCs are unavailable.
    h.reader = await h.restart()
    c.reader = c.reopen()
    h.offline_through = h.end
    c.objects.clear()
    for path in (files.root / "decisions").glob("*.json"):
        path.unlink()
    monkeypatch.setattr(files, "retain_completion", original_export)

    async def unavailable(_hotkey):
        raise TimeoutError("private provider credential must not be logged")

    monkeypatch.setattr(h.item.provider, "collect_control", unavailable)
    journal, service = setup()
    assert (
        await journal.verified_ms(
            activation_sha256=digest(c.active.decision.activation),
            validator_hotkey=h.validator_hotkey,
        )
        == 0
    )
    with caplog.at_level("INFO"):
        for _ in range(100):
            await service.step()
            if key in service._completed:
                break
        else:
            pytest.fail("retained native coverage failed to recover: " + caplog.text)
    verified = service._completed[key]
    assert digest(verified.certificate) == completion["certificate_sha256"]
    assert await service.completed_opportunity(c.active.decision.activation) == verified
    with pytest.raises(ValueError, match="differs from signed reward selection"):
        await service.completed_opportunity(
            c.active.decision.activation.model_copy(update={"allocation_sha256": "ff" * 32})
        )
    from umi.competition_cohort_recovery import (
        SignedCohortRecoveryAuthority,
        StandingCohortRecoveryAuthority,
    )
    from umi.competition_reward_decisions import (
        StandingRewardSeries,
        StandingRewardSeriesPredecessor,
    )
    from umi.competition_reward_handoff_models import StandingRewardHandoffPlan
    from umi.competition_reward_series_handoff import (
        StandingRewardPredecessorOpportunity,
        validate_standing_predecessor_opportunity,
    )

    prior_plan = c.series.cohorts[-1]
    plans = (
        prior_plan.model_copy(
            update={
                "sequence": prior_plan.sequence + 1,
                "suite_sha256": "fe" * 32,
            }
        ),
    )
    authority_body = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=c.series.policy_sha256,
        cohort_sha256s=tuple(sorted(digest(plan) for plan in plans)),
        issued_at_block=max(
            c.active.decision.observed_at_block,
            c.series.recovery.authority.issued_at_block,
        ),
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    authority = SignedCohortRecoveryAuthority(
        authority=authority_body, signatures=signatures(authority_body)
    )
    predecessor = StandingRewardSeriesPredecessor(
        schema="umi-standing-reward-series-predecessor/1",
        series_sha256=digest(c.series),
        policy_sha256=c.series.policy_sha256,
        manifest_sha256=digest(p.manifest),
        recovery_sha256=digest(c.series.recovery),
        cohort_sha256=digest(prior_plan),
        cohort_sequence=prior_plan.sequence,
        control_hotkey=c.series.control_hotkey,
        decision_sha256=digest(c.active.decision),
        activation_sha256=digest(c.active.decision.activation),
        decision_committed_at_block=c.active.decision.observed_at_block,
    )
    successor = StandingRewardSeries.model_validate_json(
        canonical_json_bytes(
            c.series.model_copy(
                update={
                    "schema_": "umi-standing-reward-series/2",
                    "recovery": authority,
                    "cohorts": plans,
                    "predecessor": predecessor,
                }
            )
        )
    )
    plan = StandingRewardHandoffPlan(
        schema="umi-standing-reward-handoff-plan/1",
        series_sha256=digest(successor),
        cohort_sha256=digest(successor.cohorts[0]),
        predecessor=predecessor,
    )
    handoff = StandingRewardPredecessorOpportunity(successor=successor, plan=plan, coverage=service)
    assert handoff.certificate_sha256() == digest(verified.certificate)
    successor_activation = c.active.decision.activation.model_copy(
        update={
            "cohort_sha256": digest(successor.cohorts[0]),
            "prior_opportunity_sha256": digest(verified.certificate),
        }
    )
    reviewed = await handoff.review(successor_activation, observed_at_block=h.end + 1)
    assert (
        validate_standing_predecessor_opportunity(
            reviewed,
            plan=plan,
            activation=successor_activation,
            block=h.end + 1,
        )
        == verified.certificate
    )
    assert verified.certificate.contributions[0].credited_ms == 12000
    assert (
        await journal.verified_ms(
            activation_sha256=digest(c.active.decision.activation),
            validator_hotkey=h.validator_hotkey,
        )
        == 12000
    )
    assert not verified.chain_submission_authorized
    assert files.certificate(digest(verified.certificate)) == canonical_json_bytes(
        verified.certificate
    )
    assert await journal.interval_keys() == interval_keys
    assert journal.journal.get("coverage_completion", key) == completion
    assert "private provider credential" not in caplog.text
    assert "coverage_complete" in caplog.text
    await service.step()
    assert await journal.interval_keys() == interval_keys
    original_config_sha256 = service.history.config_sha256
    service.history.config_sha256 = "ff" * 32
    with pytest.raises(ValueError, match="signed boundary"):
        handoff.certificate_sha256()
    service.history.config_sha256 = original_config_sha256


@pytest.mark.parametrize(
    "complete_preparation_case",
    [
        {"kind": "opportunity", "intervals": 8, "outage_blocks": 150},
        pytest.param(
            {"kind": "opportunity", "intervals": 7200, "outage_blocks": 3000},
            marks=pytest.mark.skipif(
                os.environ.get("UMI_RUN_REWARD_DAY_REHEARSAL") != "1",
                reason="full native 24-hour proof replay requires explicit scale opt-in",
            ),
            id="24-hours-two-validators",
        ),
    ],
    indirect=True,
)
async def test_coverage_waits_for_both_validators_and_rebuilds_after_outage(
    complete_preparation_case, tmp_path, monkeypatch
):
    """Native evidence and accounting; headers/trie/runtime remain synthetic.

    The optional scale case uses all 7,200 twelve-second intervals per validator,
    not enlarged block timestamps or fabricated pre-credited journal totals.
    """
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_service import StandingRewardCoverageService
    from umi.competition_reward_coverage_source import NativeRewardCoverageSource
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_publication import retain_standing_reward_inputs

    h = complete_preparation_case
    p, c = h.package_case, h.c
    count = h.coverage_scale["intervals"]
    minimum = count * 12000
    half = count // 2
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    files = StandingRewardFiles(
        tmp_path / "day-delivery",
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=16 * 1024**2,
    )
    retain_standing_reward_inputs(
        files,
        c.series,
        c.reader.policy,
        tuple(
            sorted(
                (SignedRewardControlDecision.model_validate_json(v) for v in c.objects.values()),
                key=lambda v: v.decision.sequence,
            )
        ),
        lambda _: p.package,
    )
    key = c.active.decision.activation.cohort_sha256
    activation_sha = digest(c.active.decision.activation)
    head, online, slow = h.coverage_first + min(half, 32), True, True
    slow_hotkey = h.item.members[1]

    collect_control = type(h.item.provider).collect_control

    async def current_height(hotkey):
        if not online:
            raise ConnectionError("coordinator and current-head discovery unavailable")
        current_control_finality(h, head)
        return await collect_control(h.item.provider, hotkey)

    original_capture = NativeRewardCoverageSource.capture

    async def capture(source, hotkey, height):
        if slow and hotkey == slow_hotkey:
            raise TimeoutError("one validator proof is temporarily unavailable")
        try:
            return await original_capture(source, hotkey, height)
        except ValueError as error:
            # This isolated test has synthetic/public inputs only. Expose its
            # actual failure instead of spinning on sanitized service reports.
            pytest.fail(f"native capture failed at block {height}: {error}")

    monkeypatch.setattr(NativeRewardCoverageSource, "capture", capture)

    def setup():
        monkeypatch.setattr(h.item.provider, "collect_control", current_height)
        journal = RewardCoverageJournal(
            tmp_path / "day-coverage",
            rule,
            expected_rule_sha256=digest(rule),
            maximum_bytes=2 * 1024**3,
        )
        service = StandingRewardCoverageService(
            provider=h.item.provider,
            journal=journal,
            history=h.reader,
            preparation=StandingRewardPreparation(
                c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
            ),
            files=files,
            profile=h.item.profile,
            maximum_history_blocks=4096,
        )
        return journal, service

    async def totals():
        return [
            await journal.verified_ms(activation_sha256=activation_sha, validator_hotkey=k)
            for k in c.series.validators
        ]

    async def collect_until(target, *, initial=False):
        nonlocal head
        previous_state, stalled_passes = None, 0
        for step in range(count * 4 + 2000):
            await service.step()
            amounts = await totals()
            if step % 100 == 0:
                print(
                    {
                        "phase": "initial" if initial else "resumed",
                        "step": step,
                        "head": head,
                        "credited_ms": amounts,
                    },
                    flush=True,
                )
            if min(amounts) >= target:
                return
            collector = service._collector
            state = (head, tuple(amounts), h.reader._next)
            stalled_passes = stalled_passes + 1 if state == previous_state else 0
            previous_state = state
            assert stalled_passes < 100, "native collection stopped advancing"
            if collector and all(collector._next.get(k, 0) > head for k in c.series.validators):
                # Keep the simulated producer within the collector's recent
                # window. Larger jumps deliberately create gaps and need a
                # separate backfill drain before advancing the finite chain.
                head += min(collector.capture_window, max(1, (target - min(amounts)) // 12000))
                assert head <= h.end
        pytest.fail("native coverage failed to reach the selected minimum")

    journal, service = setup()
    # A healthy validator cannot complete the obligation for its slow peer.
    for _ in range(2000):
        await service.step()
        if max(await totals()) >= 12000:
            break
    else:
        pytest.fail("healthy validator failed to collect coverage")
    assert min(await totals()) == 0
    assert journal.journal.get("coverage_completion", key) is None
    slow = False
    await collect_until(half * 12000, initial=True)
    assert journal.journal.get("coverage_completion", key) is None
    before = await totals()
    assert all(value < minimum for value in before)

    # Reopen every native owner. Stored totals do not carry native authority.
    h.reader = await h.restart()
    h.reader = h.new_reader(maximum_bytes=256 * 1024**2)
    c.reader = c.reopen()
    journal, service = setup()
    assert await totals() == [0, 0]
    online = False
    for _ in range(2000):
        await service.step()
        if await totals() == before:
            break
    else:
        pytest.fail("retained proofs did not rebuild the verified pre-outage time")
    assert journal.journal.get("coverage_completion", key) is None
    # The missing ten hours in the scale case cannot count as reward coverage.
    head += h.coverage_scale["outage_blocks"] + 128
    online = True
    await collect_until(minimum)
    assert await totals() == [minimum, minimum]
    verified = service._completed[key]
    assert len(verified.certificate.contributions) == 2
    assert all(v.credited_ms == minimum for v in verified.certificate.contributions)
    assert not verified.chain_submission_authorized
    original_completion = journal.journal.get("coverage_completion", key)
    await service.step()
    assert await totals() == [minimum, minimum]
    assert journal.journal.get("coverage_completion", key) == original_completion
    print(
        {
            "status": "native_coverage_recovered",
            "validators": 2,
            "minimum_ms": minimum,
            "outage_blocks": h.coverage_scale["outage_blocks"],
            "certificate_sha256": digest(verified.certificate),
        },
        flush=True,
    )


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_portable_proofs_restore_fresh_native_journals_without_history_rpc(
    complete_preparation_case, tmp_path, monkeypatch
):
    import json
    import shutil

    from umi.competition_chain_resources import CompetitionChainResources
    from umi.competition_reward_control_archive import HistoricalRewardControlProvider
    from umi.competition_reward_coverage_collector import RewardCoverageCollector
    from umi.competition_reward_coverage_intervals import coverage_point
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_history import RewardControlHistoryReader
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_opportunity_review import review_opportunity_certificate
    from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
    from umi.competition_reward_publication import retain_standing_reward_inputs

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    terms = dict(
        manifest=p.manifest,
        series=c.series,
        policy=c.reader.policy,
        activation=c.active.decision.activation,
    )
    owner = StandingRewardPreparation(
        c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
    )
    archive = RewardProofArchive(tmp_path / "proof-export")
    original_write = archive.write
    original_compact_copy = archive.copy_encoded_transport
    interrupted = set()

    def lost_export_reply(kind, *args, **kwargs):
        original_write(kind, *args, **kwargs)
        if kind not in interrupted:
            interrupted.add(kind)
            raise OSError("export acknowledgement lost")

    def lost_compact_export_reply(kind, *args, **kwargs):
        copied = original_compact_copy(kind, *args, **kwargs)
        if copied and kind not in interrupted:
            interrupted.add(kind)
            raise OSError("compact export acknowledgement lost")
        return copied

    monkeypatch.setattr(archive, "write", lost_export_reply)
    monkeypatch.setattr(archive, "copy_encoded_transport", lost_compact_export_reply)
    h.reader = RewardControlHistoryReader(
        tmp_path / "export-history",
        control_hotkey=c.series.control_hotkey,
        chain_config_sha256=digest(h.item.config),
        first_block=h.old.height,
        maximum_bytes=64 * 1024**2,
        export_archive=archive,
    )
    journal = RewardCoverageJournal(
        tmp_path / "source-coverage",
        rule,
        expected_rule_sha256=digest(rule),
        export_archive=archive,
    )
    source = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=journal,
        history=h.reader,
        preparation=owner,
        package=p.package,
        decisions=c.source,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )

    async def head():
        return h.end

    source.finalized_height = head
    collector = RewardCoverageCollector(journal, source, **terms, first_block=h.end - 1)
    for _ in range(100):
        progress = await collector.step()
        if progress.certificate is not None:
            break
    else:
        pytest.fail("source opportunity capture did not complete")
    certificate = progress.certificate
    assert interrupted == {"history", "endpoint", "interval"}
    (interval_key,) = await journal.interval_keys()
    interval = await journal.retained_interval(interval_key)
    assert len(tuple((archive.root / "history").glob("*.json"))) == h.end - h.old.height + 1
    witness_bytes = {
        contribution.witness_sha256: canonical_json_bytes(
            journal.journal.get("opportunity_witness", contribution.witness_sha256)
        )
        for contribution in certificate.contributions
    }

    # Produce the actual private delivery layout rather than giving the new
    # reader direct callbacks into the coordinator's package/decision objects.
    delivery = StandingRewardFiles(
        tmp_path / "input-export",
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    retain_standing_reward_inputs(
        delivery,
        c.series,
        c.reader.policy,
        (c.genesis, c.active),
        lambda sha: p.package if sha == digest(p.package) else pytest.fail("unexpected package"),
    )
    delivery.retain_completion(certificate, witness_bytes.__getitem__)
    received_root = tmp_path / "input-import"
    shutil.copytree(delivery.root, received_root)
    shutil.rmtree(delivery.root)
    received = StandingRewardFiles(
        received_root,
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    restored_package = received.package(digest(p.package))
    certificate_bytes = received.certificate(digest(certificate))
    witness_bytes.clear()

    # File transfer substitutes only the network port. No live SQLite file,
    # verification flag, aggregate total or provider cache moves to the receiver.
    remote_root = tmp_path / "proof-import"
    shutil.copytree(archive.root, remote_root)
    assert not tuple(remote_root.rglob("*.sqlite3"))
    imported = RewardProofArchive(remote_root)
    resources = CompetitionChainResources.from_config(h.item.config).model_copy(
        update={"state_directory": str(tmp_path / "receiver-chain-cache")}
    )
    h.reopen = lambda: HistoricalRewardControlProvider(
        h.item.config,
        h.item.policy,
        resources=resources,
        historical_header_directory=tmp_path / "receiver-headers",
        finality=h.item.finality,
        proofs=h.item.proofs,
        now_ms=lambda: h.item.clock.now,
    )
    await h.restart()
    h.offline_through = h.end
    h.rpc_calls.clear()
    history = RewardControlHistoryReader(
        tmp_path / "receiver-history",
        control_hotkey=c.series.control_hotkey,
        chain_config_sha256=digest(h.item.config),
        first_block=h.old.height,
        maximum_bytes=64 * 1024**2,
        archive=imported,
    )
    receiver = RewardCoverageJournal(
        tmp_path / "receiver-coverage",
        rule,
        expected_rule_sha256=digest(rule),
        archive=imported,
    )
    # Model/promotion assets still use the separately supplied native store.
    # Packages, signed decisions, witnesses and certificates use restored files.
    reader = StandingRewardControlReader(
        tmp_path / "receiver-control",
        c.series,
        c.reader.policy,
        expected_series_sha256=digest(c.series),
        expected_chain_config_sha256=digest(h.item.config),
        maximum_bytes=8 * 1024**2,
    )
    owner = StandingRewardPreparation(
        reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
    )
    source = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=receiver,
        history=history,
        preparation=owner,
        package=restored_package,
        decisions=received.decision,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )
    assert (
        await receiver.verified_ms(
            activation_sha256=digest(terms["activation"]), validator_hotkey=h.validator_hotkey
        )
        == 0
    )
    first_key = history_archive_key(history.config_sha256, history.hotkey, history.first_block)
    first_path = remote_root / "history" / (first_key + ".json")
    first_bytes = first_path.read_bytes()
    changed = json.loads(first_bytes)
    changed["context"]["block"] += 1
    first_path.write_bytes(canonical_json_bytes(changed))
    with pytest.raises(ValueError, match="requested domain"):
        await history.advance(h.item.provider, through_block=h.end, maximum_blocks=4096)
    assert history.journal.keys("control_history_block") == []
    first_path.write_bytes(first_bytes)

    left_path = remote_root / "endpoint" / (interval.left + ".json")
    left_bytes = left_path.read_bytes()
    changed = json.loads(left_bytes)
    changed["context"]["point"]["block"] += 100000
    left_path.write_bytes(canonical_json_bytes(changed))
    for _ in range(100):
        try:
            await source.replay(interval.left)
        except (HistoricalHeaderRecoveryPending, CoverageHistoryPending):
            continue
        except ValueError as error:
            assert "native coverage replay differs" in str(error)
            break
        else:
            pytest.fail("altered remote point became a native endpoint")
    else:
        pytest.fail("native replay did not reach imported summary check")
    assert history._next <= h.end + 1  # never chase the untrusted +100000 height
    assert receiver.journal.get("coverage_endpoint", interval.left) is None
    left_path.write_bytes(left_bytes)

    interval_path = remote_root / "interval" / (interval_key + ".json")
    interval_bytes = interval_path.read_bytes()
    changed = json.loads(interval_bytes)
    changed["context"]["credited_ms"] += 1
    interval_path.write_bytes(canonical_json_bytes(changed))

    async def review():
        return await review_opportunity_certificate(
            certificate_bytes,
            expected_sha256=digest(certificate),
            journal=receiver,
            witness_source=received.witness,
            review_endpoint=source.replay,
            **terms,
        )

    for _ in range(100):
        try:
            await review()
        except (HistoricalHeaderRecoveryPending, CoverageHistoryPending):
            continue
        except ValueError as error:
            assert "ordered native coverage" in str(error)
            break
        else:
            pytest.fail("altered remote interval became a native certificate")
    else:
        pytest.fail("native replay did not reach imported interval check")
    assert receiver.journal.get("coverage_interval", interval_key) is None
    assert (
        await receiver.verified_ms(
            activation_sha256=digest(terms["activation"]), validator_hotkey=h.validator_hotkey
        )
        == 0
    )
    interval_path.write_bytes(interval_bytes)
    verified = await review()
    assert verified.certificate == certificate
    assert (
        await receiver.verified_ms(
            activation_sha256=digest(terms["activation"]), validator_hotkey=h.validator_hotkey
        )
        == 12000
    )
    assert receiver.journal.get("coverage_interval", interval_key) is not None
    assert coverage_point(await source.replay(interval.left), rule).key() == interval.left
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}


@pytest.mark.parametrize("interrupt_after", ["packages", "decisions"])
async def test_reward_input_publication_recovers_original_bytes_and_offline_source(
    preparation_case, tmp_path, monkeypatch, interrupt_after
):
    from umi import competition_reward_files as file_module
    from umi import competition_reward_publication as module
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles

    p = preparation_case
    prefix = tuple(
        sorted(
            (SignedRewardControlDecision.model_validate_json(v) for v in p.objects.values()),
            key=lambda v: v.decision.sequence,
        )
    )
    files = StandingRewardFiles(
        tmp_path / "publication",
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    publisher = (
        "publish_aggregate_model" if interrupt_after == "packages" else "publish_private_model"
    )
    original = getattr(file_module, publisher)
    interrupted = False

    def lost_reply(path, *args, **kwargs):
        nonlocal interrupted
        original(path, *args, **kwargs)
        if path.parent.name == interrupt_after and not interrupted:
            interrupted = True
            raise OSError("publication reply lost")

    monkeypatch.setattr(file_module, publisher, lost_reply)
    with pytest.raises(OSError, match="reply lost"):
        module.retain_standing_reward_inputs(
            files,
            p.reader.series,
            p.reader.policy,
            prefix,
            lambda _: p.package,
        )
    before = {path: path.read_bytes() for path in files.root.rglob("*.json")}
    reopened = StandingRewardFiles(
        files.root,
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    head = module.retain_standing_reward_inputs(
        reopened,
        p.reader.series,
        p.reader.policy,
        prefix,
        lambda _: pytest.fail("completed package fetched after restart"),
    )
    assert head == digest(p.active.decision)
    assert all(path.read_bytes() == raw for path, raw in before.items())
    complete = {path: path.read_bytes() for path in files.root.rglob("*.json")}
    variants = tuple(signed(item.decision) for item in prefix)
    module.retain_standing_reward_inputs(
        reopened,
        p.reader.series,
        p.reader.policy,
        variants,
        lambda _: pytest.fail("immutable retry fetched a package"),
    )
    assert all(path.read_bytes() == raw for path, raw in complete.items())


@pytest.mark.parametrize("fault", ["missing", "wrong_package", "wrong_allocation", "unsigned"])
async def test_reward_input_publication_holds_incomplete_or_conflicting_inputs(
    preparation_case, tmp_path, fault
):
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_publication import retain_standing_reward_inputs

    p = preparation_case
    prefix = tuple(
        sorted(
            (SignedRewardControlDecision.model_validate_json(v) for v in p.objects.values()),
            key=lambda v: v.decision.sequence,
        )
    )
    files = StandingRewardFiles(
        tmp_path / "publication",
        maximum_package_bytes=8 * 1024**2,
        maximum_witness_bytes=1024**2,
    )

    def source(_):
        if fault == "missing":
            raise FileNotFoundError("package pending")
        return (
            p.package.model_copy(update={"policy_sha256": "00" * 32})
            if fault == "wrong_package"
            else p.package
        )

    if fault == "wrong_allocation":
        decision = prefix[-1].decision.model_copy(
            update={
                "activation": p.active.decision.activation.model_copy(
                    update={"allocation_sha256": "00" * 32}
                ),
            }
        )
        prefix = (*prefix[:-1], signed(decision))
    elif fault == "unsigned":
        prefix = (*prefix[:-1], prefix[-1].model_copy(update={"signatures": ()}))
    with pytest.raises((ValueError, FileNotFoundError)):
        retain_standing_reward_inputs(files, p.reader.series, p.reader.policy, prefix, source)
    assert not tuple((files.root / "decisions").glob("*.json"))


@pytest.fixture
async def native_settlement_case(native_package, service_quality_inputs, tmp_path):
    from umi.competition_cohort_quality_signing import (
        CertifiedClosedQuality,
        SignedClosedQualityVote,
    )
    from umi.competition_cohort_service_certification import ServiceAllocationVote
    from umi.competition_cohort_settlement import CohortSettlement

    p, b = native_package, service_quality_inputs
    objects = {item.sha256: canonical_json_bytes(item.value) for item in p.package.objects}
    votes = []
    for ref in p.package.benchmark.participants:
        cert = CertifiedClosedQuality.model_validate_json(objects[ref.certificate_sha256])
        votes.extend(
            SignedClosedQualityVote(result=cert.result, signature=signature)
            for signature in cert.signatures
        )
    service_votes = tuple(
        ServiceAllocationVote(statement=p.package.service.statement, signature=signature)
        for signature in p.package.service.signatures
    )

    def reopen(name="settlement"):
        return CohortSettlement(
            plan=b["history"].plan,
            authority=b["history"].authority,
            requirement=p.requirement,
            policy=b["policy"],
            journal=RoundJournal(tmp_path / name, {"cohort": p.requirement.cohort_sha256}),
            promotion_store=p.store,
            objects=objects.__getitem__,
            decisions=b["decisions"].__getitem__,
            pulses=lambda _: RetainedRevealPulse(**pulse_record()),
            output_directory=tmp_path / "settled-packages",
            maximum_promotion_bytes=1_000_000,
        )

    return SimpleNamespace(
        native=p,
        b=b,
        inputs=p.package.inputs.model_copy(update={"history": b["history"]}),
        quality_votes=tuple(votes),
        service_votes=service_votes,
        reopen=reopen,
        objects=objects,
    )


@pytest.fixture
def original_settlement_inputs(service_quality_inputs):
    from umi.competition_cohort_settlement_inputs import prepare_settlement_inputs

    b = service_quality_inputs
    c = b["service_case"]
    inputs = RewardReplayInputs(
        closure=b["closure"],
        roster=b["roster"],
        suite=b["suite"],
        transport=b["transport"],
        terms=c.terms,
        reveal=b["reveal"],
        catalogs=(c.assignment.catalog,),
        seals=(b["service_seal"],),
        history=b["history"],
    )
    requirement = RewardReplayRequirement(
        cohort_sha256=digest(inputs.history.plan),
        terms_sha256=digest(c.terms),
        catalog_sha256s=(digest(c.assignment.catalog.catalog),),
    )
    package = prepare_settlement_inputs(
        inputs,
        b["policy"],
        requirement,
        b["objects"].__getitem__,
        b["decisions"].__getitem__,
        iter(b["records"]),
        lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(inputs.history),
        current_block=1000000,
    )
    return SimpleNamespace(b=b, package=package, requirement=requirement)


@pytest.fixture
def settlement_service_umask():
    # Both deployed settlement and replication units use UMask=0077. These
    # integration fixtures run their services and copy loop in this process;
    # pathlib's parents=True otherwise creates intermediate directories with
    # the pytest runner's umask, unlike either supported service entry point.
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.fixture
async def recurring_settlement_case(
    original_settlement_inputs, registered_case, tmp_path, request, settlement_service_umask
):
    """Real owner journals, signatures, file exchange and native settlement.

    Only finality/proof verification and the original fixture model are synthetic.
    No completed package or quality votes are supplied to these services.
    """
    from collections import Counter
    from contextlib import ExitStack
    from pathlib import Path

    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.competition_cohort_settlement_boot import settlement_store
    from umi.competition_cohort_settlement_config import SettlementServiceConfig
    from umi.competition_cohort_settlement_inputs import publish_settlement_inputs
    from umi.competition_cohort_settlement_proofs import SettlementRegistrationFiles
    from umi.competition_cohort_settlement_service import CohortSettlementService
    from umi.open_competition import identity
    from umi.private_files import ensure_private_directory, publish_private_model

    from .test_competition_cohort_coordinator import Harness

    c, b = original_settlement_inputs, original_settlement_inputs.b
    history = c.package.inputs.history
    reference_start = getattr(request, "param", False)
    if reference_start:
        assert history.transitions[-1].transition.phase == "reference_reveal"
        history = history.model_copy(update={"transitions": history.transitions[:-1]})
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(b["policy"]),
        cohorts=(c.requirement,),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(b["policy"]),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Ferdie").hotkey.ss58_address,
        recovery=history.authority,
        cohorts=(history.plan,),
        validators=(registered_case.hotkey,),
        maximum_proof_lag_blocks=2,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    clock = SimpleNamespace(
        block=history.transitions[-1].transition.observed_at_block + 100,
        collects=0,
        fail_collect=False,
    )
    calls = Counter()

    async def collect():
        return await Harness.collect(clock)

    async def archive(observation):
        return b"original-registration-proof", b"runtime-metadata"

    async def review_archive(observation, raw, metadata):
        assert (raw, metadata) == await archive(observation)
        assert observation.block <= clock.block
        return SimpleNamespace(
            original=observation, replayed_at=SimpleNamespace(block_number=clock.block)
        )

    provider = SimpleNamespace(
        policy=b["policy"],
        collect=collect,
        retained_archive=archive,
        review_archive=review_archive,
        ensure_observer_running=lambda: None,
    )
    result = SimpleNamespace(
        c=c,
        b=b,
        nodes={},
        stacks={},
        configs={},
        calls=calls,
        clock=clock,
        provider=provider,
        assemble_inputs=False,
        reference_start=reference_start,
        original_sources=None,
        seed_handoff=True,
    )

    def config(name):
        root = tmp_path / ("recurring-" + name)
        ensure_private_directory(root)
        configs = tuple(
            o.config
            for o in b["owners"].values()
            if identity(o.config.signer) == identity(wallet(name).hotkey.ss58_address)
        )
        paths = {
            key: str(root / key)
            for key in (
                "state_directory",
                "inputs_directory",
                "history_directory",
                "promotion_directory",
                "settlement_directory",
                "proof_import_directory",
                "proof_export_directory",
                "exchange_inbox",
                "exchange_outbox",
            )
        }
        from .cohort_settlement_original_fixture import select_original_sources

        sources = (
            (result.original_sources or select_original_sources(root / "originals", history))
            if result.assemble_inputs and name == "Charlie"
            else None
        )
        return SettlementServiceConfig(
            schema="umi-cohort-settlement-config/2"
            if sources
            else "umi-cohort-settlement-config/1",
            original_sources=sources,
            role="coordinator" if name == "Charlie" else "reviewer",
            series=series,
            policy=b["policy"],
            manifest=manifest,
            chain=registered_case.config.model_copy(
                update={
                    "policy_sha256": digest(b["policy"]),
                    "state_directory": str(root / "chain"),
                    "proof_rpc_fallback_urls": (
                        "wss://backup-one.example.org",
                        "wss://backup-two.example.org",
                    ),
                }
            ),
            signer_hotkey=wallet(name).hotkey.ss58_address,
            proposer_hotkey=wallet("Charlie").hotkey.ss58_address,
            signer_key_file=str(root / "key"),
            executions=configs,
            maximum_package_bytes=64 * 1024**2,
            maximum_promotion_bytes=1_000_000,
            maximum_state_bytes=128 * 1024**2,
            **paths,
        )

    async def start(name):
        old = result.stacks.pop(name, None)
        if old:
            old.close()
        conf = result.configs.setdefault(name, config(name))
        stack = result.stacks[name] = ExitStack()
        store = stack.enter_context(
            settlement_store(
                Path(conf.state_directory) / digest(series) / digest(history.plan),
                conf.maximum_state_bytes,
            )
        )
        proofs = SettlementRegistrationFiles(
            provider,
            inbox=Path(conf.proof_import_directory),
            outbox=Path(conf.proof_export_directory),
        )
        for d in b["decisions"].values():
            await proofs.publish(d.observation)
        copy(Path(conf.proof_export_directory), Path(conf.proof_import_directory))
        if not result.assemble_inputs:
            publish_settlement_inputs(
                Path(conf.inputs_directory) / (digest(history.plan) + ".json"),
                c.package,
            )
        elif conf.original_sources is not None and name not in result.nodes:
            from .cohort_settlement_original_fixture import publish_original_sources

            result.intake = publish_original_sources(
                conf.original_sources, b, intake=getattr(result, "intake", None)
            )
        if result.seed_handoff:
            publish_private_model(
                Path(conf.history_directory) / (digest(history.plan) + ".json"),
                CohortOrderHistory(
                    history=history,
                    decisions=tuple(
                        b["decisions"][t.transition.evidence_sha256]
                        for t in history.transitions
                        if t.transition.operation != "revoke"
                    ),
                ),
                maximum_bytes=8 * 1024**2,
            )
        promotion = CompetitionStore(Path(conf.promotion_directory), b["policy"])
        if name not in result.nodes:
            root = tmp_path / ("native-model-" + name)
            bundle = bundle_at(root)
            archive_root = tmp_path / ("native-archive-" + name)
            preserve_bundle(bundle, root, archive_root, b["policy"])
            promotion.initialize_baseline(bundle, archive_root)

        async def sign(body):
            calls[(name, digest(body))] += 1
            return sign_object(body, wallet(name))

        executions = tuple(
            o
            for o in b["owners"].values()
            if identity(o.config.signer) == identity(conf.signer_hotkey)
        )
        node = CohortSettlementService(
            conf,
            history.plan,
            store=store,
            provider=provider,
            proofs=proofs,
            promotion=promotion,
            executions=executions,
            sign=sign,
        )
        result.nodes[name] = node
        return node

    def copy(origin, target):
        for path in origin.rglob("*.json"):
            destination = target / path.relative_to(origin)
            ensure_private_directory(destination.parent)
            if destination.exists():
                assert destination.read_bytes() == path.read_bytes()
            else:
                destination.write_bytes(path.read_bytes())
                destination.chmod(0o600)

    def deliver():
        for sender, receiver in (("Charlie", "Dave"), ("Dave", "Charlie")):
            a, z = result.configs[sender], result.configs[receiver]
            copy(Path(a.proof_export_directory), Path(a.proof_import_directory))
            copy(Path(a.exchange_outbox), Path(z.exchange_inbox))
            copy(Path(a.proof_export_directory), Path(z.proof_import_directory))
            if a.role == "coordinator":
                copy(Path(a.exchange_outbox) / "inputs", Path(z.inputs_directory))
                copy(Path(a.history_directory), Path(z.history_directory))

    result.start, result.deliver = start, deliver
    try:
        yield result
    finally:
        for stack in result.stacks.values():
            stack.close()


def test_reference_input_package_cannot_replace_certified_scoring_inputs(
    original_settlement_inputs,
):
    from umi.competition_cohort_settlement_delivery import SettlementResultVotes
    from umi.competition_cohort_settlement_inputs import (
        prepare_settlement_inputs,
        replay_settlement_inputs,
    )

    h, b = original_settlement_inputs, original_settlement_inputs.b
    original = h.package.inputs.history
    prefix = original.model_copy(update={"transitions": original.transitions[:-1]})
    inputs = h.package.inputs.model_copy(update={"history": prefix})

    def no_pulses(_):
        pytest.fail("reference certification must not decrypt or score miner responses")

    package = prepare_settlement_inputs(
        inputs,
        b["policy"],
        h.requirement,
        b["objects"].__getitem__,
        b["decisions"].__getitem__,
        b["records"],
        no_pulses,
        expected_tip_sha256=tip(prefix),
        current_block=1000000,
    )

    def replay(value, history):
        return replay_settlement_inputs(
            value,
            b["policy"],
            h.requirement,
            history,
            expected_package_sha256=digest(value),
            expected_tip_sha256=tip(history),
            current_block=1000000,
            current_decisions=b["decisions"].__getitem__,
        )

    data = replay(package, prefix)
    assert package.schema_ == "umi-settlement-input-package/2"
    assert package.pulses == () and data.quality is None and data.service is None
    with pytest.raises(ValueError, match="certified reference reveal"):
        SettlementResultVotes(
            data,
            hotkey=wallet("Charlie").hotkey.ss58_address,
            executions=(),
            journal=None,
            sign=None,
            inbox=None,
            outbox=None,
        )
    with pytest.raises(ValueError):
        replay(package, original)  # Scoring needs the newly certified input package.
    with pytest.raises(ValueError, match="schema's phase"):
        replay(package.model_copy(update={"schema_": "umi-settlement-input-package/1"}), prefix)
    with pytest.raises(ValueError, match="schema's phase"):
        replay(h.package.model_copy(update={"schema_": "umi-settlement-input-package/2"}), original)


@pytest.mark.parametrize("service_catalog_inputs", [True, "precommitted"], indirect=True)
async def test_recurring_settlement_certifies_without_inference_or_manual_votes(
    recurring_settlement_case,
):
    from pathlib import Path

    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = recurring_settlement_case
    assert all(not o.journal.keys("closed_quality_vote") for o in h.b["owners"].values())
    a, z = await h.start("Charlie"), await h.start("Dave")
    assert await z.tick() == "reviewing"
    h.deliver()
    with pytest.raises(SettlementPhaseQuorumPending):
        await a.tick()
    h.deliver()
    assert await z.tick() == "reviewing"
    h.deliver()
    # Lose a published local quality reply after the native signature committed.
    lost = next(Path(z.config.exchange_outbox).glob("quality/**/*.json"))
    original = lost.read_bytes()
    lost.unlink()
    h.clock.block += 100000
    a, z = await h.start("Charlie"), await h.start("Dave")
    for _ in range(15):
        h.deliver()
        await z.tick()
        h.deliver()
        try:
            status = await a.tick()
        except SettlementPhaseQuorumPending:
            continue
        if status == "package_published":
            break
    else:
        pytest.fail("recurring settlement did not publish its reward package")
    assert lost.read_bytes() == original
    assert max(h.calls.values()) == 1
    assert h.b["service_case"].p.model.calls == 1
    package_path = Path(a.config.settlement_directory) / (a.cohort + ".json")
    raw = package_path.read_bytes()
    from umi.competition_cohort_reward_package import CohortRewardPackage

    package = CohortRewardPackage.model_validate_json(raw)
    assert canonical_json_bytes(package) == raw
    assert len(package.benchmark.participants) == len(h.c.package.inputs.roster.participants)
    assert a.data is None and a.phases is None
    # Final certification frees the reviewer's raw inputs but retains recovery
    # of its exact signed deliveries without a second native signature.
    h.deliver()
    assert await z.tick() == "reviewing"
    assert z.data is None and z.reviewed_terminal_tip is not None
    lost_replies = tuple(
        next(Path(z.config.exchange_outbox).glob(kind + "/**/*.json"))
        for kind in ("votes", "quality", "service")
    )
    retained_replies = tuple(path.read_bytes() for path in lost_replies)
    for path in lost_replies:
        path.unlink()
    assert await z.tick() == "reviewing"
    assert tuple(path.read_bytes() for path in lost_replies) == retained_replies
    assert max(h.calls.values()) == 1
    z = await h.start("Dave")
    assert await z.tick() == "reviewing"
    assert z.data is None and max(h.calls.values()) == 1
    h.clock.block += 100000
    a = await h.start("Charlie")
    assert await a.tick() == "package_published"
    assert package_path.read_bytes() == raw and max(h.calls.values()) == 1


@pytest.mark.parametrize("fault", ["missing_execution", "missing_proof", "revoked", "changed_vote"])
async def test_recurring_settlement_retries_without_signing_unverified_results(
    recurring_settlement_case,
    fault,
):
    from pathlib import Path

    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.competition_cohort_quality_signing import SignedClosedQualityVote
    from umi.open_competition import identity
    from umi.private_files import read_private_model

    from .test_competition_cohort_consumers import transition

    h = recurring_settlement_case
    z = await h.start("Dave")
    if fault == "missing_execution":
        z.executions = ()
        with pytest.raises(FileNotFoundError):
            await z.tick()
        assert not h.calls
        z = await h.start("Dave")
        assert await z.tick() == "reviewing"
    elif fault == "missing_proof":
        # Both selected archives can supply the exact original. Remove both to
        # exercise unavailable proof, rather than successful outbox recovery.
        files = [
            path
            for directory in (z.config.proof_import_directory, z.config.proof_export_directory)
            for path in Path(directory).rglob("*.json")
        ]
        assert files
        for path in files:
            path.unlink()
        with pytest.raises(FileNotFoundError):
            await z.tick()
        assert not h.calls
        z = await h.start("Dave")
        assert await z.tick() == "reviewing"
    elif fault == "revoked":
        path = Path(z.config.history_directory) / (z.cohort + ".json")
        original = read_private_model(path, CohortOrderHistory, maximum_bytes=8 * 1024**2)
        history = transition(original.history, h.b["policy"], "revoke", h.clock.block)
        path.write_bytes(canonical_json_bytes(original.model_copy(update={"history": history})))
        assert await z.tick() == "revoked"
        assert not h.calls and z.phases is None
    else:
        a = await h.start("Charlie")
        await z.tick()
        h.deliver()
        await a._handoff()
        await a._start(a.store.published_history(a.cohort))
        path = next(Path(a.config.exchange_inbox).glob("quality/**/*.json"))
        vote = read_private_model(path, SignedClosedQualityVote, maximum_bytes=16 * 1024**2)
        wrong = vote.model_copy(
            update={
                "signature": vote.signature.model_copy(
                    update={
                        "hotkey": wallet("Alice").hotkey.ss58_address,
                    }
                )
            }
        )
        path.write_bytes(canonical_json_bytes(wrong))
        before = dict(h.calls)
        with pytest.raises(ValueError):
            a.votes.collect()
        assert h.calls == before
        assert not list(Path(a.config.settlement_directory).glob("*.json"))
        assert all(name != "Charlie" for name, _ in h.calls)
        assert identity(wrong.signature.hotkey) != identity(vote.signature.hotkey)


async def test_recurring_settlement_loops_publish_with_automatic_file_delivery(
    recurring_settlement_case,
):
    from pathlib import Path

    h = recurring_settlement_case
    a, z = await h.start("Charlie"), await h.start("Dave")
    for node in (a, z):
        node.config = node.config.model_copy(update={"poll_seconds": 1})
    stop = asyncio.Event()
    tasks = [asyncio.create_task(node.run(stop)) for node in (a, z)]
    output = Path(a.config.settlement_directory) / (a.cohort + ".json")

    async def replicate_and_wait():
        while not output.exists():
            h.deliver()
            for task in tasks:
                if task.done():
                    task.result()
                    pytest.fail("settlement loop stopped unexpectedly")
            await asyncio.sleep(0.05)

    try:
        await asyncio.wait_for(replicate_and_wait(), timeout=600)
    finally:
        stop.set()
        await asyncio.gather(*tasks)
    assert a.last_report == "package_published"
    assert max(h.calls.values()) == 1
    assert h.b["service_case"].p.model.calls == 1


@pytest.mark.parametrize("recurring_settlement_case", [True], indirect=True)
@pytest.mark.parametrize("replication", ["files", "rclone"])
async def test_native_request_certification_starts_recurring_settlement(
    recurring_settlement_case, tmp_path, monkeypatch, replication
):
    from pathlib import Path

    from umi.competition_cohort_intake import CohortIntakePublisher
    from umi.competition_cohort_lifecycle import CohortLifecycleService, CohortPhaseDriver
    from umi.competition_cohort_order_signer import order_slot
    from umi.competition_cohort_recovery import StandingCohortRecoveryAuthority
    from umi.competition_cohort_request_export_worker import RequestExportWorker
    from umi.competition_cohort_request_files import RequestCompletionFiles
    from umi.competition_cohort_request_publication import CohortRequestSettlementPublisher
    from umi.competition_round_journal import RoundJournal

    from .test_competition_cohort_request_phase import make_request_owner, request_controller

    h = recurring_settlement_case
    replica = None
    if replication == "rclone":
        from .cohort_replication_support import Replica

        replica = Replica(tmp_path / "rclone-command")
        replica.settlement(h)
    if not isinstance(h.b["history"].authority.authority, StandingCohortRecoveryAuthority):
        pytest.skip("automatic request runtime requires standing authority")
    original = h.b["history"]
    index = next(
        i
        for i, t in enumerate(original.transitions)
        if t.transition.phase == "requests" and t.transition.operation == "close_phase"
    )
    b = dict(h.b, history=original.model_copy(update={"transitions": original.transitions[:index]}))
    owner = make_request_owner(b, tmp_path / "request-owner", monkeypatch)
    h.assemble_inputs, h.seed_handoff = True, False
    h.original_sources, h.intake = owner.sources, owner.intake
    a, z = await h.start("Charlie"), await h.start("Dave")
    # The original inference fixture has finished, but its terminal signatures
    # and their delivery now belong to the recurring evaluator export workers.
    for (order_sha, evaluator), evaluator_owner in b["owners"].items():
        order = next(o for o in b["orders"] if digest(o) == order_sha)
        with evaluator_owner.journal.transaction() as db:
            db.execute(
                "DELETE FROM records WHERE kind IN ('request_terminal', 'request_terminal_intent')"
            )
        endpoint_archive = b["endpoint_archives"][(order_sha, evaluator)]
        if endpoint_archive is not None:
            evaluator_owner.journal.put(
                "endpoint_replay_archive", order_slot(order.order), endpoint_archive
            )
    completed = RequestCompletionFiles(tmp_path / "request-exports")
    imported = (
        RequestCompletionFiles(tmp_path / "request-imports") if replica is not None else completed
    )
    owner.source.orders = lambda: imported.orders(b["roster"])
    owner.source.terminals = imported.terminal
    owner.source.external = imported.objects
    exporters = tuple(
        RequestExportWorker(
            node.executions,
            node.provider,
            node.sign,
            completed,
            RoundJournal(tmp_path / ("request-exporter-" + name), {"signer": name}),
        )
        for name, node in (("Charlie", a), ("Dave", z))
    )
    handoff = Path(a.config.history_directory) / (owner.cohort + ".json")
    assert not handoff.exists()
    for node in (a, z):
        node.config = node.config.model_copy(update={"poll_seconds": 1})
    stop = asyncio.Event()
    tasks = [asyncio.create_task(n.run(stop)) for n in (a, z)]
    output = Path(a.config.settlement_directory) / (a.cohort + ".json")

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            owner.source,
            owner.provider.collect,
            decisions,
            a.proofs.publish,
            sources=owner.sources,
            history_directory=handoff.parent,
        )

    try:
        # Settlement is already waiting. Completion and discovery require no
        # hand-authored closure or phase history file.
        await asyncio.sleep(0.1)
        assert not output.exists()
        h.deliver()
        for node in (a, z):
            assert not list(Path(node.config.inputs_directory).glob("*.json"))
            assert not list((Path(node.config.exchange_outbox) / "inputs").glob("*.json"))
        assert owner.window().completion == "pending"
        h.clock.block = owner.block + 100
        tasks.extend(asyncio.create_task(e.run(stop, poll_seconds=1)) for e in exporters)
        with request_controller(owner, tmp_path, publication) as control:

            async def no_intake():
                pytest.fail("certified intake must not reopen")

            async def prepared_driver():
                async def already_published(history):
                    # This test starts with original prepared-round fixtures;
                    # the lifecycle intake/preparation tests produce them natively.
                    assert (Path(owner.sources.round_directory) / (owner.cohort + ".json")).exists()

                return CohortPhaseDriver(control.observer(), already_published)

            async def request_driver():
                async def sample_service(state, capture):
                    from umi.concurrency import run_owned_thread

                    if replica is not None:
                        await run_owned_thread(
                            replica.copy, completed.root, imported.root, "requests"
                        )
                    return await run_owned_thread(
                        lambda: owner.source.sample_service(state, capture, serving=True)
                    )

                return CohortPhaseDriver(control.observer(), control.publisher, sample_service)

            lifecycle = CohortLifecycleService(
                control.store,
                owner.cohort,
                owner.b["policy"],
                b["history"].genesis_signatures,
                owner.provider,
                CohortIntakePublisher(owner.intake, owner.provider.collect, control.decision),
                {"intake": no_intake, "preparation": prepared_driver, "requests": request_driver},
            )
            # Native replay and concurrent exporter reads can exceed a minute
            # on shared CI CPUs. This watchdog bounds only the test, not the
            # cohort's authority or its recoverable processing interval.
            result = await asyncio.wait_for(lifecycle.run(stop, poll_seconds=0.01), timeout=600)
            assert result["status"] == "settlement_handoff_published"
        assert handoff.exists()
        request_signatures = tuple(owner.calls)

        async def replicate_and_wait():
            while not output.exists():
                h.deliver()
                for task in tasks:
                    if task.done():
                        task.result()
                        pytest.fail("settlement loop stopped unexpectedly")
                await asyncio.sleep(0.05)

        try:
            await asyncio.wait_for(replicate_and_wait(), timeout=900)
        except asyncio.TimeoutError:
            pytest.fail(
                "settlement handoff did not finish: "
                f"coordinator={a.last_report}, reviewer={z.last_report}"
            )
        assert tuple(owner.calls) == request_signatures
    finally:
        stop.set()
        await asyncio.gather(*tasks)
    assert a.last_report == "package_published"
    assert max(h.calls.values()) == 1
    assert h.b["service_case"].p.model.calls == 1
    from umi.competition_cohort_reward_package import CohortRewardPackage

    published = CohortRewardPackage.model_validate_json(output.read_bytes())
    assert digest(published.inputs.closure) != digest(h.b["closure"])
    assert a.data is None and a.phases is None
    original_handoff, signatures = handoff.read_bytes(), dict(h.calls)

    async def settled_decision(cohort, key):
        from umi.competition_cohort_coordinator import CohortDecisionInput

        return a.store.source(cohort, key, CohortDecisionInput)

    late = CohortRequestSettlementPublisher(
        owner.reopen(),
        a.provider.collect,
        settled_decision,
        a.proofs.publish,
        sources=owner.sources,
        history_directory=handoff.parent,
    )
    h.clock.block += 100000
    await late(a.store.published_history(a.cohort))
    assert handoff.read_bytes() == original_handoff
    assert dict(h.calls) == signatures


@pytest.mark.parametrize("recurring_settlement_case", [False, True], indirect=True)
async def test_automatic_settlement_assembly_delivery_and_late_restart(
    recurring_settlement_case, monkeypatch
):
    from pathlib import Path

    from umi.competition_cohort_settlement_assembly import assemble_settlement_inputs
    from umi.competition_cohort_settlement_inputs import SettlementInputPackage
    from umi.private_files import read_private_model

    h = recurring_settlement_case
    h.assemble_inputs = True
    a, z = await h.start("Charlie"), await h.start("Dave")
    if h.reference_start:
        # The new reveal must be constructed by the coordinator, retained in
        # its owner journal and recovered from there for settlement assembly.
        (
            Path(a.config.original_sources.objects_directory) / (digest(h.b["reveal"]) + ".json")
        ).unlink()
        from umi import competition_cohort_settlement_service as service_module

        original_votes = service_module.SettlementResultVotes
        failed = []

        def interrupted_stage(*args, **kwargs):
            if not failed:
                failed.append(True)
                raise OSError("interrupted setup after scoring-input retention")
            return original_votes(*args, **kwargs)

        monkeypatch.setattr(service_module, "SettlementResultVotes", interrupted_stage)
    for node in (a, z):
        assert not (Path(node.config.inputs_directory) / (node.cohort + ".json")).exists()
        node.config = node.config.model_copy(update={"poll_seconds": 1})
    stop = asyncio.Event()
    tasks = [asyncio.create_task(n.run(stop)) for n in (a, z)]
    output = Path(a.config.settlement_directory) / (a.cohort + ".json")

    async def replicate():
        while not output.exists():
            h.deliver()
            for task in tasks:
                if task.done():
                    task.result()
                    pytest.fail("settlement stopped before publication")
            await asyncio.sleep(0.05)

    try:
        await asyncio.wait_for(replicate(), timeout=600)
    finally:
        stop.set()
        await asyncio.gather(*tasks)
    path = Path(a.config.inputs_directory) / (a.cohort + ".json")
    package = read_private_model(path, SettlementInputPackage)
    if h.reference_start:
        assert failed == [True]
        assert package.inputs.reveal == h.b["reveal"]
        assert package.inputs.history.transitions[-1] != h.c.package.inputs.history.transitions[-1]
        reference_path = Path(a.config.inputs_directory) / (a.cohort + "-reference.json")
        reference = read_private_model(reference_path, SettlementInputPackage)
        assert reference.schema_ == "umi-settlement-input-package/2"
        assert reference.pulses == ()
        assert reference.inputs.history.transitions[-1].transition.phase == "requests"
        assert (
            read_private_model(
                Path(z.config.inputs_directory) / reference_path.name, SettlementInputPackage
            )
            == reference
        )
    else:
        assert package == h.c.package
    assert len(package.intake) == 3  # Includes superseded consent for the two selected miners.
    # A first producer arriving after certification must select the same original prefix.
    current = a.store.published_history(a.cohort)
    from umi.competition_cohort_endpoint_archive import JournalEndpointObjects

    assert len(current.transitions) > len(package.inputs.history.transitions)
    assert (
        assemble_settlement_inputs(
            a.config.original_sources,
            a.config.policy,
            h.c.requirement,
            current,
            a._decisions,
            current_block=h.clock.block + 100000,
            maximum_bytes=a.config.maximum_package_bytes,
            retained_objects=JournalEndpointObjects(a.journal),
        )
        == package
    )
    before = dict(h.calls)
    original = path.read_bytes()
    # Lose the entire upstream publication and export, retaining the original reviewed package.
    sources_root = Path(a.config.original_sources.intake.directory).parent
    sources_root.rename(sources_root.with_name("sources-offline"))
    outbox = Path(a.config.exchange_outbox) / "inputs" / (a.cohort + ".json")
    outbox.unlink()
    h.clock.block += 100000
    a = await h.start("Charlie")
    assert await a.tick() == "package_published"
    assert path.read_bytes() == outbox.read_bytes() == original
    assert dict(h.calls) == before and max(h.calls.values()) == 1
    assert h.b["service_case"].p.model.calls == 1


@pytest.mark.parametrize("recurring_settlement_case", [True], indirect=True)
@pytest.mark.parametrize("fault", [None, "signature", "decisions", "fork", "proof", "filename"])
async def test_reviewer_imports_only_verified_history_extensions(
    recurring_settlement_case, fault, monkeypatch
):
    from pathlib import Path

    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.private_files import publish_private_model

    h = recurring_settlement_case
    h.assemble_inputs = True
    z = await h.start("Dave")
    current = await z._handoff()
    before = z.store.status(z.cohort)[0]
    history = h.c.package.inputs.history
    decisions = tuple(h.b["decisions"][t.transition.evidence_sha256] for t in history.transitions)
    if fault == "signature":
        last = history.transitions[-1].model_copy(update={"signatures": ()})
        history = history.model_copy(update={"transitions": (*history.transitions[:-1], last)})
    elif fault == "decisions":
        decisions = decisions[:-1]
    elif fault == "fork":
        history = history.model_copy(
            update={"plan": history.plan.model_copy(update={"suite_sha256": "00" * 32})}
        )
    elif fault == "proof":

        async def missing_proof(_):
            raise FileNotFoundError("original archive unavailable")

        monkeypatch.setattr(z.proofs, "read", missing_proof)
    value = CohortOrderHistory(history=history, decisions=decisions)
    path = (
        Path(z.config.exchange_inbox)
        / "history"
        / z.cohort
        / (("00" * 32 if fault == "filename" else tip(history)) + ".json")
    )
    publish_private_model(path, value)
    if fault is None:
        assert await z._receive_history(current) == history
        assert z.store.status(z.cohort)[0].phase == "evidence"
        assert await z._receive_history(history) == history
        assert not h.calls
        assert await z._handoff() == history
        # History can arrive before the package. Restart must retain that
        # certified advance even though no input digest has been pinned yet.
        z = await h.start("Dave")
        with pytest.raises(FileNotFoundError):
            await z.tick()
        assert z.store.status(z.cohort)[0].phase == "evidence"
        assert not h.calls

        from umi.competition_cohort_settlement_exchange import SettlementProgressRequest
        from umi.competition_cohort_settlement_inputs import publish_settlement_inputs

        decision = decisions[-1]
        vote = next(
            s
            for s in decision.progress.signatures
            if s.hotkey == wallet("Charlie").hotkey.ss58_address
        )
        old_request = SettlementProgressRequest(
            schema="umi-settlement-progress-request/1",
            history=current,
            decisions=decisions[:-1],
            observation=decision.observation,
            progress=decision.progress.model_copy(update={"signatures": (vote,)}),
        )
        publish_private_model(
            Path(z.config.exchange_inbox)
            / "requests"
            / z.cohort
            / "reference_reveal-progress.json",
            old_request,
        )
        publish_settlement_inputs(
            Path(z.config.inputs_directory) / (z.cohort + ".json"), h.c.package
        )
        assert await z.tick() == "reviewing"
        assert ("Dave", digest(decision.progress.progress)) not in h.calls
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            await z._receive_history(current)
        assert z.store.status(z.cohort)[0] == before
        assert not h.calls


@pytest.mark.parametrize("recurring_settlement_case", [True], indirect=True)
async def test_reference_service_resumes_original_intent_without_fresh_observation(
    recurring_settlement_case,
):
    from pathlib import Path

    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = recurring_settlement_case
    h.assemble_inputs = True
    a, z = await h.start("Charlie"), await h.start("Dave")
    with pytest.raises(SettlementPhaseQuorumPending):
        await a.tick()
    package_path = Path(a.config.inputs_directory) / (a.cohort + "-reference.json")
    original = package_path.read_bytes()
    h.deliver()
    assert await z.tick() == "reviewing"
    h.deliver()
    # The controller already reserved its original finalized observation.
    # Restart cannot demand another RPC observation or upstream assembly.
    sources = Path(a.config.original_sources.intake.directory).parent
    sources.rename(sources.with_name("reference-sources-offline"))
    h.clock.block += 100000
    h.clock.fail_collect = True
    a = await h.start("Charlie")
    with pytest.raises(SettlementPhaseQuorumPending):
        await a.tick()
    h.deliver()
    assert await z.tick() == "reviewing"
    h.deliver()
    assert await a.tick() == "evidence"
    assert a.store.status(a.cohort)[0].phase == "evidence"
    assert package_path.read_bytes() == original
    assert len(h.calls) == 4 and set(h.calls.values()) == {1}


@pytest.mark.parametrize(
    "fault", ["missing", "changed", "superseded", "round", "catalog", "pulse", "revoked"]
)
async def test_automatic_settlement_incomplete_sources_never_sign(
    recurring_settlement_case, fault, monkeypatch
):
    from pathlib import Path

    from umi.competition_cohort_intake_records import read_participation
    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.private_files import read_private_model

    from .test_competition_cohort_consumers import transition

    h = recurring_settlement_case
    h.assemble_inputs = True
    a = await h.start("Charlie")
    s, restore = a.config.original_sources, None
    if fault in {"missing", "changed"}:
        path = Path(s.objects_directory) / (digest(h.b["closure"]) + ".json")
    elif fault == "round":
        path = Path(s.round_directory) / (a.cohort + ".json")
    elif fault == "catalog":
        path = Path(s.catalogs_directory) / (h.c.requirement.catalog_sha256s[0] + ".json")
    elif fault == "pulse":
        path = next(Path(s.pulses_directory).glob("*.json"))
        from umi.drand import QuicknetClient

        async def unavailable(self, number):
            raise FileNotFoundError("original Quicknet pulse temporarily unavailable")

        monkeypatch.setattr(QuicknetClient, "fetch", unavailable)
    elif fault == "superseded":
        key = next(
            k
            for k, raw in h.b["records"]
            if read_participation(raw).request.signed_submission.submission.sequence == 1
            and k
            not in {m.record.proposed_admission.consent_sha256 for m in h.b["roster"].participants}
        )
        with h.intake._connection() as (db, _):
            restore = db.execute("SELECT * FROM cohort_consents WHERE consent=?", (key,)).fetchone()
            db.execute("DELETE FROM cohort_consents WHERE consent=?", (key,))
    else:
        path = Path(a.config.history_directory) / (a.cohort + ".json")
        selected = read_private_model(path, CohortOrderHistory)
        revoked = transition(selected.history, a.config.policy, "revoke", h.clock.block)
        path.write_bytes(canonical_json_bytes(selected.model_copy(update={"history": revoked})))
        assert await a.tick() == "revoked"
        assert not h.calls
        assert not (Path(a.config.inputs_directory) / (a.cohort + ".json")).exists()
        return
    if restore is None:
        raw = path.read_bytes()
        if fault == "changed":
            path.write_bytes(b"{}")
        else:
            path.unlink()
    with pytest.raises((FileNotFoundError, ValueError)):
        await a.tick()
    assert not h.calls
    assert a.journal.get("settlement_input", "original") is None
    assert not (Path(a.config.inputs_directory) / (a.cohort + ".json")).exists()
    if restore is not None:
        with h.intake._connection() as (db, _):
            db.execute("INSERT INTO cohort_consents VALUES (?,?,?,?,?,?,?,?)", restore)
    else:
        path.write_bytes(raw)
        path.chmod(0o600)
    # A delay is not an expiry. Recover on the next normal polling pass.
    h.clock.block += 100000
    with pytest.raises(RuntimeError, match="not ready for attestation"):
        await a.tick()
    assert a.package_reference == (
        Path(a.config.inputs_directory) / (a.cohort + ".json"),
        digest(h.c.package),
    )
    assert a.package_reference[0].read_bytes() == canonical_json_bytes(h.c.package)


@pytest.mark.parametrize("outage", [False, True])
async def test_automatic_settlement_fetches_missing_original_pulse_and_resumes(
    recurring_settlement_case, monkeypatch, outage
):
    from pathlib import Path

    import bittensor as bt
    import httpx

    from umi import competition_cohort_settlement_pulses as pulse_module
    from umi.drand import DrandVerificationError, QuicknetClient

    from .test_drand import ROUND, info_record, json_response

    h = recurring_settlement_case
    h.assemble_inputs = True
    a = await h.start("Charlie")
    path = Path(a.config.original_sources.pulses_directory) / (str(ROUND) + ".json")
    original = path.read_bytes()
    path.unlink()
    calls, available = [], not outage

    def handler(request):
        calls.append(request.url.path)
        if not available:
            return httpx.Response(503)
        return json_response(
            info_record() if request.url.path.endswith("/info") else pulse_record()
        )

    client = QuicknetClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(pulse_module, "QuicknetClient", lambda: client)
    # The admission fixture freezes selection before the retained BLS vector's
    # reveal. Advance only the local publication clock, keeping signed history
    # and the requested original round unchanged.
    monkeypatch.setattr(bt.timelock, "current_round", lambda: ROUND + 1)
    original_history = await a._handoff()
    if outage:
        with pytest.raises(DrandVerificationError):
            await a._start(original_history)
        assert not h.calls and not path.exists()
        assert a.journal.get("settlement_input", "original") is None
        h.clock.block += 100000  # Delay is not a new request/reveal clock.
        a = await h.start("Charlie")
        assert await a._handoff() == original_history
        available = True
    await a._start(original_history)
    package_path = Path(a.config.inputs_directory) / (a.cohort + ".json")
    assert path.read_bytes() == original
    assert package_path.read_bytes() == canonical_json_bytes(h.c.package)
    assert a.package_reference == (package_path, digest(h.c.package))
    assert len(calls) == (4 if outage else 2)
    assert all(p.endswith("/info") or p.endswith("/" + str(ROUND)) for p in calls)
    before = len(calls)
    a = await h.start("Charlie")
    await a._start(await a._handoff())
    assert len(calls) == before
    assert package_path.read_bytes() == canonical_json_bytes(h.c.package)


@pytest.mark.parametrize("where", ["before_input", "after_input", "export"])
async def test_automatic_settlement_recovers_interrupted_publication(
    recurring_settlement_case, monkeypatch, where
):
    from pathlib import Path

    from umi import competition_cohort_settlement_service as service_module

    h = recurring_settlement_case
    h.assemble_inputs = True
    a = await h.start("Charlie")
    publish = service_module.publish_settlement_inputs
    local = Path(a.config.inputs_directory) / (a.cohort + ".json")

    def interrupted(path, *args, **kwargs):
        target = path == local if where != "export" else "inputs" in path.parts and path != local
        if target and where == "before_input":
            raise OSError("publication interrupted")
        publish(path, *args, **kwargs)
        if target:
            raise OSError("publication acknowledgement lost")

    replicate = service_module.replicate_verified_aggregate

    def interrupted_replica(source, destination, **kwargs):
        replicate(source, destination, **kwargs)
        raise OSError("publication acknowledgement lost")

    with monkeypatch.context() as patch:
        if where == "export":
            patch.setattr(service_module, "replicate_verified_aggregate", interrupted_replica)
        else:
            patch.setattr(service_module, "publish_settlement_inputs", interrupted)
        with pytest.raises(OSError):
            await a.tick()
    assert not h.calls
    if where != "before_input":

        def no_rebuild(*args, **kwargs):
            raise AssertionError("retained package must be reused")

        monkeypatch.setattr(service_module, "assemble_settlement_inputs", no_rebuild)
    h.clock.block += 100000
    a = await h.start("Charlie")
    with pytest.raises(RuntimeError, match="not ready for attestation"):
        await a.tick()
    assert a.package_reference == (
        Path(a.config.inputs_directory) / (a.cohort + ".json"),
        digest(h.c.package),
    )
    assert a.package_reference[0].read_bytes() == canonical_json_bytes(h.c.package)


@pytest.mark.parametrize("damage", ["lost", "changed"])
async def test_reviewed_automatic_inputs_require_original_replica(
    recurring_settlement_case, monkeypatch, damage
):
    from pathlib import Path

    from umi import competition_cohort_settlement_service as service_module

    h = recurring_settlement_case
    h.assemble_inputs = True
    a = await h.start("Charlie")
    original_config = a.config
    a.config = a.config.model_copy(update={"maximum_package_bytes": 1024})
    with pytest.raises(ValueError, match="byte bound"):
        await a.tick()
    assert not h.calls and a.journal.get("settlement_input", "original") is None
    a.config = original_config
    await a._start(await a._handoff())
    path = Path(a.config.inputs_directory) / (a.cohort + ".json")
    original = path.read_bytes()
    if damage == "lost":
        path.unlink()
    else:
        path.write_bytes(
            canonical_json_bytes(h.c.package.model_copy(update={"policy_sha256": "ff" * 32}))
        )

    def no_rebuild(*args, **kwargs):
        raise AssertionError("a reviewed package must be restored, not rebuilt")

    monkeypatch.setattr(service_module, "assemble_settlement_inputs", no_rebuild)
    a = await h.start("Charlie")
    with pytest.raises((FileNotFoundError, ValueError)):
        await a.tick()
    assert not h.calls
    path.write_bytes(original)
    path.chmod(0o600)
    # The owner automatically repairs the restored exact original against its
    # retained identity. It must neither rebuild nor repeat the repair on retry.
    repairs = []
    original_repair = a.verified_packages.repair

    def repair(*args, **kwargs):
        repairs.append((args, kwargs))
        return original_repair(*args, **kwargs)

    monkeypatch.setattr(a.verified_packages, "repair", repair)
    with pytest.raises(RuntimeError, match="not ready for attestation"):
        await a.tick()
    assert len(repairs) == 1
    assert repairs[0][1]["expected_sha256"] == digest(h.c.package)
    h.clock.block += 100000
    with pytest.raises(RuntimeError, match="not ready for attestation"):
        await a.tick()
    assert len(repairs) == 1
    assert a.package_reference == (
        Path(a.config.inputs_directory) / (a.cohort + ".json"),
        digest(h.c.package),
    )
    assert a.package_reference[0].read_bytes() == canonical_json_bytes(h.c.package)


async def test_settlement_input_replica_recovers_before_quality_votes(
    original_settlement_inputs, tmp_path
):
    """Native execution/replay/votes; phase quorum and model assets are fixtures."""
    from umi.competition_cohort_settlement import CohortSettlement
    from umi.competition_cohort_settlement_inputs import (
        load_settlement_inputs,
        publish_settlement_inputs,
    )

    from .test_competition_cohort_quality import votes_for

    c, b = original_settlement_inputs, original_settlement_inputs.b
    assert all(not owner.journal.keys("closed_quality_vote") for owner in b["owners"].values())
    path = tmp_path / "replica" / "inputs.json"
    publish_settlement_inputs(path, c.package)
    raw = path.read_bytes()
    publish_settlement_inputs(path, c.package)  # Lost acknowledgement retry.
    assert path.read_bytes() == raw
    original_intake = tuple(b["records"])
    b["objects"].clear()
    b["decisions"].clear()
    b["records"] = ()
    history, block = c.package.inputs.history, 1100000

    def read():
        return load_settlement_inputs(
            path,
            b["policy"],
            c.requirement,
            history,
            expected_package_sha256=digest(c.package),
            expected_tip_sha256=tip(history),
            current_block=block,
            current_decisions=b["decisions"].__getitem__,
        )

    restored = read()
    assert sorted(restored.intake) == sorted(original_intake)
    store = CompetitionStore(tmp_path / "promotion", b["policy"])
    bundle = bundle_at(tmp_path / "model")
    preserve_bundle(bundle, tmp_path / "model", tmp_path / "archive", b["policy"])
    store.initialize_baseline(bundle, tmp_path / "archive")

    def reopen(data):
        return CohortSettlement(
            plan=history.plan,
            authority=history.authority,
            requirement=c.requirement,
            policy=b["policy"],
            journal=RoundJournal(tmp_path / "settlement", {"scope": "replica"}),
            promotion_store=store,
            objects=data.objects,
            decisions=data.decisions,
            pulses=data.pulses,
            output_directory=tmp_path / "settled",
            maximum_promotion_bytes=1000000,
        )

    pending = reopen(restored).advance(
        restored.inputs,
        restored.intake,
        expected_tip_sha256=tip(history),
        current_block=block,
    )
    assert pending.status == "waiting_quality_votes" and pending.package is None
    quality_votes = []
    for order in b["orders"]:
        quality_votes.extend(await votes_for(b, restored.quality, order))
    service_votes = []
    for name in ("Charlie", "Dave"):

        async def sign(body, name=name):
            return sign_object(body, wallet(name))

        service_votes.append(
            await sign_service_allocation(
                RoundJournal(tmp_path / ("replica-service-" + name), {"scope": "replica-service"}),
                restored.service,
                wallet(name).hotkey.ss58_address,
                sign,
            )
        )
    for phase in ("evidence", "review", "certification", "first_admission"):
        restored = read()
        owner = reopen(restored)
        result = owner.advance(
            restored.inputs,
            restored.intake,
            expected_tip_sha256=tip(history),
            current_block=block,
            quality_votes=quality_votes,
            service_votes=service_votes,
        )
        if phase == "first_admission":
            assert result.status == "package_published"
            break
        assert result.status == "phase_ready" and result.progress.phase == phase
        history = close(
            history, b["policy"], b["decisions"], block, result.progress.phase_result_sha256
        )
        block += 100000
    assert canonical_json_bytes(result.package) == owner.output.read_bytes()
    assert len(result.package.benchmark.participants) == len(restored.quality.closure.participants)
    assert not b["objects"] and not b["records"]
    assert b["service_case"].p.model.calls == 1
    assert path.read_bytes() == raw


async def test_settlement_input_replica_rejects_missing_or_changed_evidence(
    original_settlement_inputs, tmp_path
):
    from umi.competition_cohort_reward_package import RewardPackageObject
    from umi.competition_cohort_settlement_inputs import (
        publish_settlement_inputs,
        replay_settlement_inputs,
    )

    from .test_competition_cohort_consumers import transition

    c, b = original_settlement_inputs, original_settlement_inputs.b

    def replay(package, **changes):
        args = dict(
            expected_package_sha256=digest(package),
            expected_tip_sha256=tip(c.package.inputs.history),
            current_block=2**53 - 1,
        )
        args.update(changes)
        return replay_settlement_inputs(
            package,
            b["policy"],
            c.requirement,
            c.package.inputs.history,
            **args,
        )

    with pytest.raises(ValueError, match="identity or history"):
        replay(c.package, expected_package_sha256="a" * 64)
    with pytest.raises(ValueError, match="selected current tip"):
        replay(c.package, expected_tip_sha256="b" * 64)
    with pytest.raises(ValueError, match="byte bound"):
        replay(c.package, maximum_bytes=1024)
    history = c.package.inputs.history
    revoked = transition(history, b["policy"], "revoke", 2000000)
    with pytest.raises(ValueError, match="not active after reference reveal"):
        replay_settlement_inputs(
            c.package,
            b["policy"],
            c.requirement,
            revoked,
            expected_package_sha256=digest(c.package),
            expected_tip_sha256=tip(revoked),
            current_block=2000000,
        )
    rollback = history.model_copy(update={"transitions": history.transitions[:-1]})
    with pytest.raises(ValueError, match="identity or history"):
        replay_settlement_inputs(
            c.package,
            b["policy"],
            c.requirement,
            rollback,
            expected_package_sha256=digest(c.package),
            expected_tip_sha256=tip(rollback),
            current_block=2000000,
        )

    original_decision = c.package.inputs.history.transitions[0].transition.evidence_sha256
    missing_decision = c.package.model_copy(
        update={"objects": tuple(o for o in c.package.objects if o.sha256 != original_decision)}
    )
    with pytest.raises(ValueError, match="lack original decision"):
        replay(missing_decision)

    # Retain all history and intake but remove one original execution object.
    reserved = (
        {r.record_sha256 for r in c.package.intake}
        | {t.transition.evidence_sha256 for t in c.package.inputs.history.transitions}
        | {p.pulse_sha256 for p in c.package.pulses}
    )
    missing = next(o for o in c.package.objects if o.sha256 not in reserved)
    with pytest.raises((KeyError, FileNotFoundError)):
        replay(
            c.package.model_copy(
                update={"objects": tuple(o for o in c.package.objects if o != missing)}
            )
        )
    altered = missing.model_copy(update={"value": {"changed": True}})
    with pytest.raises(ValueError, match="bounded identity"):
        replay(
            c.package.model_copy(
                update={"objects": tuple(altered if o == missing else o for o in c.package.objects)}
            )
        )
    extra = RewardPackageObject(sha256=digest({"unused": True}), value={"unused": True})
    with pytest.raises(ValueError, match="unreferenced evidence"):
        replay(
            c.package.model_copy(
                update={
                    "objects": tuple(
                        sorted(
                            (*c.package.objects, extra),
                            key=lambda o: o.sha256,
                        )
                    )
                }
            )
        )
    wrong_terms = c.package.inputs.terms.model_copy(
        update={"stratum_weights": {"fingerspelling": 99, "continuous": 1}}
    )
    with pytest.raises(ValueError, match="approved cohort or service terms"):
        replay(
            c.package.model_copy(
                update={
                    "inputs": c.package.inputs.model_copy(
                        update={"terms": wrong_terms},
                    )
                }
            )
        )
    path = tmp_path / "replica" / "inputs.json"
    publish_settlement_inputs(path, c.package)
    with pytest.raises(ValueError):
        publish_settlement_inputs(path, missing_decision)
    assert path.read_bytes() == canonical_json_bytes(c.package)
    assert all(not owner.journal.keys("closed_quality_vote") for owner in b["owners"].values())


@pytest.mark.parametrize(
    "lost_reply",
    ["closed_quality_peer", "service_allocation_peer", "cohort_reward_allocation", "publish"],
)
async def test_native_settlement_recovers_every_stage_and_keeps_one_package(
    native_settlement_case, monkeypatch, lost_reply
):
    """Native execution/certificates; phase quorum and finality are synthetic."""
    from umi import competition_cohort_settlement as settlement

    c = native_settlement_case
    owner = c.reopen()
    inputs = c.inputs
    block = inputs.history.transitions[-1].transition.observed_at_block + 100

    def advance(**kwargs):
        return owner.advance(
            inputs,
            iter(c.b["records"]),
            expected_tip_sha256=tip(inputs.history),
            current_block=block,
            **kwargs,
        )

    # An incomplete vote set must survive a restart and never drop a miner.
    result = advance(quality_votes=c.quality_votes[:1])
    assert result.status == "waiting_quality_votes"
    assert result.progress is None and result.package is None
    assert not owner.output.exists()
    owner = c.reopen()
    assert advance().status == "waiting_quality_votes"
    failed = False

    original_put = RoundJournal.put

    def put(journal, kind, key, value):
        nonlocal failed
        original_put(journal, kind, key, value)
        if not failed and kind == lost_reply and journal.root == owner.journal.root:
            failed = True
            raise OSError("lost durable write acknowledgement")

    original_publish = settlement.publish_reward_package

    def publish(*args, **kwargs):
        nonlocal failed
        original_publish(*args, **kwargs)
        if not failed and lost_reply == "publish":
            failed = True
            raise OSError("lost durable write acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(RoundJournal, "put", put)
        patch.setattr(settlement, "publish_reward_package", publish)
        for phase in ("evidence", "review", "certification", "first_admission"):
            while True:
                try:
                    result = advance(quality_votes=c.quality_votes, service_votes=c.service_votes)
                    break
                except OSError as error:
                    assert str(error) == "lost durable write acknowledgement"
                    owner = c.reopen()
                    block += 100000  # Processing authority does not expire during an outage.
            if phase == "first_admission":
                break
            assert result.status == "phase_ready" and result.progress.phase == phase
            assert result.package is None and not owner.output.exists()
            h = close(
                inputs.history,
                c.b["policy"],
                c.b["decisions"],
                block,
                result.progress.phase_result_sha256,
            )
            assert (
                c.b["decisions"][h.transitions[-1].transition.evidence_sha256].progress.progress
                == result.progress
            )
            inputs = inputs.model_copy(update={"history": h})
            owner = c.reopen()
            block += 10
    assert failed
    assert result.status == "package_published"
    raw = owner.output.read_bytes()
    assert canonical_json_bytes(result.package) == raw
    assert result.package.allocation == c.native.allocation
    assert result.package.service == c.native.package.service
    assert result.package.benchmark == c.native.package.benchmark

    # Completed history is newer, but packaging remains byte-for-byte stable.
    h = close(inputs.history, c.b["policy"], c.b["decisions"], block, digest(result.package))
    inputs = inputs.model_copy(update={"history": h})
    block = 2**53 - 1
    owner = c.reopen()

    def no_new_promotion(*args, **kwargs):
        raise AssertionError("recovery selected a different promotion head")

    monkeypatch.setattr(c.native.store, "reviewed_promotion_head", no_new_promotion)
    assert canonical_json_bytes(advance().package) == raw
    assert owner.output.read_bytes() == raw
    assert c.b["service_case"].p.model.calls == 1


@pytest.mark.parametrize("fault", ["terms", "missing_evidence", "wrong_phase_result", "revoked"])
async def test_native_settlement_does_not_publish_invalid_or_revoked_evidence(
    native_settlement_case, fault
):
    from .test_competition_cohort_consumers import transition

    c, owner = native_settlement_case, native_settlement_case.reopen()
    inputs = c.inputs
    block = inputs.history.transitions[-1].transition.observed_at_block + 100
    if fault == "terms":
        owner.requirement = owner.requirement.model_copy(update={"terms_sha256": "ff" * 32})
    elif fault == "missing_evidence":
        c.objects.clear()
    elif fault == "wrong_phase_result":
        h = close(inputs.history, c.b["policy"], c.b["decisions"], block, "ab" * 32)
        inputs = inputs.model_copy(update={"history": h})
    else:
        h = transition(inputs.history, c.b["policy"], "revoke", block)
        inputs = inputs.model_copy(update={"history": h})
    with pytest.raises((ValueError, KeyError)):
        owner.advance(
            inputs,
            iter(c.b["records"]),
            expected_tip_sha256=tip(inputs.history),
            current_block=block,
            quality_votes=c.quality_votes,
            service_votes=c.service_votes,
        )
    assert not owner.output.exists()


async def test_native_settlement_waits_for_service_votes_then_recovers_capacity(
    native_settlement_case,
):
    c = native_settlement_case
    complete = c.native.package.inputs
    evidence_close = next(
        i + 1
        for i, t in enumerate(complete.history.transitions)
        if t.transition.phase == "evidence"
    )
    inputs = complete.model_copy(
        update={
            "history": complete.history.model_copy(
                update={"transitions": complete.history.transitions[:evidence_close]}
            )
        }
    )
    for value in (
        c.native.package.benchmark,
        c.native.package.service,
        c.native.package.allocation,
    ):
        c.objects[digest(value)] = canonical_json_bytes(value)
    owner = c.reopen()

    def advance(**kwargs):
        return owner.advance(
            inputs,
            iter(c.b["records"]),
            expected_tip_sha256=tip(inputs.history),
            current_block=2**53 - 1,
            **kwargs,
        )

    result = advance(quality_votes=c.quality_votes, service_votes=c.service_votes[:1])
    assert result.status == "waiting_service_votes"
    assert result.progress is None and result.package is None
    assert not owner.output.exists()
    owner = c.reopen()
    assert advance().status == "waiting_service_votes"
    assert advance(service_votes=c.service_votes[1:]).status == "phase_ready"
    inputs = complete
    owner.package_bytes = 1024
    with pytest.raises(ValueError, match=r"bound|capacity"):
        advance()
    assert not owner.output.exists()
    owner = c.reopen()
    result = advance()
    assert result.status == "package_published"
    assert canonical_json_bytes(result.package) == canonical_json_bytes(c.native.package)
    assert owner.output.read_bytes() == canonical_json_bytes(c.native.package)


@pytest.fixture
async def settlement_signing_case(native_settlement_case, tmp_path, request):
    import sqlite3
    from collections import Counter

    from umi.competition_cohort_coordinator import CohortDecisionInput, CohortRecoveryCoordinator
    from umi.competition_cohort_recovery_store import CohortRecoveryStore
    from umi.competition_cohort_settlement_controller import (
        CohortSettlementPhases,
        SettlementInputBatch,
        SettlementPeer,
        SettlementPeerReviewer,
    )
    from umi.competition_cohort_settlement_signing import (
        SettlementPhaseReview,
        SettlementPhaseSigner,
    )
    from umi.competition_execution import execution_boundary

    from .test_competition_cohort_coordinator import Harness

    c = native_settlement_case
    if getattr(request, "param", False):
        # Start with certified requests; the native owner must now construct
        # and certify reference reveal before any quality phase can close.
        assert c.inputs.history.transitions[-1].transition.phase == "reference_reveal"
        c.inputs = c.inputs.model_copy(
            update={
                "history": c.inputs.history.model_copy(
                    update={"transitions": c.inputs.history.transitions[:-1]}
                )
            }
        )
    initial = c.inputs.history
    h = SimpleNamespace(
        c=c,
        cohort=digest(initial.plan),
        signatures=Counter(),
        published=[],
        captures={},
        fail=None,
        provider=SimpleNamespace(
            block=initial.transitions[-1].transition.observed_at_block + 100,
            collects=0,
            fail_collect=False,
        ),
    )
    h.db = sqlite3.connect(tmp_path / "settlement-controller.sqlite3")
    h.store = CohortRecoveryStore(h.db)
    h.store.publish_history(initial, c.b["policy"], current_block=h.provider.block)
    for certified in initial.transitions:
        if certified.transition.operation != "revoke":
            h.store.retain_source(h.cohort, c.b["decisions"][certified.transition.evidence_sha256])

    async def collect():
        capture = await Harness.collect(h.provider)
        h.captures[capture.snapshot.block] = capture
        return capture

    h.raw_provider = SimpleNamespace(collect=collect)

    def signer(name):
        async def sign(body):
            h.signatures[(name, digest(body))] += 1
            return sign_object(body, wallet(name))

        return SettlementPhaseSigner(
            RoundJournal(tmp_path / ("phase-votes-" + name), {"cohort": h.cohort, "signer": name}),
            c.b["policy"],
            wallet(name).hotkey.ss58_address,
            sign,
        )

    def inputs():
        return c.inputs.model_copy(
            update={
                "history": h.store.export_history(
                    h.cohort,
                    genesis_signatures=initial.genesis_signatures,
                )
            }
        )

    def owner(name):
        selected = c.reopen("settlement-evidence-" + name)
        selected.decisions = lambda key: h.store.source(h.cohort, key, CohortDecisionInput)
        if name == "Dave":
            # In-process immutable object delivery stands in for replication.
            def source(key):
                try:
                    return c.objects[key]
                except KeyError:
                    return owner("Charlie").archive(key)

            selected.external = source
            # A late reviewer uses the native historical promotion verifier.
            # It must not select a new current head for the same allocation.
            selected.promotion_store = SimpleNamespace(
                policy=c.native.store.policy,
                reviewed_promotion_at=c.native.store.reviewed_promotion_at,
            )
        return selected

    def review(name, capture, proposed_progress=None):
        selected = inputs()
        return SettlementPhaseReview(
            owner(name),
            selected,
            iter(c.b["records"]),
            observation=execution_boundary(capture),
            expected_tip_sha256=tip(selected.history),
            current_block=h.provider.block,
            quality_votes=c.quality_votes,
            service_votes=c.service_votes,
            proposed_progress=proposed_progress,
        )

    async def archive(observation):
        # Proof RPC/finality are synthetic; use the original retained capture.
        assert execution_boundary(h.captures[observation.block]) == observation
        return b"original-registration-proof", b"runtime-metadata"

    async def review_archive(observation, raw, metadata):
        assert (raw, metadata) == await archive(observation)
        return SimpleNamespace(
            original=observation, replayed_at=SimpleNamespace(block_number=h.provider.block)
        )

    async def peer_progress(request, observation):
        if h.fail == "progress":
            h.fail = None
            raise OSError("peer unavailable")
        return await h.peer.progress(request, observation)

    async def peer_transition(proposal, evidence):
        if h.fail == "transition":
            h.fail = None
            raise OSError("peer unavailable")
        return await h.peer.transition(proposal, evidence)

    async def publish(history):
        # Local durable history stands in for remote replicated publication.
        h.published.append(canonical_json_bytes(history))

    def coordinator():
        h.signers = {name: signer(name) for name in ("Charlie", "Dave")}

        def source():
            return SettlementInputBatch(
                inputs(), tuple(c.b["records"]), c.quality_votes, c.service_votes
            )

        h.peer = SettlementPeerReviewer(
            CohortSettlementPhases(
                owner=owner("Dave"),
                store=h.store,
                signer=h.signers["Dave"],
                source=source,
                peers=(),
            ),
            SimpleNamespace(policy=c.b["policy"], review_archive=review_archive),
            archive,
            proposer=wallet("Charlie").hotkey.ss58_address,
        )
        h.phases = CohortSettlementPhases(
            owner=owner("Charlie"),
            store=h.store,
            signer=h.signers["Charlie"],
            source=source,
            peers=(
                SettlementPeer(wallet("Dave").hotkey.ss58_address, peer_progress, peer_transition),
            ),
        )
        return CohortRecoveryCoordinator(
            h.store,
            h.cohort,
            c.b["policy"],
            initial.genesis_signatures,
            h.raw_provider,
            None,
            h.phases.certify,
            publish,
            sample_progress=h.phases.sample,
            attest_progress=h.phases.attest,
        )

    def reopen():
        h.db.close()
        h.db = sqlite3.connect(tmp_path / "settlement-controller.sqlite3")
        h.store = CohortRecoveryStore(h.db)
        return coordinator()

    h.coordinator, h.reopen, h.inputs, h.owner, h.review = (
        coordinator,
        reopen,
        inputs,
        owner,
        review,
    )
    try:
        yield h
    finally:
        h.db.close()


@pytest.mark.parametrize("settlement_signing_case", [True], indirect=True)
@pytest.mark.parametrize(
    "fault", ["reference", "corrupt_reference", "suite", "catalog", "reveal", "terminal", "early"]
)
async def test_reference_review_rejects_incomplete_or_changed_inputs(
    settlement_signing_case, fault
):
    import json

    h = settlement_signing_case
    h.coordinator()
    inputs = h.c.inputs
    key = inputs.catalogs[0].catalog.work[0].reference_sha256
    if fault == "reference":
        del h.c.objects[key]
    elif fault == "corrupt_reference":
        original = json.loads(h.c.objects[key])
        h.c.objects[key] = canonical_json_bytes({**original, "reference": "substitution"})
    elif fault == "suite":
        h.c.inputs = inputs.model_copy(
            update={"suite": inputs.suite.model_copy(update={"policy_sha256": "00" * 32})}
        )
    elif fault == "catalog":
        h.c.inputs = inputs.model_copy(update={"catalogs": ()})
    elif fault == "reveal":
        h.c.inputs = inputs.model_copy(
            update={
                "reveal": inputs.reveal.model_copy(update={"request_closure_sha256": "00" * 32})
            }
        )
    elif fault == "terminal":
        del h.c.objects[inputs.closure.catalogs[0].terminals[0]]
    else:
        h.provider.block = inputs.history.transitions[-1].transition.observed_at_block
    capture = await h.raw_provider.collect()
    with pytest.raises((ValueError, KeyError, FileNotFoundError)):
        await h.signers["Charlie"].attest(h.review("Charlie", capture))
    assert not h.signatures


@pytest.mark.parametrize("offline_stage", ["progress", "transition"])
async def test_native_settlement_controller_resumes_original_votes_after_peer_outage(
    settlement_signing_case,
    offline_stage,
    caplog,
):
    """No phase-completion helper after reveal: native review/signing/controller."""
    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = settlement_signing_case
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    h.fail = offline_stage
    controller = h.coordinator()
    with pytest.raises(SettlementPhaseQuorumPending):
        await controller.tick()
    observed = h.provider.block
    assert h.provider.collects == 1
    h.provider.block += 100000
    h.provider.fail_collect = True
    controller = h.reopen()
    report = await controller.tick()
    assert report["status"] == "phase_decision_published"
    assert report["phase"] == "review"
    assert h.provider.collects == 1  # Reuse the original completed-phase capture.
    assert h.inputs().history.transitions[-1].transition.observed_at_block == observed
    h.provider.fail_collect = False
    for phase in ("certification", "first_admission"):
        h.provider.block += 1
        report = await h.reopen().tick()
        assert report["phase"] == phase
    assert h.provider.collects == 3
    assert len(h.signatures) == 12  # Two evaluator keys, two signatures per phase.
    assert set(h.signatures.values()) == {1}
    selected = h.inputs()
    result = h.owner("Charlie").advance(
        selected,
        iter(h.c.b["records"]),
        expected_tip_sha256=tip(selected.history),
        current_block=h.provider.block,
    )
    assert result.status == "package_published"
    assert result.package.allocation == h.c.native.allocation
    assert result.package.benchmark == h.c.native.package.benchmark
    assert result.package.service == h.c.native.package.service
    assert h.c.b["service_case"].p.model.calls == 1
    events = json_progress_payloads(
        caplog.records,
        logger="umi.competition.progress",
        schema="umi-competition-work-progress/1",
    )
    for phase in ("evidence", "review", "certification"):
        for suffix in ("native_review", "peer_progress_vote", "peer_decision_vote"):
            completed = [
                e
                for e in events
                if e["stage"] == phase + "_" + suffix and e["state"] == "completed"
            ]
            assert completed, (phase, suffix)
            assert all(e["percent"] == 100 and e["eta_seconds"] == 0 for e in completed)
            assert all(e["cohort_sha256"] == h.cohort for e in completed)
    interrupted = [e for e in events if e["state"] == "interrupted"]
    suffix = "progress" if offline_stage == "progress" else "decision"
    assert any(e["stage"] == "evidence_peer_" + suffix + "_vote" for e in interrupted)
    assert all(e["percent"] < 100 and e["eta_seconds"] is None for e in interrupted)


async def test_settlement_phase_signing_rejects_changed_body_and_drains_cancellation(
    settlement_signing_case,
    tmp_path,
):
    from umi.competition_cohort_settlement_signing import SettlementPhaseSigner

    h = settlement_signing_case
    capture = await h.raw_provider.collect()
    reviewed = h.review("Charlie", capture)
    started, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def sign(body):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return sign_object(body, wallet("Charlie"))

    journal = RoundJournal(tmp_path / "cancelled-phase-vote", {"cohort": h.cohort})
    signer = SettlementPhaseSigner(
        journal, h.c.b["policy"], wallet("Charlie").hotkey.ss58_address, sign
    )
    task = asyncio.create_task(signer.attest(reviewed))
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    reopened = SettlementPhaseSigner(
        journal, h.c.b["policy"], wallet("Charlie").hotkey.ss58_address, sign
    )
    vote = await reopened.attest(reviewed)
    assert calls == 1
    assert await reopened.collect(reviewed, [vote]) is None
    with pytest.raises(ValueError):
        await reopened.collect(reviewed, [sign_object(reviewed.progress, wallet("Alice"))])
    h.provider.block += 1
    changed = h.review("Charlie", await h.raw_provider.collect())
    with pytest.raises(ValueError):
        await reopened.attest(changed)
    assert calls == 1


async def test_settlement_peer_replays_original_proofs_before_signing_without_blocking_loop(
    settlement_signing_case,
):
    from umi.competition_cohort_coordinator import AttestedCohortPhaseProgress
    from umi.competition_execution import execution_boundary

    h = settlement_signing_case
    h.coordinator()
    capture = await h.raw_provider.collect()
    state, _ = h.store.status(h.cohort)
    ticks = 0
    stop = asyncio.Event()

    async def heartbeat():
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.01)

    heartbeat_task = asyncio.create_task(heartbeat())
    try:
        progress = await h.phases.sample(state, capture)
    finally:
        stop.set()
        await heartbeat_task
    assert ticks > 1  # Native replay leaves the finality/service loop responsive.
    observation = execution_boundary(capture)
    request = AttestedCohortPhaseProgress(
        progress=progress, signatures=(sign_object(progress, wallet("Charlie")),)
    )
    bad = request.model_copy(update={"signatures": (sign_object(progress, wallet("Alice")),)})
    with pytest.raises(ValueError, match="proposer"):
        await h.peer.progress(bad, observation)
    with pytest.raises(ValueError, match="another block"):
        await h.peer.progress(
            request, observation.model_copy(update={"block": observation.block + 1})
        )

    original = h.peer.provider.review_archive

    async def unavailable(*args):
        raise OSError("original finality unavailable")

    h.peer.provider.review_archive = unavailable
    with pytest.raises(OSError, match="finality unavailable"):
        await h.peer.progress(request, observation)
    assert not h.signatures
    h.peer.provider.review_archive = original
    h.provider.block += 100000
    vote = await h.peer.progress(request, observation)
    assert vote.hotkey == wallet("Dave").hotkey.ss58_address
    assert sum(h.signatures.values()) == 1


@pytest.fixture
async def settlement_file_case(settlement_signing_case, tmp_path):
    """Separate SQLite owners and actual immutable request/vote delivery.

    Native result replay is retained. Original object/promotion and proof verification
    sources still use the native fixture's synthetic delivery boundaries.
    """
    import sqlite3

    from umi.competition_cohort_coordinator import CohortDecisionInput
    from umi.competition_cohort_recovery_store import CohortRecoveryStore
    from umi.competition_cohort_settlement_controller import SettlementInputBatch
    from umi.competition_cohort_settlement_exchange import SettlementReviewExchange
    from umi.competition_cohort_settlement_proofs import SettlementRegistrationFiles
    from umi.private_files import ensure_private_directory

    h = settlement_signing_case
    initial = h.c.inputs.history
    db = None

    def start(reopen=False):
        nonlocal db
        if db is not None:
            db.close()
        controller = h.reopen() if reopen else h.coordinator()
        db = sqlite3.connect(tmp_path / "independent-reviewer.sqlite3")
        peer = h.peer.phases
        peer.store = CohortRecoveryStore(db)
        # A replacement reviewer may have only the approved admission. Each
        # delivered request must bring its signed prefix and decision sources.
        if not db.execute("SELECT count(*) FROM cohort_recovery_bindings").fetchone()[0]:
            peer.store.publish_history(
                initial.model_copy(update={"transitions": ()}),
                h.c.b["policy"],
                current_block=h.provider.block,
            )
        peer.owner.decisions = lambda key: peer.store.source(h.cohort, key, CohortDecisionInput)

        def source():
            history = peer.store.export_history(
                h.cohort, genesis_signatures=initial.genesis_signatures
            )
            return SettlementInputBatch(
                h.c.inputs.model_copy(update={"history": history}),
                tuple(h.c.b["records"]),
                h.c.quality_votes,
                h.c.service_votes,
            )

        peer.source = source
        h.peer.provider.ensure_observer_running = lambda: None
        h.sender = SettlementReviewExchange(
            h.phases,
            proposer=wallet("Charlie").hotkey.ss58_address,
            inbox=tmp_path / "sender-inbox",
            outbox=tmp_path / "sender-outbox",
            proofs=SettlementRegistrationFiles(
                SimpleNamespace(policy=h.c.b["policy"], retained_archive=h.peer.archive),
                inbox=tmp_path / "sender-inbox/proofs",
                outbox=tmp_path / "sender-outbox/proofs",
            ),
        )
        h.receiver = SettlementReviewExchange(
            peer,
            proposer=wallet("Charlie").hotkey.ss58_address,
            inbox=tmp_path / "receiver-inbox",
            outbox=tmp_path / "receiver-outbox",
            proofs=SettlementRegistrationFiles(
                h.peer.provider,
                inbox=tmp_path / "receiver-inbox/proofs",
                outbox=tmp_path / "receiver-outbox/proofs",
            ),
        )
        h.phases.peers = (h.sender.peer(wallet("Dave").hotkey.ss58_address),)
        return controller

    def copy_files(origin, target):
        import os

        for path in origin.rglob("*.json"):
            destination = target / path.relative_to(origin)
            ensure_private_directory(destination.parent)
            raw = path.read_bytes()
            if destination.exists():
                assert destination.read_bytes() == raw
            else:
                with open(destination, "xb") as out:
                    os.chmod(destination, 0o600)
                    out.write(raw)

    h.file_start = start
    h.deliver_requests = lambda: copy_files(h.sender.outbox, h.receiver.inbox)
    h.deliver_votes = lambda: copy_files(h.receiver.outbox, h.sender.inbox)
    try:
        yield h
    finally:
        if db is not None:
            db.close()


@pytest.mark.parametrize("settlement_signing_case", [False, True], indirect=True)
async def test_settlement_file_delivery_recovers_phases_with_independent_state(
    settlement_file_case,
):
    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = settlement_file_case
    controller = h.file_start()
    transitions = [
        ("evidence", "review"),
        ("review", "certification"),
        ("certification", "first_admission"),
    ]
    if h.store.status(h.cohort)[0].phase == "reference_reveal":
        transitions.insert(0, ("reference_reveal", "evidence"))
    for phase, following in transitions:
        h.provider.block += 1
        original_block = h.provider.block
        with pytest.raises(SettlementPhaseQuorumPending):
            await controller.tick()  # Request durable; peer has not received it.
        local_signatures = sum(h.signatures.values())
        h.provider.block += 100000
        h.provider.fail_collect = True
        controller = h.file_start(reopen=True)
        h.deliver_requests()
        request = h.receiver.request(phase, "progress")
        assert request.observation.block == original_block
        await h.receiver.review(request)
        assert h.peer.phases.store is not h.store
        # Crash and lose the delivery acknowledgement after native signing.
        count = sum(h.signatures.values())
        controller = h.file_start(reopen=True)
        await h.receiver.review(h.receiver.request(phase, "progress"))
        assert sum(h.signatures.values()) == count == local_signatures + 1
        h.deliver_votes()
        with pytest.raises(SettlementPhaseQuorumPending):
            await controller.tick()  # Transition request now retained.
        h.deliver_requests()
        await h.receiver.review(h.receiver.request(phase, "transition"))
        h.deliver_votes()
        controller = h.file_start(reopen=True)
        report = await controller.tick()
        assert report["phase"] == following
        assert h.inputs().history.transitions[-1].transition.observed_at_block == original_block
        h.provider.fail_collect = False
    assert h.provider.collects == len(transitions)
    assert len(h.signatures) == 4 * len(transitions) and set(h.signatures.values()) == {1}
    result = h.owner("Charlie").advance(
        h.inputs(),
        iter(h.c.b["records"]),
        expected_tip_sha256=tip(h.inputs().history),
        current_block=h.provider.block,
    )
    assert result.status == "package_published"
    assert result.package.allocation == h.c.native.allocation
    # Old delivered requests remain replayable after the receiver has advanced.
    before = dict(h.signatures)
    await h.receiver.review(h.receiver.request("evidence", "progress"))
    assert dict(h.signatures) == before
    old_request = h.receiver.request("evidence", "progress")
    delivery = h.receiver._vote_path(
        h.receiver.outbox, old_request, wallet("Dave").hotkey.ss58_address
    )
    original_bytes = delivery.read_bytes()
    delivery.unlink()  # Restore scenario: signer journal survives, outbox does not.
    await h.receiver.review(old_request)
    assert delivery.read_bytes() == original_bytes
    assert dict(h.signatures) == before
    assert h.c.b["service_case"].p.model.calls == 1


async def test_settlement_file_request_rejects_changes_before_history_or_proof_io(
    settlement_file_case,
):
    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = settlement_file_case
    controller = h.file_start()
    with pytest.raises(SettlementPhaseQuorumPending):
        await controller.tick()
    h.deliver_requests()
    request = h.receiver.request("evidence", "progress")
    state = h.peer.phases.store.status(h.cohort)
    count = sum(h.signatures.values())
    # A valid signed request with an undelivered proof cannot advance history.
    proof = h.receiver.proofs.inbox.root / "registration" / (digest(request.observation) + ".json")
    held = proof.with_suffix(".held")
    proof.rename(held)
    with pytest.raises(FileNotFoundError):
        await h.receiver.review(request)
    assert h.peer.phases.store.status(h.cohort) == state
    assert sum(h.signatures.values()) == count
    held.rename(proof)
    changed_vote = sign_object(request.progress.progress, wallet("Alice"))
    cases = (
        request.model_copy(update={"decisions": request.decisions[:-1]}),
        request.model_copy(update={"decisions": (*request.decisions, request.decisions[0])}),
        request.model_copy(
            update={
                "observation": request.observation.model_copy(
                    update={"block": request.observation.block + 1}
                )
            }
        ),
        request.model_copy(
            update={"progress": request.progress.model_copy(update={"signatures": (changed_vote,)})}
        ),
    )
    for changed in cases:
        with pytest.raises(ValueError):
            await h.receiver.review(changed)
        assert h.peer.phases.store.status(h.cohort) == state
        assert sum(h.signatures.values()) == count


async def test_settlement_file_reviewer_loop_recovers_after_missing_proof(settlement_file_case):
    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = settlement_file_case
    with pytest.raises(SettlementPhaseQuorumPending):
        await h.file_start().tick()
    h.deliver_requests()
    request = h.receiver.request("evidence", "progress")
    native = h.peer.provider.review_archive
    attempted = asyncio.Event()

    async def unavailable(*args):
        attempted.set()
        raise FileNotFoundError("proof transport unavailable")

    h.peer.provider.review_archive = unavailable
    original_state = h.peer.phases.store.status(h.cohort)
    stop = asyncio.Event()
    task = asyncio.create_task(h.receiver.run_reviewer(stop, poll_seconds=0.01))
    try:
        await asyncio.wait_for(attempted.wait(), 10)
        assert not tuple(h.receiver.outbox.rglob("*.json"))
        assert h.peer.phases.store.status(h.cohort) == original_state
        h.peer.provider.review_archive = native

        async def delivered():
            while not tuple(h.receiver.outbox.rglob("*.json")):
                await asyncio.sleep(0.01)

        await asyncio.wait_for(delivered(), 20)
    finally:
        stop.set()
        await task
    assert h.receiver._vote_path(
        h.receiver.outbox, request, wallet("Dave").hotkey.ss58_address
    ).exists()
    assert sum(v for (name, _), v in h.signatures.items() if name == "Dave") == 1


async def test_native_reward_package_uses_dedicated_aggregate_file_and_replay_budget(
    native_package, tmp_path
):
    from umi.competition_cohort_reward_package import load_reward_package, publish_reward_package
    from umi.competition_reward_files import StandingRewardFiles

    p = native_package
    maximum = 1024**3
    files = StandingRewardFiles(
        tmp_path / "aggregate-reward",
        maximum_package_bytes=maximum,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    assert files.package(digest(p.package)) == p.package
    path = tmp_path / "aggregate-settlement" / "package.json"
    publish_reward_package(path, p.package, maximum_bytes=maximum)
    selected = dict(
        expected_package_sha256=digest(p.package),
        expected_cohort_sha256=p.requirement.cohort_sha256,
        expected_tip_sha256=tip(p.package.inputs.history),
        current_block=2**53 - 1,
        expected_terms_sha256=p.requirement.terms_sha256,
        expected_catalog_sha256s=p.requirement.catalog_sha256s,
        maximum_promotion_bytes=1_000_000,
    )
    assert (
        load_reward_package(
            path,
            p.store.policy,
            p.store,
            p.package.inputs.history,
            maximum_bytes=maximum,
            **selected,
        )
        == p.allocation
    )
    with pytest.raises(ValueError, match="input exceeds"):
        load_reward_package(
            path,
            p.store.policy,
            p.store,
            p.package.inputs.history,
            maximum_bytes=1024,
            **selected,
        )


async def test_reward_snapshot_detaches_nested_mutation_and_preserves_exact_budget(native_package):
    package = native_package.package
    raw = canonical_json_bytes(package)
    snapshot = preparation._validated_reward_snapshot(package, len(raw))
    assert canonical_json_bytes(snapshot) == raw
    assert digest(snapshot) == digest(package)
    with pytest.raises(ValueError, match="byte bound"):
        preparation._validated_reward_snapshot(package, len(raw) - 1)
    original = next(obj for obj in package.objects if isinstance(obj.value, dict))
    original.value["snapshot_mutation"] = [1, 2, 3]
    assert canonical_json_bytes(snapshot) == raw
    assert digest(snapshot) != digest(package)
    original.value["snapshot_mutation"].append(2**53)
    with pytest.raises(ValueError):
        preparation._validated_reward_snapshot(package, 1024**3)


async def test_retained_coverage_package_keeps_native_owner_and_historical_boundary(
    historical_preparation_case,
):
    from umi.competition_reward_coverage_prepared import (
        CoveragePackageReplayRequired,
        RetainedCoveragePackage,
        prepare_retained_coverage,
    )

    p, control, chosen, args = historical_preparation_case
    prepared = await p.preparation.prepare_historical(p.package, **args)
    retained = RetainedCoveragePackage(prepared)
    assert await prepare_retained_coverage(p.preparation, retained, **args) is prepared
    # A current successor drain still uses its independently proved effective predecessor.
    chosen.current = replace(
        chosen.current, selection=replace(chosen.current.selection, state="draining")
    )
    assert await prepare_retained_coverage(p.preparation, retained, **args) is prepared
    control.snapshot = replace(control.snapshot, block_number=prepared.reviewed_at_block - 1)
    with pytest.raises(CoveragePackageReplayRequired):
        await prepare_retained_coverage(p.preparation, retained, **args)
    control.snapshot = replace(control.snapshot, block_number=prepared.reviewed_at_block)
    changed = RetainedCoveragePackage(replace(prepared, _owner=object()))
    with pytest.raises(ValueError, match="native replay owner"):
        await prepare_retained_coverage(p.preparation, changed, **args)
    p.preparation.model_artifacts = object()
    with pytest.raises(CoveragePackageReplayRequired):
        await prepare_retained_coverage(p.preparation, retained, **args)


async def test_retained_coverage_package_refuses_changed_activation_or_authority(
    historical_preparation_case,
):
    from umi.competition_reward_coverage_prepared import (
        RetainedCoveragePackage,
        prepare_retained_coverage,
    )

    p, _, chosen, args = historical_preparation_case
    prepared = await p.preparation.prepare_historical(p.package, **args)
    retained = RetainedCoveragePackage(prepared)
    before = chosen.current
    chosen.current = replace(
        before,
        effective_selection=replace(
            before.effective_selection,
            activation=prepared.activation.model_copy(update={"package_sha256": "ff" * 32}),
        ),
    )
    with pytest.raises(ValueError, match="historical activation"):
        await prepare_retained_coverage(p.preparation, retained, **args)
    chosen.current = before
    p.preparation.manifest = p.manifest.model_copy(update={"policy_sha256": "ee" * 32})
    with pytest.raises(ValueError, match="authority changed"):
        await prepare_retained_coverage(p.preparation, retained, **args)


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_lazy_native_coverage_releases_package_and_reloads_earlier_history(
    complete_preparation_case,
    tmp_path,
):
    import gc
    import weakref

    from umi.competition_cohort_reward_package import CohortRewardPackage
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_opportunity import opportunity_rule

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    journal = RewardCoverageJournal(
        tmp_path / "lazy-coverage", rule, expected_rule_sha256=digest(rule)
    )
    owner = StandingRewardPreparation(
        c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
    )
    references = []

    def load():
        package = CohortRewardPackage.model_validate_json(canonical_json_bytes(p.package))
        references.append(weakref.ref(package))
        return package

    source = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=journal,
        history=h.reader,
        preparation=owner,
        package_loader=load,
        package_sha256=digest(p.package),
        decisions=c.source,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )

    async def capture(height):
        for _ in range(100):
            try:
                return await source.capture(h.validator_hotkey, height)
            except CoverageHistoryPending:
                continue
        pytest.fail("native historical coverage did not converge")

    later = await capture(h.end)
    assert later.covered and len(references) == 1
    gc.collect()
    assert references[0]() is None and source.package is None
    again = await capture(h.end)
    assert again.covered and len(references) == 1
    earlier = await capture(h.end - 1)
    assert earlier.covered and len(references) == 2
    gc.collect()
    assert all(reference() is None for reference in references)
    await capture(h.end)
    assert len(references) == 2
    # Retained journal replay still authenticates original proofs with compact native preparation.
    await journal.retain_endpoint(later)
    source._cache.clear()
    from umi.competition_reward_coverage_intervals import coverage_point

    assert (await source.replay(coverage_point(later, rule).key())).covered
    assert len(references) == 2


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_remote_coverage_reuses_native_facts_after_eviction_restart_and_repair(
    complete_preparation_case, tmp_path, monkeypatch
):
    from umi import competition_reward_coverage_journal as coverage_module
    from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
    from umi.competition_reward_coverage_intervals import coverage_point
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_proof_archive import RewardProofArchive

    from .test_competition_remote_proof_store import EvidenceServer, store

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    server = EvidenceServer()
    state, remote_state, archive_root = (
        tmp_path / "coverage",
        tmp_path / "r2-state",
        tmp_path / "outbox",
    )

    def open_owner():
        remote = store(remote_state, server)
        journal = RewardCoverageJournal(
            state,
            rule,
            expected_rule_sha256=digest(rule),
            export_archive=RewardProofArchive(archive_root, remote=remote),
        )

        def no_implicit_migration(*_args, **_kwargs):
            pytest.fail("native coverage started an implicit legacy source migration")

        monkeypatch.setattr(journal.externalized, "externalize_many", no_implicit_migration)
        preparation = StandingRewardPreparation(
            c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
        )
        return journal, remote, preparation

    journal, remote, owner = open_owner()
    source = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=journal,
        history=h.reader,
        preparation=owner,
        package=p.package,
        decisions=c.source,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )
    endpoints = []
    for height in (h.end - 1, h.end):
        for _ in range(100):
            try:
                endpoint = await source.capture(h.validator_hotkey, height)
                break
            except CoverageHistoryPending:
                continue
        else:
            pytest.fail("native coverage fixture did not converge")
        await journal.retain_endpoint(endpoint)
        endpoints.append(endpoint)
    interval = await journal.credit(*endpoints)
    assert interval.credited_ms == 12000
    keys = [coverage_point(e, rule).key() for e in endpoints]
    with journal.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
        assert (
            db.execute(
                "SELECT COUNT(*) FROM records WHERE kind IN "
                "('coverage_object','coverage_endpoint','coverage_blob_proof','coverage_blob_metadata')"
            ).fetchone()[0]
            == 0
        )
    with pytest.raises(ValueError, match="unsupported round journal"):
        RoundJournal(state, rule, maximum_rounds=65536, maximum_bytes=4 * 1024**3)

    fresh, remote, owner = open_owner()
    loads = []

    def unavailable_package():
        loads.append(True)
        raise AssertionError("completed coverage reread its package")

    restarted = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=fresh,
        history=h.reader,
        preparation=owner,
        package_loader=unavailable_package,
        package_sha256=digest(p.package),
        decisions=c.source,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )

    def prohibit(*_args, **_kwargs):
        raise AssertionError("completed coverage repeated native proof work")

    server.calls.clear()
    with monkeypatch.context() as m:
        m.setattr(coverage_module, "review_reward_eligibility", prohibit)
        m.setattr(coverage_module, "review_reward_coverage", prohibit)
        m.setattr(fresh, "_load", prohibit)
        m.setattr("umi.competition_reward_coverage_source.capture_reward_eligibility", prohibit)
        restored = [
            await restarted.capture(h.validator_hotkey, height) for height in (h.end - 1, h.end)
        ]
        assert await fresh.credit(*restored) == interval
        assert all(endpoint.covered for endpoint in restored)
    assert not loads and not server.calls
    # Upgrade a supported old coverage owner with no supplementary transport
    # domain. The original native endpoints and all byte/block results remain.
    # An old not_selected dependency mode is not an empty direct inventory.
    from umi.competition_reward_transport_qualification import KIND

    qualifications = owner.transport_qualifications
    legacy_original = fresh.checkpoints.load(keys[0])
    qualifications.root.rename(qualifications.root.with_name("prior-transport-fixture"))
    qualifications.marker.rename(qualifications.marker.with_suffix(".fixture"))
    owner._transport_qualifications = None

    def original_package_metadata():
        loads.append(True)
        return p.package

    restarted._package_loader = original_package_metadata
    with monkeypatch.context() as m:
        m.setattr(coverage_module, "review_reward_eligibility", prohibit)
        m.setattr(coverage_module, "review_reward_coverage", prohibit)
        m.setattr(fresh, "_load", prohibit)
        restored = [await restarted.replay(key) for key in keys]
    assert loads == [True] and not server.calls
    assert fresh.checkpoints.load(keys[0]) == legacy_original
    qualifications = owner.transport_qualifications
    qualified = qualifications.load(
        legacy_original["package_sha256"], legacy_original["cohort_sha256"]
    )
    assert qualified["direct_acceptances"] == []
    with qualifications.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=?", (KIND,))
    restarted._package_loader = unavailable_package
    with pytest.raises(CoverageCheckpointRepairRequired, match="scoped repair"):
        await restarted.replay(keys[0])
    with monkeypatch.context() as m:
        m.setattr(coverage_module, "review_reward_eligibility", prohibit)
        m.setattr(coverage_module, "review_reward_coverage", prohibit)
        m.setattr(fresh, "_load", prohibit)
        repaired = await restarted.repair_model_transport(
            keys[0], reason="restore exact supplementary completion from original ledger"
        )
    assert repaired.covered and loads == [True] and not server.calls
    foreign = RewardCoverageJournal(tmp_path / "foreign", rule, expected_rule_sha256=digest(rule))
    with pytest.raises(ValueError, match="lost its native result"):
        await foreign.credit(*restored)

    # Reproduce an older compact completion that did not retain row-match/update
    # metadata. Preserve the exact original endpoint/proof bytes and old fact;
    # absence of the added field means unknown until explicit native repair.
    legacy_result = dict(fresh.checkpoints.load(keys[0]))
    legacy_result.pop("row_state")

    def select_legacy(db):
        db.execute(
            "UPDATE coverage_checkpoint_index SET result=? WHERE id=?",
            (digest(legacy_result), keys[0]),
        )

    fresh.journal.put_many(
        (("coverage_verified", digest(legacy_result), legacy_result),), index=select_legacy
    )
    restarted._cache.clear()
    legacy_endpoint = await restarted.replay(keys[0])
    assert legacy_endpoint.row_matches is None and legacy_endpoint.validator_last_update is None
    restarted._package_loader = lambda: p.package
    repaired = await restarted.repair(keys[0], reason="reward_revision_row_state_upgrade")
    assert repaired.row_matches == endpoints[0].row_matches
    metadata = fresh.checkpoints.load(keys[0])
    assert metadata["row_state"] == {
        "row_matches": endpoints[0].row_matches,
        "validator_last_update": endpoints[0].eligibility.subject.validator_last_update,
    }
    assert metadata["repair"] == "reward_revision_row_state_upgrade"
    assert fresh.journal.get("coverage_verified", digest(legacy_result)) == legacy_result
    fresh, remote, owner = open_owner()
    restarted = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=fresh,
        history=h.reader,
        preparation=owner,
        package_loader=unavailable_package,
        package_sha256=digest(p.package),
        decisions=c.source,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )
    with monkeypatch.context() as m:
        m.setattr(coverage_module, "review_reward_eligibility", prohibit)
        m.setattr(coverage_module, "review_reward_coverage", prohibit)
        fixed = await restarted.replay(keys[0])
        assert fixed.row_matches == repaired.row_matches
        assert fixed.validator_last_update == metadata["row_state"]["validator_last_update"]
    # Only the earlier supplementary transport migration loaded original
    # package metadata; subsequent native repair and restart add no loads.
    assert loads == [True]

    # An observed missing remote source remains a hold across restart. Restoring
    # its exact generation requires one explicit transport repair, no proof replay.
    alias = fresh.journal.get("coverage_remote_source", digest(["coverage_endpoint", keys[0]]))
    reference = alias["remote"]
    raw = server.objects.pop(reference["key"])
    remote.evict_cache()
    with pytest.raises(ValueError, match="explicit repair"):
        fresh._load(keys[0])
    with pytest.raises(CoverageCheckpointRepairRequired):
        fresh.checkpoints.load(keys[0])
    with pytest.raises(CoverageCheckpointRepairRequired):
        await restarted.replay(keys[0])  # Even a process-local cache must hold.
    server.objects[reference["key"]] = raw
    remote.repair_reference(reference)
    assert fresh.checkpoints.load(keys[0]) is not None
    server.calls.clear()
    with monkeypatch.context() as m:
        m.setattr(coverage_module, "review_reward_eligibility", prohibit)
        m.setattr(coverage_module, "review_reward_coverage", prohibit)
        assert (await restarted.replay(keys[0])).covered
    assert not server.calls and loads == [True]


async def test_settlement_releases_parsed_package_after_native_replay(
    recurring_settlement_case, monkeypatch
):
    import gc
    import weakref

    from umi import competition_cohort_settlement_service as service_module

    h = recurring_settlement_case
    h.assemble_inputs = True
    a = await h.start("Charlie")
    assemble = service_module.assemble_settlement_inputs
    references = []

    def capture(*args, **kwargs):
        package = assemble(*args, **kwargs)
        references.append(weakref.ref(package))
        return package

    monkeypatch.setattr(service_module, "assemble_settlement_inputs", capture)
    await a._start(await a._handoff())
    await asyncio.sleep(0)
    gc.collect()
    assert references and all(reference() is None for reference in references)
    assert a.package_reference[1] == digest(h.c.package)
    assert a.package_reference[0].read_bytes() == canonical_json_bytes(h.c.package)
    assert a.data is not None and a.phases is not None


def test_settlement_serialization_scope_preserves_native_checks_and_package_bytes(
    original_settlement_inputs, monkeypatch, caplog
):
    from umi import canonical_reuse as reuse
    from umi import open_competition as protocol
    from umi.competition_cohort_settlement_inputs import (
        prepare_settlement_inputs,
        replay_settlement_inputs,
    )

    case, results = original_settlement_inputs, []
    b = case.b
    verify = protocol.verify_response_signature
    count = 0

    def counted_signature(*args, **kwargs):
        nonlocal count
        count += 1
        return verify(*args, **kwargs)

    monkeypatch.setattr(protocol, "verify_response_signature", counted_signature)
    caplog.set_level("INFO", logger="umi.competition.progress")
    for budget in (0, 64 * 1024**2):
        start = count
        read_keys = []

        def source(key, read_keys=read_keys):
            read_keys.append(key)
            return b["objects"][key]

        with reuse.canonical_json_reuse(maximum_bytes=budget, maximum_entries=65536):
            cache = reuse._ACTIVE.get()
            package = prepare_settlement_inputs(
                case.package.inputs,
                b["policy"],
                case.requirement,
                source,
                b["decisions"].__getitem__,
                iter(b["records"]),
                lambda _: RetainedRevealPulse(**pulse_record()),
                expected_tip_sha256=tip(case.package.inputs.history),
                current_block=1000000,
            )
            replayed = replay_settlement_inputs(
                package,
                b["policy"],
                case.requirement,
                package.inputs.history,
                expected_package_sha256=digest(package),
                expected_tip_sha256=tip(package.inputs.history),
                current_block=1000000,
            )
            results.append(
                (
                    canonical_json_bytes(package),
                    canonical_json_bytes(replayed.inputs),
                    tuple(read_keys),
                    count - start,
                )
            )
        assert cache.closed and not cache.entries and cache.size == 0
        assert reuse._ACTIVE.get() is None
    assert results[0] == results[1]
    assert results[0][-1] > 0 and results[0][-2]
    events = json_progress_payloads(
        caplog.records,
        logger="umi.competition.progress",
        schema="umi-competition-work-progress/1",
    )
    names = {event.get("operation_name") for event in events}
    assert {"settlement_prepare", "settlement_replay"} <= names
    assert all(event["certification_authority"] is False for event in events)


async def test_durable_snapshot_preparation_reuses_native_work_across_all_consumers(
    historical_preparation_case, tmp_path, monkeypatch, record_property
):
    """Installed file loader, fresh/restarted writer, predecessor and initial replay."""
    from umi import competition_cohort_endpoint_archive as archive_module
    from umi import competition_cohort_endpoint_quality as endpoint_module
    from umi import competition_cohort_request_terminal as terminal_module
    from umi import competition_cohort_service_quality as service_module
    from umi.competition_reward_files import StandingRewardFiles

    p, _, chosen, historical_args = historical_preparation_case
    files = StandingRewardFiles(
        tmp_path / "durable-inputs",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    package_sha = digest(p.package)
    before = (files.root / "packages" / (package_sha + ".json")).read_bytes()
    counts = {"cases": 0, "endpoint_content": 0, "paid_content": 0, "execution": 0}
    for module, name, key in (
        (archive_module, "verify_case_decision", "cases"),
        (endpoint_module, "decrypt_endpoint_content", "endpoint_content"),
        (service_module, "decrypt_endpoint_content", "paid_content"),
        (terminal_module, "replay_execution_steps", "execution"),
    ):
        native = getattr(module, name)

        def counted(*args, _native=native, _key=key, **kwargs):
            counts[_key] += 1
            return _native(*args, **kwargs)

        monkeypatch.setattr(module, name, counted)
    snapshot = files.verified_package(package_sha)
    ready = await p.preparation.prepare(snapshot, **replay_args(await p.observations()))
    assert ready.allocation == p.allocation
    cold = counts.copy()
    assert all(value > 0 for value in cold.values())
    from .reward_snapshot_assertions import NativeContextReads

    reads = NativeContextReads(monkeypatch, p.package, snapshot)
    restored = p.reopen()
    snapshot = files.verified_package(package_sha)
    again = await restored.prepare(snapshot, **replay_args(await p.observations()))
    assert again.allocation == p.allocation
    assert counts == cold
    assert reads.check()["objects"] > 0
    predecessor = await p.reopen().prepare_historical(snapshot, **historical_args)
    reads.check()
    chosen.current = replace(chosen.current, initial_selection=chosen.current.selection)
    initial = await p.reopen().prepare_initial(snapshot, **historical_args)
    reads.check()
    assert predecessor.allocation == initial.allocation == ready.allocation
    assert counts == cold
    fresh = await p.observations()
    projected = await restored.project(again, **fresh)
    assert sum(projected.projection.weights) == 65535
    assert not projected.chain_submission_authorized
    assert (files.root / "packages" / (package_sha + ".json")).read_bytes() == before
    record_property("warm_context_reads", json.dumps(reads.checks))


async def test_reward_delivery_consumers_reuse_snapshots_and_require_explicit_repair(
    preparation_case, tmp_path, monkeypatch, capsys
):
    """Real signed packages through publication, readback and publisher delivery."""
    from umi import competition_verification_snapshot as snapshot_module
    from umi.competition_reward_control_publisher import StandingControlPublisher
    from umi.competition_reward_coordinator import StandingRewardCoordinator
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_publication import retain_standing_reward_inputs
    from umi.competition_verification_snapshot_cli import main as snapshot_command

    p = preparation_case
    prefix = tuple(
        sorted(
            (SignedRewardControlDecision.model_validate_json(v) for v in p.objects.values()),
            key=lambda v: v.decision.sequence,
        )
    )
    roots = (tmp_path / "delivery-original", tmp_path / "delivery-readback")

    def open_files(root):
        return StandingRewardFiles(
            root, maximum_package_bytes=8 * 1024**2, maximum_witness_bytes=1024**2
        )

    for root in roots:
        files = open_files(root)
        retain_standing_reward_inputs(
            files, p.reader.series, p.reader.policy, prefix, lambda _: p.package
        )
        files.verified_package(digest(p.package))
    files, readback = map(open_files, roots)
    publisher = SimpleNamespace(files=files)
    coordinator = SimpleNamespace(readback=readback, publisher=publisher)

    def no_fetch(*args, **kwargs):
        pytest.fail("unchanged successful package was fetched or parsed again")

    def consume():
        assert retain_standing_reward_inputs(
            files, p.reader.series, p.reader.policy, prefix, no_fetch
        ) == digest(p.active.decision)
        StandingControlPublisher._delivered(publisher, prefix)
        StandingRewardCoordinator._readback(coordinator, prefix)

    with monkeypatch.context() as warm:
        warm.setattr(snapshot_module, "read_aggregate_model", no_fetch)
        native_read = snapshot_module._read_bounded_private_bytes

        def metadata_only(path, **kwargs):
            assert path.suffix != ".bin"
            assert path not in {root / "packages" / (digest(p.package) + ".json") for root in roots}
            return native_read(path, **kwargs)

        warm.setattr(snapshot_module, "_read_bounded_private_bytes", metadata_only)
        consume()

        record = next(
            path
            for path in (files.root / "verification" / "packages").glob("*.json")
            if json.loads(path.read_bytes()).get("schema") == "umi-private-verification-snapshot/1"
        )
        record.unlink()
        with pytest.raises(snapshot_module.VerificationSnapshotRepairRequired):
            consume()
        with pytest.raises(snapshot_module.VerificationSnapshotRepairRequired):
            StandingControlPublisher._delivered(publisher, prefix)

    # The supported operator entry point restores only the damaged snapshot.
    # Signed package/decision bytes and source paths are not rewritten.
    source = files.root / "packages" / (digest(p.package) + ".json")
    original = source.stat()
    snapshot_command(
        [
            "repair",
            "--store",
            str(files.root / "verification" / "packages"),
            "--source",
            str(source),
            "--kind",
            "reward",
            "--maximum-bytes",
            str(files.maximum_package_bytes),
            "--package-sha256",
            digest(p.package),
            "--reason",
            "missing snapshot completion",
        ]
    )
    assert json.loads(capsys.readouterr().out)["status"] == "ready"
    assert source.stat() == original
    with monkeypatch.context() as warm:
        warm.setattr(snapshot_module, "read_aggregate_model", no_fetch)
        consume()


@pytest.fixture
def runtime_consensus(request):
    return getattr(request, "param", None)


@pytest.mark.parametrize("runtime_consensus", ["Yuma"], indirect=True)
@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
@pytest.mark.parametrize("runtime_scope", ["forward", "historical_gap"])
async def test_runtime_adoption_retains_old_facts_and_new_native_archive_after_restart(
    complete_preparation_case, tmp_path, monkeypatch, runtime_consensus, runtime_scope
):
    from umi import competition_reward_coverage_journal as coverage_module
    from umi.competition_reward_coverage_intervals import coverage_point
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_eligibility import RewardEligibilityRuntime
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_runtime_adoption import (
        RewardRuntimeAdoption,
        RewardRuntimeAdoptionSelection,
        SignedRewardRuntimeAdoption,
        select_reward_runtime,
    )
    from umi.competition_reward_runtime_review import (
        review_selected_reward_eligibility,
        validate_selected_reward_eligibility,
    )

    h = complete_preparation_case
    p, c = h.package_case, h.c
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    root = tmp_path / "runtime-coverage"
    preparation_owner = StandingRewardPreparation(
        c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
    )

    def source(journal):
        return NativeRewardCoverageSource(
            provider=h.item.provider,
            journal=journal,
            history=h.reader,
            preparation=preparation_owner,
            package=p.package,
            decisions=c.source,
            profile=h.item.profile,
            maximum_history_blocks=4096,
        )

    async def capture(owner, height):
        for _ in range(100):
            try:
                return await owner.capture(h.validator_hotkey, height)
            except CoverageHistoryPending:
                pass
        pytest.fail("native fixture history did not converge")

    original = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
    old = await capture(source(original), h.end - 1)
    await original.retain_endpoint(old)
    old_point = coverage_point(old, rule)
    old_result = original.checkpoints.load(old_point.key())
    original_evidence = old.eligibility.eligibility_evidence
    effective = RewardEligibilityRuntime.model_validate_json(
        canonical_json_bytes(
            {
                **h.item.profile.model_dump(mode="json", by_alias=True),
                "schema": "umi-reward-eligibility-runtime/2",
                "epoch_source_revision": "f4786f9087cac84cfab37cbdf1e01c399042653a",
            }
        )
    )
    monkeypatch.setattr(
        "umi.competition_reward_eligibility._QUALIFIED_YUMA_RUNTIMES",
        frozenset({(effective.runtime_code_sha256, effective.epoch_source_revision)}),
    )
    body = RewardRuntimeAdoption(
        schema="umi-standing-reward-runtime-adoption/1",
        series_sha256=digest(c.series),
        manifest_sha256=digest(p.manifest),
        policy_sha256=digest(c.reader.policy),
        authority_sha256=digest(c.series.recovery.authority),
        original_runtime_profile_sha256=digest(h.item.profile),
        effective_profile=effective,
        first_block=h.end - 1,
        last_block=h.end + 100,
        issued_at_block=h.end,
        revision=1,
        predecessor_adoption_sha256=None,
        original_signed_inputs_unchanged=True,
    )
    signed = SignedRewardRuntimeAdoption(adoption=body, signatures=signatures(body))
    scopes, schema = (signed,), "umi-standing-reward-runtime-adoption-selection/1"
    if runtime_scope == "historical_gap":
        forward = body.model_copy(update={"first_block": h.end + 10})
        body = body.model_copy(
            update={
                "last_block": h.end + 1,
                "revision": 2,
                "predecessor_adoption_sha256": digest(forward),
            }
        )
        scopes = (
            SignedRewardRuntimeAdoption(adoption=forward, signatures=signatures(forward)),
            SignedRewardRuntimeAdoption(adoption=body, signatures=signatures(body)),
        )
        schema = "umi-standing-reward-runtime-adoption-selection/2"
    selection = select_reward_runtime(
        RewardRuntimeAdoptionSelection(schema=schema, adoptions=scopes),
        series=c.series,
        manifest=p.manifest,
        policy=c.reader.policy,
        original_profile=h.item.profile,
    )
    journal = RewardCoverageJournal(
        root, rule, expected_rule_sha256=digest(rule), runtime_selection=selection
    )
    current = await capture(source(journal), h.end)
    new_point = coverage_point(current, rule)
    assert new_point.runtime_profile_sha256 == digest(h.item.profile)
    assert new_point.effective_runtime_profile_sha256 == digest(effective)
    assert new_point.runtime_adoption_sha256 == digest(body)
    assert current.eligibility.runtime_profile_sha256 == digest(effective)
    assert current.covered and old.covered
    await journal.retain_endpoint(current)
    assert await journal.credit(old, current)
    assert original_evidence == old.eligibility.eligibility_evidence
    assert journal.checkpoints.load(old_point.key()) == old_result

    # Independent current observer and portable archive replay use the exact
    # same authenticated selection and complete native proof path.
    control, current_eligibility = await current_state(
        h,
        (await h.reader.verified_prefix(h.end)).tip,
        validator_hotkey=h.validator_hotkey,
        runtime_selection=selection,
    )
    chain = current_eligibility.chain
    assert validate_selected_reward_eligibility(
        current_eligibility, selection=selection, expected_chain_config_sha256=digest(h.item.config)
    ) == digest(body)
    h.reader = await h.restart()
    archived = await review_selected_reward_eligibility(
        h.item.provider,
        selection=selection,
        block=chain.block,
        runtime_profile_sha256=digest(effective),
        runtime_adoption_sha256=digest(body),
        control=control.evidence,
        chain=chain.evidence,
        eligibility=current_eligibility.evidence,
        metadata=chain.runtime.metadata_bytes,
        validator_hotkey=h.validator_hotkey,
        control_hotkey=c.series.control_hotkey,
    )
    assert archived.eligible
    with pytest.raises(ValueError):
        await review_selected_reward_eligibility(
            h.item.provider,
            selection=selection,
            block=chain.block + 1,
            runtime_profile_sha256=digest(effective),
            runtime_adoption_sha256=digest(body),
            control=control.evidence,
            chain=chain.evidence,
            eligibility=current_eligibility.evidence,
            metadata=chain.runtime.metadata_bytes,
            validator_hotkey=h.validator_hotkey,
            control_hotkey=c.series.control_hotkey,
        )

    fresh = RewardCoverageJournal(
        root, rule, expected_rule_sha256=digest(rule), runtime_selection=selection
    )
    restarted = source(fresh)

    def prohibit(*args, **kwargs):
        raise AssertionError("unchanged native coverage was reverified or reread")

    with monkeypatch.context() as warm:
        warm.setattr(coverage_module, "review_reward_eligibility", prohibit)
        warm.setattr(coverage_module, "review_reward_coverage", prohibit)
        warm.setattr(fresh, "_load", prohibit)
        restored = [await restarted.replay(value.key()) for value in (old_point, new_point)]
        assert await fresh.credit(*restored)
    assert fresh.checkpoints.load(old_point.key()) == old_result
    # Dropping the authenticated new profile never lets its completed native
    # facts be borrowed under the original legacy boot alone.
    absent = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
    with pytest.raises(ValueError, match="not independently selected"):
        await source(absent).replay(new_point.key())


async def test_native_allocation_export_repairs_partial_delivery_without_replay(
    preparation_case, tmp_path, monkeypatch, caplog
):
    from umi import competition_reward_preparation as preparation_module
    from umi.competition_reward_files import StandingRewardFiles

    p = preparation_case
    files = StandingRewardFiles(
        tmp_path / "compact-allocation-export",
        maximum_package_bytes=1024**2,
        maximum_witness_bytes=1024**2,
    )
    attempts = []

    def interrupted(allocation):
        attempts.append(digest(allocation))
        if len(attempts) == 1:
            raise OSError("interrupted compact export")
        files.retain_allocation(allocation)

    owner = p.reopen(allocation_sink=interrupted)
    observations = await p.observations()
    with caplog.at_level("INFO", logger="umi.competition.progress"):
        with pytest.raises(OSError, match="interrupted compact export"):
            await owner.prepare(p.package, **replay_args(observations))

        def no_replay(*args, **kwargs):
            pytest.fail("compact export retry repeated completed native package replay")

        with monkeypatch.context() as completed_native:
            completed_native.setattr(
                preparation_module, "_replay_detached_reward_package", no_replay
            )
            prepared = await owner.prepare(p.package, **replay_args(observations))
            assert files.allocation(digest(prepared.allocation)) == prepared.allocation
            path = files.root / "allocations" / (digest(prepared.allocation) + ".json")
            identity = path.stat()
            assert await owner.prepare(p.package, **replay_args(observations)) is prepared
            # An unchanged delivery can be read during retry, updating atime.
            # Its inode, ownership, size and mutation timestamps must remain.
            fields = (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            unchanged = path.stat()
            assert tuple(getattr(unchanged, name) for name in fields) == tuple(
                getattr(identity, name) for name in fields
            )
            # Repair the delivery copy, preserving completed native verification.
            path.unlink()
            assert await owner.prepare(p.package, **replay_args(observations)) is prepared
            assert files.allocation(digest(prepared.allocation)) == prepared.allocation
    assert "reward_allocation_export" in caplog.text
    assert digest(prepared.allocation) == p.active.decision.activation.allocation_sha256


async def test_native_quality_publication_progress_counts_durable_actions(
    recurring_settlement_case, monkeypatch
):
    from collections import OrderedDict
    from pathlib import Path

    from umi import competition_cohort_public_progress as public
    from umi import competition_cohort_settlement_delivery as delivery

    monkeypatch.setattr(public.PUBLIC_COHORT_PROGRESS, "entries", OrderedDict())
    h = recurring_settlement_case
    node = await h.start("Dave")
    original = delivery.publish_private_model
    events = []
    fail = [True]
    record = public.PUBLIC_COHORT_PROGRESS.record

    def observed(kind, body):
        if kind == "work" and body.get("stage") == "quality_vote_publication":
            events.append(dict(body))
        return record(kind, body)

    def publish(path, value, **kwargs):
        if "quality" in Path(path).parts and fail[0]:
            fail[0] = False
            raise OSError("interrupted original vote delivery")
        return original(path, value, **kwargs)

    monkeypatch.setattr(public.PUBLIC_COHORT_PROGRESS, "record", observed)
    monkeypatch.setattr(delivery, "publish_private_model", publish)
    with pytest.raises(OSError, match="interrupted original vote delivery"):
        await node.tick()
    assert events and all(e["completed"] == 0 for e in events)
    assert await node.tick() == "reviewing"
    completed = [e for e in events if e["state"] == "completed"][-1]
    count = len(tuple(Path(node.config.exchange_outbox).glob("quality/**/*.json")))
    assert completed["completed"] == completed["total"] == count > 0
    prior_epoch = node.public_progress.epoch
    node.public_progress.publish()
    node = await h.start("Dave")
    assert node.public_progress.epoch != prior_epoch
    assert node.public_progress.snapshot()["percent"] is None
    assert await node.tick() == "reviewing"
    assert max(h.calls.values()) == 1  # Native signed votes were recovered, not signed twice.
    completed = [e for e in events if e["state"] == "completed"][-1]
    assert completed["completed"] == completed["total"] == count


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_completed_native_interval_credit_restores_with_shared_dependency_refresh(
    complete_preparation_case, tmp_path, monkeypatch
):
    from umi.competition_reward_coverage_credits import validate_native_credit
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_opportunity import opportunity_rule

    h = complete_preparation_case
    p, c = h.package_case, h.c
    selected = opportunity_rule(p.manifest, c.series, c.reader.policy)
    root = tmp_path / "native-interval-credit"
    owner = StandingRewardPreparation(
        c.reader, p.store, p.manifest, maximum_promotion_bytes=1_000_000
    )

    def source(journal):
        return NativeRewardCoverageSource(
            provider=h.item.provider,
            journal=journal,
            history=h.reader,
            preparation=owner,
            package=p.package,
            decisions=c.source,
            profile=h.item.profile,
            maximum_history_blocks=4096,
        )

    journal = RewardCoverageJournal(root, selected, expected_rule_sha256=digest(selected))
    native = source(journal)

    async def capture(height):
        for _ in range(100):
            try:
                return await native.capture(h.validator_hotkey, height)
            except CoverageHistoryPending:
                pass
        pytest.fail("native fixture failed to converge")

    left, right = await capture(h.end - 1), await capture(h.end)
    await journal.retain_endpoint(left)
    await journal.retain_endpoint(right)
    # First adoption starts with original native endpoints and no interval
    # credit ledger. It still refreshes the common model group once, while
    # independently restoring exact history/runtime/source for each endpoint.
    from umi import competition_reward_coverage_models as model_checks
    from umi.competition_reward_coverage_intervals import coverage_point

    adoption_journal = RewardCoverageJournal(root, selected, expected_rule_sha256=digest(selected))
    adoption = source(adoption_journal)
    model_restore = model_checks.restore_coverage_model_dependencies
    history_restore = adoption._history
    model_calls, history_calls = [], []

    async def count_model(*args, **kwargs):
        model_calls.append(1)
        return await model_restore(*args, **kwargs)

    async def count_history(height):
        history_calls.append(height)
        return await history_restore(height)

    monkeypatch.setattr(model_checks, "restore_coverage_model_dependencies", count_model)
    monkeypatch.setattr(adoption, "_history", count_history)
    for native_endpoint in (left, right):
        original_point = coverage_point(native_endpoint, selected)
        restored_endpoint = await adoption.replay(original_point.key())
        assert coverage_point(restored_endpoint, selected) == original_point
    assert model_calls == [1]
    assert history_calls == [h.end - 1, h.end]
    interval = await journal.credit(left, right)
    assert interval is not None
    # Reopen the native owner. The complete current endpoint issuer/authority
    # path is still used once for the identical group; raw interval hints cannot
    # skip that independently owned refresh.
    fresh = RewardCoverageJournal(root, selected, expected_rule_sha256=digest(selected))
    restarted = source(fresh)
    replay = restarted.replay
    calls = []

    async def counted(key):
        calls.append(key)
        return await replay(key)

    monkeypatch.setattr(restarted, "replay", counted)
    restored = await restarted.restore_credit(interval.key())
    assert validate_native_credit(restored, fresh) == (interval, h.end)
    assert len(calls) == 1
    assert (
        await fresh.verified_ms(
            activation_sha256=interval.activation_sha256, validator_hotkey=h.validator_hotkey
        )
        == interval.credited_ms
    )
    assert await restarted.restore_credit(interval.key()) == restored
    assert len(calls) == 1
    # An explicit stopped-owner repair restores both original endpoint
    # verdicts and interval arithmetic. It does not recreate any native proof.
    with fresh.journal.transaction() as db:
        db.execute("DELETE FROM coverage_credit_index WHERE id=?", (interval.key(),))
    with pytest.raises(ValueError):
        await restarted.restore_credit(interval.key())
    repaired = await restarted.repair_credit(
        interval.key(), reason="restore selected credit metadata"
    )
    assert repaired["original_interval_unchanged"]
    repaired_native = await restarted.restore_credit(interval.key())
    assert validate_native_credit(repaired_native, fresh) == (interval, h.end)
    from umi.competition_reward_opportunity_review import (
        prepare_opportunity_certificate,
        review_opportunity_certificate,
    )

    terms = dict(
        manifest=p.manifest,
        series=c.series,
        policy=h.item.policy,
        activation=c.active.decision.activation,
    )
    certificate = await prepare_opportunity_certificate(fresh, **terms)

    async def forbidden_replay(_):
        pytest.fail("exact native interval credit must not replay both endpoints again")

    checked = await review_opportunity_certificate(
        canonical_json_bytes(certificate),
        expected_sha256=digest(certificate),
        journal=fresh,
        witness_source=lambda sha: canonical_json_bytes(
            fresh.journal.get("opportunity_witness", sha)
        ),
        review_endpoint=forbidden_replay,
        review_interval=restarted.restore_credit,
        **terms,
    )
    assert checked.certificate == certificate and not checked.chain_submission_authorized
