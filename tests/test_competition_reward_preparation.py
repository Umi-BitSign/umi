"""Replay/projection lifecycle with native packages, signatures and state readers.

Lifecycle fault tests substitute the complete-history selection boundary. The
combined test uses native history, package replay and registration projection.
RPC/finality/trie/SCALE and miner video/inference are synthetic ports; installed
signing and chain submission are not qualified here.
"""

import asyncio
import hashlib
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
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_closed as service_closed
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import service_quality
from .test_competition_cohort_service_grants import service_quality_inputs as service_quality_inputs
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_competition_model_burn import burn_policy
from .test_competition_reward_control import commitment
from .test_competition_reward_control_archive import make_historical
from .test_competition_reward_decisions import signed
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
    pytest.mark.parametrize("service_catalog_inputs", [True], indirect=True),
]


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
    replay = preparation.replay_reward_package
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

    monkeypatch.setattr(preparation, "replay_reward_package", slow)
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
    replay, calls = preparation.replay_reward_package, []

    def delayed(*args, **kwargs):
        calls.append(1)
        started.set()
        assert release.wait(30)
        return replay(*args, **kwargs)

    monkeypatch.setattr(preparation, "replay_reward_package", delayed)
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
    replay, calls = preparation.replay_reward_package, []

    def interrupted(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("promotion archive temporarily unavailable")
        return replay(*args, **kwargs)

    monkeypatch.setattr(preparation, "replay_reward_package", interrupted)
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
async def complete_preparation_case(preparation_case, tmp_path, monkeypatch):
    p = preparation_case
    item = p.item
    validator_hotkey = item.hotkey
    series = p.reader.series
    await p.provider.aclose()
    item.hotkey = series.control_hotkey
    item.spec = ("Commitments", "CommitmentOf", (78, item.hotkey))
    first = series.recovery.authority.issued_at_block
    activation_block = p.package.inputs.history.transitions[-1].transition.observed_at_block + 1
    end = (
        activation_block
        + series.maximum_proof_lag_blocks
        + series.maximum_transaction_lifetime_blocks
    )
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
    h.reader = h.new_reader(maximum_bytes=64 * 1024**2)
    h.package_case, h.validator_hotkey = p, validator_hotkey
    try:
        yield h
    finally:
        await item.provider.aclose()


async def test_complete_native_history_package_and_projection_restart_without_coordinator(
    complete_preparation_case,
):
    h = complete_preparation_case
    p, c = h.package_case, h.c

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
    ready, result = await prepare(owner(), captured)
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
    restored, again = await prepare(owner(), replayed)
    assert restored is not ready and restored.allocation == ready.allocation
    assert again.projection == result.projection
    assert again.current.selection == result.current.selection
    assert h.body_requests == list(range(h.old.height, h.end + 1))
