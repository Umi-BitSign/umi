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
    replay = preparation.replay_reward_package
    blocks = []

    def checked(*a, **kw):
        blocks.append(kw["current_block"])
        return replay(*a, **kw)

    monkeypatch.setattr(preparation, "replay_reward_package", checked)
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
async def complete_preparation_case(preparation_case, tmp_path, monkeypatch, request):
    p = preparation_case
    item = p.item
    validator_hotkey = item.hotkey
    series = p.reader.series
    await p.provider.aclose()
    await configure_eligibility(item, monkeypatch, tmp_path)
    await item.provider.aclose()
    variant = getattr(request, "param", "matching")
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
                        minimum_validator_ms=12000,
                    ),
                }
            )
        )
        series = series.model_copy(update={"manifest_sha256": digest(p.manifest)})
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
    variant = getattr(request, "param", "matching")
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
    h.reader = h.new_reader(maximum_bytes=64 * 1024**2)
    h.package_case, h.validator_hotkey, h.variant = p, validator_hotkey, variant
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
    files_before = tuple(files.root.rglob("*.json"))
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
        assert tuple(files.root.rglob("*.json")) == files_before


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


@pytest.mark.parametrize("successor", [False, True])
async def test_offer_discovery_waits_for_bound_settlement_and_prior_opportunity(
    native_package, tmp_path, successor
):
    """Discovery only: later-slot authority and interval claims are synthetic.

    The first-activation integration above separately performs native review.
    An emitted offer carries no signature or chain permission.
    """
    from umi.competition_cohort_reward_package import publish_reward_package
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_service import CoverageCompletion
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
    if successor:
        prior = RewardActivation(
            cohort_sha256=digest(plans[0]),
            allocation_sha256="44" * 32,
            package_sha256="55" * 32,
            recovery_tip_sha256="66" * 32,
            prior_opportunity_sha256=digest(handoff),
        )
        prefix += (
            signed(
                RewardControlDecision(
                    schema="umi-reward-control-decision/1",
                    series_sha256=digest(series),
                    sequence=1,
                    predecessor_sha256=digest(prefix[-1].decision),
                    kind="activate",
                    observed_at_block=body.issued_at_block + 1,
                    activation=prior,
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
    )
    cohort = digest(plans[-1])
    with pytest.raises(ValueError, match="next admitted"):
        offers("ff" * 32, prefix)
    assert offers(cohort, prefix) is None
    path = settlements / (cohort + ".json")
    publish_reward_package(path, package)
    if successor:
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
        coverage.journal.put("coverage_completion", prior.cohort_sha256, completion)
        with pytest.raises(FileNotFoundError):
            offers(cohort, prefix)
        files.retain_completion(certificate, lambda _: canonical_json_bytes(witness))
    offer = offers(cohort, prefix)
    assert offer.package_sha256 == digest(package)
    assert offer.prior_opportunity_sha256 == (digest(certificate) if successor else digest(handoff))
    assert files.package(offer.package_sha256) == package
    assert offers(cohort, prefix) == offer
    # A conflicting or misrouted settlement cannot change a proposal silently.
    path.write_bytes(canonical_json_bytes(package.model_copy(update={"policy_sha256": "ee" * 32})))
    with pytest.raises(ValueError, match="approved cohort"):
        offers(cohort, prefix)


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
    control = h.reader._tip.slot
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
    with pytest.raises(ValueError, match="approved legacy handoff"):
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
    control = h.reader._tip.slot
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
    "complete_preparation_case",
    [
        "matching",
        "sparse_zeros",
        "raw_row",
        "missing_recipient",
        "extra_recipient",
        "permit_missing",
    ],
    indirect=True,
)
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
    archived_control = h.reader._tip.slot
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
            return db.execute("SELECT COUNT(*),SUM(LENGTH(body)) FROM records").fetchone()

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

    def interrupt_before_commit(records):
        def fail(db):
            assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] > 0
            raise OSError("simulated interrupted commit")

        original_put(records, index=fail)

    with monkeypatch.context() as m:
        m.setattr(journal.journal, "put_many", interrupt_before_commit)
        with pytest.raises(OSError, match="interrupted commit"):
            await journal.credit(left, right)
    assert counts(journal) == (0, None)
    assert await journal.verified_ms(**query) == 0

    def lost_acknowledgement(records):
        original_put(records)
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

    def slow_commit(records):
        entered.set()
        assert release.wait(20)
        original_put(records)

    with monkeypatch.context() as m:
        m.setattr(cancelled.journal, "put_many", slow_commit)
        pending = asyncio.create_task(cancelled.credit(*restored))
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
    assert await cancelled.credit(*restored) == result
    assert await cancelled.verified_ms(**query) == 12000

    # Corruption is a hold, not permission to replace evidence or reset the
    # accounting journal. This operates only on the isolated fixture database.
    with restarted.journal.transaction() as db:
        sha, raw = db.execute(
            "SELECT id,body FROM records WHERE kind='coverage_object' LIMIT 1"
        ).fetchone()
        db.execute("DELETE FROM records WHERE kind='coverage_object' AND id=?", (sha,))
    damaged = counts(restarted)
    with pytest.raises(ValueError, match="evidence object is missing"):
        await restarted.credit(*restored)
    assert counts(restarted) == damaged
    with restarted.journal.transaction() as db:
        db.execute("INSERT INTO records VALUES ('coverage_object',?,?)", (sha, raw))
    assert counts(restarted) == committed
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
        # A retained claim is not enough after a crash, even when its digest
        # is right. The original proofs must be reviewed again.
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
async def test_native_historical_coverage_capture(complete_preparation_case):
    from umi.competition_reward_coverage import review_reward_coverage
    from umi.competition_reward_coverage_capture import capture_reward_eligibility

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
        captured = await capture_reward_eligibility(
            h.item.provider,
            control,
            validator_hotkey=h.validator_hotkey,
            control_hotkey=c.series.control_hotkey,
            profile=h.item.profile,
            expected_runtime_profile_sha256=digest(h.item.profile),
        )
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
    from umi.competition_reward_coverage_source import NativeRewardCoverageSource
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

    # A fresh process trusts neither summaries nor totals. All historical state
    # and block body RPCs are unavailable; only owned ancestry is still served.
    h.reader = await h.restart()
    h.offline_through = h.end
    c.reader = c.reopen()
    journal, source, collector = setup()
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

    async def fresh_height(_hotkey):
        # This is a discovery hint only. Native retained control/eligibility
        # proof readers establish the actual selection and every interval.
        return SimpleNamespace(snapshot=SimpleNamespace(block_number=h.end))

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
    interrupted = set()

    def lost_export_reply(kind, *args, **kwargs):
        original_write(kind, *args, **kwargs)
        if kind not in interrupted:
            interrupted.add(kind)
            raise OSError("export acknowledgement lost")

    monkeypatch.setattr(archive, "write", lost_export_reply)
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
    original = file_module.publish_private_model
    interrupted = False

    def lost_reply(path, *args, **kwargs):
        nonlocal interrupted
        original(path, *args, **kwargs)
        if path.parent.name == interrupt_after and not interrupted:
            interrupted = True
            raise OSError("publication reply lost")

    monkeypatch.setattr(file_module, "publish_private_model", lost_reply)
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
async def settlement_signing_case(native_settlement_case, tmp_path):
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


@pytest.mark.parametrize("offline_stage", ["progress", "transition"])
async def test_native_settlement_controller_resumes_original_votes_after_peer_outage(
    settlement_signing_case,
    offline_stage,
):
    """No phase-completion helper after reveal: native review/signing/controller."""
    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = settlement_signing_case
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


async def test_settlement_file_delivery_recovers_three_phases_with_independent_state(
    settlement_file_case,
):
    from umi.competition_cohort_settlement_controller import SettlementPhaseQuorumPending

    h = settlement_file_case
    controller = h.file_start()
    for phase, following in (
        ("evidence", "review"),
        ("review", "certification"),
        ("certification", "first_admission"),
    ):
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
    assert h.provider.collects == 3
    assert len(h.signatures) == 12 and set(h.signatures.values()) == {1}
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
