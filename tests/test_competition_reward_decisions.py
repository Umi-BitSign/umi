from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_recovery import (
    PHASES,
    PhaseTarget,
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    StandingCohortRecoveryAuthority,
)
from umi.competition_reward_decisions import (
    RewardActivation,
    RewardControlDecision,
    SignedRewardControlDecision,
    StandingRewardControlReader,
    StandingRewardSeries,
    StandingRewardSeriesPredecessor,
    verify_reward_decisions,
)
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_reward_control import chain as chain
from .test_competition_reward_control import chain_config as chain_config
from .test_competition_reward_control import commitment
from .test_competition_reward_control import control as control
from .test_competition_reward_control import policy as policy
from .test_open_competition import wallet


def signatures(body, names=("Charlie", "Dave")):
    return tuple(
        sorted((sign_object(body, wallet(n)) for n in names), key=lambda s: identity(s.hotkey))
    )


def signed(body, names=("Charlie", "Dave")):
    return SignedRewardControlDecision(decision=body, signatures=signatures(body, names))


def successor_series(series):
    first = series.cohorts[-1].sequence + 1
    plans = tuple(
        series.cohorts[-1].model_copy(
            update={"sequence": sequence, "suite_sha256": f"{sequence:02x}" * 32}
        )
        for sequence in (first, first + 1)
    )
    authority = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=series.policy_sha256,
        cohort_sha256s=tuple(sorted(digest(plan) for plan in plans)),
        issued_at_block=150,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    recovery = SignedCohortRecoveryAuthority(authority=authority, signatures=signatures(authority))
    predecessor = StandingRewardSeriesPredecessor(
        schema="umi-standing-reward-series-predecessor/1",
        series_sha256=digest(series),
        policy_sha256=series.policy_sha256,
        manifest_sha256=series.manifest_sha256,
        recovery_sha256=digest(series.recovery),
        cohort_sha256=digest(series.cohorts[-1]),
        cohort_sequence=series.cohorts[-1].sequence,
        control_hotkey=series.control_hotkey,
        decision_sha256="d1" * 32,
        activation_sha256="d2" * 32,
        decision_committed_at_block=149,
    )
    candidate = series.model_copy(
        update={
            "schema_": "umi-standing-reward-series/2",
            "recovery": recovery,
            "cohorts": plans,
            "predecessor": predecessor,
        }
    )
    return StandingRewardSeries.model_validate_json(canonical_json_bytes(candidate))


@pytest.fixture
def series_case(control, tmp_path):
    item = control
    plans = tuple(
        RecoverableCohortPlan(
            schema="umi-recoverable-cohort-plan/1",
            policy_sha256=digest(item.policy),
            launch_sha256="a3" * 32,
            sequence=n,
            suite_sha256=f"{n:02x}" * 32,
            not_before_block=200,
            initial_targets=tuple(
                PhaseTarget(phase=p, target_block=300 + 90 * i) for i, p in enumerate(PHASES)
            ),
        )
        for n in range(5, 11)
    )
    authority = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=digest(item.policy),
        cohort_sha256s=tuple(sorted(digest(p) for p in plans)),
        issued_at_block=150,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    recovery = SignedCohortRecoveryAuthority(authority=authority, signatures=signatures(authority))
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(item.policy),
        policy_epoch=1,
        manifest_sha256="ab" * 32,
        control_hotkey=item.hotkey,
        recovery=recovery,
        cohorts=plans,
        validators=tuple(
            sorted(
                (wallet("Alice").hotkey.ss58_address, wallet("Bob").hotkey.ss58_address),
                key=identity,
            )
        ),
        maximum_proof_lag_blocks=32,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )

    def reopen(**overrides):
        args = dict(
            expected_series_sha256=digest(series),
            expected_chain_config_sha256=digest(item.config),
            maximum_bytes=8 * 1024**2,
        )
        args.update(overrides)
        return StandingRewardControlReader(tmp_path / "reader", series, item.policy, **args)

    c = SimpleNamespace(
        control=item, series=series, reopen=reopen, reader=reopen(), objects={}, fetches=[]
    )

    def decision(parent=None, cohort=None, *, kind=None, observed=160, **changes):
        body = RewardControlDecision(
            schema="umi-reward-control-decision/1",
            series_sha256=digest(series),
            sequence=0 if parent is None else parent.decision.sequence + 1,
            predecessor_sha256=None if parent is None else digest(parent.decision),
            kind=kind or ("admit_series" if parent is None else "activate"),
            observed_at_block=observed,
            activation=None
            if cohort is None
            else RewardActivation(
                cohort_sha256=digest(plans[cohort - 5]),
                allocation_sha256=f"{cohort:02x}" * 32,
                package_sha256=f"{cohort + 10:02x}" * 32,
                recovery_tip_sha256=f"{cohort + 20:02x}" * 32,
                prior_opportunity_sha256=f"{cohort + 30:02x}" * 32,
            ),
        ).model_copy(update=changes)
        result = signed(body)
        c.objects[digest(body)] = canonical_json_bytes(result)
        return result

    def source(key):
        c.fetches.append(key)
        return c.objects[key]

    async def observe(tip, *, block=160, head=None):
        if head is not None:
            item.finality.ref = replace(
                item.finality.ref,
                block_number=head,
                block_hash="0x" + hashlib.sha256(str(head).encode()).hexdigest(),
            )
        item.rpc.values[item.spec] = commitment(digest(tip.decision), block)
        return await item.provider.collect_control(item.hotkey)

    c.decision, c.source, c.observe = decision, source, observe
    c.genesis = decision()
    return c


async def test_restart_and_long_outage_use_retained_history_and_new_owned_proof(series_case):
    c = series_case
    first = c.reader.select(await c.observe(c.genesis), c.source)
    assert first.state == "admitted" and not first.chain_submission_authorized
    height = c.control.finality.ref.block_number
    active = c.decision(c.genesis, 5, observed=height - 1000)
    decision = c.reader.select(await c.observe(active, block=height - 900), c.source)
    assert decision.state == "selected" and decision.activation.cohort_sha256 == digest(
        c.series.cohorts[0]
    )
    assert not decision.chain_submission_authorized
    saved = (c.reader.journal.path.read_bytes(), len(c.fetches))
    c.reader = c.reopen()

    def offline(_):
        raise ConnectionError("coordinator is unavailable")

    late = c.reader.select(
        await c.observe(active, block=height - 900, head=height + 1_000_000), offline
    )
    assert (
        late.activation == decision.activation and late.decision_sha256 == decision.decision_sha256
    )
    assert c.reader.journal.keys("reward_control_decision") == ["0000", "0001"]
    assert len(c.fetches) == saved[1]


async def test_fence_completes_without_another_signature_or_publication(series_case):
    c = series_case
    head = c.control.finality.ref.block_number
    active = c.decision(c.genesis, 5, observed=head - 159)
    early = c.reader.select(await c.observe(active, block=head - 159), c.source)
    assert early.state == "draining" and early.effective_at_block == head + 1
    c.reader = c.reopen()
    ready = c.reader.select(
        await c.observe(active, block=head - 159, head=head + 1), lambda _: None
    )
    assert ready.state == "selected" and ready.decision_sha256 == early.decision_sha256


async def test_all_six_cohorts_are_selected_in_order_after_arbitrary_delays(series_case):
    c = series_case
    tip = c.genesis
    head = c.control.finality.ref.block_number
    for n in range(5, 11):
        tip = c.decision(tip, n, observed=head)
        head += 1_000_000
        selected = c.reader.select(await c.observe(tip, block=head - 900, head=head), c.source)
        assert selected.state == "selected"
        assert selected.activation.cohort_sha256 == digest(c.series.cohorts[n - 5])
        assert not selected.chain_submission_authorized
        c.reader = c.reopen()
    assert len(c.reader.journal.keys("reward_control_decision")) == 7


async def test_unknown_current_decision_cannot_use_cached_allocation(series_case):
    c = series_case
    head = c.control.finality.ref.block_number
    a = c.decision(c.genesis, 5, observed=head - 1000)
    c.reader.select(await c.observe(a, block=head - 900), c.source)
    b = c.decision(a, 6, observed=head - 800)
    obs = await c.observe(b, block=head - 700)

    def unavailable(_):
        raise FileNotFoundError("decision unavailable")

    with pytest.raises(FileNotFoundError):
        c.reader.select(obs, unavailable)
    assert len(c.reader.journal.keys("reward_control_decision")) == 2
    assert c.reader.select(obs, c.source).activation.cohort_sha256 == digest(c.series.cohorts[1])


async def test_revocation_survives_restart_and_prevents_continuation(series_case):
    c = series_case
    head = c.control.finality.ref.block_number
    a = c.decision(c.genesis, 5, observed=head - 1000)
    revoke = c.decision(a, kind="revoke", observed=head - 500)
    value = c.reader.select(await c.observe(revoke, block=head - 400), c.source)
    assert (
        value.state == "revoked" and value.activation is None and value.effective_at_block is None
    )
    c.reader = c.reopen()
    assert (
        c.reader.select(await c.observe(revoke, block=head - 400), lambda _: None).state
        == "revoked"
    )
    after = c.decision(revoke, 6, observed=head - 300)
    with pytest.raises(ValueError, match="revoked"):
        c.reader.select(await c.observe(after, block=head - 200), c.source)


@pytest.mark.parametrize(
    "bad", ["rollback", "fork", "skip", "repeat", "wrong_series", "wrong_parent"]
)
async def test_conflicting_or_out_of_order_history_is_rejected(series_case, bad):
    c = series_case
    head = c.control.finality.ref.block_number
    a = c.decision(c.genesis, 5, observed=head - 1000)
    c.reader.select(await c.observe(a, block=head - 900), c.source)
    if bad == "rollback":
        tip = c.genesis
    elif bad == "fork":
        tip = c.decision(c.genesis, 5, observed=head - 999)
    elif bad == "skip":
        tip = c.decision(a, 7, observed=head - 800)
    elif bad == "repeat":
        tip = c.decision(a, 5, observed=head - 800)
    elif bad == "wrong_series":
        tip = c.decision(a, 6, observed=head - 800, series_sha256="ff" * 32)
    else:
        tip = c.decision(a, 6, observed=head - 800, predecessor_sha256=digest(c.genesis.decision))
    with pytest.raises(ValueError):
        c.reader.select(
            await c.observe(tip, block=160 if bad == "rollback" else head - 700), c.source
        )
    assert len(c.reader.journal.keys("reward_control_decision")) == 2


@pytest.mark.parametrize(
    "bad",
    [
        "signature",
        "partial_quorum",
        "unauthorized",
        "duplicate",
        "wrong_hash",
        "noncanonical",
        "oversize",
        "unsigned_fields",
        "malformed",
    ],
)
async def test_untrusted_source_is_authenticated_before_retention(series_case, bad):
    c = series_case
    key = digest(c.genesis.decision)
    raw = c.objects[key]
    if bad == "signature":
        raw = raw.replace(b'"signature":"0x', b'"signature":"0x00', 1)
        if raw == c.objects[key]:
            item = c.genesis.model_copy(
                update={
                    "signatures": (
                        c.genesis.signatures[0].model_copy(update={"signature": "00" * 64}),
                        c.genesis.signatures[1],
                    )
                }
            )
            raw = canonical_json_bytes(item)
    elif bad == "partial_quorum":
        raw = canonical_json_bytes(signed(c.genesis.decision, ("Charlie",)))
    elif bad == "unauthorized":
        raw = canonical_json_bytes(signed(c.genesis.decision, ("Alice", "Bob")))
    elif bad == "duplicate":
        raw = canonical_json_bytes(
            c.genesis.model_copy(update={"signatures": c.genesis.signatures[:1] * 2})
        )
    elif bad == "wrong_hash":
        raw = canonical_json_bytes(c.decision(observed=161))
    elif bad == "noncanonical":
        raw = b" " + raw
    elif bad == "oversize":
        raw = b" " * 131073
    elif bad == "unsigned_fields":
        raw = canonical_json_bytes(
            c.genesis.model_copy(
                update={
                    "decision": c.genesis.decision.model_copy(update={"observed_at_block": 161})
                }
            )
        )
    else:
        raw = b"{}"
    with pytest.raises((ValueError, RuntimeError)):
        c.reader.select(await c.observe(c.genesis), lambda _: raw)
    assert c.reader.journal.keys("reward_control_decision") == []


@pytest.mark.parametrize("bad", ["series", "policy", "manifest", "cohort_order", "epoch"])
def test_independent_authority_binding_cannot_change(series_case, bad):
    c = series_case
    if bad == "series":
        with pytest.raises(ValueError):
            c.reopen(expected_series_sha256="ff" * 32)
        return
    series = c.series
    if bad == "policy":
        series = series.model_copy(update={"policy_sha256": "ff" * 32})
    elif bad == "manifest":
        series = series.model_copy(update={"manifest_sha256": "ff" * 32})
    elif bad == "epoch":
        series = series.model_copy(update={"policy_epoch": 2})
    else:
        series = series.model_copy(update={"cohorts": tuple(reversed(series.cohorts))})
    with pytest.raises(ValueError):
        StandingRewardControlReader(
            c.reader.journal.root,
            series,
            c.control.policy,
            expected_series_sha256=digest(c.series),
            expected_chain_config_sha256=digest(c.control.config),
            maximum_bytes=8 * 1024**2,
        )


async def test_expired_or_edited_proof_and_absence_cannot_select_old_history(
    series_case, monkeypatch
):
    c = series_case
    obs = await c.observe(c.genesis)
    c.reader.select(obs, c.source)
    with pytest.raises(ValueError):
        c.reader.select(replace(obs, control_sha256="bb" * 32), c.source)
    del c.control.rpc.values[c.control.spec]
    absent = await c.control.provider.collect_control(c.control.hotkey)
    with pytest.raises(ValueError, match="absent"):
        c.reader.select(absent, c.source)
    monkeypatch.setattr(
        "umi.competition_reward_control.time.monotonic_ns", lambda: obs.expires_monotonic_ns + 1
    )
    with pytest.raises(ValueError, match="proof adapter"):
        c.reader.select(obs, c.source)


async def test_proof_expiring_during_signature_replay_does_not_return_selection(
    series_case, monkeypatch
):
    c = series_case
    obs = await c.observe(c.genesis)

    def source(key):
        monkeypatch.setattr(
            "umi.competition_reward_control.time.monotonic_ns", lambda: obs.expires_monotonic_ns + 1
        )
        return c.source(key)

    with pytest.raises(ValueError):
        c.reader.select(obs, source)
    assert c.reader.journal.keys("reward_control_decision") == []


@pytest.mark.parametrize("bad", ["before_authority", "late_genesis", "uncommitted_observation"])
async def test_decisions_respect_their_admission_and_observation_bounds(series_case, bad):
    c = series_case
    tip = c.decision(observed=149 if bad == "before_authority" else 160)
    block = (
        c.control.policy.valid_through_block + 1
        if bad == "late_genesis"
        else 159
        if bad == "uncommitted_observation"
        else 160
    )
    with pytest.raises(ValueError):
        c.reader.select(await c.observe(tip, block=block), c.source)
    assert c.reader.journal.keys("reward_control_decision") == []


async def test_regressed_finality_does_not_partially_record_new_history(series_case):
    c = series_case
    head = c.control.finality.ref.block_number
    c.reader.select(await c.observe(c.genesis), c.source)
    active = c.decision(c.genesis, 5, observed=head - 1000)
    c.reader.select(await c.observe(active, block=head - 900, head=head + 100), c.source)
    next_ = c.decision(active, 6, observed=head - 800)
    with pytest.raises(ValueError, match="regressed"):
        c.reader.select(await c.observe(next_, block=head - 700, head=head + 99), c.source)
    assert len(c.reader.journal.keys("reward_control_decision")) == 2


async def test_lost_acknowledgement_retries_immutable_decisions_after_restart(
    series_case, monkeypatch
):
    c = series_case
    obs = await c.observe(c.genesis)
    original = c.reader.journal.put_many

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise ConnectionError("acknowledgement lost")

    monkeypatch.setattr(c.reader.journal, "put_many", lost)
    with pytest.raises(ConnectionError):
        c.reader.select(obs, c.source)
    c.reader = c.reopen()
    assert c.reader.select(obs, lambda _: None).state == "admitted"
    assert c.reader.journal.keys("reward_control_decision") == ["0000"]


def test_signature_verification_alone_never_claims_chain_or_reward_admission(series_case):
    c = series_case
    assert verify_reward_decisions(c.series, c.control.policy, (c.genesis,)) == (c.genesis,)
    with pytest.raises(ValueError):
        verify_reward_decisions(c.series, c.control.policy, ())


def test_initial_series_serialization_does_not_gain_a_successor_field(series_case):
    raw = canonical_json_bytes(series_case.series)
    assert b'"predecessor"' not in raw
    assert StandingRewardSeries.model_validate_json(raw) == series_case.series


@pytest.mark.parametrize(
    "change",
    [
        {"schema_": "umi-standing-reward-series/1"},
        {"predecessor": None},
        {"control_hotkey": wallet("Alice").hotkey.ss58_address},
    ],
)
def test_successor_series_requires_its_complete_exact_boundary(series_case, change):
    successor = successor_series(series_case.series)
    with pytest.raises(ValueError):
        StandingRewardSeries.model_validate_json(
            canonical_json_bytes(successor.model_copy(update=change))
        )


async def test_successor_reader_stops_at_signed_predecessor_boundary(series_case, tmp_path):
    c = series_case
    successor = successor_series(c.series)
    reader = StandingRewardControlReader(
        tmp_path / "successor-reader",
        successor,
        c.control.policy,
        expected_series_sha256=digest(successor),
        expected_chain_config_sha256=digest(c.control.config),
        maximum_bytes=8 * 1024**2,
    )
    body = RewardControlDecision(
        schema="umi-reward-control-decision/2",
        series_sha256=digest(successor),
        sequence=0,
        predecessor_sha256=successor.predecessor.decision_sha256,
        kind="admit_series",
        observed_at_block=160,
        activation=None,
    )
    item = signed(body)
    source_calls = []

    def source(key):
        source_calls.append(key)
        if key == successor.predecessor.decision_sha256:
            raise AssertionError("successor reader fetched across its signed boundary")
        return canonical_json_bytes(item)

    c.control.rpc.values[c.control.spec] = commitment(digest(body), 160)
    observation = await c.control.provider.collect_control(c.control.hotkey)
    selected = reader.select(observation, source)
    assert selected.state == "admitted"
    assert source_calls == [digest(body)]
    assert reader.journal.keys("reward_control_decision") == ["0000"]


@pytest.mark.parametrize("failure", ["capacity", "locked"])
async def test_transient_storage_hold_preserves_work_and_can_retry(series_case, failure):
    c = series_case
    obs = await c.observe(c.genesis)
    if failure == "capacity":
        obs = await c.observe(c.decision(c.genesis, 5))
        original = c.reader.journal.maximum_bytes
        c.reader.journal.maximum_bytes = 1024
        with pytest.raises(ValueError):
            c.reader.select(obs, c.source)
        c.reader.journal.maximum_bytes = original
    else:
        with c.reader.journal.locked(), pytest.raises(BlockingIOError):
            c.reader.select(obs, c.source)
    assert c.reader.journal.keys("reward_control_decision") == []
    assert c.reader.select(obs, c.source).state == (
        "selected" if failure == "capacity" else "admitted"
    )


async def test_recommit_cannot_shorten_the_transition_fence(series_case):
    c = series_case
    head = c.control.finality.ref.block_number
    a = c.decision(c.genesis, 5, observed=head - 1000)
    original = c.reader.select(await c.observe(a, block=head - 900), c.source)
    c.reader = c.reopen()
    republished = c.reader.select(await c.observe(a, block=head), lambda _: None)
    assert original.state == "selected"
    assert republished.state == "draining" and republished.effective_at_block == head + 160
    assert len(c.reader.journal.keys("reward_control_decision")) == 2


async def test_different_valid_quorum_bytes_for_same_body_reuse_the_first_record(series_case):
    c = series_case
    obs = await c.observe(c.genesis)
    c.reader.select(obs, c.source)
    prior = c.reader.journal.get("reward_control_decision", "0000")
    changed = canonical_json_bytes(signed(c.genesis.decision))
    # Local authenticated history owns retries; remote certificate serialization
    # is irrelevant when its body identity is already retained.
    assert c.reader.select(obs, lambda _: changed).state == "admitted"
    assert c.reader.journal.get("reward_control_decision", "0000") == prior


@pytest.mark.parametrize(
    "change",
    [
        {"maximum_proof_lag_blocks": 0},
        {"maximum_transaction_lifetime_blocks": 0},
        {"netuid": 79},
        {"genesis_hash": "ff" * 32},
        {"lifetime": "until_deadline"},
    ],
)
def test_invalid_standing_series_bounds_and_chain_are_rejected(series_case, change):
    c = series_case
    with pytest.raises(ValueError):
        StandingRewardSeries.model_validate_json(
            canonical_json_bytes(c.series.model_copy(update=change))
        )


async def test_host_and_rpc_configuration_can_change_without_losing_signed_history(
    series_case, tmp_path
):
    c = series_case
    old = await c.observe(c.genesis)
    c.reader.select(old, c.source)
    destination = tmp_path / "migrated-reader"
    shutil.copytree(c.reader.journal.root, destination)
    await c.control.provider.aclose()
    c.control.config = c.control.config.model_copy(
        update={
            "state_directory": str(tmp_path / "migrated-proof-state"),
            "rpc_url": "wss://different.example.org",
        }
    )
    c.control.provider = c.control.reopen()
    c.reader = StandingRewardControlReader(
        destination,
        c.series,
        c.control.policy,
        expected_series_sha256=digest(c.series),
        expected_chain_config_sha256=digest(c.control.config),
        maximum_bytes=8 * 1024**2,
    )
    with pytest.raises(ValueError, match="proof adapter"):
        c.reader.select(old, c.source)
    fresh = await c.observe(c.genesis)
    assert c.reader.select(fresh, lambda _: None).state == "admitted"
    assert c.reader.journal.keys("reward_control_decision") == ["0000"]
