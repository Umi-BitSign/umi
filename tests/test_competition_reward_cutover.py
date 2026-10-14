"""Native journals/history/selection with synthetic chain and fresh nonce ports.

These fixtures never read production state. Full history is issued by the native
reader from the existing trie/header/codec fixtures; only current-control/nonce
issuance is explicitly synthetic. They do not establish an installed cutover.
"""

import json
import logging
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_control as current_module
from umi import competition_reward_control_signing as nonce_module
from umi import competition_reward_cutover as cutover
from umi.competition_cohort_recovery import SignedCohortRecoveryAuthority
from umi.competition_reward_cutover_ownership import hold_reward_cutover_owner
from umi.competition_reward_decisions import RewardActivation, RewardControlDecision
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_history import RewardControlHistoryReader
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_history as history_fixtures
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_coordinator_boot import inputs as inputs
from .test_competition_reward_cutover_runtime import components
from .test_competition_reward_decisions import signatures, signed
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import make_history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
original_chain = history_fixtures.chain
original_chain_config = history_fixtures.chain_config


@pytest.fixture
def chain_config(original_chain_config):
    return original_chain_config.model_copy(
        update={
            "minimum_finalized_block": 150,
            "finality_pin": original_chain_config.finality_pin.model_copy(
                update={"bootstrap_block_number": 149}
            ),
            "proof_rpc_fallback_urls": (
                "wss://backup-one.example.org",
                "wss://backup-two.example.org",
            ),
        }
    )


@pytest.fixture
def chain(original_chain):
    original_chain.finality.ref = replace(original_chain.finality.ref, block_number=160)
    return original_chain


@pytest.fixture
async def cutover_case(historical, config_case, monkeypatch, tmp_path, request):
    mode = getattr(request, "param", "empty")
    h, original = historical, config_case.config
    first = h.old.height
    authority = original.series.recovery.authority.model_copy(update={"issued_at_block": first})
    plans = original.series.cohorts
    if mode == "age":
        plans = tuple(p.model_copy(update={"not_before_block": first}) for p in plans)
        authority = authority.model_copy(
            update={"cohort_sha256s": tuple(sorted(digest(p) for p in plans))}
        )
    manifest = original.manifest.model_copy(
        update={
            "cohorts": tuple(
                r.model_copy(update={"cohort_sha256": digest(p)})
                for r, p in zip(original.manifest.cohorts, plans, strict=True)
            )
        }
    )
    series = original.series.model_copy(
        update={
            "recovery": SignedCohortRecoveryAuthority(
                authority=authority, signatures=signatures(authority)
            ),
            "maximum_proof_lag_blocks": 7200,
            "cohorts": plans,
            "manifest_sha256": digest(manifest),
        }
    )
    config = original.model_copy(
        update={
            "series": series,
            "manifest": manifest,
            "chain": h.item.config,
            "handoff": original.handoff.model_copy(
                update={"series_sha256": digest(series), "cohort_sha256": digest(plans[0])}
            ),
        }
    )
    config = type(config).model_validate_json(canonical_json_bytes(config))
    body = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(series),
        sequence=0,
        predecessor_sha256=None,
        kind="admit_series",
        observed_at_block=first,
        activation=None,
    )
    genesis = signed(body)
    activation = signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/1",
            series_sha256=digest(series),
            sequence=1,
            predecessor_sha256=digest(body),
            kind="activate",
            observed_at_block=first + 1,
            activation=RewardActivation(
                cohort_sha256=digest(series.cohorts[0]),
                allocation_sha256="a1" * 32,
                package_sha256="a2" * 32,
                recovery_tip_sha256="a3" * 32,
                prior_opportunity_sha256="a4" * 32,
            ),
        )
    )
    revoke = signed(
        RewardControlDecision(
            schema="umi-reward-control-decision/1",
            series_sha256=digest(series),
            sequence=2,
            predecessor_sha256=digest(activation.decision),
            kind="revoke",
            observed_at_block=first + 2,
            activation=None,
        )
    )
    writes = {height: () for height in range(first, first + 5)}
    if mode != "empty":
        writes[first] = (digest(body),)
    if mode in {"activate", "revoke", "unresolved"}:
        writes[first + 1] = (digest(activation.decision),)
    if mode == "revoke":
        writes[first + 2] = (digest(revoke.decision),)
    h.c.control_writes = writes
    if mode == "unresolved":
        h.c.cleared_blocks = {first + 3}
    h = await make_history_case(h, monkeypatch, tmp_path)
    root, reader, history, decisions, transactions = components(config)
    files = StandingRewardFiles(
        root.parent / "unused-files",
        maximum_package_bytes=1_000_000,
        maximum_witness_bytes=1_000_000,
    )
    # The config selects this exact store; all other signed inputs remain fixed.
    config = config.model_copy(update={"files_directory": str(files.root)})
    for item in (genesis, activation, revoke):
        files.retain_decision(item)
    c = SimpleNamespace(
        h=h,
        config=config,
        root=root,
        reader=reader,
        history=history,
        decisions=decisions,
        transactions=transactions,
        files=files,
        target=h.end,
        calls=[],
        genesis=genesis,
        activation=activation,
        revoke=revoke,
        cohort=digest(series.cohorts[0]),
    )

    async def state(height):
        old = await h.item.provider.capture_control_at(h.item.hotkey, height)
        async with h.item.provider._lock:
            _, runtime = await h.item.provider._review_control_runtime_locked(
                old.evidence, old.metadata
            )
        now = time.monotonic_ns()
        observation = current_module.OwnedRewardControlObservation(
            old.snapshot,
            h.item.clock.now,
            h.item.hotkey,
            old.control_sha256,
            old.committed_at_block,
            digest(config.chain),
            now,
            now + 3600 * 10**9,
            runtime,
            old.evidence,
            _issuer=current_module._ISSUER,
        )
        observation = replace(observation, _binding=current_module._binding(observation))
        result = nonce_module.RewardControlSigningState(
            observation,
            4,
            runtime,
            canonical_json_bytes({"fixture_nonce": 4}),
            _issuer=nonce_module._ISSUER,
        )
        return replace(result, _binding=nonce_module._binding(result))

    async def collect(provider, hotkey):
        assert provider is h.item.provider and hotkey == h.item.hotkey
        c.calls.append(c.target)
        return await state(c.target)

    monkeypatch.setattr(cutover, "collect_control_signing_state", collect)
    c.state = state

    def review(lease, operation="fixture-v1"):
        return cutover.NativeRewardCutoverReview(
            config=c.config,
            lease=lease,
            provider=h.item.provider,
            history=c.history,
            reader=c.reader,
            decisions=c.decisions,
            transactions=c.transactions,
            files=c.files,
            operation=operation,
        )

    def restart():
        c.history = RewardControlHistoryReader(
            root / "history",
            control_hotkey=h.item.hotkey,
            chain_config_sha256=digest(config.chain),
            first_block=first,
            maximum_bytes=config.maximum_history_bytes,
        )

    c.review, c.restart = review, restart
    yield c
    await h.item.provider.aclose()


@pytest.mark.parametrize(
    "cutover_case,action,count",
    [
        ("empty", "first_activation_may_select_adoption_on_next_native_review", 0),
        ("admit", "first_activation_may_select_adoption_on_next_native_review", 1),
        ("activate", "existing_activation_requires_native_revision_or_live_lock_review", 2),
        ("revoke", "series_revoked_preserve_state", 3),
    ],
    indirect=["cutover_case"],
)
async def test_native_history_selects_explicit_economic_branch(cutover_case, action, count, caplog):
    c = cutover_case
    caplog.set_level(logging.INFO, logger=cutover.__name__)
    with hold_reward_cutover_owner(c.config) as lease:
        result = await c.review(lease).step(c.cohort)
    assert result["cutover_decision"] == action
    assert result["finalized_control_decisions"] == count
    assert result["signed_delay_blocks"] == 7328
    assert result["history_first_block"] == c.history.first_block
    assert result["history_through_block"] == c.target
    assert not result["publication_authorized"] and not result["live_reward_row_checked"]
    assert result["writer_reconciliation_required"] and result["native_startup_recheck_required"]
    if count >= 2:
        assert digest(c.activation.decision) in result["finalized_activation_decisions"]
    if count == 2:
        assert result["control_selection"]["state"] == "draining"
        assert result["control_selection"]["effective_at_block"] == c.history.first_block + 1 + 7328
    events = [json.loads(r.message) for r in caplog.records if r.name == cutover.__name__]
    assert events[-1]["percent"] == 100 and events[-1]["eta_seconds"] == 0
    assert all("elapsed_seconds" in e and "eta_basis" in e for e in events)


async def test_bounded_fixed_target_restart_reuses_completed_blocks(cutover_case):
    c = cutover_case
    c.config = c.config.model_copy(
        update={"service": c.config.service.model_copy(update={"maximum_history_blocks": 2})}
    )
    with hold_reward_cutover_owner(c.config) as lease:
        result = await c.review(lease).step(c.cohort)
    assert result["status"] == "history_pending"
    assert result["next_block"] == c.history.first_block + 2
    c.restart()
    with hold_reward_cutover_owner(c.config) as lease:
        result = await c.review(lease).step(c.cohort)
    assert result["status"] == "history_pending"
    assert len(c.calls) == 1  # Fixed target was retained; no moving-head restart.
    assert c.history.progress.latest["restored_completed"] >= 2
    c.restart()
    with hold_reward_cutover_owner(c.config) as lease:
        result = await c.review(lease).step(c.cohort)
    assert result["status"] == "reconciled" and len(c.calls) == 2


@pytest.mark.parametrize("cutover_case", ["unresolved"], indirect=True)
async def test_unresolved_history_never_approves(cutover_case):
    c = cutover_case
    with (
        hold_reward_cutover_owner(c.config) as lease,
        pytest.raises(ValueError, match="unresolved"),
    ):
        await c.review(lease).step(c.cohort)


async def test_damaged_target_fails_and_expired_fresh_proof_retries(cutover_case, monkeypatch):
    c = cutover_case
    with hold_reward_cutover_owner(c.config) as lease:
        review = c.review(lease)
        value = await c.state(c.target)
        review._target(c.cohort, value)
        key = digest(["cutover-target", c.cohort])
        with review.targets.transaction() as db:
            db.execute(
                "UPDATE records SET body=? WHERE kind=?",
                (canonical_json_bytes({"height": c.target, "block_hash": "invalid"}), key),
            )
        with pytest.raises(ValueError, match="binding is damaged"):
            await review.step(c.cohort)
        fresh = await c.state(c.target)
        expired_control = replace(fresh.control, expires_monotonic_ns=time.monotonic_ns() - 1)
        expired_control = replace(
            expired_control, _binding=current_module._binding(expired_control)
        )
        expired = replace(fresh, control=expired_control)
        expired = replace(expired, _binding=nonce_module._binding(expired))

        async def collect(*_):
            return expired

        monkeypatch.setattr(cutover, "collect_control_signing_state", collect)
        result = await c.review(lease, operation="expired-v1").step(c.cohort)
        assert result["status"] == "refresh_required" and not result["publication_authorized"]


async def test_fresh_final_tail_has_exact_current_snapshot_and_rollback_refuses(
    cutover_case,
    monkeypatch,
):
    c = cutover_case
    targets = iter((c.target - 2, c.target))

    async def collect(*_):
        return await c.state(next(targets))

    monkeypatch.setattr(cutover, "collect_control_signing_state", collect)
    with hold_reward_cutover_owner(c.config) as lease:
        review = c.review(lease)
        result = await review.step(c.cohort)
        assert result["history_through_block"] == c.target
        assert result["status"] == "reconciled"
        with pytest.raises(ValueError, match="rolled back"):
            review._target(c.cohort, await c.state(c.target - 1))
        changed = await c.state(c.target)
        changed = replace(
            changed,
            control=replace(
                changed.control,
                snapshot=replace(changed.control.snapshot, block_hash="0x" + "00" * 32),
            ),
        )
        with pytest.raises(ValueError, match="finality changed"):
            review._target(c.cohort, changed)


@pytest.mark.parametrize("capacity", [False, True])
async def test_native_header_recovery_is_resumable_or_capacity_pending(
    cutover_case,
    monkeypatch,
    capacity,
):
    c = cutover_case
    with hold_reward_cutover_owner(c.config) as lease:
        review = c.review(lease)
        original = review._recover

        async def unfinished(*_):
            error = (
                cutover.HistoricalHeaderRecoveryPending
                if capacity
                else cutover.HistoricalHeaderRecoveryProgress
            )
            raise error("synthetic bounded native recovery")

        monkeypatch.setattr(review, "_recover", unfinished)
        result = await review.step(c.cohort)
        assert result["status"] == (
            "historical_recovery_pending" if capacity else "historical_recovery_progress"
        )
        assert result["capacity_repair_required"] is capacity
        assert not result["publication_authorized"]
        assert "recovery_eta_basis" in result
        monkeypatch.setattr(review, "_recover", original)
        assert (await review.step(c.cohort))["status"] == "reconciled"


@pytest.mark.parametrize("cutover_case", ["age"], indirect=True)
async def test_reconciliation_produces_native_age_and_reuses_it_on_restart(
    cutover_case, monkeypatch
):
    c = cutover_case
    with hold_reward_cutover_owner(c.config) as lease:
        first = await c.review(lease).step(c.cohort)
    age = first["activation_age"]
    assert age["cohort_start_block"] == c.history.first_block
    assert age["observed_at_block"] == first["history_through_block"]
    assert age["observed_timestamp_ms"] >= age["cohort_start_timestamp_ms"]
    assert first["selected_activation_delay_blocks"] == 7328
    c.restart()
    import umi.competition_reward_timing_review as timing

    async def cannot_repeat(*args, **kwargs):
        raise AssertionError("unchanged cohort timestamp must be reused")

    monkeypatch.setattr(timing, "verify_slot_archive", cannot_repeat)

    def cannot_parse(*args, **kwargs):
        raise AssertionError("unchanged start proof must not be read or hashed")

    monkeypatch.setattr(timing, "_Archive", cannot_parse)
    original_load = c.history._load

    def bounded_load(height):
        if height == c.history.first_block:
            cannot_parse()
        return original_load(height)

    monkeypatch.setattr(c.history, "_load", bounded_load)
    with hold_reward_cutover_owner(c.config) as lease:
        second = await c.review(lease).step(c.cohort)
    assert second["activation_age"] == age
    assert not second["publication_authorized"]
