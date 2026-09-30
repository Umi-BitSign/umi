"""Stopped C4 inventory and first-activation writer ownership.

The host receipt/container, completed C5 replay and cryptographic expiry result
are explicit fixture ports. Signed C4 packages, authorization/history replay,
the original worker's durable ordering, both journal formats and OS locks are
real. Native expiry cryptography is covered by test_competition_reward_legacy_recovery.
"""

import asyncio
import fcntl
import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_handoff as handoff
from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.competition_reward_decisions import RewardActivation
from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan, validate_legacy_handoff
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.competition_supervisor import SuccessorSupervisorDirectivePage
from umi.competition_supervisor_runtime import SuccessorRuntimeLimits, SuccessorSupervisorRuntime
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import advance_supervisor_directive_state

from .test_competition_reward_decisions import series_case as series_case
from .test_competition_supervisor_adapters import (
    _candidate_storage,
    _run,
)
from .test_competition_supervisor_adapters import adapter_case as adapter_case
from .test_competition_supervisor_adapters import chain as chain
from .test_competition_supervisor_adapters import chain_config as chain_config
from .test_competition_supervisor_adapters import package_case as package_case
from .test_competition_supervisor_adapters import package_limits as package_limits
from .test_competition_supervisor_adapters import policy as policy
from .test_competition_supervisor_adapters import release_identity as release_identity
from .test_competition_supervisor_adapters import replay_limits as replay_limits
from .test_competition_supervisor_adapters import successor_case as successor_case
from .test_competition_supervisor_adapters import successor_chain as successor_chain
from .test_competition_supervisor_adapters import successor_release as successor_release
from .test_competition_supervisor_adapters import weight_case as weight_case
from .test_competition_supervisor_adapters import worker_capacity as worker_capacity
from .test_open_competition import wallet
from .test_validator_supervisor import _config as v3_config
from .test_validator_supervisor import _directive as v3_directive
from .test_validator_supervisor import _signed as v3_signed


@pytest.fixture
def v3_predecessor():
    hotkey = wallet("Eve").hotkey.ss58_address
    config = v3_config(validator_hotkey=hotkey)
    signed = v3_signed(v3_directive(validator_hotkeys=[hotkey]))
    state = advance_supervisor_directive_state(
        signed, config=config, finalized_block=120, prior_state=None
    )
    return SimpleNamespace(
        config=config, signed=signed, body=canonical_json_bytes(signed), state=state
    )


@pytest.fixture
def control(chain):
    # Only construct the signed series fixture here. Current standing control
    # proof collection belongs to preparation's independently tested boundary.
    return SimpleNamespace(
        policy=chain.policy, config=chain.config, hotkey=wallet("Ferdie").hotkey.ss58_address
    )


@pytest.fixture(params=["legacy", "cas"])
async def migration(series_case, adapter_case, monkeypatch, request):
    c = adapter_case
    _candidate_storage(c, request.param)
    c.select("competition_weights")
    await c.adapter.stage(c.selection)
    c.adapter._retain(c.adapter._staged[c.selection.directive_sha256])
    installation = c.installation
    installation.v3_state = c.predecessor.state
    installation.v3_signed_bytes = c.predecessor.body
    installation.initial_page = SuccessorSupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/4",
        after_version=3,
        after_sequence=c.predecessor.state.accepted_sequence,
        after_directive_sha256=c.predecessor.state.accepted_directive_sha256,
        directives=[c.selection.signed],
        more=False,
        head=c.selection.signed,
    )
    installation.initial_accepted_at_finalized_block = 170
    root = Path(c.config.state_root)
    for name, body in (
        ("directive-state.json", canonical_json_bytes(c.predecessor.state)),
        ("supervisor-process.lock", b"original lock\n"),
    ):
        (root / name).write_bytes(body)
        (root / name).chmod(0o600)

    async def no_fetch(**_):
        pytest.fail("migration must not fetch C4 directives")

    def reopen():
        return SuccessorSupervisorRuntime(
            installation=installation,
            worker_adapter=c.adapter,
            directive_fetcher=SimpleNamespace(fetch_directive_page=no_fetch),
            observation_reader=c.observer,
            limits=SuccessorRuntimeLimits(maximum_history_records=8, maximum_history_bytes=1024**2),
        )

    c.reopen = reopen
    c.series = series_case.series.model_copy(update={"validators": (c.item.hotkey,)})
    target = c.selection.signed.directive.replay_package
    c.plan = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(c.series),
        cohort_sha256=digest(c.series.cohorts[0]),
        legacy_policy_sha256=target.policy_sha256,
        legacy_round_sha256=target.round_sha256,
        legacy_package_sha256=target.package_sha256,
    )
    activation = RewardActivation(
        cohort_sha256=c.plan.cohort_sha256,
        allocation_sha256="11" * 32,
        package_sha256="12" * 32,
        recovery_tip_sha256="13" * 32,
        prior_opportunity_sha256=digest(c.plan),
    )
    c.prepared = SimpleNamespace(activation=activation, reviewed_at_block=180)
    c.preparation = object.__new__(StandingRewardPreparation)
    c.preparation.reader = SimpleNamespace(series=c.series)
    c.preparation.series_sha256 = digest(c.series)

    def check_prepared(value):
        assert value is c.prepared

    c.preparation._check_prepared = check_prepared
    provider = object.__new__(HistoricalRewardControlProvider)
    provider.config = c.item.config
    c.providers = {digest(provider.config): provider}
    c.reviews, c.validations = [], []
    c.expired = True

    async def review(actual_provider, **inputs):
        assert actual_provider is provider
        assert inputs["validator_hotkey"] == c.item.hotkey
        item = json.loads(inputs["attempt"])
        assert hashlib.sha256(inputs["chain"]).hexdigest() == item["chain_evidence_sha256"]
        assert (
            hashlib.sha256(inputs["metadata"]).hexdigest()
            == json.loads(inputs["chain"])["runtime_metadata_sha256"]
        )
        c.reviews.append(inputs["attempt"])
        if not c.expired:
            return None
        return SimpleNamespace(
            finalized=SimpleNamespace(block_number=200), attempt=inputs["attempt"]
        )

    def validate(result, **inputs):
        assert result.attempt == inputs["attempt"]
        assert inputs["chain_config_sha256"] == digest(provider.config)
        assert inputs["validator_hotkey"] == c.item.hotkey
        c.validations.append(inputs["attempt"])

    monkeypatch.setattr(handoff, "review_legacy_weight_expiry", review)
    monkeypatch.setattr(handoff, "validate_legacy_weight_expiry", validate)

    async def disconnected(encoded, signer):
        with sqlite3.connect(c.item.worker.path) as db:
            saved = json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])
        assert saved["signed_extrinsic"] == "0x" + encoded.hex()
        c.item.encoded.append(encoded)
        raise ConnectionError("reply lost after durable signed bytes")

    monkeypatch.setattr(c.item.transport, "submit", disconnected)
    c.args = dict(
        preparation=c.preparation, prepared=c.prepared, plan=c.plan, providers=c.providers
    )
    c.validate = lambda value: validate_legacy_handoff(
        value, series=c.series, activation=activation, validator_hotkey=c.item.hotkey, block=200
    )
    return c


async def signed_attempt(c):
    with pytest.raises(ConnectionError, match="reply lost"):
        await _run(c.item)


def assert_locked(path):
    with Path(path).open("rb") as f, pytest.raises(BlockingIOError):
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)


async def test_complete_native_inventory_stays_locked_and_preserved_across_restart(migration):
    c = migration
    await signed_attempt(c)
    before = c.item.worker.path.read_bytes()
    old = (Path(c.config.state_root) / "directive-state.json").read_bytes()
    for _ in range(2):
        async with c.reopen() as runtime:
            async with handoff.hold_legacy_reward_handoff(runtime, **c.args) as result:
                c.validate(result)
                assert not result.chain_submission_authorized
                assert result.through_block == 200
                assert_locked(c.item.worker.lock_path)
                assert_locked(Path(c.config.state_root) / "supervisor-process.lock")
                with pytest.raises(ValueError, match=r"native provenance|qualified legacy"):
                    c.validate(replace(result, inventory_sha256="ff" * 32))
            with pytest.raises(ValueError, match="lease has ended"):
                c.validate(result)
            assert (await runtime.reconcile()).reason == "standing_reward_handoff"
    assert c.item.worker.path.read_bytes() == before
    assert (Path(c.config.state_root) / "directive-state.json").read_bytes() == old
    assert len(c.reviews) == len(c.validations) == 2
    assert len(c.item.encoded) == 1


async def test_live_attempt_cannot_be_skipped_and_later_retry_uses_same_intent(migration):
    c = migration
    await signed_attempt(c)
    c.expired = False
    async with c.reopen() as runtime:
        with pytest.raises(ValueError, match="remains live"):
            async with handoff.hold_legacy_reward_handoff(runtime, **c.args):
                pytest.fail("still-live bytes cannot yield writer ownership")
        intent = runtime._standing_handoff_intent()
    c.expired = True
    async with (
        c.reopen() as runtime,
        handoff.hold_legacy_reward_handoff(runtime, **c.args) as result,
    ):
        c.validate(result)
        assert runtime._standing_handoff_intent() == intent


@pytest.mark.parametrize("state", ["empty", "intent", "unknown"])
async def test_no_signed_bytes_needs_no_expiry_but_still_fences_old_writer(
    migration, monkeypatch, state
):
    c = migration
    if state != "empty":

        def fail_sign(*_, **__):
            raise RuntimeError("signer stopped")

        monkeypatch.setattr(c.item.transport, "encode", fail_sign)
        with pytest.raises(RuntimeError, match="signer stopped"):
            await _run(c.item)
        if state == "unknown":
            assert (await _run(c.item)).status == "unknown"
    before = c.item.worker.path.read_bytes()
    async with (
        c.reopen() as runtime,
        handoff.hold_legacy_reward_handoff(runtime, **c.args) as result,
    ):
        c.validate(result)
        assert_locked(c.item.worker.lock_path)
    assert not c.reviews and not c.item.encoded
    assert c.item.worker.path.read_bytes() == before


@pytest.mark.parametrize("change", ["checkpoint", "authority", "hash", "missing_provider"])
async def test_invalid_inventory_leaves_durable_hold_without_new_writer(migration, change):
    c = migration
    await signed_attempt(c)
    if change == "missing_provider":
        c.providers.clear()
    else:
        with sqlite3.connect(c.item.worker.path) as db:
            raw = db.execute("SELECT body FROM attempts").fetchone()[0]
            body = json.loads(raw)
            if change != "hash":
                key = (
                    "recovery_checkpoint_sha256"
                    if change == "checkpoint"
                    else "authorization_sha256"
                )
                body[key] = "ff" * 32
                raw = canonical_json_bytes(body)
            sha = "ff" * 32 if change == "hash" else hashlib.sha256(raw).hexdigest()
            db.execute("UPDATE attempts SET body=?,sha256=?", (raw, sha))
    async with c.reopen() as runtime:
        with pytest.raises(ValueError):
            async with handoff.hold_legacy_reward_handoff(runtime, **c.args):
                pytest.fail("invalid inventory cannot grant handoff")
        assert runtime._standing_handoff_intent() is not None
        assert (await runtime.reconcile()).reason == "standing_reward_handoff"
    assert not c.reviews and len(c.item.encoded) == 1


async def test_cancellation_keeps_intent_but_invalidates_scoped_result(migration):
    c = migration
    await signed_attempt(c)
    results = []
    entered = asyncio.Event()

    async def run():
        async with (
            c.reopen() as runtime,
            handoff.hold_legacy_reward_handoff(runtime, **c.args) as result,
        ):
            results.append(result)
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(run())
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(ValueError, match="lease has ended"):
        c.validate(results[0])
    async with c.reopen() as runtime:
        assert (await runtime.reconcile()).reason == "standing_reward_handoff"


@pytest.mark.parametrize("target", ["journal", "registry", "weight_lock", "process_lock"])
async def test_projection_cannot_reuse_handoff_after_retained_state_changes(migration, target):
    c = migration
    await signed_attempt(c)
    async with (
        c.reopen() as runtime,
        handoff.hold_legacy_reward_handoff(runtime, **c.args) as result,
    ):
        c.validate(result)
        path = {
            "journal": c.item.worker.path,
            "registry": c.adapter.path,
            "weight_lock": c.item.worker.lock_path,
            "process_lock": Path(c.config.state_root) / "supervisor-process.lock",
        }[target]
        if target.endswith("lock"):
            # Keep the original inode available to restore for orderly fixture
            # shutdown; the replacement must never be mistaken for ownership.
            preserved = path.with_suffix(".preserved")
            path.rename(preserved)
            path.write_bytes(preserved.read_bytes())
            path.chmod(0o600)
            try:
                with pytest.raises(ValueError, match=r"state changed|inode changed"):
                    c.validate(result)
            finally:
                preserved.replace(path)
        else:
            if target == "journal":
                # SQLite itself blocks a concurrent writer. An external edit
                # bypassing that protocol must also invalidate the capability.
                with (
                    sqlite3.connect(path, timeout=0) as db,
                    pytest.raises(sqlite3.OperationalError, match="locked"),
                ):
                    db.execute("PRAGMA user_version=1")
                path.touch()
            else:
                with sqlite3.connect(path) as db:
                    db.execute("PRAGMA user_version=1")
            with pytest.raises(ValueError, match="state changed"):
                c.validate(result)


async def test_even_terminal_unrecognized_second_attempt_prevents_handoff(migration):
    c = migration
    await signed_attempt(c)
    with sqlite3.connect(c.item.worker.path) as db:
        body = json.loads(db.execute("SELECT body FROM attempts").fetchone()[0])
        body.update(authorization_id="ff" * 32, phase="applied")
        raw = canonical_json_bytes(body)
        db.execute(
            "INSERT INTO attempts VALUES (?,?,?)",
            (body["authorization_id"], raw, hashlib.sha256(raw).hexdigest()),
        )
    async with c.reopen() as runtime:
        with pytest.raises(ValueError, match="exact retained authority"):
            async with handoff.hold_legacy_reward_handoff(runtime, **c.args):
                pytest.fail("a local terminal flag cannot hide an unreviewed transaction")
        assert (await runtime.reconcile()).reason == "standing_reward_handoff"
