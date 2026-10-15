"""Genuine stopped owner with exact native SCALE and retained transaction inputs.

The chain finality/trie ports remain the explicit synthetic ports of the native
transaction fixture; no test issues a stopped-owner or transaction capability.
"""

import fcntl
import os
from dataclasses import replace
from pathlib import Path

import bittensor as bt
import bittensor_core
import pytest

from umi import competition_reward_writer_review as review_module
from umi.competition_reward_host import StandingRewardHostApproval
from umi.competition_reward_transactions import StandingWeightJournal
from umi.competition_reward_writer_journals import hold_stopped_writer_journals
from umi.competition_reward_writer_reconciliation import (
    hold_stopped_standing_writer,
    review_stopped_standing_attempt,
)
from umi.competition_reward_writer_review import select_stopped_writer_boot
from umi.competition_round_journal import RoundJournal
from umi.competition_supervisor_runtime import hold_successor_startup_lease
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_decisions import (
    chain as chain,
)
from .test_competition_reward_decisions import (
    control as control,
)
from .test_competition_reward_decisions import (
    series_case as series_case,
)
from .test_competition_reward_transaction_recovery import (
    native_encoding as base_native_encoding,
)
from .test_competition_reward_transaction_recovery import (
    original as original,
)
from .test_competition_reward_writer_reconciliation import (
    activation_case as activation_case,
)
from .test_competition_reward_writer_reconciliation import (
    anchor_case as anchor_case,
)
from .test_competition_reward_writer_reconciliation import (
    chain_config as chain_config,
)
from .test_competition_reward_writer_reconciliation import (
    explicit as explicit,
)
from .test_competition_reward_writer_reconciliation import (
    limits as limits,
)
from .test_competition_reward_writer_reconciliation import (
    owner_case as owner_case,
)
from .test_competition_reward_writer_reconciliation import (
    package_case as package_case,
)
from .test_competition_reward_writer_reconciliation import (
    package_limits as package_limits,
)
from .test_competition_reward_writer_reconciliation import (
    policy as policy,
)
from .test_competition_reward_writer_reconciliation import (
    release_identity as release_identity,
)
from .test_competition_reward_writer_reconciliation import (
    replay_limits as replay_limits,
)
from .test_competition_reward_writer_reconciliation import (
    signed_case as signed_case,
)
from .test_competition_reward_writer_reconciliation import (
    successor_release as successor_release,
)
from .test_competition_reward_writer_reconciliation import (
    trusted_ports as trusted_ports,
)
from .test_competition_reward_writer_reconciliation import (
    worker_capacity as worker_capacity,
)

_NATIVE_RUNTIME = bittensor_core.Runtime


@pytest.fixture
def native_encoding():
    value = base_native_encoding.__wrapped__()
    value.signer = bt.sp_core.Keypair.from_uri("//DirectBootstrapOwner", crypto_type=1)
    value.context["validator_hotkey"] = value.signer.ss58_address
    return value


@pytest.fixture
def selected_boot(owner_case, inputs):
    c, item = owner_case, inputs
    series = item.value.series.model_copy(
        update={
            "validators": tuple(
                sorted(
                    {*item.value.series.validators, c.anchor.config.validator_hotkey},
                    key=identity,
                )
            )
        }
    )
    item.value = item.value.model_copy(
        update={
            "series": series,
            "handoff": item.value.handoff.model_copy(update={"series_sha256": digest(series)}),
        }
    )
    item.save(item.path, canonical_json_bytes(item.value))
    approval = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/1",
        source_config_sha256=digest(c.anchor.config),
        installation_receipt_sha256=c.anchor.receipt_sha256,
        host_manifest_sha256=c.anchor.receipt.host_manifest_sha256,
        validator_hotkey=c.anchor.config.validator_hotkey,
        series_sha256=digest(item.value.series),
        policy_sha256=digest(item.value.policy),
        manifest_sha256=digest(item.value.manifest),
        chain_config_sha256=digest(item.value.chain),
        legacy_handoff_plan_sha256=digest(item.value.handoff),
    )
    item.approval = approval
    item.save(Path(item.value.approval_path), canonical_json_bytes(approval))
    return c, item


def test_original_active_and_held_approval_remain_exact(selected_boot):
    c, item = selected_boot
    value = select_stopped_writer_boot(c.anchor, item.path)
    value.recheck()
    with pytest.raises(ValueError, match="sealed"):
        replace(value, boot_raw_sha256="ab" * 32).recheck()
    original = Path(item.value.approval_path)
    raw = original.read_bytes()
    held = original.with_suffix(".held")
    original.rename(held)
    value = select_stopped_writer_boot(c.anchor, item.path, held_approval=held)
    assert value.approval_held
    value.recheck()
    assert not original.exists() and held.read_bytes() == raw
    item.save(original, raw)
    with pytest.raises(ValueError, match="hold changed"):
        value.recheck()


@pytest.mark.parametrize("fault", ["approval", "boot", "both_active_and_held", "dangling_original"])
def test_original_approval_binding_is_required_before_any_journal_open(selected_boot, fault):
    c, item = selected_boot
    held = None
    if fault == "approval":
        changed = item.approval.model_copy(update={"series_sha256": "ab" * 32})
        item.save(Path(item.value.approval_path), canonical_json_bytes(changed))
    elif fault == "boot":
        item.save(
            item.path,
            canonical_json_bytes(
                item.value.model_copy(
                    update={"delivery_directory": str(item.path.parent / "changed")}
                )
            )
            + b" ",
        )
    else:
        held = Path(item.value.approval_path).with_suffix(".held")
        item.save(held, Path(item.value.approval_path).read_bytes())
        if fault == "dangling_original":
            Path(item.value.approval_path).unlink()
            Path(item.value.approval_path).symlink_to(held.with_suffix(".missing"))
    with pytest.raises(ValueError):
        select_stopped_writer_boot(c.anchor, item.path, held_approval=held)


async def test_held_approval_recheck_rejects_dangling_original(selected_boot):
    c, item = selected_boot
    active = Path(item.value.approval_path)
    held = active.with_suffix(".held")
    active.rename(held)
    selected = select_stopped_writer_boot(c.anchor, item.path, held_approval=held)
    active.symlink_to(held.with_suffix(".missing"))
    with pytest.raises(ValueError, match="hold changed"):
        selected.recheck()


async def test_installed_review_locks_original_writer_before_native_open(
    selected_boot, monkeypatch
):
    c, item = selected_boot
    root = c.root / "standing-rewards" / digest(item.value.series)
    root.parent.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    for name in ("history", "control"):
        RoundJournal(root / name, {"fixture": name}, maximum_bytes=8 * 1024**2)
    lock = root.parent / "standing-writer.lock"
    lock.write_bytes(b"original writer lock")
    lock.chmod(0o600)
    snapshots = [(p, p.read_bytes()) for p in root.rglob("rounds.sqlite3")]

    def forbidden(*args, **kwargs):
        raise AssertionError("mutable constructor ran without original process ownership")

    async def synthetic_resource_preflight(config, resources):
        assert resources.state_directory == config.state_directory
        return {"native_artifacts_checked": 3, "chain_submission_authorized": False}

    monkeypatch.setattr(review_module, "preflight_chain_resources", synthetic_resource_preflight)
    monkeypatch.setattr(review_module, "RewardControlHistoryReader", forbidden)
    fd = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            await review_module.review_installed_standing_writer(
                c.anchor,
                item.path,
                unit=c.unit,
                config_path=c.config_path,
                through_block=item.value.series.recovery.authority.issued_at_block,
            )
    finally:
        os.close(fd)
    assert all(path.read_bytes() == raw for path, raw in snapshots)


async def _pending(owner_case, series_case, original, *, corrupt=False, unsigned=False):
    c, t = owner_case, original
    assert c.anchor.config.validator_hotkey == t.hotkey
    series = series_case.series.model_copy(
        update={
            "control_hotkey": t.hotkey,
            "validators": tuple(sorted({*series_case.series.validators, t.hotkey}, key=identity)),
        }
    )
    state = c.root / "standing-rewards"
    state.mkdir(mode=0o700)
    root = state / digest(series)
    root.mkdir(mode=0o700)
    journal = StandingWeightJournal(
        root / "weights",
        series_sha256=digest(series),
        validator_hotkey=t.hotkey,
        chain_config_sha256=digest(t.provider.config),
        maximum_bytes=8 * 1024**2,
    )
    intent = t.intent.model_copy(update={"series_sha256": digest(series)})
    journal.reserve(
        intent,
        chain=t.chain.evidence,
        control=t.control.evidence,
        metadata=t.chain.runtime.metadata_bytes,
    )
    if not unsigned:
        encoded = bytearray(t.encoded)
        if corrupt:
            encoded[40] ^= 1
        journal.retain_signed(intent, bytes(encoded))
    for path in (state / "standing-writer.lock", journal.journal.root / "standing-writer.lock"):
        path.write_bytes(b"original writer lock")
        path.chmod(0o600)
    return c, t, series, journal


async def test_expired_original_attempt_remains_unknown_and_exact(
    original, owner_case, series_case, monkeypatch
):
    monkeypatch.setattr(bittensor_core, "Runtime", _NATIVE_RUNTIME)
    c, t, series, journal = await _pending(owner_case, series_case, original)
    before, inode = journal.recovery_inputs(), journal.journal.path.stat().st_ino
    with hold_successor_startup_lease(c.anchor) as startup:
        async with hold_stopped_standing_writer(
            startup, unit=c.unit, config_path=c.config_path
        ) as owner:
            result = await review_stopped_standing_attempt(
                owner, journal, t.provider, series=series
            )
            assert result["status"] == "expired_outcome_unknown"
            assert result["signed_extrinsic_hash"] == before.pending.signed.extrinsic_hash
            assert not result["chain_submission_authorized"]
    assert journal.recovery_inputs() == before
    assert journal.journal.path.stat().st_ino == inode


async def test_corrupted_native_signed_attempt_is_not_discarded_on_expiry(
    original, owner_case, series_case, monkeypatch
):
    monkeypatch.setattr(bittensor_core, "Runtime", _NATIVE_RUNTIME)
    c, t, series, journal = await _pending(owner_case, series_case, original, corrupt=True)
    before = journal.recovery_inputs()
    with hold_successor_startup_lease(c.anchor) as startup:
        async with hold_stopped_standing_writer(
            startup, unit=c.unit, config_path=c.config_path
        ) as owner:
            with pytest.raises(ValueError, match="signed transaction"):
                await review_stopped_standing_attempt(owner, journal, t.provider, series=series)
    assert journal.recovery_inputs() == before


async def test_original_weight_writer_lock_contention_refuses_before_reconciliation(
    original, owner_case, series_case, monkeypatch
):
    monkeypatch.setattr(bittensor_core, "Runtime", _NATIVE_RUNTIME)
    c, t, series, journal = await _pending(owner_case, series_case, original)
    before = journal.recovery_inputs()
    fd = os.open(journal.journal.root / "standing-writer.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with hold_successor_startup_lease(c.anchor) as startup:
            async with hold_stopped_standing_writer(
                startup, unit=c.unit, config_path=c.config_path
            ) as owner:
                with pytest.raises(BlockingIOError):
                    await review_stopped_standing_attempt(owner, journal, t.provider, series=series)
    finally:
        os.close(fd)
    assert journal.recovery_inputs() == before


async def test_original_native_attempt_reuses_preconstructor_journal_locks(
    original, owner_case, series_case, monkeypatch
):
    monkeypatch.setattr(bittensor_core, "Runtime", _NATIVE_RUNTIME)
    c, t, series, journal = await _pending(owner_case, series_case, original)
    root = journal.journal.root.parent
    for name in ("history", "control"):
        RoundJournal(root / name, {"fixture": name}, maximum_bytes=8 * 1024**2)
    before = journal.recovery_inputs()
    with hold_successor_startup_lease(c.anchor) as startup:
        async with hold_stopped_standing_writer(
            startup, unit=c.unit, config_path=c.config_path
        ) as owner:
            async with hold_stopped_writer_journals(owner, series) as journal_owner:
                result = await review_stopped_standing_attempt(
                    owner, journal, t.provider, series=series, journal_owner=journal_owner
                )
                assert result["status"] == "expired_outcome_unknown"
                journal_owner.recheck(journal)
            with pytest.raises(ValueError, match="live ownership"):
                journal_owner.recheck(journal)
    assert journal.recovery_inputs() == before
