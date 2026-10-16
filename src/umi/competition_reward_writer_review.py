"""Non-signing stopped-writer review under the installed native startup lease.

This command restores native successful history at its selected original path.
It never selects a different directory, restores host approval or reads a wallet.
A later directory cutover must retain this process's native ownership and compare
its original snapshot to the candidate; JSON output is diagnostics only.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path

from .competition_chain_resource_preflight import preflight_chain_resources
from .competition_cohort_recovery import verify_recovery_authority
from .competition_host_activation import _read_root_control_path
from .competition_host_anchor import MaterializedSuccessorAnchor
from .competition_proof_archive_selection import selected_proof_archives
from .competition_reward_boot import (
    MAX_BOOT_BYTES,
    StandingRewardBootConfig,
    _disjoint,
    validate_writer_byte_store_paths,
)
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_cutover_ownership import _existing
from .competition_reward_cutover_runtime import _await_initial_finality
from .competition_reward_decisions import SignedRewardControlDecision, StandingRewardControlReader
from .competition_reward_files import StandingRewardFiles
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_host import StandingRewardHostApproval
from .competition_reward_service import _close_provider
from .competition_reward_transactions import StandingWeightJournal
from .competition_reward_writer_adoption import select_writer_adoptions
from .competition_reward_writer_journals import hold_stopped_writer_journals
from .competition_reward_writer_reconciliation import (
    StoppedStandingWriter,
    hold_stopped_standing_writer,
    reconcile_stopped_control_history,
    review_stopped_standing_attempt,
)
from .competition_reward_writer_resources import select_writer_resources
from .competition_supervisor_runtime import hold_successor_startup_lease
from .concurrency import run_owned_thread
from .historical_header_recovery import HistoricalHeaderRecoveryProgress
from .host_memory_runtime import memory_runtime
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_LOG = logging.getLogger(__name__)
_ISSUER = object()


@dataclass(frozen=True, slots=True)
class StoppedWriterBoot:
    config: StandingRewardBootConfig
    boot_path: Path
    approval_path: Path
    boot_raw_sha256: str
    approval_raw_sha256: str
    approval_held: bool
    _anchor: MaterializedSuccessorAnchor = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def _seal(self):
        return digest(
            {
                "config": digest(self.config),
                "boot_path": str(self.boot_path),
                "approval_path": str(self.approval_path),
                "boot": self.boot_raw_sha256,
                "approval": self.approval_raw_sha256,
                "held": self.approval_held,
                "anchor": self._anchor._binding,
            }
        )

    def recheck(self):
        if (
            type(self) is not StoppedWriterBoot
            or self._issuer is not _ISSUER
            or self._binding != self._seal()
        ):
            raise ValueError("writer review lacks the original sealed boot selection")
        self._anchor.recheck_for_parent_repair()
        if (
            hashlib.sha256(
                _read_root_control_path(self.boot_path, MAX_BOOT_BYTES, modes={0o444})
            ).hexdigest()
            != self.boot_raw_sha256
            or hashlib.sha256(
                _read_root_control_path(self.approval_path, 8192, modes={0o444})
            ).hexdigest()
            != self.approval_raw_sha256
        ):
            raise ValueError("writer review boot or approval changed")
        if self.approval_held and (
            Path(self.config.approval_path).exists() or Path(self.config.approval_path).is_symlink()
        ):
            raise ValueError("writer approval hold changed during review")


def select_stopped_writer_boot(anchor, boot_path, *, held_approval=None):
    """Authenticate active or explicitly held original approval without moving it."""
    if type(anchor) is not MaterializedSuccessorAnchor:
        raise TypeError("writer review requires its native materialized anchor")
    anchor.recheck_for_parent_repair()
    raw = _read_root_control_path(Path(boot_path), MAX_BOOT_BYTES, modes={0o444})
    config = StandingRewardBootConfig.model_validate_json(raw)
    if canonical_json_bytes(config) != raw:
        raise ValueError("writer boot is not canonical")
    selected = Path(config.approval_path) if held_approval is None else Path(held_approval)
    if held_approval is not None and (
        selected == Path(config.approval_path)
        or Path(config.approval_path).exists()
        or Path(config.approval_path).is_symlink()
    ):
        raise ValueError("explicit held approval requires the original approval to remain absent")
    approval_raw = _read_root_control_path(selected, 8192, modes={0o444})
    approval = StandingRewardHostApproval.model_validate_json(approval_raw)
    successor = config.series.predecessor is not None
    expected = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/2"
        if successor
        else "umi-standing-reward-host-approval/1",
        source_config_sha256=digest(anchor.config),
        installation_receipt_sha256=anchor.receipt_sha256,
        host_manifest_sha256=anchor.receipt.host_manifest_sha256,
        validator_hotkey=anchor.config.validator_hotkey,
        series_sha256=digest(config.series),
        policy_sha256=digest(config.policy),
        manifest_sha256=digest(config.manifest),
        chain_config_sha256=digest(config.chain),
        legacy_handoff_plan_sha256=None if successor else digest(config.handoff),
        standing_handoff_plan_sha256=digest(config.handoff) if successor else None,
        predecessor_approval_sha256=config.predecessor_approval_sha256,
    )
    if canonical_json_bytes(approval) != approval_raw or approval != expected:
        raise ValueError("writer review differs from the exact installed approval")
    for series in (config.series, *((config.predecessor_series,) if successor else ())):
        if identity(anchor.config.validator_hotkey) not in {
            identity(value) for value in series.validators
        }:
            raise ValueError("writer validator differs from the selected series")
        verify_recovery_authority(series.recovery, config.policy)
    validate_writer_byte_store_paths(config, anchor.config)
    _disjoint((*config.mutable_stores(), Path(anchor.config.state_root) / "standing-rewards"))
    result = StoppedWriterBoot(
        config,
        Path(boot_path),
        selected,
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(approval_raw).hexdigest(),
        held_approval is not None,
        anchor,
        _ISSUER,
    )
    object.__setattr__(result, "_binding", result._seal())
    result.recheck()
    return result


async def restore_stopped_writer_history(
    owner: StoppedStandingWriter,
    history: RewardControlHistoryReader,
    provider: HistoricalRewardControlProvider,
    *,
    series,
    through_block,
    maximum_blocks,
):
    """Restore genuine original-path checkpoints; verify only missing blocks."""
    if type(owner) is not StoppedStandingWriter or type(history) is not RewardControlHistoryReader:
        raise TypeError("writer history review requires native owners")
    expected = (
        Path(owner.startup.config.state_root) / "standing-rewards" / digest(series) / "history"
    )
    if (
        history.journal.root != expected
        or history.first_block != series.recovery.authority.issued_at_block
        or identity(history.hotkey) != identity(series.control_hotkey)
        or history.config_sha256 != digest(provider.config)
    ):
        raise ValueError("writer history differs from its original selected path or chain")
    await owner.recheck()
    while True:
        try:
            result = await history.advance(
                provider, through_block=through_block, maximum_blocks=maximum_blocks
            )
        except HistoricalHeaderRecoveryProgress:
            await owner.recheck()
            await asyncio.sleep(0)
            continue
        await owner.recheck()
        if result.history is not None:
            return result.history
        await asyncio.sleep(0)


async def review_installed_standing_writer(
    anchor,
    boot_path: Path,
    *,
    unit: str,
    config_path: Path,
    through_block: int,
    held_approval: Path | None = None,
    history: str = "current",
    reward_adoptions: Path | None = None,
    resource_launch: Path | None = None,
    preparation_approval: Path | None = None,
):
    """Review original history and exact standing attempt without authorizing a switch."""
    started, phase, native_history = time.monotonic(), 0, None

    def report(state="running"):
        elapsed = time.monotonic() - started
        body = {
            "stage": "stopped_writer_review",
            "state": state,
            "completed_items": phase,
            "total_items": 5,
            "percent": 100 if state == "completed" else min(99.9, phase * 20),
            "elapsed_seconds": elapsed,
            "eta_seconds": 0 if state == "completed" else None,
            "planning_eta_seconds": [1, 300] if state == "running" and elapsed <= 300 else None,
            "eta_basis": "planning_local_open_and_native_restore_excludes_missing_history"
            if state == "running" and elapsed <= 300
            else "completed"
            if state == "completed"
            else "withdrawn",
            "eta_scope": "writer_review_only_excludes_directory_selection_and_rewards",
            "chain_submission_authorized": False,
        }
        if native_history is not None:
            body["history_progress"] = native_history.progress.latest
        _LOG.info("stopped_writer_review_progress %s", body)

    loop, timer = asyncio.get_running_loop(), None

    def heartbeat():
        nonlocal timer
        report("stalled" if time.monotonic() - started > 300 and phase < 3 else "running")
        timer = loop.call_later(30, heartbeat)

    report()
    timer = loop.call_later(30, heartbeat)
    try:
        selected = select_stopped_writer_boot(anchor, boot_path, held_approval=held_approval)
        config = selected.config
        series = config.series if history == "current" else config.predecessor_series
        if history not in {"current", "predecessor"} or series is None:
            raise ValueError("writer review history is not configured")
        adoptions = select_writer_adoptions(config, history, reward_adoptions)
        if type(through_block) is not int or not (
            series.recovery.authority.issued_at_block <= through_block < 2**53
        ):
            raise ValueError("writer review requires a finite selected history interval")
        native = select_writer_resources(
            anchor,
            selected,
            history,
            launch_path=resource_launch,
            preparation_approval=preparation_approval,
            through_block=through_block,
        )
        await preflight_chain_resources(config.chain, native.resources)
        selected.recheck()
        native.recheck()
        with hold_successor_startup_lease(anchor) as startup:
            async with hold_stopped_standing_writer(
                startup, unit=unit, config_path=config_path
            ) as owner:
                root = Path(startup.config.state_root) / "standing-rewards" / digest(series)
                for name in ("history", "control"):
                    _existing(root / name, directory=True)
                    for child in ("rounds.sqlite3", "rounds.lock"):
                        _existing(root / name / child)
                phase = 1
                async with AsyncExitStack() as resources:
                    journal_owner = await resources.enter_async_context(
                        hold_stopped_writer_journals(owner, series)
                    )
                    resources.enter_context(
                        memory_runtime(
                            config.host_memory_admission,
                            maximum_aggregate_bytes=config.maximum_package_bytes,
                            role="reward_writer",
                        )
                    )
                    imported, exported = await run_owned_thread(
                        selected_proof_archives,
                        Path(config.proof_import_directory),
                        Path(config.proof_export_directory),
                        config.proof_stores,
                    )

                    def construct():
                        nonlocal native_history
                        native_history = RewardControlHistoryReader(
                            root / "history",
                            control_hotkey=series.control_hotkey,
                            chain_config_sha256=digest(config.chain),
                            first_block=series.recovery.authority.issued_at_block,
                            maximum_bytes=config.maximum_history_bytes,
                            verification_profile=config.service.history_verification,
                            archive=imported,
                            export_archive=exported,
                        )
                        return StandingRewardControlReader(
                            root / "control",
                            series,
                            config.policy,
                            expected_series_sha256=digest(series),
                            expected_chain_config_sha256=digest(config.chain),
                            maximum_bytes=config.maximum_reader_bytes,
                            reward_adoptions=adoptions.selection,
                        )

                    control = await run_owned_thread(construct)
                    provider = HistoricalRewardControlProvider(
                        config.chain,
                        config.policy,
                        resources=native.resources,
                        runtime_proof_reads=config.runtime_proof_reads,
                        historical_header_directory=root / "headers" / digest(config.chain),
                        historical_header_maximum_bytes=config.maximum_header_bytes,
                        historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
                    )
                    resources.push_async_callback(_close_provider, provider)
                    await provider.start()
                    await _await_initial_finality(provider)
                    phase = 2
                    restored = await restore_stopped_writer_history(
                        owner,
                        native_history,
                        provider,
                        series=series,
                        through_block=through_block,
                        maximum_blocks=config.service.maximum_history_blocks,
                    )
                    phase = 3
                    # Preserve original signed control bytes; fetch only the
                    # exact native observed prefix from retained delivery.
                    observation = await native_history.review_control(provider, through_block)
                    files = StandingRewardFiles(
                        Path(config.delivery_directory),
                        maximum_package_bytes=config.maximum_package_bytes,
                        maximum_witness_bytes=config.maximum_witness_bytes,
                    )

                    def observed_decisions():
                        result = []
                        previous = None
                        for write in restored.writes:
                            if write.decision_sha256 == previous:
                                continue
                            raw = files.decision(write.decision_sha256)
                            value = SignedRewardControlDecision.model_validate_json(raw)
                            if canonical_json_bytes(value) != raw or (
                                digest(value.decision) != write.decision_sha256
                            ):
                                raise ValueError("observed writer decision delivery differs")
                            result.append(value)
                            previous = write.decision_sha256
                        return tuple(result)

                    # Fetch only exact natively observed controls. The native
                    # reviewer authenticates the full chain without retaining
                    # new records or advancing the original reader highwater.
                    decisions = await run_owned_thread(observed_decisions)
                    review = await reconcile_stopped_control_history(
                        owner,
                        control,
                        original=restored,
                        candidate=restored,
                        candidate_original_prefix=restored,
                        observation=observation,
                        decisions=decisions,
                    )
                    phase = 4
                    weights = root / "weights"
                    if not weights.exists():
                        attempt = {
                            "status": "standing_journal_absent_requires_native_handoff_review",
                            "legacy_handoff_recheck_required": True,
                            "chain_submission_authorized": False,
                        }
                    else:
                        for child in ("rounds.sqlite3", "rounds.lock", "standing-writer.lock"):
                            _existing(weights / child)
                        _existing(root.parent / "standing-writer.lock")
                        journal = await run_owned_thread(
                            lambda: StandingWeightJournal(
                                weights,
                                series_sha256=digest(series),
                                validator_hotkey=startup.config.validator_hotkey,
                                chain_config_sha256=digest(config.chain),
                                maximum_bytes=config.service.maximum_journal_bytes,
                            )
                        )
                        attempt = await review_stopped_standing_attempt(
                            owner, journal, provider, series=series, journal_owner=journal_owner
                        )
                    await owner.recheck()
                    selected.recheck()
                    adoptions.recheck()
                    native.recheck()
                    phase = 5
                    report("completed")
                    return {
                        "schema": "umi-installed-stopped-writer-review/1",
                        "status": "original_reviewed",
                        "series_sha256": digest(series),
                        "through_block": restored.tip.block_number,
                        "original_checkpoint_owner": native_history.checkpoints.owner,
                        "history": review,
                        "standing_attempt": attempt,
                        "approval_hold_preserved": selected.approval_held,
                        "directory_selection_authorized": False,
                        "legacy_handoff_recheck_required": True,
                        "chain_submission_authorized": False,
                    }
    except BaseException:
        report("interrupted_or_retry_required")
        raise
    finally:
        if timer is not None:
            timer.cancel()
