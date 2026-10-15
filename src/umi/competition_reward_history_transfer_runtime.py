"""Bounded coordinator-to-writer history transfer under original stopped owners."""

from __future__ import annotations

import threading
from functools import partial
from pathlib import Path

from .canonical_reuse import canonical_json_reuse
from .competition_journal_physical_budget import HistoryTransferPhysicalBudget
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_transfer import (
    review_history_materialization,
    transfer_history_checkpoints,
)
from .competition_reward_history_transfer_owner import hold_history_transfer_owner
from .competition_reward_proof_archive import RewardProofArchive
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest


def _open_readers(owner, physical_budget=None):
    with TransferProgress(
        "history_transfer_reader_preparation",
        3,
        unit="readers",
        planning_unit_seconds=(0.01, 300.0),
    ) as report:
        owner.recheck()
        readers = []
        for root, config, export in (
            (owner.source_root, owner._source_config, False),
            (owner.target_root, owner._writer_boot.config, True),
        ):
            readers.append(
                RewardControlHistoryReader(
                    root,
                    control_hotkey=config.series.control_hotkey,
                    chain_config_sha256=digest(config.chain),
                    first_block=config.series.recovery.authority.issued_at_block,
                    maximum_bytes=config.maximum_history_bytes,
                    existing_only=physical_budget is not None,
                    read_only=physical_budget is not None and not export,
                    physical_budget=physical_budget.journal
                    if physical_budget is not None and export
                    else None,
                    compact_export_only=physical_budget is not None,
                    export_archive=RewardProofArchive(
                        Path(config.proof_export_directory),
                        physical_budget=physical_budget.archive
                        if physical_budget is not None
                        else None,
                    )
                    if export
                    else None,
                )
            )
            report.advance(1)
        owner.recheck(*readers)
        report.advance(1)
        return tuple(readers)


async def transfer_installed_history(
    anchor,
    *,
    unit,
    config_path,
    standing_boot,
    coordinator_config,
    first_block,
    through_block,
    maximum_blocks=256,
    held_approval=None,
    stop_requested=None,
    physical_budget: HistoryTransferPhysicalBudget | None = None,
):
    """Preserve completed block work; leave ordinary restore/finality to the writer.

    Stop only between bounded atomic work units. A repeat may select the same
    interval: the transfer ledger and export receipts retain completed work.
    This function neither changes service selection nor reads signing keys.
    """
    if (
        type(first_block) is not int
        or type(through_block) is not int
        or not 0 < first_block <= through_block
        or type(maximum_blocks) is not int
        or not 1 <= maximum_blocks <= 256
    ):
        raise ValueError("history transfer requires a bounded positive block interval")
    if physical_budget is not None and type(physical_budget) is not HistoryTransferPhysicalBudget:
        raise ValueError("typed history transfer physical budget required")
    stop = threading.Event() if stop_requested is None else stop_requested
    completed = copied = existing = exported = 0
    # Exact JSON content only: owner, file, source and authority checks still run.
    # Owned threads inherit this bounded cache and drain before its scope closes.
    with canonical_json_reuse():
        async with hold_history_transfer_owner(
            anchor,
            unit=unit,
            config_path=config_path,
            standing_boot=standing_boot,
            coordinator_config=coordinator_config,
            held_approval=held_approval,
        ) as owner:
            opener = (
                _open_readers
                if physical_budget is None
                else partial(_open_readers, physical_budget=physical_budget)
            )
            source, target = await run_owned_thread(opener, owner)
            with TransferProgress(
                "history_transfer_and_export",
                through_block - first_block + 1,
                unit="blocks",
                planning_unit_seconds=(0.01, 3.0),
            ) as progress:
                next_block = first_block
                while next_block <= through_block and not stop.is_set():
                    end = min(through_block, next_block + maximum_blocks - 1)
                    result = await run_owned_thread(
                        partial(
                            transfer_history_checkpoints,
                            source,
                            target,
                            owner=owner,
                            first_block=next_block,
                            through_block=end,
                            maximum_blocks=maximum_blocks,
                            stop_requested=stop,
                            progress=progress.child_report(),
                        ),
                        on_cancel=stop.set,
                    )
                    # Native facts are durable before export. Cancellation or a
                    # delivery failure leaves them usable by an unchanged retry.
                    for height in range(next_block, end + 1):
                        if stop.is_set():
                            break
                        await run_owned_thread(owner.recheck, source, target)
                        value = await run_owned_thread(target.checkpoints.load, height)
                        if value is None:
                            raise ValueError("history transfer did not retain selected block")
                        identity = target._export_identity()
                        with target.journal.locked():
                            updated = await target._ensure_checkpoint_export(value)
                        exported += int(
                            identity not in value["exports"] and bool(updated["exports"])
                        )
                        completed += 1
                        progress.advance(1)
                    # Counts describe this execution; the original source and target
                    # checkpoint inventories remain the durable completion evidence.
                    copied += result["transferred_blocks"]
                    existing += result["existing_blocks"]
                    next_block = end + 1
                await run_owned_thread(owner.recheck, source, target)
            materialization = None
            if completed == through_block - first_block + 1 and not stop.is_set():
                try:
                    materialization = await run_owned_thread(
                        partial(
                            review_history_materialization,
                            source,
                            target,
                            owner=owner,
                            first_block=first_block,
                            through_block=through_block,
                            stop_requested=stop,
                        ),
                        on_cancel=stop.set,
                    )
                except InterruptedError:
                    if not stop.is_set():
                        raise
            result = {
                "status": "complete" if materialization is not None else "interrupted",
                "first_block": first_block,
                "through_block": through_block,
                "completed_blocks": completed,
                "transferred_blocks": copied,
                "existing_blocks": existing,
                "new_export_receipts": exported,
                "source_owner": source.checkpoints.owner,
                "target_owner": target.checkpoints.owner,
                "context_sha256": owner.context_sha256,
                "ordered_restore_and_fresh_finality_required": True,
                "directory_exchange_performed": False,
                "chain_submission_authorized": False,
            }
            if materialization is not None:
                result["materialization"] = materialization
            return result
