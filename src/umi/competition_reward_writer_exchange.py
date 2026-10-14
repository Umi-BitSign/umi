"""Same-child native writer reconciliation across the root's directory exchange."""

from __future__ import annotations

import os
from contextlib import AsyncExitStack
from pathlib import Path

from .competition_chain_resources import CompetitionChainResources
from .competition_proof_archive_selection import selected_proof_archives
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_cutover_ownership import _existing
from .competition_reward_cutover_runtime import _await_initial_finality
from .competition_reward_decisions import SignedRewardControlDecision, StandingRewardControlReader
from .competition_reward_files import StandingRewardFiles
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_service import _close_provider
from .competition_reward_transactions import StandingWeightJournal
from .competition_reward_writer_adoption import select_writer_adoptions
from .competition_reward_writer_journals import hold_stopped_writer_journals
from .competition_reward_writer_prefix import (
    restore_completed_prefix,
    retained_completed_tip,
    review_empty_original,
)
from .competition_reward_writer_reconciliation import (
    hold_stopped_standing_writer,
    reconcile_stopped_control_history,
    review_stopped_standing_attempt,
)
from .competition_reward_writer_review import select_stopped_writer_boot
from .competition_supervisor_runtime import hold_successor_startup_lease
from .competition_work_progress import WorkProgress
from .concurrency import run_owned_thread
from .host_memory_runtime import memory_runtime
from .open_competition import digest
from .protocol import canonical_json_bytes


async def exchange_installed_standing_writer(anchor, args, channel):
    selected = select_stopped_writer_boot(
        anchor, args.standing_boot, held_approval=args.held_approval
    )
    if not selected.approval_held:
        raise ValueError("writer directory exchange requires original approval held")
    config = selected.config
    series = config.series if args.history == "current" else config.predecessor_series
    if series is None or args.through_block < series.recovery.authority.issued_at_block:
        raise ValueError("writer exchange history interval differs")
    adoptions = select_writer_adoptions(
        config,
        args.history,
        getattr(args, "reward_adoptions", None),
        expected_sha256=getattr(args, "reward_adoptions_sha256", None),
    )

    def recheck_inputs():
        selected.recheck()
        adoptions.recheck()

    if getattr(args, "readiness_only", False):
        # This non-authorizing environment check runs while the original writer
        # may still be active. It never acquires an original startup/journal
        # owner or constructs a provider, and cannot enter the exchange branch.
        await channel.send("namespace_ready")
        message = await channel.receive("readiness")
        message.validate("readiness")
        root = Path(anchor.config.state_root) / "standing-rewards" / digest(series)
        for directory in (root / "history", root / "control"):
            _existing(directory, directory=True)
            if not os.access(directory, os.R_OK | os.W_OK | os.X_OK):
                raise ValueError("writer service account cannot access original state")
            for name in ("rounds.sqlite3", "rounds.lock"):
                _existing(directory / name)
                if not os.access(directory / name, os.R_OK | os.W_OK):
                    raise ValueError("writer service account cannot open original journal")
        recheck_inputs()
        from .competition_coordinator_namespace import active_coordinator_view

        view = active_coordinator_view(args.unit)
        if view is not None:
            view.recheck()
        result = {
            "status": "namespace_readiness_passed",
            "service_uid": os.getuid(),
            "service_gid": os.getgid(),
            "supplementary_groups": os.getgroups(),
            "mount_namespace": os.readlink("/proc/self/ns/mnt"),
            "native_coordinator_view": view is not None,
            "original_owner_checked": False,
            "original_locks_acquired": False,
            "original_journals_opened": False,
            "original_services_changed": False,
            "directory_exchange_performed": False,
            "approval_hold_preserved": True,
            "chain_submission_authorized": False,
        }
        await channel.send("complete", result=result)
        return result
    with hold_successor_startup_lease(anchor) as startup:
        async with hold_stopped_standing_writer(
            startup, unit=args.unit, config_path=args.config
        ) as owner:
            # The root can recover an interrupted directory mapping only after
            # this actual original owner is continuously held.
            await channel.send("owned", descriptors=(startup._descriptor,))
            begin = await channel.receive()
            if begin.action == "already_committed":
                begin.validate("already_committed")
                recheck_inputs()
                await owner.recheck()
                result = {
                    "status": "already_selected",
                    "approval_hold_preserved": True,
                    "chain_submission_authorized": False,
                    "legacy_handoff_recheck_required": True,
                }
                await channel.send("complete", result=result)
                return result
            begin.validate("begin")
            async with (
                hold_stopped_writer_journals(owner, series) as journals,
                AsyncExitStack() as resources,
            ):
                resources.enter_context(
                    memory_runtime(
                        config.host_memory_admission,
                        maximum_aggregate_bytes=config.maximum_package_bytes,
                        role="reward_writer",
                    )
                )
                root = journals.root
                imported, exported = await run_owned_thread(
                    selected_proof_archives,
                    Path(config.proof_import_directory),
                    Path(config.proof_export_directory),
                    config.proof_stores,
                )

                def history_reader():
                    return RewardControlHistoryReader(
                        root / "history",
                        control_hotkey=series.control_hotkey,
                        chain_config_sha256=digest(config.chain),
                        first_block=series.recovery.authority.issued_at_block,
                        maximum_bytes=config.maximum_history_bytes,
                        verification_profile=config.service.history_verification,
                        archive=imported,
                        export_archive=exported,
                    )

                original_reader = await run_owned_thread(history_reader)
                control = await run_owned_thread(
                    lambda: StandingRewardControlReader(
                        root / "control",
                        series,
                        config.policy,
                        expected_series_sha256=digest(series),
                        expected_chain_config_sha256=digest(config.chain),
                        maximum_bytes=config.maximum_reader_bytes,
                        reward_adoptions=adoptions.selection,
                    )
                )
                provider = HistoricalRewardControlProvider(
                    config.chain,
                    config.policy,
                    resources=CompetitionChainResources.from_config(config.chain),
                    runtime_proof_reads=config.runtime_proof_reads,
                    historical_header_directory=root / "headers" / digest(config.chain),
                    historical_header_maximum_bytes=config.maximum_header_bytes,
                    historical_header_database_maximum_bytes=config.maximum_header_database_bytes,
                )
                resources.push_async_callback(_close_provider, provider)
                await provider.start()
                await _await_initial_finality(provider)
                exchanged = False
                try:
                    with WorkProgress("writer_directory_selection", 6, unit="checks") as progress:
                        original_tip = await run_owned_thread(
                            retained_completed_tip, original_reader
                        )
                        if original_tip > args.through_block:
                            raise ValueError("candidate would regress original retained history")
                        original = (
                            await run_owned_thread(review_empty_original, original_reader, journals)
                            if original_tip < original_reader.first_block
                            else await restore_completed_prefix(
                                original_reader,
                                provider,
                                through_block=original_tip,
                                maximum_blocks=config.service.maximum_history_blocks,
                                owner=owner,
                            )
                        )
                        progress.advance()
                        if (root / "weights").exists():
                            journal = await run_owned_thread(
                                lambda: StandingWeightJournal(
                                    root / "weights",
                                    series_sha256=digest(series),
                                    validator_hotkey=startup.config.validator_hotkey,
                                    chain_config_sha256=digest(config.chain),
                                    maximum_bytes=config.service.maximum_journal_bytes,
                                )
                            )
                            attempt = await review_stopped_standing_attempt(
                                owner, journal, provider, series=series, journal_owner=journals
                            )
                        else:
                            attempt = {
                                "status": "standing_journal_absent_requires_native_handoff_review",
                                "legacy_handoff_recheck_required": True,
                                "chain_submission_authorized": False,
                            }
                        progress.advance()
                        journals.recheck()
                        recheck_inputs()
                        if original_tip < original_reader.first_block:
                            await run_owned_thread(review_empty_original, original_reader, journals)
                        await channel.send(
                            "original_reviewed",
                            descriptors=tuple(fd for _, fd, _ in journals._locks),
                            original_tip=original_tip,
                            original_checkpoint_owner=original_reader.checkpoints.owner,
                            standing_attempt=attempt,
                        )
                        message = await channel.receive()
                        if message.action == "rolled_back":
                            journals.accept_history_exchange(message)
                            return {"status": "rolled_back"}
                        journals.accept_history_exchange(message)
                        exchanged = True
                        progress.advance()
                        candidate_reader = await run_owned_thread(history_reader)
                        candidate = await restore_completed_prefix(
                            candidate_reader,
                            provider,
                            through_block=args.through_block,
                            maximum_blocks=config.service.maximum_history_blocks,
                            owner=owner,
                        )
                        prefix = (
                            None
                            if original_tip < original_reader.first_block
                            else await candidate_reader.verified_prefix(original_tip)
                        )
                        observation = await candidate_reader.review_control(
                            provider, args.through_block
                        )
                        files = StandingRewardFiles(
                            Path(config.delivery_directory),
                            maximum_package_bytes=config.maximum_package_bytes,
                            maximum_witness_bytes=config.maximum_witness_bytes,
                        )

                        def decisions():
                            values, previous = [], None
                            for write in candidate.writes:
                                if write.decision_sha256 == previous:
                                    continue
                                raw = files.decision(write.decision_sha256)
                                value = SignedRewardControlDecision.model_validate_json(raw)
                                if (
                                    canonical_json_bytes(value) != raw
                                    or digest(value.decision) != write.decision_sha256
                                ):
                                    raise ValueError(
                                        "candidate observed control differs from signed delivery"
                                    )
                                values.append(value)
                                previous = write.decision_sha256
                            return tuple(values)

                        review = await reconcile_stopped_control_history(
                            owner,
                            control,
                            original=original,
                            candidate=candidate,
                            candidate_original_prefix=prefix,
                            observation=observation,
                            decisions=await run_owned_thread(decisions),
                        )
                        progress.advance()
                        journals.recheck()
                        recheck_inputs()
                        reopened = await run_owned_thread(history_reader)
                        if reopened.checkpoints.owner != candidate_reader.checkpoints.owner:
                            raise ValueError("selected history reopen changed owner")
                        await channel.send(
                            "candidate_reviewed",
                            review=review,
                            standing_attempt=attempt,
                            candidate_checkpoint_owner=candidate_reader.checkpoints.owner,
                        )
                        message = await channel.receive()
                        if message.action == "rolled_back":
                            journals.accept_history_exchange(message)
                            return {"status": "rolled_back"}
                        message.validate("committed")
                        progress.advance()
                        journals.recheck()
                        recheck_inputs()
                        await owner.recheck()
                        progress.advance()
                        result = {
                            "status": "selected",
                            "through_block": args.through_block,
                            "history": review,
                            "standing_attempt": attempt,
                            "approval_hold_preserved": True,
                            "chain_submission_authorized": False,
                            "legacy_handoff_recheck_required": True,
                        }
                        await channel.send("complete", result=result)
                        return result
                except BaseException:
                    # Drain failure inside genuine ownership. Root rollback
                    # completes before any original process/journal lock exits.
                    try:
                        await channel.send("failed", exchanged=exchanged)
                        rollback = await channel.receive("rolled_back")
                        journals.accept_history_exchange(rollback)
                    except BaseException:
                        startup.preserve_on_failure()
                    raise
