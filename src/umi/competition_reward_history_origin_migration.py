"""Preserve installed342 successful block exports under a local origin contract.

This command performs no signing, publication or chain transaction. It preserves
the old raw journal in place, installs normal durable per-block results, and
requires the ordinary history reader to check ordered effects and fresh finality.
Missing/changed completed records require explicit native repair, never replayed
silently. An interrupted first migration resumes only remaining blocks.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import suppress
from pathlib import Path

from . import competition_reward_admission_provenance as provenance
from .competition_reward_admission_provenance import (
    open_existing_owner_locks,
    validate_provenance,
)
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_checkpoint import ABI, HistoryCheckpointRepairRequired
from .competition_reward_history_origin import (
    REASON,
    load_original_export_origin,
    read_original_export,
    retain_original_export_origin,
)
from .competition_reward_history_projection import OriginalHistoryProjection
from .competition_reward_proof_archive import RewardProofArchive

logger = logging.getLogger(__name__)


def _report(*, done, total, started, state, restored, last_changed):
    with suppress(Exception):
        elapsed = time.monotonic() - started
        fresh = done - restored
        rate = fresh / elapsed if fresh >= 8 and elapsed > 0 else None
        logger.info(
            "reward_history_origin_migration_progress %s",
            {
                "stage": "original_successful_export_semantic_migration",
                "state": state,
                "completed_blocks": done,
                "total_blocks": total,
                "percent": 100.0 * done / total,
                "restored_blocks": restored,
                "elapsed_seconds": elapsed,
                "since_last_progress_seconds": time.monotonic() - last_changed,
                "eta_seconds": 0
                if state == "completed"
                else (total - done) / rate
                if rate and state in {"running", "completed"}
                else None,
                "planning_eta_seconds": [(total - done) * 0.04, (total - done) * 0.25]
                if not rate and state == "running"
                else None,
                "eta_basis": "complete"
                if state == "completed"
                else "measured_new_blocks_per_wall_second_including_restore_and_checkpoints"
                if rate and state in {"running", "completed"}
                else "planning_four_local_samples_plus_unmeasured_checkpoint_cost"
                if not rate and state == "running"
                else "withdrawn_repair_or_retry_required",
                "eta_scope": "local_migration_excludes_finality_admission_and_rewards",
                "aggregate_completion_claimed": False,
            },
        )


def migrate_original_export_history(
    origin_path: Path,
    *,
    maximum_history_bytes: int,
    maximum_blocks: int | None = None,
    progress=None,
):
    """Run only after the original owner drains; caller provisions local capacity.

    ``maximum_blocks`` bounds one invocation without expiring its checkpoints.
    It does not reduce the selected interval. ``progress`` receives completed
    counts after atomic commits, permitting a cooperative caller to stop safely.
    """
    started = last_changed = time.monotonic()
    done = restored = total = 0
    stop = threading.Event()
    heartbeat = None
    if maximum_blocks is not None and (type(maximum_blocks) is not int or maximum_blocks < 1):
        raise ValueError("migration work window must be positive")
    try:
        origin, selected = load_original_export_origin(Path(origin_path))
        total = origin["through_block"] - origin["first_block"] + 1

        def pulse():
            while not stop.wait(30):
                _report(
                    done=done,
                    total=total,
                    started=started,
                    state="stalled" if time.monotonic() - last_changed > 60 else "running",
                    restored=restored,
                    last_changed=last_changed,
                )

        heartbeat = threading.Thread(
            target=pulse, name="original-history-migration-progress", daemon=True
        )
        heartbeat.start()
        _report(
            done=0,
            total=total,
            started=started,
            state="running",
            restored=0,
            last_changed=last_changed,
        )
        with open_existing_owner_locks(selected):
            validate_provenance(selected, require_stopped=True)
            # Only stopped original ownership may initialize mutation identities.
            history = RewardControlHistoryReader(
                Path(selected["paths"]["history_root"]),
                control_hotkey=selected["control_hotkey"],
                chain_config_sha256=selected["chain_config_sha256"],
                first_block=selected["first_block"],
                maximum_bytes=maximum_history_bytes,
                export_archive=RewardProofArchive(Path(origin["export_root"])),
            )
            origin_key = retain_original_export_origin(history.journal, origin)
            database = None

            def record(kind, key):
                value = history.journal.get(kind, key, db=database)
                if value is None:
                    raise HistoryCheckpointRepairRequired("original history source is missing")
                return value

            def revision(kind, key):
                row = database.execute(
                    "SELECT revision,present FROM history_source_identity WHERE kind=? AND id=?",
                    (kind, key),
                ).fetchone()
                if row is None or row[1] != 1:
                    raise HistoryCheckpointRepairRequired("original source identity is missing")
                return row[0]

            projection = OriginalHistoryProjection(record, identity=revision)
            # The source config is root-sealed and byte-exact. Its finality tool
            # identity is context only; fresh finality remains the reader's job.
            config = json.loads(Path(selected["configuration"]["path"]).read_bytes())
            chain = config["chain"]
            finality_sha = chain["finality_pin"]["release_sha256_by_target"][chain["target_triple"]]
            committed = 0
            for height in range(origin["first_block"], origin["through_block"] + 1):
                prior = history.checkpoints.load(height)
                if prior is not None:
                    if prior["repair"] != {"reason": REASON, "operation": origin_key}:
                        raise HistoryCheckpointRepairRequired(
                            "migration overlaps another verified owner result"
                        )
                    restored += 1
                else:
                    if maximum_blocks is not None and committed >= maximum_blocks:
                        break
                    exported, stamp = read_original_export(origin, selected, height)
                    with history.journal.read_transaction() as db:
                        database = db
                        facts = projection.derive(
                            height,
                            exported,
                            hotkey=selected["control_hotkey"],
                            chain_sha256=selected["chain_config_sha256"],
                            finality_sha256=finality_sha,
                        )
                        sources = history.checkpoints.sources(projection.keys, db)
                    database = None
                    repeated, repeated_stamp = read_original_export(origin, selected, height)
                    if repeated != exported or repeated_stamp != stamp:
                        raise HistoryCheckpointRepairRequired(
                            "original export changed during semantic reconstruction"
                        )
                    for seal in (origin["_seal"], selected["_seal"]):
                        actual = provenance._metadata(
                            seal["path"], owner=provenance._ROOT_UID, immutable=True
                        )
                        if actual != {k: v for k, v in seal.items() if k != "sha256"}:
                            raise HistoryCheckpointRepairRequired(
                                "original export selection changed during migration"
                            )
                    value = {
                        "schema": ABI,
                        "owner": history.checkpoints.owner,
                        "semantics": history.checkpoints.semantics,
                        **facts,
                        "sources": sources,
                        "exports": [history._export_identity()],
                        "repair": {"reason": REASON, "operation": origin_key},
                    }
                    history.checkpoints.remember(value)
                    committed += 1
                done += 1
                last_changed = time.monotonic()
                if progress is not None:
                    progress(
                        {
                            "completed_blocks": done,
                            "total_blocks": total,
                            "height": height,
                            "restored_blocks": restored,
                        }
                    )
                if done == total or done % 32 == 0:
                    _report(
                        done=done,
                        total=total,
                        started=started,
                        state="running",
                        restored=restored,
                        last_changed=last_changed,
                    )
            _report(
                done=done,
                total=total,
                started=started,
                state="completed" if done == total else "checkpointed",
                restored=restored,
                last_changed=last_changed,
            )
            return {
                "status": "semantic_checkpoints_complete" if done == total else "checkpointed",
                "completed_blocks": done,
                "total_blocks": total,
                "restored_blocks": restored,
                "elapsed_seconds": time.monotonic() - started,
                "origin_sha256": origin_key,
                "aggregate_completion_claimed": False,
                "next_action": "native_ordered_history_restore_and_fresh_boundary_review_required",
            }
    except (OSError, ValueError, KeyError, TypeError, sqlite3.DatabaseError) as error:
        if total:
            _report(
                done=done,
                total=total,
                started=started,
                state="repair_required",
                restored=restored,
                last_changed=last_changed,
            )
        if isinstance(error, HistoryCheckpointRepairRequired):
            raise
        raise HistoryCheckpointRepairRequired(
            "original export migration requires explicit repair"
        ) from error
    except BaseException:
        if total:
            _report(
                done=done,
                total=total,
                started=started,
                state="retrying",
                restored=restored,
                last_changed=last_changed,
            )
        raise
    finally:
        stop.set()
        if heartbeat is not None:
            heartbeat.join(timeout=5)
