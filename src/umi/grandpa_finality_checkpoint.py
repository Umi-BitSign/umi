"""Drain completed WAL frames under the existing finality mutation owner."""

import json
import logging
import time
from pathlib import Path

# A maintenance trigger, not a new evidence or database capacity limit.
CHECKPOINT_BYTES = 4 * 1024**2
# Existing miner/validator entrypoints configure this parent explicitly.
_LOGGER = logging.getLogger("umi.grandpa_finality_supervisor.checkpoint")


def checkpoint_wal(connection, database):
    """Try without waiting for readers; the caller publishes the final identity.

    All keeper read transactions must have ended, but a read-only connection
    must remain open until the writer closes. Otherwise SQLite can checkpoint
    after the caller has retained its file-bound audit completion.
    """
    wal = Path(str(database) + "-wal")
    if not wal.exists() or wal.stat().st_size < CHECKPOINT_BYTES:
        return
    wal_bytes = wal.stat().st_size
    started = time.monotonic()
    event = dict(
        schema="umi-finality-wal-maintenance/1",
        stage="finality_wal_checkpoint",
        status="running",
        completed=0,
        total=1,
        unit="checkpoints",
        wal_bytes_before=wal_bytes,
        elapsed_seconds=0,
        eta_seconds=None,
        planning_eta_seconds=[1, 300],
        eta_basis="planning_local_checkpoint_io_excludes_reader_wait",
        stalled_or_retrying=False,
    )
    _LOGGER.info(json.dumps(event, separators=(",", ":")))
    timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
    try:
        connection.execute("PRAGMA busy_timeout=0")
        busy, frames, copied = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    except BaseException as error:
        event.update(
            status="retrying",
            elapsed_seconds=time.monotonic() - started,
            planning_eta_seconds=None,
            eta_basis="checkpoint_failed_native_owner_must_resolve_before_reuse",
            error_type=type(error).__name__,
            stalled_or_retrying=True,
        )
        _LOGGER.info(json.dumps(event, separators=(",", ":")))
        raise
    finally:
        connection.execute(f"PRAGMA busy_timeout={timeout}")
    event.update(
        status="retrying" if busy else "completed",
        completed=0 if busy else 1,
        wal_bytes_after=wal.stat().st_size,
        wal_frames=frames,
        checkpointed_frames=copied,
        elapsed_seconds=time.monotonic() - started,
        eta_seconds=None if busy else 0,
        planning_eta_seconds=None,
        eta_basis="active_reader_or_checkpoint_owner_retry_on_next_native_mutation"
        if busy
        else "completed_owned_checkpoint",
        stalled_or_retrying=bool(busy),
    )
    _LOGGER.info(json.dumps(event, separators=(",", ":")))
