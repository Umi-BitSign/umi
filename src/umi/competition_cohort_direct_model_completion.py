"""Resume miner-signed multipart completions through the standing upload owner."""

import sqlite3
import time
from bisect import bisect_right
from functools import partial

from .competition_cohort_direct_model_attempts import DirectModelAttemptRepairRequired
from .competition_cohort_direct_model_upload import SignedDirectModelUploadCompletion
from .concurrency import run_owned_thread
from .protocol import canonical_json_bytes


async def recover_requested_completions(owner, *, now_unix_ms, report=None):
    """Recover a bounded batch, preserving the existing completion and verification gates."""
    started = time.monotonic()
    journal = owner.journal
    keys = await run_owned_thread(journal.pending_completion_keys)
    after = await run_owned_thread(partial(journal.poll_cursor, completion=True))
    split = bisect_right(keys, after)
    keys = keys[split:] + keys[:split]
    attempted = completed = retrying = repairs = 0
    error_type = None

    def progress():
        pending = len(keys) - completed
        elapsed = time.monotonic() - started
        value = {
            "completion_recovery_total": len(keys),
            "completion_recovery_attempted": attempted,
            "completion_recovery_completed": completed,
            "completion_recovery_pending": pending,
            "completion_recovery_retrying": retrying,
            "completion_recovery_repair_required": bool(repairs),
            "completion_recovery_error_type": error_type,
            "completion_recovery_elapsed_seconds": round(elapsed, 3),
            "completion_recovery_eta_seconds": (
                0
                if not pending
                else elapsed / completed * pending
                if completed and not retrying and not repairs
                else None
            ),
            "completion_recovery_eta_basis": (
                "complete"
                if not pending
                else "measured_current_batch_rate"
                if completed and not retrying and not repairs
                else "awaiting_successful_provider_completion_or_metadata_repair"
            ),
            "completion_recovery_scope": "retained_signed_completion_requests_only",
        }
        if report is not None:
            report({"active_object_stage": "completion_recovery", **value})
        return value

    progress()
    for key in keys[: owner.config.verification_batch_size]:
        # This scheduling hint is separate from verification rotation. Advancing
        # before I/O lets another pending completion run after a crash or retry.
        await run_owned_thread(partial(journal.advance_poll_cursor, key, completion=True))
        attempted += 1
        progress()
        try:
            raw = await run_owned_thread(journal.get, "direct-completion", key)
            if raw is None:
                raise DirectModelAttemptRepairRequired("retained completion disappeared")
            signed = SignedDirectModelUploadCompletion.model_validate_json(
                canonical_json_bytes(raw)
            )
            if signed.completion.reservation_sha256 != key:
                raise DirectModelAttemptRepairRequired("retained completion identity changed")
            await owner.complete(signed, now_unix_ms=now_unix_ms)
        except (DirectModelAttemptRepairRequired, ValueError) as error:
            repairs += 1
            error_type = type(error).__name__
        except (OSError, RuntimeError, sqlite3.Error) as error:
            retrying += 1
            error_type = type(error).__name__
        else:
            completed += 1
        progress()
    return progress()
