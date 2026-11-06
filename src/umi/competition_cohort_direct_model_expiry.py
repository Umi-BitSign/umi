"""Retain upload expiry before provider cleanup; resolve admission only after cleanup."""

import sqlite3
import time
from bisect import bisect_right
from functools import partial

from .competition_cohort_direct_model_upload import SignedDirectModelUploadCompletion
from .competition_cohort_participation import CohortParticipationRequest
from .competition_cohort_upload_completion_policy import (
    DirectUploadExpiryIntent,
    DirectUploadExpiryReceipt,
)
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes, sha256_hex


def expiry_state(owner, upload, *, finalized=False):
    """Read retained policy-bound closure; it never authorizes deleting model bytes."""
    with owner.journal.read_transaction() as db:
        raw = owner.journal.get("direct-expiry-intent", upload, db=db)
        receipt_raw = owner.journal.get("direct-expiry-receipt", upload, db=db)
        if raw is None:
            if receipt_raw is not None:
                raise ValueError("upload expiry receipt lacks its original intent")
            return False
        intent = DirectUploadExpiryIntent.model_validate(raw)
        policy = owner.completion_policy
        if (
            policy is None
            or intent.policy_sha256 != digest(policy)
            or intent.upload_sha256 != upload
            or intent.created_at_unix_ms < policy.close_completion_at_unix_ms
        ):
            raise ValueError("retained upload expiry differs from its selected policy")
        terminal = owner.journal.get("direct-completion-expired", intent.reservation_sha256, db=db)
        if intent.completion_sha256 is not None:
            completion = owner.journal.get("direct-completion", intent.reservation_sha256, db=db)
            if completion is None or digest(completion) != intent.completion_sha256:
                raise ValueError("expired accepted completion requires retained metadata repair")
            if terminal != receipt_raw:
                raise ValueError("expired completion recovery marker differs from cleanup receipt")
        elif terminal is not None:
            raise ValueError("unsigned expiry has an unexpected completion recovery marker")
        if receipt_raw is None:
            return not finalized
        receipt = DirectUploadExpiryReceipt.model_validate(receipt_raw)
        if (
            receipt.intent_sha256 != digest(intent)
            or receipt.reservation_sha256 != intent.reservation_sha256
            or receipt.expired_at_unix_ms < intent.created_at_unix_ms
        ):
            raise ValueError("retained upload expiry receipt differs from its intent")
        return True


async def _expire_one(owner, item, *, now_unix_ms, at):
    # Completion, restart and reservation issuance use the same mutex. Requests
    # already accepted into completion retain their recovery path.
    async with owner._mutex:
        if expiry_state(owner, item.upload, finalized=True):
            return "expired"
        attempt = owner._latest_attempt(item.upload)
        if attempt is None:
            raise ValueError("issued upload lost its current attempt")
        reservation = owner._signed_reservation(attempt)
        if reservation is None:
            raw = owner.journal.get("direct-request", item.upload)
            request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(raw))
            reservation = owner.admission_reservation(request)
        key = digest(reservation.reservation)
        if owner.journal.get("direct-object", key) is not None:
            return "completed"
        completion_raw = owner.journal.get("direct-completion", key)
        if completion_raw is not None:
            signed_completion = SignedDirectModelUploadCompletion.model_validate_json(
                canonical_json_bytes(completion_raw)
            )
            # Check the retained miner signature and exact current generation.
            owner._completion(signed_completion)
        provider = owner._provider(attempt)
        if provider is None:
            raise ValueError("unfinished provider identity requires retained metadata repair")
        # No completed provider object may be discarded because local metadata
        # is missing. The signed completion must be restored in that case.
        if await owner.multipart.head(attempt.object_key, at=at) is not None:
            if completion_raw is not None:
                return "completion_pending"
            raise ValueError("completed provider object lacks its signed completion")
        if completion_raw is not None and await owner.multipart.multipart_exists(
            attempt.object_key, upload_id=provider.provider_upload_id, at=at
        ):
            return "completion_pending"
        raw = owner.journal.get("direct-expiry-intent", item.upload)
        expected = {
            "schema": "umi-direct-upload-expiry-intent/1",
            "policy_sha256": digest(owner.completion_policy),
            "reservation_sha256": key,
            "attempt_id": attempt.attempt_id,
            "upload_sha256": item.upload,
            "object_key_sha256": sha256_hex(attempt.object_key.encode()),
            "provider_upload_id_sha256": sha256_hex(provider.provider_upload_id.encode()),
            "completion_sha256": None if completion_raw is None else digest(completion_raw),
        }
        if raw is None:
            intent = DirectUploadExpiryIntent(**expected, created_at_unix_ms=now_unix_ms)
            owner.journal.put("direct-expiry-intent", item.upload, intent)
        else:
            intent = DirectUploadExpiryIntent.model_validate(raw)
            if (
                intent.model_dump(mode="json", by_alias=True, exclude={"created_at_unix_ms"})
                != expected
            ):
                raise ValueError("retained expiry cleanup target changed")
        await owner.multipart.abort(
            attempt.object_key, upload_id=provider.provider_upload_id, at=at
        )
        if await owner.multipart.head(attempt.object_key, at=at) is not None:
            raise ValueError("provider completion raced upload expiry; preserve object for repair")
        if await owner.multipart.multipart_exists(
            attempt.object_key, upload_id=provider.provider_upload_id, at=at
        ):
            raise OSError("provider multipart cleanup is not yet complete")
        receipt = DirectUploadExpiryReceipt(
            schema="umi-direct-upload-expiry-receipt/1",
            intent_sha256=digest(intent),
            reservation_sha256=key,
            expired_at_unix_ms=now_unix_ms,
        )
        records = [("direct-expiry-receipt", item.upload, receipt)]
        if completion_raw is not None:
            records.append(("direct-completion-expired", key, receipt))
        owner.journal.put_many(records)
        return "expired"


async def expire_selected_uploads(owner, selected, *, now_unix_ms, at, report=None):
    """Bound remote cleanup; leave accepted completions and unavailable evidence pending."""
    policy = owner.completion_policy
    if policy is None:
        return {}
    started = time.monotonic()
    cutoff = policy.close_completion_at_unix_ms
    expired = attempted = completing = retrying = repairs = 0
    last_error = None

    def progress():
        pending = len(selected) - expired
        value = {
            "upload_expiry_total": len(selected),
            "upload_expiry_completed": expired,
            "upload_expiry_pending": pending,
            "upload_expiry_attempted": attempted,
            "upload_expiry_accepted_completions": completing,
            "upload_expiry_retrying": retrying,
            "upload_expiry_repair_required": bool(repairs),
            "upload_expiry_error_type": last_error,
            "upload_completion_deadline_unix_ms": cutoff,
            "upload_expiry_elapsed_seconds": round(time.monotonic() - started, 3),
            "upload_expiry_eta_seconds": 0
            if not pending
            else (max(0, cutoff - now_unix_ms) / 1000 if now_unix_ms < cutoff else None),
            "upload_expiry_eta_basis": "complete"
            if not pending
            else (
                "operator_grace_remaining"
                if now_unix_ms < cutoff
                else "provider_cleanup_or_accepted_completion_pending"
            ),
            "upload_expiry_eta_scope": "selected_unfinished_upload_cleanup_only",
            "upload_expiry_stalled_or_retrying": bool(pending and now_unix_ms >= cutoff),
        }
        if report is not None:
            report({"active_object_stage": "upload_expiry", **value})
        return value

    progress()
    if now_unix_ms < cutoff:
        return progress()
    if owner.selection_authority(owner.config.cohort_sha256) != digest(policy.admission_deadline):
        raise ValueError("upload expiry authority changed; selected policy requires repair")
    after = await run_owned_thread(partial(owner.journal.poll_cursor, expiry=True))
    split = bisect_right([item.upload for item in selected], after)
    selected = selected[split:] + selected[:split]
    for item in selected:
        if await run_owned_thread(owner.upload_expired, item.upload):
            expired += 1
            continue
        if attempted >= owner.config.cleanup_batch_size:
            continue
        attempted += 1
        await run_owned_thread(partial(owner.journal.advance_poll_cursor, item.upload, expiry=True))
        progress()
        try:
            state = await _expire_one(owner, item, now_unix_ms=now_unix_ms, at=at)
        except ValueError as error:
            repairs += 1
            last_error = type(error).__name__
        except (OSError, RuntimeError, sqlite3.Error) as error:
            retrying += 1
            last_error = type(error).__name__
        else:
            if state in ("expired", "completed"):
                expired += 1
            else:
                attempted -= 1  # Accepted completion lookup performed no provider work.
                completing += 1
        progress()
    return progress()
