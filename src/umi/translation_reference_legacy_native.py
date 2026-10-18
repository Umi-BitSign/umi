"""Native stopped v2 bridge reconciliation with per-attempt durable reuse.

The original bridge files never change. Completion metadata belongs to the new
follower owner and cannot grant independent cohort certification or permission
to retry an old transaction. Unknown v1 effects retain their separate drain gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from functools import partial

from pydantic import Field, model_validator

from .bridge.receipts import BridgeReceiptReader
from .bridge.transactions import RegistrationBridgeTransactionJournal
from .competition_bridge_reconciliation import (
    bridge_outcomes_match_current_state,
    summarize_bridge_outcome,
)
from .competition_bridge_recovery import JOURNAL, audit_bridge_history
from .competition_recovery_models import BridgeRecoveryOutcome
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import ensure_private_directory, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .translation_reference_legacy_state import NATIVE_V2_RULE, _file_identity
from .translation_reference_state import TranslationReferenceError, _row

_MAXIMUM_METADATA_BYTES = 32 * 1024
_MAXIMUM_OUTCOMES = 4096
_DIRECTORY = "legacy-native-verification"
_CONTEXT_SCHEMA = "umi-reference-original-v2-outcome-context/1"


class NativeLegacyOutcomeRecord(StrictProtocolModel):
    schema_: str = Field(alias="schema")
    context_json: str
    outcome: BridgeRecoveryOutcome
    checksum: Hex32

    @model_validator(mode="after")
    def integrity(self):
        if self.checksum != digest(
            {
                "context_json": self.context_json,
                "outcome": self.outcome.model_dump(mode="json", by_alias=True),
            }
        ):
            raise ValueError("native legacy outcome checksum requires restoration")
        return self


class NativeLegacyOutcomeCompletion(StrictProtocolModel):
    schema_: str = Field(alias="schema")
    context_sha256: Hex32
    result_sha256: Hex32


def _context(lease, *, path, files, hotkey, semantics):
    lease.require_owner()
    if path not in files or path not in lease._initial:
        raise TranslationReferenceError("reference_legacy_outcome_source_missing")
    return {
        "schema": _CONTEXT_SCHEMA,
        "root_identity": lease._root_identity,
        "file_identity": lease._initial[path],
        "path": path,
        "journal_sha256": hashlib.sha256(files[path]).hexdigest(),
        "validator_account": identity(hotkey),
        "verifier_semantics_sha256": semantics,
    }


class NativeLegacyOutcomeStore:
    """Small independent verdicts; no copying of old or live SQLite state."""

    def __init__(self, lease):
        self.lease = lease
        self.directory = lease.follower_root / _DIRECTORY
        ensure_private_directory(self.directory)

    def _paths(self, context):
        key = digest(context)
        return key, self.directory / (key + ".json"), self.directory / (key + ".complete")

    def load(self, context):
        self.lease.require_owner()
        key, result_path, completion_path = self._paths(context)
        record = completion = None
        try:
            if result_path.exists():
                record = read_private_model(
                    result_path, NativeLegacyOutcomeRecord, maximum_bytes=_MAXIMUM_METADATA_BYTES
                )
            if completion_path.exists():
                completion = read_private_model(
                    completion_path, NativeLegacyOutcomeCompletion, maximum_bytes=1024
                )
            if record is None and completion is None:
                return None
            if (
                record is None
                or completion is None
                or record.schema_ != "umi-reference-native-legacy-outcome/1"
                or record.context_json != canonical_json_bytes(context).decode()
                or completion.schema_ != "umi-reference-native-legacy-completion/1"
                or completion.context_sha256 != key
                or completion.result_sha256 != digest(record)
                or record.outcome.path != context["path"]
                or record.outcome.journal_sha256 != context["journal_sha256"]
            ):
                raise ValueError("legacy verification metadata is missing or damaged")
        except (OSError, ValueError, TypeError) as error:
            raise TranslationReferenceError(
                "reference_legacy_outcome_verification_repair_required"
            ) from error
        self.lease.require_owner()
        return record.outcome

    def remember(self, context, outcome):
        self.lease.require_owner()
        key, result_path, completion_path = self._paths(context)
        if outcome.path != context["path"] or outcome.journal_sha256 != context["journal_sha256"]:
            raise TranslationReferenceError("reference_legacy_outcome_source_changed")
        record = NativeLegacyOutcomeRecord(
            schema="umi-reference-native-legacy-outcome/1",
            context_json=canonical_json_bytes(context).decode(),
            outcome=outcome,
            checksum=digest(
                {
                    "context_json": canonical_json_bytes(context).decode(),
                    "outcome": outcome.model_dump(mode="json", by_alias=True),
                }
            ),
        )
        publish_private_model(result_path, record, maximum_bytes=_MAXIMUM_METADATA_BYTES)
        publish_private_model(
            completion_path,
            NativeLegacyOutcomeCompletion(
                schema="umi-reference-native-legacy-completion/1",
                context_sha256=key,
                result_sha256=digest(record),
            ),
            maximum_bytes=1024,
        )
        self.lease.require_owner()

    def repair_completions(self, *, hotkey):
        """Restore only completion markers from unchanged original verdicts."""
        started = time.monotonic()
        self.lease._emit("reference_legacy_outcome_repair_owner", 0, 1, started)
        try:
            self._repair_completions(hotkey=hotkey)
        except BaseException:
            self.lease._emit("reference_legacy_outcome_repair_owner", 0, 1, started, retrying=True)
            raise
        self.lease._emit("reference_legacy_outcome_repair_owner", 1, 1, started)

    def _repair_completions(self, *, hotkey):
        self.lease.require_owner()
        files = self.lease.capture_files()
        paths = []
        for index, path in enumerate(self.directory.iterdir(), 1):
            if index > 2 * _MAXIMUM_OUTCOMES + 17:
                raise TranslationReferenceError("reference_legacy_outcome_metadata_capacity")
            if path.name.startswith(".pending-complete-"):
                _file_identity(path)
                if path.stat().st_size > 1024:
                    raise TranslationReferenceError(
                        "reference_legacy_outcome_unclassified_metadata"
                    )
                # Only this explicit repair creates these temporary names. The
                # original service mutex is held, and no consumer opens them.
                path.unlink()
                continue
            if path.name == ".publish.lock":
                _file_identity(path)
                if path.stat().st_size:
                    raise TranslationReferenceError(
                        "reference_legacy_outcome_unclassified_metadata"
                    )
                continue
            if path.suffix not in {".json", ".complete"}:
                raise TranslationReferenceError("reference_legacy_outcome_unclassified_metadata")
            if path.suffix == ".json":
                paths.append(path)
            elif not path.with_suffix(".json").exists():
                raise TranslationReferenceError("reference_legacy_outcome_restore_required")
        started = time.monotonic()
        self.lease._emit("reference_legacy_outcome_metadata_repair", 0, len(paths), started)
        for count, path in enumerate(sorted(paths), 1):
            record = read_private_model(
                path, NativeLegacyOutcomeRecord, maximum_bytes=_MAXIMUM_METADATA_BYTES
            )
            context = json.loads(record.context_json)
            expected = _context(
                self.lease,
                path=record.outcome.path,
                files=files,
                hotkey=hotkey,
                semantics=context["verifier_semantics_sha256"],
            )
            if (
                record.schema_ != "umi-reference-native-legacy-outcome/1"
                or context != expected
                or record.context_json != canonical_json_bytes(expected).decode()
                or path.stem != digest(expected)
                or record.outcome.journal_sha256 != expected["journal_sha256"]
            ):
                raise TranslationReferenceError("reference_legacy_outcome_restore_required")
            completion = NativeLegacyOutcomeCompletion(
                schema="umi-reference-native-legacy-completion/1",
                context_sha256=digest(expected),
                result_sha256=digest(record),
            )
            self._replace_completion(path.with_suffix(".complete"), completion)
            self.lease._emit("reference_legacy_outcome_metadata_repair", count, len(paths), started)
        self.lease.require_owner()

    def _replace_completion(self, path, value):
        """Explicit atomic derived repair; the original verdict is untouched."""
        self.lease.require_owner()
        if path.exists() or path.is_symlink():
            _file_identity(path)
        raw = canonical_json_bytes(value)
        if len(raw) > 1024:
            raise ValueError("reference legacy completion exceeds its metadata bound")
        descriptor, temporary = tempfile.mkstemp(prefix=".pending-complete-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


@dataclass(frozen=True)
class _NativeLegacyCurrent:
    block: int
    block_hash: str
    validator_uid: int
    validator_last_update: int
    validator_row: tuple


async def approve_native_legacy(
    lease,
    state,
    policy,
    journal,
    *,
    receipts: BridgeReceiptReader,
    verifier_semantics_sha256,
    now,
):
    cached = await run_owned_thread(
        partial(
            lease.cached_approval,
            state,
            journal,
            verifier_semantics_sha256=verifier_semantics_sha256,
        )
    )
    if cached is not None:
        return cached
    files = await run_owned_thread(lease.capture_files)
    # Keep the existing v1/fresh route and its exact compatibility semantics.
    if JOURNAL not in files:
        return await run_owned_thread(
            partial(
                lease.approve,
                state,
                policy,
                journal,
                verifier_semantics_sha256=verifier_semantics_sha256,
                now=now,
            )
        )
    audit = await run_owned_thread(partial(audit_bridge_history, files, hotkey=journal.hotkey))
    allowed = set(audit.recognized) | {"service.lock"}
    if "journal.json" in files:
        allowed.add("journal.json")
    if set(files) - allowed:
        raise TranslationReferenceError("reference_legacy_unclassified_state")
    versioned = [
        (p, j) for p, j in audit.attempts if type(j) is RegistrationBridgeTransactionJournal
    ]
    if not versioned:
        return await run_owned_thread(
            partial(
                lease.approve,
                state,
                policy,
                journal,
                verifier_semantics_sha256=verifier_semantics_sha256,
                now=now,
            )
        )
    if len(versioned) > _MAXIMUM_OUTCOMES or set(audit.holds) - {
        "registration_bridge_transaction_proof_required",
    }:
        raise TranslationReferenceError("reference_legacy_native_recovery_required")
    store = await run_owned_thread(NativeLegacyOutcomeStore, lease)
    started, outcomes = time.monotonic(), []

    def emit(*, retrying=False):
        remaining = len(versioned) - len(outcomes)
        span = max(
            (
                state.signing.runtime.snapshot.block_number - original.attempt.preflight_block
                for _, original in versioned[:remaining]
            ),
            default=0,
        )
        lease._emit(
            "reference_legacy_native_attempts",
            len(outcomes),
            len(versioned),
            started,
            retrying=retrying,
            eta_seconds=0 if not remaining and not retrying else None,
            planning_seconds=None
            if not remaining or retrying
            else [
                max(1, int(span * 0.05 + remaining * 5)),
                max(1, int(span * 4 + remaining * 120)),
            ],
            eta_basis="planning: 0.05-2s per ancestor, up to two walks plus 5-120s per "
            "attempt; current RPC rate unmeasured; retries and chain growth extend range",
            remaining_attempts=remaining,
            ancestor_span_blocks=span,
            calibrated=False,
        )

    emit()
    try:
        # The common native receipt reader resumes backwards hash walks. Visit
        # newest first and checkpoint each completed attempt independently.
        for path, original in reversed(versioned):
            context = _context(
                lease,
                path=path,
                files=files,
                hotkey=journal.hotkey,
                semantics=verifier_semantics_sha256,
            )
            result = await run_owned_thread(store.load, context)
            if result is None:
                proven = None
                if (
                    original.phase
                    in {"submitting", "outcome_unknown", "receipt_returned", "applied", "failed"}
                    and original.signed_extrinsic is not None
                ):
                    proven = await receipts.find(original)
                if proven is None:
                    if original.phase in {"applied", "failed", "receipt_returned"}:
                        raise TranslationReferenceError("reference_legacy_native_receipt_pending")
                    proven = await receipts.expiry(original)
                lease.require_owner()
                result = summarize_bridge_outcome(path, original, proven)
                await run_owned_thread(store.remember, context, result)
            outcomes.append(result)
            emit()
        if any(
            o.verified_head_block > state.signing.runtime.snapshot.block_number for o in outcomes
        ):
            raise TranslationReferenceError(
                "reference_legacy_native_observation_behind_completed_proofs"
            )
        decision = state.decision(policy, now=now)
        own = next(
            r
            for r in state.rows.reads
            if r.spec.item == "Weights" and r.spec.params == (78, decision.writer_uid)
        )
        raw_row = state.signing.runtime.decode_storage(
            own.spec.pallet, own.spec.item, own.raw_value
        )
        current = _NativeLegacyCurrent(
            state.signing.runtime.snapshot.block_number,
            state.signing.runtime.snapshot.block_hash,
            decision.writer_uid,
            decision.writer_last_update,
            _row(raw_row) if raw_row else (),
        )
        if not bridge_outcomes_match_current_state(audit, tuple(outcomes), current):
            raise TranslationReferenceError("reference_legacy_native_current_state_changed")
        inspection = {
            "status": "native_v2_bridge_bound_to_current_state",
            "retained_files_sha256": digest(
                {n: hashlib.sha256(raw).hexdigest() for n, raw in sorted(files.items())}
            ),
            "terminal_attempts": len(audit.attempts),
            "native_v2_attempts": len(outcomes),
            "observed_block": current.block,
            "last_weight_update": current.validator_last_update,
        }
        await run_owned_thread(
            partial(
                lease.retain_approval,
                state,
                journal,
                inspection,
                verifier_semantics_sha256=verifier_semantics_sha256,
                rule=NATIVE_V2_RULE,
            )
        )
        return inspection
    except BaseException:
        emit(retrying=True)
        raise
