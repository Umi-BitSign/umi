"""Inspect a legacy bridge handoff without rewriting its retained journals.

Only a fully accounted, terminal v1 bridge history can use this path. Native
v2 reconciliation and older explicit bootstrap migration retain their existing
recovery requirements. An uncertain record never becomes safe from row equality.
The caller must hold the original service lock and preserve the inspected bytes;
this pure inspection does not issue a stopped-host or signing capability.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from .bridge.journal import RegistrationBridgeJournal
from .competition_bridge_recovery import JOURNAL, audit_bridge_history
from .protocol import canonical_json_bytes
from .translation_reference_policy import TranslationReferencePolicy
from .translation_reference_state import TranslationReferenceError, TranslationReferenceState, _row


@dataclass(frozen=True, slots=True)
class TranslationLegacyInspection:
    retained_files_sha256: str
    terminal_attempts: int
    last_weight_update: int
    observed_block: int
    chain_submission_authorized: bool = False


def inspect_translation_legacy(
    files: dict[str, bytes],
    state: TranslationReferenceState,
    policy: TranslationReferencePolicy,
    *,
    now: datetime,
) -> TranslationLegacyInspection:
    """Bind the latest completed bridge result to this fresh native own row.

    Historical receipt claims remain historical. Current native state proves
    the latest selected row and LastUpdate; it does not re-sign or renew any
    old policy. All archived phase ordering and prior-LastUpdate links still
    undergo the common bridge audit.
    """
    decision = state.decision(policy, now=now)
    if JOURNAL not in files:
        raise TranslationReferenceError("reference_legacy_layout_requires_supported_recovery")
    if files.get("service.lock", b"") != b"":
        raise TranslationReferenceError("reference_legacy_lock_not_empty")
    audit = audit_bridge_history(files, hotkey=state.signing.validator_hotkey)
    allowed = set(audit.recognized) | {"service.lock"}
    # The common bootstrap journal is already bound byte-for-byte to its bridge
    # archive by audit_bridge_history. No old file is deleted or rewritten.
    if "journal.json" in files:
        allowed.add("journal.json")
    if set(files) - allowed:
        raise TranslationReferenceError("reference_legacy_unclassified_state")
    if audit.holds:
        raise TranslationReferenceError("reference_legacy_native_recovery_required")
    current = audit.current
    if type(current) is not RegistrationBridgeJournal or current.phase != "applied":
        raise TranslationReferenceError("reference_legacy_terminal_receipt_required")
    runtime = state.signing.runtime
    block = runtime.snapshot.block_number
    if block < current.last_observed_block or (
        block == current.last_observed_block
        and runtime.snapshot.block_hash != current.last_observed_block_hash
    ):
        raise TranslationReferenceError("reference_legacy_observation_rollback")
    if decision.writer_last_update != current.weight_call.block_number:
        raise TranslationReferenceError("reference_legacy_current_update_changed")
    own = next(
        item
        for item in state.rows.reads
        if item.spec.item == "Weights" and item.spec.params == (78, decision.writer_uid)
    )
    native_row = _row(runtime.decode_storage(own.spec.pallet, own.spec.item, own.raw_value))
    if native_row != tuple(map(tuple, current.attempt.expected_row)):
        raise TranslationReferenceError("reference_legacy_current_row_changed")
    identity = hashlib.sha256(
        canonical_json_bytes(
            {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}
        )
    ).hexdigest()
    return TranslationLegacyInspection(
        identity,
        len(audit.attempts),
        current.weight_call.block_number,
        block,
    )
