"""Read-only audit of retained registration-bridge attempts.

These are historical local claims, not chain proofs or submission authority.
The caller must separately prove the latest row with owned finalized storage.
An uncertain attempt remains unresolved even when a matching row is visible.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .encoding import account_id32
from .protocol import canonical_json_bytes
from .registration_bridge import (
    MAX_HISTORY_FILES,
    RegistrationBridgeJournal,
)
from .simple_bootstrap_validator import SimpleBootstrapJournal

JOURNAL = "registration-bridge-journal.json"
ARCHIVE = "registration-bridge-legacy-journal.json"
HISTORY = "registration-bridge-history"


@dataclass(frozen=True)
class BridgeHistoryAudit:
    current: RegistrationBridgeJournal
    attempts: tuple[tuple[str, RegistrationBridgeJournal], ...]
    recognized: frozenset[str]
    holds: tuple[str, ...]


def _model(raw: bytes, model):
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("bridge recovery record is not canonical")
    return value


def audit_bridge_history(files: dict[str, bytes], *, hotkey: str) -> BridgeHistoryAudit:
    current = _model(files[JOURNAL], RegistrationBridgeJournal)
    if account_id32(current.validator_hotkey) != account_id32(hotkey):
        raise ValueError("bridge recovery journal belongs to another validator")
    recognized = {JOURNAL}
    legacy = files.get("journal.json")
    if files.get(ARCHIVE) != legacy or current.legacy_journal_sha256 != (
        hashlib.sha256(legacy).hexdigest() if legacy is not None else None
    ):
        raise ValueError("bridge recovery legacy archive or digest changed")
    prior_receipt = None
    prior_observation = 0
    if legacy is not None:
        old = _model(legacy, SimpleBootstrapJournal)
        if (
            account_id32(old.validator_hotkey) != account_id32(hotkey)
            or old.phase != "applied"
            or old.weight_call is None
        ):
            raise ValueError("bridge recovery legacy handoff is not terminal")
        prior_receipt = old.weight_call.block_number
        prior_observation = max(old.observation_block or 0, prior_receipt)
        recognized.add(ARCHIVE)
    groups: dict[str, dict[str, RegistrationBridgeJournal]] = {}
    history_count = 0
    for path, raw in files.items():
        if not path.startswith(HISTORY + "/"):
            continue
        history_count += 1
        if history_count > MAX_HISTORY_FILES:
            raise ValueError("bridge recovery history exceeds its bound")
        item = _model(raw, RegistrationBridgeJournal)
        if (
            item.attempt is None
            or path != f"{HISTORY}/{item.attempt.attempt_id}-{item.phase}.json"
            or item.validator_hotkey != current.validator_hotkey
            or item.legacy_journal_sha256 != current.legacy_journal_sha256
            or item.last_observed_block > current.last_observed_block
            or (
                item.last_observed_block == current.last_observed_block
                and item.last_observed_block_hash != current.last_observed_block_hash
            )
        ):
            raise ValueError("bridge recovery history identity or finality changed")
        groups.setdefault(item.attempt.attempt_id, {})[item.phase] = item
        recognized.add(path)
    if current.attempt is None:
        if groups:
            raise ValueError("bridge recovery current journal rolled back to idle")
        return BridgeHistoryAudit(current, (), frozenset(recognized), ())
    if current.attempt.attempt_id not in groups:
        raise ValueError("bridge recovery current attempt history is missing")
    records = []
    holds = set()
    order = {"submitting": 0, "outcome_unknown": 1, "receipt_returned": 2, "applied": 3}
    for identity, phases in groups.items():
        if "submitting" not in phases:
            raise ValueError("bridge recovery history intent is missing")
        attempt = phases["submitting"].attempt
        if any(record.attempt != attempt for record in phases.values()):
            raise ValueError("bridge recovery immutable attempt changed")
        terminal = max(phases.values(), key=lambda item: order[item.phase])
        receipts = [item.weight_call for item in phases.values() if item.weight_call is not None]
        if any(receipt != receipts[0] for receipt in receipts):
            raise ValueError("bridge recovery retained receipt changed")
        if "applied" in phases and "receipt_returned" not in phases:
            raise ValueError("bridge recovery applied history lacks the returned receipt")
        if terminal.phase == "applied" and (
            terminal.last_observed_block < terminal.weight_call.block_number
        ):
            raise ValueError("bridge recovery applied observation predates the receipt")
        if identity == current.attempt.attempt_id:
            if (
                current.phase != terminal.phase
                or current.weight_call != terminal.weight_call
                or current.attempt != attempt
            ):
                raise ValueError("bridge recovery current phase or receipt rolled back")
            terminal = current
            path = JOURNAL
        else:
            if terminal.phase != "applied":
                holds.add("registration_bridge_retained_attempt_unresolved")
            path = f"{HISTORY}/{identity}-{terminal.phase}.json"
        if "outcome_unknown" in phases or terminal.phase == "submitting":
            holds.add("registration_bridge_attempt_mortality_unknown")
        records.append((path, terminal))
    records.sort(key=lambda pair: pair[1].attempt.preflight_block)
    if records[-1][0] != JOURNAL:
        raise ValueError("bridge recovery current attempt is not the latest")
    prior_preflight = -1
    for _, record in records:
        attempt = record.attempt
        if attempt.preflight_block <= prior_preflight:
            raise ValueError("bridge recovery attempt ordering changed")
        if attempt.preflight_block < prior_observation:
            raise ValueError("bridge recovery preflight predates the previous terminal observation")
        if prior_receipt is not None and (
            attempt.prior_last_update != prior_receipt or attempt.preflight_block < prior_receipt
        ):
            raise ValueError("bridge recovery attempts have an unexplained LastUpdate gap")
        prior_preflight = attempt.preflight_block
        prior_receipt = record.weight_call.block_number if record.weight_call else None
        prior_observation = record.last_observed_block
    return BridgeHistoryAudit(current, tuple(records), frozenset(recognized), tuple(sorted(holds)))
