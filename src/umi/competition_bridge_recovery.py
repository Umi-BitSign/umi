"""Read-only audit of retained registration-bridge attempts.

These are historical local claims, not chain proofs or submission authority.
The caller must separately prove the latest row with owned finalized storage.
An uncertain attempt remains unresolved even when a matching row is visible.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .bridge.journal_history import (
    MAX_HISTORY_FILES,
    HistoryContinuity,
    audit_attempt_phases,
    audit_current_history,
    audit_history_sequence,
)
from .bridge.policy import RegistrationBridgeError
from .bridge.transactions import (
    BridgeJournal,
    RegistrationBridgeTransactionJournal,
    parse_bridge_journal,
)
from .encoding import account_id32
from .protocol import canonical_json_bytes
from .simple_bootstrap_validator import SimpleBootstrapJournal

JOURNAL = "registration-bridge-journal.json"
ARCHIVE = "registration-bridge-legacy-journal.json"
HISTORY = "registration-bridge-history"


@dataclass(frozen=True)
class BridgeHistoryAudit:
    current: BridgeJournal
    attempts: tuple[tuple[str, BridgeJournal], ...]
    recognized: frozenset[str]
    holds: tuple[str, ...]


def _model(raw: bytes, model):
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("bridge recovery record is not canonical")
    return value


def audit_bridge_history(files: dict[str, bytes], *, hotkey: str) -> BridgeHistoryAudit:
    """Validate both journal versions without changing any retained byte."""
    try:
        return _audit_bridge_history(files, hotkey=hotkey)
    except RegistrationBridgeError as exc:
        # Preserve the stopped-recovery API's validation exception family.
        reason = {
            "history_attempt_order_changed": "attempt ordering changed",
            "history_preflight_predates_observation": (
                "preflight predates the previous terminal observation"
            ),
            "history_lastupdate_gap": "attempts have an unexplained LastUpdate gap",
        }.get(exc.reason_code, exc.reason_code)
        raise ValueError(f"bridge recovery {reason}") from exc


def _audit_bridge_history(files: dict[str, bytes], *, hotkey: str) -> BridgeHistoryAudit:
    current = parse_bridge_journal(files[JOURNAL])
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
    groups: dict[str, dict[str, BridgeJournal]] = {}
    history_count = 0
    for path, raw in files.items():
        if not path.startswith(HISTORY + "/"):
            continue
        history_count += 1
        if history_count > MAX_HISTORY_FILES:
            raise ValueError("bridge recovery history exceeds its bound")
        item = parse_bridge_journal(raw)
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
    records: list[tuple[str, BridgeJournal]] = []
    holds = set()
    # Keep the legacy stopped-reader's unresolved-history diagnostics. New
    # transaction records also require the live writer's complete history audit.
    if any(
        type(item) is RegistrationBridgeTransactionJournal
        for phases in groups.values()
        for item in phases.values()
    ):
        terminals = audit_current_history(current, groups)
    else:
        terminals = {identity: audit_attempt_phases(phases) for identity, phases in groups.items()}
    for identity, terminal in terminals.items():
        attempt = terminal.attempt
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
            if terminal.phase not in {"applied", "expired_nonce_available", "failed"}:
                holds.add("registration_bridge_retained_attempt_unresolved")
            path = f"{HISTORY}/{identity}-{terminal.phase}.json"
        if type(terminal) is RegistrationBridgeTransactionJournal:
            # A retained nonce, failure, expiry or receipt is still only a local
            # claim. The stopped handoff must authenticate its chain evidence;
            # SDK row equality cannot clear this hold.
            holds.add("registration_bridge_transaction_proof_required")
        elif "outcome_unknown" in groups[identity] or terminal.phase == "submitting":
            holds.add("registration_bridge_attempt_mortality_unknown")
        records.append((path, terminal))
    records.sort(key=lambda pair: pair[1].attempt.preflight_block)
    if records[-1][0] != JOURNAL:
        raise ValueError("bridge recovery current attempt is not the latest")
    audit_history_sequence(
        (record for _, record in records),
        after=HistoryContinuity(last_update=prior_receipt, observed_block=prior_observation),
    )
    return BridgeHistoryAudit(current, tuple(records), frozenset(recognized), tuple(sorted(holds)))
