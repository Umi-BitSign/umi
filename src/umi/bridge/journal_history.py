"""Pure validation of immutable bridge archives and versioned transitions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

from .journal import RegistrationBridgeJournal
from .policy import _require
from .transactions import BridgeJournal, RegistrationBridgeTransactionJournal

MAX_HISTORY_FILES = 4096

_LEGACY_ORDER = {"submitting": 0, "outcome_unknown": 1, "receipt_returned": 2, "applied": 3}
_TRANSACTION_ORDER = {
    "preparing": 0,
    "signed": 1,
    "submitting": 2,
    "outcome_unknown": 3,
    "receipt_returned": 4,
    "applied": 5,
    "expired_nonce_available": 5,
    "failed": 5,
}
_TRANSACTION_EDGES = {
    "preparing": {"signed", "outcome_unknown", "expired_nonce_available"},
    "signed": {"submitting", "outcome_unknown", "expired_nonce_available"},
    "submitting": {"outcome_unknown", "receipt_returned", "expired_nonce_available", "failed"},
    "outcome_unknown": {"receipt_returned", "expired_nonce_available", "failed"},
    "receipt_returned": {"applied"},
    "applied": set(),
    "expired_nonce_available": set(),
    "failed": set(),
}


@dataclass(frozen=True, slots=True)
class HistoryContinuity:
    """In-memory traversal state, never a chain proof or persisted checkpoint."""

    preflight_block: int = -1
    last_update: int | None = None
    observed_block: int = 0

    @classmethod
    def following(cls, record: BridgeJournal) -> HistoryContinuity:
        last_update = None
        if record.weight_call is not None:
            last_update = record.weight_call.block_number
        elif type(record) is RegistrationBridgeTransactionJournal:
            last_update = record.attempt.prior_last_update
        return cls(
            preflight_block=-1 if record.attempt is None else record.attempt.preflight_block,
            last_update=last_update,
            observed_block=record.last_observed_block,
        )


def audit_history_sequence(
    records: Iterable[BridgeJournal], *, after: HistoryContinuity | None = None
) -> HistoryContinuity:
    """Check ordered, phase-audited attempts with constant traversal memory.

    Callers retain responsibility for phase/identity checks and owned chain
    evidence. Passing the returned boundary to the next page preserves the same
    continuity checks as traversing the complete sequence at once.
    """
    if after is None:
        after = HistoryContinuity()
    for record in records:
        attempt = record.attempt
        _require(attempt is not None, "history_intent_missing")
        _require(attempt.preflight_block > after.preflight_block, "history_attempt_order_changed")
        _require(
            attempt.preflight_block >= after.observed_block,
            "history_preflight_predates_observation",
        )
        _require(
            after.last_update is None
            or (
                attempt.prior_last_update == after.last_update
                and attempt.preflight_block >= after.last_update
            ),
            "history_lastupdate_gap",
        )
        after = HistoryContinuity.following(record)
    return after


def _transaction_identity(
    older: RegistrationBridgeTransactionJournal, newer: RegistrationBridgeTransactionJournal
) -> None:
    if older.signed_extrinsic is not None:
        _require(
            (older.signed_extrinsic, older.signed_extrinsic_hash)
            == (newer.signed_extrinsic, newer.signed_extrinsic_hash),
            "history_signed_extrinsic_changed",
        )
    if older.expiry_observation is not None:
        _require(
            older.expiry_observation == newer.expiry_observation,
            "history_expiry_observation_changed",
        )
    if older.failed_call is not None:
        _require(older.failed_call == newer.failed_call, "history_failed_receipt_changed")


def validate_next_journal(
    previous: BridgeJournal | None, current: BridgeJournal, *, archive: bool
) -> None:
    """Prevent a new-format writer from dropping transaction identity or intent.

    This validates a local transition, not the chain evidence authorizing it.
    Legacy-to-legacy transitions keep their existing validation path.
    """
    if (
        type(previous) is not RegistrationBridgeTransactionJournal
        and type(current) is RegistrationBridgeJournal
    ):
        return
    _require(previous is not None, "bridge_transaction_initial_state_missing")
    _require(type(current) is RegistrationBridgeTransactionJournal, "bridge_journal_downgrade")
    _require(
        current.validator_hotkey == previous.validator_hotkey
        and current.legacy_journal_sha256 == previous.legacy_journal_sha256,
        "history_binding_changed",
    )
    _require(
        current.last_observed_block >= previous.last_observed_block, "journal_finality_rollback"
    )
    _require(
        current.last_observed_block != previous.last_observed_block
        or current.last_observed_block_hash == previous.last_observed_block_hash,
        "journal_finality_equivocation",
    )
    if previous.attempt is None or previous.attempt.attempt_id != current.attempt.attempt_id:
        _require(
            previous.phase in {"idle", "applied", "expired_nonce_available", "failed"},
            "retained_unresolved_attempt",
        )
        _require(current.phase == "preparing" and archive, "history_intent_missing")
        _require(
            current.attempt.preflight_block >= previous.last_observed_block
            and (
                previous.attempt is None
                or current.attempt.preflight_block > previous.attempt.preflight_block
            ),
            "current_journal_rolled_back",
        )
        audit_history_sequence((current,), after=HistoryContinuity.following(previous))
        return
    _require(
        type(previous) is RegistrationBridgeTransactionJournal
        and current.attempt == previous.attempt,
        "history_attempt_changed",
    )
    _transaction_identity(previous, current)
    _require(
        previous.signed_extrinsic is not None
        or current.signed_extrinsic is None
        or (previous.phase == "preparing" and current.phase == "signed"),
        "bridge_signed_bytes_without_signing_transition",
    )
    _require(
        previous.weight_call is None or current.weight_call == previous.weight_call,
        "history_receipt_changed",
    )
    if current.phase == previous.phase:
        _require(
            current.signed_extrinsic == previous.signed_extrinsic
            and current.expiry_observation == previous.expiry_observation
            and current.failed_call == previous.failed_call,
            "history_transaction_changed",
        )
    else:
        _require(
            archive and current.phase in _TRANSACTION_EDGES[previous.phase],
            "bridge_journal_transition_invalid",
        )


def audit_attempt_phases(phases: dict[str, BridgeJournal]) -> BridgeJournal:
    """Return the latest archived transition after checking one attempt."""
    _require(bool(phases), "history_intent_missing")
    _require(
        all(item.phase == phase and item.attempt is not None for phase, item in phases.items()),
        "history_phase_identity_changed",
    )
    transaction = any(
        type(item) is RegistrationBridgeTransactionJournal for item in phases.values()
    )
    first = "preparing" if transaction else "submitting"
    _require(first in phases, "history_intent_missing")
    original = phases[first]
    _require(
        all(
            type(item) is type(original)
            and item.attempt == original.attempt
            and item.validator_hotkey == original.validator_hotkey
            and item.legacy_journal_sha256 == original.legacy_journal_sha256
            for item in phases.values()
        ),
        "history_attempt_changed",
    )
    order = _TRANSACTION_ORDER if transaction else _LEGACY_ORDER
    ordered = sorted(phases.values(), key=lambda item: order[item.phase])
    receipts = [item.weight_call for item in ordered if item.weight_call is not None]
    _require(
        not receipts or all(receipt == receipts[0] for receipt in receipts),
        "history_receipt_changed",
    )
    _require(
        "applied" not in phases or "receipt_returned" in phases,
        "history_applied_receipt_missing",
    )
    if "applied" in phases:
        applied = phases["applied"]
        _require(
            applied.weight_call is not None
            and applied.last_observed_block >= applied.weight_call.block_number,
            "history_applied_observation_predates_receipt",
        )
    if transaction:
        _require(
            not (
                "failed" in phases
                and {"applied", "receipt_returned", "expired_nonce_available"} & phases.keys()
            ),
            "history_conflicting_resolution",
        )
        if "failed" in phases:
            _require("submitting" in phases, "history_submission_missing")
        _require(
            not (
                "expired_nonce_available" in phases
                and ({"applied", "receipt_returned"} & phases.keys())
            ),
            "history_conflicting_resolution",
        )
        if any(item.signed_extrinsic is not None for item in ordered):
            _require("signed" in phases, "history_signed_extrinsic_missing")
        if receipts:
            _require(
                "submitting" in phases and "receipt_returned" in phases,
                "history_submission_missing",
            )
        for older, newer in pairwise(ordered):
            validate_next_journal(older, newer, archive=True)
    return ordered[-1]


def audit_current_history(
    current: BridgeJournal, groups: dict[str, dict[str, BridgeJournal]]
) -> dict[str, BridgeJournal]:
    """Validate the current record and return each audited terminal attempt."""
    if current.attempt is None:
        _require(not groups, "current_journal_rolled_back")
        return {}
    _require(current.attempt.attempt_id in groups, "current_attempt_history_missing")
    terminals = {}
    for identity, phases in groups.items():
        terminal = audit_attempt_phases(phases)
        terminals[identity] = terminal
        attempt = terminal.attempt
        _require(
            attempt.preflight_block <= current.attempt.preflight_block,
            "current_journal_rolled_back",
        )
        if identity != current.attempt.attempt_id:
            _require(
                attempt.preflight_block < current.attempt.preflight_block
                and terminal.phase in {"applied", "expired_nonce_available", "failed"},
                "retained_unresolved_attempt",
            )
            _require(
                type(terminal) is not RegistrationBridgeTransactionJournal
                or type(current) is RegistrationBridgeTransactionJournal,
                "bridge_journal_downgrade",
            )
        else:
            _require(
                type(current) is type(terminal)
                and current.attempt == attempt
                and current.phase == terminal.phase,
                "current_journal_rolled_back",
            )
            _require(current.weight_call == terminal.weight_call, "current_receipt_changed")
            if type(current) is RegistrationBridgeTransactionJournal:
                _transaction_identity(terminal, current)
                _require(
                    current.signed_extrinsic == terminal.signed_extrinsic,
                    "history_signed_extrinsic_changed",
                )
    return terminals


def reconcile_archived_transition(
    current: BridgeJournal,
    groups: dict[str, dict[str, BridgeJournal]],
    *,
    after: HistoryContinuity | None = None,
) -> BridgeJournal:
    """Complete at most one archived v2 transition after a torn publication.

    No signing or transaction retry follows from this repair. The current
    record and its complete earlier history must describe the direct predecessor
    of the archived record. Legacy records never gain a new recovery rule.
    """
    result = current
    if groups:
        newest = max(
            groups.values(), key=lambda phases: next(iter(phases.values())).attempt.preflight_block
        )
        terminal = audit_attempt_phases(newest)
        if type(terminal) is RegistrationBridgeTransactionJournal and (
            current.attempt is None
            or current.attempt.attempt_id != terminal.attempt.attempt_id
            or current.phase != terminal.phase
        ):
            preceding = {identity: dict(phases) for identity, phases in groups.items()}
            identity = terminal.attempt.attempt_id
            del preceding[identity][terminal.phase]
            if not preceding[identity]:
                del preceding[identity]
            # A missing earlier intent, changed signed bytes, or more than one
            # skipped durable transition is corruption, not a recoverable tear.
            audit_current_history(current, preceding)
            validate_next_journal(current, terminal, archive=True)
            result = terminal
    for phases in groups.values():
        for retained in phases.values():
            _require(
                retained.last_observed_block <= result.last_observed_block,
                "history_finality_rollback",
            )
            if type(retained) is RegistrationBridgeTransactionJournal:
                _require(
                    retained.last_observed_block != result.last_observed_block
                    or retained.last_observed_block_hash == result.last_observed_block_hash,
                    "history_finality_equivocation",
                )
    terminals = audit_current_history(result, groups)
    audit_history_sequence(
        sorted(terminals.values(), key=lambda record: record.attempt.preflight_block), after=after
    )
    return result
