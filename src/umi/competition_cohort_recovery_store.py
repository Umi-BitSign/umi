"""Durable, serialized schedule decisions for explicitly recoverable cohorts.

The owner supplies its private SQLite connection and process lifecycle. A full
transaction reserves exact decision bytes before signing. Committed certificates
and their entire predecessor chain are verified on reopen; no wall clock expires
the retained cohort. Network publication and phase evidence checks are separate.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Literal, TypeVar

from pydantic import Field

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import (
    CohortRecoveryGenesis,
    CohortRecoveryState,
    CohortRecoveryTransition,
    Phase,
    RecoverableCohortPlan,
    RecoveryOperation,
    SignedCohortRecoveryAuthority,
    SignedCohortRecoveryTransition,
    admit_recoverable_cohort,
    apply_recovery_transition,
    propose_recovery_transition,
    verify_recovery_quorum,
)
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class _Binding(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovery-binding/1"] = Field(alias="schema")
    plan: RecoverableCohortPlan
    authority: SignedCohortRecoveryAuthority
    policy: CompetitionPolicy
    genesis: CohortRecoveryGenesis


class _DecisionKey(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovery-decision-key/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    phase: Phase
    operation: RecoveryOperation
    evidence_sha256: Hex32


class _PublishedGenesis(StrictProtocolModel):
    genesis: CohortRecoveryGenesis
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def _decision_key(cohort: str, phase: Phase, operation: RecoveryOperation, evidence: str) -> str:
    return digest(
        _DecisionKey(
            schema="umi-cohort-recovery-decision-key/1",
            cohort_sha256=cohort,
            phase=phase,
            operation=operation,
            evidence_sha256=evidence,
        )
    )


_Record = TypeVar("_Record", bound=StrictProtocolModel)


def _decode(model: type[_Record], raw: bytes, maximum: int) -> _Record:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("cohort recovery record exceeds its byte bound")
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("cohort recovery record is not canonical")
    return value


class CohortRecoveryStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.db = connection
        if self.db.in_transaction:
            raise ValueError("cohort recovery cannot take over an existing transaction")
        # The host owns WAL/DELETE choice and filesystem bounds. FULL is required
        # here because an acknowledged reservation must survive loss of power.
        self.db.execute("PRAGMA synchronous=FULL")
        with self._transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS cohort_recovery_bindings (
                cohort TEXT PRIMARY KEY, body BLOB NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS cohort_recovery_decisions (
                cohort TEXT NOT NULL, sequence INTEGER NOT NULL,
                decision TEXT NOT NULL, body BLOB NOT NULL, certificate BLOB,
                PRIMARY KEY(cohort,sequence), UNIQUE(cohort,decision))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS cohort_recovery_sources (
                cohort TEXT NOT NULL, digest TEXT NOT NULL, body BLOB NOT NULL,
                PRIMARY KEY(cohort,digest))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS cohort_published_genesis (
                cohort TEXT PRIMARY KEY, body BLOB NOT NULL)""")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self.db.in_transaction:
            raise ValueError("cohort recovery requires its own atomic transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def admit(
        self,
        plan: RecoverableCohortPlan,
        authority: SignedCohortRecoveryAuthority,
        policy: CompetitionPolicy,
        *,
        admitted_at_block: int,
    ) -> CohortRecoveryState:
        genesis, _ = admit_recoverable_cohort(
            plan,
            authority,
            policy,
            admitted_at_block=admitted_at_block,
        )
        binding = _Binding(
            schema="umi-cohort-recovery-binding/1",
            plan=plan,
            authority=authority,
            policy=policy,
            genesis=genesis,
        )
        raw = canonical_json_bytes(binding)
        _decode(_Binding, raw, 512 * 1024)
        with self._transaction():
            prior = self.db.execute(
                "SELECT substr(body,1,524289) FROM cohort_recovery_bindings WHERE cohort=?",
                (genesis.cohort_sha256,),
            ).fetchone()
            if prior is not None and prior[0] != raw:
                raise ValueError("cohort admission already has a different recovery binding")
            self.db.execute(
                "INSERT OR IGNORE INTO cohort_recovery_bindings VALUES (?,?)",
                (genesis.cohort_sha256, raw),
            )
            _, state, _ = self._load(genesis.cohort_sha256)
            return state

    def _load(
        self,
        cohort: str,
    ) -> tuple[_Binding, CohortRecoveryState, CohortRecoveryTransition | None]:
        row = self.db.execute(
            "SELECT substr(body,1,524289) FROM cohort_recovery_bindings WHERE cohort=?", (cohort,)
        ).fetchone()
        if row is None:
            raise ValueError("cohort has no explicit recovery admission")
        binding = _decode(_Binding, row[0], 512 * 1024)
        genesis, state = admit_recoverable_cohort(
            binding.plan,
            binding.authority,
            binding.policy,
            admitted_at_block=binding.genesis.admitted_at_block,
        )
        if genesis != binding.genesis or cohort != genesis.cohort_sha256:
            raise ValueError("cohort recovery binding differs from its original admission")
        pending = None
        for sequence, decision, raw, certificate in self.db.execute(
            "SELECT sequence,decision,substr(body,1,16385),substr(certificate,1,65537) "
            "FROM cohort_recovery_decisions "
            "WHERE cohort=? ORDER BY sequence",
            (cohort,),
        ):
            if pending is not None:
                raise ValueError("cohort has decisions after an uncommitted reservation")
            transition = _decode(CohortRecoveryTransition, raw, 16 * 1024)
            if decision != _decision_key(
                cohort, transition.phase, transition.operation, transition.evidence_sha256
            ):
                raise ValueError("retained cohort decision has a different operation identity")
            expected = propose_recovery_transition(
                state,
                binding.authority.authority,
                operation=transition.operation,
                observed_at_block=transition.observed_at_block,
                evidence_sha256=transition.evidence_sha256,
                extension_blocks=transition.extension_blocks,
            )
            if sequence != state.sequence + 1 or transition != expected:
                raise ValueError("retained cohort decision forks its authenticated history")
            if certificate is None:
                pending = transition
            else:
                signed = _decode(SignedCohortRecoveryTransition, certificate, 64 * 1024)
                if signed.transition != transition:
                    raise ValueError("cohort decision differs from its certificate")
                state = apply_recovery_transition(state, signed, binding.authority, binding.policy)
        return binding, state, pending

    def status(self, cohort: str) -> tuple[CohortRecoveryState, CohortRecoveryTransition | None]:
        # One consistent snapshot even if another process commits during replay.
        with self._transaction():
            _, state, pending = self._load(cohort)
            return state, pending

    def publish_history(
        self, history: CohortRecoveryHistory, policy: CompetitionPolicy, *, current_block: int
    ) -> CohortRecoveryState:
        """Atomically adopt a complete certified history in a consumer's ledger.

        The service owner authenticates the configured cohort and supplies owned
        finality. A signed older prefix or a fork never replaces the retained
        tip. No intermediate prefix becomes visible during a multi-step import.
        This consumer path does not replace the coordinator's signing journal.
        """
        history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
        tip = digest(history.transitions[-1].transition if history.transitions else history.genesis)
        view = verify_cohort_history(
            history, policy, expected_tip_sha256=tip, current_block=current_block
        )
        cohort = view.state.cohort_sha256
        binding = _Binding(
            schema="umi-cohort-recovery-binding/1",
            plan=history.plan,
            authority=history.authority,
            policy=policy,
            genesis=history.genesis,
        )
        raw = canonical_json_bytes(binding)
        _decode(_Binding, raw, 512 * 1024)
        genesis = canonical_json_bytes(
            _PublishedGenesis(genesis=history.genesis, signatures=history.genesis_signatures)
        )
        with self._transaction():
            prior = self.db.execute(
                "SELECT substr(body,1,524289) FROM cohort_recovery_bindings WHERE cohort=?",
                (cohort,),
            ).fetchone()
            if prior is not None and prior[0] != raw:
                raise ValueError("published cohort differs from its retained binding")
            self.db.execute(
                "INSERT OR IGNORE INTO cohort_recovery_bindings VALUES (?,?)", (cohort, raw)
            )
            _, state, pending = self._load(cohort)
            if pending is not None:
                raise ValueError("consumer publication cannot replace a pending signing decision")
            if state.sequence > view.state.sequence:
                raise ValueError("published cohort history rolls back its retained tip")
            for signed in history.transitions:
                transition = signed.transition
                encoded = canonical_json_bytes(transition)
                prior = self.db.execute(
                    "SELECT substr(body,1,16385) FROM cohort_recovery_decisions "
                    "WHERE cohort=? AND sequence=?",
                    (cohort, transition.sequence),
                ).fetchone()
                if prior is not None:
                    if prior[0] != encoded:
                        raise ValueError("published cohort history forks its retained decisions")
                    continue
                self.db.execute(
                    "INSERT INTO cohort_recovery_decisions VALUES (?,?,?,?,?)",
                    (
                        cohort,
                        transition.sequence,
                        _decision_key(
                            cohort,
                            transition.phase,
                            transition.operation,
                            transition.evidence_sha256,
                        ),
                        encoded,
                        canonical_json_bytes(signed),
                    ),
                )
            self.db.execute(
                "INSERT OR IGNORE INTO cohort_published_genesis VALUES (?,?)", (cohort, genesis)
            )
            _, state, _ = self._load(cohort)
            if state != view.state:
                raise ValueError("published cohort tip differs after import")
            return state

    def published_history(self, cohort: str) -> CohortRecoveryHistory:
        with self._transaction():
            row = self.db.execute(
                "SELECT substr(body,1,65537) FROM cohort_published_genesis WHERE cohort=?",
                (cohort,),
            ).fetchone()
            if row is None:
                raise ValueError("cohort has no published admission")
            genesis = _decode(_PublishedGenesis, row[0], 64 * 1024)
            binding, _, _ = self._load(cohort)
            if genesis.genesis != binding.genesis:
                raise ValueError("published admission differs from the retained cohort")
        return self.export_history(cohort, genesis_signatures=genesis.signatures)

    def retain_source(self, cohort: str, value: StrictProtocolModel) -> str:
        """Retain decision input before reservation; consumers authenticate its meaning."""
        raw = canonical_json_bytes(value)
        if len(raw) > 256 * 1024:
            raise ValueError("cohort decision source exceeds its byte bound")
        key = digest(value)
        with self._transaction():
            self._load(cohort)
            prior = self.db.execute(
                "SELECT substr(body,1,262145) FROM cohort_recovery_sources "
                "WHERE cohort=? AND digest=?",
                (cohort, key),
            ).fetchone()
            if prior is not None and prior[0] != raw:
                raise ValueError("cohort decision source changed")
            self.db.execute(
                "INSERT OR IGNORE INTO cohort_recovery_sources VALUES (?,?,?)", (cohort, key, raw)
            )
        return key

    def source(self, cohort: str, key: str, model: type[_Record]) -> _Record:
        """Read a content-bound input; it is not itself proof of phase completion."""
        with self._transaction():
            row = self.db.execute(
                "SELECT substr(body,1,262145) FROM cohort_recovery_sources "
                "WHERE cohort=? AND digest=?",
                (cohort, key),
            ).fetchone()
            if row is None:
                raise ValueError("cohort decision source is missing")
            value = _decode(model, row[0], 256 * 1024)
            if digest(value) != key:
                raise ValueError("cohort decision source digest changed")
            return value

    def export_history(
        self,
        cohort: str,
        *,
        genesis_signatures: tuple[Signature, ...],
    ) -> CohortRecoveryHistory:
        """Export committed history only, requiring quorum-certified admission.

        The caller must retain the admission signatures separately and publish
        the returned tip through its authenticated, monotonic publication path.
        A local pending signature reservation is never a committed extension.
        """
        with self._transaction():
            return self.read_history(cohort, genesis_signatures=genesis_signatures)

    def read_history(
        self, cohort: str, *, genesis_signatures: tuple[Signature, ...]
    ) -> CohortRecoveryHistory:
        """Read authenticated history inside the owner's existing transaction.

        This lets native phase observers atomically bind their records to the
        current history. The caller owns commit/rollback; no nested transaction
        or uncommitted decision is promoted to certified history.
        """
        if not self.db.in_transaction:
            raise ValueError("cohort history read requires an owned transaction")
        binding, state, _ = self._load(cohort)
        records = self.db.execute(
            "SELECT substr(certificate,1,65537) FROM cohort_recovery_decisions "
            "WHERE cohort=? AND certificate IS NOT NULL ORDER BY sequence",
            (cohort,),
        )
        history = CohortRecoveryHistory(
            schema="umi-cohort-recovery-history/1",
            plan=binding.plan,
            authority=binding.authority,
            genesis=binding.genesis,
            genesis_signatures=genesis_signatures,
            transitions=tuple(
                _decode(SignedCohortRecoveryTransition, raw, 64 * 1024) for (raw,) in records
            ),
        )
        verify_cohort_history(
            history,
            binding.policy,
            expected_tip_sha256=state.tip_sha256,
            current_block=state.observed_at_block,
        )
        return history

    def reserve(
        self,
        cohort: str,
        *,
        phase: Phase,
        operation: RecoveryOperation,
        observed_at_block: int,
        evidence_sha256: str,
        extension_blocks: int | None = None,
    ) -> CohortRecoveryTransition:
        """Acknowledge the same decision or return pending bytes before new work.

        Recovery must finish that body first even if its observed block is old.
        A later extension can catch up after it commits. This is the signing
        boundary; a retry must never sign an alternative for the same predecessor.
        """
        with self._transaction():
            binding, state, pending = self._load(cohort)
            key = _decision_key(cohort, phase, operation, evidence_sha256)
            prior = self.db.execute(
                "SELECT substr(body,1,16385) FROM cohort_recovery_decisions "
                "WHERE cohort=? AND decision=?",
                (cohort, key),
            ).fetchone()
            if prior is not None:
                return _decode(CohortRecoveryTransition, prior[0], 16 * 1024)
            if pending is not None:
                return pending
            if phase != state.phase:
                raise ValueError("cohort decision targets a closed or different phase")
            transition = propose_recovery_transition(
                state,
                binding.authority.authority,
                operation=operation,
                observed_at_block=observed_at_block,
                evidence_sha256=evidence_sha256,
                extension_blocks=extension_blocks,
            )
            raw = canonical_json_bytes(transition)
            _decode(CohortRecoveryTransition, raw, 16 * 1024)
            self.db.execute(
                "INSERT INTO cohort_recovery_decisions VALUES (?,?,?,?,NULL)",
                (cohort, transition.sequence, key, raw),
            )
            return transition

    def commit(self, signed: SignedCohortRecoveryTransition) -> CohortRecoveryState:
        """Adopt a verified next certificate or acknowledge an identical prior body."""
        encoded = canonical_json_bytes(signed)
        signed = _decode(SignedCohortRecoveryTransition, encoded, 64 * 1024)
        transition = signed.transition
        with self._transaction():
            binding, state, pending = self._load(transition.cohort_sha256)
            verify_recovery_quorum(transition, signed.signatures, binding.policy)
            prior = self.db.execute(
                "SELECT body,certificate FROM cohort_recovery_decisions "
                "WHERE cohort=? AND sequence=?",
                (transition.cohort_sha256, transition.sequence),
            ).fetchone()
            if prior is not None:
                if prior[0] != canonical_json_bytes(transition):
                    raise ValueError("cohort certificate conflicts with a reserved decision")
                if prior[1] is not None:
                    return state
            updated = apply_recovery_transition(state, signed, binding.authority, binding.policy)
            if pending is not None and pending != transition:
                raise ValueError("cohort certificate conflicts with pending history")
            key = _decision_key(
                transition.cohort_sha256,
                transition.phase,
                transition.operation,
                transition.evidence_sha256,
            )
            if self.db.execute(
                "SELECT 1 FROM cohort_recovery_decisions WHERE cohort=? "
                "AND decision=? AND sequence!=?",
                (transition.cohort_sha256, key, transition.sequence),
            ).fetchone():
                raise ValueError("cohort recovery evidence already has a decision")
            self.db.execute(
                "INSERT INTO cohort_recovery_decisions VALUES (?,?,?,?,?) "
                "ON CONFLICT(cohort,sequence) DO UPDATE SET certificate=excluded.certificate",
                (
                    transition.cohort_sha256,
                    transition.sequence,
                    key,
                    canonical_json_bytes(transition),
                    encoded,
                ),
            )
            return updated
