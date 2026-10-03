"""Bind standing execution to an approved installation and its retained journal.

Approval is a root-owned local input. It cannot replace native package, chain,
handoff or transaction verification. Durable journal identity survives copying
preserved state to another host; device/inode checks apply only within a process.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import Field, model_serializer, model_validator

from .competition_host_activation import _read_root_control_path
from .competition_reward_handoff_models import (
    RewardHandoffPlan,
    StandingRewardHandoffPlan,
    VerifiedLegacyRewardHandoff,
    validate_legacy_handoff,
    verify_handoff_plan,
)
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_reward_series_handoff import (
    VerifiedStandingPredecessorOpportunity,
    validate_standing_predecessor_opportunity,
)
from .competition_reward_transactions import StandingWeightJournal
from .competition_supervisor_runtime import SuccessorSupervisorRuntime
from .open_competition import Hotkey, digest, identity
from .private_files import lock_private_file, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_MAX_BYTES = 8192
_ISSUER = object()
_STANDING_HANDOFF_ISSUER = object()


def _root_control(path: Path, maximum: int) -> bytes:
    return _read_root_control_path(path, maximum, modes={0o444})


class StandingRewardHostApproval(StrictProtocolModel):
    schema_: Literal[
        "umi-standing-reward-host-approval/1", "umi-standing-reward-host-approval/2"
    ] = Field(alias="schema")
    source_config_sha256: Hex32
    installation_receipt_sha256: Hex32
    host_manifest_sha256: Hex32
    validator_hotkey: Hotkey
    series_sha256: Hex32
    policy_sha256: Hex32
    manifest_sha256: Hex32
    chain_config_sha256: Hex32
    legacy_handoff_plan_sha256: Hex32 | None = None
    standing_handoff_plan_sha256: Hex32 | None = None
    predecessor_approval_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def preserve_initial_approval_bytes(self, handler):
        value = handler(self)
        for name in (
            "legacy_handoff_plan_sha256",
            "standing_handoff_plan_sha256",
            "predecessor_approval_sha256",
        ):
            if getattr(self, name) is None:
                value.pop(name, None)
        return value

    @model_validator(mode="after")
    def handoff_kind(self):
        successor = self.schema_ == "umi-standing-reward-host-approval/2"
        if (
            successor != (self.legacy_handoff_plan_sha256 is None)
            or successor != (self.standing_handoff_plan_sha256 is not None)
            or successor != (self.predecessor_approval_sha256 is not None)
        ):
            raise ValueError("standing host approval has incomplete handoff authority")
        return self


class _StateBinding(StrictProtocolModel):
    schema_: Literal[
        "umi-standing-reward-state-binding/1", "umi-standing-reward-state-binding/2"
    ] = Field(alias="schema")
    approval_sha256: Hex32
    journal_binding_sha256: Hex32
    journal_id: Hex32
    predecessor_binding_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def preserve_initial_binding_bytes(self, handler):
        value = handler(self)
        if self.predecessor_binding_sha256 is None:
            value.pop("predecessor_binding_sha256", None)
        return value

    @model_validator(mode="after")
    def lineage(self):
        successor = self.schema_ == "umi-standing-reward-state-binding/2"
        if successor != (self.predecessor_binding_sha256 is not None):
            raise ValueError("standing execution binding has incomplete lineage")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedStandingRewardHandoff:
    """Process-local successor fence over the prior journal and opportunity."""

    opportunity: VerifiedStandingPredecessorOpportunity
    predecessor_binding_sha256: str
    predecessor_attempt_sha256: str | None
    predecessor_end_sha256: str | None
    through_block: int
    chain_submission_authorized: Literal[False] = False
    _recheck: Callable[[], None] | None = field(default=None, repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _standing_handoff_binding(value):
    return digest(
        {
            "opportunity": value.opportunity._binding,
            "predecessor_binding_sha256": value.predecessor_binding_sha256,
            "predecessor_attempt_sha256": value.predecessor_attempt_sha256,
            "predecessor_end_sha256": value.predecessor_end_sha256,
            "through_block": value.through_block,
            "recheck": id(value._recheck),
        }
    )


def _issue_standing_reward_handoff(
    opportunity,
    *,
    predecessor_binding_sha256,
    predecessor_attempt_sha256,
    predecessor_end_sha256,
    through_block,
    recheck,
):
    recheck()
    value = VerifiedStandingRewardHandoff(
        opportunity,
        predecessor_binding_sha256,
        predecessor_attempt_sha256,
        predecessor_end_sha256,
        through_block,
        _recheck=recheck,
        _issuer=_STANDING_HANDOFF_ISSUER,
    )
    object.__setattr__(value, "_binding", _standing_handoff_binding(value))
    return value


def validate_standing_reward_handoff(value, *, plan, activation, block):
    if (
        type(value) is not VerifiedStandingRewardHandoff
        or value._issuer is not _STANDING_HANDOFF_ISSUER
        or value._binding != _standing_handoff_binding(value)
        or value.chain_submission_authorized is not False
        or not callable(value._recheck)
        or type(block) is not int
        or block < value.through_block
    ):
        raise ValueError("standing successor lacks its prior writer handoff")
    validate_standing_predecessor_opportunity(
        value.opportunity,
        plan=plan,
        activation=activation,
        block=block,
    )
    value._recheck()


def _retained_binding(runtime):
    with runtime._db() as db:
        if not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='standing_execution'"
        ).fetchone():
            return None
        count, size = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM standing_execution"
        ).fetchone()
        if count != 1 or not 0 < size <= _MAX_BYTES:
            raise ValueError("standing execution binding is incomplete")
        row = db.execute("SELECT body FROM standing_execution WHERE id=1").fetchone()
    if row is None or type(row[0]) is not bytes:
        raise ValueError("standing execution binding is malformed")
    value = _StateBinding.model_validate_json(row[0])
    if canonical_json_bytes(value) != row[0]:
        raise ValueError("standing execution binding is not canonical")
    return value


def _retained_binding_history(runtime):
    with runtime._db() as db:
        if not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='standing_execution_history'"
        ).fetchone():
            return ()
        count, size = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM standing_execution_history"
        ).fetchone()
        if not 0 < count <= 64 or not 0 < size <= 64 * _MAX_BYTES:
            raise ValueError("standing execution binding history exceeds its bounds")
        rows = db.execute(
            "SELECT sha256,body FROM standing_execution_history ORDER BY sha256"
        ).fetchall()
    result = []
    for sha256, raw in rows:
        if type(sha256) is not str or type(raw) is not bytes:
            raise ValueError("standing execution binding history is malformed")
        value = _StateBinding.model_validate_json(raw)
        if canonical_json_bytes(value) != raw or digest(value) != sha256:
            raise ValueError("standing execution binding history changed")
        result.append(value)
    if len({digest(value) for value in result}) != len(result):
        raise ValueError("standing execution binding history is duplicated")
    return tuple(result)


def _identities(journal, writer_path=None):
    paths = [
        journal.journal.root,
        journal.journal.path,
        journal.journal.lock_path,
        journal.journal.root / "standing-writer.lock",
    ]
    if writer_path is not None:
        paths.append(writer_path)
    result = []
    for path in paths:
        private_path(str(path))
        info = path.stat()
        if (
            info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or (
                path != journal.journal.root
                and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)
            )
        ):
            raise ValueError("standing journal ownership or file type changed")
        result.append((info.st_dev, info.st_ino))
    journal.journal._check_files()
    return tuple(result)


@dataclass(frozen=True, slots=True)
class BoundStandingRewardHost:
    """Process-local ownership; never reconstruct this from serialized flags."""

    journal: StandingWeightJournal
    writer_path: Path
    _runtime: SuccessorSupervisorRuntime = field(repr=False)
    _preparation: StandingRewardPreparation = field(repr=False)
    _first: PreparedStandingReward = field(repr=False)
    _handoff: VerifiedLegacyRewardHandoff | VerifiedStandingRewardHandoff = field(repr=False)
    _approval_path: Path = field(repr=False)
    _approval: StandingRewardHostApproval = field(repr=False)
    _retained: _StateBinding = field(repr=False)
    _history: tuple[_StateBinding, ...] = field(repr=False)
    _identities: tuple = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _seal: tuple = field(default=(), repr=False)

    def _selection(self):
        return (
            id(self.journal),
            str(self.writer_path),
            id(self._runtime),
            id(self._preparation),
            id(self._first),
            id(self._handoff),
            str(self._approval_path),
            digest(self._approval),
            digest(self._retained),
            tuple(digest(value) for value in self._history),
            self._identities,
        )

    def recheck(self, *, journal, preparation, first, handoff):
        if (
            self._issuer is not _ISSUER
            or self._selection() != self._seal
            or journal is not self.journal
            or preparation is not self._preparation
            or first is not self._first
            or handoff is not self._handoff
        ):
            raise ValueError("standing execution lost its approved host binding")
        _check_context(self._runtime, preparation, first, handoff, self._approval)
        if (
            _root_control(self._approval_path, _MAX_BYTES) != canonical_json_bytes(self._approval)
            or _retained_binding(self._runtime) != self._retained
            or _retained_binding_history(self._runtime) != self._history
            or digest(journal.binding) != self._retained.journal_binding_sha256
            or journal.journal.get("standing_host_identity", "original")
            != self._retained.journal_id
            or _identities(journal, self.writer_path) != self._identities
        ):
            raise ValueError("standing execution approval or retained journal changed")


def _check_selection(runtime, preparation, first, plan, approval):
    runtime._require_lease()
    preparation._authority()
    if first is not None:
        preparation._check_prepared(first)
    plan = verify_handoff_plan(plan, preparation.reader.series)
    successor = type(plan) is StandingRewardHandoffPlan
    if identity(runtime.config.validator_hotkey) not in {
        identity(value) for value in preparation.reader.series.validators
    }:
        raise ValueError("standing execution validator is absent from the selected series")
    expected = StandingRewardHostApproval(
        schema=(
            "umi-standing-reward-host-approval/2"
            if successor
            else "umi-standing-reward-host-approval/1"
        ),
        source_config_sha256=digest(runtime.config),
        installation_receipt_sha256=runtime.installation.receipt_sha256,
        host_manifest_sha256=runtime.installation.host_manifest_sha256,
        validator_hotkey=runtime.config.validator_hotkey,
        series_sha256=preparation.series_sha256,
        policy_sha256=preparation.policy_sha256,
        manifest_sha256=digest(preparation.manifest),
        chain_config_sha256=preparation.reader.chain_config_sha256,
        legacy_handoff_plan_sha256=None if successor else digest(plan),
        standing_handoff_plan_sha256=digest(plan) if successor else None,
        predecessor_approval_sha256=approval.predecessor_approval_sha256,
    )
    if approval != expected:
        raise ValueError("standing execution differs from the approved installation")


def check_standing_reward_host_selection(
    runtime: SuccessorSupervisorRuntime,
    *,
    approval_path: Path,
    preparation: StandingRewardPreparation,
    first: PreparedStandingReward | None,
    plan: RewardHandoffPlan,
) -> None:
    """Check approved inputs before bootstrap or retaining a predecessor stop intent.

    During bootstrap the first package is not prepared yet. The same approval
    is checked again with native preparation before the handoff can stop the predecessor.
    """
    if (
        type(runtime) is not SuccessorSupervisorRuntime
        or type(preparation) is not StandingRewardPreparation
    ):
        raise TypeError("standing host requires native runtime and preparation")
    raw = _root_control(approval_path, _MAX_BYTES)
    approval = StandingRewardHostApproval.model_validate_json(raw)
    if canonical_json_bytes(approval) != raw:
        raise ValueError("standing host approval is not canonical")
    _check_selection(runtime, preparation, first, plan, approval)


def _check_context(runtime, preparation, first, handoff, approval):
    plan = (
        handoff.intent.plan
        if type(handoff) is VerifiedLegacyRewardHandoff
        else preparation.reader.series.predecessor
    )
    if type(handoff) is VerifiedStandingRewardHandoff:
        plan = StandingRewardHandoffPlan(
            schema="umi-standing-reward-handoff-plan/1",
            series_sha256=preparation.series_sha256,
            cohort_sha256=digest(preparation.reader.series.cohorts[0]),
            predecessor=plan,
        )
    _check_selection(runtime, preparation, first, plan, approval)
    if not runtime._mutex.locked():
        raise ValueError("standing execution requires its original writer handoff")
    if type(handoff) is VerifiedLegacyRewardHandoff:
        validate_legacy_handoff(
            handoff,
            series=preparation.reader.series,
            activation=first.activation,
            validator_hotkey=runtime.config.validator_hotkey,
            block=handoff.through_block,
        )
        if runtime._standing_handoff_intent() != handoff.intent:
            raise ValueError("standing execution differs from the retained handoff")
    else:
        assert type(plan) is StandingRewardHandoffPlan
        validate_standing_reward_handoff(
            handoff,
            plan=plan,
            activation=first.activation,
            block=handoff.through_block,
        )
        if runtime._standing_handoff_intent() is None:
            raise ValueError("standing successor lost the original runtime handoff")


def bind_standing_reward_host(
    runtime: SuccessorSupervisorRuntime,
    *,
    approval_path: Path,
    preparation: StandingRewardPreparation,
    first: PreparedStandingReward,
    handoff: VerifiedLegacyRewardHandoff | VerifiedStandingRewardHandoff,
    maximum_journal_bytes: int,
) -> BoundStandingRewardHost:
    """Open the one approved journal while the predecessor locks remain held.

    Missing state after a retained binding is an error, never fresh startup.
    Before the binding commits, a crash may leave an empty initialized journal;
    its original identity is reused. No pending transaction can precede binding.
    """
    if (
        type(runtime) is not SuccessorSupervisorRuntime
        or type(preparation) is not StandingRewardPreparation
    ):
        raise TypeError("standing host requires native runtime and preparation")
    raw = _root_control(approval_path, _MAX_BYTES)
    approval = StandingRewardHostApproval.model_validate_json(raw)
    if canonical_json_bytes(approval) != raw:
        raise ValueError("standing host approval is not canonical")
    _check_context(runtime, preparation, first, handoff, approval)
    root = (
        Path(runtime.config.state_root) / "standing-rewards" / preparation.series_sha256 / "weights"
    )
    # The journal is series-specific, but a validator can submit for only one
    # standing series at a time. This host-wide lock fences a successor series
    # even though it has a different journal and series digest.
    writer_path = Path(runtime.config.state_root) / "standing-rewards" / "standing-writer.lock"
    approval_sha256 = hashlib.sha256(raw).hexdigest()
    prior = _retained_binding(runtime)
    history = _retained_binding_history(runtime)
    successor = type(handoff) is VerifiedStandingRewardHandoff
    migration = False
    predecessor = None
    if prior is not None:
        if prior.approval_sha256 == approval_sha256:
            if successor != (prior.schema_ == "umi-standing-reward-state-binding/2"):
                raise ValueError("standing execution binding kind changed")
            if successor:
                predecessors = {digest(value): value for value in history}
                predecessor = predecessors.get(prior.predecessor_binding_sha256)
                if (
                    predecessor is None
                    or predecessor.approval_sha256 != approval.predecessor_approval_sha256
                ):
                    raise ValueError("standing execution predecessor binding is unavailable")
        elif successor and prior.approval_sha256 == approval.predecessor_approval_sha256:
            predecessor = prior
            migration = True
        else:
            raise ValueError("standing execution cannot replace its approved selection")
    elif successor:
        raise ValueError("standing successor requires its retained predecessor binding")
    if predecessor is not None:
        if digest(predecessor) != handoff.predecessor_binding_sha256:
            raise ValueError("standing successor handoff selects another predecessor binding")
        # The process-local handoff performs the authoritative predecessor
        # journal replay. Its recheck is repeated below and on every executor step.
        handoff._recheck()
    if prior is not None and not migration:
        # Check before RoundJournal can create a file or directory on reopen.
        for name in ("rounds.sqlite3", "rounds.lock", "standing-writer.lock"):
            private_path(str(root / name))
            if not (root / name).is_file():
                raise ValueError("standing execution retained journal is missing")
    journal = StandingWeightJournal(
        root,
        series_sha256=approval.series_sha256,
        validator_hotkey=approval.validator_hotkey,
        chain_config_sha256=approval.chain_config_sha256,
        maximum_bytes=maximum_journal_bytes,
    )
    with ExitStack() as locks:
        global_fd = lock_private_file(writer_path)
        locks.callback(os.close, global_fd)
        fd = lock_private_file(root / "standing-writer.lock")
        locks.callback(os.close, fd)
        identity = journal.journal.get("standing_host_identity", "original")
        if prior is not None and not migration:
            if (
                identity != prior.journal_id
                or digest(journal.binding) != prior.journal_binding_sha256
            ):
                raise ValueError("standing execution retained journal identity differs")
        else:
            if journal.pending() is not None:
                raise ValueError("unbound standing journal already contains a transaction")
            if identity is None:
                identity = secrets.token_hex(32)
                journal.journal.put("standing_host_identity", "original", identity)
            candidate = _StateBinding(
                schema=(
                    "umi-standing-reward-state-binding/2"
                    if successor
                    else "umi-standing-reward-state-binding/1"
                ),
                approval_sha256=approval_sha256,
                journal_binding_sha256=digest(journal.binding),
                journal_id=identity,
                predecessor_binding_sha256=(
                    digest(predecessor) if predecessor is not None else None
                ),
            )
            _check_context(runtime, preparation, first, handoff, approval)
            with runtime._db() as db:
                if migration:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS standing_execution_history "
                        "(sha256 TEXT PRIMARY KEY, body BLOB NOT NULL)"
                    )
                    db.execute(
                        "INSERT OR IGNORE INTO standing_execution_history VALUES (?,?)",
                        (digest(predecessor), canonical_json_bytes(predecessor)),
                    )
                    db.execute(
                        "DELETE FROM standing_execution_history WHERE rowid NOT IN "
                        "(SELECT rowid FROM standing_execution_history "
                        "ORDER BY rowid DESC LIMIT 64)"
                    )
                    db.execute(
                        "UPDATE standing_execution SET body=? WHERE id=1",
                        (canonical_json_bytes(candidate),),
                    )
                else:
                    db.execute(
                        "CREATE TABLE standing_execution "
                        "(id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
                    )
                    db.execute(
                        "INSERT INTO standing_execution VALUES (1,?)",
                        (canonical_json_bytes(candidate),),
                    )
            prior = candidate
            history = _retained_binding_history(runtime)
        bound = BoundStandingRewardHost(
            journal,
            writer_path,
            runtime,
            preparation,
            first,
            handoff,
            approval_path,
            approval,
            prior,
            history,
            _identities(journal, writer_path),
            _issuer=_ISSUER,
        )
        object.__setattr__(bound, "_seal", bound._selection())
        bound.recheck(journal=journal, preparation=preparation, first=first, handoff=handoff)
        return bound
