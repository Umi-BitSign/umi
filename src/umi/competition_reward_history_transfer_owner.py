"""Same-account coordinator/writer ownership for local history-result transfer.

No service is stopped here. Both existing process owners must be drained before
journal construction. The writer keeps its original directory, approval, clocks
and weight/control state. Transfer grants no finality or submission authority.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import ExitStack, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .competition_host_activation import _read_root_control_path
from .competition_reward_coordinator_boot import MAX_CONFIG_BYTES, load_reward_coordinator_config
from .competition_reward_cutover_ownership import hold_reward_cutover_owner
from .competition_reward_writer_journals import hold_stopped_writer_journals
from .competition_reward_writer_reconciliation import hold_stopped_standing_writer
from .competition_reward_writer_review import select_stopped_writer_boot
from .competition_supervisor_runtime import hold_successor_startup_lease
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes

_ISSUER = object()
_CONTEXT = (
    "chain",
    "series",
    "policy",
    "manifest",
    "handoff",
    "eligibility",
    "runtime_proof_reads",
    "reward_adoptions",
    "direct_model_review",
)


@dataclass(frozen=True, slots=True)
class HistoryTransferSource:
    """Root-parsed non-signing configuration retained across privilege drop.

    The coordinator's signer path may be inside a root-only host parent. Transfer
    never opens that key. Validate the original configuration while root can
    inspect its paths, then bind its exact canonical bytes after dropping root.
    This object supplies no lease or journal authority.
    """

    path: Path
    config: object = field(repr=False)
    raw_sha256: str
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def _seal(self):
        return digest([str(self.path), digest(self.config), self.raw_sha256])

    def recheck(self):
        if (
            type(self) is not HistoryTransferSource
            or self._issuer is not _ISSUER
            or self._binding != self._seal()
        ):
            raise ValueError("history transfer source selection is absent or altered")
        raw = _read_root_control_path(self.path, MAX_CONFIG_BYTES, modes={0o444})
        if hashlib.sha256(raw).hexdigest() != self.raw_sha256:
            raise ValueError("history transfer source configuration changed")
        return self.config


def prepare_history_transfer_source(path):
    """Read public configuration before account drop, without reading a wallet."""
    if (os.getuid(), os.geteuid()) != (0, 0):
        raise ValueError("history transfer source preparation requires root")
    path = Path(path)
    config = load_reward_coordinator_config(path)
    selected = HistoryTransferSource(
        path, config, hashlib.sha256(canonical_json_bytes(config)).hexdigest(), _ISSUER
    )
    object.__setattr__(selected, "_binding", selected._seal())
    selected.recheck()
    return selected


def matching_history_context(source, target):
    """A shared UID or matching block number alone cannot select native facts."""
    if source.role != "coordinator":
        raise ValueError("history transfer requires a coordinator source")
    if source.predecessor_series is not None or target.predecessor_series is not None:
        raise ValueError("history transfer of predecessor series requires separate qualification")
    for name in _CONTEXT:
        if canonical_json_bytes(getattr(source, name)) != canonical_json_bytes(
            getattr(target, name)
        ):
            raise ValueError("history transfer configuration differs: " + name)
    # Remote journal aliases have owner/namespace dependencies. A local transfer
    # must not silently turn those into new authority or materialize whole stores.
    if source.proof_stores is not None or target.proof_stores is not None:
        raise ValueError("history transfer of remote source aliases is not qualified")
    return digest(
        {
            name: hashlib.sha256(canonical_json_bytes(getattr(source, name))).hexdigest()
            for name in _CONTEXT
        }
    )


@dataclass(frozen=True, slots=True)
class HistoryTransferOwner:
    source_root: Path
    target_root: Path
    context_sha256: str
    _source_config: object = field(repr=False)
    _source_path: Path = field(repr=False)
    _source_raw_sha256: str = field(repr=False)
    _source_lease: object = field(repr=False)
    _writer_boot: object = field(repr=False)
    _writer_journals: object = field(repr=False)
    _active: list = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def _seal(self):
        return digest(
            {
                "source": str(self.source_root),
                "target": str(self.target_root),
                "context": self.context_sha256,
                "source_path": str(self._source_path),
                "source_raw": self._source_raw_sha256,
                "source_lease": id(self._source_lease),
                "writer_boot": self._writer_boot._binding,
                "writer_journals": self._writer_journals._binding,
                "lifetime": id(self._active),
            }
        )

    def recheck(self, source=None, target=None):
        if (
            type(self) is not HistoryTransferOwner
            or self._issuer is not _ISSUER
            or self._active != [True]
            or self._binding != self._seal()
        ):
            raise ValueError("history transfer lacks both original stopped owners")
        self._source_lease.recheck(self._source_config)
        self._writer_boot.recheck()
        self._writer_journals.recheck()
        if (
            matching_history_context(self._source_config, self._writer_boot.config)
            != self.context_sha256
            or self.source_root != self._source_lease.root / "history"
            or self.target_root != self._writer_journals.root / "history"
        ):
            raise ValueError("history transfer original context changed")
        raw = _read_root_control_path(self._source_path, MAX_CONFIG_BYTES, modes={0o444})
        if hashlib.sha256(raw).hexdigest() != self._source_raw_sha256:
            raise ValueError("history transfer source configuration changed")
        if (source is None) != (target is None):
            raise ValueError("history transfer requires both original readers")
        if source is not None:
            from .competition_reward_history import RewardControlHistoryReader

            if (
                type(source) is not RewardControlHistoryReader
                or type(target) is not RewardControlHistoryReader
                or source.journal.root != self.source_root
                or target.journal.root != self.target_root
            ):
                raise ValueError("history transfer reader is outside its original owner")
            for reader in (source, target):
                if (
                    reader.hotkey != self._source_config.series.control_hotkey
                    or reader.config_sha256 != digest(self._source_config.chain)
                    or reader.first_block
                    != self._source_config.series.recovery.authority.issued_at_block
                ):
                    raise ValueError("history transfer reader context differs from its owner")


@asynccontextmanager
async def hold_history_transfer_owner(
    anchor,
    *,
    unit,
    config_path,
    standing_boot,
    coordinator_config,
    held_approval=None,
):
    """Authenticate full configurations and fence both owners before any opener."""
    with ExitStack() as preparing:
        report = preparing.enter_context(
            TransferProgress(
                "history_transfer_owner_preparation",
                7,
                unit="checks",
                planning_unit_seconds=(0.01, 30.0),
            )
        )
        writer = await run_owned_thread(
            lambda: select_stopped_writer_boot(anchor, standing_boot, held_approval=held_approval)
        )
        report.advance(1)
        if type(coordinator_config) is HistoryTransferSource:
            source = await run_owned_thread(coordinator_config.recheck)
            source_path = coordinator_config.path
        else:
            source_path = Path(coordinator_config)
            source = await run_owned_thread(load_reward_coordinator_config, source_path)
        context = matching_history_context(source, writer.config)
        raw_sha = hashlib.sha256(canonical_json_bytes(source)).hexdigest()
        report.advance(1)
        with hold_successor_startup_lease(anchor) as startup:
            report.advance(1)
            async with hold_stopped_standing_writer(
                startup, unit=unit, config_path=config_path
            ) as stopped:
                report.advance(1)
                async with hold_stopped_writer_journals(stopped, writer.config.series) as journals:
                    report.advance(1)
                    with hold_reward_cutover_owner(source) as coordinator:
                        report.advance(1)
                        value = HistoryTransferOwner(
                            coordinator.root / "history",
                            journals.root / "history",
                            context,
                            source,
                            source_path,
                            raw_sha,
                            coordinator,
                            writer,
                            journals,
                            [True],
                            _ISSUER,
                        )
                        object.__setattr__(value, "_binding", value._seal())
                        try:
                            await run_owned_thread(value.recheck)
                            report.advance(1)
                            # Preparation finishes before caller work starts; its
                            # heartbeat does not keep reporting an already finished stage.
                            preparing.close()
                            yield value
                            await run_owned_thread(value.recheck)
                            await stopped.recheck()
                        finally:
                            value._active[0] = False
