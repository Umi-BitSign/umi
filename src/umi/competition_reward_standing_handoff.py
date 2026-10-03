"""Fence a predecessor standing writer before starting its signed successor."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_decisions import RewardActivation, StandingRewardSeries
from .competition_reward_handoff_models import StandingRewardHandoffPlan, verify_handoff_plan
from .competition_reward_host import (
    _identities,
    _issue_standing_reward_handoff,
    _retained_binding,
    _retained_binding_history,
)
from .competition_reward_series_handoff import (
    VerifiedStandingPredecessorOpportunity,
    validate_standing_predecessor_opportunity,
)
from .competition_reward_transaction_outcome import resolve_standing_transaction
from .competition_reward_transactions import StandingWeightJournal
from .competition_supervisor_adapters import ProductionSuccessorRuntimeAdapter
from .competition_supervisor_runtime import SuccessorSupervisorRuntime
from .open_competition import digest, identity
from .private_files import lock_private_file, private_path


@asynccontextmanager
async def hold_standing_reward_handoff(
    runtime: SuccessorSupervisorRuntime,
    *,
    successor: StandingRewardSeries,
    predecessor: StandingRewardSeries,
    plan: StandingRewardHandoffPlan,
    activation: RewardActivation,
    opportunity: VerifiedStandingPredecessorOpportunity,
    predecessor_approval_sha256: str,
    provider: HistoricalRewardControlProvider,
    maximum_journal_bytes: int,
):
    """Keep the old journal fenced after proving its last attempt terminal.

    The original supervisor process lease already excludes another installed
    service. This context also holds the predecessor series-local writer lock
    and runtime mutex through successor execution. The current executor takes
    the host-wide and successor-local locks in their normal order.
    """
    if (
        type(runtime) is not SuccessorSupervisorRuntime
        or type(runtime.adapter) is not ProductionSuccessorRuntimeAdapter
        or not isinstance(provider, HistoricalRewardControlProvider)
    ):
        raise TypeError("standing handoff requires native installed proof owners")
    plan = verify_handoff_plan(plan, successor)
    if type(plan) is not StandingRewardHandoffPlan:
        raise ValueError("standing handoff requires a standing predecessor plan")
    prior = plan.predecessor
    if (
        digest(predecessor) != prior.series_sha256
        or identity(runtime.config.validator_hotkey)
        not in {identity(value) for value in successor.validators}
        or identity(runtime.config.validator_hotkey)
        not in {identity(value) for value in predecessor.validators}
        or digest(provider.policy) != successor.policy_sha256
    ):
        raise ValueError("standing handoff differs from the installed validator context")
    async with runtime._mutex:
        runtime._require_lease()
        if runtime._standing_handoff_intent() is None:
            raise ValueError("standing handoff lost the original runtime stop intent")
        await runtime.stop_worker_for_handoff()
        container_running = (await runtime.adapter.container.status()).phase == "running"
        if not runtime.adapter._stopped or container_running:
            raise ValueError("standing handoff requires confirmed predecessor worker absence")
        current = _retained_binding(runtime)
        history = _retained_binding_history(runtime)
        candidates = (() if current is None else (current,)) + history
        retained = tuple(
            value for value in candidates if value.approval_sha256 == predecessor_approval_sha256
        )
        if len(retained) != 1:
            raise ValueError("standing handoff lacks its retained predecessor binding")
        retained = retained[0]
        root = (
            Path(runtime.config.state_root) / "standing-rewards" / prior.series_sha256 / "weights"
        )
        for name in ("rounds.sqlite3", "rounds.lock", "standing-writer.lock"):
            path = root / name
            private_path(str(path))
            if not path.is_file():
                raise ValueError("standing handoff predecessor journal is missing")
        journal = StandingWeightJournal(
            root,
            series_sha256=prior.series_sha256,
            validator_hotkey=runtime.config.validator_hotkey,
            chain_config_sha256=digest(provider.config),
            maximum_bytes=maximum_journal_bytes,
        )
        descriptor = lock_private_file(root / "standing-writer.lock")
        active = True
        try:
            if (
                digest(journal.binding) != retained.journal_binding_sha256
                or journal.journal.get("standing_host_identity", "original") != retained.journal_id
            ):
                raise ValueError("standing handoff predecessor journal identity changed")
            identities = _identities(journal)
            pending = journal.pending()
            ended = None
            if pending is not None and pending.signed is not None:
                ended = await resolve_standing_transaction(
                    provider, journal, control_hotkey=prior.control_hotkey
                )
                if ended is None:
                    raise ValueError("standing predecessor transaction remains live")
            through = max(
                (
                    opportunity.through_block,
                    *(
                        value
                        for value in (
                            None if pending is None else pending.intent.block,
                            None if ended is None else ended.snapshot.block_number,
                        )
                        if value is not None
                    ),
                ),
            )
            validate_standing_predecessor_opportunity(
                opportunity,
                plan=plan,
                activation=activation,
                block=through,
            )

            def recheck():
                runtime._require_lease()
                held, named = os.fstat(descriptor), (root / "standing-writer.lock").lstat()
                if (
                    not active
                    or not runtime._mutex.locked()
                    or runtime._standing_handoff_intent() is None
                    or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                    or held.st_nlink != 1
                    or _identities(journal) != identities
                    or journal.pending() != pending
                ):
                    raise ValueError("standing predecessor writer fence changed")

            yield _issue_standing_reward_handoff(
                opportunity,
                predecessor_binding_sha256=digest(retained),
                predecessor_attempt_sha256=(None if pending is None else digest(pending.intent)),
                predecessor_end_sha256=None if ended is None else ended._binding,
                through_block=through,
                recheck=recheck,
            )
        finally:
            active = False
            os.close(descriptor)
