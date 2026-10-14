"""Migrate one genuinely completed installed342 local admission review.

This operation runs only after the original owner stops. Its prospective,
root-sealed installation selection grants no successful-verification claim.
The original immutable native intent and matching local signature are required.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import AsyncExitStack, suppress
from dataclasses import asdict, dataclass
from pathlib import Path

from .competition_reward_admission_checkpoint import ABI
from .competition_reward_admission_provenance import (
    load_provenance,
    open_existing_owner_locks,
    provenance_selection_digest,
    validate_provenance,
)
from .competition_reward_admission_source import read_admission_source
from .competition_reward_control_archive import validate_historical_reward_control
from .competition_reward_decision_review import RewardDecisionIntent
from .competition_reward_decisions import verify_reward_decision_proposal
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CompletedAdmissionMigration:
    """Preserved history and a mandatory separate stopped-owner reconciliation.

    This result never authorizes starting signing, publishing or reward writers.
    The later-record inventory is diagnostic, not a verified economic selection.
    """

    checkpoint: dict
    reconciliation: dict


def _handoff_result(checkpoint, handoff):
    return CompletedAdmissionMigration(
        checkpoint=checkpoint,
        reconciliation={
            "status": "stopped_owner_economics_reconciliation_required",
            "publication_authorized": False,
            "later_decisions_present": any(v["count"] for v in handoff.values()),
            "later_records": handoff,
            "preserved_first_block": checkpoint["first_block"],
            "preserved_through_block": checkpoint["snapshot"]["block_number"],
            "preserved_blocks": checkpoint["snapshot"]["block_number"]
            - checkpoint["first_block"]
            + 1,
            "tail_replay_from_block": checkpoint["snapshot"]["block_number"] + 1,
            "tail_target_block": None,
            "tail_eta_seconds": None,
            "tail_eta_basis": "requires_selected_finalized_target_and_measured_native_rate",
        },
    )


def _progress_unchecked(completed, started, state):
    elapsed = time.monotonic() - started
    logger.info(
        "reward_admission_migration_progress %s",
        {
            "stage": "completed_original_admission_migration",
            "state": state,
            "completed_items": completed,
            "total_items": 4,
            "percent": 25.0 * completed,
            "elapsed_seconds": elapsed,
            "eta_seconds": 0.0 if state == "completed" else None,
            "planning_eta_seconds": [1.0, 300.0] if state == "running" else None,
            "eta_basis": "planning_one_local_result_and_one_finalized_boundary"
            if state == "running"
            else "complete"
            if state == "completed"
            else "withdrawn_repair_required",
            "eta_scope": "admission_result_migration_only",
        },
    )


def _progress(completed, started, state):
    with suppress(Exception):
        _progress_unchecked(completed, started, state)


async def migrate_completed_admission(
    provenance_path: Path,
    *,
    provider=None,
    provider_factory=None,
    series,
    policy,
    maximum_history_bytes: int,
):
    """Import under existing owner locks; never migrate an incomplete prefix.

    The caller must select the unchanged original series/policy and history
    directory. No signing key, production action or missing-state initialization
    is performed here. Later original decisions do not invalidate the completed
    admission interval. They are retained, and the returned result always requires
    stopped-owner economics reconciliation before starting any publishing role.
    """
    if (provider is None) == (provider_factory is None):
        raise ValueError("select exactly one existing provider or fenced provider factory")
    started, completed = time.monotonic(), 0
    last_changed = started
    loop, timer = asyncio.get_running_loop(), None

    def heartbeat():
        nonlocal timer
        _progress(
            completed, started, "stalled" if time.monotonic() - last_changed > 60 else "running"
        )
        timer = loop.call_later(30, heartbeat)

    _progress(completed, started, "running")
    timer = loop.call_later(30, heartbeat)
    try:
        selection = await run_owned_thread(load_provenance, Path(provenance_path))
        if (
            selection["series_sha256"] != digest(series)
            or selection["policy_sha256"] != digest(policy)
            or selection["manifest_sha256"] != series.manifest_sha256
            or (
                provider is not None and selection["chain_config_sha256"] != digest(provider.config)
            )
            or selection["first_block"] != series.recovery.authority.issued_at_block
            or selection["control_hotkey"] != series.control_hotkey
            or series.predecessor is not None
        ):
            raise HistoryCheckpointRepairRequired(
                "admission migration changes original owner binding"
            )
        # These helpers open only existing locks and refuse an active old owner.
        with open_existing_owner_locks(selection):
            # No constructor may create or upgrade a journal before prospective
            # original-owner identity and exclusive stopped ownership are proved.
            await run_owned_thread(lambda: validate_provenance(selection, require_stopped=True))
            async with AsyncExitStack() as resources:
                if provider_factory is not None:
                    provider = await resources.enter_async_context(provider_factory(selection))
                if selection["chain_config_sha256"] != digest(provider.config):
                    raise HistoryCheckpointRepairRequired("admission provider binding changed")
                history = await run_owned_thread(
                    lambda: RewardControlHistoryReader(
                        Path(selection["paths"]["history_root"]),
                        control_hotkey=selection["control_hotkey"],
                        chain_config_sha256=selection["chain_config_sha256"],
                        first_block=selection["first_block"],
                        maximum_bytes=maximum_history_bytes,
                    )
                )
                async with history._advance_lock, history._lock:
                    old = await run_owned_thread(history.completed_admission.load)
                    if old is not None:
                        if old["provenance_sha256"] != provenance_selection_digest(selection):
                            raise HistoryCheckpointRepairRequired(
                                "admission migration provenance differs"
                            )
                        _progress(4, started, "completed")
                        retained = await run_owned_thread(
                            lambda: read_admission_source(selection, include_handoff=True)
                        )
                        return _handoff_result(old, retained["handoff"])
                    source = await run_owned_thread(
                        lambda: read_admission_source(selection, include_handoff=True)
                    )
                    handoff = source.pop("handoff")
                    intent = RewardDecisionIntent.model_validate(source["intent"])
                    vote = Signature.model_validate(source["vote"])
                    body = verify_reward_decision_proposal(series, policy, (), intent.decision)
                    if (
                        body.sequence != 0
                        or body.kind != "admit_series"
                        or body.activation is not None
                        or body.predecessor_sha256 is not None
                        or intent.manifest_sha256 != selection["manifest_sha256"]
                        or intent.chain_config_sha256 != selection["chain_config_sha256"]
                        or identity(vote.hotkey) != identity(selection["signer_hotkey"])
                        or identity(vote.hotkey)
                        not in {identity(e.hotkey) for e in policy.evaluators}
                    ):
                        raise HistoryCheckpointRepairRequired(
                            "original native admission result differs"
                        )
                    verify_signature(body, vote)
                    if history._next != history.first_block:
                        raise HistoryCheckpointRepairRequired(
                            "admission migration needs the stopped original prefix"
                        )
                    completed = 1
                    last_changed = time.monotonic()
                    _progress(completed, started, "running")
                    height = body.observed_at_block
                    try:
                        saved = await run_owned_thread(history._load, height)
                        if saved is None:
                            raise HistoryCheckpointRepairRequired(
                                "completed admission boundary frame is missing"
                            )
                        control = await provider.review_control(
                            saved["slot_evidence"], saved["slot_metadata"]
                        )
                        validate_historical_reward_control(
                            control,
                            expected_control_hotkey=history.hotkey,
                            expected_chain_config_sha256=history.config_sha256,
                        )
                        if (
                            control.snapshot.block_number != height
                            or control.control_sha256 is not None
                            or control.committed_at_block is not None
                            or control.evidence_sha256 != intent.control_evidence_sha256
                            or control.metadata_sha256 != intent.control_metadata_sha256
                        ):
                            raise HistoryCheckpointRepairRequired(
                                "completed admission finalized boundary differs"
                            )
                        completed = 2
                        last_changed = time.monotonic()
                        _progress(completed, started, "running")
                        # Cancellation/finality must not race an identity change.
                        repeated = await run_owned_thread(
                            lambda: read_admission_source(selection, include_handoff=True)
                        )
                        if repeated.pop("handoff") != handoff or repeated != source:
                            raise HistoryCheckpointRepairRequired(
                                "original admission changed during migration"
                            )
                        value = {
                            "schema": ABI,
                            "owner": history.checkpoints.owner,
                            "semantics": history.checkpoints.semantics,
                            "first_block": history.first_block,
                            "control_hotkey": history.hotkey,
                            "chain_config_sha256": history.config_sha256,
                            "snapshot": asdict(control.snapshot),
                            "header": json.loads(control.evidence)["finality"]["block"][
                                "scale_header"
                            ],
                            "control_sha256": None,
                            "committed_at_block": None,
                            "history_sha256": intent.control_history_sha256,
                            "provenance_path": str(Path(provenance_path)),
                            "provenance_sha256": provenance_selection_digest(selection),
                            "source_sha256": digest(source),
                            "boundary_sources": history._source_tokens[height],
                        }
                        completed = 3
                        last_changed = time.monotonic()
                        _progress(completed, started, "running")
                        await run_owned_thread(history.completed_admission.remember, value)
                    finally:
                        history._source_tokens.pop(height, None)
                        history._prepared_encodings.pop(height, None)
                    _progress(4, started, "completed")
                    return _handoff_result(value, handoff)
    except asyncio.CancelledError:
        _progress(completed, started, "interrupted")
        raise
    except Exception as error:
        _progress(completed, started, "repair_required")
        if isinstance(error, HistoryCheckpointRepairRequired):
            raise
        raise HistoryCheckpointRepairRequired(
            "original completed admission migration requires explicit repair"
        ) from error
    finally:
        if timer is not None:
            timer.cancel()
