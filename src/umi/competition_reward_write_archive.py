"""Replay complete control blocks using retained bytes and owned finality.

The archive is untrusted input. Only the native slot, runtime, body and event
verifiers can recreate an owned observation. Historical state RPCs are not used
as a fallback; ancestry recovery may still read headers from the chain.
"""

from __future__ import annotations

import hashlib

from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
)
from .competition_reward_control_writes import (
    OwnedRewardControlWrites,
    _control_block_identity,
    _issue_writes,
)
from .competition_reward_history_verifier import verify_write_archive
from .competition_reward_write_evidence import _WriteArchive
from .concurrency import run_owned_thread


async def review_control_writes(
    provider: HistoricalRewardControlProvider,
    *,
    slot_evidence: bytes,
    slot_metadata: bytes,
    evidence: bytes,
) -> OwnedRewardControlWrites:
    """Recreate historical writes after restart without coordinator/state RPCs."""
    if not isinstance(provider, HistoricalRewardControlProvider):
        raise TypeError("control write replay requires the historical native provider")
    archive = await run_owned_thread(_WriteArchive, evidence)
    if hashlib.sha256(slot_evidence).hexdigest() != archive.body["slot_evidence_sha256"]:
        raise ValueError("control write archive names another slot proof")
    slot = await provider.review_control(slot_evidence, slot_metadata)
    async with provider._lock:
        if provider._closed or not provider._owned:
            raise ValueError("control write replay requires a running owned provider")
        await provider._resolve_control_header(slot.snapshot, archive.body["header"])
        identity = _control_block_identity(
            provider, slot, archive.body["header"], archive.body["parent_header"]
        )
        writes, unresolved = await verify_write_archive(
            archive,
            provider._history_proof_tools(),
            identity,
            hotkey=slot.control_hotkey,
            control=slot.control_sha256,
            committed=slot.committed_at_block,
        )
        return _issue_writes(slot, writes, unresolved, evidence)
