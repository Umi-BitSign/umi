"""Recover immutable request timestamps without treating them as fresh captures.

An owned finalized descendant commits every historical parent header. The
timestamp still needs its own state-root proof. Recovered blocks never become
observer records; each reviewer recovers them using its own observer and proofs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import OrderedDict
from weakref import WeakValueDictionary

from .historical_header_recovery import HistoricalHeaderRecovery
from .protocol import canonical_json_bytes
from .validator_chain import PinnedRuntimeContext, StorageReadSpec
from .validator_plans import VerifiedFinalizedBlock

MAXIMUM_REQUEST_BLOCK_CACHE_BYTES = 32 * 1024**2


class HistoricalRequestBlocks:
    """Provider-scoped proof reuse shared by otherwise short-lived transport views."""

    def __init__(self, provider):
        self.provider = provider
        self.headers = HistoricalHeaderRecovery(provider._connect)
        self._blocks = OrderedDict()
        self._bytes = 0
        self._locks = WeakValueDictionary()

    async def recover(self, height):
        provider = self.provider
        if type(height) is not int or not provider.config.minimum_finalized_block <= height < 2**53:
            raise ValueError("historical request height is outside chain bounds")
        if provider._closed:
            raise ValueError("registration provider is closed")
        if not provider._owned or provider._registration_rpc is None:
            return None
        lock = self._locks.setdefault(height, asyncio.Lock())
        async with lock:
            block = self._blocks.get(height)
            if block is not None:
                self._blocks.move_to_end(height)
                return block
            block = await asyncio.wait_for(
                self._recover(height), provider.config.collection_timeout_seconds
            )
            if block is not None:
                self._blocks[height] = block
                self._bytes += len(block.finality_evidence)
                while self._bytes > MAXIMUM_REQUEST_BLOCK_CACHE_BYTES:
                    _, old = self._blocks.popitem(last=False)
                    self._bytes -= len(old.finality_evidence)
            return block

    async def _recover(self, height):
        provider = self.provider
        anchor = await provider._finality.verified_block_after(height, maximum_distance=None)
        if anchor is None:
            return None
        if not isinstance(anchor, VerifiedFinalizedBlock):
            raise ValueError("historical request anchor is not verified")
        provider._check_finality_context(anchor)
        recovered = await self.headers.recover_height(
            anchor, height, provider._registration_rpc.request
        )
        ref = recovered.snapshot
        runtime = await provider._runtime_context(ref)
        if (
            not isinstance(runtime, PinnedRuntimeContext)
            or runtime.snapshot != ref
            or runtime.pin != provider._runtime_pin
        ):
            raise ValueError("historical request runtime binding mismatch")
        timestamp_spec = StorageReadSpec("Timestamp", "Now")
        batch = await provider._read(runtime, (timestamp_spec,))
        timestamp = batch.reads[0].decoded_value
        if type(timestamp) is not int or not 0 < timestamp <= anchor.timestamp_ms:
            raise ValueError("historical request timestamp exceeds its owned anchor")
        # This receipt describes the owned recovery, not a self-contained GRANDPA
        # proof or an observation made at the old height. Parent headers remain
        # durable hints and are rehashed from the owned anchor after restart.
        evidence = canonical_json_bytes(
            {
                "schema": "umi-cohort-historical-request-block/1",
                "evidence_class": "verified_finalized_ancestry",
                "offline_finality_proof": False,
                "genesis_hash": "0x" + provider.config.chain_pin.genesis_block_hash,
                "anchor": json.loads(anchor.finality_evidence),
                "anchor_sha256": anchor.finality_evidence_sha256,
                "scale_header": recovered.encoded,
                "runtime_metadata_sha256": runtime.metadata_sha256,
                "storage_codec_mode": runtime.storage_codec_mode,
                "timestamp_storage": {
                    "state_root": batch.evidence.verified_state_root,
                    "claims": [
                        {"key": "0x" + c.storage_key.hex(), "value": "0x" + c.value.hex()}
                        for c in batch.evidence.claims
                    ],
                    "proof": ["0x" + node.hex() for node in batch.evidence.proof],
                },
            }
        )
        return VerifiedFinalizedBlock(
            height=ref.block_number,
            block_hash=ref.block_hash,
            state_root=ref.state_root,
            timestamp_ms=timestamp,
            scoring_policy_hash=provider._finality_policy_hash(),
            chain_observation=provider.config.chain_pin,
            finality_verifier_sha256=anchor.finality_verifier_sha256,
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )
