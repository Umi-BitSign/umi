from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from umi.chain_evidence import FinalizedSnapshotRef, ShadowNoWeightScan
from umi.grandpa_finality_supervisor import (
    ACCEPTANCE_RECEIPT_SCHEMA,
    VerifiedFinalityScanInterval,
    _acceptance_digest,
)
from umi.protocol import canonical_json_bytes
from umi.validator_chain_scan import (
    DecodedNoWeightInterval,
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from umi.validator_no_weight import LiveNoWeightCaptureError, LiveNoWeightCapturePort

VALIDATOR = bytes.fromhex("11" * 32)


def _snapshot(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=f"0x{height:064x}",
        parent_hash=f"0x{height - 1:064x}",
        state_root=f"0x{height + 100:064x}",
    )


def _identity(height: int) -> VerifiedFinalizedBlockIdentity:
    return VerifiedFinalizedBlockIdentity(
        snapshot=_snapshot(height),
        parent_snapshot=_snapshot(height - 1),
        extrinsics_root=f"0x{height + 200:064x}",
        finality_verifier_sha256="aa" * 32,
        finality_evidence_sha256="bb" * 32,
    )


def _binding(height: int) -> FinalityAttestationReplayBinding:
    return FinalityAttestationReplayBinding(
        minimum_finalized_block=height,
        maximum_records=1,
        startup_timeout_seconds=60,
        expected_sequence=0,
        previous_number=None,
        previous_timestamp_ms=None,
    )


@dataclass
class FakeFinality:
    interval: VerifiedFinalityScanInterval | None
    calls: list[tuple[int, int]]

    async def verified_scan_interval(self, start_height, end_height):
        self.calls.append((start_height, end_height))
        return self.interval


class FakeScanner:
    def __init__(self, result: DecodedNoWeightInterval) -> None:
        self.result = result
        self.calls = []

    async def capture_no_weight_interval(self, identities, **kwargs):
        self.calls.append((identities, kwargs))
        return self.result


def _materials():
    identities = (_identity(10), _identity(11))
    # The interval dataclass validates hashes; these test attestations therefore
    # use a matching digest in replacement identities.
    attestations = (b"attestation-10", b"attestation-11")
    identities = tuple(
        VerifiedFinalizedBlockIdentity(
            snapshot=item.snapshot,
            parent_snapshot=item.parent_snapshot,
            extrinsics_root=item.extrinsics_root,
            finality_verifier_sha256=item.finality_verifier_sha256,
            finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
        )
        for item, attestation in zip(identities, attestations, strict=True)
    )
    bindings = (_binding(10), _binding(11))
    acceptance_receipts = []
    previous_acceptance_digest = bytes(32)
    for sequence, (identity, attestation) in enumerate(zip(identities, attestations, strict=True)):
        accepted_at_unix_ms = 2_000_000_000_000 + sequence
        acceptance_digest = _acceptance_digest(
            previous_acceptance_digest,
            height=identity.snapshot.block_number,
            block_hash=identity.snapshot.block_hash,
            evidence_digest=hashlib.sha256(attestation).digest(),
            segment_index=0,
            sequence=sequence,
            restart_gap=False,
            accepted_at_unix_ms=accepted_at_unix_ms,
        )
        acceptance_receipts.append(
            canonical_json_bytes(
                {
                    "schema": ACCEPTANCE_RECEIPT_SCHEMA,
                    "height": identity.snapshot.block_number,
                    "block_hash": identity.snapshot.block_hash,
                    "evidence_sha256": identity.finality_evidence_sha256,
                    "segment_index": 0,
                    "segment_sequence": sequence,
                    "restart_gap_before": False,
                    "accepted_at_unix_ms": accepted_at_unix_ms,
                    "previous_acceptance_digest": previous_acceptance_digest.hex(),
                    "acceptance_digest": acceptance_digest.hex(),
                }
            )
        )
        previous_acceptance_digest = acceptance_digest
    finality = VerifiedFinalityScanInterval(
        identities,
        attestations,
        bindings,
        tuple(acceptance_receipts),
    )
    blocks = ()
    scan = ShadowNoWeightScan(
        start_snapshot=_snapshot(10),
        end_snapshot=_snapshot(11),
        validator_account_id32=VALIDATOR,
        netuid=78,
        mechanism_id=0,
        scanned_blocks=2,
        scanned_calls=0,
        scanned_events=0,
    )
    # Construct without duplicating scanner fixture machinery; the adapter only
    # accepts this after the fake scanner returns the exact class and boundaries.
    decoded = object.__new__(DecodedNoWeightInterval)
    object.__setattr__(decoded, "blocks", blocks)
    object.__setattr__(decoded, "scan", scan)
    object.__setattr__(decoded, "evidence", (object(), object()))
    return finality, decoded


@pytest.mark.asyncio
async def test_capture_passes_only_verified_inputs_and_hardcoded_shadow_target() -> None:
    finality_interval, decoded = _materials()
    finality = FakeFinality(finality_interval, [])
    scanner = FakeScanner(decoded)
    port = LiveNoWeightCapturePort(
        finality=finality,
        scanner=scanner,
        validator_account=VALIDATOR,
    )

    result = await port.capture(start_block=10, end_block=11)

    assert result is decoded
    assert finality.calls == [(10, 11)]
    identities, kwargs = scanner.calls[0]
    assert identities == finality_interval.identities
    assert kwargs["finality_attestations"] == finality_interval.attestations
    assert kwargs["finality_replay_bindings"] == finality_interval.replay_bindings
    assert kwargs["validator_account"] == VALIDATOR
    assert kwargs["netuid"] == 78
    assert kwargs["mechanism_id"] == 0


@pytest.mark.asyncio
async def test_missing_finality_waits_without_scanning() -> None:
    _finality_interval, decoded = _materials()
    finality = FakeFinality(None, [])
    scanner = FakeScanner(decoded)
    port = LiveNoWeightCapturePort(
        finality=finality,
        scanner=scanner,
        validator_account=VALIDATOR,
    )

    assert await port.capture(start_block=10, end_block=11) is None
    assert scanner.calls == []


@pytest.mark.asyncio
async def test_scanner_failure_is_fail_closed() -> None:
    finality_interval, decoded = _materials()

    class BrokenScanner(FakeScanner):
        async def capture_no_weight_interval(self, identities, **kwargs):
            raise RuntimeError("rpc failed")

    port = LiveNoWeightCapturePort(
        finality=FakeFinality(finality_interval, []),
        scanner=BrokenScanner(decoded),
        validator_account=VALIDATOR,
    )
    with pytest.raises(LiveNoWeightCaptureError, match="no_weight_scan_failed"):
        await port.capture(start_block=10, end_block=11)
