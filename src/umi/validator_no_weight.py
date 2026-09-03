"""Read-only production wiring for a proof-bearing shadow no-weight interval.

This adapter joins two independently constrained components: the durable smoldot
finality store chooses the exact finalized identities and replay attestations,
while ``FinalizedBlockScanner`` authenticates bodies/events and rejects every
SN78 MechId 0 weight call or event from the validator.  It owns no wallet,
signing key, call builder, submission method, or broadcast client.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .chain_evidence import MECHANISM_ID, NETUID
from .encoding import account_id32
from .grandpa_finality_supervisor import VerifiedFinalityScanInterval
from .validator_chain_scan import DecodedNoWeightInterval


class LiveNoWeightCaptureError(RuntimeError):
    """Stable fail-closed error at the finality/scanner composition boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@runtime_checkable
class VerifiedFinalityScanPort(Protocol):
    async def verified_scan_interval(
        self,
        start_height: int,
        end_height: int,
    ) -> VerifiedFinalityScanInterval | None: ...


@runtime_checkable
class NoWeightScannerPort(Protocol):
    async def capture_no_weight_interval(
        self,
        identities,
        *,
        finality_attestations,
        finality_replay_bindings,
        start_block: int,
        end_block: int,
        validator_account: str | bytes,
        netuid: int,
        mechanism_id: int,
    ) -> DecodedNoWeightInterval: ...


class LiveNoWeightCapturePort:
    """Capture one complete proof-bearing interval, or wait for finality."""

    def __init__(
        self,
        *,
        finality: VerifiedFinalityScanPort,
        scanner: NoWeightScannerPort,
        validator_account: str | bytes,
    ) -> None:
        if not callable(getattr(finality, "verified_scan_interval", None)):
            raise TypeError("finality must implement verified_scan_interval")
        if not callable(getattr(scanner, "capture_no_weight_interval", None)):
            raise TypeError("scanner must implement capture_no_weight_interval")
        self._finality = finality
        self._scanner = scanner
        self.validator_account_id32 = account_id32(validator_account)

    async def capture(
        self,
        *,
        start_block: int,
        end_block: int,
    ) -> DecodedNoWeightInterval | None:
        """Return authenticated scan evidence, or ``None`` until the range exists."""

        if isinstance(start_block, bool) or not isinstance(start_block, int) or start_block <= 0:
            raise ValueError("scan start block must be a positive integer")
        if isinstance(end_block, bool) or not isinstance(end_block, int):
            raise TypeError("scan end block must be an integer")
        if end_block < start_block:
            raise ValueError("scan end block must not precede its start")
        try:
            finality = await self._finality.verified_scan_interval(start_block, end_block)
        except Exception as error:
            raise LiveNoWeightCaptureError("finality_interval_failed") from error
        if finality is None:
            return None
        if not isinstance(finality, VerifiedFinalityScanInterval):
            raise LiveNoWeightCaptureError("finality_interval_invalid")
        try:
            captured = await self._scanner.capture_no_weight_interval(
                finality.identities,
                finality_attestations=finality.attestations,
                finality_replay_bindings=finality.replay_bindings,
                start_block=start_block,
                end_block=end_block,
                validator_account=self.validator_account_id32,
                netuid=NETUID,
                mechanism_id=MECHANISM_ID,
            )
        except Exception as error:
            raise LiveNoWeightCaptureError("no_weight_scan_failed") from error
        if not isinstance(captured, DecodedNoWeightInterval) or not captured.evidence:
            raise LiveNoWeightCaptureError("no_weight_scan_evidence_missing")
        if (
            captured.scan.start_snapshot.block_number != start_block
            or captured.scan.end_snapshot.block_number != end_block
            or len(captured.evidence) != end_block - start_block + 1
        ):
            raise LiveNoWeightCaptureError("no_weight_scan_interval_mismatch")
        return captured


__all__ = [
    "LiveNoWeightCaptureError",
    "LiveNoWeightCapturePort",
    "NoWeightScannerPort",
    "VerifiedFinalityScanPort",
]
