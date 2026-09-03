"""Policy-pinned production composition for the three Bittensor anchors.

Construction is deliberately inert: it creates adapters and durable stores but
performs no RPC and cannot broadcast.  The returned object exposes only
``BittensorAnchorPorts``' operation-bound ``ExtrinsicPorts`` closures; the
wallet, Bittensor client, proof verifier, and raw RPC escape hatch remain
private inside the composition.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from .encoding import account_id32
from .grandpa_finality_supervisor import DurableGrandpaFinalityPort
from .policy import ScoringPolicy, scoring_policy_hash
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_anchor_evidence import (
    MAX_ANCHOR_SCAN_OBJECT_BYTES,
    MAX_ANCHOR_SCAN_TOTAL_BYTES,
    DurableAnchorScanEvidenceStore,
)
from .validator_anchor_ports import (
    DEFAULT_ERA_PERIOD,
    BittensorAnchorPorts,
    DurablePreparedAnchorReader,
    GrandpaQuicknetRoundPort,
)
from .validator_chain import (
    BittensorRawJsonRpc,
    FinalizedProofCollector,
    FinalizedRuntimePin,
    ProofCollectionLimits,
)
from .validator_chain_scan import FinalizedBlockScanner, ScanLimits
from .validator_chain_scan_port import LiveFinalizedBlockScanPort
from .validator_extrinsics import ValidatorExtrinsicJournal


class BittensorAnchorCompositionError(RuntimeError):
    """Production dependencies do not reproduce the live policy pins."""


def build_production_bittensor_anchor_ports(
    *,
    policy: ScoringPolicy,
    target_triple: str,
    subtensor: Any,
    signer: Any,
    journal: ValidatorExtrinsicJournal,
    sidecar_root: str | Path,
    finality: DurableGrandpaFinalityPort,
    storage_proof_verifier: SubprocessStorageProofVerifier,
    finality_verifier_sha256: str,
    proof_limits: ProofCollectionLimits | None = None,
    scan_limits: ScanLimits | None = None,
    maximum_sidecar_object_bytes: int = MAX_ANCHOR_SCAN_OBJECT_BYTES,
    maximum_sidecar_total_bytes: int = MAX_ANCHOR_SCAN_TOTAL_BYTES,
    era_period: int = DEFAULT_ERA_PERIOD,
    signer_role: Literal["validator", "publisher"] = "validator",
) -> BittensorAnchorPorts:
    """Build the exact live anchor boundary without making a chain request.

    The function requires the concrete hash-pinned proof verifier and durable
    smoldot finality store.  It accepts no generic call builder or submitter and
    does not return any of its lower-level capabilities.
    """

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    pins = policy.implementation_pins
    live = pins.live_chain
    proof_pin = pins.storage_proof_verifier
    finality_pin = pins.finality_verifier
    if (
        pins.pin_profile != "live_shadow_calibration"
        or not pins.conformance_fixtures_verified
        or live is None
        or proof_pin is None
        or finality_pin is None
    ):
        raise BittensorAnchorCompositionError(
            "anchor production composition requires complete live-shadow pins"
        )
    if not isinstance(target_triple, str) or not target_triple:
        raise ValueError("target_triple must be nonempty")
    if proof_limits is not None and not isinstance(proof_limits, ProofCollectionLimits):
        raise TypeError("proof_limits must be ProofCollectionLimits or None")
    if scan_limits is not None and not isinstance(scan_limits, ScanLimits):
        raise TypeError("scan_limits must be ScanLimits or None")
    if (
        isinstance(maximum_sidecar_object_bytes, bool)
        or not isinstance(maximum_sidecar_object_bytes, int)
        or not 0 < maximum_sidecar_object_bytes <= MAX_ANCHOR_SCAN_OBJECT_BYTES
        or isinstance(maximum_sidecar_total_bytes, bool)
        or not isinstance(maximum_sidecar_total_bytes, int)
        or not 0 < maximum_sidecar_total_bytes <= MAX_ANCHOR_SCAN_TOTAL_BYTES
        or maximum_sidecar_object_bytes > maximum_sidecar_total_bytes
    ):
        raise ValueError("anchor sidecar byte ceilings exceed their production limits")
    expected_proof = proof_pin.release_sha256_by_target.get(target_triple)
    expected_finality = finality_pin.release_sha256_by_target.get(target_triple)
    if expected_proof is None or expected_finality is None:
        raise BittensorAnchorCompositionError(
            "selected target is absent from the live verifier release pins"
        )
    if not isinstance(storage_proof_verifier, SubprocessStorageProofVerifier):
        raise TypeError("storage_proof_verifier must be the hash-pinned subprocess verifier")
    if storage_proof_verifier.expected_sha256 != expected_proof:
        raise BittensorAnchorCompositionError(
            "storage-proof verifier differs from the target-specific policy release"
        )
    if finality_verifier_sha256 != expected_finality:
        raise BittensorAnchorCompositionError(
            "finality verifier differs from the target-specific policy release"
        )
    if not isinstance(finality, DurableGrandpaFinalityPort):
        raise TypeError("finality must be a DurableGrandpaFinalityPort")

    policy_digest = scoring_policy_hash(policy)
    if (
        finality.scoring_policy_digest != policy_digest
        or finality.chain_observation != live
        or finality.finality_verifier_sha256 != expected_finality
    ):
        raise BittensorAnchorCompositionError(
            "durable finality store differs from the policy or release pins"
        )
    try:
        signer_address = signer.ss58_address
        signer_account = account_id32(signer_address)
    except Exception as error:
        raise TypeError("signer does not expose a valid Bittensor account") from error
    if signer_role == "validator":
        registered = {account_id32(entry.validator_hotkey) for entry in policy.validator_registry}
        allowed_anchor_kinds = frozenset({"assignment_set", "request_set", "response_set"})
    else:
        registered = {account_id32(entry.publisher_hotkey) for entry in policy.publisher_registry}
        allowed_anchor_kinds = frozenset({"publisher_pool"})
    if signer_account not in registered:
        raise BittensorAnchorCompositionError(
            f"anchor signer is absent from the policy {signer_role} registry"
        )
    if not isinstance(journal, ValidatorExtrinsicJournal):
        raise TypeError("journal must be a ValidatorExtrinsicJournal")
    _require_disjoint_stores(journal.root, Path(sidecar_root))

    runtime_pin = FinalizedRuntimePin(
        metadata_sha256=live.metadata_sha256,
        spec_version=live.runtime_spec_version,
        transaction_version=live.transaction_version,
        state_version=live.state_version,
        ss58_prefix=42,
    )
    rpc = BittensorRawJsonRpc(subtensor)
    proofs = FinalizedProofCollector(
        rpc,
        finality=finality,
        verifier=storage_proof_verifier,
        limits=proof_limits,
    )
    scan_port = LiveFinalizedBlockScanPort(
        rpc=rpc,
        proofs=proofs,
        runtime_pin=runtime_pin,
        limits=scan_limits,
    )
    scanner = FinalizedBlockScanner(
        scan_port,
        extrinsics_root_verifier=storage_proof_verifier.verify_extrinsics_root,
        event_proof_verifier=storage_proof_verifier,
        supported_runtime_pins=(runtime_pin,),
        limits=scan_limits,
    )
    rounds = GrandpaQuicknetRoundPort(
        finality=finality,
        scoring_policy_sha256=policy_digest,
        chain_observation=live,
        finality_pin=finality_pin,
        finality_verifier_sha256=expected_finality,
    )
    prepared = DurablePreparedAnchorReader(journal.root)
    sidecars = DurableAnchorScanEvidenceStore(
        sidecar_root,
        maximum_object_bytes=maximum_sidecar_object_bytes,
        maximum_total_object_bytes=maximum_sidecar_total_bytes,
    )
    return BittensorAnchorPorts(
        subtensor=subtensor,
        signer=signer,
        evidence=proofs,
        runtime_pin=runtime_pin,
        rounds=rounds,
        prepared=prepared,
        finality=finality,
        scanner=scanner,
        sidecars=sidecars,
        genesis_hash=live.genesis_block_hash,
        finality_verifier_sha256=expected_finality,
        era_period=era_period,
        allowed_anchor_kinds=allowed_anchor_kinds,
    )


def _require_disjoint_stores(journal_root: Path, sidecar_root: Path) -> None:
    if not journal_root.is_absolute() or not sidecar_root.is_absolute():
        raise BittensorAnchorCompositionError(
            "production anchor evidence stores require absolute paths"
        )
    try:
        journal = journal_root.resolve(strict=True)
        sidecar = sidecar_root.resolve(strict=False)
    except OSError as error:
        raise BittensorAnchorCompositionError("anchor evidence paths are unavailable") from error
    if journal == sidecar or journal in sidecar.parents or sidecar in journal.parents:
        raise BittensorAnchorCompositionError(
            "extrinsic journal and anchor sidecar stores must be disjoint"
        )


__all__ = [
    "BittensorAnchorCompositionError",
    "build_production_bittensor_anchor_ports",
]
