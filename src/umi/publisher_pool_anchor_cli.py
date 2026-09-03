"""Installed local validation boundary for publisher pool anchors."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .grandpa_finality_supervisor import DurableGrandpaFinalityPort
from .policy import validate_live_shadow_runtime
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .publisher_pool_anchor import (
    MAX_INPUT_BYTES,
    POOL_ANCHOR_ERA_PERIOD_BLOCKS,
    PoolAnchorEvidence,
    PoolAnchorPending,
    ProofBackedPublisherClosingPort,
    PublisherPoolAnchorError,
    PublisherPoolAnchorOperator,
    load_pool_anchor_material,
)
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_anchor_composition import build_production_bittensor_anchor_ports
from .validator_chain import BittensorRawJsonRpc, FinalizedProofCollector, FinalizedRuntimePin
from .validator_extrinsics import ExtrinsicState, ValidatorExtrinsicJournal

OPERATOR_CONFIG_SCHEMA = "umi-publisher-pool-anchor-operator-config/1"
EXECUTION_ACKNOWLEDGEMENT = "submit-exact-publisher-pool-anchor"


class PublisherPoolAnchorOperatorConfig(StrictProtocolModel):
    schema_: Literal[OPERATOR_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    network: Literal["finney"]
    publisher_hotkey: str
    wallet_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_hotkey_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_path: Annotated[str, Field(min_length=1, max_length=4096)]
    state_root: Annotated[str, Field(min_length=1, max_length=4096)]
    target_triple: Annotated[str, Field(min_length=1, max_length=256)]
    storage_proof_verifier_binary: Annotated[str, Field(min_length=1, max_length=4096)]
    finality_verifier_binary: Annotated[str, Field(min_length=1, max_length=4096)]
    finality_chain_spec_path: Annotated[str, Field(min_length=1, max_length=4096)]
    maximum_advances: Annotated[int, Field(ge=1, le=64)] = 16
    poll_seconds: Annotated[float, Field(gt=0, le=30)] = 1.0
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        from .encoding import account_id32

        account_id32(self.publisher_hotkey)
        paths = (
            self.wallet_path,
            self.state_root,
            self.storage_proof_verifier_binary,
            self.finality_verifier_binary,
            self.finality_chain_spec_path,
        )
        if any(not Path(value).is_absolute() for value in paths):
            raise ValueError("operator paths must be absolute")
        if any(Path(value) != Path(os.path.normpath(value)) for value in paths):
            raise ValueError("operator paths must be normalized")
        return self


def _read(path: Path, label: str, *, private: bool = False) -> bytes:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise PublisherPoolAnchorError(f"{label}_path_invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublisherPoolAnchorError(f"{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & (0o077 if private else 0o022)
            or not 0 < before.st_size <= MAX_INPUT_BYTES
        ):
            raise PublisherPoolAnchorError(f"{label}_unsafe")
        chunks = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        getattr(before, "st_ctime_ns", None),
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_ctime_ns", None),
    )
    if before_identity != after_identity or len(raw) != before.st_size:
        raise PublisherPoolAnchorError(f"{label}_changed")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify one certified SN78 publisher pool-anchor intent"
    )
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--certified-release", required=True, type=Path)
    parser.add_argument("--anchor-intents", required=True, type=Path)
    parser.add_argument("--publisher-hotkey", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="validate only; performs no state writes, signing, RPC, or broadcast",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="emit the exact operation identity; performs no writes, signing, RPC, or broadcast",
    )
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--operator-config", type=Path)
    parser.add_argument("--acknowledgement")
    parser.add_argument("--ack-operation-id")
    return parser


def run_cli(argv: Sequence[str] | None = None, *, client_factory=bt.Client) -> int:
    args = _parser().parse_args(argv)
    try:
        loaded = load_pool_anchor_material(
            policy_bytes=_read(args.policy, "policy"),
            certified_release_bytes=_read(args.certified_release, "certified_release"),
            anchor_intents_bytes=_read(args.anchor_intents, "anchor_intents"),
            configured_publisher_hotkey=args.publisher_hotkey,
        )
        if args.execute:
            if args.operator_config is None:
                raise PublisherPoolAnchorError("operator_config_required")
            if args.acknowledgement != EXECUTION_ACKNOWLEDGEMENT:
                raise PublisherPoolAnchorError("execution_acknowledgement_required")
            if args.ack_operation_id != loaded.operation.operation_id:
                raise PublisherPoolAnchorError("execution_operation_id_mismatch")
            config = _load_operator_config(args.operator_config)
            if config.publisher_hotkey != args.publisher_hotkey:
                raise PublisherPoolAnchorError("operator_publisher_mismatch")
            state = Path(config.state_root)
            protected_inputs = (
                args.policy,
                args.certified_release,
                args.anchor_intents,
                args.operator_config,
                Path(config.wallet_path),
                Path(config.storage_proof_verifier_binary),
                Path(config.finality_verifier_binary),
                Path(config.finality_chain_spec_path),
            )
            if any(
                item == state or state in item.parents or item in state.parents
                for item in protected_inputs
            ):
                raise PublisherPoolAnchorError("operator_state_input_overlap")
            return asyncio.run(_execute(loaded, config, client_factory=client_factory))
        print(
            canonical_json_bytes(
                {
                    "binding_sha256": hashlib.sha256(loaded.binding_bytes).hexdigest(),
                    "call": "Commitments.set_commitment",
                    "field_sha256": loaded.intent.pool_manifest_sha256,
                    "mode": "dry_run" if args.dry_run else "check",
                    "netuid": 78,
                    "operation_id": loaded.operation.operation_id,
                    "publisher_hotkey": loaded.intent.publisher_hotkey,
                    "status": "ready",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                    "writes_performed": False,
                    "broadcast_performed": False,
                }
            ).decode("utf-8")
        )
        return 0
    except (PublisherPoolAnchorError, ValueError) as error:
        reason = getattr(error, "reason_code", "pool_anchor_check_failed")
        print(
            canonical_json_bytes(
                {
                    "reason_code": reason,
                    "status": "blocked",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                    "writes_performed": False,
                    "broadcast_performed": False,
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            canonical_json_bytes(
                {
                    "reason_code": (
                        "pool_anchor_execution_failed"
                        if args.execute
                        else "pool_anchor_check_failed"
                    ),
                    "status": "blocked",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                    "writes_performed": "unknown" if args.execute else False,
                    "broadcast_performed": "unknown" if args.execute else False,
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2


def _load_operator_config(path: Path) -> PublisherPoolAnchorOperatorConfig:
    raw = _read(path, "operator_config", private=True)
    try:
        value = PublisherPoolAnchorOperatorConfig.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise PublisherPoolAnchorError("operator_config_invalid") from error
    if canonical_json_bytes(value) != raw:
        raise PublisherPoolAnchorError("operator_config_noncanonical")
    return value


async def _execute(loaded, config, *, client_factory) -> int:
    client = None
    finality = None
    stop = asyncio.Event()
    task = None
    try:
        validate_live_shadow_runtime(
            loaded.policy,
            target_triple=config.target_triple,
            storage_proof_verifier_binary=config.storage_proof_verifier_binary,
            finality_verifier_binary=config.finality_verifier_binary,
            finality_chain_spec_path=config.finality_chain_spec_path,
        )
        wallet = bt.Wallet(
            name=config.wallet_name,
            hotkey=config.wallet_hotkey_name,
            path=config.wallet_path,
        )
        signer = bt.resolve_signer(wallet, role="hotkey")
        from .encoding import account_id32

        if account_id32(signer.ss58_address) != account_id32(config.publisher_hotkey):
            raise PublisherPoolAnchorError("publisher_signer_mismatch")
        client = client_factory(config.network)
        if await client.connect() is not client:
            raise PublisherPoolAnchorError("bittensor_client_connection_invalid")
        root = Path(config.state_root)
        journal = ValidatorExtrinsicJournal(root / "journal")
        finality = DurableGrandpaFinalityPort.from_policy(
            loaded.policy,
            target_triple=config.target_triple,
            binary_path=config.finality_verifier_binary,
            chain_spec_path=config.finality_chain_spec_path,
            state_path=root / "finality.sqlite3",
            initial_minimum_finalized_block=loaded.policy.activation_block - 1,
        )
        proof_pin = loaded.policy.implementation_pins.storage_proof_verifier
        live = loaded.policy.implementation_pins.live_chain
        finality_pin = loaded.policy.implementation_pins.finality_verifier
        if proof_pin is None or live is None or finality_pin is None:
            raise PublisherPoolAnchorError("live_policy_pins_missing")
        proof_digest = proof_pin.release_sha256_by_target.get(config.target_triple)
        finality_digest = finality_pin.release_sha256_by_target.get(config.target_triple)
        if proof_digest is None or finality_digest is None:
            raise PublisherPoolAnchorError("policy_target_missing")
        verifier = SubprocessStorageProofVerifier(
            binary_path=config.storage_proof_verifier_binary,
            expected_sha256=proof_digest,
        )
        anchor = build_production_bittensor_anchor_ports(
            policy=loaded.policy,
            target_triple=config.target_triple,
            subtensor=client,
            signer=signer,
            journal=journal,
            sidecar_root=root / "scan-sidecars",
            finality=finality,
            storage_proof_verifier=verifier,
            finality_verifier_sha256=finality_digest,
            era_period=POOL_ANCHOR_ERA_PERIOD_BLOCKS,
            signer_role="publisher",
        )
        runtime_pin = FinalizedRuntimePin(
            metadata_sha256=live.metadata_sha256,
            spec_version=live.runtime_spec_version,
            transaction_version=live.transaction_version,
            state_version=live.state_version,
            ss58_prefix=42,
        )
        proofs = FinalizedProofCollector(
            BittensorRawJsonRpc(client), finality=finality, verifier=verifier
        )
        operator = PublisherPoolAnchorOperator(
            root / "publisher-anchor",
            journal=journal,
            anchor_ports=anchor,
            submission_finality=finality,
            closing_proofs=ProofBackedPublisherClosingPort(
                finality=finality, proofs=proofs, runtime_pin=runtime_pin
            ),
        )
        task = asyncio.create_task(finality.run(stop))
        result = await _advance_until_terminal(
            operator,
            loaded,
            maximum_advances=config.maximum_advances,
            poll_seconds=config.poll_seconds,
        )
        print(canonical_json_bytes(result).decode("utf-8"))
        return 0
    finally:
        stop.set()
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if finality is not None:
            finality.close()
        if client is not None:
            await client.close()


async def _advance_until_terminal(
    operator: PublisherPoolAnchorOperator,
    loaded,
    *,
    maximum_advances: int,
    poll_seconds: float,
    sleep=asyncio.sleep,
) -> PoolAnchorEvidence:
    """Bound journal work while polling closing finality to its exact height."""

    advances = 0
    waiting_for_closing = False
    last_pending_height = -1
    while True:
        result = await operator.advance(loaded)
        if isinstance(result, PoolAnchorEvidence):
            return result
        if isinstance(result, PoolAnchorPending):
            if (
                result.reason_code != "closing_finality_pending"
                or result.operation_id != loaded.operation.operation_id
                or result.closing_block != loaded.intent.closing_block
                or result.observed_finalized_height >= result.closing_block
                or result.observed_finalized_height < last_pending_height
            ):
                raise PublisherPoolAnchorError("pool_anchor_pending_state_invalid")
            waiting_for_closing = True
            last_pending_height = result.observed_finalized_height
        else:
            if waiting_for_closing:
                raise PublisherPoolAnchorError("pool_anchor_pending_state_regressed")
            if result.state is ExtrinsicState.FINALIZED_FAILURE:
                raise PublisherPoolAnchorError("pool_anchor_inclusion_failed")
            if result.state is ExtrinsicState.EXPIRED:
                raise PublisherPoolAnchorError("pool_anchor_mortal_era_expired")
            advances += 1
            if advances >= maximum_advances:
                raise PublisherPoolAnchorError("anchor_not_terminal")
        await sleep(poll_seconds)


def main() -> None:
    raise SystemExit(run_cli())


__all__ = [
    "EXECUTION_ACKNOWLEDGEMENT",
    "PublisherPoolAnchorOperatorConfig",
    "main",
    "run_cli",
]
