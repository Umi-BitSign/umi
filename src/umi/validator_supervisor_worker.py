"""Fixed, lease-bound worker for signed validator-supervisor releases.

The host supervisor selects an immutable OCI manifest and one typed mode.  This
entrypoint accepts no command, module, or path from the directive.  Bootstrap
inputs have fixed names beneath the read-only operator-input mount, and every
chain-capable attempt is fenced by a separately owned GRANDPA stream plus a
durable intent journal.

Only the temporary bootstrap mode is implemented in this release.  Hold remains
an absence of a worker container.  Shadow and translation modes fail closed until
their complete signed worker profiles are released.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import os
import re
import stat
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any, Literal, Protocol

import bittensor as bt
from pydantic import Field, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_direct_weights import (
    DIRECT_LIVE_SUBMIT_ACKNOWLEDGEMENT,
    BittensorDirectBootstrapChain,
    DirectBootstrapCallMaterial,
    DirectBootstrapOperationalPreflight,
    DirectBootstrapSubmissionJournal,
    DirectBootstrapSubmissionReceipt,
    DirectBootstrapTransitionAuthorization,
    submit_direct_bootstrap_weights,
    validate_direct_bootstrap_preflight,
    verify_direct_transition_authorization,
)
from .bootstrap_weight_operator import BootstrapOperatorError
from .bootstrap_weights import (
    SignedBootstrapEligibilityManifest,
    bootstrap_policy_hash,
)
from .encoding import account_id32
from .grandpa_finality import (
    FINNEY_BOOTSTRAP_BLOCK_HASH,
    FINNEY_BOOTSTRAP_BLOCK_NUMBER,
    FINNEY_CHAIN_SPEC_SHA256,
    FINNEY_GENESIS_HASH,
    GrandpaFinalityObserver,
)
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import MAX_JSON_SAFE_INTEGER
from .validator_supervisor_adapters import (
    FinneyFinalizedBlockReader,
    OwnedFinalizedBlock,
    SupervisorReleaseManifest,
)

WORKER_JOURNAL_SCHEMA = "umi-validator-supervisor-worker-journal/1"
WORKER_AUTHORIZATION_CLAIM_SCHEMA = "umi-validator-supervisor-authorization-claim/1"
WORKER_STATE_SCHEMA_VERSION = 1

WORKER_RELEASE_MANIFEST = Path("/run/umi/release/release-manifest.json")
WORKER_OPERATOR_INPUT_ROOT = Path("/run/umi/operator-inputs")
WORKER_WALLET_ROOT = Path("/run/umi/wallets")
WORKER_WALLET_NAME = "runtime"
WORKER_STATE_ROOT = Path("/var/lib/umi-worker")
WORKER_IMAGE_REVISION = Path("/opt/umi-image-revision")
WORKER_FINALITY_BINARY = Path("/opt/umi/bin/umi-grandpa-finality-observer")
WORKER_FINALITY_CHAIN_SPEC = Path("/opt/umi/finney.json")

BOOTSTRAP_INPUT_ROOT = WORKER_OPERATOR_INPUT_ROOT / "bootstrap"
BOOTSTRAP_SIGNED_MANIFEST = BOOTSTRAP_INPUT_ROOT / "signed-manifest.json"
BOOTSTRAP_TRANSITION_AUTHORIZATION = BOOTSTRAP_INPUT_ROOT / "direct-transition-authorization.json"
BOOTSTRAP_DRAIN_CHECKPOINT = BOOTSTRAP_INPUT_ROOT / "drain-checkpoint.json"

MAX_WORKER_INPUT_BYTES = 4 * 1024 * 1024
MAX_WORKER_JOURNAL_BYTES = 1024 * 1024
OWNED_FINALITY_TIMEOUT_SECONDS = 30.0
WORKER_INITIAL_HEAD_TIMEOUT_SECONDS = 120.0
WORKER_FINALITY_FRESHNESS_SECONDS = 30.0
BOOTSTRAP_DIRECTIVE_HEADROOM_BLOCKS = 16

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9_]{1,128}$")
_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_MODE_BY_COMMAND = {
    "run-hold": "hold",
    "run-inactive-shadow": "inactive_shadow",
    "run-bootstrap-service-weights": "bootstrap_service_weights",
    "run-translation-weights": "translation_weights",
}


class SupervisorWorkerError(RuntimeError):
    """Stable, non-sensitive worker failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class SupervisorWorkerEnvironment:
    """Exact fixed values supplied by the host's reviewed Podman adapter."""

    mode: str
    directive_sha256: str
    policy_sha256: str
    release_manifest_sha256: str
    sequence: int
    valid_from_block: int
    valid_through_block: int
    expected_validator_hotkey: str
    wallet_hotkey_name: str

    @classmethod
    def from_environ(
        cls,
        mode_command: str,
        environ: Mapping[str, str] | None = None,
    ) -> SupervisorWorkerEnvironment:
        values = os.environ if environ is None else environ
        mode = _MODE_BY_COMMAND.get(mode_command)
        if mode is None:
            raise SupervisorWorkerError("worker_mode_invalid")
        _require_fixed_environment(values)
        try:
            sequence = int(values["UMI_SUPERVISOR_SEQUENCE"], 10)
            valid_from = int(values["UMI_SUPERVISOR_VALID_FROM_BLOCK"], 10)
            valid_through = int(values["UMI_SUPERVISOR_VALID_THROUGH_BLOCK"], 10)
            result = cls(
                mode=mode,
                directive_sha256=values["UMI_SUPERVISOR_DIRECTIVE_SHA256"],
                policy_sha256=values["UMI_SUPERVISOR_POLICY_SHA256"],
                release_manifest_sha256=values["UMI_RELEASE_MANIFEST_SHA256"],
                sequence=sequence,
                valid_from_block=valid_from,
                valid_through_block=valid_through,
                expected_validator_hotkey=values["UMI_EXPECTED_VALIDATOR_HOTKEY"],
                wallet_hotkey_name=values["UMI_WALLET_HOTKEY"],
            )
        except (KeyError, ValueError) as error:
            raise SupervisorWorkerError("worker_environment_invalid") from error
        result.validate()
        return result

    def validate(self) -> None:
        for value in (
            self.directive_sha256,
            self.policy_sha256,
            self.release_manifest_sha256,
        ):
            if _HEX32_RE.fullmatch(value) is None:
                raise SupervisorWorkerError("worker_environment_invalid")
        if not 1 <= self.sequence <= MAX_JSON_SAFE_INTEGER:
            raise SupervisorWorkerError("worker_environment_invalid")
        if not 1 <= self.valid_from_block <= self.valid_through_block <= MAX_JSON_SAFE_INTEGER:
            raise SupervisorWorkerError("worker_environment_invalid")
        try:
            account_id32(self.expected_validator_hotkey)
        except (TypeError, ValueError) as error:
            raise SupervisorWorkerError("worker_environment_invalid") from error
        if (
            not self.wallet_hotkey_name
            or Path(self.wallet_hotkey_name).name != self.wallet_hotkey_name
            or len(self.wallet_hotkey_name) > 128
        ):
            raise SupervisorWorkerError("worker_environment_invalid")


class SupervisorWorkerJournal(StrictProtocolModel):
    """Durable, single-attempt bootstrap effect record."""

    schema_: Literal[WORKER_JOURNAL_SCHEMA] = Field(alias="schema")
    state_schema_version: Literal[WORKER_STATE_SCHEMA_VERSION]
    mode: Literal["bootstrap_service_weights"]
    directive_sha256: Hex32
    policy_sha256: Hex32
    release_manifest_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_from_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    manifest_input_sha256: Hex32
    transition_authorization_input_sha256: Hex32
    drain_checkpoint_input_sha256: Hex32
    phase: Literal["prepared", "effect_intent", "completed", "ambiguous"]
    intent_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)] | None
    receipt_sha256: Hex32 | None
    call_material_sha256: Hex32 | None
    reason_code: Annotated[str, Field(min_length=1, max_length=128)] | None

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        account_id32(self.validator_hotkey)
        if self.valid_through_block < self.valid_from_block:
            raise ValueError("worker journal lease is inverted")
        if self.phase == "prepared":
            if any(
                value is not None
                for value in (
                    self.intent_finalized_block,
                    self.receipt_sha256,
                    self.call_material_sha256,
                    self.reason_code,
                )
            ):
                raise ValueError("prepared worker journal has outcome fields")
        elif self.phase == "effect_intent":
            if self.intent_finalized_block is None or any(
                value is not None
                for value in (self.receipt_sha256, self.call_material_sha256, self.reason_code)
            ):
                raise ValueError("effect-intent journal fields are inconsistent")
        elif self.phase == "completed":
            if (
                self.intent_finalized_block is None
                or self.receipt_sha256 is None
                or self.call_material_sha256 is None
                or self.reason_code is not None
            ):
                raise ValueError("completed worker journal lacks exact outputs")
        elif (
            self.intent_finalized_block is None
            or self.reason_code is None
            or any(value is not None for value in (self.receipt_sha256, self.call_material_sha256))
        ):
            raise ValueError("ambiguous worker journal fields are inconsistent")
        return self


class SupervisorBootstrapAuthorizationClaim(StrictProtocolModel):
    """Validator-global durable claim for one single-use transition authorization."""

    schema_: Literal[WORKER_AUTHORIZATION_CLAIM_SCHEMA] = Field(alias="schema")
    submission_id: Hex32
    transition_authorization_sha256: Hex32
    manifest_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    directive_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    intent_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    intent_finalized_block_hash: BlockHash

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


@dataclass(frozen=True, slots=True)
class BootstrapWorkerInputs:
    signed_manifest: SignedBootstrapEligibilityManifest
    transition_authorization: DirectBootstrapTransitionAuthorization
    drain_checkpoint: DirectBootstrapOperationalPreflight
    manifest_bytes: bytes
    transition_authorization_bytes: bytes
    drain_checkpoint_bytes: bytes


@dataclass(frozen=True, slots=True)
class BootstrapWorkerOutputs:
    root: Path
    receipt: Path
    call_material: Path
    operator_state: Path


class WorkerFinalizedBlockReader(Protocol):
    async def read_finalized_identity(self) -> OwnedFinalizedBlock: ...

    async def stop(self) -> None: ...


class OwnedFinalityLease:
    """Continuously enforce one directive lease from an owned finality source."""

    def __init__(
        self,
        reader: WorkerFinalizedBlockReader,
        *,
        valid_from_block: int,
        valid_through_block: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.reader = reader
        self.valid_from_block = valid_from_block
        self.valid_through_block = valid_through_block
        self.monotonic = monotonic
        self.head: OwnedFinalizedBlock | None = None
        self._identities: dict[int, str] = {}
        self._accepted_at: float | None = None
        self._ready = asyncio.Event()
        self._advanced = asyncio.Event()
        self._terminal = asyncio.Event()
        self._terminal_reason: str | None = None

    async def run(self) -> None:
        try:
            while not self._terminal.is_set():
                block = await self.reader.read_finalized_identity()
                if not isinstance(block, OwnedFinalizedBlock) or (
                    self.head is not None and block.number <= self.head.number
                ):
                    raise SupervisorWorkerError("worker_finality_invalid")
                self.head = block
                self._identities[block.number] = block.block_hash
                self._accepted_at = self.monotonic()
                self._advanced.set()
                if block.number >= self.valid_from_block:
                    self._ready.set()
                if block.number >= self.valid_through_block:
                    self._finish("directive_lease_expired")
        except asyncio.CancelledError:
            raise
        except Exception:
            self._finish("worker_finality_failed")

    async def wait_ready(
        self, timeout_seconds: float = WORKER_INITIAL_HEAD_TIMEOUT_SECONDS
    ) -> OwnedFinalizedBlock:
        ready = asyncio.create_task(self._ready.wait())
        terminal = asyncio.create_task(self._terminal.wait())
        try:
            done, _pending = await asyncio.wait(
                (ready, terminal),
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise SupervisorWorkerError("worker_finality_start_timeout")
            if self._terminal.is_set():
                raise SupervisorWorkerError(self._terminal_reason or "worker_finality_failed")
            return self.require_headroom(0)
        finally:
            for task in (ready, terminal):
                if not task.done():
                    task.cancel()
            await asyncio.gather(ready, terminal, return_exceptions=True)

    def require_headroom(self, blocks: int) -> OwnedFinalizedBlock:
        if isinstance(blocks, bool) or not isinstance(blocks, int) or blocks < 0:
            raise TypeError("lease headroom must be a nonnegative integer")
        if self._terminal.is_set():
            raise SupervisorWorkerError(self._terminal_reason or "worker_finality_failed")
        head, accepted = self.head, self._accepted_at
        if head is None or accepted is None or head.number < self.valid_from_block:
            raise SupervisorWorkerError("directive_lease_not_active")
        if self.monotonic() - accepted > WORKER_FINALITY_FRESHNESS_SECONDS:
            raise SupervisorWorkerError("worker_finality_stale")
        if head.number + blocks >= self.valid_through_block:
            raise SupervisorWorkerError("directive_lease_headroom_insufficient")
        return head

    async def require_snapshot(
        self,
        block_number: int,
        block_hash: str,
        headroom_blocks: int,
    ) -> None:
        """Require an SDK snapshot to match an owned finalized block exactly."""

        if (
            isinstance(block_number, bool)
            or not isinstance(block_number, int)
            or not 1 <= block_number <= MAX_JSON_SAFE_INTEGER
            or not isinstance(block_hash, str)
            or _BLOCK_HASH_RE.fullmatch(block_hash) is None
        ):
            raise SupervisorWorkerError("worker_finality_snapshot_invalid")
        while self.head is None or self.head.number < block_number:
            if self._terminal.is_set():
                raise SupervisorWorkerError(self._terminal_reason or "worker_finality_failed")
            self._advanced.clear()
            if self.head is not None and self.head.number >= block_number:
                break
            advanced = asyncio.create_task(self._advanced.wait())
            terminal = asyncio.create_task(self._terminal.wait())
            try:
                done, _pending = await asyncio.wait(
                    (advanced, terminal), return_when=asyncio.FIRST_COMPLETED
                )
                if terminal in done:
                    raise SupervisorWorkerError(self._terminal_reason or "worker_finality_failed")
            finally:
                for task in (advanced, terminal):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(advanced, terminal, return_exceptions=True)
        if self._identities.get(block_number) != block_hash:
            raise SupervisorWorkerError("worker_finality_snapshot_mismatch")
        self.require_headroom(headroom_blocks)

    async def wait_terminal(self) -> str:
        await self._terminal.wait()
        return self._terminal_reason or "worker_finality_failed"

    def _finish(self, reason_code: str) -> None:
        if not self._terminal.is_set():
            self._terminal_reason = reason_code
            self._terminal.set()
            self._ready.set()
            self._advanced.set()


BootstrapEffectIntent = Callable[[], None]
BootstrapSnapshotGuard = Callable[[int, str, int], Awaitable[None]]

BootstrapSubmitter = Callable[
    [
        BootstrapWorkerInputs,
        SupervisorWorkerEnvironment,
        BootstrapWorkerOutputs,
        Any,
        BootstrapEffectIntent,
        BootstrapSnapshotGuard,
    ],
    Awaitable[DirectBootstrapSubmissionReceipt],
]

BootstrapPreflighter = Callable[
    [BootstrapWorkerInputs, SupervisorWorkerEnvironment, Any],
    Awaitable[DirectBootstrapOperationalPreflight],
]


async def run_bootstrap_worker(
    environment: SupervisorWorkerEnvironment,
    *,
    release_manifest_path: Path = WORKER_RELEASE_MANIFEST,
    operator_input_root: Path = WORKER_OPERATOR_INPUT_ROOT,
    state_root: Path = WORKER_STATE_ROOT,
    image_revision_path: Path = WORKER_IMAGE_REVISION,
    finality_reader: WorkerFinalizedBlockReader | None = None,
    wallet_loader: Callable[[SupervisorWorkerEnvironment], Any] | None = None,
    preflighter: BootstrapPreflighter | None = None,
    submitter: BootstrapSubmitter | None = None,
    remain_until_expiry: bool = True,
) -> SupervisorWorkerJournal:
    """Run or recover the one bootstrap submission authorized by a directive."""

    environment.validate()
    if environment.mode != "bootstrap_service_weights":
        raise SupervisorWorkerError("worker_mode_unimplemented")
    release_bytes, release = _read_canonical(release_manifest_path, SupervisorReleaseManifest)
    _verify_release(environment, release, release_bytes, image_revision_path)
    transaction_root = state_root / "bootstrap-transactions" / environment.directive_sha256
    authorization_root = state_root / "bootstrap-authorizations"
    _prepare_transaction_root(transaction_root)
    _prepare_transaction_root(authorization_root)
    lock = _acquire_lock(transaction_root / "worker.lock")
    owned_reader = finality_reader or _production_finality_reader()
    lease = OwnedFinalityLease(
        owned_reader,
        valid_from_block=environment.valid_from_block,
        valid_through_block=environment.valid_through_block,
    )
    finality_task = asyncio.create_task(lease.run(), name="umi-worker-owned-finality")
    try:
        head = await lease.wait_ready()
        outputs = _bootstrap_outputs(transaction_root, authorization_root)
        _prepare_transaction_root(outputs.operator_state)
        journal = _load_or_prepare_transaction(
            environment,
            transaction_root=transaction_root,
            operator_input_root=operator_input_root,
            worker_revision=release.umi_git_revision,
            current_block=head.number,
        )
        inputs = _load_snapshot_inputs(
            transaction_root,
            journal,
            worker_revision=release.umi_git_revision,
            current_block=head.number,
        )
        claim = _load_authorization_claim(authorization_root, inputs, environment)
        if claim is not None and journal.phase == "prepared":
            journal = _restore_claimed_intent(journal, claim)
            _replace_canonical(outputs.root / "journal.json", journal)
        elif claim is None and journal.phase != "prepared":
            raise SupervisorWorkerError("worker_authorization_claim_missing")
        wallet = (wallet_loader or _load_bound_wallet)(environment)
        _require_wallet_identity(wallet, environment.expected_validator_hotkey)

        if journal.phase == "effect_intent":
            recovered = _recover_completed_output(journal, inputs, outputs)
            if recovered is None:
                journal = _mark_ambiguous(journal, "worker_interrupted_after_effect_intent")
                _replace_canonical(outputs.root / "journal.json", journal)
                raise SupervisorWorkerError("worker_effect_ambiguous")
            journal = recovered
            _replace_canonical(outputs.root / "journal.json", journal)
        elif journal.phase == "ambiguous":
            raise SupervisorWorkerError("worker_effect_ambiguous")
        elif journal.phase == "completed":
            recovered = _recover_completed_output(journal, inputs, outputs)
            if (
                recovered is None
                or recovered.receipt_sha256 != journal.receipt_sha256
                or recovered.call_material_sha256 != journal.call_material_sha256
            ):
                raise SupervisorWorkerError("worker_completed_state_invalid")
        elif journal.phase == "prepared":
            fresh = await _run_read_only_under_lease(
                lease,
                (preflighter or _direct_bootstrap_preflight)(inputs, environment, wallet),
            )
            _validate_drain_continuity(
                environment,
                inputs,
                fresh,
                lease.require_headroom(0).number,
            )
            await lease.require_snapshot(
                fresh.chain.snapshot.block_number,
                fresh.chain.snapshot.block_hash,
                0,
            )

            def record_effect_intent() -> None:
                nonlocal journal
                identity = lease.require_headroom(BOOTSTRAP_DIRECTIVE_HEADROOM_BLOCKS)
                durable_claim = _claim_bootstrap_authorization(
                    authorization_root,
                    inputs,
                    environment,
                    identity,
                )
                candidate = _restore_claimed_intent(journal, durable_claim)
                _replace_canonical(outputs.root / "journal.json", candidate)
                journal = candidate

            effect = asyncio.create_task(
                (submitter or _submit_bootstrap)(
                    inputs,
                    environment,
                    outputs,
                    wallet,
                    record_effect_intent,
                    lease.require_snapshot,
                ),
                name="umi-worker-bootstrap-effect",
            )
            terminal = asyncio.create_task(lease.wait_terminal(), name="umi-worker-lease-terminal")
            done, _pending = await asyncio.wait(
                (effect, terminal), return_when=asyncio.FIRST_COMPLETED
            )
            if terminal in done:
                effect.cancel()
                await asyncio.gather(effect, return_exceptions=True)
                journal = _restore_intent_from_disk_claim(
                    journal,
                    authorization_root,
                    inputs,
                    environment,
                    outputs.root / "journal.json",
                )
                if journal.phase == "effect_intent":
                    journal = _mark_ambiguous(journal, terminal.result())
                    _replace_canonical(outputs.root / "journal.json", journal)
                    raise SupervisorWorkerError("worker_effect_ambiguous")
                raise SupervisorWorkerError(terminal.result())
            terminal.cancel()
            await asyncio.gather(terminal, return_exceptions=True)
            try:
                receipt = effect.result()
                if journal.phase != "effect_intent":
                    raise SupervisorWorkerError("worker_effect_intent_missing")
                journal = _complete_from_output(journal, inputs, outputs, receipt)
            except Exception as error:
                journal = _restore_intent_from_disk_claim(
                    journal,
                    authorization_root,
                    inputs,
                    environment,
                    outputs.root / "journal.json",
                )
                if journal.phase == "effect_intent":
                    journal = _mark_ambiguous(journal, _stable_effect_reason(error))
                    _replace_canonical(outputs.root / "journal.json", journal)
                    raise SupervisorWorkerError("worker_effect_ambiguous") from error
                raise SupervisorWorkerError(_stable_effect_reason(error)) from error
            _replace_canonical(outputs.root / "journal.json", journal)

        if remain_until_expiry:
            reason = await lease.wait_terminal()
            if reason != "directive_lease_expired":
                raise SupervisorWorkerError(reason)
        return journal
    finally:
        finality_task.cancel()
        await asyncio.gather(finality_task, return_exceptions=True)
        with contextlib.suppress(Exception):
            await owned_reader.stop()
        os.close(lock)


async def _submit_bootstrap(
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
    outputs: BootstrapWorkerOutputs,
    wallet: Any,
    before_first_effect: BootstrapEffectIntent,
    finalized_snapshot_guard: BootstrapSnapshotGuard,
) -> DirectBootstrapSubmissionReceipt:
    return await submit_direct_bootstrap_weights(
        inputs.signed_manifest,
        authorization=inputs.transition_authorization,
        wallet=wallet,
        chain=BittensorDirectBootstrapChain(finalized_timeout_seconds=20.0),
        receipt_output=outputs.receipt,
        call_material_output=outputs.call_material,
        state_dir=outputs.operator_state,
        live_submit=True,
        acknowledgement=DIRECT_LIVE_SUBMIT_ACKNOWLEDGEMENT,
        before_first_effect=before_first_effect,
        finalized_snapshot_guard=finalized_snapshot_guard,
    )


async def _direct_bootstrap_preflight(
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
    wallet: Any,
) -> DirectBootstrapOperationalPreflight:
    del wallet
    chain = BittensorDirectBootstrapChain(finalized_timeout_seconds=20.0)
    return await chain.direct_operational_preflight(
        inputs.signed_manifest,
        authorization=inputs.transition_authorization,
        validator_hotkey=environment.expected_validator_hotkey,
    )


async def _run_read_only_under_lease(
    lease: OwnedFinalityLease,
    operation: Awaitable[DirectBootstrapOperationalPreflight],
) -> DirectBootstrapOperationalPreflight:
    task = asyncio.create_task(operation, name="umi-worker-direct-preflight")
    terminal = asyncio.create_task(lease.wait_terminal(), name="umi-worker-preflight-lease")
    try:
        done, _pending = await asyncio.wait((task, terminal), return_when=asyncio.FIRST_COMPLETED)
        if terminal in done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise SupervisorWorkerError(terminal.result())
        terminal.cancel()
        await asyncio.gather(terminal, return_exceptions=True)
        return task.result()
    finally:
        for pending in (task, terminal):
            if not pending.done():
                pending.cancel()
        await asyncio.gather(task, terminal, return_exceptions=True)


def _load_or_prepare_transaction(
    environment: SupervisorWorkerEnvironment,
    *,
    transaction_root: Path,
    operator_input_root: Path,
    worker_revision: str,
    current_block: int,
) -> SupervisorWorkerJournal:
    journal_path = transaction_root / "journal.json"
    if journal_path.exists():
        journal = _load_canonical(journal_path, SupervisorWorkerJournal)
        _require_journal_binding(journal, environment)
        return journal
    if any(transaction_root.iterdir()):
        allowed = {"worker.lock"}
        if {item.name for item in transaction_root.iterdir()} != allowed:
            raise SupervisorWorkerError("worker_partial_state")
    source_root = operator_input_root / "bootstrap"
    manifest_bytes, signed = _read_canonical(
        source_root / "signed-manifest.json", SignedBootstrapEligibilityManifest
    )
    authorization_bytes, authorization = _read_canonical(
        source_root / "direct-transition-authorization.json",
        DirectBootstrapTransitionAuthorization,
    )
    drain_bytes, drain = _read_canonical(
        source_root / "drain-checkpoint.json", DirectBootstrapOperationalPreflight
    )
    _validate_bootstrap_inputs(
        environment,
        signed,
        authorization,
        drain,
        worker_revision,
        current_block,
    )
    _write_new_bytes(transaction_root / "signed-manifest.json", manifest_bytes)
    _write_new_bytes(transaction_root / "direct-transition-authorization.json", authorization_bytes)
    _write_new_bytes(transaction_root / "drain-checkpoint.json", drain_bytes)
    journal = SupervisorWorkerJournal(
        schema=WORKER_JOURNAL_SCHEMA,
        state_schema_version=WORKER_STATE_SCHEMA_VERSION,
        mode="bootstrap_service_weights",
        directive_sha256=environment.directive_sha256,
        policy_sha256=environment.policy_sha256,
        release_manifest_sha256=environment.release_manifest_sha256,
        sequence=environment.sequence,
        valid_from_block=environment.valid_from_block,
        valid_through_block=environment.valid_through_block,
        validator_hotkey=environment.expected_validator_hotkey,
        manifest_input_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        transition_authorization_input_sha256=hashlib.sha256(authorization_bytes).hexdigest(),
        drain_checkpoint_input_sha256=hashlib.sha256(drain_bytes).hexdigest(),
        phase="prepared",
        intent_finalized_block=None,
        receipt_sha256=None,
        call_material_sha256=None,
        reason_code=None,
    )
    _write_new_canonical(transaction_root / "journal.json", journal)
    return journal


def _load_snapshot_inputs(
    transaction_root: Path,
    journal: SupervisorWorkerJournal,
    *,
    worker_revision: str,
    current_block: int,
) -> BootstrapWorkerInputs:
    manifest_bytes, signed = _read_canonical(
        transaction_root / "signed-manifest.json", SignedBootstrapEligibilityManifest
    )
    authorization_bytes, authorization = _read_canonical(
        transaction_root / "direct-transition-authorization.json",
        DirectBootstrapTransitionAuthorization,
    )
    drain_bytes, drain = _read_canonical(
        transaction_root / "drain-checkpoint.json", DirectBootstrapOperationalPreflight
    )
    if (
        hashlib.sha256(manifest_bytes).hexdigest() != journal.manifest_input_sha256
        or hashlib.sha256(authorization_bytes).hexdigest()
        != journal.transition_authorization_input_sha256
        or hashlib.sha256(drain_bytes).hexdigest() != journal.drain_checkpoint_input_sha256
    ):
        raise SupervisorWorkerError("worker_input_snapshot_mismatch")
    _validate_bootstrap_inputs_from_journal(
        journal,
        signed,
        authorization,
        drain,
        worker_revision,
        current_block,
    )
    return BootstrapWorkerInputs(
        signed_manifest=signed,
        transition_authorization=authorization,
        drain_checkpoint=drain,
        manifest_bytes=manifest_bytes,
        transition_authorization_bytes=authorization_bytes,
        drain_checkpoint_bytes=drain_bytes,
    )


def _validate_bootstrap_inputs(
    environment: SupervisorWorkerEnvironment,
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
    drain: DirectBootstrapOperationalPreflight,
    worker_revision: str,
    current_block: int,
) -> None:
    if bootstrap_policy_hash(signed.manifest.policy) != environment.policy_sha256:
        raise SupervisorWorkerError("worker_policy_binding_mismatch")
    _validate_bootstrap_policy_bounds(environment, signed, authorization)
    if authorization.umi_git_revision != worker_revision:
        raise SupervisorWorkerError("worker_transition_revision_mismatch")
    try:
        verify_direct_transition_authorization(
            signed,
            authorization,
            current_block=current_block,
        )
    except Exception as error:
        raise SupervisorWorkerError("worker_transition_authorization_invalid") from error
    _validate_checkpoint_binding(environment, signed, authorization, drain, current_block)


def _validate_bootstrap_inputs_from_journal(
    journal: SupervisorWorkerJournal,
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
    drain: DirectBootstrapOperationalPreflight,
    worker_revision: str,
    current_block: int,
) -> None:
    environment = SupervisorWorkerEnvironment(
        mode=journal.mode,
        directive_sha256=journal.directive_sha256,
        policy_sha256=journal.policy_sha256,
        release_manifest_sha256=journal.release_manifest_sha256,
        sequence=journal.sequence,
        valid_from_block=journal.valid_from_block,
        valid_through_block=journal.valid_through_block,
        expected_validator_hotkey=journal.validator_hotkey,
        wallet_hotkey_name="snapshot",
    )
    _validate_bootstrap_inputs(
        environment,
        signed,
        authorization,
        drain,
        worker_revision,
        current_block,
    )


def _validate_bootstrap_policy_bounds(
    environment: SupervisorWorkerEnvironment,
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
) -> None:
    policy = signed.manifest.policy
    if policy.translation_weights_active or not policy.service_weights_active:
        raise SupervisorWorkerError("worker_bootstrap_policy_mode_invalid")
    if not (
        authorization.valid_from_block
        <= environment.valid_from_block
        <= environment.valid_through_block
        <= authorization.expires_at_block
        < policy.hard_sunset_block
    ):
        raise SupervisorWorkerError("worker_directive_outside_transition_authorization")


def _validate_checkpoint_binding(
    environment: SupervisorWorkerEnvironment,
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
    checkpoint: DirectBootstrapOperationalPreflight,
    current_block: int,
) -> None:
    chain = checkpoint.chain
    if (
        checkpoint.signed_manifest != signed
        or chain.transition_authorization != authorization
        or chain.manifest_sha256 != signed.manifest_sha256
        or chain.policy_sha256 != environment.policy_sha256
        or account_id32(chain.validator_hotkey)
        != account_id32(environment.expected_validator_hotkey)
        or chain.snapshot.block_number > current_block
    ):
        raise SupervisorWorkerError("worker_drain_checkpoint_binding_mismatch")
    try:
        checked_at = datetime.fromtimestamp(
            chain.snapshot.block_timestamp_ms / 1_000,
            tz=timezone.utc,
        )
        rebuilt = validate_direct_bootstrap_preflight(
            signed,
            chain.snapshot,
            authorization=authorization,
            subnet_owner_hotkey=bytes.fromhex(chain.subnet_owner_hotkey_account_id32[2:]),
            validator_hotkey=environment.expected_validator_hotkey,
            now=checked_at,
        )
    except Exception as error:
        raise SupervisorWorkerError("worker_drain_checkpoint_invalid") from error
    if rebuilt != chain:
        raise SupervisorWorkerError("worker_drain_checkpoint_invalid")


def _validate_drain_continuity(
    environment: SupervisorWorkerEnvironment,
    inputs: BootstrapWorkerInputs,
    fresh: DirectBootstrapOperationalPreflight,
    owned_finalized_block: int,
) -> None:
    if not isinstance(fresh, DirectBootstrapOperationalPreflight):
        raise SupervisorWorkerError("worker_direct_preflight_invalid")
    _validate_checkpoint_binding(
        environment,
        inputs.signed_manifest,
        inputs.transition_authorization,
        fresh,
        owned_finalized_block,
    )
    checkpoint = inputs.drain_checkpoint
    before = checkpoint.chain
    after = fresh.chain
    if (
        fresh.signed_manifest != inputs.signed_manifest
        or after.transition_authorization != inputs.transition_authorization
        or account_id32(after.validator_hotkey) != account_id32(before.validator_hotkey)
        or after.snapshot.block_number < before.snapshot.block_number
        or after.snapshot.block_number > owned_finalized_block
        or after.expected_applied_row != before.expected_applied_row
        or after.prior_row_classification != before.prior_row_classification
    ):
        raise SupervisorWorkerError("worker_drain_checkpoint_changed")


def _complete_from_output(
    journal: SupervisorWorkerJournal,
    inputs: BootstrapWorkerInputs,
    outputs: BootstrapWorkerOutputs,
    receipt: DirectBootstrapSubmissionReceipt,
) -> SupervisorWorkerJournal:
    if not isinstance(receipt, DirectBootstrapSubmissionReceipt):
        raise SupervisorWorkerError("worker_receipt_invalid")
    disk_receipt = _load_canonical(outputs.receipt, DirectBootstrapSubmissionReceipt)
    material = _load_canonical(outputs.call_material, DirectBootstrapCallMaterial)
    if disk_receipt != receipt:
        raise SupervisorWorkerError("worker_receipt_mismatch")
    _validate_completed_output(journal, inputs, disk_receipt, material, outputs.operator_state)
    return journal.model_copy(
        update={
            "phase": "completed",
            "receipt_sha256": hashlib.sha256(canonical_json_bytes(disk_receipt)).hexdigest(),
            "call_material_sha256": hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        }
    )


def _recover_completed_output(
    journal: SupervisorWorkerJournal,
    inputs: BootstrapWorkerInputs,
    outputs: BootstrapWorkerOutputs,
) -> SupervisorWorkerJournal | None:
    if not outputs.receipt.exists() or not outputs.call_material.exists():
        return None
    try:
        receipt = _load_canonical(outputs.receipt, DirectBootstrapSubmissionReceipt)
        material = _load_canonical(outputs.call_material, DirectBootstrapCallMaterial)
        _validate_completed_output(journal, inputs, receipt, material, outputs.operator_state)
    except Exception:
        return None
    return journal.model_copy(
        update={
            "phase": "completed",
            "receipt_sha256": hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
            "call_material_sha256": hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        }
    )


def _validate_completed_output(
    journal: SupervisorWorkerJournal,
    inputs: BootstrapWorkerInputs,
    receipt: DirectBootstrapSubmissionReceipt,
    material: DirectBootstrapCallMaterial,
    operator_state: Path,
) -> None:
    authorization_hash = hashlib.sha256(
        canonical_json_bytes(inputs.transition_authorization)
    ).hexdigest()
    direct_journal_path = operator_state / (
        f"direct-{authorization_hash}-{account_id32(journal.validator_hotkey).hex()}.json"
    )
    direct_journal = _load_canonical(direct_journal_path, DirectBootstrapSubmissionJournal)
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    if (
        receipt.classification != "applied"
        or receipt.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or receipt.validator_uid != 0
        or account_id32(receipt.validator_hotkey) != account_id32(journal.validator_hotkey)
        or receipt.call_material_sha256
        != hashlib.sha256(canonical_json_bytes(material)).hexdigest()
        or material.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or material.operational_preflight.chain.policy_sha256 != journal.policy_sha256
        or material.operational_preflight.signed_manifest != inputs.signed_manifest
        or material.operational_preflight.chain.transition_authorization
        != inputs.transition_authorization
        or direct_journal.phase != "applied"
        or direct_journal.submission_id != inputs.transition_authorization.submission_id
        or direct_journal.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or direct_journal.transition_authorization_sha256 != authorization_hash
        or account_id32(direct_journal.validator_hotkey) != account_id32(journal.validator_hotkey)
        or direct_journal.call_material_sha256 != receipt.call_material_sha256
        or direct_journal.anchor != receipt.anchor
        or direct_journal.weight_call != receipt.weight_call
        or direct_journal.receipt_sha256 != receipt_sha256
    ):
        raise SupervisorWorkerError("worker_completed_output_invalid")


def _mark_ambiguous(
    journal: SupervisorWorkerJournal,
    reason_code: str,
) -> SupervisorWorkerJournal:
    if journal.intent_finalized_block is None:
        raise SupervisorWorkerError("worker_journal_transition_invalid")
    return journal.model_copy(
        update={
            "phase": "ambiguous",
            "receipt_sha256": None,
            "call_material_sha256": None,
            "reason_code": reason_code[:128] or "worker_effect_ambiguous",
        }
    )


def _authorization_claim_path(
    authorization_root: Path,
    inputs: BootstrapWorkerInputs,
) -> Path:
    return authorization_root / f"claim-{inputs.transition_authorization.submission_id}.json"


def _authorization_claim_value(
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
    identity: OwnedFinalizedBlock,
) -> SupervisorBootstrapAuthorizationClaim:
    return SupervisorBootstrapAuthorizationClaim(
        schema=WORKER_AUTHORIZATION_CLAIM_SCHEMA,
        submission_id=inputs.transition_authorization.submission_id,
        transition_authorization_sha256=hashlib.sha256(
            canonical_json_bytes(inputs.transition_authorization)
        ).hexdigest(),
        manifest_sha256=inputs.signed_manifest.manifest_sha256,
        validator_hotkey=environment.expected_validator_hotkey,
        directive_sha256=environment.directive_sha256,
        sequence=environment.sequence,
        intent_finalized_block=identity.number,
        intent_finalized_block_hash=identity.block_hash,
    )


def _require_authorization_claim_binding(
    claim: SupervisorBootstrapAuthorizationClaim,
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
) -> None:
    if claim.directive_sha256 != environment.directive_sha256:
        raise SupervisorWorkerError("worker_transition_authorization_already_claimed")
    if (
        claim.submission_id != inputs.transition_authorization.submission_id
        or claim.transition_authorization_sha256
        != hashlib.sha256(canonical_json_bytes(inputs.transition_authorization)).hexdigest()
        or claim.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or account_id32(claim.validator_hotkey)
        != account_id32(environment.expected_validator_hotkey)
        or claim.sequence != environment.sequence
    ):
        raise SupervisorWorkerError("worker_authorization_claim_invalid")


def _load_authorization_claim(
    authorization_root: Path,
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
) -> SupervisorBootstrapAuthorizationClaim | None:
    path = _authorization_claim_path(authorization_root, inputs)
    if not path.exists():
        return None
    claim = _load_canonical(path, SupervisorBootstrapAuthorizationClaim)
    _require_authorization_claim_binding(claim, inputs, environment)
    return claim


def _claim_bootstrap_authorization(
    authorization_root: Path,
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
    identity: OwnedFinalizedBlock,
) -> SupervisorBootstrapAuthorizationClaim:
    claim = _authorization_claim_value(inputs, environment, identity)
    path = _authorization_claim_path(authorization_root, inputs)
    try:
        _write_new_canonical(path, claim)
        return claim
    except SupervisorWorkerError:
        existing = _load_authorization_claim(authorization_root, inputs, environment)
        if existing is None:
            raise
        return existing


def _restore_claimed_intent(
    journal: SupervisorWorkerJournal,
    claim: SupervisorBootstrapAuthorizationClaim,
) -> SupervisorWorkerJournal:
    if journal.phase == "prepared":
        return journal.model_copy(
            update={
                "phase": "effect_intent",
                "intent_finalized_block": claim.intent_finalized_block,
            }
        )
    if (
        journal.phase != "effect_intent"
        or journal.intent_finalized_block != claim.intent_finalized_block
    ):
        raise SupervisorWorkerError("worker_authorization_claim_invalid")
    return journal


def _restore_intent_from_disk_claim(
    journal: SupervisorWorkerJournal,
    authorization_root: Path,
    inputs: BootstrapWorkerInputs,
    environment: SupervisorWorkerEnvironment,
    journal_path: Path,
) -> SupervisorWorkerJournal:
    claim = _load_authorization_claim(authorization_root, inputs, environment)
    if claim is None or journal.phase != "prepared":
        return journal
    restored = _restore_claimed_intent(journal, claim)
    _replace_canonical(journal_path, restored)
    return restored


def _stable_effect_reason(error: Exception) -> str:
    reason = getattr(error, "reason_code", None)
    if isinstance(reason, str) and _REASON_CODE_RE.fullmatch(reason) is not None:
        return reason
    return "worker_bootstrap_effect_failed"


def _bootstrap_outputs(
    transaction_root: Path,
    authorization_root: Path,
) -> BootstrapWorkerOutputs:
    return BootstrapWorkerOutputs(
        root=transaction_root,
        receipt=transaction_root / "submission-receipt.json",
        call_material=transaction_root / "call-material.json",
        operator_state=authorization_root / "operator-state",
    )


def _require_journal_binding(
    journal: SupervisorWorkerJournal,
    environment: SupervisorWorkerEnvironment,
) -> None:
    expected = (
        environment.mode,
        environment.directive_sha256,
        environment.policy_sha256,
        environment.release_manifest_sha256,
        environment.sequence,
        environment.valid_from_block,
        environment.valid_through_block,
        account_id32(environment.expected_validator_hotkey),
    )
    observed = (
        journal.mode,
        journal.directive_sha256,
        journal.policy_sha256,
        journal.release_manifest_sha256,
        journal.sequence,
        journal.valid_from_block,
        journal.valid_through_block,
        account_id32(journal.validator_hotkey),
    )
    if observed != expected:
        raise SupervisorWorkerError("worker_journal_binding_mismatch")


def _verify_release(
    environment: SupervisorWorkerEnvironment,
    release: SupervisorReleaseManifest,
    release_manifest_bytes: bytes,
    image_revision_path: Path,
) -> None:
    if hashlib.sha256(release_manifest_bytes).hexdigest() != environment.release_manifest_sha256:
        raise SupervisorWorkerError("worker_release_manifest_mismatch")
    if release.entrypoint_profile != "umi-bootstrap-weight-validator/1":
        raise SupervisorWorkerError("worker_release_profile_mismatch")
    if (
        not release.state_schema_minimum
        <= WORKER_STATE_SCHEMA_VERSION
        <= (release.state_schema_maximum)
    ):
        raise SupervisorWorkerError("worker_state_schema_unsupported")
    revision = _read_revision_marker(image_revision_path)
    if revision != release.umi_git_revision:
        raise SupervisorWorkerError("worker_image_revision_mismatch")


def _load_bound_wallet(environment: SupervisorWorkerEnvironment) -> Any:
    try:
        return bt.Wallet(
            name=WORKER_WALLET_NAME,
            hotkey=environment.wallet_hotkey_name,
            path=str(WORKER_WALLET_ROOT),
        )
    except Exception as error:
        raise SupervisorWorkerError("worker_wallet_unavailable") from error


def _require_wallet_identity(wallet: Any, expected_hotkey: str) -> None:
    try:
        signer = bt.resolve_signer(wallet, role="hotkey")
        observed = account_id32(signer.ss58_address)
    except Exception as error:
        raise SupervisorWorkerError("worker_wallet_unavailable") from error
    if observed != account_id32(expected_hotkey):
        raise SupervisorWorkerError("worker_wallet_hotkey_mismatch")


def _production_finality_reader() -> FinneyFinalizedBlockReader:
    binary_sha256 = _sha256_regular_file(WORKER_FINALITY_BINARY, executable=True)
    chain_sha256 = _sha256_regular_file(WORKER_FINALITY_CHAIN_SPEC, executable=False)
    if chain_sha256 != FINNEY_CHAIN_SPEC_SHA256:
        raise SupervisorWorkerError("worker_finality_chain_spec_mismatch")
    try:
        observer = GrandpaFinalityObserver(
            binary_path=WORKER_FINALITY_BINARY,
            expected_binary_sha256=binary_sha256,
            chain_spec_path=WORKER_FINALITY_CHAIN_SPEC,
            expected_chain_spec_sha256=FINNEY_CHAIN_SPEC_SHA256,
            expected_genesis_hash=f"0x{FINNEY_GENESIS_HASH}",
            bootstrap_block_number=FINNEY_BOOTSTRAP_BLOCK_NUMBER,
            bootstrap_block_hash=f"0x{FINNEY_BOOTSTRAP_BLOCK_HASH}",
            record_timeout_seconds=OWNED_FINALITY_TIMEOUT_SECONDS,
        )
        return FinneyFinalizedBlockReader(
            SimpleNamespace(),
            observer=observer,
            timeout_seconds=OWNED_FINALITY_TIMEOUT_SECONDS,
        )
    except Exception as error:
        raise SupervisorWorkerError("worker_finality_unavailable") from error


def _require_fixed_environment(values: Mapping[str, str]) -> None:
    expected = {
        "UMI_NETWORK": "finney",
        "UMI_NETUID": "78",
        "UMI_MECHANISM_ID": "0",
        "UMI_WALLET_PATH": str(WORKER_WALLET_ROOT),
        "UMI_WALLET_NAME": WORKER_WALLET_NAME,
        "UMI_OPERATOR_INPUT_ROOT": str(WORKER_OPERATOR_INPUT_ROOT),
        "UMI_WORKER_STATE_ROOT": str(WORKER_STATE_ROOT),
        "UMI_RELEASE_MANIFEST": str(WORKER_RELEASE_MANIFEST),
    }
    if any(values.get(name) != value for name, value in expected.items()):
        raise SupervisorWorkerError("worker_environment_invalid")


def _read_revision_marker(path: Path) -> str:
    value = _read_bounded_file(path, 41)
    if len(value) != 41 or not value.endswith(b"\n"):
        raise SupervisorWorkerError("worker_image_revision_invalid")
    try:
        revision = value[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise SupervisorWorkerError("worker_image_revision_invalid") from error
    if _GIT_REVISION_RE.fullmatch(revision) is None:
        raise SupervisorWorkerError("worker_image_revision_invalid")
    return revision


def _read_canonical(path: Path, model_type: type[Any]) -> tuple[bytes, Any]:
    raw = _read_bounded_file(path, MAX_WORKER_INPUT_BYTES)
    try:
        value = model_type.model_validate_json(raw, strict=True)
    except Exception as error:
        raise SupervisorWorkerError("worker_input_invalid") from error
    if canonical_json_bytes(value) != raw:
        raise SupervisorWorkerError("worker_input_noncanonical")
    return raw, value


def _load_canonical(path: Path, model_type: type[Any]) -> Any:
    return _read_canonical(path, model_type)[1]


def _read_bounded_file(path: Path, maximum_bytes: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | _no_follow())
    except OSError as error:
        raise SupervisorWorkerError("worker_file_unavailable") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise SupervisorWorkerError("worker_file_unsafe")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not raw or len(raw) > maximum_bytes:
            raise SupervisorWorkerError("worker_file_size_invalid")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _sha256_regular_file(path: Path, *, executable: bool) -> str:
    try:
        details = path.stat(follow_symlinks=False)
    except OSError as error:
        raise SupervisorWorkerError("worker_artifact_unavailable") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_mode & 0o022
        or (executable and not details.st_mode & 0o111)
    ):
        raise SupervisorWorkerError("worker_artifact_unsafe")
    digest = hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise SupervisorWorkerError("worker_artifact_unavailable") from error
    return digest.hexdigest()


def _prepare_transaction_root(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = path.stat(follow_symlinks=False)
    except OSError as error:
        raise SupervisorWorkerError("worker_state_unavailable") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o077
    ):
        raise SupervisorWorkerError("worker_state_unsafe")


def _acquire_lock(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | _no_follow(), 0o600)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise SupervisorWorkerError("worker_lock_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as error:
        with contextlib.suppress(UnboundLocalError):
            os.close(descriptor)
        raise SupervisorWorkerError("worker_already_running") from error
    except Exception:
        with contextlib.suppress(UnboundLocalError):
            os.close(descriptor)
        raise


def _write_new_bytes(path: Path, payload: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | _no_follow(),
            0o400,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except OSError as error:
        raise SupervisorWorkerError("worker_state_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _fsync_directory(path.parent)


def _write_new_canonical(path: Path, value: Any) -> None:
    payload = canonical_json_bytes(value)
    if not payload or len(payload) > MAX_WORKER_JOURNAL_BYTES:
        raise SupervisorWorkerError("worker_journal_size_invalid")
    _write_new_bytes(path, payload)


def _replace_canonical(path: Path, value: Any) -> None:
    payload = canonical_json_bytes(value)
    if not payload or len(payload) > MAX_WORKER_JOURNAL_BYTES:
        raise SupervisorWorkerError("worker_journal_size_invalid")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o400)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as error:
        raise SupervisorWorkerError("worker_state_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _no_follow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umi-validator-supervisor-worker",
        description="Run one fixed UMI validator-supervisor worker profile",
    )
    parser.add_argument("mode", choices=sorted(_MODE_BY_COMMAND))
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        environment = SupervisorWorkerEnvironment.from_environ(args.mode)
        if environment.mode == "hold":
            raise SupervisorWorkerError("worker_hold_must_be_host_inert")
        if environment.mode != "bootstrap_service_weights":
            raise SupervisorWorkerError("worker_mode_unimplemented")
        journal = asyncio.run(run_bootstrap_worker(environment))
        print(canonical_json_bytes(journal).decode("utf-8"))
        return 0
    except (
        BootstrapOperatorError,
        OSError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        reason = getattr(error, "reason_code", "worker_failed")
        print(f"validator supervisor worker failed: {reason}", file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run_cli())


__all__ = [
    "BOOTSTRAP_DIRECTIVE_HEADROOM_BLOCKS",
    "OwnedFinalityLease",
    "SupervisorWorkerEnvironment",
    "SupervisorWorkerError",
    "SupervisorWorkerJournal",
    "run_bootstrap_worker",
    "run_cli",
]
