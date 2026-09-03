"""Closed, restart-safe operator for one certified publisher pool anchor.

The module deliberately accepts only the protocol's ``PoolAnchorIntent``.  It
does not expose a call builder, wallet, or generic submission callback.
"""

from __future__ import annotations

import fcntl
import hashlib
import inspect
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import Field, ValidationError

from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .publisher_availability import CertifiedPoolRelease, PoolAnchorIntent
from .validator_anchor_ports import _commitment_binding
from .validator_chain import FinalizedRuntimePin, PinnedRuntimeContext, VerifiedStorageRead
from .validator_extrinsics import (
    ANCHOR_INTENT_SCHEMA,
    AnchorField,
    AnchorIntent,
    ExtrinsicJournalError,
    ExtrinsicOperation,
    ExtrinsicPorts,
    ExtrinsicState,
    JournalEntry,
    ValidatorExtrinsicJournal,
    mortal_era_bounds,
)

POOL_ANCHOR_BINDING_SCHEMA = "umi-publisher-pool-anchor-binding/1"
POOL_ANCHOR_EVIDENCE_SCHEMA = "umi-publisher-pool-anchor-evidence/1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
# A submitted pool anchor still has to enter finalized state by ``closing_block``.
# Four unfinalized heights gives the ordinary Finney inclusion path roughly one
# block interval to enter a block and three more to finalize before close.
POOL_ANCHOR_ERA_PERIOD_BLOCKS = 4
POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS = POOL_ANCHOR_ERA_PERIOD_BLOCKS


class PublisherPoolAnchorError(RuntimeError):
    """Stable fail-closed publisher anchor error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class PoolAnchorBinding(StrictProtocolModel):
    schema_: Literal[POOL_ANCHOR_BINDING_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    publisher_hotkey: str
    publisher_account_id32: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    scoring_policy_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    certified_release_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    anchor_intents_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    anchor_intent_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    pool_manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    closing_block: Annotated[int, Field(gt=0)]
    mortal_era_period_blocks: Literal[POOL_ANCHOR_ERA_PERIOD_BLOCKS]
    last_safe_finalized_height: Annotated[int, Field(ge=0)]
    call: Literal["Commitments.set_commitment"]
    field_count: Literal[1]
    field_type: Literal["Data::Sha256"]
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]


class ClosingAnchorEvidence(StrictProtocolModel):
    """Proof-backed exact closing-block state returned by the chain port."""

    closing_block: Annotated[int, Field(gt=0)]
    closing_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    finality_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    pallet: Literal["Commitments"]
    storage_item: Literal["CommitmentOf"]
    netuid: Literal[78]
    publisher_hotkey: str
    field_count: Literal[1]
    field_type: Literal["Data::Sha256"]
    field_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    storage_key_hex: Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{2})+$")]
    storage_value_hex: Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{2})+$")]
    storage_proof_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    proof_verified: Literal[True]


class PoolAnchorEvidence(StrictProtocolModel):
    schema_: Literal[POOL_ANCHOR_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    operation_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    binding_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    final_receipt_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    final_receipt_state: Literal["finalized_success"]
    closing: ClosingAnchorEvidence
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]


@dataclass(frozen=True, slots=True)
class PoolAnchorPending:
    """Nonterminal closing-finality status reconstructed from durable state."""

    reason_code: Literal["closing_finality_pending"]
    operation_id: str
    binding_sha256: str
    final_receipt_sha256: str
    closing_block: int
    observed_finalized_height: int


@dataclass(frozen=True, slots=True)
class LoadedPoolAnchor:
    policy: ScoringPolicy
    release: CertifiedPoolRelease
    intent: PoolAnchorIntent
    binding: PoolAnchorBinding
    binding_bytes: bytes
    operation: ExtrinsicOperation


class ClosedAnchorPorts(Protocol):
    @property
    def signer_account_id32(self) -> bytes: ...

    def for_operation(self, operation: ExtrinsicOperation): ...


class ClosingProofPort(Protocol):
    async def prove_closing_anchor(
        self,
        intent: PoolAnchorIntent,
        entry: JournalEntry,
    ) -> ClosingAnchorEvidence: ...


class ExactHeightFinalityPort(Protocol):
    async def finalized_head_height(self) -> int: ...

    async def verified_scan_interval(self, start_height: int, end_height: int): ...


class _PoolAnchorSubmissionGuardError(ExtrinsicJournalError):
    """Internal signal raised before the submit port performs a network call."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ExactStorageProofPort(Protocol):
    async def pinned_runtime(self, snapshot, pin: FinalizedRuntimePin) -> PinnedRuntimeContext: ...

    async def storage_read(
        self,
        runtime: PinnedRuntimeContext,
        pallet: str,
        item: str,
        params: Sequence[object] = (),
    ) -> VerifiedStorageRead: ...


class ProofBackedPublisherClosingPort:
    """Read exactly ``CommitmentOf`` at the verifier-finalized closing block."""

    def __init__(
        self,
        *,
        finality: ExactHeightFinalityPort,
        proofs: ExactStorageProofPort,
        runtime_pin: FinalizedRuntimePin,
    ) -> None:
        self._finality = finality
        self._proofs = proofs
        self._runtime_pin = runtime_pin

    async def prove_closing_anchor(
        self, intent: PoolAnchorIntent, entry: JournalEntry
    ) -> ClosingAnchorEvidence:
        if entry.state is not ExtrinsicState.FINALIZED_SUCCESS:
            raise PublisherPoolAnchorError("anchor_inclusion_not_successful")
        interval = await self._finality.verified_scan_interval(
            intent.closing_block, intent.closing_block
        )
        identities = getattr(interval, "identities", ())
        attestations = getattr(interval, "attestations", ())
        if len(identities) != 1 or len(attestations) != 1:
            raise PublisherPoolAnchorError("closing_finality_unavailable")
        identity = identities[0]
        snapshot = identity.snapshot
        if snapshot.block_number != intent.closing_block:
            raise PublisherPoolAnchorError("closing_finality_mismatch")
        runtime = await self._proofs.pinned_runtime(snapshot, self._runtime_pin)
        if runtime.snapshot != snapshot or runtime.pin != self._runtime_pin:
            raise PublisherPoolAnchorError("closing_runtime_mismatch")
        storage = await self._proofs.storage_read(
            runtime,
            "Commitments",
            "CommitmentOf",
            (78, intent.publisher_hotkey),
        )
        if not isinstance(storage, VerifiedStorageRead) or storage.evidence.snapshot != snapshot:
            raise PublisherPoolAnchorError("closing_storage_proof_invalid")
        matches, _commitment_block = _commitment_binding(
            storage.decoded_value, intent.pool_manifest_sha256
        )
        if not matches:
            raise PublisherPoolAnchorError("closing_proof_mismatch")
        proof_digest = hashlib.sha256(
            canonical_json_bytes(["0x" + node.hex() for node in storage.evidence.proof])
        ).hexdigest()
        return ClosingAnchorEvidence(
            closing_block=intent.closing_block,
            closing_block_hash=snapshot.block_hash,
            finality_evidence_sha256=identity.finality_evidence_sha256,
            pallet="Commitments",
            storage_item="CommitmentOf",
            netuid=78,
            publisher_hotkey=intent.publisher_hotkey,
            field_count=1,
            field_type="Data::Sha256",
            field_sha256=intent.pool_manifest_sha256,
            storage_key_hex="0x" + storage.evidence.storage_key.hex(),
            storage_value_hex="0x" + (storage.evidence.value or b"").hex(),
            storage_proof_sha256=proof_digest,
            proof_verified=True,
        )


def load_pool_anchor_material(
    *,
    policy_bytes: bytes,
    certified_release_bytes: bytes,
    anchor_intents_bytes: bytes,
    configured_publisher_hotkey: str,
) -> LoadedPoolAnchor:
    """Validate and bind one publisher intent to one certified release."""

    try:
        import json

        policy_document = json.loads(policy_bytes)
    except (TypeError, ValueError) as error:
        raise PublisherPoolAnchorError("policy_invalid") from error
    if (
        isinstance(policy_document, Mapping)
        and policy_document.get("translation_weights_active") is True
    ):
        raise PublisherPoolAnchorError("pool_anchor_requires_shadow_policy")
    policy = _parse_canonical(policy_bytes, ScoringPolicy, "policy")
    if policy.translation_weights_active is not False:
        raise PublisherPoolAnchorError("pool_anchor_requires_shadow_policy")
    release = _parse_canonical(certified_release_bytes, CertifiedPoolRelease, "certified_release")
    try:
        raw_intents = _canonical_array(anchor_intents_bytes)
        intents = [PoolAnchorIntent.model_validate(item) for item in raw_intents]
    except (ValidationError, TypeError, ValueError) as error:
        raise PublisherPoolAnchorError("anchor_intents_invalid") from error
    if canonical_json_bytes(raw_intents) != anchor_intents_bytes:
        raise PublisherPoolAnchorError("anchor_intents_noncanonical")
    intent_accounts = [account_id32(item.publisher_hotkey) for item in intents]
    if intent_accounts != sorted(intent_accounts) or len(set(intent_accounts)) != len(
        intent_accounts
    ):
        raise PublisherPoolAnchorError("anchor_intents_order_invalid")
    if hashlib.sha256(anchor_intents_bytes).hexdigest() != release.anchor_intents_sha256:
        raise PublisherPoolAnchorError("anchor_intents_release_mismatch")
    if release.translation_weights_active or release.weight_submission_capability:
        raise PublisherPoolAnchorError("certified_release_unsafe_capability")
    if release.window.scoring_policy_hash != scoring_policy_hash(policy):
        raise PublisherPoolAnchorError("certified_release_policy_mismatch")
    if release.window.closing_block <= 0:
        raise PublisherPoolAnchorError("closing_block_invalid")

    configured = account_id32(configured_publisher_hotkey)
    matching = [item for item in intents if account_id32(item.publisher_hotkey) == configured]
    if len(matching) != 1:
        raise PublisherPoolAnchorError("configured_publisher_intent_missing")
    intent = matching[0]
    if account_id32(intent.publisher_hotkey) != configured:
        raise PublisherPoolAnchorError("publisher_hotkey_mismatch")
    if (
        intent.netuid != 78
        or intent.window_id != release.window.window_id
        or intent.closing_block != release.window.closing_block
        or intent.pallet != "Commitments"
        or intent.call != "set_commitment"
        or len(intent.fields) != 1
        or intent.fields[0].variant != "Data::Sha256"
        or intent.broadcast_authorized
        or intent.translation_weights_active
        or intent.weight_submission_capability
    ):
        raise PublisherPoolAnchorError("pool_anchor_intent_not_closed")
    released = [
        item for item in release.pool_manifests if account_id32(item.publisher_hotkey) == configured
    ]
    if len(released) != 1 or released[0].sha256 != intent.pool_manifest_sha256:
        raise PublisherPoolAnchorError("pool_manifest_release_mismatch")

    intent_bytes = canonical_json_bytes(intent)
    binding = PoolAnchorBinding(
        schema=POOL_ANCHOR_BINDING_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=intent.window_id,
        publisher_hotkey=intent.publisher_hotkey,
        publisher_account_id32=configured.hex(),
        scoring_policy_sha256=scoring_policy_hash(policy),
        certified_release_sha256=hashlib.sha256(certified_release_bytes).hexdigest(),
        anchor_intents_sha256=release.anchor_intents_sha256,
        anchor_intent_sha256=hashlib.sha256(intent_bytes).hexdigest(),
        pool_manifest_sha256=intent.pool_manifest_sha256,
        closing_block=intent.closing_block,
        mortal_era_period_blocks=POOL_ANCHOR_ERA_PERIOD_BLOCKS,
        last_safe_finalized_height=(intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS),
        call="Commitments.set_commitment",
        field_count=1,
        field_type="Data::Sha256",
        translation_weights_active=False,
        weight_submission_capability=False,
    )
    operation = ExtrinsicOperation(
        schema="umi-validator-extrinsic-operation/1",
        protocol=PROTOCOL_VERSION,
        operation="publisher_pool_anchor",
        window_id=intent.window_id,
        validator_hotkey=intent.publisher_hotkey,
        request=AnchorIntent(
            schema=ANCHOR_INTENT_SCHEMA,
            call="Commitments.set_commitment",
            netuid=78,
            anchor_kind="publisher_pool",
            field=AnchorField(type="Data::Sha256", sha256=intent.pool_manifest_sha256),
        ),
    )
    return LoadedPoolAnchor(
        policy=policy,
        release=release,
        intent=intent,
        binding=binding,
        binding_bytes=canonical_json_bytes(binding),
        operation=operation,
    )


class PublisherPoolAnchorOperator:
    """Advance one exact publisher anchor and verify its closing state."""

    def __init__(
        self,
        root: str | Path,
        *,
        journal: ValidatorExtrinsicJournal,
        anchor_ports: ClosedAnchorPorts,
        submission_finality: ExactHeightFinalityPort,
        closing_proofs: ClosingProofPort,
    ) -> None:
        self.root = Path(root)
        self.journal = journal
        self.anchor_ports = anchor_ports
        self.submission_finality = submission_finality
        self.closing_proofs = closing_proofs
        _secure_directory(self.root)

    async def advance(
        self, loaded: LoadedPoolAnchor
    ) -> JournalEntry | PoolAnchorPending | PoolAnchorEvidence:
        if self.anchor_ports.signer_account_id32 != account_id32(loaded.binding.publisher_hotkey):
            raise PublisherPoolAnchorError("publisher_signer_mismatch")
        current = self.journal.load(loaded.operation)
        history = self.journal.history(loaded.operation)
        self._validate_persisted_mortal_era(loaded, current)
        if self._requires_open_submission_window(current, history):
            await self._require_open_submission_window(loaded)
        binding_sha256 = hashlib.sha256(loaded.binding_bytes).hexdigest()
        self._claim(loaded, binding_sha256)
        ports = self._deadline_guarded_ports(
            loaded,
            self.anchor_ports.for_operation(loaded.operation),
        )
        if current is not None and current.state is ExtrinsicState.FINALIZED_SUCCESS:
            entry = current
        else:
            try:
                entry = await self.journal.advance(
                    loaded.operation,
                    ports,
                    expected_operation_id=loaded.operation.operation_id,
                )
            except _PoolAnchorSubmissionGuardError as error:
                raise PublisherPoolAnchorError(error.reason_code) from error
        self._validate_persisted_mortal_era(loaded, entry)
        if entry.state is not ExtrinsicState.FINALIZED_SUCCESS:
            return entry
        observed_finalized_height = await self._validated_finalized_head_height()
        if observed_finalized_height < loaded.intent.closing_block:
            return PoolAnchorPending(
                reason_code="closing_finality_pending",
                operation_id=loaded.operation.operation_id,
                binding_sha256=binding_sha256,
                final_receipt_sha256=entry.receipt_sha256,
                closing_block=loaded.intent.closing_block,
                observed_finalized_height=observed_finalized_height,
            )
        closing = await self.closing_proofs.prove_closing_anchor(loaded.intent, entry)
        self._validate_closing(loaded, closing)
        evidence = PoolAnchorEvidence(
            schema=POOL_ANCHOR_EVIDENCE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            operation_id=loaded.operation.operation_id,
            binding_sha256=binding_sha256,
            final_receipt_sha256=entry.receipt_sha256,
            final_receipt_state="finalized_success",
            closing=closing,
            translation_weights_active=False,
            weight_submission_capability=False,
        )
        self._write_once(self.root / "evidence.json", canonical_json_bytes(evidence))
        return evidence

    @staticmethod
    def _requires_open_submission_window(
        current: JournalEntry | None,
        history: Sequence[JournalEntry],
    ) -> bool:
        if current is None:
            return True
        if current.state in {
            ExtrinsicState.FINALIZED_SUCCESS,
            ExtrinsicState.FINALIZED_FAILURE,
            ExtrinsicState.EXPIRED,
            ExtrinsicState.SUBMITTED,
        }:
            return False
        return not any(
            item.receipt.submission is not None
            or item.receipt.reason_code == "submit_outcome_unknown"
            for item in history
        )

    async def _require_open_submission_window(self, loaded: LoadedPoolAnchor) -> None:
        try:
            height = await self._validated_finalized_head_height()
        except PublisherPoolAnchorError:
            raise
        except Exception as error:
            raise PublisherPoolAnchorError("pool_anchor_finality_unavailable") from error
        last_safe_height = loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
        if height > last_safe_height:
            raise PublisherPoolAnchorError("pool_anchor_submission_window_closed")

    async def _validated_finalized_head_height(self) -> int:
        height = await self.submission_finality.finalized_head_height()
        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            raise PublisherPoolAnchorError("pool_anchor_finalized_head_invalid")
        return height

    @staticmethod
    def _validate_persisted_mortal_era(
        loaded: LoadedPoolAnchor,
        entry: JournalEntry | None,
    ) -> None:
        if entry is None:
            return
        receipt = entry.receipt
        if (
            receipt.era_death_block > loaded.intent.closing_block
            or receipt.era_death_block - receipt.era_birth_block != POOL_ANCHOR_ERA_PERIOD_BLOCKS
        ):
            raise PublisherPoolAnchorError("pool_anchor_mortal_era_exceeds_close")

    def _deadline_guarded_ports(
        self,
        loaded: LoadedPoolAnchor,
        ports: ExtrinsicPorts,
    ) -> ExtrinsicPorts:
        async def submit(unsigned, signature):
            try:
                _birth, death = mortal_era_bounds(unsigned)
            except Exception as error:
                raise _PoolAnchorSubmissionGuardError("pool_anchor_mortal_era_invalid") from error
            if death > loaded.intent.closing_block:
                raise _PoolAnchorSubmissionGuardError("pool_anchor_mortal_era_exceeds_close")
            try:
                await self._require_open_submission_window(loaded)
            except PublisherPoolAnchorError as error:
                raise _PoolAnchorSubmissionGuardError(error.reason_code) from error
            result = ports.submit(unsigned, signature)
            if inspect.isawaitable(result):
                return await result
            return result

        return ExtrinsicPorts(
            prepare=ports.prepare,
            verify_prepared_call=ports.verify_prepared_call,
            sign=ports.sign,
            submit=submit,
            reconcile=ports.reconcile,
            derive_signed_hash=ports.derive_signed_hash,
        )

    def _claim(self, loaded: LoadedPoolAnchor, digest: str) -> None:
        lock = self.root / ".lock"
        lock.touch(mode=0o600, exist_ok=True)
        with lock.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            path = self.root / "binding.json"
            if path.exists():
                raw = _read_safe(path, MAX_INPUT_BYTES, "binding")
                if hashlib.sha256(raw).hexdigest() != digest or raw != loaded.binding_bytes:
                    raise PublisherPoolAnchorError("pool_anchor_equivocation")
                return
            self._write_once(path, loaded.binding_bytes)

    def _validate_closing(self, loaded: LoadedPoolAnchor, evidence: ClosingAnchorEvidence) -> None:
        if not isinstance(evidence, ClosingAnchorEvidence):
            raise PublisherPoolAnchorError("closing_proof_invalid")
        if (
            evidence.closing_block != loaded.intent.closing_block
            or evidence.netuid != 78
            or account_id32(evidence.publisher_hotkey)
            != account_id32(loaded.intent.publisher_hotkey)
            or evidence.field_count != 1
            or evidence.field_type != "Data::Sha256"
            or evidence.field_sha256 != loaded.intent.pool_manifest_sha256
            or not evidence.proof_verified
        ):
            raise PublisherPoolAnchorError("closing_proof_mismatch")

    @staticmethod
    def _write_once(path: Path, raw: bytes) -> None:
        if path.exists():
            if _read_safe(path, MAX_INPUT_BYTES, path.stem) != raw:
                raise PublisherPoolAnchorError("pool_anchor_evidence_tampered")
            return
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _parse_canonical(raw: bytes, model, label: str):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise PublisherPoolAnchorError(f"{label}_size_invalid")
    try:
        value = model.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise PublisherPoolAnchorError(f"{label}_invalid") from error
    if canonical_json_bytes(value) != raw:
        raise PublisherPoolAnchorError(f"{label}_noncanonical")
    return value


def _canonical_array(raw: bytes) -> list[Mapping[str, object]]:
    import json

    value = json.loads(raw)
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError("anchor intents must be an array")
    if not value or any(not isinstance(item, Mapping) for item in value):
        raise ValueError("anchor intents must contain objects")
    return list(value)


def _secure_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o022
    ):
        raise PublisherPoolAnchorError("pool_anchor_state_unsafe")


def _read_safe(path: Path, maximum: int, label: str) -> bytes:
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
            or before.st_mode & 0o022
            or not 0 < before.st_size <= maximum
        ):
            raise PublisherPoolAnchorError(f"{label}_unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
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


__all__ = [
    "ClosingAnchorEvidence",
    "LoadedPoolAnchor",
    "PoolAnchorBinding",
    "PoolAnchorEvidence",
    "PoolAnchorPending",
    "ProofBackedPublisherClosingPort",
    "PublisherPoolAnchorError",
    "PublisherPoolAnchorOperator",
    "load_pool_anchor_material",
]
