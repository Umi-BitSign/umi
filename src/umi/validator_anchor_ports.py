"""Production Bittensor ports for the validator's three transcript anchors.

This module is intentionally not a generic transaction adapter.  It can only
prepare ``Commitments.set_commitment`` on SN78 with one ``Sha256`` field, and
it only exposes signing/submission as an :class:`ExtrinsicPorts` bundle bound
to one closed :class:`ExtrinsicOperation`.  The durable
``ValidatorExtrinsicJournal`` remains the interlock which orders those ports:
prepare and persist, sign the persisted payload, reconcile, then submit the
exact persisted unsigned record and signature.

Finalized state is not trusted merely because a Bittensor RPC decoded it.  A
``FinalizedProofCollector``-shaped port must provide an independently verified
finalized head, allowlisted runtime metadata, and a trie-proof-backed
``Commitments.CommitmentOf`` read.  Inclusion comes only from complete
verifier-owned intervals whose bodies and ``System.Events`` are authenticated
by ``FinalizedBlockScanner``; node-decoded lookup results are not authoritative.
The exact replay inputs are durably stored behind a compact content-addressed
sidecar reference before reconciliation returns.  Quicknet timing is a separate
read-only trust boundary: ``VerifiedRoundAtBlockPort`` must independently bind
a round observation to the exact finalized block number and hash supplied to it.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
import stat
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import bittensor as bt
from bittensor import UnsignedExtrinsic
from pydantic import JsonValue

from .grandpa_finality import EVIDENCE_CLASS, RECORD_SCHEMA
from .grandpa_finality_supervisor import VerifiedFinalityScanInterval
from .policy import FinalityVerifierPin, LiveChainObservationPin
from .protocol import canonical_json_bytes
from .validator_anchor_evidence import AnchorScanEvidenceRef
from .validator_assignments import FrozenRoot
from .validator_chain import (
    FinalizedRuntimePin,
    PinnedRuntimeContext,
    VerifiedStorageRead,
)
from .validator_chain_scan import (
    CapturedFinalizedBlockInterval,
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from .validator_extrinsics import (
    MAX_RECEIPT_BYTES,
    PREPARED_CALL_SCHEMA,
    RECONCILIATION_SCHEMA,
    SUBMISSION_SCHEMA,
    ExtrinsicJournalError,
    ExtrinsicOperation,
    ExtrinsicPorts,
    ExtrinsicReceipt,
    ExtrinsicState,
    JournalEntry,
    PreparedCallEvidence,
    ReconcileOutcome,
    ReconcileQuery,
    ReconciliationEvidence,
    SubmissionEvidence,
    mortal_era_bounds,
)
from .validator_plans import VerifiedFinalizedBlock
from .validator_transcript_effects import VerifiedAnchorFinality
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, quicknet_round_at_ms

NETUID = 78
DEFAULT_ERA_PERIOD = 64
MAX_ERA_PERIOD = 4_096
MAX_ROUND_EVIDENCE_BYTES = 256 * 1024
_READ_CHUNK_BYTES = 64 * 1024

ANCHOR_SCAN_SCHEMA = "umi-bittensor-anchor-reconciliation/1"
ANCHOR_FINALITY_EVIDENCE_SCHEMA = "umi-bittensor-anchor-finality/1"
GRANDPA_ROUND_EVIDENCE_SCHEMA = "umi-grandpa-quicknet-round-at-block/1"

_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_ANCHOR_KINDS = frozenset({"assignment_set", "request_set", "response_set", "publisher_pool"})
_GRANDPA_ATTESTATION_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "evidence_class",
        "offline_finality_proof",
        "source_revision",
        "sequence",
        "chain_spec_sha256",
        "genesis_hash",
        "bootstrap_block_number",
        "bootstrap_block_hash",
        "bootstrap_source",
        "bootstrap_selected",
        "startup_finalized_block_number",
        "startup_finalized_block_hash",
        "block",
        "ancestry",
        "ancestry_complete_since_previous",
        "previous_finalized_hash",
        "previous_transcript_digest",
        "transcript_digest",
    }
)


class BittensorAnchorPortError(ExtrinsicJournalError):
    """A stable fail-closed error at the live anchor boundary."""


class BittensorAnchorBindingError(BittensorAnchorPortError):
    """Live SDK, proof, or round material binds another operation."""


class BittensorAnchorSubmissionError(RuntimeError):
    """Submission crossed the SDK boundary without an affirmative result.

    This deliberately is not an ``ExtrinsicJournalError``.  The journal treats
    it as an ambiguous submission outcome, persists ``UNKNOWN``, and will only
    reconcile afterwards; it will not blindly rebroadcast.
    """


class GrandpaQuicknetRoundError(RuntimeError):
    """A durable verifier attestation cannot prove one block's Quicknet round."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class VerifiedRoundAtBlock:
    """An independently verified Quicknet round bound to one chain block."""

    block_number: int
    block_hash: str
    state_root: str
    timestamp_ms: int
    quicknet_round: int
    finality_verifier_sha256: str
    finality_evidence_sha256: str
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        _nonnegative_int(self.block_number, "round observation block")
        _chain_hash(self.block_hash, "round observation block hash")
        _chain_hash(self.state_root, "round observation state root")
        _nonnegative_int(self.timestamp_ms, "round observation timestamp")
        _positive_int(self.quicknet_round, "verified Quicknet round")
        if self.quicknet_round != quicknet_round_at_ms(self.timestamp_ms):
            raise ValueError("verified Quicknet round does not match its timestamp")
        _hex32(self.finality_verifier_sha256, "round finality verifier digest")
        _hex32(self.finality_evidence_sha256, "round finality evidence digest")
        if (
            not isinstance(self.evidence_bytes, bytes)
            or not self.evidence_bytes
            or len(self.evidence_bytes) > MAX_ROUND_EVIDENCE_BYTES
        ):
            raise ValueError("verified round evidence has an invalid size")


class VerifiedRoundAtBlockPort(Protocol):
    """Read-only proof boundary for block-timestamp-to-Quicknet mapping.

    Implementations must verify their own evidence.  This adapter only checks
    that the returned proof result names the exact finalized block requested.
    """

    def verified_round_at(
        self,
        block_number: int,
        block_hash: str,
    ) -> VerifiedRoundAtBlock | Awaitable[VerifiedRoundAtBlock | None] | None: ...


class VerifiedFinalizedBlockAtHeightPort(Protocol):
    """Read one durable verifier-attested finalized block by exact height."""

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None: ...


class GrandpaQuicknetRoundPort:
    """Derive Quicknet time from smoldot-authenticated ``Timestamp.Now``.

    ``DurableGrandpaFinalityPort`` obtains the timestamp through its embedded
    smoldot light client, so the storage read and finalized block identity do
    not come from the Bittensor provider used for transaction submission.  This
    adapter reparses the canonical durable attestation, reproduces its content
    and transcript digests, and binds every policy/runtime identity before it
    maps the authenticated millisecond timestamp onto the pinned Quicknet
    schedule.  It is read-only and holds no signer or broadcast capability.
    """

    def __init__(
        self,
        *,
        finality: VerifiedFinalizedBlockAtHeightPort,
        scoring_policy_sha256: str,
        chain_observation: LiveChainObservationPin,
        finality_pin: FinalityVerifierPin,
        finality_verifier_sha256: str,
    ) -> None:
        if not callable(getattr(finality, "verified_block_at", None)):
            raise TypeError("finality must define verified_block_at()")
        _hex32(scoring_policy_sha256, "scoring policy digest")
        if not isinstance(chain_observation, LiveChainObservationPin):
            raise TypeError("chain_observation must be a LiveChainObservationPin")
        if not isinstance(finality_pin, FinalityVerifierPin):
            raise TypeError("finality_pin must be a FinalityVerifierPin")
        _hex32(finality_verifier_sha256, "finality verifier digest")
        if finality_pin.expected_genesis_hash != chain_observation.genesis_block_hash:
            raise ValueError("finality and live-chain genesis pins disagree")
        if finality_verifier_sha256 not in finality_pin.release_sha256_by_target.values():
            raise ValueError("finality verifier digest is absent from the policy release pins")
        self._finality = finality
        self._scoring_policy_sha256 = scoring_policy_sha256
        self._chain_observation = chain_observation
        self._finality_pin = finality_pin
        self._finality_verifier_sha256 = finality_verifier_sha256

    async def verified_round_at(
        self,
        block_number: int,
        block_hash: str,
    ) -> VerifiedRoundAtBlock | None:
        _nonnegative_int(block_number, "round lookup block")
        _chain_hash(block_hash, "round lookup block hash")
        try:
            block = await self._finality.verified_block_at(block_number)
        except Exception as error:
            raise GrandpaQuicknetRoundError("verified_block_lookup_failed") from error
        if block is None:
            return None
        if not isinstance(block, VerifiedFinalizedBlock):
            raise GrandpaQuicknetRoundError("verified_block_invalid")
        if block.height != block_number or block.block_hash != block_hash:
            raise GrandpaQuicknetRoundError("verified_block_identity_mismatch")
        if (
            block.scoring_policy_hash != self._scoring_policy_sha256
            or block.chain_observation != self._chain_observation
            or block.finality_verifier_sha256 != self._finality_verifier_sha256
        ):
            raise GrandpaQuicknetRoundError("verified_block_policy_mismatch")
        record = self._verified_attestation(block)
        timestamp_ms = block.timestamp_ms
        quicknet_round = quicknet_round_at_ms(timestamp_ms)
        transcript_digest = record["transcript_digest"]
        evidence = canonical_json_bytes(
            {
                "schema": GRANDPA_ROUND_EVIDENCE_SCHEMA,
                "block_number": block.height,
                "block_hash": block.block_hash,
                "state_root": block.state_root,
                "timestamp_ms": timestamp_ms,
                "quicknet_round": quicknet_round,
                "quicknet_genesis_ms": QUICKNET_GENESIS_MS,
                "quicknet_period_ms": QUICKNET_PERIOD_MS,
                "scoring_policy_sha256": self._scoring_policy_sha256,
                "chain_genesis_hash": self._chain_observation.genesis_block_hash,
                "finality_verifier_sha256": self._finality_verifier_sha256,
                "finality_evidence_sha256": block.finality_evidence_sha256,
                "finality_transcript_digest": transcript_digest,
            }
        )
        return VerifiedRoundAtBlock(
            block_number=block.height,
            block_hash=block.block_hash,
            state_root=block.state_root,
            timestamp_ms=timestamp_ms,
            quicknet_round=quicknet_round,
            finality_verifier_sha256=self._finality_verifier_sha256,
            finality_evidence_sha256=block.finality_evidence_sha256,
            evidence_bytes=evidence,
        )

    def _verified_attestation(self, block: VerifiedFinalizedBlock) -> Mapping[str, Any]:
        encoded = block.finality_evidence
        try:
            value = json.loads(
                encoded,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise GrandpaQuicknetRoundError("finality_attestation_invalid") from error
        if (
            not isinstance(value, dict)
            or frozenset(value) != _GRANDPA_ATTESTATION_KEYS
            or canonical_json_bytes(value) != encoded
        ):
            raise GrandpaQuicknetRoundError("finality_attestation_noncanonical")
        fixed = {
            "schema": RECORD_SCHEMA,
            "evidence_class": EVIDENCE_CLASS,
            "offline_finality_proof": False,
            "source_revision": self._finality_pin.source_revision,
            "chain_spec_sha256": self._finality_pin.chain_spec_sha256,
            "genesis_hash": "0x" + self._finality_pin.expected_genesis_hash,
            "bootstrap_block_number": self._finality_pin.bootstrap_block_number,
            "bootstrap_block_hash": "0x" + self._finality_pin.bootstrap_block_hash,
            "bootstrap_source": "grandpa_checkpoint",
            "bootstrap_selected": True,
        }
        if any(value.get(name) != expected for name, expected in fixed.items()):
            raise GrandpaQuicknetRoundError("finality_attestation_pin_mismatch")
        if hashlib.sha256(encoded).hexdigest() != block.finality_evidence_sha256:
            raise GrandpaQuicknetRoundError("finality_attestation_digest_mismatch")
        transcript_digest = value.get("transcript_digest")
        if not isinstance(transcript_digest, str) or _HEX32_RE.fullmatch(transcript_digest) is None:
            raise GrandpaQuicknetRoundError("finality_transcript_digest_invalid")
        unsigned = dict(value)
        unsigned.pop("transcript_digest", None)
        expected_transcript = hashlib.sha256(
            b"umi-grandpa-finality-attestation-v1\0" + canonical_json_bytes(unsigned)
        ).hexdigest()
        if transcript_digest != expected_transcript:
            raise GrandpaQuicknetRoundError("finality_transcript_digest_mismatch")
        body = value.get("block")
        if not isinstance(body, Mapping) or set(body) != {
            "number",
            "hash",
            "parent_hash",
            "state_root",
            "extrinsics_root",
            "scale_header",
            "timestamp_ms",
        }:
            raise GrandpaQuicknetRoundError("finality_block_invalid")
        if (
            body.get("number") != block.height
            or body.get("hash") != block.block_hash
            or body.get("state_root") != block.state_root
            or body.get("timestamp_ms") != block.timestamp_ms
        ):
            raise GrandpaQuicknetRoundError("finality_block_identity_mismatch")
        startup_number = value.get("startup_finalized_block_number")
        startup_hash = value.get("startup_finalized_block_hash")
        if (
            isinstance(startup_number, bool)
            or not isinstance(startup_number, int)
            or not self._finality_pin.bootstrap_block_number <= startup_number <= block.height
            or not isinstance(startup_hash, str)
            or _CHAIN_HASH_RE.fullmatch(startup_hash) is None
            or (startup_number == block.height and startup_hash != block.block_hash)
        ):
            raise GrandpaQuicknetRoundError("finality_startup_receipt_invalid")
        _verify_scale_header_identity(body)
        return value


class FinalizedAnchorEvidencePort(Protocol):
    """The proof-backed subset of ``FinalizedProofCollector`` used here."""

    async def finalized_snapshot(self) -> Any: ...

    async def pinned_runtime(
        self,
        snapshot: Any,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext: ...

    async def storage_read(
        self,
        runtime: PinnedRuntimeContext,
        pallet: str,
        item: str,
        params: Sequence[Any] = (),
    ) -> VerifiedStorageRead: ...


class PersistedPreparedAnchorPort(Protocol):
    """Lock-independent lookup of an immutable journal PREPARED receipt.

    The signing callback runs while ``ValidatorExtrinsicJournal`` owns its
    process and filesystem locks.  Implementations therefore must not acquire
    that journal lock or mutate/recover the journal.  They must return only
    evidence already durably stored before the current journal advance.
    """

    def prepared_anchor(
        self,
        operation_id: str,
    ) -> JournalEntry | Awaitable[JournalEntry | None] | None: ...


class VerifiedAnchorFinalityScanPort(Protocol):
    """Independent finalized identities and replay inputs for one interval."""

    async def verified_scan_interval(
        self,
        start_height: int,
        end_height: int,
    ) -> VerifiedFinalityScanInterval | None: ...


class ProofBoundAnchorScannerPort(Protocol):
    """Authenticate bodies/events and retain exact replay inputs."""

    async def capture_blocks(
        self,
        identities: Sequence[VerifiedFinalizedBlockIdentity],
        *,
        finality_attestations: Sequence[bytes],
        finality_replay_bindings: Sequence[FinalityAttestationReplayBinding],
        start_block: int,
        end_block: int,
    ) -> CapturedFinalizedBlockInterval: ...


class AnchorScanEvidenceStorePort(Protocol):
    """Durably persist and replay proof-bound anchor scan sidecars."""

    def persist(
        self,
        *,
        operation: ExtrinsicOperation,
        expected_extrinsic_hash: str,
        signed_extrinsic: bytes,
        interval: CapturedFinalizedBlockInterval,
        storage: VerifiedStorageRead,
        matches: Sequence[tuple[int, int]],
    ) -> AnchorScanEvidenceRef: ...

    def load(self, reference: AnchorScanEvidenceRef) -> dict[str, JsonValue]: ...


class DurablePreparedAnchorReader:
    """Read one exact PREPARED receipt without acquiring the journal lock.

    Receipt files are immutable, canonical, content-addressed objects.  A
    valid signing boundary has exactly the sequence-zero receipt and no other
    file in that operation directory.  Pending files, forks, successors,
    symlinks, oversized files, noncanonical JSON, and changed bytes all fail
    closed.  This reader never performs the journal's pending-file recovery.
    """

    def __init__(
        self,
        journal_root: str | Path,
        *,
        maximum_receipt_bytes: int = MAX_RECEIPT_BYTES,
    ) -> None:
        if (
            isinstance(maximum_receipt_bytes, bool)
            or not isinstance(maximum_receipt_bytes, int)
            or not 0 < maximum_receipt_bytes <= MAX_RECEIPT_BYTES
        ):
            raise ValueError("prepared-receipt ceiling is invalid")
        self._operations = Path(journal_root) / "operations"
        self._maximum_receipt_bytes = maximum_receipt_bytes

    def prepared_anchor(self, operation_id: str) -> JournalEntry | None:
        if not isinstance(operation_id, str) or _HEX32_RE.fullmatch(operation_id) is None:
            raise BittensorAnchorBindingError("prepared lookup operation ID is invalid")
        operation_dir = self._operations / operation_id
        if not os.path.lexists(operation_dir):
            return None
        _require_real_directory(operation_dir, "prepared receipt directory")
        try:
            paths = tuple(operation_dir.iterdir())
        except OSError as error:
            raise BittensorAnchorPortError("prepared receipt directory is unavailable") from error
        if len(paths) != 1:
            raise BittensorAnchorBindingError(
                "prepared receipt history is absent, pending, forked, or already advanced"
            )
        path = paths[0]
        match = re.fullmatch(r"([0-9a-f]{64})\.json", path.name)
        if match is None:
            raise BittensorAnchorBindingError("prepared receipt filename is not canonical")
        encoded = _read_bounded_regular_file(path, self._maximum_receipt_bytes)
        digest = hashlib.sha256(encoded).hexdigest()
        if digest != match.group(1):
            raise BittensorAnchorBindingError("prepared receipt filename does not match its bytes")
        try:
            decoded = json.loads(encoded)
            receipt = ExtrinsicReceipt.model_validate(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise BittensorAnchorBindingError("persisted prepared receipt is invalid") from error
        if canonical_json_bytes(receipt) != encoded:
            raise BittensorAnchorBindingError(
                "persisted prepared receipt is not exact canonical JSON"
            )
        if (
            receipt.operation_id != operation_id
            or receipt.sequence != 0
            or receipt.previous_receipt_sha256 is not None
            or ExtrinsicState(receipt.state) is not ExtrinsicState.PREPARED
        ):
            raise BittensorAnchorBindingError(
                "persisted evidence is not the exact prepared receipt"
            )
        return JournalEntry(receipt=receipt, receipt_sha256=digest, path=path)


@dataclass(slots=True)
class _SubmissionAuthorization:
    extrinsic_hash: str
    unsigned_record_sha256: str
    payload_sha256: str
    signature_sha256: str


@dataclass(slots=True)
class _BoundOperationState:
    runtime: PinnedRuntimeContext | None = None
    expected_extrinsic_hash: str | None = None
    expected_signed_bytes: bytes | None = None
    submission_authorization: _SubmissionAuthorization | None = None


class BittensorAnchorPorts:
    """Bind one private Bittensor signer and substrate client to exact anchors.

    ``subtensor`` must be an awaited Bittensor 11.1 ``Client`` (or a direct
    object implementing its public ``Substrate`` protocol).  The signer and
    substrate object remain private; callers receive only operation-bound
    ``ExtrinsicPorts`` closures and the read-only ``verify_anchor`` method.
    """

    def __init__(
        self,
        *,
        subtensor: Any,
        signer: Any,
        evidence: FinalizedAnchorEvidencePort,
        runtime_pin: FinalizedRuntimePin,
        rounds: VerifiedRoundAtBlockPort,
        prepared: PersistedPreparedAnchorPort,
        finality: VerifiedAnchorFinalityScanPort,
        scanner: ProofBoundAnchorScannerPort,
        sidecars: AnchorScanEvidenceStorePort,
        genesis_hash: str,
        finality_verifier_sha256: str,
        era_period: int = DEFAULT_ERA_PERIOD,
        allowed_anchor_kinds: frozenset[str] = frozenset(
            {"assignment_set", "request_set", "response_set"}
        ),
    ) -> None:
        substrate = getattr(subtensor, "_substrate", subtensor)
        for name in (
            "compose",
            "prepare",
            "submit_signature",
        ):
            if not callable(getattr(substrate, name, None)):
                raise TypeError(f"subtensor substrate must define {name}()")
        for name in ("finalized_snapshot", "pinned_runtime", "storage_read"):
            if not callable(getattr(evidence, name, None)):
                raise TypeError(f"evidence port must define {name}()")
        if not isinstance(runtime_pin, FinalizedRuntimePin):
            raise TypeError("runtime_pin must be a FinalizedRuntimePin")
        if not callable(getattr(rounds, "verified_round_at", None)):
            raise TypeError("rounds port must define verified_round_at()")
        if not callable(getattr(prepared, "prepared_anchor", None)):
            raise TypeError("prepared port must define prepared_anchor()")
        if not callable(getattr(finality, "verified_scan_interval", None)):
            raise TypeError("finality port must define verified_scan_interval()")
        if not callable(getattr(scanner, "capture_blocks", None)):
            raise TypeError("scanner port must define capture_blocks()")
        if not all(callable(getattr(sidecars, name, None)) for name in ("persist", "load")):
            raise TypeError("sidecars port must define persist() and load()")
        _hex32(genesis_hash, "chain genesis hash")
        _hex32(finality_verifier_sha256, "finality verifier digest")
        if (
            isinstance(era_period, bool)
            or not isinstance(era_period, int)
            or not 4 <= era_period <= MAX_ERA_PERIOD
            or era_period & (era_period - 1)
        ):
            raise ValueError("era_period must be a power of two between 4 and 4096")
        if not allowed_anchor_kinds or not allowed_anchor_kinds.issubset(_ANCHOR_KINDS):
            raise ValueError("allowed anchor kinds are invalid")

        try:
            address = signer.ss58_address
            public_key = signer.public_key
            crypto_type = signer.crypto_type
            sign = signer.sign
        except Exception as error:
            raise TypeError("signer does not implement the Bittensor Signer contract") from error
        if not isinstance(address, str) or not address:
            raise ValueError("signer address must be nonempty")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("signer public key must contain exactly 32 bytes")
        if crypto_type not in {0, 1}:
            raise ValueError("only ed25519 and sr25519 anchor signers are supported")
        if not callable(sign):
            raise TypeError("signer must define sign()")

        self._substrate = substrate
        self._signer = signer
        self._address = address
        self._public_key = public_key
        self._crypto_type = crypto_type
        self._evidence = evidence
        self._runtime_pin = runtime_pin
        self._rounds = rounds
        self._prepared = prepared
        self._finality = finality
        self._scanner = scanner
        self._sidecars = sidecars
        self._genesis_hash = genesis_hash
        self._finality_verifier_sha256 = finality_verifier_sha256
        self._era_period = era_period
        self._allowed_anchor_kinds = allowed_anchor_kinds

    @property
    def signer_account_id32(self) -> bytes:
        """Return only the public account identity bound to this adapter.

        The private signer and generic substrate client intentionally remain
        inaccessible.  Production service composition uses this read-only value
        to reject an anchor adapter for a different configured validator.
        """

        return self._public_key

    @property
    def runtime_pin(self) -> FinalizedRuntimePin:
        """Return the immutable runtime identity accepted by this adapter."""

        return self._runtime_pin

    @property
    def genesis_hash(self) -> str:
        """Return the immutable chain genesis hash accepted by this adapter."""

        return self._genesis_hash

    @property
    def finality_verifier_sha256(self) -> str:
        """Return the immutable finality-verifier release bound to this adapter."""

        return self._finality_verifier_sha256

    def __call__(self, operation: ExtrinsicOperation, _work: Any = None) -> ExtrinsicPorts:
        """Implement ``TranscriptEffectPorts.anchor_ports``."""

        return self.for_operation(operation)

    def for_operation(self, operation: ExtrinsicOperation) -> ExtrinsicPorts:
        """Return the journal ports for one closed anchor operation."""

        self._require_operation(operation)
        state = _BoundOperationState()

        async def prepare(requested: ExtrinsicOperation) -> UnsignedExtrinsic:
            self._require_same_operation(operation, requested)
            return await self._prepare(operation, state)

        async def verify_prepared_call(
            requested: ExtrinsicOperation,
            unsigned: UnsignedExtrinsic,
        ) -> PreparedCallEvidence:
            self._require_same_operation(operation, requested)
            return await self._verify_prepared_call(operation, unsigned, state)

        async def sign(payload: bytes, operation_id: str) -> bytes:
            return await self._sign(operation, state, payload, operation_id)

        async def derive_signed_hash(unsigned: UnsignedExtrinsic, signature: bytes) -> str:
            return await self._derive_signed_hash(operation, state, unsigned, signature)

        async def reconcile(query: ReconcileQuery) -> ReconciliationEvidence:
            return await self._reconcile(operation, state, query)

        async def submit(
            unsigned: UnsignedExtrinsic,
            signature: bytes,
        ) -> SubmissionEvidence:
            return await self._submit(operation, state, unsigned, signature)

        return ExtrinsicPorts(
            prepare=prepare,
            verify_prepared_call=verify_prepared_call,
            sign=sign,
            submit=submit,
            reconcile=reconcile,
            derive_signed_hash=derive_signed_hash,
        )

    async def _prepare(
        self,
        operation: ExtrinsicOperation,
        state: _BoundOperationState,
    ) -> UnsignedExtrinsic:
        snapshot = await self._finalized_snapshot()
        runtime = await self._pinned_runtime(snapshot)
        raw_call = bt.calls.Commitments.set_commitment(
            netuid=NETUID,
            info={"fields": [{"Sha256": bytes.fromhex(operation.request.field.sha256)}]},
        )
        if (
            raw_call.module != "Commitments"
            or raw_call.function != "set_commitment"
            or raw_call.params
            != {
                "netuid": NETUID,
                "info": {"fields": [{"Sha256": bytes.fromhex(operation.request.field.sha256)}]},
            }
        ):
            raise BittensorAnchorBindingError("generated commitment call is not exact")
        try:
            composed = await self._substrate.compose(raw_call)
            unsigned = await self._substrate.prepare(
                composed,
                address=self._address,
                crypto_type=self._crypto_type,
                period=self._era_period,
                tip=0,
                metadata_hash=None,
            )
        except BittensorAnchorPortError:
            raise
        except Exception as error:
            raise BittensorAnchorPortError("anchor preparation failed") from error
        if not isinstance(unsigned, UnsignedExtrinsic):
            raise BittensorAnchorBindingError("Bittensor prepare did not return UnsignedExtrinsic")
        await self._validate_unsigned_envelope(operation, unsigned, snapshot)
        self._verify_call_bytes(operation, unsigned, runtime)
        state.runtime = runtime
        return unsigned

    async def _verify_prepared_call(
        self,
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
        state: _BoundOperationState,
    ) -> PreparedCallEvidence:
        runtime = state.runtime
        if runtime is None:
            snapshot = await self._finalized_snapshot()
            await self._validate_unsigned_envelope(operation, unsigned, snapshot)
            runtime = await self._pinned_runtime(snapshot)
        self._verify_call_bytes(operation, unsigned, runtime)
        state.runtime = runtime
        try:
            return PreparedCallEvidence(
                schema=PREPARED_CALL_SCHEMA,
                operation_id=operation.operation_id,
                call_data_sha256=hashlib.sha256(unsigned.call_data).hexdigest(),
                call_data_size_bytes=len(unsigned.call_data),
                module="Commitments",
                function="set_commitment",
                netuid=NETUID,
                anchor_kind=operation.request.anchor_kind,
                field_sha256=operation.request.field.sha256,
                runtime_spec_version=runtime.pin.spec_version,
                transaction_version=runtime.pin.transaction_version,
                runtime_metadata_sha256=runtime.metadata_sha256,
            )
        except (TypeError, ValueError) as error:
            raise BittensorAnchorBindingError("prepared-call evidence is invalid") from error

    async def _sign(
        self,
        operation: ExtrinsicOperation,
        state: _BoundOperationState,
        payload: bytes,
        operation_id: str,
    ) -> bytes:
        if operation_id != operation.operation_id:
            raise BittensorAnchorBindingError("sign request names another operation")
        if not isinstance(payload, bytes) or not 0 < len(payload) <= 256:
            raise BittensorAnchorBindingError("sign request payload has an invalid size")
        entry = await self._persisted_prepared(operation.operation_id)
        receipt = entry.receipt
        if receipt.operation_id != operation.operation_id or receipt.operation != operation:
            raise BittensorAnchorBindingError("persisted prepared evidence binds another operation")
        if (
            entry.state is not ExtrinsicState.PREPARED
            or receipt.sequence != 0
            or receipt.previous_receipt_sha256 is not None
        ):
            raise BittensorAnchorBindingError("persisted evidence is not a prepared receipt")
        persisted_digest = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        if (
            entry.receipt_sha256 != persisted_digest
            or entry.path.name != f"{persisted_digest}.json"
        ):
            raise BittensorAnchorBindingError("persisted prepared receipt is not content-addressed")
        unsigned = entry.unsigned
        if payload != bytes(unsigned.payload) or (
            hashlib.sha256(payload).hexdigest() != receipt.payload_sha256
        ):
            raise BittensorAnchorBindingError("sign request is not the persisted SDK payload")
        snapshot = await self._finalized_snapshot()
        runtime = await self._pinned_runtime(snapshot)
        await self._validate_unsigned_envelope(operation, unsigned, snapshot)
        self._verify_call_bytes(operation, unsigned, runtime)
        prepared_call = receipt.prepared_call
        if (
            prepared_call.operation_id != operation.operation_id
            or prepared_call.runtime_metadata_sha256 != runtime.metadata_sha256
            or prepared_call.runtime_spec_version != runtime.pin.spec_version
            or prepared_call.transaction_version != runtime.pin.transaction_version
            or prepared_call.call_data_sha256 != hashlib.sha256(unsigned.call_data).hexdigest()
            or prepared_call.call_data_size_bytes != len(unsigned.call_data)
            or prepared_call.module != "Commitments"
            or prepared_call.function != "set_commitment"
            or prepared_call.netuid != NETUID
            or prepared_call.anchor_kind != operation.request.anchor_kind
            or prepared_call.field_sha256 != operation.request.field.sha256
        ):
            raise BittensorAnchorBindingError(
                "persisted prepared-call evidence is not the exact anchor"
            )
        state.runtime = runtime
        method = self._signer.sign
        try:
            if inspect.iscoroutinefunction(method):
                signature = await method(payload)
            else:
                signature = await asyncio.to_thread(method, payload)
                if inspect.isawaitable(signature):
                    signature = await signature
        except Exception as error:
            raise BittensorAnchorPortError("anchor signing failed") from error
        self._validate_signature(signature)
        return signature

    async def _derive_signed_hash(
        self,
        operation: ExtrinsicOperation,
        state: _BoundOperationState,
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> str:
        self._validate_signature(signature)
        snapshot = await self._finalized_snapshot()
        await self._validate_unsigned_envelope(operation, unsigned, snapshot)
        runtime = state.runtime
        if runtime is None or runtime.snapshot != snapshot:
            runtime = await self._pinned_runtime(snapshot)
        self._verify_call_bytes(operation, unsigned, runtime)
        state.runtime = runtime
        signature_bytes, signature_version = _normalized_signature(
            signature,
            unsigned.crypto_type,
        )
        try:
            signed_data, core_hash = runtime._runtime.encode_signed_extrinsic(
                bytes(unsigned.call_data),
                public_key=bytes(unsigned.public_key),
                signature=signature_bytes,
                signature_version=signature_version,
                era=unsigned.era,
                nonce=unsigned.nonce,
                tip=unsigned.tip,
                tip_asset_id=unsigned.tip_asset_id,
                metadata_hash_enabled=unsigned.metadata_hash is not None,
            )
            signed_data = bytes(signed_data)
            core_hash = bytes(core_hash)
        except Exception as error:
            raise BittensorAnchorPortError("signed anchor assembly failed") from error
        if not signed_data or len(core_hash) != 32:
            raise BittensorAnchorBindingError("signed anchor assembly returned invalid bytes")
        calculated = hashlib.blake2b(signed_data, digest_size=32).digest()
        if calculated != core_hash:
            raise BittensorAnchorBindingError("SDK signed extrinsic hash does not reproduce")
        result = "0x" + core_hash.hex()
        state.expected_extrinsic_hash = result
        state.expected_signed_bytes = signed_data
        return result

    async def _reconcile(
        self,
        operation: ExtrinsicOperation,
        state: _BoundOperationState,
        query: ReconcileQuery,
    ) -> ReconciliationEvidence:
        if not isinstance(query, ReconcileQuery):
            raise TypeError("query must be a ReconcileQuery")
        self._require_same_operation(operation, query.operation)
        self._validate_signature(query.signature)
        state.submission_authorization = None
        binding = _material_binding(query.unsigned, query.signature)

        derived_hash = await self._derive_signed_hash(
            operation,
            state,
            query.unsigned,
            query.signature,
        )
        expected_hash = query.expected_extrinsic_hash
        if expected_hash is not None:
            _chain_hash(expected_hash, "expected signed extrinsic hash")
            if derived_hash != expected_hash:
                raise BittensorAnchorBindingError("signed extrinsic hash changed")
        else:
            expected_hash = derived_hash
        state.expected_extrinsic_hash = expected_hash

        snapshot = await self._finalized_snapshot()
        if snapshot.block_number < query.era_birth_block:
            raise BittensorAnchorPortError("finalized head predates the anchor mortal era")
        scan_end = min(snapshot.block_number, query.era_death_block - 1)
        if query.era_birth_block == 0:
            raise BittensorAnchorPortError("anchor mortal era includes unscannable genesis")
        try:
            finalized_interval = await self._finality.verified_scan_interval(
                query.era_birth_block,
                scan_end,
            )
        except Exception as error:
            raise BittensorAnchorPortError("verified finalized interval is unavailable") from error
        if not isinstance(finalized_interval, VerifiedFinalityScanInterval):
            raise BittensorAnchorPortError("verified finalized interval is unavailable")
        expected_heights = tuple(range(query.era_birth_block, scan_end + 1))
        if (
            tuple(item.snapshot.block_number for item in finalized_interval.identities)
            != expected_heights
        ):
            raise BittensorAnchorBindingError("verified finalized interval is incomplete")
        if any(
            item.finality_verifier_sha256 != self._finality_verifier_sha256
            for item in finalized_interval.identities
        ):
            raise BittensorAnchorBindingError(
                "verified finalized interval uses another finality verifier"
            )
        if (
            scan_end == snapshot.block_number
            and finalized_interval.identities[-1].snapshot != snapshot
        ):
            raise BittensorAnchorBindingError(
                "scanner finality and owned storage finality disagree"
            )
        try:
            captured = await self._scanner.capture_blocks(
                finalized_interval.identities,
                finality_attestations=finalized_interval.attestations,
                finality_replay_bindings=finalized_interval.replay_bindings,
                start_block=query.era_birth_block,
                end_block=scan_end,
            )
        except Exception as error:
            raise BittensorAnchorPortError("proof-bound finalized scan failed") from error
        if (
            not isinstance(captured, CapturedFinalizedBlockInterval)
            or tuple(block.snapshot.block_number for block in captured.blocks) != expected_heights
            or tuple(item.identity for item in captured.evidence) != finalized_interval.identities
        ):
            raise BittensorAnchorBindingError("proof-bound finalized scan is inconsistent")
        signed_bytes = state.expected_signed_bytes
        if signed_bytes is None:
            raise BittensorAnchorBindingError("signed anchor bytes were not reproduced")
        matches: list[tuple[int, str, int, Any]] = []
        blocks: list[dict[str, JsonValue]] = []
        for item in captured.evidence:
            height = item.identity.snapshot.block_number
            block_hash = item.identity.snapshot.block_hash
            matched_indices: list[int] = []
            for index, raw in enumerate(item.body.extrinsics):
                if raw != signed_bytes:
                    continue
                if index >= len(item.decoded_block.calls):
                    raise BittensorAnchorBindingError(
                        "proof-bound scan omitted the matched decoded call"
                    )
                call = item.decoded_block.calls[index]
                self._validate_scanned_anchor_call(
                    operation,
                    query.unsigned,
                    item,
                    call,
                    index,
                )
                matched_indices.append(index)
                matches.append((height, block_hash, index, call))
            blocks.append(
                {
                    "number": height,
                    "hash": block_hash,
                    "parent_hash": item.identity.snapshot.parent_hash,
                    "state_root": item.identity.snapshot.state_root,
                    "extrinsics_root": item.identity.extrinsics_root,
                    "finality_verifier_sha256": item.identity.finality_verifier_sha256,
                    "finality_evidence_sha256": item.identity.finality_evidence_sha256,
                    "body_sha256": item.body.body_sha256,
                    "system_events_value_sha256": item.event_storage.value_sha256,
                    "matched_indices": matched_indices,
                }
            )

        runtime = await self._pinned_runtime(snapshot)
        try:
            storage = await self._evidence.storage_read(
                runtime,
                "Commitments",
                "CommitmentOf",
                (NETUID, self._address),
            )
        except BittensorAnchorPortError:
            raise
        except Exception as error:
            raise BittensorAnchorPortError("finalized commitment proof failed") from error
        if not isinstance(storage, VerifiedStorageRead):
            raise BittensorAnchorBindingError(
                "commitment proof port did not return VerifiedStorageRead"
            )
        if storage.runtime != runtime or storage.evidence.snapshot != snapshot:
            raise BittensorAnchorBindingError("commitment proof binds another finalized head")
        storage_matches, storage_block = _commitment_binding(
            storage.decoded_value,
            operation.request.field.sha256,
        )

        outcome = ReconcileOutcome.UNKNOWN
        inclusion_block: int | None = None
        inclusion_hash: str | None = None
        if len(matches) == 1:
            inclusion_block, inclusion_hash, _inclusion_index, call = matches[0]
            if call.successful is False:
                outcome = ReconcileOutcome.FINALIZED_FAILURE
            elif storage_matches and storage_block == inclusion_block:
                outcome = ReconcileOutcome.FINALIZED_SUCCESS
            else:
                # Exact successful inclusion without the matching proven state
                # is contradictory or overwritten.  Never call it successful.
                outcome = ReconcileOutcome.UNKNOWN
                inclusion_block = None
                inclusion_hash = None
        elif not matches and not storage_matches:
            outcome = ReconcileOutcome.NOT_FOUND

        try:
            sidecar = await asyncio.to_thread(
                self._sidecars.persist,
                operation=operation,
                expected_extrinsic_hash=expected_hash,
                signed_extrinsic=signed_bytes,
                interval=captured,
                storage=storage,
                matches=tuple((height, index) for height, _hash, index, _call in matches),
            )
            if inspect.isawaitable(sidecar):
                sidecar = await sidecar
        except Exception as error:
            raise BittensorAnchorPortError("anchor scan sidecar persistence failed") from error
        if not isinstance(sidecar, AnchorScanEvidenceRef):
            raise BittensorAnchorBindingError("anchor scan sidecar reference is invalid")

        scan: dict[str, JsonValue] = {
            "schema": ANCHOR_SCAN_SCHEMA,
            "operation_id": operation.operation_id,
            "expected_extrinsic_hash": expected_hash,
            "blocks": blocks,
            "matched_inclusions": [
                {
                    "number": height,
                    "hash": block_hash,
                    "extrinsic_index": index,
                    "call_hash": call.call_hash,
                    "module": call.module,
                    "function": call.function,
                    "signer_account_id32": "0x" + bytes(call.signer_account_id32).hex(),
                    "effective_origin_account_id32": (
                        "0x" + bytes(call.effective_origin_account_id32).hex()
                    ),
                    "successful": call.successful,
                    "netuid": NETUID,
                    "field_sha256": operation.request.field.sha256,
                }
                for height, block_hash, index, call in matches
            ],
            "sidecar": sidecar.as_json(),
            "storage": {
                "pallet": "Commitments",
                "item": "CommitmentOf",
                "params": [NETUID, self._address],
                "snapshot": _snapshot_json(snapshot),
                "runtime": {
                    "metadata_sha256": runtime.metadata_sha256,
                    "spec_version": runtime.pin.spec_version,
                    "transaction_version": runtime.pin.transaction_version,
                },
                "key_sha256": hashlib.sha256(storage.evidence.storage_key).hexdigest(),
                "value_sha256": hashlib.sha256(storage.evidence.value or b"").hexdigest(),
                "proof_node_count": len(storage.evidence.proof),
                "proof_sha256": hashlib.sha256(
                    canonical_json_bytes(["0x" + node.hex() for node in storage.evidence.proof])
                ).hexdigest(),
                "decoded": _json_native(storage.decoded_value),
                "matches_anchor": storage_matches,
                "commitment_block": storage_block,
            },
        }
        try:
            scan_sha256 = hashlib.sha256(canonical_json_bytes(scan)).hexdigest()
            evidence = ReconciliationEvidence(
                schema=RECONCILIATION_SCHEMA,
                operation_id=operation.operation_id,
                outcome=outcome.value,
                finalized_head_block=snapshot.block_number,
                finalized_head_hash=snapshot.block_hash,
                scan_start_block=query.era_birth_block,
                scan_end_block=scan_end,
                scan=scan,
                scan_sha256=scan_sha256,
                extrinsic_hash=expected_hash,
                inclusion_block=inclusion_block,
                inclusion_block_hash=inclusion_hash,
                **binding,
            )
        except (TypeError, ValueError) as error:
            raise BittensorAnchorBindingError(
                "anchor reconciliation evidence exceeds or violates its schema"
            ) from error

        if outcome is ReconcileOutcome.NOT_FOUND and snapshot.block_number < query.era_death_block:
            state.submission_authorization = _SubmissionAuthorization(
                extrinsic_hash=expected_hash,
                **binding,
            )
        return evidence

    async def _submit(
        self,
        operation: ExtrinsicOperation,
        state: _BoundOperationState,
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> SubmissionEvidence:
        self._validate_signature(signature)
        authorization = state.submission_authorization
        binding = _material_binding(unsigned, signature)
        if authorization is None:
            raise BittensorAnchorBindingError(
                "submission was not authorized by a live-era not-found reconciliation"
            )
        if any(
            getattr(authorization, name) != binding[name]
            for name in (
                "unsigned_record_sha256",
                "payload_sha256",
                "signature_sha256",
            )
        ):
            raise BittensorAnchorBindingError(
                "submission material differs from the reconciled signed anchor"
            )
        # Consume the one-shot authorization before making the network call.
        state.submission_authorization = None
        try:
            result = await self._substrate.submit_signature(
                unsigned,
                signature,
                wait_for_inclusion=False,
                wait_for_finalization=False,
            )
        except Exception as error:
            raise BittensorAnchorSubmissionError("anchor submission outcome is unknown") from error
        if getattr(result, "success", None) is not True:
            raise BittensorAnchorSubmissionError("anchor submission was not accepted")
        try:
            return SubmissionEvidence(
                schema=SUBMISSION_SCHEMA,
                operation_id=operation.operation_id,
                extrinsic_hash=authorization.extrinsic_hash,
                **binding,
            )
        except (TypeError, ValueError) as error:
            raise BittensorAnchorBindingError("anchor submission evidence is invalid") from error

    async def verify_anchor(
        self,
        operation: ExtrinsicOperation,
        frozen: FrozenRoot,
        entry: JournalEntry,
        _work: Any,
    ) -> VerifiedAnchorFinality:
        """Implement ``TranscriptEffectPorts.verify_anchor`` fail-closed."""

        self._require_operation(operation)
        if not isinstance(frozen, FrozenRoot):
            raise TypeError("frozen must be a FrozenRoot")
        if frozen.kind != operation.request.anchor_kind or frozen.root != (
            operation.request.field.sha256
        ):
            raise BittensorAnchorBindingError("frozen root binds another anchor")
        if not isinstance(entry, JournalEntry):
            raise TypeError("entry must be a JournalEntry")
        receipt = entry.receipt
        reconciliation = receipt.reconciliation
        if (
            entry.state is not ExtrinsicState.FINALIZED_SUCCESS
            or receipt.operation != operation
            or reconciliation is None
            or reconciliation.outcome != ReconcileOutcome.FINALIZED_SUCCESS.value
            or reconciliation.inclusion_block is None
            or reconciliation.inclusion_block_hash is None
        ):
            raise BittensorAnchorBindingError(
                "anchor finality requires exact successful reconciliation"
            )
        storage_scan = reconciliation.scan.get("storage")
        if (
            reconciliation.scan.get("schema") != ANCHOR_SCAN_SCHEMA
            or not isinstance(storage_scan, dict)
            or storage_scan.get("matches_anchor") is not True
            or storage_scan.get("commitment_block") != reconciliation.inclusion_block
        ):
            raise BittensorAnchorBindingError(
                "anchor reconciliation lacks matching proof-backed storage"
            )
        try:
            sidecar_value = reconciliation.scan.get("sidecar")
            if not isinstance(sidecar_value, Mapping):
                raise ValueError("sidecar reference is missing")
            sidecar = AnchorScanEvidenceRef.from_json(sidecar_value)
            manifest = await asyncio.to_thread(self._sidecars.load, sidecar)
            if inspect.isawaitable(manifest):
                manifest = await manifest
        except Exception as error:
            raise BittensorAnchorPortError("anchor scan sidecar replay failed") from error
        matched_scan = reconciliation.scan.get("matched_inclusions")
        manifest_storage = (
            manifest.get("commitment_storage") if isinstance(manifest, Mapping) else None
        )
        manifest_storage_snapshot = (
            manifest_storage.get("snapshot") if isinstance(manifest_storage, Mapping) else None
        )
        if (
            not isinstance(matched_scan, list)
            or len(matched_scan) != 1
            or not isinstance(matched_scan[0], dict)
            or isinstance(matched_scan[0].get("extrinsic_index"), bool)
            or not isinstance(matched_scan[0].get("extrinsic_index"), int)
        ):
            raise BittensorAnchorBindingError(
                "anchor reconciliation lacks one exact decoded inclusion"
            )
        if (
            not isinstance(manifest, Mapping)
            or sidecar.operation_id != operation.operation_id
            or manifest.get("operation_id") != operation.operation_id
            or manifest.get("anchor_kind") != operation.request.anchor_kind
            or manifest.get("field_sha256") != frozen.root
            or manifest.get("expected_extrinsic_hash") != reconciliation.extrinsic_hash
            or manifest.get("start_block") != reconciliation.scan_start_block
            or manifest.get("end_block") != reconciliation.scan_end_block
            or not isinstance(manifest_storage_snapshot, Mapping)
            or manifest_storage_snapshot.get("block_number") != reconciliation.finalized_head_block
            or manifest_storage_snapshot.get("block_hash") != reconciliation.finalized_head_hash
            or manifest.get("matched_occurrences")
            != [
                {
                    "block": reconciliation.inclusion_block,
                    "extrinsic_index": matched_scan[0]["extrinsic_index"],
                }
            ]
        ):
            raise BittensorAnchorBindingError("anchor scan sidecar binds another finalization")

        inclusion = await self._verified_round(
            reconciliation.inclusion_block,
            reconciliation.inclusion_block_hash,
        )
        self._require_round_sidecar_binding(
            manifest,
            inclusion,
            require_scanned_attestation=True,
        )
        if (
            reconciliation.inclusion_block == reconciliation.finalized_head_block
            and reconciliation.inclusion_block_hash == reconciliation.finalized_head_hash
        ):
            finalized = inclusion
        else:
            finalized = await self._verified_round(
                reconciliation.finalized_head_block,
                reconciliation.finalized_head_hash,
            )
            self._require_round_sidecar_binding(
                manifest,
                finalized,
                require_scanned_attestation=False,
            )
        evidence_bytes = canonical_json_bytes(
            {
                "schema": ANCHOR_FINALITY_EVIDENCE_SCHEMA,
                "operation_id": operation.operation_id,
                "anchor_kind": operation.request.anchor_kind,
                "root": frozen.root,
                "reconciliation_sha256": receipt.reconciliation_sha256,
                "inclusion": _round_json(inclusion),
                "finalized_head": _round_json(finalized),
            }
        )
        try:
            return VerifiedAnchorFinality(
                anchor_kind=operation.request.anchor_kind,
                root=frozen.root,
                operation_id=operation.operation_id,
                inclusion_block=reconciliation.inclusion_block,
                inclusion_block_hash=reconciliation.inclusion_block_hash,
                inclusion_round=inclusion.quicknet_round,
                finalized_head_block=reconciliation.finalized_head_block,
                finalized_head_hash=reconciliation.finalized_head_hash,
                finalized_round=finalized.quicknet_round,
                evidence_bytes=evidence_bytes,
            )
        except (TypeError, ValueError) as error:
            raise BittensorAnchorBindingError("verified anchor timing is inconsistent") from error

    async def _verified_round(self, block_number: int, block_hash: str) -> VerifiedRoundAtBlock:
        try:
            value = self._rounds.verified_round_at(block_number, block_hash)
            if inspect.isawaitable(value):
                value = await value
        except Exception as error:
            raise BittensorAnchorPortError("verified Quicknet round is unavailable") from error
        if not isinstance(value, VerifiedRoundAtBlock):
            raise BittensorAnchorPortError("verified Quicknet round is unavailable")
        if value.block_number != block_number or value.block_hash != block_hash:
            raise BittensorAnchorBindingError("verified Quicknet round binds another block")
        if value.finality_verifier_sha256 != self._finality_verifier_sha256:
            raise BittensorAnchorBindingError(
                "verified Quicknet round uses another finality verifier"
            )
        return value

    def _require_round_sidecar_binding(
        self,
        manifest: Mapping[str, Any],
        value: VerifiedRoundAtBlock,
        *,
        require_scanned_attestation: bool,
    ) -> None:
        raw_blocks = manifest.get("blocks")
        if isinstance(raw_blocks, (str, bytes, bytearray)) or not isinstance(raw_blocks, Sequence):
            raise BittensorAnchorBindingError("anchor sidecar block vector is invalid")
        matches: list[Mapping[str, Any]] = []
        for raw in raw_blocks:
            if not isinstance(raw, Mapping):
                raise BittensorAnchorBindingError("anchor sidecar block is invalid")
            identity = raw.get("identity")
            if not isinstance(identity, Mapping):
                raise BittensorAnchorBindingError("anchor sidecar identity is invalid")
            snapshot = identity.get("snapshot")
            if not isinstance(snapshot, Mapping):
                raise BittensorAnchorBindingError("anchor sidecar snapshot is invalid")
            if snapshot.get("block_number") == value.block_number:
                matches.append(raw)
        if matches:
            if len(matches) != 1:
                raise BittensorAnchorBindingError(
                    "anchor sidecar has duplicate round block identities"
                )
            identity = matches[0]["identity"]
            snapshot = identity["snapshot"]
            if (
                snapshot.get("block_hash") != value.block_hash
                or snapshot.get("state_root") != value.state_root
                or identity.get("finality_verifier_sha256") != value.finality_verifier_sha256
                or identity.get("finality_evidence_sha256") != value.finality_evidence_sha256
            ):
                raise BittensorAnchorBindingError(
                    "verified Quicknet round disagrees with replay sidecar finality"
                )
            return
        if require_scanned_attestation:
            raise BittensorAnchorBindingError(
                "verified inclusion round lacks its replay sidecar attestation"
            )
        storage = manifest.get("commitment_storage")
        snapshot = storage.get("snapshot") if isinstance(storage, Mapping) else None
        if (
            not isinstance(snapshot, Mapping)
            or snapshot.get("block_number") != value.block_number
            or snapshot.get("block_hash") != value.block_hash
            or snapshot.get("state_root") != value.state_root
        ):
            raise BittensorAnchorBindingError(
                "verified final-head round disagrees with proof-backed storage snapshot"
            )

    async def _persisted_prepared(self, operation_id: str) -> JournalEntry:
        method = self._prepared.prepared_anchor
        try:
            if inspect.iscoroutinefunction(method):
                value = await method(operation_id)
            else:
                value = await asyncio.to_thread(method, operation_id)
                if inspect.isawaitable(value):
                    value = await value
        except BittensorAnchorPortError:
            raise
        except Exception as error:
            raise BittensorAnchorPortError("persisted prepared evidence is unavailable") from error
        if not isinstance(value, JournalEntry):
            raise BittensorAnchorBindingError("persisted prepared evidence is missing or invalid")
        return value

    async def _finalized_snapshot(self) -> Any:
        try:
            snapshot = await self._evidence.finalized_snapshot()
        except Exception as error:
            raise BittensorAnchorPortError("verified finalized head is unavailable") from error
        for name in ("block_number", "block_hash", "parent_hash", "state_root"):
            if not hasattr(snapshot, name):
                raise BittensorAnchorBindingError("verified finalized snapshot is invalid")
        _nonnegative_int(snapshot.block_number, "verified finalized block")
        _chain_hash(snapshot.block_hash, "verified finalized block hash")
        _chain_hash(snapshot.parent_hash, "verified finalized parent hash")
        _chain_hash(snapshot.state_root, "verified finalized state root")
        return snapshot

    async def _pinned_runtime(self, snapshot: Any) -> PinnedRuntimeContext:
        try:
            runtime = await self._evidence.pinned_runtime(snapshot, self._runtime_pin)
        except Exception as error:
            raise BittensorAnchorPortError(
                "allowlisted finalized runtime is unavailable"
            ) from error
        if not isinstance(runtime, PinnedRuntimeContext):
            raise BittensorAnchorBindingError("runtime port did not return PinnedRuntimeContext")
        if runtime.snapshot != snapshot or runtime.pin != self._runtime_pin:
            raise BittensorAnchorBindingError("runtime context binds another finalized snapshot")
        return runtime

    async def _validate_unsigned_envelope(
        self,
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
        finalized_snapshot: Any,
    ) -> None:
        if unsigned.address != self._address or unsigned.address != operation.validator_hotkey:
            raise BittensorAnchorBindingError("prepared anchor names another signer")
        if bytes(unsigned.public_key) != self._public_key:
            raise BittensorAnchorBindingError("prepared anchor has another public key")
        if unsigned.crypto_type != self._crypto_type:
            raise BittensorAnchorBindingError("prepared anchor has another signature scheme")
        if unsigned.tip != 0 or unsigned.tip_asset_id is not None:
            raise BittensorAnchorBindingError("prepared anchor unexpectedly carries a tip")
        if unsigned.metadata_hash is not None:
            raise BittensorAnchorBindingError("raw anchor signer cannot enable metadata-hash mode")
        if (
            unsigned.spec_version != self._runtime_pin.spec_version
            or unsigned.transaction_version != self._runtime_pin.transaction_version
        ):
            raise BittensorAnchorBindingError("prepared anchor runtime is not allowlisted")
        if (
            not isinstance(unsigned.nonce, int)
            or isinstance(unsigned.nonce, bool)
            or unsigned.nonce < 0
            or unsigned.nonce > (1 << 32) - 1
        ):
            raise BittensorAnchorBindingError("prepared anchor nonce is invalid")
        if not isinstance(unsigned.era, Mapping):
            raise BittensorAnchorBindingError("prepared anchor must use a mortal era")
        if unsigned.era.get("period") != self._era_period:
            raise BittensorAnchorBindingError("prepared anchor uses another mortal-era period")
        current = unsigned.era.get("current")
        if (
            isinstance(current, bool)
            or not isinstance(current, int)
            or current < 0
            or current > finalized_snapshot.block_number
        ):
            raise BittensorAnchorBindingError(
                "prepared anchor era is not under the owned finalized head"
            )
        birth, _death = mortal_era_bounds(unsigned)
        try:
            birth_interval = await self._finality.verified_scan_interval(birth, birth)
        except Exception as error:
            raise BittensorAnchorPortError(
                "verified mortal-era birth block is unavailable"
            ) from error
        if (
            not isinstance(birth_interval, VerifiedFinalityScanInterval)
            or len(birth_interval.identities) != 1
            or birth_interval.identities[0].snapshot.block_number != birth
            or birth_interval.identities[0].finality_verifier_sha256
            != self._finality_verifier_sha256
        ):
            raise BittensorAnchorPortError("verified mortal-era birth block is unavailable")
        birth_hash = birth_interval.identities[0].snapshot.block_hash
        if unsigned.era_block_hash != birth_hash:
            raise BittensorAnchorBindingError("prepared anchor era block hash is not canonical")
        if unsigned.genesis_hash != "0x" + self._genesis_hash:
            raise BittensorAnchorBindingError("prepared anchor genesis hash is not Finney")

    def _verify_call_bytes(
        self,
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
        runtime: PinnedRuntimeContext,
    ) -> None:
        if (
            runtime.pin.spec_version != unsigned.spec_version
            or runtime.pin.transaction_version != unsigned.transaction_version
        ):
            raise BittensorAnchorBindingError("prepared call and pinned runtime disagree")
        try:
            expected_bytes = self._compose_expected_call(operation, runtime)
            decoded = runtime._runtime.decode_call(bytes(unsigned.call_data))
        except Exception as error:
            raise BittensorAnchorPortError("pinned-runtime anchor decoding failed") from error
        if bytes(unsigned.call_data) != expected_bytes:
            raise BittensorAnchorBindingError(
                "prepared call bytes are not the exact generated commitment"
            )
        _validate_decoded_call(decoded, operation.request.field.sha256)
        self._verify_signing_payload(unsigned, runtime)

    @staticmethod
    def _verify_signing_payload(
        unsigned: UnsignedExtrinsic,
        runtime: PinnedRuntimeContext,
    ) -> None:
        """Reproduce every byte presented to the private signer.

        ``Substrate.prepare_unsigned`` obtains nonce and era data through the
        provider.  Those values may affect liveness, but they must never let the
        provider substitute arbitrary signing bytes.  The content-pinned local
        runtime independently encodes the extensions and additional-signed
        fields here, including both chain hashes and runtime versions.
        """

        core = runtime._runtime
        genesis = bytes.fromhex(unsigned.genesis_hash[2:])
        era_block = bytes.fromhex(unsigned.era_block_hash[2:])
        try:
            included_in_extrinsic, included_in_signed_data = core.signature_payload_parts(
                era=unsigned.era,
                nonce=unsigned.nonce,
                tip=unsigned.tip,
                tip_asset_id=unsigned.tip_asset_id,
                genesis_hash=genesis,
                era_block_hash=era_block,
                metadata_hash=unsigned.metadata_hash,
            )
            included_in_extrinsic = bytes(included_in_extrinsic)
            included_in_signed_data = bytes(included_in_signed_data)
            runtime_payload = bytes(
                core.signature_payload(
                    bytes(unsigned.call_data),
                    era=unsigned.era,
                    nonce=unsigned.nonce,
                    tip=unsigned.tip,
                    tip_asset_id=unsigned.tip_asset_id,
                    genesis_hash=genesis,
                    era_block_hash=era_block,
                    metadata_hash=unsigned.metadata_hash,
                )
            )
            signed_extensions = list(core.signed_extension_identifiers())
            era_bytes = bytes(core.encode_era(unsigned.era))
            extrinsic_version = core.extrinsic_version
        except Exception as error:
            raise BittensorAnchorPortError(
                "pinned-runtime signing payload reconstruction failed"
            ) from error
        raw_payload = bytes(unsigned.call_data) + included_in_extrinsic + included_in_signed_data
        expected_payload = (
            hashlib.blake2b(raw_payload, digest_size=32).digest()
            if len(raw_payload) > 256
            else raw_payload
        )
        if runtime_payload != expected_payload:
            raise BittensorAnchorBindingError(
                "pinned runtime did not reproduce its signing payload parts"
            )
        if (
            unsigned.included_in_extrinsic != included_in_extrinsic
            or unsigned.included_in_signed_data != included_in_signed_data
            or unsigned.payload != expected_payload
        ):
            raise BittensorAnchorBindingError("SDK signing payload differs from the pinned runtime")
        if (
            isinstance(extrinsic_version, bool)
            or not isinstance(extrinsic_version, int)
            or extrinsic_version <= 0
        ):
            raise BittensorAnchorBindingError("runtime extrinsic version is invalid")
        expected_json: dict[str, Any] = {
            "address": unsigned.address,
            "blockHash": unsigned.era_block_hash,
            "genesisHash": unsigned.genesis_hash,
            "method": "0x" + bytes(unsigned.call_data).hex(),
            "nonce": "0x" + unsigned.nonce.to_bytes(4, "big").hex(),
            "specVersion": "0x" + unsigned.spec_version.to_bytes(4, "big").hex(),
            "tip": "0x" + unsigned.tip.to_bytes(16, "big").hex(),
            "transactionVersion": ("0x" + unsigned.transaction_version.to_bytes(4, "big").hex()),
            "era": "0x" + era_bytes.hex(),
            "version": extrinsic_version,
        }
        if signed_extensions:
            if any(not isinstance(item, str) or not item for item in signed_extensions):
                raise BittensorAnchorBindingError(
                    "runtime signed-extension identifiers are invalid"
                )
            expected_json["signedExtensions"] = signed_extensions
        if "CheckMetadataHash" in signed_extensions:
            expected_json["mode"] = 0
            expected_json["metadataHash"] = None
        if unsigned.payload_json != expected_json:
            raise BittensorAnchorBindingError(
                "SDK signer payload JSON differs from the pinned runtime"
            )

    @staticmethod
    def _compose_expected_call(
        operation: ExtrinsicOperation,
        runtime: PinnedRuntimeContext,
    ) -> bytes:
        params = {
            "netuid": NETUID,
            "info": {"fields": [{"Sha256": bytes.fromhex(operation.request.field.sha256)}]},
        }
        try:
            composed = runtime._runtime.compose_call(
                "Commitments",
                "set_commitment",
                params,
            )
            value = bytes(getattr(composed, "data", composed))
        except Exception as error:
            raise BittensorAnchorPortError("pinned-runtime anchor composition failed") from error
        if not value:
            raise BittensorAnchorBindingError("pinned runtime composed empty anchor bytes")
        return value

    def _validate_signature(self, signature: Any) -> None:
        if not isinstance(signature, bytes) or len(signature) not in {64, 65}:
            raise BittensorAnchorBindingError("anchor signature must contain 64 or 65 bytes")
        if len(signature) == 65 and signature[0] != self._crypto_type:
            raise BittensorAnchorBindingError("anchor signature scheme differs from signer")

    def _validate_scanned_anchor_call(
        self,
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
        evidence: Any,
        call: Any,
        extrinsic_index: int,
    ) -> None:
        expected_call_hash = (
            "0x"
            + hashlib.blake2b(
                bytes(unsigned.call_data),
                digest_size=32,
            ).hexdigest()
        )
        if (
            call.extrinsic_index != extrinsic_index
            or call.call_path
            or call.module != "Commitments"
            or call.function != "set_commitment"
            or call.call_hash != expected_call_hash
            or call.signer_account_id32 != self._public_key
            or call.effective_origin_account_id32 != self._public_key
            or call.recursive_decode_complete is not True
            or call.declared_child_count != 0
            or call.children
        ):
            raise BittensorAnchorBindingError(
                "matched signed bytes do not decode as the exact root anchor call"
            )
        commitments = tuple(
            item for item in evidence.commitment_calls if item.extrinsic_index == extrinsic_index
        )
        if (
            len(commitments) != 1
            or commitments[0].call_hash != expected_call_hash
            or commitments[0].netuid != NETUID
            or commitments[0].field_sha256 != operation.request.field.sha256
        ):
            raise BittensorAnchorBindingError("matched anchor decoded to another commitment field")
        dispatch_events = tuple(
            item.event
            for item in evidence.decoded_block.events
            if item.extrinsic_index == extrinsic_index
            and item.module == "System"
            and item.event in {"ExtrinsicSuccess", "ExtrinsicFailed"}
        )
        expected_event = "ExtrinsicSuccess" if call.successful else "ExtrinsicFailed"
        if dispatch_events != (expected_event,):
            raise BittensorAnchorBindingError(
                "matched anchor lacks one exact proof-backed System dispatch result"
            )
        self._require_operation(operation)

    def _require_operation(self, operation: ExtrinsicOperation) -> None:
        if not isinstance(operation, ExtrinsicOperation):
            raise TypeError("operation must be an ExtrinsicOperation")
        request = operation.request
        expected_operation = {
            "assignment_set": "assignment_anchor",
            "request_set": "request_anchor",
            "response_set": "response_anchor",
            "publisher_pool": "publisher_pool_anchor",
        }.get(request.anchor_kind)
        if (
            request.anchor_kind not in self._allowed_anchor_kinds
            or operation.operation != expected_operation
            or request.call != "Commitments.set_commitment"
            or request.netuid != NETUID
            or request.field.type_ != "Data::Sha256"
            or _HEX32_RE.fullmatch(request.field.sha256) is None
        ):
            raise BittensorAnchorBindingError("operation is not a closed UMI anchor")
        if operation.validator_hotkey != self._address:
            raise BittensorAnchorBindingError("anchor operation names another validator")

    @staticmethod
    def _require_same_operation(
        expected: ExtrinsicOperation,
        actual: ExtrinsicOperation,
    ) -> None:
        if actual != expected or actual.operation_id != expected.operation_id:
            raise BittensorAnchorBindingError("anchor port request binds another operation")


def _validate_decoded_call(value: Any, root: str) -> None:
    if not isinstance(value, Mapping):
        raise BittensorAnchorBindingError("decoded anchor call is not a mapping")
    if value.get("call_module") != "Commitments" or value.get("call_function") != (
        "set_commitment"
    ):
        raise BittensorAnchorBindingError("decoded anchor call has another target")
    args = value.get("call_args")
    if not isinstance(args, Sequence) or isinstance(args, (str, bytes, bytearray)):
        raise BittensorAnchorBindingError("decoded anchor arguments are invalid")
    if len(args) != 2 or any(not isinstance(arg, Mapping) for arg in args):
        raise BittensorAnchorBindingError("decoded anchor argument count is not exact")
    if [arg.get("name") for arg in args] != ["netuid", "info"]:
        raise BittensorAnchorBindingError("decoded anchor argument order is not exact")
    if args[0].get("value") != NETUID or isinstance(args[0].get("value"), bool):
        raise BittensorAnchorBindingError("decoded anchor netuid is not SN78")
    info = args[1].get("value")
    if not isinstance(info, Mapping) or set(info) != {"fields"}:
        raise BittensorAnchorBindingError("decoded anchor commitment info is not exact")
    fields = info.get("fields")
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes, bytearray)):
        raise BittensorAnchorBindingError("decoded anchor fields are invalid")
    if len(fields) != 1 or not isinstance(fields[0], Mapping) or set(fields[0]) != {"Sha256"}:
        raise BittensorAnchorBindingError("decoded anchor must have one Sha256 field")
    if _digest_bytes(fields[0]["Sha256"], "decoded anchor Sha256") != bytes.fromhex(root):
        raise BittensorAnchorBindingError("decoded anchor has another Sha256 field")


def _commitment_binding(value: Any, root: str) -> tuple[bool, int | None]:
    if value is None:
        return False, None
    if not isinstance(value, Mapping):
        raise BittensorAnchorBindingError("proven commitment value is malformed")
    block = value.get("block")
    if isinstance(block, bool) or not isinstance(block, int) or block < 0:
        raise BittensorAnchorBindingError("proven commitment block is malformed")
    info = value.get("info")
    if not isinstance(info, Mapping):
        raise BittensorAnchorBindingError("proven commitment info is malformed")
    fields = info.get("fields")
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes, bytearray)):
        raise BittensorAnchorBindingError("proven commitment fields are malformed")
    if len(fields) != 1 or not isinstance(fields[0], Mapping) or set(fields[0]) != {"Sha256"}:
        return False, block
    try:
        digest = _digest_bytes(fields[0]["Sha256"], "proven commitment Sha256")
    except BittensorAnchorBindingError:
        return False, block
    return digest == bytes.fromhex(root), block


def _material_binding(unsigned: UnsignedExtrinsic, signature: bytes) -> dict[str, str]:
    try:
        record = unsigned.to_dict()
        unsigned_digest = hashlib.sha256(canonical_json_bytes(record)).hexdigest()
    except (TypeError, ValueError) as error:
        raise BittensorAnchorBindingError("unsigned anchor record is not canonical") from error
    return {
        "unsigned_record_sha256": unsigned_digest,
        "payload_sha256": hashlib.sha256(unsigned.payload).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }


def _normalized_signature(signature: bytes, default_version: int) -> tuple[bytes, int]:
    if len(signature) == 65:
        return signature[1:], signature[0]
    return signature, default_version


def _digest_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]{64}", value):
        result = bytes.fromhex(value[2:])
    else:
        raise BittensorAnchorBindingError(f"{label} is not an exact 32-byte value")
    if len(result) != 32:
        raise BittensorAnchorBindingError(f"{label} is not an exact 32-byte value")
    return result


def _json_native(value: Any) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise BittensorAnchorBindingError("evidence mapping has a non-string key")
            result[key] = _json_native(item)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_native(item) for item in value]
    raise BittensorAnchorBindingError("evidence contains a non-JSON value")


def _snapshot_json(snapshot: Any) -> dict[str, JsonValue]:
    return {
        "block_number": snapshot.block_number,
        "block_hash": snapshot.block_hash,
        "parent_hash": snapshot.parent_hash,
        "state_root": snapshot.state_root,
    }


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BittensorAnchorPortError(f"{label} cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BittensorAnchorBindingError(f"{label} must be a real directory")


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BittensorAnchorPortError(
            f"prepared receipt cannot be opened safely: {path.name}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise BittensorAnchorBindingError("prepared receipt is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise BittensorAnchorBindingError("prepared receipt exceeds its byte ceiling")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise BittensorAnchorBindingError("prepared receipt changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _round_json(value: VerifiedRoundAtBlock) -> dict[str, JsonValue]:
    return {
        "block_number": value.block_number,
        "block_hash": value.block_hash,
        "state_root": value.state_root,
        "timestamp_ms": value.timestamp_ms,
        "quicknet_round": value.quicknet_round,
        "finality_verifier_sha256": value.finality_verifier_sha256,
        "finality_evidence_sha256": value.finality_evidence_sha256,
        "evidence": "0x" + value.evidence_bytes.hex(),
        "evidence_sha256": hashlib.sha256(value.evidence_bytes).hexdigest(),
    }


def _verify_scale_header_identity(block: Mapping[str, Any]) -> None:
    encoded_value = block.get("scale_header")
    if (
        not isinstance(encoded_value, str)
        or re.fullmatch(r"0x(?:[0-9a-f]{2})+", encoded_value) is None
    ):
        raise GrandpaQuicknetRoundError("finality_scale_header_invalid")
    encoded = bytes.fromhex(encoded_value[2:])
    if len(encoded) < 98 or len(encoded) > 1024 * 1024:
        raise GrandpaQuicknetRoundError("finality_scale_header_invalid")
    number, compact_size = _decode_compact_u64(encoded[32:])
    roots_offset = 32 + compact_size
    if len(encoded) < roots_offset + 65:
        raise GrandpaQuicknetRoundError("finality_scale_header_invalid")
    expected = {
        "number": number,
        "hash": "0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest(),
        "parent_hash": "0x" + encoded[:32].hex(),
        "state_root": "0x" + encoded[roots_offset : roots_offset + 32].hex(),
        "extrinsics_root": ("0x" + encoded[roots_offset + 32 : roots_offset + 64].hex()),
    }
    if any(block.get(name) != value for name, value in expected.items()):
        raise GrandpaQuicknetRoundError("finality_scale_header_identity_mismatch")


def _decode_compact_u64(value: bytes) -> tuple[int, int]:
    if not value:
        raise GrandpaQuicknetRoundError("finality_scale_header_invalid")
    first = value[0]
    mode = first & 0b11
    if mode == 0:
        return first >> 2, 1
    if mode == 1:
        if len(value) < 2:
            raise GrandpaQuicknetRoundError("finality_scale_header_invalid")
        result = int.from_bytes(value[:2], "little") >> 2
        if result < 1 << 6:
            raise GrandpaQuicknetRoundError("finality_scale_header_noncanonical")
        return result, 2
    if mode == 2:
        if len(value) < 4:
            raise GrandpaQuicknetRoundError("finality_scale_header_invalid")
        result = int.from_bytes(value[:4], "little") >> 2
        if result < 1 << 14:
            raise GrandpaQuicknetRoundError("finality_scale_header_noncanonical")
        return result, 4
    length = (first >> 2) + 4
    if length > 8 or len(value) < length + 1:
        raise GrandpaQuicknetRoundError("finality_scale_header_unsupported")
    encoded = value[1 : length + 1]
    result = int.from_bytes(encoded, "little")
    if result < 1 << 30 or encoded[-1] == 0:
        raise GrandpaQuicknetRoundError("finality_scale_header_noncanonical")
    return result, length + 1


def _chain_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CHAIN_HASH_RE.fullmatch(value) is None:
        raise BittensorAnchorBindingError(f"{label} must be a lowercase 32-byte hash")
    return value


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase 32-byte hexadecimal")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


__all__ = [
    "ANCHOR_FINALITY_EVIDENCE_SCHEMA",
    "ANCHOR_SCAN_SCHEMA",
    "DEFAULT_ERA_PERIOD",
    "GRANDPA_ROUND_EVIDENCE_SCHEMA",
    "MAX_ERA_PERIOD",
    "MAX_ROUND_EVIDENCE_BYTES",
    "NETUID",
    "AnchorScanEvidenceStorePort",
    "BittensorAnchorBindingError",
    "BittensorAnchorPortError",
    "BittensorAnchorPorts",
    "BittensorAnchorSubmissionError",
    "DurablePreparedAnchorReader",
    "FinalizedAnchorEvidencePort",
    "GrandpaQuicknetRoundError",
    "GrandpaQuicknetRoundPort",
    "PersistedPreparedAnchorPort",
    "ProofBoundAnchorScannerPort",
    "VerifiedAnchorFinalityScanPort",
    "VerifiedFinalizedBlockAtHeightPort",
    "VerifiedRoundAtBlock",
    "VerifiedRoundAtBlockPort",
]
