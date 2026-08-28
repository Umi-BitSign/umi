"""Publisher pool certification and deterministic batch/miner selection."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, model_validator
from typing_extensions import Self

from .artifacts import PublicBatchManifest, validate_public_batch_manifest
from .crypto import parse_sealed_response, verify_response_signature
from .encoding import account_id32, raw_sha256, sha256_domain, u32be, u64be
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import (
    StrictProtocolModel,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)

POOL_MANIFEST_SCHEMA = "umi-pool-manifest/1"
AVAILABILITY_SCHEMA = "umi-availability/1"

_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{128}$")


def _hex32(value: str) -> str:
    if _HEX_32_RE.fullmatch(value) is None:
        raise ValueError("value must be 32 bytes encoded as lowercase hexadecimal")
    return value


def _opaque_id(value: str) -> str:
    if len(base64url_decode(value)) != 16:
        raise ValueError("opaque identifier must encode exactly 16 bytes")
    return value


def _signature(value: str) -> str:
    if _SIGNATURE_RE.fullmatch(value) is None:
        raise ValueError("signature must be 64 bytes encoded as 0x-prefixed lowercase hex")
    return value


Hex32 = Annotated[str, AfterValidator(_hex32)]
OpaqueId = Annotated[str, AfterValidator(_opaque_id)]
SignatureHex = Annotated[str, AfterValidator(_signature)]


class PoolBatchEntry(StrictProtocolModel):
    batch_id: OpaqueId
    batch_commitment: Hex32
    public_manifest_sha256: Hex32
    ciphertext_sha256: Hex32
    reveal_round: Annotated[int, Field(gt=0)]


class AvailabilitySignature(StrictProtocolModel):
    validator_hotkey: Annotated[str, Field(min_length=1)]
    scheme: Literal["sr25519", "ed25519"]
    signature: SignatureHex


class AvailabilityCertificate(StrictProtocolModel):
    schema_: Literal[AVAILABILITY_SCHEMA] = Field(alias="schema")
    availability_set_root: Hex32
    qualified_pool_leaves: Annotated[list[Hex32], Field(min_length=1)]
    signatures: Annotated[list[AvailabilitySignature], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        leaf_bytes = [bytes.fromhex(value) for value in self.qualified_pool_leaves]
        if len(set(leaf_bytes)) != len(leaf_bytes) or leaf_bytes != sorted(leaf_bytes):
            raise ValueError("qualified pool leaves must be unique and sorted by raw bytes")
        accounts = [account_id32(item.validator_hotkey) for item in self.signatures]
        if len(set(accounts)) != len(accounts) or accounts != sorted(accounts):
            raise ValueError(
                "availability signatures must be unique and sorted by validator account"
            )
        return self


class PoolBody(StrictProtocolModel):
    schema_: Literal[POOL_MANIFEST_SCHEMA] = Field(alias="schema")
    window_id: Hex32
    publisher_hotkey: Annotated[str, Field(min_length=1)]
    scoring_policy_hash: Hex32
    batches: Annotated[list[PoolBatchEntry], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_batches(self) -> Self:
        batch_ids = [base64url_decode(item.batch_id) for item in self.batches]
        commitments = [item.batch_commitment for item in self.batches]
        if batch_ids != sorted(batch_ids):
            raise ValueError("pool batches must be ordered by decoded batch_id")
        if len(set(batch_ids)) != len(batch_ids):
            raise ValueError("pool batch IDs must be unique")
        if len(set(commitments)) != len(commitments):
            raise ValueError("pool batch commitments must be unique")
        return self


class PoolManifest(PoolBody):
    availability_certificate: AvailabilityCertificate

    def body(self) -> PoolBody:
        return PoolBody.model_validate(
            self.model_dump(mode="json", by_alias=True, exclude={"availability_certificate"})
        )


def parse_pool_body_bytes(raw: bytes, *, policy: ScoringPolicy) -> PoolBody:
    """Parse one canonical pool body only after enforcing its raw-byte ceiling."""

    return _parse_pool_bytes(raw, model=PoolBody, policy=policy)


def parse_pool_manifest_bytes(raw: bytes, *, policy: ScoringPolicy) -> PoolManifest:
    """Parse one canonical final pool manifest after enforcing its raw-byte ceiling."""

    return _parse_pool_bytes(raw, model=PoolManifest, policy=policy)


def _parse_pool_bytes(
    raw: bytes,
    *,
    model: type[PoolBody] | type[PoolManifest],
    policy: ScoringPolicy,
) -> PoolBody | PoolManifest:
    if not isinstance(raw, bytes):
        raise TypeError("pool manifest input must be exact bytes")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if len(raw) > policy.limits.maximum_manifest_bytes:
        raise ValueError("pool manifest exceeds the policy byte ceiling")
    parsed = model.model_validate_json(raw)
    if canonical_json_bytes(parsed) != raw:
        raise ValueError("pool manifest is not RFC 8785 canonical JSON")
    expected_policy_hash = scoring_policy_hash(policy)
    if parsed.scoring_policy_hash != expected_policy_hash:
        raise ValueError("pool manifest names a different scoring policy")
    registered_publishers = {
        account_id32(entry.publisher_hotkey) for entry in policy.publisher_registry
    }
    if account_id32(parsed.publisher_hotkey) not in registered_publishers:
        raise ValueError("pool manifest publisher is absent from the policy registry")
    return parsed


def batch_commitment(public_manifest: Any, ciphertext: bytes, reveal_round: int) -> str:
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    return sha256_domain(
        b"umi-batch-v1\0",
        canonical_json_bytes(public_manifest),
        hashlib.sha256(ciphertext).digest(),
        u64be(reveal_round),
    ).hex()


def availability_leaf(pool_body: PoolBody) -> str:
    return sha256_domain(
        b"umi-availability-leaf-v1\0",
        account_id32(pool_body.publisher_hotkey),
        hashlib.sha256(canonical_json_bytes(pool_body)).digest(),
    ).hex()


def availability_set_root(leaves: Sequence[str | bytes]) -> str:
    raw = [raw_sha256(value, field="availability leaf") for value in leaves]
    if not raw:
        raise ValueError("availability set must not be empty")
    if len(set(raw)) != len(raw):
        raise ValueError("availability leaves must be unique")
    return sha256_domain(
        b"umi-availability-set-v1\0",
        u32be(len(raw)),
        b"".join(sorted(raw)),
    ).hex()


def availability_digest(window_id: str | bytes, set_root: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-availability-v1\0",
        raw_sha256(window_id, field="window ID"),
        raw_sha256(set_root, field="availability set root"),
    )


def verify_availability_certificate(
    certificate: AvailabilityCertificate,
    pool_bodies: Sequence[PoolBody],
    *,
    active_validator_hotkeys: Collection[str],
    policy: ScoringPolicy,
) -> None:
    """Verify one complete availability set and its active-validator quorum."""

    if not isinstance(certificate, AvailabilityCertificate):
        raise TypeError("certificate must be an AvailabilityCertificate")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    active_by_account = {account_id32(value): value for value in active_validator_hotkeys}
    if len(active_by_account) != len(active_validator_hotkeys):
        raise ValueError("active validator registry contains duplicate accounts")
    registered_validators = {
        account_id32(entry.validator_hotkey) for entry in policy.validator_registry
    }
    if not set(active_by_account).issubset(registered_validators):
        raise ValueError("active validator is absent from the policy registry")
    validator_count = len(active_by_account)
    if validator_count < 4:
        raise ValueError("fewer than four active validators makes the window void")
    publishers = [account_id32(body.publisher_hotkey) for body in pool_bodies]
    if len(set(publishers)) != len(publishers):
        raise ValueError("availability set contains more than one pool per publisher")
    if not pool_bodies:
        raise ValueError("availability set contains no pool bodies")
    expected_policy_hash = scoring_policy_hash(policy)
    registered_publishers = {
        account_id32(entry.publisher_hotkey) for entry in policy.publisher_registry
    }
    for body in pool_bodies:
        if not isinstance(body, PoolBody):
            raise TypeError("pool bodies must be strict PoolBody objects")
        if body.scoring_policy_hash != expected_policy_hash:
            raise ValueError("availability pool body names a different scoring policy")
        if account_id32(body.publisher_hotkey) not in registered_publishers:
            raise ValueError("availability pool publisher is absent from the policy registry")
        if len(canonical_json_bytes(body)) > policy.limits.maximum_manifest_bytes:
            raise ValueError("pool body exceeds the policy byte ceiling")
        final_manifest = PoolManifest.model_validate(
            {
                **body.model_dump(mode="json", by_alias=True),
                "availability_certificate": certificate.model_dump(mode="json", by_alias=True),
            }
        )
        if len(canonical_json_bytes(final_manifest)) > policy.limits.maximum_manifest_bytes:
            raise ValueError("final pool manifest exceeds the policy byte ceiling")
    window_ids = {body.window_id for body in pool_bodies}
    policy_hashes = {body.scoring_policy_hash for body in pool_bodies}
    if len(window_ids) != 1 or len(policy_hashes) != 1:
        raise ValueError("availability pool bodies disagree on window or policy")

    leaves = tuple(availability_leaf(body) for body in pool_bodies)
    expected_leaves = sorted(leaves, key=bytes.fromhex)
    if certificate.qualified_pool_leaves != expected_leaves:
        raise ValueError("certificate does not name the complete qualified pool set")
    expected_root = availability_set_root(leaves)
    if certificate.availability_set_root != expected_root:
        raise ValueError("availability set root does not reproduce")

    digest = availability_digest(next(iter(window_ids)), expected_root)
    valid_signers: set[bytes] = set()
    for record in certificate.signatures:
        account = account_id32(record.validator_hotkey)
        if account not in active_by_account:
            raise ValueError("availability signature is not from an active validator")
        if not verify_response_signature(
            digest,
            hotkey_ss58=record.validator_hotkey,
            scheme=record.scheme,
            signature=record.signature,
        ):
            raise ValueError("availability signature does not verify")
        valid_signers.add(account)
    quorum = max(3, (2 * validator_count) // 3 + 1)
    if len(valid_signers) < quorum:
        raise ValueError("availability certificate does not meet quorum")


def verify_pool_artifacts(
    body: PoolBody,
    *,
    public_manifests: Mapping[str, PublicBatchManifest],
    ciphertexts: Mapping[str, bytes],
    policy: ScoringPolicy,
) -> None:
    """Strictly bind every pool entry, public manifest, and portable timelock."""

    if not isinstance(body, PoolBody):
        raise TypeError("body must be a PoolBody")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if len(canonical_json_bytes(body)) > policy.limits.maximum_manifest_bytes:
        raise ValueError("pool body exceeds the policy byte ceiling")
    expected_policy_hash = scoring_policy_hash(policy)
    if body.scoring_policy_hash != expected_policy_hash:
        raise ValueError("pool body names a different scoring policy")
    registered_publishers = {
        account_id32(entry.publisher_hotkey) for entry in policy.publisher_registry
    }
    if account_id32(body.publisher_hotkey) not in registered_publishers:
        raise ValueError("pool body publisher is not in the active policy registry")
    if len(body.batches) > policy.limits.max_candidate_batches_per_publisher:
        raise ValueError("pool body exceeds the per-publisher candidate limit")

    expected_ids = {entry.batch_id for entry in body.batches}
    if set(public_manifests) != expected_ids or set(ciphertexts) != expected_ids:
        raise ValueError("pool artifacts are not a bijection with batch entries")
    for entry in body.batches:
        public_manifest = public_manifests[entry.batch_id]
        ciphertext = ciphertexts[entry.batch_id]
        if not isinstance(public_manifest, PublicBatchManifest):
            raise TypeError("public manifests must be strict PublicBatchManifest objects")
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertexts must be exact bytes")
        if len(ciphertext) > policy.limits.maximum_ground_truth_envelope_bytes:
            raise ValueError("portable ground-truth envelope exceeds the policy byte ceiling")
        if len(canonical_json_bytes(public_manifest)) > policy.limits.maximum_manifest_bytes:
            raise ValueError("public batch manifest exceeds the policy byte ceiling")
        validate_public_batch_manifest(public_manifest, policy)
        if public_manifest.batch_id != entry.batch_id:
            raise ValueError("public manifest batch ID does not match its pool entry")
        if public_manifest.window_id != body.window_id:
            raise ValueError("public manifest window ID does not match its pool body")
        if account_id32(public_manifest.publisher_hotkey) != account_id32(body.publisher_hotkey):
            raise ValueError("public manifest publisher does not match its pool body")
        if public_manifest.scoring_policy_hash != body.scoring_policy_hash:
            raise ValueError("public manifest policy hash does not match its pool body")
        if public_manifest.reveal_round != entry.reveal_round:
            raise ValueError("public manifest reveal round does not match its pool entry")
        if hashlib.sha256(canonical_json_bytes(public_manifest)).hexdigest() != (
            entry.public_manifest_sha256
        ):
            raise ValueError("public manifest hash does not match its pool entry")
        ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
        if ciphertext_sha256 != entry.ciphertext_sha256:
            raise ValueError("ciphertext hash does not match its pool entry")
        if public_manifest.ciphertext_sha256 != ciphertext_sha256:
            raise ValueError("public manifest ciphertext hash does not match the artifact")
        parse_sealed_response(
            base64url_encode(ciphertext),
            reveal_round=entry.reveal_round,
            sha256_hex=ciphertext_sha256,
        )
        if batch_commitment(public_manifest, ciphertext, entry.reveal_round) != (
            entry.batch_commitment
        ):
            raise ValueError("batch commitment does not reproduce")


@dataclass(frozen=True)
class CandidateBatch:
    publisher_hotkey: str | bytes
    control_group_id: str | bytes
    batch_id: str
    batch_commitment: str | bytes

    def __post_init__(self) -> None:
        account_id32(self.publisher_hotkey)
        raw_sha256(self.control_group_id, field="control group ID")
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("batch ID must encode exactly 16 bytes")
        raw_sha256(self.batch_commitment, field="batch commitment")

    @property
    def pool_leaf(self) -> bytes:
        return sha256_domain(
            b"umi-pool-leaf-v1\0",
            account_id32(self.publisher_hotkey),
            raw_sha256(self.batch_commitment, field="batch commitment"),
        )


def candidate_pool_root(candidates: Sequence[CandidateBatch]) -> bytes:
    if not candidates:
        raise ValueError("candidate pool must not be empty")
    leaves = [candidate.pool_leaf for candidate in candidates]
    if len(set(leaves)) != len(leaves):
        raise ValueError("candidate pool contains a duplicate pool leaf")
    return sha256_domain(
        b"umi-pool-root-v1\0",
        u32be(len(leaves)),
        b"".join(sorted(leaves)),
    )


def selection_seed(drand_signature: bytes, pool_root: str | bytes) -> bytes:
    if not isinstance(drand_signature, bytes) or len(drand_signature) != 48:
        raise ValueError("verified Quicknet signature must be exactly 48 bytes")
    return sha256_domain(
        b"umi-select-v2\0",
        drand_signature,
        raw_sha256(pool_root, field="candidate pool root"),
    )


def batch_rank(seed: str | bytes, candidate: CandidateBatch) -> bytes:
    return sha256_domain(
        b"umi-batch-rank-v1\0",
        raw_sha256(seed, field="selection seed"),
        candidate.pool_leaf,
    )


def select_batches(
    candidates: Sequence[CandidateBatch],
    seed: str | bytes,
    *,
    count: int = 2,
) -> tuple[CandidateBatch, ...]:
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise ValueError("selected batch count must be a positive integer")
    if len({candidate.pool_leaf for candidate in candidates}) != len(candidates):
        raise ValueError("candidate pool contains duplicate leaves")
    ranked = sorted(candidates, key=lambda item: (batch_rank(seed, item), item.pool_leaf))
    selected: list[CandidateBatch] = []
    groups: set[bytes] = set()
    for candidate in ranked:
        group = raw_sha256(candidate.control_group_id, field="control group ID")
        if group in groups:
            continue
        selected.append(candidate)
        groups.add(group)
        if len(selected) == count:
            return tuple(selected)
    raise ValueError("candidate pool has too few distinct control groups")


@dataclass(frozen=True)
class MinerCandidate:
    hotkey: str | bytes
    root: str | bytes
    assigned_observation_count: int

    def __post_init__(self) -> None:
        account_id32(self.hotkey)
        account_id32(self.root)
        if (
            isinstance(self.assigned_observation_count, bool)
            or not isinstance(self.assigned_observation_count, int)
            or self.assigned_observation_count < 0
        ):
            raise ValueError("assigned observation count must be a non-negative integer")


def miner_rank(
    seed: str | bytes,
    validator_hotkey: str | bytes,
    miner_hotkey: str | bytes,
) -> bytes:
    return sha256_domain(
        b"umi-miner-rank-v1\0",
        raw_sha256(seed, field="selection seed"),
        account_id32(validator_hotkey),
        account_id32(miner_hotkey),
    )


def select_miner_panel(
    candidates: Sequence[MinerCandidate],
    seed: str | bytes,
    *,
    validator_hotkey: str | bytes,
    panel_size: int,
) -> tuple[MinerCandidate, ...]:
    if isinstance(panel_size, bool) or not isinstance(panel_size, int) or panel_size <= 0:
        raise ValueError("panel size must be a positive integer")
    accounts = [account_id32(item.hotkey) for item in candidates]
    if len(set(accounts)) != len(accounts):
        raise ValueError("candidate miner set contains duplicate hotkeys")
    target_count = min(panel_size, len(candidates))
    if target_count == 0:
        return ()
    ranks = {
        account_id32(item.hotkey): miner_rank(seed, validator_hotkey, item.hotkey)
        for item in candidates
    }
    exploration_count = (target_count + 4) // 5
    exploration = sorted(
        candidates,
        key=lambda item: (
            item.assigned_observation_count,
            ranks[account_id32(item.hotkey)],
        ),
    )[:exploration_count]
    selected_accounts = {account_id32(item.hotkey) for item in exploration}
    ranked_remainder = sorted(
        (item for item in candidates if account_id32(item.hotkey) not in selected_accounts),
        key=lambda item: ranks[account_id32(item.hotkey)],
    )
    return tuple(exploration + ranked_remainder[: target_count - len(exploration)])


__all__ = [
    "AVAILABILITY_SCHEMA",
    "POOL_MANIFEST_SCHEMA",
    "AvailabilityCertificate",
    "AvailabilitySignature",
    "CandidateBatch",
    "MinerCandidate",
    "PoolBatchEntry",
    "PoolBody",
    "PoolManifest",
    "availability_digest",
    "availability_leaf",
    "availability_set_root",
    "batch_commitment",
    "batch_rank",
    "candidate_pool_root",
    "miner_rank",
    "parse_pool_body_bytes",
    "parse_pool_manifest_bytes",
    "select_batches",
    "select_miner_panel",
    "selection_seed",
    "verify_availability_certificate",
    "verify_pool_artifacts",
]
