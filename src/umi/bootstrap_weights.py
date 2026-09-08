"""Pure contracts for the temporary public-pilot service-weight bootstrap.

This module does not submit weights and is not imported by the live shadow
validator.  It freezes the narrow input to a later, separately reviewed chain
effect: miner opt-ins, recent chain-health observations, and the exact equal
u16 row derived from them.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .public_pilot_evidence import validate_public_endpoint_origin

BOOTSTRAP_WEIGHT_POLICY_SCHEMA = "umi-bootstrap-weight-policy/1"
BOOTSTRAP_OPT_IN_SCHEMA = "umi-bootstrap-opt-in/1"
BOOTSTRAP_ELIGIBILITY_MANIFEST_SCHEMA = "umi-bootstrap-eligibility-manifest/1"
BOOTSTRAP_COORDINATOR_SIGNATURE_SCHEMA = "umi-bootstrap-eligibility-manifest-signature/1"

BOOTSTRAP_POLICY_HASH_DOMAIN = b"umi-bootstrap-weight-policy-v1\0"
BOOTSTRAP_OPT_IN_SIGNATURE_DOMAIN = b"umi-bootstrap-opt-in-v1\0"
BOOTSTRAP_MANIFEST_SIGNATURE_DOMAIN = b"umi-bootstrap-eligibility-manifest-v1\0"

U16_MAX = 65_535
MAX_BOOTSTRAP_ENTRIES = 256
BOOTSTRAP_DURATION_BLOCKS = 50_400
BOOTSTRAP_TERMINAL_CLEARANCE_BLOCKS = 1_440
_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
_MAX_U64 = (1 << 64) - 1
_SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{128}$")


def _validate_hotkey(value: str, *, field: str) -> str:
    try:
        account_id32(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a valid AccountId32 SS58 address") from error
    return value


def _validate_public_evidence_origin(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("public_evidence_origin contains a control character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("public_evidence_origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or not parsed.hostname.isascii()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or value.endswith("/")
        or value != f"{parsed.scheme}://{parsed.netloc}"
        or (port is not None and not 1 <= port <= U16_MAX)
    ):
        raise ValueError("public_evidence_origin must be one normalized HTTPS origin")
    return value


class BootstrapWeightPolicy(StrictProtocolModel):
    """Published bounds for one temporary service-weight interval."""

    schema_: Literal[BOOTSTRAP_WEIGHT_POLICY_SCHEMA] = Field(alias="schema")
    network: Literal["finney"] = "finney"
    netuid: Literal[78] = 78
    mechanism_id: Literal[0] = 0
    translation_weights_active: Literal[False] = False
    service_weights_active: Literal[True] = True
    campaign_id: Hex32
    public_evidence_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    weights_version_key: Literal[1]
    published_at_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    activation_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    commit_stop_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    hard_sunset_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    health_ttl_blocks: Annotated[int, Field(ge=1, le=_MAX_JSON_SAFE_INTEGER)]
    manifest_ttl_blocks: Annotated[int, Field(ge=1, le=_MAX_JSON_SAFE_INTEGER)]

    @field_validator("coordinator_hotkey")
    @classmethod
    def validate_coordinator_hotkey(cls, value: str) -> str:
        return _validate_hotkey(value, field="coordinator_hotkey")

    @field_validator("public_evidence_origin")
    @classmethod
    def validate_public_evidence_origin(cls, value: str) -> str:
        return _validate_public_evidence_origin(value)

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if not (
            self.published_at_block
            < self.activation_block
            < self.commit_stop_block
            < self.hard_sunset_block
        ):
            raise ValueError(
                "policy blocks must satisfy published_at_block < activation_block "
                "< commit_stop_block < hard_sunset_block"
            )
        if self.hard_sunset_block - self.activation_block != BOOTSTRAP_DURATION_BLOCKS:
            raise ValueError("bootstrap service interval must be exactly 50,400 blocks")
        if self.hard_sunset_block - self.commit_stop_block != BOOTSTRAP_TERMINAL_CLEARANCE_BLOCKS:
            raise ValueError("bootstrap terminal clearance must be exactly 1,440 blocks")
        if self.health_ttl_blocks >= self.hard_sunset_block - self.published_at_block:
            raise ValueError("health_ttl_blocks must be shorter than the published policy interval")
        if self.manifest_ttl_blocks >= self.hard_sunset_block - self.activation_block:
            raise ValueError("manifest_ttl_blocks must be shorter than the active policy interval")
        return self


class BootstrapOptIn(StrictProtocolModel):
    """A miner-hotkey signature consenting to one pilot under one policy."""

    schema_: Literal[BOOTSTRAP_OPT_IN_SCHEMA] = Field(alias="schema")
    policy_sha256: Hex32
    pilot_id: Hex32
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signed_at_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE.pattern)]

    @field_validator("miner_hotkey")
    @classmethod
    def validate_miner_hotkey(cls, value: str) -> str:
        return _validate_hotkey(value, field="miner_hotkey")


class BootstrapEligibilityEntry(StrictProtocolModel):
    """One binary-utility destination and the evidence bindings behind it."""

    pilot_id: Hex32
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    uid: Annotated[int, Field(ge=0, le=U16_MAX)]
    origin: Annotated[str, Field(min_length=1, max_length=128)]
    pilot_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    health_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    utility: Literal[1] = 1
    opt_in: BootstrapOptIn

    @field_validator("miner_hotkey")
    @classmethod
    def validate_miner_hotkey(cls, value: str) -> str:
        return _validate_hotkey(value, field="miner_hotkey")

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return validate_public_endpoint_origin(value)

    @model_validator(mode="after")
    def validate_local_bindings(self) -> Self:
        if self.pilot_id != self.opt_in.pilot_id:
            raise ValueError("eligibility entry pilot_id does not match its opt-in")
        if account_id32(self.miner_hotkey) != account_id32(self.opt_in.miner_hotkey):
            raise ValueError("eligibility entry miner_hotkey does not match its opt-in")
        if self.pilot_block > self.opt_in.signed_at_block:
            raise ValueError("miner opt-in must not predate the bound public pilot")
        if self.opt_in.signed_at_block > self.health_block:
            raise ValueError("health observation must not predate the miner opt-in")
        return self


class BootstrapQuantizedWeight(StrictProtocolModel):
    """One chain-ready destination produced by max-upscaling equal utilities."""

    uid: Annotated[int, Field(ge=0, le=U16_MAX)]
    value: Literal[U16_MAX] = U16_MAX


class BootstrapEligibilityManifest(StrictProtocolModel):
    """Frozen, deterministic eligibility and weight-build input."""

    schema_: Literal[BOOTSTRAP_ELIGIBILITY_MANIFEST_SCHEMA] = Field(alias="schema")
    policy: BootstrapWeightPolicy
    policy_sha256: Hex32
    frozen_at_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    frozen_at_block_hash: BlockHash
    entries: Annotated[
        list[BootstrapEligibilityEntry], Field(min_length=1, max_length=MAX_BOOTSTRAP_ENTRIES)
    ]
    quantized_row: Annotated[
        list[BootstrapQuantizedWeight], Field(min_length=1, max_length=MAX_BOOTSTRAP_ENTRIES)
    ]

    @model_validator(mode="after")
    def validate_frozen_manifest(self) -> Self:
        _validate_manifest(self, current_block=self.frozen_at_block)
        return self


class SignedBootstrapEligibilityManifest(StrictProtocolModel):
    """Coordinator signature wrapper for one exact frozen manifest."""

    schema_: Literal[BOOTSTRAP_COORDINATOR_SIGNATURE_SCHEMA] = Field(alias="schema")
    manifest: BootstrapEligibilityManifest
    manifest_sha256: Hex32
    manifest_digest: Hex32
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE.pattern)]

    @field_validator("coordinator_hotkey")
    @classmethod
    def validate_coordinator_hotkey(cls, value: str) -> str:
        return _validate_hotkey(value, field="coordinator_hotkey")


# A descriptive alias for callers that treat the outer object as a signature record.
BootstrapCoordinatorSignature = SignedBootstrapEligibilityManifest


def bootstrap_policy_hash(policy: BootstrapWeightPolicy) -> str:
    """Return the domain-separated identity of the published policy."""

    if not isinstance(policy, BootstrapWeightPolicy):
        raise TypeError("policy must be a BootstrapWeightPolicy")
    return hashlib.sha256(BOOTSTRAP_POLICY_HASH_DOMAIN + canonical_json_bytes(policy)).hexdigest()


bootstrap_weight_policy_hash = bootstrap_policy_hash


def _opt_in_unsigned(opt_in: BootstrapOptIn) -> dict[str, Any]:
    return {
        "schema": BOOTSTRAP_OPT_IN_SCHEMA,
        "policy_sha256": opt_in.policy_sha256,
        "pilot_id": opt_in.pilot_id,
        "miner_hotkey": opt_in.miner_hotkey,
        "signed_at_block": opt_in.signed_at_block,
    }


def bootstrap_opt_in_digest(opt_in: BootstrapOptIn) -> bytes:
    """Return the domain-separated digest authenticated by the miner."""

    if not isinstance(opt_in, BootstrapOptIn):
        raise TypeError("opt_in must be a BootstrapOptIn")
    return hashlib.sha256(
        BOOTSTRAP_OPT_IN_SIGNATURE_DOMAIN + canonical_json_bytes(_opt_in_unsigned(opt_in))
    ).digest()


def sign_bootstrap_opt_in(
    policy: BootstrapWeightPolicy,
    *,
    pilot_id: str,
    wallet: Any,
    signed_at_block: int,
) -> BootstrapOptIn:
    """Create and verify one miner opt-in after policy publication."""

    hotkey, expected_scheme = _wallet_identity(wallet)
    provisional = BootstrapOptIn(
        schema=BOOTSTRAP_OPT_IN_SCHEMA,
        policy_sha256=bootstrap_policy_hash(policy),
        pilot_id=pilot_id,
        miner_hotkey=hotkey,
        signed_at_block=signed_at_block,
        signature_scheme=expected_scheme,
        signature="0x" + "00" * 64,
    )
    _validate_opt_in_bounds(provisional, policy)
    scheme, signature = sign_response_digest(wallet, bootstrap_opt_in_digest(provisional))
    if scheme != expected_scheme:
        raise ValueError("wallet signature scheme changed while signing bootstrap opt-in")
    opt_in = provisional.model_copy(update={"signature_scheme": scheme, "signature": signature})
    return verify_bootstrap_opt_in(opt_in, policy=policy)


def verify_bootstrap_opt_in(
    opt_in: BootstrapOptIn,
    *,
    policy: BootstrapWeightPolicy,
) -> BootstrapOptIn:
    """Verify policy binding, block bounds, and the miner-hotkey signature."""

    if not isinstance(opt_in, BootstrapOptIn):
        raise TypeError("opt_in must be a BootstrapOptIn")
    if not isinstance(policy, BootstrapWeightPolicy):
        raise TypeError("policy must be a BootstrapWeightPolicy")
    _validate_opt_in_bounds(opt_in, policy)
    if not verify_response_signature(
        bootstrap_opt_in_digest(opt_in),
        hotkey_ss58=opt_in.miner_hotkey,
        scheme=opt_in.signature_scheme,
        signature=opt_in.signature,
    ):
        raise ValueError("bootstrap opt-in signature is invalid")
    return opt_in


def build_bootstrap_eligibility_manifest(
    policy: BootstrapWeightPolicy,
    entries: list[BootstrapEligibilityEntry] | tuple[BootstrapEligibilityEntry, ...],
    *,
    frozen_at_block: int,
    frozen_at_block_hash: str,
) -> BootstrapEligibilityManifest:
    """Validate entries and freeze the exact equal service-weight row."""

    if not isinstance(policy, BootstrapWeightPolicy):
        raise TypeError("policy must be a BootstrapWeightPolicy")
    if not isinstance(entries, (list, tuple)):
        raise TypeError("entries must be a list or tuple of BootstrapEligibilityEntry values")
    ordered = sorted(entries, key=lambda item: account_id32(item.miner_hotkey))
    row = [
        BootstrapQuantizedWeight(uid=entry.uid, value=U16_MAX)
        for entry in sorted(ordered, key=lambda item: item.uid)
    ]
    return BootstrapEligibilityManifest(
        schema=BOOTSTRAP_ELIGIBILITY_MANIFEST_SCHEMA,
        policy=policy,
        policy_sha256=bootstrap_policy_hash(policy),
        frozen_at_block=frozen_at_block,
        frozen_at_block_hash=frozen_at_block_hash,
        entries=ordered,
        quantized_row=row,
    )


def bootstrap_manifest_digest(manifest: BootstrapEligibilityManifest) -> bytes:
    """Return the domain-separated coordinator-signature digest."""

    if not isinstance(manifest, BootstrapEligibilityManifest):
        raise TypeError("manifest must be a BootstrapEligibilityManifest")
    return hashlib.sha256(
        BOOTSTRAP_MANIFEST_SIGNATURE_DOMAIN + canonical_json_bytes(manifest)
    ).digest()


bootstrap_eligibility_manifest_digest = bootstrap_manifest_digest


def sign_bootstrap_eligibility_manifest(
    manifest: BootstrapEligibilityManifest,
    *,
    wallet: Any,
) -> SignedBootstrapEligibilityManifest:
    """Sign one frozen manifest with the policy-pinned coordinator hotkey."""

    if not isinstance(manifest, BootstrapEligibilityManifest):
        raise TypeError("manifest must be a BootstrapEligibilityManifest")
    hotkey, expected_scheme = _wallet_identity(wallet)
    if account_id32(hotkey) != account_id32(manifest.policy.coordinator_hotkey):
        raise ValueError("wallet hotkey does not match the bootstrap coordinator")
    manifest_bytes = canonical_json_bytes(manifest)
    digest = bootstrap_manifest_digest(manifest)
    scheme, signature = sign_response_digest(wallet, digest)
    if scheme != expected_scheme:
        raise ValueError("wallet signature scheme changed while signing bootstrap manifest")
    signed = SignedBootstrapEligibilityManifest(
        schema=BOOTSTRAP_COORDINATOR_SIGNATURE_SCHEMA,
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        manifest_digest=digest.hex(),
        coordinator_hotkey=hotkey,
        signature_scheme=scheme,
        signature=signature,
    )
    return verify_signed_bootstrap_eligibility_manifest(signed)


def verify_signed_bootstrap_eligibility_manifest(
    signed: SignedBootstrapEligibilityManifest,
    *,
    expected_coordinator_hotkey: str | None = None,
    current_block: int | None = None,
) -> SignedBootstrapEligibilityManifest:
    """Verify the wrapper and optionally enforce freshness at submission block."""

    if not isinstance(signed, SignedBootstrapEligibilityManifest):
        raise TypeError("signed must be a SignedBootstrapEligibilityManifest")
    manifest = signed.manifest
    manifest_bytes = canonical_json_bytes(manifest)
    digest = bootstrap_manifest_digest(manifest)
    if not hmac.compare_digest(signed.manifest_sha256, hashlib.sha256(manifest_bytes).hexdigest()):
        raise ValueError("bootstrap manifest SHA-256 is invalid")
    if not hmac.compare_digest(signed.manifest_digest, digest.hex()):
        raise ValueError("bootstrap manifest domain-separated digest is invalid")
    if account_id32(signed.coordinator_hotkey) != account_id32(manifest.policy.coordinator_hotkey):
        raise ValueError("bootstrap manifest signer is not the policy coordinator")
    if expected_coordinator_hotkey is not None and account_id32(
        signed.coordinator_hotkey
    ) != account_id32(expected_coordinator_hotkey):
        raise ValueError("bootstrap manifest signer does not match the expected coordinator")
    if not verify_response_signature(
        digest,
        hotkey_ss58=signed.coordinator_hotkey,
        scheme=signed.signature_scheme,
        signature=signed.signature,
    ):
        raise ValueError("bootstrap manifest coordinator signature is invalid")
    _validate_manifest(
        manifest,
        current_block=manifest.frozen_at_block if current_block is None else current_block,
    )
    return signed


def _validate_opt_in_bounds(opt_in: BootstrapOptIn, policy: BootstrapWeightPolicy) -> None:
    if not hmac.compare_digest(opt_in.policy_sha256, bootstrap_policy_hash(policy)):
        raise ValueError("bootstrap opt-in binds another policy")
    if not policy.published_at_block < opt_in.signed_at_block < policy.commit_stop_block:
        raise ValueError("bootstrap opt-in was not signed inside the published policy interval")


def _validate_manifest(
    manifest: BootstrapEligibilityManifest,
    *,
    current_block: int,
) -> None:
    if (
        isinstance(current_block, bool)
        or not isinstance(current_block, int)
        or not 0 <= current_block <= _MAX_JSON_SAFE_INTEGER
    ):
        raise ValueError("current_block must be a nonnegative JSON-safe integer")
    policy = manifest.policy
    if not hmac.compare_digest(manifest.policy_sha256, bootstrap_policy_hash(policy)):
        raise ValueError("bootstrap manifest policy hash is invalid")
    if not policy.activation_block <= manifest.frozen_at_block < policy.commit_stop_block:
        raise ValueError("bootstrap manifest was frozen outside policy activation")
    if not manifest.frozen_at_block <= current_block < policy.commit_stop_block:
        raise ValueError("bootstrap manifest is outside its active submission interval")
    if current_block - manifest.frozen_at_block > policy.manifest_ttl_blocks:
        raise ValueError("bootstrap frozen manifest exceeds the policy manifest TTL")

    accounts = [account_id32(entry.miner_hotkey) for entry in manifest.entries]
    if accounts != sorted(accounts):
        raise ValueError("bootstrap eligibility entries must be sorted by miner AccountId32")
    if len(set(accounts)) != len(accounts):
        raise ValueError("bootstrap eligibility entries contain a duplicate miner hotkey")
    uids = [entry.uid for entry in manifest.entries]
    if len(set(uids)) != len(uids):
        raise ValueError("bootstrap eligibility entries contain a duplicate UID")
    pilot_ids = [entry.pilot_id for entry in manifest.entries]
    if len(set(pilot_ids)) != len(pilot_ids):
        raise ValueError("bootstrap eligibility entries contain a duplicate pilot")

    for entry in manifest.entries:
        verify_bootstrap_opt_in(entry.opt_in, policy=policy)
        if entry.health_block > manifest.frozen_at_block:
            raise ValueError("bootstrap health observation postdates the frozen manifest")
        if current_block - entry.health_block > policy.health_ttl_blocks:
            raise ValueError("bootstrap health observation exceeds the policy TTL")
        if entry.pilot_block > entry.health_block:
            raise ValueError("bootstrap pilot block postdates its health observation")

    expected_row = [
        BootstrapQuantizedWeight(uid=entry.uid, value=U16_MAX)
        for entry in sorted(manifest.entries, key=lambda item: item.uid)
    ]
    if manifest.quantized_row != expected_row:
        raise ValueError(
            "bootstrap quantized row must assign max-upscaled u16 weight 65535 "
            "to every eligible UID"
        )


def _wallet_identity(wallet: Any) -> tuple[str, str]:
    import bittensor as bt

    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme = bt.wallets.format_crypto_type(signer.crypto_type)
    if scheme not in {"sr25519", "ed25519"}:
        raise ValueError(f"unsupported hotkey signature scheme: {scheme}")
    return signer.ss58_address, scheme


__all__ = [
    "BOOTSTRAP_COORDINATOR_SIGNATURE_SCHEMA",
    "BOOTSTRAP_DURATION_BLOCKS",
    "BOOTSTRAP_ELIGIBILITY_MANIFEST_SCHEMA",
    "BOOTSTRAP_MANIFEST_SIGNATURE_DOMAIN",
    "BOOTSTRAP_OPT_IN_SCHEMA",
    "BOOTSTRAP_OPT_IN_SIGNATURE_DOMAIN",
    "BOOTSTRAP_POLICY_HASH_DOMAIN",
    "BOOTSTRAP_TERMINAL_CLEARANCE_BLOCKS",
    "BOOTSTRAP_WEIGHT_POLICY_SCHEMA",
    "MAX_BOOTSTRAP_ENTRIES",
    "U16_MAX",
    "BootstrapCoordinatorSignature",
    "BootstrapEligibilityEntry",
    "BootstrapEligibilityManifest",
    "BootstrapOptIn",
    "BootstrapQuantizedWeight",
    "BootstrapWeightPolicy",
    "SignedBootstrapEligibilityManifest",
    "bootstrap_eligibility_manifest_digest",
    "bootstrap_manifest_digest",
    "bootstrap_opt_in_digest",
    "bootstrap_policy_hash",
    "bootstrap_weight_policy_hash",
    "build_bootstrap_eligibility_manifest",
    "sign_bootstrap_eligibility_manifest",
    "sign_bootstrap_opt_in",
    "verify_bootstrap_opt_in",
    "verify_signed_bootstrap_eligibility_manifest",
]
