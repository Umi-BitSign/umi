"""Signed pre-anchor readiness gate for independent availability mirrors."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .crypto import verify_response_signature
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import availability_digest
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .publisher_availability import (
    AvailabilityQualificationReceipt,
    CertifiedPoolRelease,
    PoolAnchorIntent,
    parse_qualification_receipt_bytes,
    qualification_receipt_digest,
)
from .validator_delivery import (
    MirrorDiscoveryRule,
    parse_canonical_model,
    validate_mirror_discovery_quorum,
)

if TYPE_CHECKING:
    from .mirror_service import MirrorServiceCheckResult

MIRROR_READINESS_STATEMENT_SCHEMA = "umi-mirror-readiness-statement/1"
MIRROR_READINESS_SET_SCHEMA = "umi-mirror-readiness-set/1"
MAX_MIRROR_READINESS_BYTES = 1024 * 1024
Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class MirrorReadinessError(RuntimeError):
    """Stable failure at the signed mirror-readiness boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class MirrorReadinessStatement(StrictProtocolModel):
    """One availability signer attesting an exact checked service definition."""

    schema_: Literal[MIRROR_READINESS_STATEMENT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=(1 << 53) - 1)]
    scoring_policy_sha256: Hex32
    discovery_rule_sha256: Hex32
    certified_release_sha256: Hex32
    anchor_intents_sha256: Hex32
    mirror_index_sha256: Hex32
    qualification_receipt_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    retrieval_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    delivery_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    exact_tree_configuration_checked: Literal[True]
    validator_credential_present: Literal[True]
    broadcast_performed: Literal[False]
    translation_weights_active: Literal[False]
    chain_write_capability: Literal[False]
    weight_submission_capability: Literal[False]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        account_id32(self.validator_hotkey)
        return self


class MirrorReadinessSet(StrictProtocolModel):
    """Complete verified readiness gate for every availability signer."""

    schema_: Literal[MIRROR_READINESS_SET_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=(1 << 53) - 1)]
    scoring_policy_sha256: Hex32
    discovery_rule_sha256: Hex32
    certified_release_sha256: Hex32
    anchor_intents_sha256: Hex32
    mirror_index_sha256: Hex32
    certified_release: CertifiedPoolRelease
    anchor_intents: Annotated[list[PoolAnchorIntent], Field(min_length=1, max_length=256)]
    statements: Annotated[list[MirrorReadinessStatement], Field(min_length=3, max_length=256)]
    pre_anchor_readiness_gate_passed: Literal[True]
    broadcast_performed: Literal[False]
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        signers = [account_id32(item.validator_hotkey) for item in self.statements]
        if signers != sorted(signers) or len(set(signers)) != len(signers):
            raise ValueError("mirror readiness signers must be unique and account-sorted")
        retrieval = [item.retrieval_origin for item in self.statements]
        delivery = [item.delivery_origin for item in self.statements]
        if len(set(retrieval)) != len(retrieval) or len(set(delivery)) != len(delivery):
            raise ValueError("mirror readiness statements must bind unique origin pairs")
        publishers = [account_id32(item.publisher_hotkey) for item in self.anchor_intents]
        if publishers != sorted(publishers) or len(set(publishers)) != len(publishers):
            raise ValueError("mirror readiness anchor intents must be publisher-sorted")
        return self


@dataclass(frozen=True, slots=True)
class CheckedMirrorReadinessInput:
    """Validated unsigned material that may be presented to one hotkey signer."""

    check: MirrorServiceCheckResult
    receipt: AvailabilityQualificationReceipt
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedLiveMirrorReadiness:
    """Self-contained readiness authority required by the live pool adapter."""

    raw: bytes
    readiness: MirrorReadinessSet
    expected_pool_manifest_sha256_by_publisher_account: Mapping[bytes, str]
    signer_accounts: frozenset[bytes]


def mirror_readiness_statement_digest(statement: MirrorReadinessStatement) -> bytes:
    document = statement.model_dump(mode="json", by_alias=True)
    document.pop("signature")
    return hashlib.sha256(
        b"umi-mirror-readiness-statement-v1\0" + canonical_json_bytes(document)
    ).digest()


def check_readiness_input(
    check: MirrorServiceCheckResult,
    receipt_bytes: bytes,
) -> CheckedMirrorReadinessInput:
    """Bind a pure mirror-service check to one already signed qualification receipt."""

    try:
        receipt = parse_qualification_receipt_bytes(receipt_bytes)
    except Exception as error:
        raise MirrorReadinessError("mirror_readiness_receipt_invalid") from error
    _verify_qualification_receipt(receipt)
    if (
        check.window_id != receipt.window_id
        or check.window_index != receipt.window_index
        or check.scoring_policy_sha256 != receipt.scoring_policy_hash
        or account_id32(receipt.validator_hotkey)
        not in {account_id32(item) for item in check.credential_validator_hotkeys}
    ):
        raise MirrorReadinessError("mirror_readiness_service_receipt_mismatch")
    return CheckedMirrorReadinessInput(
        check=check,
        receipt=receipt,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
    )


def sign_mirror_readiness(
    checked: CheckedMirrorReadinessInput,
    *,
    signature_scheme: Literal["sr25519", "ed25519"],
    sign_digest: Callable[[bytes], bytes],
) -> MirrorReadinessStatement:
    """Sign the exact public projection of one no-write service check."""

    if not isinstance(checked, CheckedMirrorReadinessInput):
        raise TypeError("checked readiness input has another type")
    provisional = MirrorReadinessStatement(
        schema=MIRROR_READINESS_STATEMENT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=checked.check.window_id,
        window_index=checked.check.window_index,
        scoring_policy_sha256=checked.check.scoring_policy_sha256,
        discovery_rule_sha256=checked.check.discovery_rule_sha256,
        certified_release_sha256=checked.check.certified_release_sha256,
        anchor_intents_sha256=checked.check.anchor_intents_sha256,
        mirror_index_sha256=checked.check.mirror_index_sha256,
        qualification_receipt_sha256=checked.receipt_sha256,
        validator_hotkey=checked.receipt.validator_hotkey,
        retrieval_origin=checked.check.retrieval_origin,
        delivery_origin=checked.check.delivery_origin,
        exact_tree_configuration_checked=True,
        validator_credential_present=True,
        broadcast_performed=False,
        translation_weights_active=False,
        chain_write_capability=False,
        weight_submission_capability=False,
        signature_scheme=signature_scheme,
        signature="0x" + "00" * 64,
    )
    signature = sign_digest(mirror_readiness_statement_digest(provisional))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise MirrorReadinessError("mirror_readiness_signature_invalid")
    statement = provisional.model_copy(update={"signature": "0x" + signature.hex()})
    _verify_readiness_signature(statement)
    return statement


def build_mirror_readiness_set(
    *,
    policy: ScoringPolicy,
    certified_release_bytes: bytes,
    anchor_intents_bytes: bytes,
    discovery_rule_bytes: bytes,
    qualification_receipt_bytes: Sequence[bytes],
    statements: Sequence[MirrorReadinessStatement],
) -> MirrorReadinessSet:
    """Verify the exact signer quorum and return its canonical pre-anchor gate."""

    try:
        release = CertifiedPoolRelease.model_validate_json(certified_release_bytes)
    except (ValidationError, ValueError) as error:
        raise MirrorReadinessError("mirror_readiness_release_invalid") from error
    if canonical_json_bytes(release) != certified_release_bytes:
        raise MirrorReadinessError("mirror_readiness_release_noncanonical")
    try:
        anchor_documents = json.loads(anchor_intents_bytes)
        anchor_intents = [PoolAnchorIntent.model_validate(item) for item in anchor_documents]
    except Exception as error:
        raise MirrorReadinessError("mirror_readiness_anchor_intents_invalid") from error
    if (
        canonical_json_bytes(
            [item.model_dump(mode="json", by_alias=True) for item in anchor_intents]
        )
        != anchor_intents_bytes
    ):
        raise MirrorReadinessError("mirror_readiness_anchor_intents_noncanonical")
    try:
        discovery = parse_canonical_model(
            discovery_rule_bytes,
            MirrorDiscoveryRule,
            maximum_bytes=MAX_MIRROR_READINESS_BYTES,
            label="mirror discovery rule",
        )
        required = validate_mirror_discovery_quorum(policy, discovery)
    except (TypeError, ValueError) as error:
        raise MirrorReadinessError("mirror_readiness_discovery_quorum_invalid") from error
    policy_hash = scoring_policy_hash(policy)
    release_sha256 = hashlib.sha256(certified_release_bytes).hexdigest()
    anchor_sha256 = hashlib.sha256(anchor_intents_bytes).hexdigest()
    discovery_sha256 = hashlib.sha256(discovery_rule_bytes).hexdigest()
    if (
        release.window.scoring_policy_hash != policy_hash
        or release.anchor_intents_sha256 != anchor_sha256
        or discovery_sha256 != policy.implementation_pins.rules.mirror_discovery_rule_sha256
    ):
        raise MirrorReadinessError("mirror_readiness_authority_mismatch")

    receipts: dict[bytes, tuple[AvailabilityQualificationReceipt, str]] = {}
    for raw in qualification_receipt_bytes:
        try:
            receipt = parse_qualification_receipt_bytes(raw)
        except Exception as error:
            raise MirrorReadinessError("mirror_readiness_receipt_invalid") from error
        _verify_qualification_receipt(receipt)
        account = account_id32(receipt.validator_hotkey)
        if account in receipts:
            raise MirrorReadinessError("mirror_readiness_receipt_signer_duplicate")
        receipts[account] = (receipt, hashlib.sha256(raw).hexdigest())
    if sorted(value[1] for value in receipts.values()) != sorted(release.signer_receipt_sha256s):
        raise MirrorReadinessError("mirror_readiness_receipt_set_mismatch")

    ordered = tuple(sorted(statements, key=lambda item: account_id32(item.validator_hotkey)))
    if len(ordered) != len(receipts) or len(ordered) < required:
        raise MirrorReadinessError("mirror_readiness_signer_set_incomplete")
    expected_common = (
        release.window.window_id,
        release.window.window_index,
        policy_hash,
        discovery_sha256,
        release_sha256,
        anchor_sha256,
        release.mirror_index_sha256,
    )
    retrieval: set[str] = set()
    delivery: set[str] = set()
    for statement in ordered:
        _verify_readiness_signature(statement)
        account = account_id32(statement.validator_hotkey)
        receipt_entry = receipts.get(account)
        if receipt_entry is None:
            raise MirrorReadinessError("mirror_readiness_signer_not_qualified")
        receipt, receipt_sha256 = receipt_entry
        if (
            (
                statement.window_id,
                statement.window_index,
                statement.scoring_policy_sha256,
                statement.discovery_rule_sha256,
                statement.certified_release_sha256,
                statement.anchor_intents_sha256,
                statement.mirror_index_sha256,
            )
            != expected_common
            or statement.qualification_receipt_sha256 != receipt_sha256
            or account_id32(receipt.validator_hotkey) != account
            or statement.retrieval_origin not in discovery.origins
            or statement.delivery_origin not in discovery.delivery_origins
        ):
            raise MirrorReadinessError("mirror_readiness_statement_binding_mismatch")
        if statement.retrieval_origin in retrieval or statement.delivery_origin in delivery:
            raise MirrorReadinessError("mirror_readiness_origin_reused")
        retrieval.add(statement.retrieval_origin)
        delivery.add(statement.delivery_origin)
    try:
        return MirrorReadinessSet(
            schema=MIRROR_READINESS_SET_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=release.window.window_id,
            window_index=release.window.window_index,
            scoring_policy_sha256=policy_hash,
            discovery_rule_sha256=discovery_sha256,
            certified_release_sha256=release_sha256,
            anchor_intents_sha256=anchor_sha256,
            mirror_index_sha256=release.mirror_index_sha256,
            certified_release=release,
            anchor_intents=anchor_intents,
            statements=list(ordered),
            pre_anchor_readiness_gate_passed=True,
            broadcast_performed=False,
            translation_weights_active=False,
            weight_submission_capability=False,
        )
    except (ValidationError, ValueError) as error:
        raise MirrorReadinessError("mirror_readiness_set_invalid") from error


def parse_mirror_readiness_statement(raw: bytes) -> MirrorReadinessStatement:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_MIRROR_READINESS_BYTES:
        raise MirrorReadinessError("mirror_readiness_statement_size_limit")
    try:
        statement = MirrorReadinessStatement.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise MirrorReadinessError("mirror_readiness_statement_invalid") from error
    if canonical_json_bytes(statement) != raw:
        raise MirrorReadinessError("mirror_readiness_statement_noncanonical")
    return statement


def verify_live_mirror_readiness(
    *,
    policy: ScoringPolicy,
    discovery_rule_bytes: bytes,
    readiness_set_bytes: bytes,
) -> VerifiedLiveMirrorReadiness:
    """Verify the self-contained readiness set before any pool anchor is eligible."""

    if (
        not isinstance(readiness_set_bytes, bytes)
        or not readiness_set_bytes
        or len(readiness_set_bytes) > MAX_MIRROR_READINESS_BYTES
    ):
        raise MirrorReadinessError("mirror_readiness_set_size_limit")
    try:
        readiness = MirrorReadinessSet.model_validate_json(readiness_set_bytes)
    except (ValidationError, ValueError) as error:
        raise MirrorReadinessError("mirror_readiness_set_invalid") from error
    if canonical_json_bytes(readiness) != readiness_set_bytes:
        raise MirrorReadinessError("mirror_readiness_set_noncanonical")
    try:
        discovery = parse_canonical_model(
            discovery_rule_bytes,
            MirrorDiscoveryRule,
            maximum_bytes=MAX_MIRROR_READINESS_BYTES,
            label="mirror discovery rule",
        )
        required = validate_mirror_discovery_quorum(policy, discovery)
    except (TypeError, ValueError) as error:
        raise MirrorReadinessError("mirror_readiness_discovery_quorum_invalid") from error
    release_bytes = canonical_json_bytes(readiness.certified_release)
    anchor_bytes = canonical_json_bytes(
        [item.model_dump(mode="json", by_alias=True) for item in readiness.anchor_intents]
    )
    common = (
        readiness.window_id,
        readiness.window_index,
        readiness.scoring_policy_sha256,
        readiness.discovery_rule_sha256,
        readiness.certified_release_sha256,
        readiness.anchor_intents_sha256,
        readiness.mirror_index_sha256,
    )
    expected_common = (
        readiness.certified_release.window.window_id,
        readiness.certified_release.window.window_index,
        scoring_policy_hash(policy),
        hashlib.sha256(discovery_rule_bytes).hexdigest(),
        hashlib.sha256(release_bytes).hexdigest(),
        hashlib.sha256(anchor_bytes).hexdigest(),
        readiness.certified_release.mirror_index_sha256,
    )
    if (
        common != expected_common
        or readiness.certified_release.anchor_intents_sha256 != readiness.anchor_intents_sha256
        or readiness.discovery_rule_sha256
        != policy.implementation_pins.rules.mirror_discovery_rule_sha256
        or len(readiness.statements) < required
    ):
        raise MirrorReadinessError("mirror_readiness_live_authority_mismatch")
    signer_accounts: set[bytes] = set()
    receipt_hashes: set[str] = set()
    retrieval: set[str] = set()
    delivery: set[str] = set()
    for statement in readiness.statements:
        _verify_readiness_signature(statement)
        if (
            (
                statement.window_id,
                statement.window_index,
                statement.scoring_policy_sha256,
                statement.discovery_rule_sha256,
                statement.certified_release_sha256,
                statement.anchor_intents_sha256,
                statement.mirror_index_sha256,
            )
            != common
            or statement.retrieval_origin not in discovery.origins
            or statement.delivery_origin not in discovery.delivery_origins
        ):
            raise MirrorReadinessError("mirror_readiness_live_statement_mismatch")
        account = account_id32(statement.validator_hotkey)
        if (
            account in signer_accounts
            or statement.qualification_receipt_sha256 in receipt_hashes
            or statement.retrieval_origin in retrieval
            or statement.delivery_origin in delivery
        ):
            raise MirrorReadinessError("mirror_readiness_live_uniqueness_invalid")
        signer_accounts.add(account)
        receipt_hashes.add(statement.qualification_receipt_sha256)
        retrieval.add(statement.retrieval_origin)
        delivery.add(statement.delivery_origin)
    if receipt_hashes != set(readiness.certified_release.signer_receipt_sha256s):
        raise MirrorReadinessError("mirror_readiness_live_receipt_set_mismatch")
    released = {
        account_id32(item.publisher_hotkey): item.sha256
        for item in readiness.certified_release.pool_manifests
    }
    intents = {
        account_id32(item.publisher_hotkey): item.pool_manifest_sha256
        for item in readiness.anchor_intents
    }
    if released != intents or any(
        item.netuid != policy.netuid
        or item.window_id != readiness.window_id
        or item.closing_block != readiness.certified_release.window.closing_block
        for item in readiness.anchor_intents
    ):
        raise MirrorReadinessError("mirror_readiness_live_anchor_set_mismatch")
    return VerifiedLiveMirrorReadiness(
        raw=readiness_set_bytes,
        readiness=readiness,
        expected_pool_manifest_sha256_by_publisher_account=released,
        signer_accounts=frozenset(signer_accounts),
    )


def _verify_qualification_receipt(receipt: AvailabilityQualificationReceipt) -> None:
    if not verify_response_signature(
        availability_digest(receipt.window_id, receipt.availability_set_root),
        hotkey_ss58=receipt.validator_hotkey,
        scheme=receipt.scheme,
        signature=receipt.signature,
    ) or not verify_response_signature(
        qualification_receipt_digest(receipt),
        hotkey_ss58=receipt.validator_hotkey,
        scheme=receipt.scheme,
        signature=receipt.receipt_signature,
    ):
        raise MirrorReadinessError("mirror_readiness_receipt_signature_invalid")


def _verify_readiness_signature(statement: MirrorReadinessStatement) -> None:
    if not verify_response_signature(
        mirror_readiness_statement_digest(statement),
        hotkey_ss58=statement.validator_hotkey,
        scheme=statement.signature_scheme,
        signature=statement.signature,
    ):
        raise MirrorReadinessError("mirror_readiness_signature_invalid")


__all__ = [
    "MIRROR_READINESS_SET_SCHEMA",
    "MIRROR_READINESS_STATEMENT_SCHEMA",
    "CheckedMirrorReadinessInput",
    "MirrorReadinessError",
    "MirrorReadinessSet",
    "MirrorReadinessStatement",
    "VerifiedLiveMirrorReadiness",
    "build_mirror_readiness_set",
    "check_readiness_input",
    "mirror_readiness_statement_digest",
    "parse_mirror_readiness_statement",
    "sign_mirror_readiness",
    "verify_live_mirror_readiness",
]
