"""Signed evidence that a component pilot used a chain-announced public endpoint.

The component bundle remains explicitly nonconforming and weight-ineligible.  This
extension authenticates the coordinator's public-endpoint and finalized-SDK-read
claims without upgrading those claims into storage-proof evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH
from .protocol import (
    BlockHash,
    Hex32,
    NonEmptyText,
    StrictProtocolModel,
    canonical_json_bytes,
    request_digest,
)
from .public_pilot_campaign import CAMPAIGN_ID, validate_public_pilot_replay

PUBLIC_ENDPOINT_PILOT_SCHEMA = "umi-public-endpoint-pilot/1"
PUBLIC_ENDPOINT_SIGNATURE_SCHEMA = "umi-public-endpoint-pilot-signature/1"
PUBLIC_ENDPOINT_ATTESTATION_DOMAIN = b"umi-public-endpoint-pilot-v1\0"

_SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{128}$")
_FINNEY_GENESIS_BLOCK_HASH = "0x" + FINNEY_GENESIS_HASH


def validate_public_endpoint_origin(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("public endpoint origin contains a control character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        raise ValueError("public endpoint origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or value.endswith("/")
        or value != f"{parsed.scheme}://{parsed.netloc}"
        or port is None
        or not 1 <= port <= 65_535
        or not address.is_global
    ):
        raise ValueError(
            "public endpoint origin must be one normalized HTTPS public-IP origin with a port"
        )
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    if value != f"https://{host}:{port}":
        raise ValueError(
            "public endpoint origin must be one normalized HTTPS public-IP origin with a port"
        )
    return value


# Retained for compatibility with the first public-pilot fixture imports.
_validated_https_origin = validate_public_endpoint_origin


class SDKFinalizedObservation(StrictProtocolModel):
    """One coordinator-observed SDK snapshot without portable storage proofs."""

    observation_class: Literal["sdk_finalized_block_without_storage_proofs"] = (
        "sdk_finalized_block_without_storage_proofs"
    )
    network: Literal["finney"] = "finney"
    genesis_block_hash: BlockHash
    block_number: Annotated[int, Field(ge=0)]
    block_hash: BlockHash
    block_timestamp_unix_ms: Annotated[int, Field(ge=0)]
    storage_proofs_verified: Literal[False] = False

    @field_validator("genesis_block_hash")
    @classmethod
    def validate_finney_genesis(cls, value: str) -> str:
        if value != _FINNEY_GENESIS_BLOCK_HASH:
            raise ValueError("public endpoint observation is not bound to Finney genesis")
        return value


class PublicEndpointPilotAttestation(StrictProtocolModel):
    """Coordinator-authenticated facts and explicit residual assertions."""

    schema_: Literal[PUBLIC_ENDPOINT_PILOT_SCHEMA] = Field(alias="schema")
    evidence_class: Literal["public_endpoint_component_test_no_weight"] = (
        "public_endpoint_component_test_no_weight"
    )
    base_component_manifest_sha256: Hex32
    campaign_id: Literal[CAMPAIGN_ID] = CAMPAIGN_ID
    netuid: Literal[78] = 78
    mechanism_id: Literal[0] = 0
    translation_weights_active: Literal[False] = False
    protocol_conformance: Literal[False] = False
    activation_evidence: Literal[False] = False
    validator_input_eligible: Literal[False] = False
    coordinator_hotkey: NonEmptyText
    attested_at_unix_ms: Annotated[int, Field(ge=0)]
    chain_observation: SDKFinalizedObservation
    expected_miner_uid: Annotated[int, Field(ge=0, le=65_535)]
    miner_hotkey: NonEmptyText
    validator_permit: Literal[False] = False
    announced_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    contacted_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    request_digest: Hex32
    known_public_challenge: Literal[True] = True
    public_miner_transport_used: Literal[True] = True
    attempt_count: Literal[1] = 1
    outcome_classification: Literal["ok", "signed_error", "failed"]
    failure_code: NonEmptyText | None
    miner_signed_envelope_verified: bool
    miner_signed_plaintext_verified: bool
    response_receipt_time_is_coordinator_assertion: Literal[True] = True
    attempt_completeness_is_coordinator_assertion: Literal[True] = True

    @field_validator("coordinator_hotkey", "miner_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        try:
            account_id32(value)
        except ValueError as error:
            raise ValueError("pilot hotkey is not a valid SS58 account") from error
        return value

    @field_validator("announced_origin", "contacted_origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return validate_public_endpoint_origin(value)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if account_id32(self.coordinator_hotkey) == account_id32(self.miner_hotkey):
            raise ValueError("pilot coordinator and miner hotkeys must be distinct")
        if self.announced_origin != self.contacted_origin:
            raise ValueError("contacted origin must equal the chain-announced origin")
        if self.chain_observation.block_timestamp_unix_ms > self.attested_at_unix_ms:
            raise ValueError("chain observation cannot postdate the signed attestation")
        if self.miner_signed_plaintext_verified and not self.miner_signed_envelope_verified:
            raise ValueError("verified miner plaintext requires a verified signed envelope")
        if self.outcome_classification == "ok":
            if (
                self.failure_code is not None
                or not self.miner_signed_envelope_verified
                or not self.miner_signed_plaintext_verified
            ):
                raise ValueError("an ok pilot outcome requires one fully verified response")
        elif self.outcome_classification == "signed_error":
            if (
                self.failure_code is None
                or not self.miner_signed_envelope_verified
                or not self.miner_signed_plaintext_verified
            ):
                raise ValueError("a signed-error outcome requires verified response evidence")
        elif self.failure_code is None:
            raise ValueError("a failed pilot outcome requires a failure code")
        return self


class PublicEndpointPilotSignature(StrictProtocolModel):
    """Hotkey signature over the domain-separated attestation digest."""

    schema_: Literal[PUBLIC_ENDPOINT_SIGNATURE_SCHEMA] = Field(alias="schema")
    attestation_sha256: Hex32
    attestation_digest: Hex32
    signer_hotkey: NonEmptyText
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE.pattern)]

    @field_validator("signer_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        try:
            account_id32(value)
        except ValueError as error:
            raise ValueError("pilot signature hotkey is not a valid SS58 account") from error
        return value


class PublicEndpointPilotAttachment(StrictProtocolModel):
    """Content-addressed objects attached to the final component manifest."""

    attestation: dict[str, Any]
    signature: dict[str, Any]

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        _object_ref(self.attestation, field="attestation")
        _object_ref(self.signature, field="signature")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedPublicEndpointPilot:
    attestation: PublicEndpointPilotAttestation
    signature: PublicEndpointPilotSignature
    attestation_ref: ObjectRef
    signature_ref: ObjectRef


def _object_ref(value: Any, *, field: str) -> ObjectRef:
    if not isinstance(value, dict) or set(value) != {"sha256", "media_type", "size_bytes"}:
        raise ValueError(f"public endpoint {field} reference has an invalid schema")
    if (
        not isinstance(value.get("sha256"), str)
        or value.get("media_type") != "application/json"
        or isinstance(value.get("size_bytes"), bool)
        or not isinstance(value.get("size_bytes"), int)
    ):
        raise ValueError(f"public endpoint {field} reference must name canonical JSON")
    try:
        reference = ObjectRef(
            sha256=value["sha256"],
            media_type=value["media_type"],
            size_bytes=value["size_bytes"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"public endpoint {field} reference is invalid") from error
    return reference


def public_endpoint_attestation_digest(
    attestation: PublicEndpointPilotAttestation,
) -> bytes:
    if not isinstance(attestation, PublicEndpointPilotAttestation):
        raise TypeError("attestation must be PublicEndpointPilotAttestation")
    return hashlib.sha256(
        PUBLIC_ENDPOINT_ATTESTATION_DOMAIN + canonical_json_bytes(attestation)
    ).digest()


def _verified_signed_envelope(store: EvidenceStore, replay: Any, outcome: Any) -> bool:
    if outcome.response_envelope_ref is None or outcome.response_signature_ref is None:
        return False
    try:
        from .validator import validate_response_envelope

        envelope_bytes = store.read(outcome.response_envelope_ref)
        signature_bytes = store.read(outcome.response_signature_ref)
        signature_record = json.loads(signature_bytes)
        if (
            not isinstance(signature_record, dict)
            or set(signature_record) != {"signature"}
            or canonical_json_bytes(signature_record) != signature_bytes
        ):
            return False
        validate_response_envelope(
            envelope_bytes,
            signature_record["signature"],
            request=outcome.request,
            validator_hotkey=replay.validator_hotkey,
            miner_hotkey=replay.miner_hotkey,
        )
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _derived_outcome(store: EvidenceStore, replay: Any) -> tuple[str, str | None, bool, bool]:
    if len(replay.outcomes) != 1:
        raise ValueError("public endpoint evidence requires exactly one component outcome")
    outcome = replay.outcomes[0]
    envelope_verified = _verified_signed_envelope(store, replay, outcome)
    plaintext_verified = outcome.response is not None
    if plaintext_verified and not envelope_verified:
        raise ValueError("component replay returned plaintext without a verified signed envelope")
    if (
        outcome.response is not None
        and outcome.response.status == "ok"
        and outcome.failure_code is None
    ):
        classification = "ok"
    elif outcome.response is not None and outcome.response.status == "error":
        classification = "signed_error"
    else:
        classification = "failed"
    failure_code = outcome.failure_code
    if classification == "signed_error" and failure_code is None:
        failure_code = outcome.response.error_code
    if classification == "failed" and failure_code is None:
        raise ValueError("failed public endpoint outcome has no canonical failure code")
    return classification, failure_code, envelope_verified, plaintext_verified


def verify_public_endpoint_pilot_attachment(
    store: EvidenceStore,
    manifest: dict[str, Any],
    replay: Any,
) -> VerifiedPublicEndpointPilot | None:
    """Strictly verify an optional public-endpoint extension against base replay."""

    raw_attachment = manifest.get("public_endpoint_pilot")
    if raw_attachment is None:
        return None
    attachment = PublicEndpointPilotAttachment.model_validate(raw_attachment)
    attestation_ref = _object_ref(attachment.attestation, field="attestation")
    signature_ref = _object_ref(attachment.signature, field="signature")
    attestation_bytes = store.read(attestation_ref)
    signature_bytes = store.read(signature_ref)
    try:
        attestation = PublicEndpointPilotAttestation.model_validate_json(attestation_bytes)
        signature = PublicEndpointPilotSignature.model_validate_json(signature_bytes)
    except ValueError as error:
        raise ValueError("public endpoint evidence object is invalid") from error
    if canonical_json_bytes(attestation) != attestation_bytes:
        raise ValueError("public endpoint attestation is not canonical JSON")
    if canonical_json_bytes(signature) != signature_bytes:
        raise ValueError("public endpoint signature is not canonical JSON")

    base_manifest = dict(manifest)
    del base_manifest["public_endpoint_pilot"]
    base_manifest_sha256 = hashlib.sha256(canonical_json_bytes(base_manifest)).hexdigest()
    if attestation.base_component_manifest_sha256 != base_manifest_sha256:
        raise ValueError("public endpoint attestation binds another base component manifest")
    attestation_sha256 = hashlib.sha256(attestation_bytes).hexdigest()
    digest = public_endpoint_attestation_digest(attestation)
    if (
        signature.attestation_sha256 != attestation_sha256
        or signature.attestation_digest != digest.hex()
        or account_id32(signature.signer_hotkey) != account_id32(attestation.coordinator_hotkey)
        or not verify_response_signature(
            digest,
            hotkey_ss58=signature.signer_hotkey,
            scheme=signature.signature_scheme,
            signature=signature.signature,
        )
    ):
        raise ValueError("public endpoint attestation signature is invalid")

    if len(replay.outcomes) != 1:
        raise ValueError("public endpoint evidence requires exactly one component outcome")
    outcome = replay.outcomes[0]
    validate_public_pilot_replay(outcome.request, replay.ground_truth)
    if account_id32(attestation.coordinator_hotkey) != account_id32(replay.validator_hotkey):
        raise ValueError("public endpoint coordinator does not match component authentication")
    if account_id32(attestation.miner_hotkey) != account_id32(replay.miner_hotkey):
        raise ValueError("public endpoint miner does not match component response evidence")
    if manifest.get("miner_origin") != attestation.contacted_origin:
        raise ValueError("public endpoint contact does not match component miner origin")
    if attestation.request_digest != request_digest(outcome.request):
        raise ValueError("public endpoint attestation binds another component request")
    raw_outcomes = manifest.get("outcomes")
    if not isinstance(raw_outcomes, list) or len(raw_outcomes) != 1:
        raise ValueError("public endpoint manifest does not contain exactly one outcome")
    raw_receipt = raw_outcomes[0].get("received_at_unix_ns")
    if raw_receipt is not None:
        try:
            received_at_unix_ns = int(raw_receipt)
        except (TypeError, ValueError) as error:
            raise ValueError("public endpoint receipt time is invalid") from error
        if (
            isinstance(raw_receipt, bool)
            or received_at_unix_ns < 0
            or str(received_at_unix_ns) != raw_receipt
        ):
            raise ValueError("public endpoint receipt time is invalid")
        if attestation.chain_observation.block_timestamp_unix_ms > received_at_unix_ns // 1_000_000:
            raise ValueError("chain observation cannot postdate the response receipt")
    classification, failure_code, envelope_verified, plaintext_verified = _derived_outcome(
        store, replay
    )
    if (
        attestation.outcome_classification != classification
        or attestation.failure_code != failure_code
        or attestation.miner_signed_envelope_verified != envelope_verified
        or attestation.miner_signed_plaintext_verified != plaintext_verified
    ):
        raise ValueError("public endpoint attestation outcome does not match component replay")
    return VerifiedPublicEndpointPilot(
        attestation=attestation,
        signature=signature,
        attestation_ref=attestation_ref,
        signature_ref=signature_ref,
    )


def attach_public_endpoint_pilot(
    bundle_root: Path,
    *,
    wallet: Any,
    campaign_id: str,
    network: Literal["finney"],
    genesis_block_hash: str,
    finalized_block_number: int,
    finalized_block_hash: str,
    finalized_block_timestamp_ms: int,
    expected_miner_uid: int,
    announced_origin: str,
    contacted_origin: str,
) -> Path:
    """Derive, sign, and attach public-endpoint evidence to one completed bundle."""

    from .validator import replay_bundle_detailed

    store = EvidenceStore(bundle_root)
    manifest, manifest_bytes = store.load_manifest_with_bytes()
    if "public_endpoint_pilot" in manifest:
        raise ValueError("component bundle already has public endpoint evidence")
    replay = replay_bundle_detailed(bundle_root)
    if replay.manifest != manifest:
        raise ValueError("component replay did not bind the base manifest")
    classification, failure_code, envelope_verified, plaintext_verified = _derived_outcome(
        store, replay
    )
    validate_public_pilot_replay(replay.outcomes[0].request, replay.ground_truth)
    if manifest.get("miner_origin") != contacted_origin:
        raise ValueError("contacted origin does not match the component miner origin")

    import bittensor as bt

    signer = bt.resolve_signer(wallet, role="hotkey")
    coordinator_hotkey = signer.ss58_address
    if account_id32(coordinator_hotkey) != account_id32(replay.validator_hotkey):
        raise ValueError("attestation wallet did not sign the component request")
    outcome = replay.outcomes[0]
    attestation = PublicEndpointPilotAttestation.model_validate(
        {
            "schema": PUBLIC_ENDPOINT_PILOT_SCHEMA,
            "evidence_class": "public_endpoint_component_test_no_weight",
            "base_component_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "campaign_id": campaign_id,
            "netuid": 78,
            "mechanism_id": 0,
            "translation_weights_active": False,
            "protocol_conformance": False,
            "activation_evidence": False,
            "validator_input_eligible": False,
            "coordinator_hotkey": coordinator_hotkey,
            "attested_at_unix_ms": time.time_ns() // 1_000_000,
            "chain_observation": {
                "observation_class": "sdk_finalized_block_without_storage_proofs",
                "network": network,
                "genesis_block_hash": genesis_block_hash,
                "block_number": finalized_block_number,
                "block_hash": finalized_block_hash,
                "block_timestamp_unix_ms": finalized_block_timestamp_ms,
                "storage_proofs_verified": False,
            },
            "expected_miner_uid": expected_miner_uid,
            "miner_hotkey": replay.miner_hotkey,
            "validator_permit": False,
            "announced_origin": announced_origin,
            "contacted_origin": contacted_origin,
            "request_digest": request_digest(outcome.request),
            "known_public_challenge": True,
            "public_miner_transport_used": True,
            "attempt_count": 1,
            "outcome_classification": classification,
            "failure_code": failure_code,
            "miner_signed_envelope_verified": envelope_verified,
            "miner_signed_plaintext_verified": plaintext_verified,
            "response_receipt_time_is_coordinator_assertion": True,
            "attempt_completeness_is_coordinator_assertion": True,
        }
    )
    attestation_bytes = canonical_json_bytes(attestation)
    attestation_ref = store.add_bytes(attestation_bytes, "application/json")
    digest = public_endpoint_attestation_digest(attestation)
    scheme, signed = sign_response_digest(wallet, digest)
    signature = PublicEndpointPilotSignature.model_validate(
        {
            "schema": PUBLIC_ENDPOINT_SIGNATURE_SCHEMA,
            "attestation_sha256": attestation_ref.sha256,
            "attestation_digest": digest.hex(),
            "signer_hotkey": coordinator_hotkey,
            "signature_scheme": scheme,
            "signature": signed,
        }
    )
    signature_ref = store.add_json(signature)
    manifest["public_endpoint_pilot"] = {
        "attestation": attestation_ref.as_dict(),
        "signature": signature_ref.as_dict(),
    }
    path = store.write_manifest(manifest)
    attached_replay = replay_bundle_detailed(bundle_root)
    verify_public_endpoint_pilot_attachment(store, manifest, attached_replay)
    return path


__all__ = [
    "PUBLIC_ENDPOINT_ATTESTATION_DOMAIN",
    "PUBLIC_ENDPOINT_PILOT_SCHEMA",
    "PUBLIC_ENDPOINT_SIGNATURE_SCHEMA",
    "PublicEndpointPilotAttachment",
    "PublicEndpointPilotAttestation",
    "PublicEndpointPilotSignature",
    "SDKFinalizedObservation",
    "VerifiedPublicEndpointPilot",
    "attach_public_endpoint_pilot",
    "public_endpoint_attestation_digest",
    "validate_public_endpoint_origin",
    "verify_public_endpoint_pilot_attachment",
]
