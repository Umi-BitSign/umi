from __future__ import annotations

import hashlib
from dataclasses import replace

import bittensor as bt
import pytest
from pydantic import ValidationError

from umi.anchors import (
    AssignmentAnchorRecord,
    RequestAnchorRecord,
    ResponseAnchorRecord,
    SealedResponseRecord,
    VerifiedAuthEvidence,
    assignment_set_root,
    canonical_auth_records,
    request_set_root,
    response_set_root,
)
from umi.encoding import account_id32
from umi.protocol import TranslationRequest, canonical_json_bytes, request_digest

from .factories import challenge_request, dev_wallet

WINDOW_ID = "10" * 32
VALIDATOR_WALLET = dev_wallet("//Alice")
MINER_WALLET = dev_wallet("//Bob")
VALIDATOR = VALIDATOR_WALLET.hotkey.ss58_address
MINER = MINER_WALLET.hotkey.ss58_address
TRANSLATE_PATH = "/v1/translate"


def _headers(
    request: TranslationRequest,
    nonce: int,
    *,
    wallet=VALIDATOR_WALLET,
    receiver: str = MINER,
    method: str = "POST",
    path: str = TRANSLATE_PATH,
) -> dict[str, str]:
    return bt.http_auth.sign(
        wallet,
        method=method,
        path=path,
        body=canonical_json_bytes(request),
        receiver_ss58=receiver,
        nonce_ns=nonce,
    )


def _evidence(
    request: TranslationRequest,
    nonce: int,
    *,
    headers: dict[str, str] | None = None,
    expected_validator: str = VALIDATOR,
    expected_miner: str = MINER,
) -> VerifiedAuthEvidence:
    return VerifiedAuthEvidence.from_headers(
        headers or _headers(request, nonce),
        request=request,
        expected_validator_hotkey=expected_validator,
        expected_miner_hotkey=expected_miner,
    )


def _assignment(index: int) -> AssignmentAnchorRecord:
    request = challenge_request(index)
    return AssignmentAnchorRecord(initial_auth_evidence=_evidence(request, index * 10))


def _request(
    assignment: AssignmentAnchorRecord,
    retry_nonce: int,
) -> RequestAnchorRecord:
    first = assignment.initial_auth_evidence
    retry = _evidence(first.request, retry_nonce)
    return RequestAnchorRecord(auth_evidence=(retry, first))


def _sealed(index: int) -> SealedResponseRecord:
    return SealedResponseRecord.model_validate(
        {
            "disposition": "sealed",
            "receipt_metadata": {"received_block": 100 + index},
            "wire_envelope_sha256": f"{index:064x}",
            "signature_scheme": "sr25519",
            "serving_hotkey": MINER,
            "signature": "0x" + f"{index:02x}" * 64,
            "received_bytes_sha256": None,
        }
    )


def test_anchor_leaves_and_roots_reproduce_the_binary_formulas() -> None:
    assignment = _assignment(1)
    request = _request(assignment, 11)
    response = ResponseAnchorRecord(request_leaf=request.leaf, sealed_response_record=_sealed(1))

    miner = account_id32(MINER)
    digest = bytes.fromhex(request_digest(assignment.initial_auth_evidence.request))
    assignment_leaf = hashlib.sha256(
        b"umi-assignment-leaf-v1\0"
        + miner
        + digest
        + hashlib.sha256(canonical_json_bytes(assignment.initial_auth_record)).digest()
    ).digest()
    request_leaf = hashlib.sha256(
        b"umi-request-leaf-v1\0"
        + miner
        + digest
        + hashlib.sha256(canonical_json_bytes(list(request.ordered_auth_records))).digest()
    ).digest()
    response_leaf = hashlib.sha256(
        b"umi-response-leaf-v1\0"
        + request_leaf
        + hashlib.sha256(canonical_json_bytes(response.sealed_response_record)).digest()
    ).digest()

    assert assignment.leaf == assignment_leaf
    assert request.leaf == request_leaf
    assert response.leaf == response_leaf
    assert assignment.request_digest == digest
    assert (
        assignment_set_root([assignment], window_id=WINDOW_ID, validator_hotkey=VALIDATOR)
        == hashlib.sha256(
            b"umi-assignment-set-v1\0"
            + bytes.fromhex(WINDOW_ID)
            + account_id32(VALIDATOR)
            + (1).to_bytes(4, "big")
            + assignment_leaf
        ).digest()
    )


def test_all_anchor_roots_are_permutation_invariant() -> None:
    assignments = (_assignment(1), _assignment(2))
    requests = (_request(assignments[0], 11), _request(assignments[1], 21))
    responses = tuple(
        ResponseAnchorRecord(request_leaf=request.leaf, sealed_response_record=_sealed(index))
        for index, request in enumerate(requests, 1)
    )

    assert assignment_set_root(
        assignments, window_id=WINDOW_ID, validator_hotkey=VALIDATOR
    ) == assignment_set_root(
        tuple(reversed(assignments)), window_id=WINDOW_ID, validator_hotkey=VALIDATOR
    )
    assert request_set_root(
        requests,
        assignments=assignments,
        window_id=WINDOW_ID,
        validator_hotkey=VALIDATOR,
    ) == request_set_root(
        tuple(reversed(requests)),
        assignments=tuple(reversed(assignments)),
        window_id=WINDOW_ID,
        validator_hotkey=VALIDATOR,
    )
    assert response_set_root(
        responses,
        request_records=requests,
        window_id=WINDOW_ID,
        validator_hotkey=VALIDATOR,
    ) == response_set_root(
        tuple(reversed(responses)),
        request_records=tuple(reversed(requests)),
        window_id=WINDOW_ID,
        validator_hotkey=VALIDATOR,
    )


def test_auth_transcripts_sort_verified_numeric_nonces_and_reject_reuse() -> None:
    request = challenge_request(1)
    evidence = tuple(_evidence(request, nonce) for nonce in (10, 2, 3))
    ordered = canonical_auth_records(evidence)
    assert [item.auth_record.nonce for item in ordered] == ["2", "3", "10"]
    assert [item.auth_record.nonce_int for item in ordered] == [2, 3, 10]

    duplicate = _evidence(request, 2)
    with pytest.raises(ValueError, match="reuses a nonce"):
        canonical_auth_records((evidence[1], duplicate))
    with pytest.raises(TypeError, match="VerifiedAuthEvidence"):
        canonical_auth_records(({"nonce": 1},))  # type: ignore[arg-type]


def test_anchor_preserves_and_hashes_a_realistic_nanosecond_nonce_as_text() -> None:
    request = challenge_request(1)
    nonce = 1_770_000_000_000_000_000

    evidence = _evidence(request, nonce)
    assignment = AssignmentAnchorRecord(initial_auth_evidence=evidence)

    assert nonce > 2**53 - 1
    assert evidence.auth_record.nonce == str(nonce)
    assert evidence.auth_record.nonce_int == nonce
    assert f'"nonce":"{nonce}"'.encode() in canonical_json_bytes(evidence.auth_record)
    assert len(assignment.leaf) == 32


def test_request_anchor_enforces_bijection_and_anchored_first_attempt() -> None:
    first, second = _assignment(1), _assignment(2)
    first_request = _request(first, 11)
    second_request = _request(second, 21)

    with pytest.raises(ValueError, match="bijection"):
        request_set_root(
            (first_request,),
            assignments=(first, second),
            window_id=WINDOW_ID,
            validator_hotkey=VALIDATOR,
        )
    substituted_initial = _evidence(first.initial_auth_evidence.request, 9)
    substituted = RequestAnchorRecord(
        auth_evidence=(substituted_initial, _evidence(first.initial_auth_evidence.request, 11))
    )
    with pytest.raises(ValueError, match="anchored initial attempt"):
        request_set_root(
            (substituted, second_request),
            assignments=(first, second),
            window_id=WINDOW_ID,
            validator_hotkey=VALIDATOR,
        )

    with pytest.raises(ValueError, match="duplicate keys"):
        request_set_root(
            (first_request, first_request),
            assignments=(first, second),
            window_id=WINDOW_ID,
            validator_hotkey=VALIDATOR,
        )


def test_request_transcript_cannot_combine_other_request_or_actor_evidence() -> None:
    reveal_round = bt.timelock.current_round() + 100
    first_request = challenge_request(1, reveal_round=reveal_round)
    first = _evidence(first_request, 10)
    other_request = _evidence(
        challenge_request(2, reveal_round=reveal_round),
        11,
    )
    with pytest.raises(ValueError, match="different request bytes"):
        RequestAnchorRecord(auth_evidence=(first, other_request))

    other_validator = dev_wallet("//Charlie")
    headers = _headers(first_request, 11, wallet=other_validator)
    other_sender = _evidence(
        first_request,
        11,
        headers=headers,
        expected_validator=other_validator.hotkey.ss58_address,
    )
    with pytest.raises(ValueError, match="different validator senders"):
        RequestAnchorRecord(auth_evidence=(first, other_sender))


def test_anchor_roots_reject_a_different_window_or_validator_context() -> None:
    assignment = _assignment(1)
    request = _request(assignment, 11)
    with pytest.raises(ValueError, match="different window"):
        assignment_set_root(
            (assignment,),
            window_id="99" * 32,
            validator_hotkey=VALIDATOR,
        )
    with pytest.raises(ValueError, match="different validator"):
        request_set_root(
            (request,),
            assignments=(assignment,),
            window_id=WINDOW_ID,
            validator_hotkey=dev_wallet("//Charlie").hotkey.ss58_address,
        )


def test_response_anchor_requires_exactly_one_record_per_request_leaf() -> None:
    assignments = (_assignment(1), _assignment(2))
    requests = (_request(assignments[0], 11), _request(assignments[1], 21))
    first_response = ResponseAnchorRecord(
        request_leaf=requests[0].leaf,
        sealed_response_record=_sealed(1),
    )
    with pytest.raises(ValueError, match="bijection"):
        response_set_root(
            (first_response,),
            request_records=requests,
            window_id=WINDOW_ID,
            validator_hotkey=VALIDATOR,
        )
    with pytest.raises(ValueError, match="duplicate keys"):
        response_set_root(
            (first_response, first_response),
            request_records=requests,
            window_id=WINDOW_ID,
            validator_hotkey=VALIDATOR,
        )


def test_response_anchor_rejects_unvalidated_or_subclassed_sealed_records() -> None:
    with pytest.raises(TypeError, match="exact SealedResponseRecord"):
        ResponseAnchorRecord(
            request_leaf=b"0" * 32,
            sealed_response_record={"disposition": "sealed"},  # type: ignore[arg-type]
        )

    class SealedSubclass(SealedResponseRecord):
        pass

    subclassed = SealedSubclass.model_validate(_sealed(1).model_dump(mode="json"))
    with pytest.raises(TypeError, match="exact SealedResponseRecord"):
        ResponseAnchorRecord(
            request_leaf=b"0" * 32,
            sealed_response_record=subclassed,
        )
    with pytest.raises(ValueError, match="request leaf"):
        ResponseAnchorRecord(request_leaf=b"short", sealed_response_record=_sealed(1))


def test_verified_auth_evidence_uses_real_btauth_signatures() -> None:
    request = challenge_request(1)
    evidence = _evidence(request, 123)
    assert evidence.auth_record.version == "btauth/1"
    assert evidence.auth_record.scheme == "sr25519"
    assert evidence.auth_record.method == "POST"
    assert evidence.auth_record.wire_request_target == TRANSLATE_PATH
    assert (
        evidence.auth_record.raw_body_sha256
        == hashlib.sha256(canonical_json_bytes(request)).hexdigest()
    )
    assert evidence.request_digest_bytes == bytes.fromhex(request_digest(request))

    with pytest.raises(TypeError, match="from_headers"):
        replace(evidence, _verification_token=object())
    with pytest.raises(TypeError, match="VerifiedAuthEvidence"):
        AssignmentAnchorRecord(initial_auth_evidence={"nonce": 123})  # type: ignore[arg-type]


@pytest.mark.parametrize("crypto_type", [bt.sp_core.CRYPTO_SR25519, bt.sp_core.CRYPTO_ED25519])
def test_verified_auth_evidence_preserves_the_declared_signature_scheme(crypto_type: int) -> None:
    validator = dev_wallet("//Dave", crypto_type)
    request = challenge_request(1)
    headers = _headers(request, 123, wallet=validator)
    evidence = _evidence(
        request,
        123,
        headers=headers,
        expected_validator=validator.hotkey.ss58_address,
    )
    assert evidence.auth_record.scheme == bt.wallets.format_crypto_type(crypto_type)


def test_verified_auth_rejects_unauthenticated_and_ambiguous_headers() -> None:
    request = challenge_request(1)
    with pytest.raises(ValueError, match="missing"):
        _evidence(request, 1, headers={"X-Bittensor-Nonce": "1"})

    headers = _headers(request, 1)
    headers["x-bittensor-nonce"] = headers["X-Bittensor-Nonce"]
    with pytest.raises(ValueError, match="case-insensitive duplicate"):
        _evidence(request, 1, headers=headers)


def test_verified_auth_rejects_wrong_sender_and_receiver() -> None:
    request = challenge_request(1)
    other = dev_wallet("//Charlie")
    with pytest.raises(ValueError, match="different validator sender"):
        _evidence(request, 1, expected_validator=other.hotkey.ss58_address)
    with pytest.raises(ValueError, match="different receiver"):
        _evidence(request, 1, expected_miner=other.hotkey.ss58_address)


@pytest.mark.parametrize(
    ("method", "path"),
    (("GET", TRANSLATE_PATH), ("POST", "/v1/not-translate")),
)
def test_verified_auth_rejects_wrong_method_or_path(method: str, path: str) -> None:
    request = challenge_request(1)
    headers = _headers(request, 1, method=method, path=path)
    with pytest.raises(ValueError, match="signature is invalid"):
        _evidence(request, 1, headers=headers)


def test_verified_auth_rejects_wrong_body_nonce_or_signature() -> None:
    request = challenge_request(1)
    headers = _headers(request, 1)
    with pytest.raises(ValueError, match="signature is invalid"):
        _evidence(challenge_request(2), 1, headers=headers)

    tampered_nonce = dict(headers)
    tampered_nonce["X-Bittensor-Nonce"] = "2"
    with pytest.raises(ValueError, match="signature is invalid"):
        _evidence(request, 2, headers=tampered_nonce)

    noncanonical_nonce = dict(headers)
    noncanonical_nonce["X-Bittensor-Nonce"] = "01"
    with pytest.raises(ValueError, match="not a decimal integer"):
        _evidence(request, 1, headers=noncanonical_nonce)

    tampered_signature = dict(headers)
    tampered_signature["X-Bittensor-Signature"] = "0x" + "00" * 64
    with pytest.raises(ValueError, match="signature is invalid"):
        _evidence(request, 1, headers=tampered_signature)


def test_sealed_response_shape_cannot_mix_outer_failure_and_envelope_evidence() -> None:
    _sealed(1)
    with pytest.raises(ValidationError, match="requires envelope"):
        SealedResponseRecord.model_validate({"disposition": "sealed", "receipt_metadata": {}})
    with pytest.raises(ValidationError, match="cannot carry"):
        SealedResponseRecord.model_validate(
            {
                "disposition": "missing",
                "receipt_metadata": {},
                "wire_envelope_sha256": "00" * 32,
                "signature_scheme": "sr25519",
                "serving_hotkey": MINER,
                "signature": "0x" + "00" * 64,
            }
        )
