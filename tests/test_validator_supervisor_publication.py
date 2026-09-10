from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest

from tests.factories import dev_wallet
from tests.test_bootstrap_direct_weights import NOW
from tests.test_observer_bootstrap_service_feed import _terminal_records
from umi.crypto import sign_response_digest
from umi.protocol import canonical_json_bytes
from umi.public_pilot_upload import (
    UPLOAD_AUTHENTICATION_DOMAIN,
    upload_validator_bootstrap_result,
)
from umi.validator_supervisor_publication import (
    SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
    SUPERVISOR_BOOTSTRAP_RESULT_SIGNATURE_DOMAIN,
    SupervisorBootstrapResult,
    parse_canonical_signed_supervisor_bootstrap_result,
    sign_supervisor_bootstrap_result,
)


def _signed_result():
    owner_fence, signed, authorization, material, receipt, journal, _owner, _participants = (
        _terminal_records(permitted=True)
    )
    result = SupervisorBootstrapResult(
        schema=SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
        directive_sha256="71" * 32,
        release_manifest_sha256="72" * 32,
        validator_hotkey=authorization.validator_hotkey,
        submission_id=authorization.submission_id,
        owner_fence_receipt=owner_fence,
        signed_manifest=signed,
        transition_authorization=authorization,
        drain_checkpoint=material.operational_preflight,
        call_material=material,
        submission_receipt=receipt,
        submission_journal=journal,
        created_at=NOW,
    )
    wallet = dev_wallet("//DirectBootstrapPermittedValidator")
    return sign_supervisor_bootstrap_result(result, wallet=wallet)


def test_supervisor_bootstrap_result_round_trips_canonically_and_verifies() -> None:
    signed = _signed_result()
    body = canonical_json_bytes(signed)

    parsed = parse_canonical_signed_supervisor_bootstrap_result(body)

    assert parsed == signed
    assert parsed.result.validator_hotkey == parsed.signer_hotkey
    assert parsed.result.submission_id == "66" * 32


def test_supervisor_bootstrap_result_rejects_tampering_and_wrong_signer() -> None:
    signed = _signed_result()
    payload = json.loads(canonical_json_bytes(signed))
    payload["result"]["release_manifest_sha256"] = "73" * 32

    with pytest.raises(ValueError, match="signed supervisor bootstrap result identity"):
        parse_canonical_signed_supervisor_bootstrap_result(canonical_json_bytes(payload))

    with pytest.raises(ValueError, match="supervisor bootstrap result signature is invalid"):
        sign_supervisor_bootstrap_result(
            signed.result,
            wallet=dev_wallet("//AnotherSupervisorBootstrapSigner"),
        )


def test_supervisor_bootstrap_result_rejects_invalid_nested_signature() -> None:
    signed = _signed_result()
    payload = json.loads(canonical_json_bytes(signed))
    signature = payload["result"]["signed_manifest"]["signature"]
    payload["result"]["signed_manifest"]["signature"] = signature[:-1] + (
        "0" if signature[-1] != "0" else "1"
    )

    result_bytes = canonical_json_bytes(payload["result"])
    result_digest = hashlib.sha256(
        SUPERVISOR_BOOTSTRAP_RESULT_SIGNATURE_DOMAIN + result_bytes
    ).digest()
    scheme, outer_signature = sign_response_digest(
        dev_wallet("//DirectBootstrapPermittedValidator"),
        result_digest,
    )
    payload.update(
        {
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "result_digest": result_digest.hex(),
            "signature_scheme": scheme,
            "signature": outer_signature,
        }
    )

    with pytest.raises(ValueError, match="bootstrap manifest coordinator signature is invalid"):
        parse_canonical_signed_supervisor_bootstrap_result(canonical_json_bytes(payload))


def test_validator_bootstrap_upload_is_submission_bound_and_idempotent() -> None:
    signed = _signed_result()
    body = canonical_json_bytes(signed)
    body_sha256 = hashlib.sha256(body).hexdigest()
    submission_id = signed.result.submission_id
    path = f"/validator-bootstrap-results/{submission_id}.json"
    secret = bytes.fromhex("41" * 32)
    put_count = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal put_count
        expected_url = (
            f"https://upload.example{path}"
            if request.method == "PUT"
            else f"https://public.example{path}"
        )
        assert request.url == expected_url
        if request.method == "PUT":
            put_count += 1
            timestamp = request.headers["x-umi-timestamp"]
            message = b"\n".join(
                (
                    UPLOAD_AUTHENTICATION_DOMAIN,
                    b"PUT",
                    path.encode("ascii"),
                    timestamp.encode("ascii"),
                    str(len(body)).encode("ascii"),
                    b"application/json",
                    body_sha256.encode("ascii"),
                )
            )
            assert request.headers["authorization"] == (
                "UMI-HMAC-SHA256 " + hmac.new(secret, message, hashlib.sha256).hexdigest()
            )
            assert request.read() == body
            return httpx.Response(409, json={"error": "object_exists"})
        return httpx.Response(
            200,
            stream=httpx.ByteStream(body),
            headers={"Content-Length": str(len(body))},
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        uploaded = upload_validator_bootstrap_result(
            body,
            submission_id=submission_id,
            upload_origin="https://upload.example",
            public_origin="https://public.example",
            secret=secret,
            client=client,
            timestamp=1_788_609_600,
        )

        with pytest.raises(ValueError, match="binds another submission ID"):
            upload_validator_bootstrap_result(
                body,
                submission_id="74" * 32,
                upload_origin="https://upload.example",
                public_origin="https://public.example",
                secret=secret,
                client=client,
                timestamp=1_788_609_600,
            )

    assert put_count == 1
    assert uploaded == (body_sha256, len(body), f"https://public.example{path}")
