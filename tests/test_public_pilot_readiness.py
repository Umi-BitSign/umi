from __future__ import annotations

import calendar
import hashlib
import json
import re
import time

import bittensor as bt
import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from umi.encoding import account_id32
from umi.protocol import base64url_encode, canonical_json_bytes
from umi.public_pilot_campaign import CAMPAIGN_ID
from umi.public_pilot_miner import main as miner_main
from umi.public_pilot_readiness import (
    PUBLIC_PILOT_READINESS_MARKER_PREFIX,
    PUBLIC_PILOT_READINESS_SCHEMA,
    PUBLIC_PILOT_READINESS_SIGNATURE_DOMAIN,
    PublicPilotReadinessProof,
    ReadyForCasePayload,
    ReadyToIssuePayload,
    parse_and_verify_public_pilot_readiness_marker,
    parse_public_pilot_readiness_marker,
    parse_public_pilot_readiness_payload_token,
    public_pilot_readiness_digest,
    public_pilot_readiness_marker,
    public_pilot_readiness_payload_token,
    sign_public_pilot_readiness,
    verify_public_pilot_readiness,
)

_NOW_UNIX_S = 1_800_000_000
_EXPIRES_AT = "2099-01-01T00:00:01Z"
_EXPIRES_AT_UNIX_S = calendar.timegm(time.strptime(_EXPIRES_AT, "%Y-%m-%dT%H:%M:%SZ"))


def _common_payload(wallet, **changes):
    values = {
        "schema": PUBLIC_PILOT_READINESS_SCHEMA,
        "repository_id": 123_456_789,
        "issue_id": 987_654_321,
        "issue_node_id": "I_kwDOExample123",
        "issue_number": 42,
        "campaign_id": CAMPAIGN_ID,
        "challenge_nonce": "11" * 32,
        "miner_hotkey": wallet.hotkey.ss58_address,
        "miner_account_id32": account_id32(wallet.hotkey.ss58_address).hex(),
        "expected_uid": 7,
        "expires_at": _EXPIRES_AT,
    }
    values.update(changes)
    return values


def _ready_for_case(wallet, **changes) -> ReadyForCasePayload:
    return ReadyForCasePayload(**_common_payload(wallet, action="ready_for_case", **changes))


def _ready_to_issue(wallet, **changes) -> ReadyToIssuePayload:
    return ReadyToIssuePayload(
        **_common_payload(
            wallet,
            action="ready_to_issue",
            predecessor_authorization_id="22" * 32,
            case_manifest_sha256="33" * 32,
            expected_origin="https://8.8.8.8:443",
            **changes,
        )
    )


@pytest.mark.parametrize(
    ("crypto_type", "expected_scheme", "payload_factory"),
    [
        (bt.sp_core.CRYPTO_SR25519, "sr25519", _ready_for_case),
        (bt.sp_core.CRYPTO_ED25519, "ed25519", _ready_to_issue),
    ],
)
def test_readiness_marker_round_trip_is_exact_and_hotkey_signed(
    crypto_type, expected_scheme, payload_factory
):
    wallet = dev_wallet("//Readiness", crypto_type=crypto_type)
    payload = payload_factory(wallet)

    proof = sign_public_pilot_readiness(payload, wallet=wallet, now_unix_s=_NOW_UNIX_S)
    marker = public_pilot_readiness_marker(proof)

    prefix, token, scheme, signature = marker.split(" ")
    assert prefix == PUBLIC_PILOT_READINESS_MARKER_PREFIX
    assert token == public_pilot_readiness_payload_token(payload)
    assert scheme == expected_scheme
    assert re.fullmatch(r"0x[0-9a-f]{128}", signature)
    assert marker.isascii()
    assert "\n" not in marker
    assert parse_public_pilot_readiness_marker(marker) == proof
    assert parse_public_pilot_readiness_marker(marker + "\n") == proof
    assert (
        parse_and_verify_public_pilot_readiness_marker(
            marker + "\n",
            expected_payload=payload,
            now_unix_s=_NOW_UNIX_S,
        )
        == proof
    )


def test_digest_is_domain_separated_sha256_of_exact_canonical_payload():
    payload = _ready_for_case(dev_wallet("//Digest"))

    assert (
        public_pilot_readiness_digest(payload)
        == hashlib.sha256(
            PUBLIC_PILOT_READINESS_SIGNATURE_DOMAIN + canonical_json_bytes(payload)
        ).digest()
    )


def test_action_payloads_have_exact_distinct_key_sets():
    wallet = dev_wallet("//Shape")
    common = {
        "schema",
        "action",
        "repository_id",
        "issue_id",
        "issue_node_id",
        "issue_number",
        "campaign_id",
        "challenge_nonce",
        "miner_hotkey",
        "miner_account_id32",
        "expected_uid",
        "expires_at",
    }

    assert set(_ready_for_case(wallet).model_dump(mode="json", by_alias=True)) == common
    assert set(_ready_to_issue(wallet).model_dump(mode="json", by_alias=True)) == common | {
        "predecessor_authorization_id",
        "case_manifest_sha256",
        "expected_origin",
    }


@pytest.mark.parametrize(
    "change",
    [
        {"campaign_id": "00" * 32},
        {"miner_account_id32": "00" * 32},
        {"issue_node_id": "node id"},
        {"expires_at": "2027-02-01T00:00:01+00:00"},
        {"expires_at": "2027-02-30T00:00:01Z"},
        {"repository_id": True},
        {"issue_id": 0},
        {"expected_uid": 65_536},
    ],
)
def test_common_payload_rejects_noncanonical_or_unbound_fields(change):
    with pytest.raises(ValidationError):
        _ready_for_case(dev_wallet("//Invalid"), **change)


def test_ready_to_issue_requires_exact_predecessor_manifest_and_public_origin():
    wallet = dev_wallet("//Issue")
    values = _common_payload(
        wallet,
        action="ready_to_issue",
        predecessor_authorization_id="22" * 32,
        case_manifest_sha256="33" * 32,
        expected_origin="https://8.8.8.8:443",
    )

    for field in ("predecessor_authorization_id", "case_manifest_sha256", "expected_origin"):
        missing = dict(values)
        missing.pop(field)
        with pytest.raises(ValidationError):
            ReadyToIssuePayload(**missing)
    with pytest.raises(ValidationError):
        ReadyToIssuePayload(**{**values, "expected_origin": "https://127.0.0.1:443"})
    with pytest.raises(ValidationError):
        ReadyForCasePayload(**{**_common_payload(wallet), **values, "action": "ready_for_case"})


def test_payload_token_rejects_padding_noncanonical_json_duplicates_and_extra_keys():
    payload = _ready_for_case(dev_wallet("//Canonical"))
    token = public_pilot_readiness_payload_token(payload)

    with pytest.raises(ValueError):
        parse_public_pilot_readiness_payload_token(token + "=")

    document = payload.model_dump(mode="json", by_alias=True)
    pretty = json.dumps(document, indent=2).encode()
    with pytest.raises(ValueError):
        parse_public_pilot_readiness_payload_token(base64url_encode(pretty))

    canonical = canonical_json_bytes(payload)
    duplicate = canonical.replace(
        b'"action":"ready_for_case"',
        b'"action":"ready_for_case","action":"ready_for_case"',
        1,
    )
    with pytest.raises(ValueError):
        parse_public_pilot_readiness_payload_token(base64url_encode(duplicate))

    document["unexpected"] = True
    with pytest.raises(ValueError):
        parse_public_pilot_readiness_payload_token(base64url_encode(canonical_json_bytes(document)))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda marker: " " + marker,
        lambda marker: marker + "\n\n",
        lambda marker: marker + "\r\n",
        lambda marker: marker + " \n",
        lambda marker: marker + "\n ",
        lambda marker: marker.replace(" ", "  ", 1),
        lambda marker: marker.replace(" sr25519 ", " Sr25519 "),
        lambda marker: marker[:-1] + "G",
    ],
)
def test_marker_parser_rejects_any_shape_drift(mutate):
    wallet = dev_wallet("//Marker")
    proof = sign_public_pilot_readiness(
        _ready_for_case(wallet), wallet=wallet, now_unix_s=_NOW_UNIX_S
    )
    marker = public_pilot_readiness_marker(proof)

    with pytest.raises(ValueError):
        parse_public_pilot_readiness_marker(mutate(marker))


def test_verify_rejects_payload_signature_scheme_context_and_expiry_tampering():
    wallet = dev_wallet("//Verify")
    payload = _ready_for_case(wallet)
    proof = sign_public_pilot_readiness(payload, wallet=wallet, now_unix_s=_NOW_UNIX_S)

    changed_payload = _ready_for_case(wallet, issue_number=43)
    with pytest.raises(ValueError, match="expected payload"):
        verify_public_pilot_readiness(
            proof,
            expected_payload=changed_payload,
            now_unix_s=_NOW_UNIX_S,
        )

    forged_payload_proof = PublicPilotReadinessProof(
        payload=changed_payload,
        signature_scheme=proof.signature_scheme,
        signature=proof.signature,
    )
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_public_pilot_readiness(
            forged_payload_proof,
            expected_payload=changed_payload,
            now_unix_s=_NOW_UNIX_S,
        )

    wrong_scheme = proof.model_copy(update={"signature_scheme": "ed25519"})
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_public_pilot_readiness(
            wrong_scheme,
            expected_payload=payload,
            now_unix_s=_NOW_UNIX_S,
        )

    with pytest.raises(ValueError, match="expired"):
        verify_public_pilot_readiness(
            proof,
            expected_payload=payload,
            now_unix_s=_EXPIRES_AT_UNIX_S,
        )


def test_signing_rejects_a_payload_for_another_wallet_before_returning_a_proof():
    payload = _ready_for_case(dev_wallet("//Expected"))

    with pytest.raises(ValueError, match="wallet hotkey"):
        sign_public_pilot_readiness(
            payload,
            wallet=dev_wallet("//Different"),
            now_unix_s=_NOW_UNIX_S,
        )


def test_authorize_cli_emits_only_one_exact_marker(monkeypatch, capsys):
    wallet = dev_wallet("//CLI")
    payload = _ready_to_issue(wallet)
    token = public_pilot_readiness_payload_token(payload)
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: wallet)

    miner_main(
        [
            "authorize",
            "--payload-token",
            token,
            "--wallet-name",
            "miner",
            "--hotkey",
            "public-pilot",
        ]
    )

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    marker = captured.out.removesuffix("\n")
    assert public_pilot_readiness_marker(parse_public_pilot_readiness_marker(marker)) == marker
    parse_and_verify_public_pilot_readiness_marker(
        marker,
        expected_payload=payload,
        now_unix_s=_NOW_UNIX_S,
    )


def test_authorize_cli_fails_closed_without_stdout_for_the_wrong_wallet(monkeypatch, capsys):
    payload = _ready_for_case(dev_wallet("//Claimed"))
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: dev_wallet("//Selected"))

    with pytest.raises(SystemExit) as raised:
        miner_main(
            [
                "authorize",
                "--payload-token",
                public_pilot_readiness_payload_token(payload),
                "--wallet-name",
                "miner",
                "--hotkey",
                "public-pilot",
            ]
        )

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert "wallet hotkey does not match" in captured.err
