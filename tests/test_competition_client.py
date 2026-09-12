from __future__ import annotations

import json
import sqlite3

import httpx
import pytest

from umi.competition_api import create_app
from umi.competition_client import (
    MAX_RECEIPT_BYTES,
    CompetitionSubmissionError,
    submit_signed_submission,
    validate_intake_origin,
)
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import policy as policy
from .test_open_competition import snapshot, submission


def receipt_for(policy, signed):
    return {
        "schema": "umi-competition-admission/2",
        "policy_sha256": digest(policy),
        "submission_sha256": digest(signed.submission),
        "accepted_block": 110,
        "registration_snapshot_sha256": digest(snapshot()),
        "registration_snapshot": snapshot().model_dump(mode="json", by_alias=True),
        "registration_source": "verifier_attested_finality",
        "observed_uid": 6,
        "status": "accepted_no_weight",
        "chain_submission_authorized": False,
    }


async def test_client_to_intake_is_idempotent_across_restart(policy, tmp_path):
    signed = submission(policy)

    async def current():
        return snapshot()

    async def send():
        store = CompetitionStore(tmp_path / "state", policy)
        transport = httpx.ASGITransport(
            app=create_app(store, current, registration_source="verifier_attested_finality")
        )
        return await submit_signed_submission(
            origin="https://intake.example", policy=policy, signed=signed, transport=transport
        )

    first = await send()
    assert first == await send()
    assert first.status == "accepted_no_weight"
    assert first.chain_submission_authorized is False
    store = CompetitionStore(tmp_path / "state", policy)
    assert len(store.submissions()) == 1


async def test_client_posts_only_canonical_public_body(policy):
    signed = submission(policy)

    def serve(request):
        assert request.method == "POST"
        assert str(request.url) == "https://intake.example/v1/competition/submissions"
        assert request.content == canonical_json_bytes(signed)
        assert request.headers["accept-encoding"] == "identity"
        assert "authorization" not in request.headers
        return httpx.Response(200, json=receipt_for(policy, signed))

    await submit_signed_submission(
        origin="https://intake.example/",
        policy=policy,
        signed=signed,
        transport=httpx.MockTransport(serve),
    )


@pytest.mark.parametrize("status", [301, 302, 307, 308, 409, 413, 429, 500, 503])
async def test_client_never_follows_redirect_or_echoes_error_body(policy, status):
    requests = []

    def serve(request):
        requests.append(request)
        return httpx.Response(status, text="PRIVATE SERVER DATA", headers={"location": "/other"})

    with pytest.raises(CompetitionSubmissionError) as caught:
        await submit_signed_submission(
            origin="https://intake.example",
            policy=policy,
            signed=submission(policy),
            transport=httpx.MockTransport(serve),
        )
    assert len(requests) == 1
    assert caught.value.status_code == status
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize(
    "change",
    [
        {"policy_sha256": "0" * 64},
        {"submission_sha256": "0" * 64},
        {"accepted_block": 1},
        {"accepted_block": 2000},
        {"observed_uid": 256},
        {"observed_uid": 247},
        {"registration_source": "rehearsal_snapshot"},
        {"registration_snapshot_sha256": "00" * 32},
        {"chain_submission_authorized": True},
        {"status": "rewards_active"},
        {"extra": "PRIVATE DATA"},
    ],
)
async def test_client_rejects_unbound_or_reward_claiming_receipts(policy, change):
    signed = submission(policy)

    def serve(_request):
        return httpx.Response(200, json={**receipt_for(policy, signed), **change})

    with pytest.raises(CompetitionSubmissionError):
        await submit_signed_submission(
            origin="https://intake.example",
            policy=policy,
            signed=signed,
            transport=httpx.MockTransport(serve),
        )


@pytest.mark.parametrize(
    "body,headers",
    [
        (b"x" * (MAX_RECEIPT_BYTES + 1), {"content-type": "application/json"}),
        (b"PRIVATE INVALID JSON", {"content-type": "application/json"}),
        (b"{}", {"content-type": "text/plain"}),
        (b"{}", {"content-type": "application/json", "content-encoding": "br"}),
    ],
)
async def test_client_rejects_unbounded_or_malformed_reply(policy, body, headers):
    def serve(_request):
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(body))

    with pytest.raises(CompetitionSubmissionError) as caught:
        await submit_signed_submission(
            origin="https://intake.example",
            policy=policy,
            signed=submission(policy),
            transport=httpx.MockTransport(serve),
        )
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize(
    "origin",
    [
        "http://intake.example",
        "https://user:password@intake.example",
        "https://intake.example/path",
        "https://intake.example?key=secret",
        "https://intake.example#part",
        "https://intake.example:0",
        "https://intake.example:65536",
        "https://intake.example\n",
    ],
)
def test_client_origin_is_explicit_https_without_credentials(origin):
    with pytest.raises(ValueError):
        validate_intake_origin(origin)


async def test_fixture_receipt_cannot_be_reclassified_on_restart(policy, tmp_path):
    signed = submission(policy)
    store = CompetitionStore(tmp_path / "state", policy)
    original = store.admit(signed, snapshot(), 110)
    assert original["registration_source"] == "rehearsal_snapshot"

    async def current():
        return snapshot(111)

    for source in ("rehearsal_snapshot", "verifier_attested_finality"):
        reopened = CompetitionStore(tmp_path / "state", policy)
        app = create_app(reopened, current, registration_source=source)
        with pytest.raises(CompetitionSubmissionError):
            await submit_signed_submission(
                origin="https://intake.example",
                policy=policy,
                signed=signed,
                transport=httpx.ASGITransport(app=app),
            )
        assert reopened.submission_by_digest(digest(signed.submission))["receipt"] == original


async def test_zero_or_misbound_snapshot_is_not_accepted_even_with_valid_digest(policy):
    signed = submission(policy)
    wrong_snapshot = snapshot().model_copy(update={"registrations": ()})
    receipt = receipt_for(policy, signed)
    receipt.update(
        {
            "registration_snapshot": wrong_snapshot.model_dump(mode="json", by_alias=True),
            "registration_snapshot_sha256": digest(wrong_snapshot),
        }
    )
    with pytest.raises(CompetitionSubmissionError, match="registration_mismatch"):
        await submit_signed_submission(
            origin="https://intake.example",
            policy=policy,
            signed=signed,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=receipt)),
        )


async def test_old_v1_receipts_remain_unchanged_and_unverified(policy, tmp_path):
    signed = submission(policy)
    store = CompetitionStore(tmp_path / "state", policy)
    receipt = store.admit(signed, snapshot(), 110)
    receipt["schema"] = "umi-competition-admission/1"
    del receipt["registration_source"]
    del receipt["registration_snapshot"]
    original = canonical_json_bytes(receipt)
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE submissions SET receipt=?", (original,))
    reopened = CompetitionStore(store.directory, policy)
    assert (
        reopened.admit(signed, snapshot(120), 120, registration_source="verifier_attested_finality")
        == receipt
    )
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT receipt FROM submissions").fetchone()[0] == original
    with pytest.raises(CompetitionSubmissionError, match="invalid_receipt"):
        await submit_signed_submission(
            origin="https://intake.example",
            policy=policy,
            signed=signed,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=receipt)),
        )


async def test_verified_historical_receipt_keeps_its_original_snapshot(policy, tmp_path):
    signed = submission(policy)
    store = CompetitionStore(tmp_path / "state", policy)
    original = store.admit(
        signed, snapshot(), 110, registration_source="verifier_attested_finality"
    )

    async def current():
        return snapshot(120).model_copy(update={"registrations": ()})

    app = create_app(store, current, registration_source="verifier_attested_finality")
    receipt = await submit_signed_submission(
        origin="https://intake.example",
        policy=policy,
        signed=signed,
        transport=httpx.ASGITransport(app=app),
    )
    assert receipt.model_dump(mode="json", by_alias=True) == original
    assert receipt.registration_snapshot.block == 110


async def test_bad_signature_is_rejected_before_network(policy):
    signed = submission(policy)
    broken = signed.model_copy(
        update={"signature": signed.signature.model_copy(update={"signature": "0x" + "00" * 64})}
    )

    def forbidden(_request):
        pytest.fail("invalid submission must not reach transport")

    with pytest.raises(ValueError):
        await submit_signed_submission(
            origin="https://intake.example",
            policy=policy,
            signed=broken,
            transport=httpx.MockTransport(forbidden),
        )


def test_submit_cli_uses_existing_signed_object(policy, tmp_path, monkeypatch, capsys):
    from umi import competition_client
    from umi.competition_cli import main

    signed = submission(policy)
    for name, obj in (("policy", policy), ("submission", signed)):
        (tmp_path / (name + ".json")).write_bytes(canonical_json_bytes(obj))

    async def send(**kwargs):
        assert kwargs["signed"] == signed
        assert kwargs["origin"] == "https://intake.example"
        return competition_client.AdmissionReceipt.model_validate_json(
            canonical_json_bytes(receipt_for(policy, signed))
        )

    monkeypatch.setattr(competition_client, "submit_signed_submission", send)
    main(
        [
            "--policy",
            str(tmp_path / "policy.json"),
            "submit",
            "--submission",
            str(tmp_path / "submission.json"),
            "--origin",
            "https://intake.example",
        ]
    )
    assert json.loads(capsys.readouterr().out)["chain_submission_authorized"] is False
