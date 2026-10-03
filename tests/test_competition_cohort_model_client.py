"""Public model client against native upload/preservation/intake; synthetic finality."""

import asyncio
import hashlib
from contextlib import asynccontextmanager, suppress

import bittensor as bt
import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_model_client as client
from umi.competition_artifacts import verify_preserved_bundle
from umi.competition_client import CompetitionSubmissionError
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_intake import CohortIntake
from umi.competition_cohort_model_upload import CohortModelUploads
from umi.competition_cohort_model_upload_http import model_upload_routes
from umi.competition_cohort_participation import (
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_commands import COMMAND_HANDLERS
from umi.competition_commands.arguments import build_parser
from umi.concurrency import run_owned_thread
from umi.open_competition import SignedSubmission, digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_upload import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_upload import (
    delivery as delivery,
)
from .test_competition_cohort_model_upload import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_upload import (
    policy as policy,
)
from .test_competition_cohort_model_upload import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_upload import (
    recovery as recovery,
)
from .test_competition_cohort_model_upload import (
    runtime as runtime,
)
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


def options(h, transport=None):
    return dict(
        origin="https://intake.example",
        policy=h.intake.policy,
        request=h.request,
        source=h.source,
        wallet=wallet("Alice"),
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="coordinator_chunked_v1",
        ),
        retry_seconds=0.001,
        transport=transport or httpx.ASGITransport(h.app),
    )


@asynccontextmanager
async def preservation(h):
    async def worker():
        while True:
            await run_owned_thread(h.owner.poll_once)
            await asyncio.sleep(0.005)

    task = asyncio.create_task(worker())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


def restart(h):
    h.intake = CohortIntake(h.intake.config, h.intake.policy, eligible_tracks=("endpoint", "model"))
    h.owner = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    h.app = FastAPI()
    h.app.include_router(
        cohort_routes(h.intake, h.capture, maximum_body_bytes=4 * 1024**2, models=h.owner)
    )
    h.app.include_router(model_upload_routes(h.owner, h.capture))


async def test_signed_history_selects_legacy_delivery(delivery, monkeypatch):
    h = delivery
    args = options(h)
    args.pop("delivery")
    discovered = []
    native_discovery = client.fetch_model_delivery_profile

    async def discover(**values):
        result = await native_discovery(**values)
        discovered.append(result)
        return result

    monkeypatch.setattr(client, "fetch_model_delivery_profile", discover)
    async with preservation(h):
        receipt = await asyncio.wait_for(client.submit_cohort_model(**args), 15)

    assert receipt.status == "pending_attestation"
    assert discovered == [
        ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="coordinator_chunked_v1",
        )
    ]


async def test_public_upload_recovers_outage_throttle_lost_ack_and_restart(delivery, monkeypatch):
    h = delivery
    first_size = h.request.signed_submission.submission.model_bundle.files[0].size_bytes
    monkeypatch.setattr(client, "CHUNK_BYTES", min(32, first_size // 2))
    native = httpx.ASGITransport(h.app)
    attempted = []
    lost = set()
    first_put = asyncio.Event()

    async def send(wire):
        attempted.append((wire.method, wire.url.path, wire.content))
        if len(attempted) == 1:
            raise httpx.ConnectError("private failure")
        if len(attempted) == 2:
            return httpx.Response(429)
        if wire.method == "PUT":
            response = await native.handle_async_request(wire)
            assert response.status_code == 200
            first_put.set()
            await asyncio.Event().wait()  # committed but client dies before acknowledgement
        return await native.handle_async_request(wire)

    task = asyncio.create_task(client.submit_cohort_model(**options(h, httpx.MockTransport(send))))
    await asyncio.wait_for(first_put.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    key = digest(h.request)
    offset = h.owner.status(key)["file_offsets"][0]
    assert 0 < offset < first_size
    assert h.intake.receipt(h.request) is None
    captures = h.captures
    restart(h)
    native = httpx.ASGITransport(h.app)
    writes = []
    enrollments = []
    reserved = []

    async def resume(wire):
        if wire.method == "POST" and wire.url.path.endswith("model-uploads"):
            reserved.append(wire.content)
        if wire.method == "PUT":
            writes.append((wire.url.path, int(wire.url.params["offset"])))
        if wire.url.path.endswith("participation"):
            assert h.owner.status(key)["payload_preserved"]
            enrollments.append(wire.content)
        response = await native.handle_async_request(wire)
        if response.status_code == 503:
            return response  # preservation can hold the native per-bundle lock
        assert response.status_code == 200
        # Each operation may commit before the caller loses its reply.
        group = "participation" if wire.url.path.endswith("participation") else wire.method
        if group not in lost:
            lost.add(group)
            await response.aread()
            raise httpx.ReadError("private lost response")
        return response

    async with preservation(h):
        receipt = await asyncio.wait_for(
            client.submit_cohort_model(**options(h, httpx.MockTransport(resume))), 20
        )
    assert writes[0] == (f"/v1/competition/model-uploads/{key}/files/0", offset)
    assert reserved and set(reserved) == {canonical_json_bytes(h.request)}
    assert len(enrollments) == 2 and set(enrollments) == {canonical_json_bytes(h.request)}
    assert receipt.status == "pending_attestation" and not receipt.rewards_active
    assert h.captures == captures + 1  # admission only; reservation replay needs no live finality
    sub = h.request.signed_submission.submission
    assert (
        verify_preserved_bundle(sub.model_bundle, h.owner.archive, h.intake.policy)
        == sub.model_revision
    )
    restart(h)
    again = await asyncio.wait_for(client.submit_cohort_model(**options(h)), 5)
    assert again == receipt


@pytest.mark.parametrize("failure", ["wrong-wallet", "bytes", "hardlink", "symlink"])
async def test_local_rejections_send_nothing(delivery, failure, tmp_path):
    h = delivery
    args = options(h, httpx.MockTransport(lambda _: pytest.fail("must not send")))
    record = h.request.signed_submission.submission.model_bundle.files[0]
    path = h.source / record.path
    if failure == "wrong-wallet":
        args["wallet"] = wallet("Bob")
    elif failure == "bytes":
        path.write_bytes(b"!" * record.size_bytes)
    elif failure == "hardlink":
        (tmp_path / "linked").hardlink_to(path)
    else:
        original = tmp_path / "original"
        path.rename(original)
        path.symlink_to(original)
    with pytest.raises((OSError, ValueError)):
        await client.submit_cohort_model(**args)


async def test_changed_source_between_chunks_stops_before_signing_more(delivery, monkeypatch):
    h = delivery
    monkeypatch.setattr(client, "CHUNK_BYTES", 1)
    native = httpx.ASGITransport(h.app)
    puts = []
    target = h.source / h.request.signed_submission.submission.model_bundle.files[0].path

    async def serve(wire):
        response = await native.handle_async_request(wire)
        if wire.method == "PUT":
            puts.append(wire.url.path)
            if len(puts) == 1:
                data = target.read_bytes()
                target.write_bytes(b"!" + data[1:])
        return response

    with pytest.raises(ValueError, match="source changed"):
        await asyncio.wait_for(
            client.submit_cohort_model(**options(h, httpx.MockTransport(serve))), 10
        )
    assert puts.count(puts[0]) == 1
    assert h.intake.receipt(h.request) is None


@pytest.mark.parametrize(
    "failure",
    [
        "wrong-model",
        "offset",
        "bool-offset",
        "early-preserved",
        "duplicate",
        "reward-claim",
        "redirect",
        "encoded",
        "oversize",
        "rejected",
    ],
)
async def test_invalid_remote_status_never_enrolls_or_follows_redirect(delivery, failure):
    h = delivery
    seen = []

    async def serve(wire):
        seen.append(wire)
        assert wire.method == "POST" and wire.url.path.endswith("model-uploads")
        response = await httpx.ASGITransport(h.app).handle_async_request(wire)
        raw = await response.aread()
        import json

        body = json.loads(raw)
        if failure == "wrong-model":
            body["model_sha256"] = "ff" * 32
        elif failure == "offset":
            body["file_offsets"][0] = -1
        elif failure == "bool-offset":
            body["file_offsets"][0] = False
        elif failure == "early-preserved":
            body["payload_preserved"] = True
        elif failure == "duplicate":
            body["complete_files"] = [0, 0]
        elif failure == "reward-claim":
            body["artifact_review_certified"] = True
        elif failure == "redirect":
            return httpx.Response(307, headers={"Location": "https://elsewhere.example"})
        elif failure == "encoded":
            return httpx.Response(200, headers={"Content-Encoding": "identity,identity"}, json=body)
        elif failure == "oversize":
            return httpx.Response(
                200, content=b" " * (512 * 1024 + 1), headers={"Content-Type": "application/json"}
            )
        elif failure == "rejected":
            return httpx.Response(422)
        return httpx.Response(200, json=body)

    with pytest.raises(CompetitionSubmissionError):
        await asyncio.wait_for(
            client.submit_cohort_model(**options(h, httpx.MockTransport(serve))), 10
        )
    assert len(seen) == 1 and h.intake.receipt(h.request) is None


async def test_empty_file_is_uploaded_and_verified(delivery):
    h = delivery
    sub = h.request.signed_submission.submission
    files = list(sub.model_bundle.files)
    files[0] = files[0].model_copy(
        update={"size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    )
    (h.source / files[0].path).write_bytes(b"")
    bundle = sub.model_bundle.model_copy(update={"files": tuple(files)})
    sub = sub.model_copy(update={"model_bundle": bundle, "model_revision": digest(bundle)})
    consent = h.request.consent.consent.model_copy(update={"submission_sha256": digest(sub)})
    h.request = CohortParticipationRequest(
        signed_submission=SignedSubmission(
            submission=sub, signature=sign_object(sub, wallet("Alice"))
        ),
        consent=SignedCohortParticipationConsent(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )
    async with preservation(h):
        result = await asyncio.wait_for(client.submit_cohort_model(**options(h)), 15)
    assert result.status == "pending_attestation"
    assert h.owner.status(digest(h.request))["payload_preserved"]


def test_public_command_routes_to_client_and_returns_only_receipt(delivery, monkeypatch, capsys):
    h = delivery
    request_path = h.source.parent / "request.json"
    request_path.write_bytes(canonical_json_bytes(h.request))
    args = build_parser().parse_args(
        [
            "--policy",
            "policy.json",
            "submit-cohort-model",
            "--request",
            str(request_path),
            "--source",
            str(h.source),
            "--origin",
            "https://intake.example",
            "--wallet-name",
            "miner",
            "--hotkey-name",
            "hk",
            "--wallet-path",
            "private-wallet",
        ]
    )
    used = []
    actual = client.submit_cohort_model

    def opened(**kwargs):
        used.append(kwargs)
        return wallet("Alice")

    async def send(**kwargs):
        assert kwargs["request"] == h.request
        kwargs.update(transport=httpx.ASGITransport(h.app), retry_seconds=0.001)
        async with preservation(h):
            return await asyncio.wait_for(actual(**kwargs), 15)

    monkeypatch.setattr(bt, "Wallet", opened)
    monkeypatch.setattr(client, "submit_cohort_model", send)
    result = COMMAND_HANDLERS[args.command](args, h.intake.policy)
    assert result["status"] == "pending_attestation" and not result["rewards_active"]
    assert used == [{"name": "miner", "hotkey": "hk", "path": "private-wallet"}]
    output = capsys.readouterr()
    assert not output.out and "model_payload_preserved" in output.err
    assert "private-wallet" not in output.err
