"""Native intake -> private reviewer queue -> public certificate, with fake chain ports."""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cli import execute
from umi.competition_client import CompetitionSubmissionError
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_admission_worker import (
    CohortAdmissionWorker,
    CohortAdmissionWorkerConfig,
    run_admission_worker,
)
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_client import fetch_cohort_admission, submit_cohort_participation
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_records import read_participation
from umi.competition_commands.arguments import build_parser
from umi.competition_store import AdmissionCapacity
from umi.concurrency import run_owned_thread
from umi.open_competition import digest, sign_object
from umi.private_files import lock_private_file
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_admission_signer import closed_source
from .test_competition_cohort_admission_signer import harness as harness
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import request_for
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_historical_registration import archive as archive
from .test_open_competition import policy as policy
from .test_open_competition import submission, wallet


@pytest.fixture
def relay(harness):
    h = harness
    h.intake = CohortIntake(h.intake_config, h.archive.chain.policy)
    h.queue = CohortAdmissionQueue(h.intake)
    h.request = read_participation(h.raw).request
    h.cohort = h.request.consent.consent.cohort_sha256
    h.consent = digest(h.request.consent.consent)

    def worker(name="Charlie", **kwargs):
        signer = h.worker(name)

        async def history(cohort):
            return await run_owned_thread(h.queue.history, cohort)

        signer.history = history
        return CohortAdmissionWorker(h.queue, signer, **kwargs)

    h.reviewer = worker
    h.app = FastAPI()
    h.app.include_router(
        cohort_routes(
            h.intake,
            h.archive.reviewer.collect,
            maximum_body_bytes=2 * 1024**2,
            archive=h.archive.reviewer.retained_archive,
        )
    )
    return h


async def submit(h):
    return await submit_cohort_participation(
        origin="https://intake.example",
        policy=h.archive.chain.policy,
        request=h.request,
        transport=httpx.ASGITransport(h.app),
    )


async def status(h):
    return await fetch_cohort_admission(
        origin="https://intake.example",
        policy=h.archive.chain.policy,
        request=h.request,
        transport=httpx.ASGITransport(h.app),
    )


async def test_two_automatic_reviewers_publish_native_certificate_visible_to_miner(relay):
    h = relay
    receipt = await submit(h)
    assert receipt.record_sha256 == digest(read_participation(h.raw))
    assert h.queue.evidence(h.cohort, h.consent) == (h.raw, h.archive.raw, h.archive.metadata)
    assert (await status(h)).status == "pending_attestation"
    first = await h.reviewer("Charlie").poll_once()
    assert first["votes_published"] == 1 and first["certificates_published"] == 0
    assert (await status(h)).certificate is None
    second = await h.reviewer("Dave").poll_once()
    assert second["certificates_published"] == 1
    result = await status(h)
    assert (
        result.status == "admission_certified"
        and result.certificate.admission == receipt.proposed_admission
    )
    assert result.chain_submission_authorized is False
    assert (await h.reviewer("Charlie").poll_once())["votes_published"] == 0
    assert len(h.calls) == 2


async def test_lost_queue_commit_ack_and_restart_do_not_resign(relay, monkeypatch):
    h = relay
    await submit(h)
    first = h.reviewer("Charlie")
    publish = h.queue.publish_vote

    def lost(vote, capture):
        publish(vote, capture)
        raise OSError("acknowledgement lost")

    monkeypatch.setattr(h.queue, "publish_vote", lost)
    assert (await first.poll_once())["retry_count"] == 1
    assert len(h.calls) == 1
    monkeypatch.setattr(h.queue, "publish_vote", publish)
    h.queue = CohortAdmissionQueue(CohortIntake(h.intake_config, h.archive.chain.policy))
    assert (await h.reviewer("Charlie").poll_once())["votes_published"] == 0
    assert (await h.reviewer("Dave").poll_once())["certificates_published"] == 1
    assert len(h.calls) == 2 and (await status(h)).status == "admission_certified"


async def test_failed_queue_commit_restores_from_retained_signer_intent(relay, monkeypatch):
    h = relay
    await submit(h)
    first = h.reviewer("Charlie")
    publish = h.queue.publish_vote

    def failed(*_):
        raise OSError("disk unavailable")

    monkeypatch.setattr(h.queue, "publish_vote", failed)
    assert (await first.poll_once())["retry_count"] == 1
    assert len(h.calls) == 1
    with h.queue._connection() as (db, _):
        db.execute("DELETE FROM cohort_admission_artifacts")
    monkeypatch.setattr(h.queue, "publish_vote", publish)
    assert (await h.reviewer("Charlie").poll_once())["votes_published"] == 1
    assert h.queue.evidence(h.cohort, h.consent)[1:] == (h.archive.raw, h.archive.metadata)
    assert len(h.calls) == 1


async def test_api_retries_original_archive_without_requiring_new_capture(relay, monkeypatch):
    h = relay
    original = h.archive.reviewer._retained_archive
    monkeypatch.setattr(
        h.archive.reviewer,
        "_retained_archive",
        lambda _: (_ for _ in ()).throw(FileNotFoundError("missing")),
    )
    with pytest.raises(CompetitionSubmissionError):
        await submit(h)
    assert h.intake.receipt(h.request)["record_sha256"] == digest(read_participation(h.raw))
    monkeypatch.setattr(h.archive.reviewer, "_retained_archive", original)
    monkeypatch.setattr(h.archive.reviewer, "collect", AsyncMock(side_effect=OSError("offline")))
    assert (await submit(h)).proposed_admission == h.receipt.proposed_admission


async def test_archive_capacity_failure_is_atomic_and_can_be_enlarged(relay):
    h = relay
    h.intake.capacity = AdmissionCapacity(
        maximum_bytes=len(h.raw) + len(h.archive.raw) + len(h.archive.metadata) - 1
    )
    with pytest.raises(ValueError, match="capacity"):
        h.queue.attach_evidence(h.cohort, h.consent, h.archive.raw, h.archive.metadata)
    with h.queue._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_artifacts").fetchone()[0] == 0
    h.intake.capacity = AdmissionCapacity()
    assert (await submit(h)).proposed_admission == h.receipt.proposed_admission


@pytest.mark.parametrize("failure", ["artifact", "vote", "certificate"])
async def test_corrupt_retained_queue_data_never_becomes_a_certificate(relay, failure):
    h = relay
    await submit(h)
    if failure == "artifact":
        with h.queue._connection() as (db, _):
            db.execute("UPDATE cohort_admission_artifacts SET body=?", (b"{}",))
        assert (await h.reviewer().poll_once())["retry_count"] == 1
        assert not h.calls
    else:
        await h.reviewer("Charlie").poll_once()
        if failure == "vote":
            with h.queue._connection() as (db, _):
                db.execute("UPDATE cohort_admission_votes SET body=?", (b"{}",))
            assert (await h.reviewer("Dave").poll_once())["retry_count"] == 1
            assert h.queue.certificate(h.cohort, h.consent) is None
        else:
            await h.reviewer("Dave").poll_once()
            with h.queue._connection() as (db, _):
                db.execute("UPDATE cohort_admission_certificates SET body=?", (b"{}",))
            with pytest.raises(CompetitionSubmissionError, match="admission_unavailable"):
                await status(h)


async def test_certification_after_intake_closes_replays_retained_seal_and_decision(relay):
    h = relay
    await submit(h)
    closed = closed_source(h)
    h.intake.seal(h.cohort, h.archive.capture, expected_tip_sha256=history_tip(h.source.history))
    h.intake.publish(
        closed.history, await h.archive.reviewer.collect(), closure_input=closed.closure
    )
    h.queue = CohortAdmissionQueue(CohortIntake(h.intake_config, h.archive.chain.policy))
    assert h.queue.history(h.cohort) == closed
    await h.reviewer("Charlie").poll_once()
    assert (await h.reviewer("Dave").poll_once())["certificates_published"] == 1
    assert (await status(h)).status == "admission_certified"


async def test_runner_owns_provider_lifecycle_and_stop(relay, monkeypatch, tmp_path):
    h = relay
    await submit(h)
    h.worker("Charlie")
    config = CohortAdmissionWorkerConfig(
        schema="umi-cohort-admission-worker-config/1",
        policy_sha256=digest(h.archive.chain.policy),
        intake=h.intake_config,
        signing=h.configs["Charlie"],
        chain=h.archive.chain.config,
        wallet_name="test",
        hotkey_name="default",
        wallet_path=str(tmp_path / "wallet"),
    )
    provider = h.archive.reviewer
    started, closed = AsyncMock(), AsyncMock()
    monkeypatch.setattr(provider, "start", started)
    monkeypatch.setattr(provider, "aclose", closed)
    monkeypatch.setattr(provider, "ensure_observer_running", lambda: None)
    stop = asyncio.Event()
    reports = []

    def report(value):
        reports.append(value)
        stop.set()

    result = await run_admission_worker(
        config,
        h.archive.chain.policy,
        wallet=wallet("Charlie"),
        provider_factory=lambda *a, **kw: provider,
        stop=stop,
        report=report,
    )
    assert result["status"] == "stopped" and reports[0]["votes_published"] == 1
    started.assert_awaited_once()
    closed.assert_awaited_once()


@pytest.mark.parametrize("failure", ["policy", "consent", "quorum", "reward_claim"])
async def test_public_client_rejects_wrong_certificate_or_scope(relay, failure):
    h = relay
    await submit(h)
    await h.reviewer("Charlie").poll_once()
    await h.reviewer("Dave").poll_once()
    value = (await status(h)).model_dump(mode="json", by_alias=True)
    if failure == "policy":
        value["policy_sha256"] = "ff" * 32
    elif failure == "consent":
        value["consent_sha256"] = "ff" * 32
    elif failure == "quorum":
        value["certificate"]["signatures"] = value["certificate"]["signatures"][:1]
    else:
        value["chain_submission_authorized"] = True
    with pytest.raises(CompetitionSubmissionError, match="invalid_admission_certificate"):
        await fetch_cohort_admission(
            origin="https://intake.example",
            policy=h.archive.chain.policy,
            request=h.request,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value)),
        )


async def test_certificate_commit_failure_rolls_back_vote_and_reuses_signature(relay):
    h = relay
    await submit(h)
    await h.reviewer("Charlie").poll_once()
    with h.queue._connection() as (db, _):
        db.execute(
            "CREATE TRIGGER deny_certificate BEFORE INSERT ON cohort_admission_certificates "
            "BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END"
        )
    assert (await h.reviewer("Dave").poll_once())["retry_count"] == 1
    assert len(h.calls) == 2
    with h.queue._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_votes").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_certificates").fetchone()[0] == 0
        db.execute("DROP TRIGGER deny_certificate")
    assert (await h.reviewer("Dave").poll_once())["certificates_published"] == 1
    assert len(h.calls) == 2


def second_request(h, scenario):
    original = request_for(scenario, block=h.archive.old.height)
    signed = submission(scenario["policy"], name="Bob")
    body = original.consent.consent.model_copy(
        update={
            "hotkey": signed.submission.hotkey,
            "submission_sha256": digest(signed.submission),
        }
    )
    return original.__class__(
        signed_submission=signed,
        consent=original.consent.__class__(
            consent=body,
            signature=sign_object(body, wallet("Bob")),
        ),
    )


async def test_missing_archive_does_not_starve_later_record_and_is_retried(relay, scenario):
    h = relay
    await submit(h)
    second = second_request(h, scenario)
    h.intake.retain(second, h.archive.capture)
    consents = sorted((h.consent, digest(second.consent.consent)))
    reviewer = h.reviewer(batch_size=1)
    missing = True
    original = h.queue.evidence

    def evidence(cohort, consent):
        if missing and consent == consents[0]:
            raise FileNotFoundError("not yet copied")
        return original(cohort, consent)

    h.queue.evidence = evidence

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    reviewer.signer.sign = sign
    assert (await reviewer.poll_once())["retry_count"] == 1
    assert (await reviewer.poll_once())["votes_published"] == 1
    assert (await reviewer.poll_once())["votes_published"] == 0
    missing = False
    assert (await reviewer.poll_once())["votes_published"] == 1


async def test_new_consent_accounts_for_retained_proof_bytes(relay, scenario):
    h = relay
    await submit(h)
    second = second_request(h, scenario)
    # Two records alone fit, but the retained metadata/proofs must also count.
    from umi.competition_cohort_intake import cohort_intake_bytes

    with h.queue._connection() as (db, _):
        used = cohort_intake_bytes(db)
    h.intake.capacity = AdmissionCapacity(maximum_bytes=used)
    with pytest.raises(ValueError, match="capacity"):
        h.intake.retain(second, h.archive.capture)
    assert h.intake.receipt(second) is None
    h.intake.capacity = AdmissionCapacity()
    assert h.intake.retain(second, h.archive.capture)["status"] == "pending_attestation"


async def test_unknown_status_and_retained_status_need_no_live_chain(relay, monkeypatch):
    h = relay
    await submit(h)
    await h.reviewer("Charlie").poll_once()
    await h.reviewer("Dave").poll_once()
    monkeypatch.setattr(h.archive.reviewer, "collect", AsyncMock(side_effect=OSError("offline")))
    assert (await status(h)).status == "admission_certified"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(h.app), base_url="https://x") as c:
        for consent in ("invalid", "ff" * 32):
            r = await c.get(f"/v1/competition/cohorts/{h.cohort}/admissions/{consent}")
            assert r.status_code == 404


@pytest.mark.parametrize("failure", ["redirect", "encoding", "bytes", "transport", "type"])
async def test_status_transport_is_bounded_and_never_follows_redirects(relay, failure):
    h = relay
    requests = []

    def response(request):
        requests.append(request)
        if failure == "transport":
            raise httpx.ReadError("private remote details")
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://untrusted.example"})
        headers = {"content-type": "application/json"}
        if failure == "encoding":
            headers["content-encoding"] = "unknown"
        if failure == "type":
            headers["content-type"] = "text/plain"
        return httpx.Response(200, headers=headers, content=b"x" * (128 * 1024 + 1))

    with pytest.raises(CompetitionSubmissionError) as error:
        await fetch_cohort_admission(
            origin="https://intake.example",
            policy=h.archive.chain.policy,
            request=h.request,
            transport=httpx.MockTransport(response),
        )
    assert len(requests) == 1 and "private remote details" not in str(error.value)


def worker_config(h, tmp_path):
    h.worker("Charlie")
    return CohortAdmissionWorkerConfig(
        schema="umi-cohort-admission-worker-config/1",
        policy_sha256=digest(h.archive.chain.policy),
        intake=h.intake_config,
        signing=h.configs["Charlie"],
        chain=h.archive.chain.config,
        wallet_name="test",
        hotkey_name="default",
        wallet_path=str(tmp_path / "wallet"),
    )


async def test_runner_rejects_wrong_wallet_and_releases_service_lock(relay, tmp_path):
    h = relay
    config = worker_config(h, tmp_path)
    with pytest.raises(ValueError, match="configured hotkey"):
        await run_admission_worker(config, h.archive.chain.policy, wallet=wallet("Dave"))
    lease = lock_private_file(Path(config.signing.directory) / "admission-service.lock")
    os.close(lease)


@pytest.mark.parametrize("command", ["query-cohort-admission", "run-cohort-admission-worker"])
def test_admission_commands_use_native_client_and_service(relay, monkeypatch, tmp_path, command):
    h = relay
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical_json_bytes(h.archive.chain.policy))
    args = ["--policy", str(policy), command]
    if command == "query-cohort-admission":
        request = tmp_path / "request.json"
        request.write_bytes(canonical_json_bytes(h.request))
        args += ["--request", str(request), "--origin", "https://intake.example"]

        async def fetch(**kwargs):
            return await fetch_cohort_admission(**kwargs, transport=httpx.ASGITransport(h.app))

        monkeypatch.setattr("umi.competition_commands.cohorts.fetch_cohort_admission", fetch)
        assert execute(build_parser().parse_args(args))["status"] == "pending_attestation"
    else:
        config = worker_config(h, tmp_path)
        path = tmp_path / "worker.json"
        path.write_bytes(canonical_json_bytes(config))
        args += ["--config", str(path), "--once"]
        provider = h.archive.reviewer
        monkeypatch.setattr(provider, "start", AsyncMock())
        monkeypatch.setattr(provider, "aclose", AsyncMock())
        monkeypatch.setattr(provider, "ensure_observer_running", lambda: None)

        async def run(*args, **kwargs):
            return await run_admission_worker(
                *args,
                **kwargs,
                wallet=wallet("Charlie"),
                provider_factory=lambda *a, **kw: provider,
            )

        monkeypatch.setattr("umi.competition_cohort_admission_worker.run_admission_worker", run)
        result = execute(build_parser().parse_args(args))
        # The request is retained but its archive is not copied until submit.
        assert result["status"] == "admission_review_retry"
        assert result["chain_submission_authorized"] is False


@pytest.mark.parametrize("shutdown", ["stop", "cancel_twice"])
async def test_shutdown_drains_signing_before_closing_provider_and_unlocking(
    relay, monkeypatch, tmp_path, shutdown
):
    h = relay
    await submit(h)
    config = worker_config(h, tmp_path)
    provider = h.archive.reviewer
    closed = AsyncMock()
    monkeypatch.setattr(provider, "start", AsyncMock())
    monkeypatch.setattr(provider, "aclose", closed)
    monkeypatch.setattr(provider, "ensure_observer_running", lambda: None)
    entered, release = threading.Event(), threading.Event()
    import umi.competition_cohort_admission_worker as module

    original = module.sign_object

    def blocking_sign(*args):
        entered.set()
        assert release.wait(10)
        return original(*args)

    monkeypatch.setattr(module, "sign_object", blocking_sign)
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_admission_worker(
            config,
            h.archive.chain.policy,
            wallet=wallet("Charlie"),
            provider_factory=lambda *a, **kw: provider,
            stop=stop,
        )
    )
    lock = Path(config.signing.directory) / "admission-service.lock"
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        if shutdown == "stop":
            stop.set()
        else:
            task.cancel()
            await asyncio.sleep(0.02)
            task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and closed.await_count == 0
        with pytest.raises((OSError, ValueError)):
            lock_private_file(lock)
    finally:
        release.set()
        result = (await asyncio.gather(task, return_exceptions=True))[0]
    if shutdown == "stop":
        assert result["status"] == "stopped"
    else:
        assert isinstance(result, asyncio.CancelledError)
    closed.assert_awaited_once()
    lease = lock_private_file(lock)
    os.close(lease)
