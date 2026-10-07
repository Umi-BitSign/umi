"""Native HTTP admission and journals with explicit synthetic chain/proof ports.

The existing chain fixture runs the registration collector and archive retention;
its synthetic verifier does not establish real network finality.
"""

import asyncio
import fcntl
import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeBinding,
    CohortIntakeConfig,
    history_tip,
)
from umi.competition_cohort_roster import verify_recoverable_roster_membership
from umi.competition_cohort_service_api import (
    PATH,
    ServiceWorkAdmissionAPI,
    prepared_service_roster,
    service_admission_routes,
)
from umi.competition_cohort_service_queue import MAX_ADMISSION_BYTES, ServiceWorkQueue
from umi.competition_cohort_service_work import (
    MAX_CLAIM_BYTES,
    PrecommittedServiceWorkCatalog,
    SignedServiceWorkCatalog,
    SignedServiceWorkClaim,
    service_work_key,
)
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistrationProvider
from umi.competition_round_journal import RecordReservation
from umi.concurrency import run_owned_thread
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_service_queue import admit, inputs
from .test_competition_cohort_service_queue import base_policy as base_policy
from .test_competition_cohort_service_queue import harness as harness
from .test_competition_cohort_service_queue import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_queue import policy as policy
from .test_competition_cohort_service_queue import queue_case as queue_case
from .test_competition_cohort_service_queue import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_queue import recovery as recovery
from .test_competition_cohort_service_queue import runtime as runtime
from .test_competition_cohort_service_queue import scenario as scenario
from .test_competition_historical_registration import change_block
from .test_competition_registration_retention import retained_rows
from .test_open_competition import wallet


@pytest.fixture
def finality_padding(request):
    return getattr(request, "param", 0)


@pytest.fixture
async def api_case(queue_case, chain, finality_padding, monkeypatch):
    c = queue_case
    change_block(chain, chain.finality.ref.block_number)
    if finality_padding:
        original = chain.finality.verified_block_at

        async def padded(height):
            block = await original(height)
            raw = canonical_json_bytes(
                {
                    **json.loads(block.finality_evidence),
                    "fixture_padding": "x" * finality_padding,
                }
            )
            return replace(
                block,
                finality_evidence=raw,
                finality_evidence_sha256=hashlib.sha256(raw).hexdigest(),
            )

        monkeypatch.setattr(chain.finality, "verified_block_at", padded)
    provider = HistoricalRegistrationProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    observed = await provider.collect()
    s = SimpleNamespace(
        c=c,
        provider=provider,
        observed=observed,
        calls=[],
        offline=set(),
        source=c.h.source,
        roster=c.h.batch["roster"],
    )

    def called(port):
        s.calls.append(port)
        if port in s.offline:
            raise OSError("private provider path and URL must never reach HTTP errors")

    async def capture():
        called("capture")
        return await provider.collect()

    async def history(cohort):
        called("history")
        assert cohort == c.catalog.catalog.cohort_sha256
        return s.source

    async def roster(cohort, source, capture):
        called("roster")
        assert cohort == c.catalog.catalog.cohort_sha256
        verify_recoverable_roster_membership(
            s.roster,
            c.queue.policy,
            source.history,
            decision_source=source.inputs().__getitem__,
            intake_records=c.h.batch["records"],
            expected_tip_sha256=history_tip(source.history),
            current_block=capture.snapshot.block,
        )
        return s.roster

    async def archive(observation):
        called("archive")
        return await provider.retained_archive(observation)

    def build(queues=None, **kwargs):
        s.api = ServiceWorkAdmissionAPI(
            queues or {c.cfg.catalog_sha256: c.queue},
            capture,
            history,
            roster,
            archive,
            **kwargs,
        )
        s.app = FastAPI()
        s.app.include_router(service_admission_routes(s.api))

    s.build = build
    build()
    yield s
    await provider.aclose()
    await chain.provider.aclose()


async def request(s, method, path, **kwargs):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=s.app), base_url="https://owner.example"
    ) as client:
        return await client.request(method, path, **kwargs)


async def post(s, signed=None, **kwargs):
    signed = signed or inputs(s.c)[0]
    return await request(
        s,
        "POST",
        f"{PATH}/{s.c.cfg.catalog_sha256}/claims",
        content=canonical_json_bytes(signed),
        headers={"Content-Type": "application/json"},
        **kwargs,
    )


async def ready(s):
    return await request(
        s, "GET", f"{PATH}/{s.c.cfg.catalog_sha256}/readiness", params={"nonce": "ab" * 16}
    )


def restart(s):
    s.c.queue = ServiceWorkQueue(s.c.cfg, s.c.queue.policy)
    s.build()
    s.calls.clear()


def prior_admission_without_archive(s):
    """An existing queue obligation accepted before the HTTP atomic archive path."""
    return s.c.queue.admit(
        *inputs(s.c),
        s.source,
        s.observed,
        expected_tip_sha256=history_tip(s.source.history),
    )


def assert_no_admission_or_archive(s):
    assert s.c.queue.lookup(inputs(s.c)[0]) is None
    with s.c.queue.journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM service_claims").fetchone()[0] == 0
        assert (
            db.execute("SELECT COUNT(*) FROM records WHERE kind='service_admission'").fetchone()[0]
            == 0
        )
        assert db.execute("SELECT COUNT(*) FROM service_admission_artifacts").fetchone()[0] == 0


async def test_signed_claim_uses_owned_original_roster_and_archives_before_ack(api_case):
    s, c = api_case, api_case.c
    response = await post(s)
    assert response.status_code == 200, response.text
    signed, submission, participant = inputs(c)
    accepted = c.queue.lookup(signed)
    assert accepted.submission == submission and accepted.participant == participant
    assert accepted.registration == s.observed.snapshot
    assert accepted.history_sha256 == digest(c.h.source)
    assert s.api.archives[c.cfg.catalog_sha256].read(accepted) == (
        await s.provider.retained_archive(accepted.observation)
    )
    body = response.json()
    assert body["admission_sha256"] == digest(accepted)
    assert body["ordinal"] == 1 and body["status"] == "accepted"
    assert not body["chain_submission_authorized"] and not body["service_credit_authorized"]
    assert response.headers["cache-control"] == "no-store"
    assert set(body) == {
        "schema",
        "status",
        "catalog_sha256",
        "claim_sha256",
        "admission_sha256",
        "work_sha256",
        "ordinal",
        "service_credit_authorized",
        "chain_submission_authorized",
    }


async def test_discovery_is_selected_metadata_and_never_private_inventory(api_case, tmp_path):
    s, c = api_case, api_case.c
    body = c.catalog.catalog.model_copy(update={"service_terms_sha256": "d1" * 32})
    signed = SignedServiceWorkCatalog(catalog=body, signatures=signatures(body))
    config = c.cfg.model_copy(
        update={
            "directory": str(tmp_path / "other-queue"),
            "catalog_sha256": digest(body),
            "service_terms_sha256": body.service_terms_sha256,
        }
    )
    other = ServiceWorkQueue(config, c.queue.policy)
    other.install(
        signed,
        c.round,
        c.h.source,
        s.observed,
        expected_tip_sha256=history_tip(c.h.source.history),
    )
    selected = {c.cfg.catalog_sha256: c.queue, config.catalog_sha256: other}
    s.build(selected)
    selected.clear()  # The host's caller cannot mutate the configured route selection.
    response = await request(s, "GET", PATH)
    assert response.status_code == 200
    entries = response.json()["catalogs"]
    assert [e["catalog_sha256"] for e in entries] == sorted((c.cfg.catalog_sha256, digest(body)))
    assert all(e["round_sha256"] == digest(c.round) and e["work_items"] == 4 for e in entries)
    assert not s.calls
    for entry in entries:
        assert set(entry) == {
            "status",
            "catalog_sha256",
            "policy_sha256",
            "cohort_sha256",
            "authority_sha256",
            "round_sha256",
            "service_terms_sha256",
            "work_items",
            "selection_rule",
            "credit_rule",
            "claims_url",
            "readiness_url",
        }
    claim = inputs(c)[0].claim.model_copy(update={"catalog_sha256": config.catalog_sha256})
    claim = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, wallet("Alice")))
    second = await request(
        s,
        "POST",
        f"{PATH}/{config.catalog_sha256}/claims",
        content=canonical_json_bytes(claim),
        headers={"Content-Type": "application/json"},
    )
    assert second.status_code == 200, second.text
    assert other.lookup(claim).ordinal == 1 and c.queue.entries() == ()
    mismatch = await post(s, claim)
    assert mismatch.status_code == 409
    unknown = await request(s, "POST", f"{PATH}/{'ff' * 32}/claims", content=b"{}")
    assert unknown.status_code == 404


async def test_restart_duplicate_recovers_before_all_live_ports(api_case):
    s = api_case
    first = await post(s)
    assert first.status_code == 200, first.text
    restart(s)
    s.offline = {"capture", "history", "roster", "archive"}
    s.source = source_for(s.c.h.batch, s.c.h.batch["history"])
    duplicate = await post(s)
    assert duplicate.json() == first.json() and not s.calls
    assert len(s.c.queue.entries()) == 1


async def test_archive_outage_does_not_accept_new_claim(api_case):
    s = api_case
    s.offline = {"archive"}
    assert (await post(s)).status_code == 503
    assert_no_admission_or_archive(s)
    restart(s)
    s.offline.clear()
    assert (await post(s)).json()["ordinal"] == 1


async def test_prior_admission_missing_archive_retries_original_capture(api_case):
    s = api_case
    accepted = prior_admission_without_archive(s)
    restart(s)
    s.offline = {"capture", "history", "roster"}
    s.source = source_for(s.c.h.batch, s.c.h.batch["history"])
    for _ in range(2):
        s.offline.add("archive")
        assert (await post(s)).status_code == 503
        assert s.c.queue.lookup(inputs(s.c)[0]) == accepted
    s.offline.remove("archive")
    result = await post(s)
    assert result.status_code == 200 and result.json()["admission_sha256"] == digest(accepted)
    assert set(s.calls) == {"archive"}


@pytest.mark.parametrize(
    "stage", ["before_write", "before_proofs", "after_first_proof", "after_proofs", "after_commit"]
)
async def test_interrupted_commits_and_lost_ack_preserve_exact_obligation(
    api_case, monkeypatch, stage
):
    s = api_case
    journal = s.c.queue.journal
    original = journal.put_many

    def fail(records, **kwargs):
        records = tuple(records)
        if any(kind == "service_admission" for kind, _, _ in records):
            if stage == "after_commit":
                original(records, **kwargs)
            raise OSError("simulated lost write acknowledgement")
        return original(records, **kwargs)

    if stage in {"before_write", "after_commit"}:
        monkeypatch.setattr(journal, "put_many", fail)
    elif stage == "after_first_proof":
        with journal.transaction() as db:
            db.execute(
                "CREATE TRIGGER fail_second_proof BEFORE INSERT ON service_admission_artifacts "
                "WHEN (SELECT COUNT(*) FROM service_admission_artifacts)=1 "
                "BEGIN SELECT RAISE(ABORT, 'fixture interrupted second proof'); END"
            )
    else:
        archive = s.api.archives[s.c.cfg.catalog_sha256]
        attach = archive.attach

        def interrupted(admission, raw, metadata, *, db):
            assert db.in_transaction
            assert db.execute("SELECT COUNT(*) FROM service_claims").fetchone()[0] == 1
            if stage == "after_proofs":
                attach(admission, raw, metadata, db=db)
                assert (
                    db.execute("SELECT COUNT(*) FROM service_admission_artifacts").fetchone()[0]
                    == 2
                )
            raise OSError("simulated interruption inside admission transaction")

        monkeypatch.setattr(archive, "attach", interrupted)
    assert (await post(s)).status_code == 503
    retained = s.c.queue.lookup(inputs(s.c)[0])
    assert (retained is not None) == (stage == "after_commit")
    if retained is None:
        assert_no_admission_or_archive(s)
    else:
        assert s.api.archives[s.c.cfg.catalog_sha256].read(retained) == (
            await s.provider.retained_archive(retained.observation)
        )
    if stage == "after_first_proof":
        with journal.transaction() as db:
            db.execute("DROP TRIGGER fail_second_proof")
    restart(s)
    if retained is not None:
        s.offline = {"history", "capture", "roster", "archive"}
    reply = await post(s)
    assert reply.status_code == 200, reply.text
    assert len(s.c.queue.entries()) == 1 and reply.json()["ordinal"] == 1
    if retained is not None:
        assert reply.json()["admission_sha256"] == digest(retained)
        assert not s.calls


@pytest.mark.parametrize("damage", ["metadata", "snapshot", "evidence"])
@pytest.mark.parametrize("prior", [False, True])
async def test_wrong_archive_cannot_accept_or_replace_original_registration(
    api_case, damage, prior
):
    s = api_case
    accepted = prior_admission_without_archive(s) if prior else None
    raw, metadata = await s.provider.retained_archive(execution_boundary(s.observed))
    if damage == "metadata":
        metadata += b"changed"
    elif damage == "snapshot":
        raw = raw.replace(f'"block":{s.observed.snapshot.block}'.encode(), b'"block":401')
    else:
        raw += b" "

    async def wrong(_):
        return raw, metadata

    s.api.archive = wrong
    assert (await post(s)).status_code == 503
    if accepted is None:
        assert_no_admission_or_archive(s)
    else:
        assert s.c.queue.lookup(inputs(s.c)[0]) == accepted
        with pytest.raises(FileNotFoundError):
            s.api.archives[s.c.cfg.catalog_sha256].read(accepted)
    restart(s)
    assert (await post(s)).status_code == 200
    if accepted is not None:
        assert s.c.queue.lookup(inputs(s.c)[0]) == accepted


@pytest.mark.parametrize("damage", ["signature", "extra_registration", "extra_participant", "json"])
async def test_untrusted_ingress_never_supplies_registration_or_eligibility(api_case, damage):
    s = api_case
    signed = inputs(s.c)[0]
    body = signed.model_dump(mode="json", by_alias=True)
    if damage == "signature":
        body["signature"] = sign_object(signed.claim, wallet("Bob")).model_dump(mode="json")
    elif damage == "extra_registration":
        body["registration"] = s.observed.snapshot.model_dump(mode="json")
    elif damage == "extra_participant":
        body["participant"] = inputs(s.c)[2].model_dump(mode="json")
    raw = b"{" if damage == "json" else canonical_json_bytes(body)
    result = await request(
        s,
        "POST",
        f"{PATH}/{s.c.cfg.catalog_sha256}/claims",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert result.status_code == 422 and not s.calls
    assert s.c.queue.entries() == ()


async def test_stream_limit_ignores_false_content_length_and_stops_consuming(api_case):
    s = api_case
    consumed = []

    async def oversized():
        consumed.append(1)
        yield b" " * MAX_CLAIM_BYTES
        consumed.append(2)
        yield b" "
        raise AssertionError("bounded reader consumed past the limit")

    path = f"{PATH}/{s.c.cfg.catalog_sha256}/claims"
    response = await request(
        s,
        "POST",
        path,
        content=oversized(),
        headers={"Content-Type": "application/json", "Content-Length": "1"},
    )
    assert response.status_code == 413 and consumed == [1, 2] and not s.calls
    assert (await request(s, "POST", path, content=b"{}")).status_code == 415
    raw = canonical_json_bytes(inputs(s.c)[0])
    exact = await request(
        s,
        "POST",
        path,
        content=raw + b" " * (MAX_CLAIM_BYTES - len(raw)),
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    assert exact.status_code == 200, exact.text


async def test_claim_requires_matching_miner_and_prepared_submission(api_case):
    s = api_case
    claim = inputs(s.c)[0].claim.model_copy(
        update={"submission_sha256": inputs(s.c, "Bob")[0].claim.submission_sha256}
    )
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, wallet("Alice")))
    assert (await post(s, signed)).status_code == 409
    assert s.c.queue.entries() == ()


async def test_nonce_reuse_cannot_change_accepted_claim(api_case):
    s = api_case
    first = await post(s)
    claim = inputs(s.c)[0].claim.model_copy(update={"submission_sha256": "ff" * 32})
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, wallet("Alice")))
    s.calls.clear()
    assert (await post(s, signed)).status_code == 503
    assert not s.calls and (await post(s)).json() == first.json()
    assert len(s.c.queue.entries()) == 1


@pytest.mark.parametrize("port", ["capture", "history", "roster", "archive"])
async def test_readiness_probes_actual_owned_ports_without_accepting_work(api_case, port):
    s = api_case
    live = await ready(s)
    assert live.status_code == 200 and live.json()["ready"], live.text
    assert live.json()["remaining_claims"] == 4
    assert live.json()["nonce"] == "ab" * 16
    assert "observation" not in live.json()
    assert live.headers["cache-control"] == "no-store"
    s.offline.add(port)
    result = await ready(s)
    assert result.status_code == 200 and not result.json()["ready"]
    assert result.json()["reason_code"] == (
        "archive_unavailable" if port == "archive" else "owner_inputs_unavailable"
    )
    assert "private provider" not in result.text
    assert s.c.queue.entries() == ()


@pytest.mark.parametrize("fence", ["capacity", "sealed", "bytes"])
async def test_readiness_capacity_and_seal_preserve_duplicate_recovery(api_case, fence):
    s = api_case
    first = await post(s)
    if fence == "capacity":
        s.c.cfg = s.c.cfg.model_copy(update={"maximum_claims": 1})
        restart(s)
    elif fence == "sealed":
        s.c.queue.seal(s.source, s.observed, expected_tip_sha256=history_tip(s.source.history))
    else:
        with s.c.queue.journal.transaction() as db:
            _, used, _ = s.c.queue.journal._capacity(db)
        s.c.queue.journal.maximum_bytes = used
    status = await ready(s)
    assert not status.json()["ready"]
    assert status.json()["reason_code"] == ("sealed" if fence == "sealed" else "capacity_exhausted")
    assert (await post(s, inputs(s.c, nonce=2)[0])).status_code == 503
    s.offline = {"history", "capture", "roster", "archive"}
    assert (await post(s)).json() == first.json()


async def test_closed_history_is_remembered_and_cannot_roll_back(api_case, chain):
    s = api_case
    first = await post(s)
    old = s.source
    s.source = source_for(s.c.h.batch, s.c.h.batch["history"])
    change_block(chain, s.observed.snapshot.block + 20000)
    closed = await ready(s)
    assert not closed.json()["ready"]
    s.source = old
    assert (await post(s, inputs(s.c, nonce=2)[0])).status_code == 503
    assert (await post(s)).json() == first.json()


async def test_history_change_during_roster_lookup_does_not_accept(api_case, chain):
    s = api_case
    original = s.api.roster

    async def changing(*args):
        value = await original(*args)
        s.source = source_for(s.c.h.batch, s.c.h.batch["history"])
        change_block(chain, s.observed.snapshot.block + 20000)
        return value

    s.api.roster = changing
    assert (await post(s)).status_code == 503
    assert s.c.queue.entries() == ()
    s.source = s.c.h.source
    s.api.roster = original
    assert (await post(s)).status_code == 503


async def test_concurrent_duplicate_http_requests_consume_one_slot(api_case):
    s = api_case
    responses = await asyncio.gather(*(post(s) for _ in range(3)))
    assert all(r.status_code == 200 for r in responses)
    assert responses[0].json() == responses[1].json() == responses[2].json()
    assert len(s.c.queue.entries()) == 1


async def test_native_preparation_adapter_only_reads_original_retained_round(api_case):
    s = api_case
    calls = []

    class Owner:
        def retained(self, cohort, **kwargs):
            calls.append((cohort, kwargs))
            return SimpleNamespace(roster=s.roster)

    adapter = prepared_service_roster(Owner())
    assert await adapter(s.c.round.cohort_sha256, s.source, s.observed) == s.roster
    assert calls == [
        (
            s.c.round.cohort_sha256,
            {
                "expected_tip_sha256": history_tip(s.source.history),
                "current_block": s.observed.snapshot.block,
            },
        )
    ]


async def test_future_selected_queue_does_not_hide_installed_catalog(api_case, tmp_path):
    s, c = api_case, api_case.c
    cfg = c.cfg.model_copy(
        update={
            "directory": str(tmp_path / "pending-queue"),
            "catalog_sha256": "ed" * 32,
        }
    )
    pending = ServiceWorkQueue(cfg, c.queue.policy)
    s.build({c.cfg.catalog_sha256: c.queue, cfg.catalog_sha256: pending})
    response = await request(s, "GET", PATH)
    entries = {e["catalog_sha256"]: e for e in response.json()["catalogs"]}
    assert entries[c.cfg.catalog_sha256]["status"] == "installed"
    assert entries[cfg.catalog_sha256] == {
        "catalog_sha256": cfg.catalog_sha256,
        "status": "pending_installation",
        "claims_url": f"{PATH}/{cfg.catalog_sha256}/claims",
        "readiness_url": f"{PATH}/{cfg.catalog_sha256}/readiness",
    }
    response = await request(
        s, "GET", entries[cfg.catalog_sha256]["readiness_url"], params={"nonce": "ab" * 16}
    )
    assert not response.json()["ready"] and response.json()["reason_code"] == "catalog_pending"
    assert not s.calls
    assert (await post(s)).status_code == 200


async def test_prior_admission_archive_capacity_failure_is_atomic_and_recoverable(api_case):
    s = api_case
    accepted = prior_admission_without_archive(s)
    journal = s.c.queue.journal
    with journal.transaction() as db:
        _, used, _ = journal._capacity(db)
    raw, metadata = await s.provider.retained_archive(accepted.observation)
    journal.maximum_bytes = used + len(raw) + len(metadata) - 1
    s.offline = {"history", "capture", "roster"}
    assert (await post(s)).status_code == 503
    with journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM service_admission_artifacts").fetchone()[0] == 0
    restart(s)
    assert (await post(s)).json()["admission_sha256"] == digest(accepted)


@pytest.mark.parametrize("finality_padding", [3 * 1024**2], indirect=True)
async def test_proof_capacity_failure_rolls_back_new_admission_and_recovers_after_growth(api_case):
    s = api_case
    queue, journal = s.c.queue, s.c.queue.journal
    raw, metadata = await s.provider.retained_archive(execution_boundary(s.observed))
    assert len(raw) > MAX_ADMISSION_BYTES
    # Fund the native next-slot and seal allowances, but not this proof archive.
    # Replacing the admission allowance with its small record cannot pay for it.
    work = service_work_key(s.c.catalog.catalog, 1)
    queue._reserve_seal()
    journal.reserve_records(
        work, (RecordReservation("service_admission", work, MAX_ADMISSION_BYTES),)
    )
    with journal.transaction() as db:
        _, used, _ = journal._capacity(db)
    original_capacity = s.c.cfg.maximum_bytes
    s.c.cfg = s.c.cfg.model_copy(update={"maximum_bytes": used + 1024})
    restart(s)
    allowance = s.c.queue.journal.reservation(work)
    assert (await post(s)).status_code == 503
    assert_no_admission_or_archive(s)
    assert s.c.queue.journal.reservation(work) == allowance
    s.c.cfg = s.c.cfg.model_copy(update={"maximum_bytes": original_capacity})
    restart(s)
    receipt = await post(s)
    assert receipt.status_code == 200 and receipt.json()["ordinal"] == 1, receipt.text
    accepted = s.c.queue.lookup(inputs(s.c)[0])
    assert s.api.archives[s.c.cfg.catalog_sha256].read(accepted) == (raw, metadata)
    restart(s)
    s.offline = {"history", "capture", "roster", "archive"}
    assert (await post(s)).json() == receipt.json() and not s.calls


async def test_corrupt_retained_archive_never_falls_back_to_network(api_case):
    s = api_case
    assert (await post(s)).status_code == 200
    with s.c.queue.journal.transaction() as db:
        db.execute("UPDATE service_admission_artifacts SET body=?", (b"changed",))
    restart(s)
    assert (await post(s)).status_code == 503 and not s.calls
    assert len(s.c.queue.entries()) == 1


async def test_incomplete_owned_roster_is_refused(api_case):
    s = api_case

    async def incomplete(*_):
        return s.roster.model_copy(update={"participants": s.roster.participants[:1]})

    s.api.roster = incomplete
    assert (await post(s)).status_code == 503
    assert s.c.queue.entries() == ()


async def test_owned_port_timeout_is_bounded_and_redacted(api_case):
    s = api_case
    stopped = asyncio.Event()

    async def unavailable(_):
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    s.api.history = unavailable
    s.api.timeout = 0.01
    reply = await asyncio.wait_for(post(s), timeout=2)
    assert reply.status_code == 503 and stopped.is_set()
    assert s.c.queue.entries() == ()


def native_intake(s, tmp_path):
    intake = CohortIntake(
        CohortIntakeConfig(
            directory=str(tmp_path / "native-intake"),
            cohorts=(
                CohortIntakeBinding(
                    cohort_sha256=s.c.round.cohort_sha256,
                    authority_sha256=s.c.catalog.catalog.authority_sha256,
                ),
            ),
        ),
        s.c.queue.policy,
        initialize=True,
    )

    def restore(source):
        # Restore the harness's certified history through the native consumer
        # ledger, holding the same lock as publication and service commitment.
        with intake._connection() as (_, store):
            store.publish_history(
                source.history, intake.policy, current_block=s.observed.snapshot.block
            )
            for decision in source.decisions:
                store.retain_source(s.c.round.cohort_sha256, decision)

    restore(s.source)
    s.build(intake=intake)
    return intake, restore


async def test_native_intake_lock_covers_final_check_and_queue_commit(
    api_case, tmp_path, monkeypatch
):
    s = api_case
    intake, _ = native_intake(s, tmp_path)
    original = s.c.queue.admit
    checked = []

    def under_lock(*args, **kwargs):
        lease = os.open(intake.directory / "intake.lock", os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            checked.append(True)
            return original(*args, **kwargs)
        finally:
            os.close(lease)

    monkeypatch.setattr(s.c.queue, "admit", under_lock)
    reply = await post(s)
    assert reply.status_code == 200, reply.text
    assert checked == [True]


async def test_native_publication_after_last_async_check_prevents_admission(
    api_case, tmp_path, monkeypatch
):
    s = api_case
    _, publish = native_intake(s, tmp_path)
    original = s.api._unchanged

    async def close(*args):
        await original(*args)
        await run_owned_thread(publish, source_for(s.c.h.batch, s.c.h.batch["history"]))

    monkeypatch.setattr(s.api, "_unchanged", close)
    reply = await post(s)
    assert reply.status_code == 503 and s.c.queue.entries() == ()


async def test_precommitted_catalog_uses_queue_round_for_discovery_and_admission(
    api_case, tmp_path
):
    s, c = api_case, api_case.c
    body = PrecommittedServiceWorkCatalog(
        schema="umi-cohort-service-work-catalog/2",
        **c.catalog.catalog.model_dump(exclude={"schema_", "round_sha256", "issued_at_block"}),
    )
    c.catalog = SignedServiceWorkCatalog(catalog=body, signatures=signatures(body))
    c.cfg = c.cfg.model_copy(
        update={
            "catalog_sha256": digest(body),
            "directory": str(tmp_path / "precommitted-queue"),
        }
    )
    c.queue = ServiceWorkQueue(c.cfg, c.queue.policy)
    c.queue.install(
        c.catalog,
        c.round,
        s.source,
        s.observed,
        expected_tip_sha256=history_tip(s.source.history),
    )
    s.build()
    discovery = await request(s, "GET", PATH)
    assert discovery.json()["catalogs"][0]["round_sha256"] == digest(c.round)
    assert (await ready(s)).json()["ready"]
    accepted = await post(s)
    assert accepted.status_code == 200, accepted.text
    restart(s)
    s.offline = {"capture", "history", "roster", "archive"}
    assert (await post(s)).json() == accepted.json() and not s.calls


@pytest.mark.parametrize("damage", ["index", "canonical", "hold"])
async def test_bad_service_retention_rolls_back_registration_pruning(api_case, chain, damage):
    s = api_case
    original = admit(s.c)
    before = retained_rows(s.provider)
    s.provider._retained_capture_blocks = s.c.queue.retained_registration_blocks
    with s.c.queue.journal.transaction() as db:
        if damage == "index":
            db.execute("UPDATE service_claims SET admission=?", ("ff" * 32,))
        elif damage == "canonical":
            db.execute(
                "UPDATE records SET body=? WHERE kind='service_admission'",
                (canonical_json_bytes(original) + b"\n",),
            )
        else:
            db.execute("INSERT INTO holds VALUES (?)", (original.work_sha256,))
    change_block(
        chain, s.observed.snapshot.block + s.provider.policy.maximum_snapshot_age_blocks + 1
    )
    with pytest.raises((ValueError, RuntimeError)):
        await s.provider.collect()
    assert retained_rows(s.provider) == before
    with sqlite3.connect(s.provider._path) as db:
        assert db.execute("SELECT block FROM observed_head").fetchone()[0] == before[-1][0]


async def test_archive_acquired_before_cutoff_survives_delayed_admission(
    api_case, chain, monkeypatch
):
    s = api_case
    captured = asyncio.Event()
    resume = asyncio.Event()
    unchanged = s.api._unchanged
    original_block = s.observed.snapshot.block
    original_archive = await s.provider.retained_archive(execution_boundary(s.observed))
    s.provider._retained_capture_blocks = s.c.queue.retained_registration_blocks

    async def delayed(queue, source):
        captured.set()
        await resume.wait()
        await unchanged(queue, source)

    monkeypatch.setattr(s.api, "_unchanged", delayed)
    request = asyncio.create_task(post(s))
    try:
        await asyncio.wait_for(captured.wait(), timeout=120)
        change_block(chain, original_block + s.provider.policy.maximum_snapshot_age_blocks + 1)
        await s.provider.collect()
        assert original_block not in {row[0] for row in retained_rows(s.provider)}
    finally:
        resume.set()
    result = await request
    assert result.status_code == 200, result.text
    accepted = s.c.queue.lookup(inputs(s.c)[0])
    assert accepted.observation.block == original_block
    assert s.api.archives[s.c.cfg.catalog_sha256].read(accepted) == original_archive
    restart(s)
    s.offline = {"capture", "history", "roster", "archive"}
    duplicate = await post(s)
    assert duplicate.json() == result.json() and not s.calls
    assert s.api.archives[s.c.cfg.catalog_sha256].read(accepted) == original_archive


@pytest.mark.parametrize("path", ["current", "readiness"])
async def test_owned_roster_validation_runs_off_listener_thread(api_case, monkeypatch, path):
    """Native roster serialization/validation cannot occupy the HTTP event loop."""
    import threading

    from umi.competition_cohort_roster import RecoverableRosterEvidence

    s = api_case
    loop_thread = threading.get_ident()
    original = RecoverableRosterEvidence.model_validate_json
    calls = []

    async def retained_roster(cohort, source, capture):
        return s.roster

    def validate(cls, *args, **kwargs):
        ident = threading.get_ident()
        calls.append(ident)
        assert ident != loop_thread, "native roster validation blocked the listener"
        return original(*args, **kwargs)

    s.api.roster = retained_roster
    monkeypatch.setattr(RecoverableRosterEvidence, "model_validate_json", classmethod(validate))
    if path == "current":
        _, _, _, roster = await s.api._current(s.c.queue)
        assert roster == s.roster
    else:
        report = await s.api.readiness(s.c.cfg.catalog_sha256, "ab" * 16)
        assert report["ready"] is True
    assert calls


async def test_owned_roster_validation_drains_before_releasing_readiness_owner(
    api_case, monkeypatch
):
    import threading

    s = api_case
    entered, release = threading.Event(), threading.Event()
    original = s.api._check_roster
    loop_thread = threading.get_ident()

    async def retained_roster(cohort, source, capture):
        return s.roster

    def held(value, round_):
        assert threading.get_ident() != loop_thread
        entered.set()
        assert release.wait(60), "fixture release was never delivered"
        return original(value, round_)

    s.api.roster = retained_roster
    monkeypatch.setattr(s.api, "_check_roster", held)
    task = asyncio.create_task(s.api.readiness(s.c.cfg.catalog_sha256, "ab" * 16))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 60), timeout=65)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert s.api.serial[s.c.cfg.catalog_sha256].locked()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()
    assert not s.api.serial[s.c.cfg.catalog_sha256].locked()


async def test_service_admission_failure_is_diagnosable_without_exposing_provider_data(
    api_case, monkeypatch
):
    from umi import competition_progress as progress

    s = api_case
    reports = []
    monkeypatch.setattr(progress, "_emit", lambda body, **_kwargs: reports.append(body))
    s.offline.add("capture")
    response = await post(s)
    assert response.status_code == 503
    assert reports[-1]["operation"] == "service_claim"
    assert reports[-1]["stage"] == "admit"
    assert "private provider" not in str(reports)
    assert "private provider" not in response.text
    readiness = await ready(s)
    assert readiness.json()["ready"] is False
    assert reports[-1]["operation"] == "service_readiness"
    assert reports[-1]["stage"] == "owner_inputs_unavailable"
    assert s.c.queue.entries() == ()


async def test_service_readiness_reports_native_stage_timings(api_case, monkeypatch):
    from umi import competition_progress as progress

    reports = []
    monkeypatch.setattr(progress, "_emit", lambda body, **_kwargs: reports.append(body))
    response = await ready(api_case)
    assert response.json()["ready"] is True
    phases = [r for r in reports if r.get("phase", "").startswith("service_admission_")]
    assert [(r["phase"], r["event"]) for r in phases] == [
        ("service_admission_" + stage, event)
        for stage in ("catalog", "history", "capture", "history_review", "roster")
        for event in ("started", "completed")
    ]
    assert all(r["elapsed_ms"] >= 0 for r in phases if r["event"] == "completed")
    assert all(
        set(r) <= {"phase", "phase_id", "parent_phase_id", "event", "elapsed_ms"} for r in phases
    )


async def test_busy_readiness_returns_hold_without_waiting_for_admission(api_case):
    s = api_case
    entered, release = asyncio.Event(), asyncio.Event()
    original = s.api.history

    async def held_history(cohort):
        entered.set()
        await release.wait()
        return await original(cohort)

    s.api.history = held_history
    admission = asyncio.create_task(post(s))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        response = await asyncio.wait_for(ready(s), 2)
        assert response.status_code == 200
        body = response.json()
        assert body["reason_code"] == "admission_busy" and body["ready"] is False
        assert not body["chain_submission_authorized"]
        assert not body["service_credit_authorized"]
        assert body["nonce"] == "ab" * 16
        assert not admission.done()
        assert_no_admission_or_archive(s)
    finally:
        release.set()
        accepted = await admission
    assert accepted.status_code == 200
    # The ordinary path still collects all fresh owned inputs after the hold.
    assert (await ready(s)).json()["ready"] is True


async def test_second_readiness_does_not_queue_or_cancel_the_first(api_case):
    s = api_case
    entered, release = asyncio.Event(), asyncio.Event()
    original = s.api.history

    async def held_history(cohort):
        entered.set()
        await release.wait()
        return await original(cohort)

    s.api.history = held_history
    first = asyncio.create_task(ready(s))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        second = await asyncio.wait_for(ready(s), 2)
        assert second.json()["reason_code"] == "admission_busy"
        assert second.json()["ready"] is False and not first.done()
        assert_no_admission_or_archive(s)
    finally:
        release.set()
        completed = await first
    assert completed.json()["ready"] is True
