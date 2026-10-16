"""Metadata-only owner exports preserve exact originals without advancing intake."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_legacy_model_storage import LegacyModelOriginals
from umi.competition_cohort_model_delivery_candidate import ModelDeliveryAdoptionCandidate
from umi.competition_cohort_model_delivery_preflight import (
    PATH,
    ModelDeliveryPreflightExporter,
    ModelDeliveryPreflightRequest,
    model_delivery_preflight_routes,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_delivery_issuance import base_policy as base_policy
from .test_competition_cohort_model_delivery_issuance import case as case
from .test_competition_cohort_model_delivery_issuance import census, post
from .test_competition_cohort_model_delivery_issuance import issuance as issuance
from .test_competition_cohort_model_delivery_issuance import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_delivery_issuance import owner_api as owner_api
from .test_competition_cohort_model_delivery_issuance import policy as policy
from .test_competition_cohort_model_delivery_issuance import prepared as prepared
from .test_competition_cohort_model_delivery_issuance import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_delivery_issuance import recovery as recovery
from .test_competition_cohort_model_delivery_issuance import runtime as runtime
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def selected(i, maximum_bytes=64 * 1024**2):
    exporter = ModelDeliveryPreflightExporter(
        i.case.owner.intake,
        i.uploads,
        maximum_bytes=maximum_bytes,
        timeout_seconds=30,
    )
    request = ModelDeliveryPreflightRequest(
        schema="umi-model-delivery-preflight-request/1",
        cohort_sha256=i.case.cohort,
        expected_predecessor_sha256=history_tip(i.case.history),
        challenge="a1" * 32,
    )
    return exporter, request


def database_bytes(i):
    return {
        path: path.read_bytes()
        for root in (i.case.owner.intake.directory, i.uploads.journal.root)
        for path in root.glob("*.sqlite3")
    }


def test_complete_originals_repeat_without_writes_or_payload_checks(issuance, monkeypatch):
    i = issuance
    before = database_bytes(i)
    exporter, request = selected(i)

    def forbidden(*args, **kwargs):
        raise AssertionError("metadata export must not open writable state or payloads")

    monkeypatch.setattr(i.case.owner.intake, "_exclusive_connection", forbidden)
    monkeypatch.setattr(i.uploads, "complete", forbidden)
    monkeypatch.setattr(i.uploads, "_paths", forbidden)
    raw = exporter.export(request)
    assert selected(i)[0].export(request) == raw
    value = json.loads(raw)
    objects = {o["raw_sha256"]: o["raw_json"].encode() for o in value["objects"]}
    assert all(sha256_hex(raw) == key for key, raw in objects.items())
    for expected, actual in zip(i.case.legacy.entries, value["entries"], strict=True):
        for field in (
            "request_sha256",
            "model_sha256",
            "request_raw_sha256",
            "participation_raw_sha256",
            "admission_raw_sha256",
            "intent_raw_sha256",
            "certificate_raw_sha256",
        ):
            assert actual[field] == getattr(expected, field)
        assert actual["upload_retained"]
        assert objects[actual["request_raw_sha256"]] == i.case.objects[expected.request_raw_sha256]
    assert value["pending_transition_sha256"] is None
    assert value["phase"] == "intake" and value["intake_sealed"] is False
    assert value["observational_only"] is True
    assert value["legacy_allocations_all_cohorts"] == i.uploads.allocations.snapshot()
    assert database_bytes(i) == before
    assert not i.remote.reads


def test_upload_only_original_is_exported_without_invented_admission(issuance):
    i, c = issuance, issuance.case
    record = c.requests[1].record
    consent = record.proposed_admission.consent_sha256
    with c.owner.intake._connection() as (db, _):
        db.execute("DELETE FROM cohort_consents WHERE consent=?", (consent,))
        db.execute("DELETE FROM cohort_admission_certificates WHERE consent=?", (consent,))
        db.execute(
            "DELETE FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
            (c.cohort, digest(c.subs[1])),
        )
    exporter, request = selected(i)
    value = json.loads(exporter.export(request))
    entry = next(e for e in value["entries"] if e["request_sha256"] == digest(record.request))
    assert entry["upload_retained"] is True
    assert all(
        entry[f] is None
        for f in (
            "participation_raw_sha256",
            "admission_raw_sha256",
            "intent_raw_sha256",
            "certificate_raw_sha256",
        )
    )
    assert len(value["entries"]) == len(c.requests)


def test_pending_adoption_is_observed_without_changing_reservation(issuance):
    census(issuance, reserve=True)
    before = database_bytes(issuance)
    exporter, request = selected(issuance)
    value = json.loads(exporter.export(request))
    assert value["pending_transition_sha256"] == digest(issuance.transition)
    assert database_bytes(issuance) == before


def test_repeated_submission_keeps_each_original_consent_lineage_through_reservation(issuance):
    i, c = issuance, issuance.case
    original = c.requests[0].record.request
    body = original.consent.consent.model_copy(
        update={"signed_at_block": original.consent.consent.signed_at_block + 1}
    )
    duplicate = original.model_copy(
        update={
            "consent": original.consent.model_copy(
                update={"consent": body, "signature": sign_object(body, wallet("Alice"))}
            )
        }
    )
    assert duplicate.signed_submission == original.signed_submission
    assert digest(duplicate) != digest(original)
    assert i.uploads.reserve(duplicate, capture_at(220)) == digest(duplicate)
    before = database_bytes(i)
    exporter, request = selected(i)
    exported = json.loads(exporter.export(request))
    assert exporter.export(request) == canonical_json_bytes(exported)
    assert database_bytes(i) == before
    entries = {e["request_sha256"]: e for e in exported["entries"]}
    extra = entries[digest(duplicate)]
    assert extra["participation_raw_sha256"] is None
    assert extra["admission_raw_sha256"] is None
    assert extra["intent_raw_sha256"] is None
    assert extra["certificate_raw_sha256"] is None
    accepted = entries[digest(original)]
    assert accepted["certificate_raw_sha256"] is not None
    assert accepted["intent_raw_sha256"] is not None
    raw_objects = {o["raw_sha256"]: o["raw_json"].encode() for o in exported["objects"]}
    for entry in c.legacy.entries:
        for field in (
            "request_raw_sha256",
            "participation_raw_sha256",
            "admission_raw_sha256",
            "intent_raw_sha256",
            "certificate_raw_sha256",
        ):
            identity = getattr(entry, field)
            if identity is not None:
                assert raw_objects[identity] == c.objects[identity]
    for key, raw in raw_objects.items():
        path = i.root / "objects" / (key + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)
    extra_native = LegacyModelOriginals(
        request_sha256=digest(duplicate),
        model_sha256=extra["model_sha256"],
        request_raw_sha256=extra["request_raw_sha256"],
        payload_state="preserved",
    )
    legacy = c.legacy.model_copy(
        update={
            "entries": tuple(
                sorted((*c.legacy.entries, extra_native), key=lambda e: e.request_sha256)
            )
        }
    )
    preservation = c.preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
    (i.root / "legacy-inventory.json").write_bytes(canonical_json_bytes(legacy))
    (i.root / "preservation-inventory.json").write_bytes(canonical_json_bytes(preservation))
    i.transition = i.candidate.prepare(c.history, 221)
    assert census(i, reserve=True).legacy == legacy
    i.candidate = ModelDeliveryAdoptionCandidate(i.config, c.policy, multipart=i.remote)
    assert census(i, reserve=True).legacy == legacy
    assert i.uploads.reserve(duplicate, None) == digest(duplicate)
    assert not i.remote.reads


@pytest.mark.parametrize("boundary", ["preflight", "census"])
def test_acceptance_without_an_admitted_parent_refuses_instead_of_disappearing(issuance, boundary):
    i, c = issuance, issuance.case
    consent = c.requests[0].record.proposed_admission.consent_sha256
    with c.owner.intake._connection() as (db, _):
        db.execute("DELETE FROM cohort_admission_certificates WHERE consent=?", (consent,))
    with pytest.raises(ValueError, match=r"orphaned acceptance|orphaned original acceptance"):
        if boundary == "preflight":
            exporter, request = selected(i)
            exporter.export(request)
        else:
            census(i, reserve=True)
    assert c.owner.intake.pending_policy_adoption(c.cohort) is None


@pytest.mark.parametrize("fault", ["changed_tip", "capacity", "orphan"])
def test_refuses_changed_or_incomplete_view(issuance, fault):
    exporter, request = selected(issuance, 1024 if fault == "capacity" else 64 * 1024**2)
    if fault == "changed_tip":
        request = request.model_copy(update={"expected_predecessor_sha256": "f1" * 32})
    elif fault == "orphan":
        with issuance.case.owner.intake._connection() as (db, _):
            db.execute(
                "UPDATE cohort_model_acceptance_intents SET submission=? WHERE submission=?",
                ("f2" * 32, digest(issuance.case.subs[1])),
            )
    with pytest.raises((ValueError, OSError)):
        exporter.export(request)


def test_snapshot_holds_native_writer_fence(issuance, monkeypatch):
    entered, release, writer_entered = Event(), Event(), Event()
    original = issuance.uploads.journal.keys

    def pause(kind):
        if kind == "upload":
            entered.set()
            assert release.wait(5)
        return original(kind)

    monkeypatch.setattr(issuance.uploads.journal, "keys", pause)
    exporter, request = selected(issuance)

    def writer():
        with issuance.case.owner.intake._connection():
            writer_entered.set()

    with ThreadPoolExecutor(max_workers=2) as workers:
        reading = workers.submit(exporter.export, request)
        assert entered.wait(5)
        writing = workers.submit(writer)
        assert not writer_entered.wait(0.05)
        release.set()
        reading.result(timeout=5)
        writing.result(timeout=5)
    assert writer_entered.is_set()


async def test_private_route_authenticates_and_binds_challenge(issuance):
    exporter, request = selected(issuance)
    app = FastAPI()
    app.include_router(
        model_delivery_preflight_routes(
            issuance.case.owner.intake,
            issuance.uploads,
            token="h" * 32,
            maximum_bytes=exporter.maximum_bytes,
            timeout_seconds=exporter.timeout_seconds,
        )
    )
    before = database_bytes(issuance)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://owner"
    ) as client:
        assert (await post(client, PATH, request)).status_code == 401
        response = await post(client, PATH, request, token="h" * 32)
        assert response.status_code == 200, response.text
        assert response.json()["challenge"] == request.challenge
        assert response.content == canonical_json_bytes(response.json())
        changed = request.model_copy(update={"expected_predecessor_sha256": "01" * 32})
        assert (await post(client, PATH, changed, token="h" * 32)).status_code == 503
    assert database_bytes(issuance) == before


async def test_configured_owner_boot_installs_unsigned_native_preflight(
    owner_api, tmp_path, monkeypatch
):
    import umi.competition_cohort_admission_host as boot
    from umi.competition_cohort_admission_queue import CohortAdmissionQueue
    from umi.competition_cohort_preparation_owner import CohortPreparation
    from umi.competition_store import CompetitionStore

    a, i = owner_api, owner_api.i
    intake = i.case.owner.intake
    preparation = CohortPreparation(
        CohortAdmissionQueue(intake), CompetitionStore(tmp_path / "boot-promotion", intake.policy)
    )
    capture = AsyncMock(side_effect=AssertionError("preflight must not capture finality"))
    provider = SimpleNamespace(policy=intake.policy, collect=capture)
    config = boot.AdmissionOwnerConfig(
        schema="umi-cohort-admission-owner/1",
        directory=str(tmp_path / "boot-owner"),
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        owner_key_file=str(tmp_path / "unused-key"),
        export_token_file=str(tmp_path / "export-token"),
        reviewers=tuple(
            boot.CohortReviewPeerConfig(
                signer=wallet(name).hotkey.ss58_address,
                origin="http://127.0.0.1:19579",
                token_file=str(tmp_path / (name + "-token")),
            )
            for name in ("Charlie", "Dave")
        ),
        listen_port=18090,
    )
    credentials = {
        config.export_token_file: "h" * 32,
        **{
            peer.token_file: ("v" if index == 0 else "w") * 32
            for index, peer in enumerate(config.reviewers)
        },
    }
    monkeypatch.setattr(boot, "_token", credentials.__getitem__)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *args: wallet("Charlie"))
    monkeypatch.setattr(boot, "sign_object", lambda *args: pytest.fail("preflight must not sign"))
    service = SimpleNamespace(
        preparation=preparation,
        provider=provider,
        capture=capture,
        uploads=i.uploads,
        config=SimpleNamespace(series=a.series, lifecycle=None),
    )
    before = database_bytes(i)
    async with (
        boot.admission_owner_app(config, preparation, provider, service_host=service) as app,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://owner"
        ) as client,
    ):
        request = selected(i)[1]
        response = await post(client, PATH, request, token="h" * 32)
        assert response.status_code == 200, response.text
        assert len(response.json()["entries"]) == len(i.case.requests)
    capture.assert_not_called()
    assert database_bytes(i) == before
