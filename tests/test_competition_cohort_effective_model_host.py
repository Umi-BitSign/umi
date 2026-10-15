"""Actual configured host adopts R2 without rewriting an original C6 plan."""

import hashlib
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservationRequest,
    SignedDirectModelPayload,
)
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_model_upload import ModelUploadConfig
from umi.competition_cohort_order_host import OrderHostConfig
from umi.competition_cohort_order_queue import CohortOrderQueueConfig
from umi.competition_cohort_service_host import ServiceAdmissionHost
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_acceptance import adopt_direct_transport
from .test_competition_cohort_native_direct import NativeDirect
from .test_competition_cohort_native_pipeline import base_policy as base_policy
from .test_competition_cohort_native_pipeline import chain_config as chain_config
from .test_competition_cohort_native_pipeline import (
    configure_owner,
    model_request,
    precommit_model_inventory,
)
from .test_competition_cohort_native_pipeline import host as host
from .test_competition_cohort_native_pipeline import intake as intake
from .test_competition_cohort_native_pipeline import legacy_scenario as legacy_scenario
from .test_competition_cohort_native_pipeline import lifecycle as lifecycle
from .test_competition_cohort_native_pipeline import (
    lifecycle_before_intake as lifecycle_before_intake,
)
from .test_competition_cohort_native_pipeline import policy as policy
from .test_competition_cohort_native_pipeline import recovery as recovery
from .test_competition_cohort_native_pipeline import runtime as runtime
from .test_competition_cohort_native_pipeline import scenario as scenario
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
    pytest.mark.parametrize("lifecycle_before_intake", [precommit_model_inventory], indirect=True),
]


@pytest.mark.parametrize("adopted", [False, True])
async def test_configured_owner_selects_authenticated_transport_and_recovers_reservation(
    host, scenario, tmp_path, monkeypatch, chain_config, adopted
):
    o, h = host, host.h
    plan_bytes = canonical_json_bytes(h.intake.history(h.cohort).plan)
    direct = NativeDirect(tmp_path / "direct", h.intake.policy, monkeypatch)
    orders = OrderHostConfig(
        schema="umi-cohort-order-host/1",
        queue=CohortOrderQueueConfig(
            schema="umi-cohort-order-queue-config/1",
            directory=str(tmp_path / "orders"),
            policy_sha256=digest(h.intake.policy),
            cohorts=h.intake.config.cohorts,
            reviewers=tuple(
                sorted((p.signer for p in o.config.admission_owner.reviewers), key=identity)
            ),
        ),
    )
    overrides = direct.owner_config(o)
    overrides["model_uploads"] = ModelUploadConfig(
        directory=str(tmp_path / "legacy-upload-state"), maximum_reserved_bytes=1024**2
    )
    if not adopted:
        with pytest.raises(ValueError, match="owned authenticated transport"):
            configure_owner(
                o, orders, chain_config, tmp_path / "configured", monkeypatch, overrides=overrides
            )
        assert not (tmp_path / "direct/uploads").exists()
        return
    h.block += 1
    amended = adopt_direct_transport(h.intake, h.cohort, block=h.block)
    configure_owner(
        o, orders, chain_config, tmp_path / "configured", monkeypatch, overrides=overrides
    )
    profile = amended.transitions[-1].transition.model_delivery_adoption.delivery
    owner = o.service.direct_uploads.owners[h.cohort]
    assert owner.config.delivery == profile
    assert canonical_json_bytes(o.config.series.cohorts[0]) == plan_bytes
    assert o.service.uploads.root == Path(overrides["model_uploads"].directory)
    request = model_request(scenario, h.model, sequence=3, block=h.block)
    raw = b"".join(
        (tmp_path / "model-submission" / record.path).read_bytes() for record in h.model.files
    )
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(request),
        model_sha256=digest(h.model),
        payload_sha256=hashlib.sha256(raw).hexdigest(),
        total_bytes=len(raw),
        file_count=len(h.model.files),
        part_size_bytes=profile.part_size_bytes,
        total_parts=1,
    )
    signed = DirectModelUploadReservationRequest(
        schema="umi-direct-model-upload-reservation-request/1",
        request=request,
        payload=SignedDirectModelPayload(
            schema="umi-signed-direct-model-payload/1",
            payload=payload,
            signature=sign_object(payload, wallet("Alice")),
        ),
    )

    async def reserve(service):
        app = FastAPI()
        app.include_router(
            cohort_routes(
                h.intake, service.capture, models=service.payloads, maximum_body_bytes=4 * 1024**2
            )
        )
        app.include_router(
            direct_model_upload_routes(
                service.direct_uploads.owners, now_unix_ms=lambda: 1_800_000_000_000
            )
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://public.example"
        ) as client:
            discovery = await client.get("/v1/competition/cohorts")
            assert discovery.status_code == 200
            route = discovery.json()["cohorts"][0]["direct_model_upload_url"]
            response = await client.post(
                route,
                content=canonical_json_bytes(signed),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 200, response.text
            return response.json()

    first = await reserve(o.service)
    restarted = ServiceAdmissionHost(
        o.config,
        h.intake,
        h.owner.promotion,
        o.service.capture,
        h.provider.retained_archive,
        provider=h.provider,
    )
    assert await reserve(restarted) == first
    assert canonical_json_bytes(h.intake.history(h.cohort).plan) == plan_bytes
    assert not o.service.uploads.journal.keys("upload")
