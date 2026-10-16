"""Actual configured host adopts R2 without rewriting an original C6 plan."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_service_host as host_module
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservationRequest,
    SignedDirectModelPayload,
)
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_legacy_model_selection import LegacyModelStorageSourceConfig
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_cohort_model_upload import ModelUploadConfig
from umi.competition_cohort_order_host import OrderHostConfig
from umi.competition_cohort_order_queue import CohortOrderQueueConfig
from umi.competition_cohort_service_host import ServiceAdmissionHost, ServiceAdmissionHostConfig
from umi.open_competition import digest, identity, sign_object
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_legacy_model_admission import freeze
from .test_competition_cohort_legacy_model_storage import adoption
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
@pytest.mark.parametrize("with_storage", [False, True, "shared"])
async def test_configured_owner_selects_authenticated_transport_and_recovers_reservation(
    host, scenario, tmp_path, monkeypatch, chain_config, adopted, with_storage
):
    o, h = host, host.h
    old = canonical_json_bytes(o.config)
    assert b'"legacy_model_storage"' not in old
    assert b'"legacy_model_verification_directory"' not in old
    assert canonical_json_bytes(ServiceAdmissionHostConfig.model_validate_json(old)) == old
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
    if with_storage:
        for worker in h.admissions:
            await worker.poll_once()
        frozen = freeze(o.service.models.owner, h.cohort, h.model, block=h.block)
        amended = adoption(frozen, block=h.block).history
        source = LegacyModelStorageSourceConfig(
            schema="umi-legacy-model-storage-source/1",
            cohort_sha256=h.cohort,
            directory=str(tmp_path / "legacy-metadata"),
            baseline_model_sha256=digest(h.model),
        )
        if with_storage == "shared":
            from umi.competition_model_byte_store import ModelByteStoreConfig

            source = source.model_copy(
                update={
                    "shared_byte_store": ModelByteStoreConfig(
                        schema="umi-model-byte-verification-store/1",
                        directory=str(tmp_path / "shared-bytes"),
                    )
                }
            )
        root = Path(source.directory)
        publish_private_model(root / "legacy-inventory.json", frozen.legacy)
        publish_private_model(root / "preservation-inventory.json", frozen.preservation)
        ensure_private_directory(root / "objects")
        for key, raw in frozen.objects.items():
            path = root / "objects" / (key + ".json")
            path.write_bytes(raw)
            path.chmod(0o600)
        for file in h.model.files:
            direct.provider.objects["chunks/sha256/" + file.sha256] = (
                tmp_path / "model-submission" / file.path
            ).read_bytes()
        overrides.update(
            legacy_model_storage=(source,),
            legacy_model_verification_directory=str(tmp_path / "legacy-verification"),
        )
    else:
        amended = adopt_direct_transport(h.intake, h.cohort, block=h.block)
    configure_owner(
        o, orders, chain_config, tmp_path / "configured", monkeypatch, overrides=overrides
    )
    profile = amended.transitions[-1].transition.model_delivery_adoption.delivery
    owner = o.service.direct_uploads.owners[h.cohort]
    assert owner.config.delivery == profile
    assert canonical_json_bytes(o.config.series.cohorts[0]) == plan_bytes
    assert o.service.uploads.root == Path(overrides["model_uploads"].directory)
    if with_storage:
        if with_storage == "shared":
            assert Path(source.shared_byte_store.directory) in o.config.stores()
            resolution = o.service.legacy_payloads.sources.resolve(h.cohort, baseline=True)
            assert o.service.legacy_payloads.sources.reader(resolution).root == Path(
                source.shared_byte_store.directory
            )
        sub = frozen.subs[0]
        owner = o.service.models.owner
        assert owner.intent(h.cohort, digest(sub)) is None
        await owner.ensure_payload(h.cohort, digest(sub))
        body = owner.prepare(
            h.cohort,
            digest(sub),
            ModelArtifactReviewInputs(
                model_sha256=sub.model_revision,
                rights_evidence={"reviewed": True},
                reconstruction_evidence={"reconstructed": True},
            ),
            capture_at(h.block),
        )
        assert body.direct_artifact is None and body.accepted_ordinal == 1
        assert o.service.payloads.review_artifact(frozen.requests[0]) is None
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
        if with_storage:
            bridge = service.continued_payloads
            assert bridge.intake is h.intake
            assert bridge.uploads is service.uploads
            assert bridge.acceptances is service.models.owner
            assert bridge.sources is service.legacy_payloads.sources
            assert bridge.direct is service.direct_uploads
        else:
            assert service.continued_payloads is None
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
    if with_storage:
        for changes in (
            {"legacy_model_verification_directory": source.directory},
            {"legacy_model_verification_directory": o.config.inputs_directory},
            {"legacy_model_verification_directory": None},
            {"legacy_model_storage": ()},
        ):
            with pytest.raises(ValueError, match=r"disjoint|durable verification"):
                ServiceAdmissionHostConfig.model_validate_json(
                    canonical_json_bytes(o.config.model_copy(update=changes))
                )

        def forbidden(*args, **kwargs):
            raise AssertionError("state or key opened before metadata authentication")

        with monkeypatch.context() as patch:
            patch.setattr(host_module, "load_named_hotkey", forbidden)
            patch.setattr(host_module, "CohortPreparation", forbidden)
            patch.setattr(
                host_module, "R2MultipartClient", lambda signer, **_: SimpleNamespace(signer=signer)
            )
            wrong_namespace = o.config.model_copy(
                update={
                    "direct_model_uploads": o.config.direct_model_uploads.model_copy(
                        update={"r2_bucket": "other-model-bucket"}
                    ),
                }
            )
            with pytest.raises(ValueError, match="credentialed R2 namespace"):
                ServiceAdmissionHost(
                    wrong_namespace,
                    h.intake,
                    h.owner.promotion,
                    o.service.capture,
                    h.provider.retained_archive,
                    provider=h.provider,
                )
        # An installed source refuses damaged metadata before new keys/state.
        (root / "legacy-inventory.json").unlink()

        with monkeypatch.context() as patch:
            patch.setattr(host_module, "load_named_hotkey", forbidden)
            patch.setattr(host_module, "CohortPreparation", forbidden)
            with pytest.raises(ValueError, match="inventories require repair"):
                ServiceAdmissionHost(
                    o.config,
                    h.intake,
                    h.owner.promotion,
                    o.service.capture,
                    h.provider.retained_archive,
                    provider=h.provider,
                )
