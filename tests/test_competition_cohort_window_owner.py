"""Native signed grants through the authenticated window owner boundary."""

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_window_http import (
    WINDOW_PATH,
    LocalWindowClient,
    RemoteWindowClient,
    window_routes,
)
from umi.competition_cohort_window_owner import CohortWindowOwner, WindowOperation
from umi.competition_cohort_window_store import CohortMinerWindowStore
from umi.config import Limits
from umi.endpoint_retirement import EndpointRetirementReceipt, SignedEndpointRetirementReceipt
from umi.open_competition import digest, sign_object
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes, request_digest

from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import harness as harness
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import original_harness as original_harness
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group

TOKEN = "owner-window-test-token-32-bytes-long"


def owner_at(service, path, *, bootstrap=True):
    p = service.p
    cohorts = p.e.cfg.cohorts
    store = CohortMinerWindowStore(
        path,
        cohorts=tuple(c.cohort_sha256 for c in cohorts),
        evaluators=tuple(e.hotkey for e in p.c.policy.evaluators),
        transports={
            scoring_policy_hash(p.transport_policy): Limits.from_policy(p.transport_policy)
        },
        bootstrap_sources=("native-fixture",),
    )
    if bootstrap:
        store.seal_bootstrap({"native-fixture": "aa" * 32})
    return CohortWindowOwner(
        store,
        p.c.policy,
        (p.transport_policy,),
        {c.cohort_sha256: c.authority_sha256 for c in cohorts},
    )


def operation(grant, request):
    return WindowOperation(schema="umi-cohort-window-operation/1", grant=grant, request=request)


async def test_signed_endpoint_and_paid_grants_reuse_exact_checks_after_restart(
    service, tmp_path, monkeypatch
):
    c, p = service, service.p
    path = tmp_path / "windows"
    owner = owner_at(c, path)
    endpoint = operation(p.grant, p.requests[0])
    paid = operation(c.grant, c.grant.body.request)
    assert owner.apply(endpoint).status == owner.apply(paid).status == "reserved"
    owner = owner_at(c, path)
    monkeypatch.setattr(
        owner, "_verify", lambda value: pytest.fail("exact grant was already verified")
    )
    assert owner.apply(endpoint).status == owner.apply(paid).status == "reserved"
    with pytest.raises(ValueError):
        owner.apply(endpoint.model_copy(update={"request": paid.request}))


async def test_invalid_signature_cannot_reserve_a_window(service, tmp_path):
    c = service
    owner = owner_at(c, tmp_path / "windows")
    grant = c.grant.model_copy(update={"signatures": ()})
    with pytest.raises(ValueError):
        owner.apply(operation(grant, c.grant.body.request))
    with owner.store.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM miner_windows").fetchone() == (0,)


async def test_private_owner_auth_and_bound_remote_retirement(service, tmp_path):
    c, p = service, service.p
    owner = owner_at(c, tmp_path / "windows")
    local = LocalWindowClient(owner)
    app = FastAPI()
    app.include_router(window_routes(local, token=TOKEN))
    grant, request = p.grant, p.requests[0]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://owner.example"
    ) as http:
        denied = await http.post(
            WINDOW_PATH,
            content=canonical_json_bytes(operation(grant, request)),
            headers={"content-type": "application/json"},
        )
        assert denied.status_code == 401
        remote = RemoteWindowClient(http, "https://owner.example", token=TOKEN)
        assert await remote.reserve(grant, request) == "reserved"
        body = EndpointRetirementReceipt(
            schema="umi-endpoint-retirement/1",
            grant_sha256=digest(grant),
            request_digest=request_digest(request),
            miner_hotkey=p.miner.hotkey_ss58,
            evaluator_hotkey=p.validator.hotkey.ss58_address,
            result="response_retained",
            response_sha256="ef" * 32,
        )
        receipt = SignedEndpointRetirementReceipt(
            receipt=body, signature=sign_object(body, p.miner.wallet)
        )
        assert await remote.retire(grant, request, receipt) == "retired"
        assert await remote.reserve(grant, request) == "retired"


async def test_remote_reply_cannot_change_reserved_operation(service):
    c = service
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "schema": "umi-cohort-window-result/1",
                    "operation_sha256": "ab" * 32,
                    "status": "reserved",
                },
            )
        )
    ) as http:
        client = RemoteWindowClient(http, "https://owner.example", token=TOKEN)
        with pytest.raises(ValueError):
            await client.reserve(c.grant, c.grant.body.request)
