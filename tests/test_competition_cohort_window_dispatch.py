"""One real miner ledger shared by native benchmark and paid dispatch paths.

Chain, finality, media and inference are fixture ports. Signed grants, private
owner HTTP, miner ASGI, requests, responses and retirement are native.
"""

import json

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_endpoint_dispatch import CohortEndpointDispatcher
from umi.competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from umi.competition_cohort_endpoint_retirement import CohortEndpointRetirement
from umi.competition_cohort_service_grant import service_grant_slot
from umi.competition_cohort_service_requests import ServiceWorkRequests
from umi.competition_cohort_service_transport import ServiceWorkTransport
from umi.competition_cohort_window_bootstrap import (
    ENDPOINT_KINDS,
    SERVICE_KINDS,
    import_window_source,
)
from umi.competition_cohort_window_http import LocalWindowClient, RemoteWindowClient, window_routes
from umi.endpoint_protocol import COHORT_RETIRE_PATH, TRANSLATE_PATH
from umi.miner import create_app

from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import fresh_window, produce_grant
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
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_competition_cohort_service_worker import loop as loop
from .test_competition_cohort_window_owner import TOKEN, owner_at


@pytest.mark.parametrize("bootstrap_existing", [False, True])
async def test_paid_window_waits_for_endpoint_retirement_through_lost_ack_and_owner_restart(
    loop, tmp_path, monkeypatch, bootstrap_existing
):
    s, p, c = loop, loop.p, loop.c
    root = tmp_path / "mixed-windows"
    local = LocalWindowClient(owner_at(c, root, bootstrap=not bootstrap_existing))
    private = FastAPI()
    private.include_router(window_routes(local, token=TOKEN))
    paths, statuses = [], []
    lost_retirement = False

    class MinerNetwork(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            nonlocal lost_retirement
            paths.append(request.url.path)
            response = await httpx.ASGITransport(app=create_app(p.miner)).handle_async_request(
                request
            )
            statuses.append(response.status_code)
            if request.url.path == COHORT_RETIRE_PATH and lost_retirement:
                assert response.status_code == 200
                lost_retirement = False
                await response.aread()
                await response.aclose()
                raise httpx.ReadError("lost original retirement acknowledgement")
            return response

    network = MinerNetwork()
    existing = p.e.journal
    p.e.journal = lambda **kw: existing(directory=str(tmp_path / "mixed-execution"), **kw)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=private)) as http:
        remote = RemoteWindowClient(http, "https://owner.example", token=TOKEN)
        recovery = CohortEndpointResponseRecovery(
            p.service(),
            p.validator,
            transport=network,
            windows=None if bootstrap_existing else remote,
        )
        selected = await recovery.prepare(p.e.assignment, p.signed, p.transport_policy)
        slot, case = selected.assignment_slot, p.case_id
        sent = await CohortEndpointDispatcher(recovery, p.finality).dispatch(slot, case)
        assert sent["status"] == "recovered", sent
        assert paths.count(TRANSLATE_PATH) == p.model.calls == 1

        if bootstrap_existing:
            with recovery.journal.journal.read_transaction() as db:
                records = {
                    (kind, key): json.loads(raw)
                    for kind, key, raw in db.execute("SELECT kind,id,body FROM records")
                    if kind in ENDPOINT_KINDS
                }
            # An orphan old send cannot be omitted just because its parent is
            # missing. Partial import is retained but cannot enable scheduling.
            broken = dict(records)
            original = next(
                value for (kind, _), value in records.items() if kind == "endpoint_dispatch_intent"
            )
            broken["endpoint_dispatch_intent", "ff" * 32] = original
            with pytest.raises(ValueError, match="lacks its original selection"):
                import_window_source(local.owner, "native-fixture", "endpoint", broken)
            receipt = import_window_source(local.owner, "native-fixture", "endpoint", records)
            assert receipt["requests"] == 1 and receipt["retired"] == 0
            local.owner.store.seal_bootstrap({"native-fixture": receipt["source_sha256"]})
            recovery.windows = remote

        window = fresh_window(p, p.requests[0], monkeypatch)
        grant = produce_grant(p, c, window)
        assert grant.body.request.window_id != p.requests[0].window_id
        paid = ServiceWorkTransport(
            ServiceWorkRequests(c.queue, p.transport_policy),
            p.validator,
            p.finality,
            s.origin,
            transport=network,
            windows=local,
        )
        paid_slot = service_grant_slot(grant.body)
        held = await paid.advance(paid_slot)
        assert held.reason == "miner_window_admission_pending"
        assert paid.journal.get("service_dispatch_intent", paid_slot) is None
        assert paths.count(TRANSLATE_PATH) == p.model.calls == 1

        lost_retirement = True
        retirement = CohortEndpointRetirement(recovery)
        assert (await retirement.retire(slot, case)).status == "pending"
        # The miner fenced execution, but the owner has no acknowledged fence.
        local.owner = owner_at(c, root, bootstrap=False)
        assert (await paid.advance(paid_slot)).reason == "miner_window_admission_pending"
        assert paths.count(TRANSLATE_PATH) == p.model.calls == 1
        assert (await retirement.retire(slot, case)).status == "retained"
        completed = await paid.advance(paid_slot)
        assert completed.reason == "response_retained", completed
        assert completed.response is not None and completed.retirement is not None
        assert paths.count(TRANSLATE_PATH) == p.model.calls == 2
        assert 429 not in statuses
        assert (await paid.advance(paid_slot)) == completed
        assert p.model.calls == 2
        with paid.journal.read_transaction() as db:
            records = {
                (kind, key): json.loads(raw)
                for kind, key, raw in db.execute("SELECT kind,id,body FROM records")
                if kind in SERVICE_KINDS
            }
        imported = owner_at(c, tmp_path / "paid-bootstrap", bootstrap=False)
        receipt = import_window_source(imported, "native-fixture", "service", records)
        assert receipt["requests"] == receipt["retired"] == 1
        imported.store.seal_bootstrap({"native-fixture": receipt["source_sha256"]})
        assert await LocalWindowClient(imported).reserve(grant, grant.body.request) == "retired"
