"""Archival quorum selection feeds the existing native retirement and retry owner."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_legacy_model_admission import LegacyModelAdmissionPayloads
from umi.competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from umi.competition_cohort_legacy_model_storage import authenticate_legacy_storage_inventories
from umi.competition_cohort_model_transport_selection import committed_model_delivery_selection
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_delivery_issuance import base_policy as base_policy
from .test_competition_cohort_model_delivery_issuance import case as case
from .test_competition_cohort_model_delivery_issuance import issuance as issuance
from .test_competition_cohort_model_delivery_issuance import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_delivery_issuance import model_only as model_only
from .test_competition_cohort_model_delivery_issuance import owner_api as owner_api
from .test_competition_cohort_model_delivery_issuance import policy as policy
from .test_competition_cohort_model_delivery_issuance import prepared as prepared
from .test_competition_cohort_model_delivery_issuance import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_delivery_issuance import recovery as recovery
from .test_competition_cohort_model_delivery_issuance import runtime as runtime
from .test_competition_cohort_model_delivery_issuance import storage_only as storage_only
from .test_competition_cohort_model_delivery_issuance import (
    test_normal_owner_routes_review_quorum_commit_and_repeat as commit_issuance,
)
from .test_competition_model_storage_retirement import retirement as retirement
from .test_competition_model_storage_retirement import (
    test_absent_consumer_never_fences_or_unlinks_native_payload as absent_consumer,
)
from .test_competition_model_storage_retirement import (
    test_background_poll_retires_then_restarts_and_reuses_original_requests as retire_and_restart,
)
from .test_competition_model_storage_retirement import (
    test_generation_reuse_never_substitutes_for_retirement_restore_availability as no_restore,
)
from .test_competition_model_storage_retirement import (
    test_interrupted_retirement_resumes_without_payload_reverification as interrupted_retirement,
)

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
    pytest.mark.parametrize("storage_only", [True], indirect=True),
]


@pytest.fixture
async def frozen(owner_api, tmp_path):
    a, i = owner_api, owner_api.i
    c = i.case
    await commit_issuance(a, tmp_path)
    selection = committed_model_delivery_selection(a.store, c.cohort, c.policy)
    auth = authenticate_legacy_storage_inventories(
        canonical_json_bytes(c.legacy),
        canonical_json_bytes(c.preservation),
        selection=selection,
        policy=c.policy,
        expected_baseline_sha256=digest(c.baseline),
    )
    sources = LegacyModelStorageReaders(
        {c.cohort: auth},
        policy=c.policy,
        load_original=c.objects.__getitem__,
        multipart=i.remote,
        verification_root=i.config.verification_directory,
    )
    payloads = LegacyModelAdmissionPayloads(c.owner.intake, sources)
    model = c.subs[0].model_revision
    (c.owner.archive / model).rename(tmp_path / "offline-original")
    return SimpleNamespace(
        case=SimpleNamespace(
            **(
                vars(c)
                | {
                    "requests": [r.record.request for r in c.requests],
                }
            )
        ),
        owner=SimpleNamespace(intake=c.owner.intake, legacy_payloads=payloads),
        sources=sources,
        remote=i.remote,
    )


async def test_archival_retirement_and_original_retry_restart(retirement):
    await retire_and_restart(retirement)


async def test_archival_retirement_requires_live_consumer(retirement):
    await absent_consumer(retirement)


async def test_archival_retirement_requires_remote_restore_availability(retirement):
    await no_restore(retirement)


@pytest.mark.parametrize("boundary", ["unlink_done", "payload_removed", "release_completed"])
async def test_archival_retirement_resumes_interrupted_unlink_without_reverification(
    retirement, monkeypatch, boundary
):
    await interrupted_retirement(retirement, monkeypatch, boundary)
