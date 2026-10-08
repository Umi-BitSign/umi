"""Retry fences use native request, journal and miner handlers with fixture ports."""

import pytest

from umi.competition_cohort_endpoint_dispatch import CohortDispatchRetryIntent
from umi.competition_cohort_endpoint_selection import case_record_key
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_request_signer import (
    base_policy as base_policy,
)
from .test_competition_cohort_request_signer import (
    chain as chain,
)
from .test_competition_cohort_request_signer import (
    chain_config as chain_config,
)
from .test_competition_cohort_request_signer import (
    decisions as decisions,
)
from .test_competition_cohort_request_signer import (
    delivery as delivery,
)
from .test_competition_cohort_request_signer import (
    endpoint as endpoint,
)
from .test_competition_cohort_request_signer import (
    execution as execution,
)
from .test_competition_cohort_request_signer import (
    granted as granted,
)
from .test_competition_cohort_request_signer import (
    harness as harness,
)
from .test_competition_cohort_request_signer import (
    known_video_bytes as known_video_bytes,
)
from .test_competition_cohort_request_signer import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_request_signer import (
    policy as policy,
)
from .test_competition_cohort_request_signer import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_request_signer import (
    recovery as recovery,
)
from .test_competition_cohort_request_signer import (
    recovery_case as recovery_case,
)
from .test_competition_cohort_request_signer import (
    reject_first_translate,
)
from .test_competition_cohort_request_signer import (
    relay as relay,
)
from .test_competition_cohort_request_signer import (
    retiring as retiring,
)
from .test_competition_cohort_request_signer import (
    runtime as runtime,
)
from .test_competition_cohort_request_signer import (
    scenario as scenario,
)
from .test_competition_cohort_request_signer import (
    signing as signing,
)


@pytest.mark.parametrize("damage", ["original", "selection", "case", "time", "ordinal"])
async def test_retry_rejects_changed_original_binding_before_network(signing, damage):
    p = signing.p
    worker, seen = await reject_first_translate(p)
    selected, _, job = p.delivery_recovery.selection(p.retire_slot)
    original = worker._intent(selected, job, p.case_id)
    intent = original.model_copy(
        update={"started_at_unix_ns": str(int(original.started_at_unix_ns) + 1)}
    )
    retry = CohortDispatchRetryIntent(
        schema="umi-cohort-endpoint-dispatch-retry-intent/1",
        original_intent_sha256=digest(original),
        intent=intent,
    )
    raw = retry.model_dump(mode="json", by_alias=True)
    if damage == "original":
        raw["original_intent_sha256"] = "ab" * 32
    elif damage == "ordinal":
        raw["transmission_number"] = 3
    elif damage == "time":
        raw["intent"]["started_at_unix_ns"] = "0"
    else:
        raw["intent"]["selection_sha256" if damage == "selection" else "case_id"] = "ab" * 32
    key = case_record_key(selected, p.case_id)
    db = p.delivery_recovery.journal.journal
    prior = canonical_json_bytes(db.get("endpoint_dispatch_intent", key))
    db.put("endpoint_dispatch_retry_intent", key, raw)
    with pytest.raises(ValueError):
        await worker.dispatch(p.retire_slot, p.case_id)
    assert len(seen) == 1 and p.model.calls == 0
    assert canonical_json_bytes(db.get("endpoint_dispatch_intent", key)) == prior


async def test_retired_request_cannot_create_retry_intent(signing, monkeypatch):
    from umi.competition_cohort_endpoint_retirement import CohortEndpointRetirement

    from .test_competition_cohort_attempt_pipeline import expire_child

    p = signing.p
    worker, seen = await reject_first_translate(p)
    expire_child(p, p.grant, monkeypatch)
    retired = await CohortEndpointRetirement(p.delivery_recovery).retire(p.retire_slot, p.case_id)
    assert retired.status == "retained", retired
    result = await worker.dispatch(p.retire_slot, p.case_id)
    assert result == {"status": "pending", "reason": "dispatch_request_retired"}
    assert len(seen) == 1 and p.model.calls == 0
    selected, *_ = p.delivery_recovery.selection(p.retire_slot)
    assert (
        p.delivery_recovery.journal.journal.get(
            "endpoint_dispatch_retry_intent", case_record_key(selected, p.case_id)
        )
        is None
    )


async def test_policy_single_transmission_cannot_create_retry_intent(signing, monkeypatch):
    from dataclasses import replace

    from umi.config import Limits

    p = signing.p
    worker, seen = await reject_first_translate(p)
    native = Limits.from_policy
    # Exercise the dispatch-budget boundary without altering the retained
    # fixture's signed policy or weakening its grant/authority verification.
    monkeypatch.setattr(
        Limits,
        "from_policy",
        lambda policy: replace(native(policy), maximum_request_transmissions_per_assignment=1),
    )
    result = await worker.dispatch(p.retire_slot, p.case_id)
    assert result == {"status": "pending", "reason": "dispatch_transmission_budget_exhausted"}
    assert len(seen) == 1 and p.model.calls == 0
    selected, *_ = p.delivery_recovery.selection(p.retire_slot)
    assert (
        p.delivery_recovery.journal.journal.get(
            "endpoint_dispatch_retry_intent", case_record_key(selected, p.case_id)
        )
        is None
    )
