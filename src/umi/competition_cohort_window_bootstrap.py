"""Import old sends from retained, quiesced dispatcher snapshots.

The deployment caller must stop every configured dispatch writer, retain its
original snapshot and keep it stopped until all sources are imported and the
shared owner is selected. This module does not stop services or authorize live
dispatch. Missing or inconsistent originals leave the bootstrap unsealed.
"""

import hashlib
from collections.abc import Mapping

from .anchors import VerifiedAuthEvidence
from .competition_cohort_endpoint_dispatch import CohortDispatchIntent, CohortDispatchRetryIntent
from .competition_cohort_endpoint_retirement import CohortRetiredEndpointCase
from .competition_cohort_endpoint_selection import (
    case_record_key,
    parse_endpoint_selection,
    selected_requests,
    selection_grant,
    selection_slot,
)
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_miner_case import parse_miner_grant
from .competition_cohort_service_grant import ServiceMinerGrant, service_grant_slot
from .competition_cohort_service_transport import ServiceDispatchIntent, ServiceDispatchRetryIntent
from .competition_cohort_window_owner import CohortWindowOwner, WindowOperation
from .endpoint_retirement import SignedEndpointRetirementReceipt, retirement_absence_elapsed
from .open_competition import digest
from .protocol import canonical_json_bytes
from .validator import PreparedRequestAttempt

ENDPOINT_KINDS = frozenset(
    {
        "assignment",
        "endpoint_recovery_selection",
        "endpoint_dispatch_intent",
        "endpoint_dispatch_retry_intent",
        "endpoint_retired_case",
    }
)
SERVICE_KINDS = frozenset(
    {
        "service_grant",
        "service_dispatch_intent",
        "service_dispatch_retry_intent",
        "service_retirement",
    }
)


def _intent(value, selected, case_id, grant):
    intent = CohortDispatchIntent.model_validate_json(canonical_json_bytes(value))
    request = next(request for case, request in selected_requests(selected) if case == case_id)
    job = grant.attempt.order.job
    if intent.selection_sha256 != digest(selected) or intent.case_id != case_id:
        raise ValueError("bootstrap endpoint intent changed its selection")
    auth = VerifiedAuthEvidence.from_headers(
        dict(intent.auth_headers),
        request=request,
        expected_validator_hotkey=job.evaluator_hotkey,
        expected_miner_hotkey=job.submission.submission.hotkey,
    )
    PreparedRequestAttempt(
        request,
        canonical_json_bytes(request),
        job.evaluator_hotkey,
        job.submission.submission.hotkey,
        intent.auth_headers,
        auth,
    )
    return intent


def _endpoint(records):
    covered = set()
    for (kind, slot), raw in sorted(records.items()):
        if kind != "endpoint_recovery_selection":
            continue
        selected = parse_endpoint_selection(canonical_json_bytes(raw))
        if selection_slot(selected) != slot:
            raise ValueError("bootstrap endpoint selection changed its slot")
        assignment = CohortExecutionAssignment.model_validate_json(
            canonical_json_bytes(records["assignment", selected.assignment_slot])
        )
        grant = selection_grant(selected, assignment)
        for case, request in selected_requests(selected):
            key = case_record_key(selected, case)
            original = records.get(("endpoint_dispatch_intent", key))
            retired = records.get(("endpoint_retired_case", key))
            retry = records.get(("endpoint_dispatch_retry_intent", key))
            if original is None and retired is None and retry is None:
                continue  # A stored grant by itself never consumed a window.
            if original is not None:
                original = _intent(original, selected, case, grant)
                covered.add(("endpoint_dispatch_intent", key))
            if retry is not None:
                retry = CohortDispatchRetryIntent.model_validate_json(canonical_json_bytes(retry))
                if (
                    original is None
                    or retry.original_intent_sha256 != digest(original)
                    or int(retry.intent.started_at_unix_ns) < int(original.started_at_unix_ns)
                ):
                    raise ValueError("bootstrap endpoint retry lost its original intent")
                _intent(retry.intent, selected, case, grant)
                covered.add(("endpoint_dispatch_retry_intent", key))
            receipt = None
            if retired is not None:
                retired = CohortRetiredEndpointCase.model_validate_json(
                    canonical_json_bytes(retired)
                )
                if retired.selection_sha256 != digest(selected) or retired.case_id != case:
                    raise ValueError("bootstrap retirement changed its selection")
                receipt = retired.retirement
                if receipt.receipt.result != "response_retained" and not retirement_absence_elapsed(
                    receipt.receipt,
                    request,
                    observed_block=retired.observed_block,
                    observed_round=retired.observed_round,
                ):
                    raise ValueError("bootstrap absence predates its original request expiry")
                covered.add(("endpoint_retired_case", key))
            yield WindowOperation(
                schema="umi-cohort-window-operation/1",
                grant=grant,
                request=request,
                retirement=receipt,
            )
    required = {
        key
        for key in records
        if key[0] in ENDPOINT_KINDS - {"assignment", "endpoint_recovery_selection"}
    }
    if covered != required:
        raise ValueError("bootstrap endpoint send or retirement lacks its original selection")


def _service(records):
    keys = {key for kind, key in records if kind in SERVICE_KINDS - {"service_grant"}}
    for slot in sorted(keys):
        grant = parse_miner_grant(canonical_json_bytes(records["service_grant", slot]))
        if not isinstance(grant, ServiceMinerGrant) or service_grant_slot(grant.body) != slot:
            raise ValueError("bootstrap service grant changed its slot")
        original = records.get(("service_dispatch_intent", slot))
        if original is not None:
            original = ServiceDispatchIntent.model_validate_json(canonical_json_bytes(original))
            if original.grant_sha256 != digest(grant):
                raise ValueError("bootstrap service intent changed its original grant")
        retry = records.get(("service_dispatch_retry_intent", slot))
        if retry is not None:
            retry = ServiceDispatchRetryIntent.model_validate_json(canonical_json_bytes(retry))
            if (
                original is None
                or retry.original_intent_sha256 != digest(original)
                or retry.intent.grant_sha256 != digest(grant)
                or int(retry.intent.started_at_unix_ns) < int(original.started_at_unix_ns)
            ):
                raise ValueError("bootstrap service retry lost its original intent")
        raw = records.get(("service_retirement", slot))
        receipt = (
            None
            if raw is None
            else SignedEndpointRetirementReceipt.model_validate_json(canonical_json_bytes(raw))
        )
        yield WindowOperation(
            schema="umi-cohort-window-operation/1",
            grant=grant,
            request=grant.body.request,
            retirement=receipt,
        )


def import_window_source(
    owner: CohortWindowOwner,
    name: str,
    kind: str,
    records: Mapping[tuple[str, str], object],
) -> dict:
    if name not in owner.store.sources or kind not in {"endpoint", "service"}:
        raise ValueError("bootstrap source is outside configured dispatch ownership")
    kinds = ENDPOINT_KINDS if kind == "endpoint" else SERVICE_KINDS
    if any(key[0] not in kinds for key in records):
        raise ValueError("bootstrap contains an unexpected record kind")
    count = retired = 0
    for operation in _endpoint(records) if kind == "endpoint" else _service(records):
        selected = owner.selected(operation)
        owner.store.import_request(selected, operation.retirement)
        count += 1
        retired += operation.retirement is not None
    # Seal only after every configured source succeeded. This receipt identifies
    # the exact retained inputs, not a claim about process fencing or rewards.
    receipt = digest(
        [
            name,
            kind,
            [
                [*key, hashlib.sha256(canonical_json_bytes(value)).hexdigest()]
                for key, value in sorted(records.items())
            ],
        ]
    )
    return {"source": name, "source_sha256": receipt, "requests": count, "retired": retired}
