"""Replay the complete accepted FIFO prefix before service request closure.

The seal is an owner export, not a quorum assertion of completeness. Independent
reviewers must authenticate the original queue and the allowed catalog set.
"""

from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint_archive import EndpointObjectSource, read_endpoint_object
from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_service_work import (
    ServiceWorkAssignment,
    review_service_assignment,
    review_service_catalog,
)
from .competition_execution import ExecutionBoundary
from .open_competition import CompetitionPolicy, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_SERVICE_SEAL_BYTES = 2 * 1024**2


class ServiceAcceptedWork(StrictProtocolModel):
    work_sha256: Hex32
    assignment_sha256: Hex32


class ServiceWorkSeal(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-work-seal/1"] = Field(alias="schema")
    catalog_sha256: Hex32
    source_sha256: Hex32
    observation: ExecutionBoundary
    accepted: Annotated[tuple[ServiceAcceptedWork, ...], Field(max_length=8192)]
    chain_submission_authorized: Literal[False] = False


def sealed_service_assignments(
    seal: ServiceWorkSeal,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    *,
    catalog,
    round_,
) -> Iterable[ServiceWorkAssignment]:
    """Exhaust this iterator to verify every member and its exact predecessor."""
    seal = ServiceWorkSeal.model_validate_json(canonical_json_bytes(seal))
    if seal.catalog_sha256 != digest(catalog.catalog):
        raise ValueError("service seal substituted its catalog")
    source = CohortOrderHistory.model_validate_json(
        read_endpoint_object(objects, seal.source_sha256)
    )
    review_service_catalog(
        catalog,
        round_,
        policy,
        source,
        expected_tip_sha256=history_tip(source.history),
        current_block=seal.observation.block,
    )
    if len(seal.accepted) > len(catalog.catalog.work):
        raise ValueError("service seal exceeds its catalog")
    previous = None
    for ordinal, ref in enumerate(seal.accepted, 1):
        assignment = review_service_assignment(
            ServiceWorkAssignment.model_validate_json(
                read_endpoint_object(objects, ref.assignment_sha256)
            ),
            policy,
        )
        admission = assignment.admission
        prefix = assignment.source.history.transitions
        if (
            assignment.catalog != catalog
            or assignment.round != round_
            or admission.ordinal != ordinal
            or assignment.previous != previous
            or admission.work_sha256 != ref.work_sha256
            or admission.observation.block > seal.observation.block
            or assignment.source.history.authority != source.history.authority
            or assignment.source.history.plan != source.history.plan
            or prefix != source.history.transitions[: len(prefix)]
        ):
            raise ValueError("service seal differs from its complete accepted prefix")
        previous = admission
        yield assignment
