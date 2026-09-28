"""Construct complete request evidence from the original accepted work.

The caller selects the authenticated catalog set and owner seals. Missing
terminal work stays pending without an age cutoff. This builder neither seals
admissions nor reveals references, signs a phase, or changes a reward allocation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import EndpointObjectSource, read_endpoint_object
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_request_closure import CohortRequestClosure
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_closure import (
    CohortServiceRequestClosure,
    ServiceCatalogClosure,
    review_service_request_closure,
)
from .competition_cohort_service_seal import ServiceWorkSeal, sealed_service_assignments
from .competition_cohort_service_terminal import SignedServiceTerminal
from .competition_cohort_service_work import ServiceWorkAssignment, SignedServiceWorkCatalog
from .open_competition import CompetitionPolicy, digest
from .policy import ScoringPolicy
from .protocol import canonical_json_bytes


class PendingServiceRequestClosure(ValueError):
    def __init__(self, work: tuple[str, ...]):
        self.work = work
        super().__init__(f"service request closure still has {len(work)} pending jobs")


def build_service_request_closure(
    benchmark: CohortRequestClosure,
    roster: RecoverableRosterEvidence,
    catalogs: tuple[SignedServiceWorkCatalog, ...],
    seals: tuple[ServiceWorkSeal, ...],
    terminal_source: Callable[[ServiceWorkAssignment], SignedServiceTerminal | None],
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    history: CohortRecoveryHistory,
    transport: ScoringPolicy,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> CohortServiceRequestClosure:
    """Gather every accepted terminal, then replay the complete native closure.

    Benchmark, seal and terminal objects must be durably retrievable by digest.
    Inputs come from owner exports; this function never inspects a peer's live
    database. A caller cannot use arrival time to retime the benchmark closure.
    """
    benchmark = CohortRequestClosure.model_validate_json(canonical_json_bytes(benchmark))
    catalogs = tuple(
        SignedServiceWorkCatalog.model_validate_json(canonical_json_bytes(c)) for c in catalogs
    )
    seals = tuple(ServiceWorkSeal.model_validate_json(canonical_json_bytes(s)) for s in seals)
    keys = tuple(digest(c.catalog) for c in catalogs)
    if (
        not 1 <= len(keys) <= 64
        or keys != tuple(sorted(set(keys)))
        or tuple(s.catalog_sha256 for s in seals) != keys
    ):
        raise ValueError("request completion requires every selected catalog and owner seal")
    if read_endpoint_object(objects, digest(benchmark)) != canonical_json_bytes(benchmark):
        raise ValueError("request completion changed the retained benchmark")
    pending, completed = [], []
    for catalog, seal in zip(catalogs, seals, strict=True):
        if read_endpoint_object(objects, digest(seal)) != canonical_json_bytes(seal):
            raise ValueError("request completion changed an owner seal")
        terminals = []
        for assignment in sealed_service_assignments(
            seal, objects, policy, catalog=catalog, round_=roster.round
        ):
            terminal = terminal_source(assignment)
            if terminal is None:
                pending.append(assignment.admission.work_sha256)
                continue
            terminal = SignedServiceTerminal.model_validate_json(canonical_json_bytes(terminal))
            if terminal.terminal.work_sha256 != assignment.admission.work_sha256:
                raise ValueError("request completion substituted another accepted job")
            terminals.append(digest(terminal))
        completed.append(
            ServiceCatalogClosure(
                catalog_sha256=digest(catalog.catalog),
                seal_sha256=digest(seal),
                terminals=tuple(terminals),
            )
        )
    if pending:
        raise PendingServiceRequestClosure(tuple(pending))
    closure = CohortServiceRequestClosure(
        schema="umi-cohort-request-closure/2",
        benchmark_closure_sha256=digest(benchmark),
        recovery_tip_sha256=benchmark.recovery_tip_sha256,
        observation=benchmark.observation,
        catalogs=tuple(completed),
    )
    return review_service_request_closure(
        closure,
        roster,
        objects,
        policy,
        history,
        transport,
        expected_catalogs=catalogs,
        expected_seals=seals,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
