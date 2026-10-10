"""Complete service request closure alongside the retained benchmark closure.

Every accepted job binds its fenced response or an explicit tail disposition
before references are revealed. Missing infrastructure evidence is never a zero.
The configured catalog set and owner exports must be authenticated by reviewers.
"""

from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_endpoint_archive import EndpointObjectSource, read_endpoint_object
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_request_closure import (
    CohortRequestClosure,
    review_request_closure,
    unfinished_request_miners,
)
from .competition_cohort_request_progress import certified_request_prefix
from .competition_cohort_request_tail import review_request_tail
from .competition_cohort_service_seal import ServiceWorkSeal, sealed_service_assignments
from .competition_cohort_service_terminal import SignedServiceTerminal, read_service_terminal
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_execution import ExecutionBoundary
from .open_competition import CompetitionPolicy, digest, identity
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ServiceCatalogClosure(StrictProtocolModel):
    catalog_sha256: Hex32
    seal_sha256: Hex32
    terminals: Annotated[tuple[Hex32, ...], Field(max_length=8192)]
    skipped_work: Annotated[tuple[Hex32, ...], Field(max_length=8192)] | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.skipped_work is None:
            value.pop("skipped_work", None)
        return value

    @model_validator(mode="after")
    def unique_skipped_work(self):
        if self.skipped_work is not None and self.skipped_work != tuple(
            sorted(set(self.skipped_work))
        ):
            raise ValueError("skipped service work must be unique and ordered")
        return self


class CohortServiceRequestClosure(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-closure/2", "umi-cohort-request-closure/4"] = Field(
        alias="schema"
    )
    benchmark_closure_sha256: Hex32
    recovery_tip_sha256: Hex32
    observation: ExecutionBoundary
    catalogs: Annotated[tuple[ServiceCatalogClosure, ...], Field(min_length=1, max_length=64)]
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def selected_version(self):
        tail = self.schema_ == "umi-cohort-request-closure/4"
        if any((c.skipped_work is not None) != tail for c in self.catalogs):
            raise ValueError("service closure version differs from explicit skipped inventory")
        return self


def review_service_request_closure(
    closure: CohortServiceRequestClosure,
    roster,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    history,
    transport: ScoringPolicy,
    *,
    expected_catalogs: tuple[SignedServiceWorkCatalog, ...],
    expected_seals: tuple[ServiceWorkSeal, ...],
    decision_source,
    intake_records,
    expected_tip_sha256: str,
    current_block: int,
):
    closure = CohortServiceRequestClosure.model_validate_json(canonical_json_bytes(closure))
    expected = tuple(digest(c.catalog) for c in expected_catalogs)
    if (
        expected != tuple(sorted(set(expected)))
        or tuple(c.catalog_sha256 for c in closure.catalogs) != expected
    ):
        raise ValueError("service closure must include the complete authorized catalog set")
    if tuple(s.catalog_sha256 for s in expected_seals) != expected or tuple(
        digest(s) for s in expected_seals
    ) != tuple(c.seal_sha256 for c in closure.catalogs):
        raise ValueError("service closure differs from independently selected owner seals")
    benchmark = CohortRequestClosure.model_validate_json(
        read_endpoint_object(objects, closure.benchmark_closure_sha256)
    )
    tail = closure.schema_ == "umi-cohort-request-closure/4"
    if tail != (benchmark.schema_ == "umi-cohort-request-closure/3"):
        raise ValueError("service closure version differs from its benchmark disposition")
    if (
        benchmark.observation != closure.observation
        or benchmark.recovery_tip_sha256 != closure.recovery_tip_sha256
    ):
        raise ValueError("service and benchmark closure observations differ")
    review_request_closure(
        benchmark,
        roster,
        objects,
        policy,
        history,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    opened = view.closure("preparation").observed_at_block
    # Distinct signed catalogs do not establish new useful work for one video.
    # Reject overlapping inventory in this closure even when only one is used.
    videos = set()
    all_assignments, unfinished = [], set()
    if tail:
        unfinished.update(unfinished_request_miners(benchmark, roster))
    for ref, catalog in zip(closure.catalogs, expected_catalogs, strict=True):
        inventory = {w.video_sha256 for w in catalog.catalog.work}
        if videos & inventory:
            raise ValueError("service catalogs repeat a paid input")
        videos.update(inventory)
        seal = ServiceWorkSeal.model_validate_json(read_endpoint_object(objects, ref.seal_sha256))
        if seal.observation.block > closure.observation.block:
            raise ValueError("service accepted set was sealed after request closure")
        if not tail and len(ref.terminals) != len(seal.accepted):
            raise ValueError("service closure omits accepted terminal work")
        sealed_source = CohortOrderHistory.model_validate_json(
            read_endpoint_object(objects, seal.source_sha256)
        )
        if (
            sealed_source.history.authority != history.authority
            or sealed_source.history.plan != history.plan
            or sealed_source.history.transitions
            != history.transitions[: len(sealed_source.history.transitions)]
        ):
            raise ValueError("service seal belongs to another request history")
        assignments = tuple(
            sealed_service_assignments(
                seal,
                objects,
                policy,
                catalog=catalog,
                round_=roster.round,
            )
        )
        all_assignments.extend(assignments)
        by_work = {a.admission.work_sha256: a for a in assignments}
        if len(by_work) != len(assignments):
            raise ValueError("service closure repeats an accepted work identity")
        skipped = set(ref.skipped_work or ())
        if not skipped <= set(by_work):
            raise ValueError("service closure skips unaccepted work")
        unfinished.update(
            identity(by_work[k].admission.submission.submission.hotkey) for k in skipped
        )
        completed = []
        for terminal_sha in ref.terminals:
            signed = SignedServiceTerminal.model_validate_json(
                read_endpoint_object(objects, terminal_sha)
            )
            key = signed.terminal.work_sha256
            if key not in by_work or key in completed or key in skipped:
                raise ValueError("service closure repeats, substitutes or skips completed work")
            completed.append(key)
            assignment = by_work[key]
            grant = read_service_terminal(
                signed,
                objects,
                policy,
                transport,
                request_interval=(opened, closure.observation.block),
            )
            if grant.body.assignment != assignment:
                raise ValueError("service closure terminal belongs to another accepted work")
            source = CohortOrderHistory.model_validate_json(
                read_endpoint_object(objects, signed.terminal.source_sha256)
            )
            if (
                source.history.authority != history.authority
                or source.history.plan != history.plan
                or source.history.transitions
                != history.transitions[: len(source.history.transitions)]
            ):
                raise ValueError("service terminal belongs to another request history")
        if set(completed) | skipped != set(by_work):
            raise ValueError("service closure must partition every accepted work identity")
        if not tail and completed != [a.admission.work_sha256 for a in assignments]:
            raise ValueError("legacy service closure changed its original terminal order")
    if tail:
        review_request_tail(
            benchmark.tail,
            roster=roster,
            history=history,
            decision_source=decision_source,
            observation=closure.observation,
            unfinished_hotkeys=unfinished,
            service_assignments=tuple(all_assignments),
        )
    return closure


def verify_certified_service_request_closure(
    closure,
    roster,
    objects,
    policy,
    history,
    transport,
    *,
    expected_catalogs,
    expected_seals,
    decision_source,
    intake_records,
    expected_tip_sha256,
    current_block,
):
    closure = CohortServiceRequestClosure.model_validate_json(canonical_json_bytes(closure))
    benchmark = CohortRequestClosure.model_validate_json(
        read_endpoint_object(objects, closure.benchmark_closure_sha256)
    )
    prefix = certified_request_prefix(
        closure,
        objects,
        policy,
        history,
        decision_source=decision_source,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
        tail=benchmark.tail,
    )
    return review_service_request_closure(
        closure,
        roster,
        objects,
        policy,
        prefix,
        transport,
        expected_catalogs=expected_catalogs,
        expected_seals=expected_seals,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=history_tip(prefix),
        current_block=closure.observation.block,
    )
