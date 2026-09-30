"""Pure, conservative admission bounds for one evaluator's dispatch workload.

This is a capacity check, not a new schedule or permission to extend a request.
Operational timings and the future block-advance bound must be supplied from an
operator's qualification; the calculation does not establish those assumptions.
Runtime finality, claim, response and expiry checks remain authoritative.
"""

from __future__ import annotations

from collections import Counter
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_authorization import (
    EndpointAssignment,
    EndpointAuthorizationPublication,
    scheduled_assignment_key,
)
from .competition_dispatch_inbox import MAXIMUM_INBOX_FILES, validate_inbox_capacity
from .open_competition import digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div

_MaximumInt = Annotated[int, Field(ge=0, le=2**53 - 1)]
_BudgetMs = Annotated[int, Field(ge=1, le=86_400_000)]
_MAXIMUM_JOBS = 262144


class DispatchTimingLimits(StrictProtocolModel):
    """Exact operative fields from EndpointDispatchConfig, with no defaults."""

    maximum_concurrency: Annotated[int, Field(ge=1, le=128)]
    page_size: Annotated[int, Field(ge=1, le=100)]
    poll_seconds: Annotated[int, Field(ge=1, le=30)]
    discovery_grace_seconds: Annotated[int, Field(ge=5, le=60)]
    request_timeout_seconds: Annotated[int, Field(ge=1, le=900)]


class DispatchTimingBudget(StrictProtocolModel):
    """Explicit qualified upper bounds, never inferred from fixture timings.

    Ingestion includes one publication's parse, proof collection and durable
    insertion. Local cycle time bounds remaining polling and per-job local work.
    Publication delay bounds signing/delivery until the complete inbox is ready.
    The rational block-advance bound applies over elapsed milliseconds; headroom
    must cover observation age and finality catch-up. It is an assumption, not a
    replacement for proving an actual finalized head.
    """

    proof_collection_ms: _BudgetMs
    origin_collection_ms: _BudgetMs
    publication_ingestion_ms: _BudgetMs
    local_cycle_ms: _BudgetMs
    publication_delay_ms: Annotated[int, Field(ge=0, le=86_400_000)]
    block_advance_numerator: Annotated[int, Field(ge=1, le=1_000_000)]
    block_advance_denominator_ms: Annotated[int, Field(ge=1, le=86_400_000)]
    finality_headroom_blocks: Annotated[int, Field(ge=0, le=1_000_000)]
    measurement_sha256: Hex32


class DispatchCapacityJob(StrictProtocolModel):
    """One local assignment, including pre-existing pending or in-flight work.

    Completed, expired and crash-uncertain claims are not runnable jobs. An
    actually in-flight job is charged a full remaining timeout conservatively;
    this input must come from the owned dispatcher, not an assumed retry.
    """

    assignment_key: Hex32
    miner_account: Hex32
    publication_sha256: Hex32
    issued_block: _MaximumInt
    deadline_block: _MaximumInt
    issue_close_ms: _MaximumInt
    response_close_ms: _MaximumInt
    state: Literal["pending", "in_flight"] = "pending"

    @model_validator(mode="after")
    def ordered_deadlines(self):
        if self.deadline_block <= self.issued_block:
            raise ValueError("dispatch block deadline must follow issuance")
        if self.response_close_ms <= self.issue_close_ms:
            raise ValueError("dispatch response deadline must follow issue close")
        return self


class DispatchCapacityPlan(StrictProtocolModel):
    """A common worst-case envelope, deliberately not a per-miner promise."""

    profile_sha256: Hex32
    assignment_count: _MaximumInt
    pending_count: _MaximumInt
    publication_count: _MaximumInt
    maximum_miner_assignments: _MaximumInt
    scan_cycles: _MaximumInt
    serial_overhead_ms: _MaximumInt
    parallel_work_ms: _MaximumInt
    last_start_upper_bound_ms: _MaximumInt
    last_finish_upper_bound_ms: _MaximumInt
    finish_block_upper_bound: _MaximumInt
    conditional_block_advance: Literal[True] = True


def timing_profile_sha256(limits: DispatchTimingLimits, budget: DispatchTimingBudget) -> str:
    limits = DispatchTimingLimits.model_validate_json(canonical_json_bytes(limits))
    budget = DispatchTimingBudget.model_validate_json(canonical_json_bytes(budget))
    return digest(
        {"limits": limits.model_dump(mode="json"), "budget": budget.model_dump(mode="json")}
    )


def capacity_job(
    publication: EndpointAuthorizationPublication,
    assignment: EndpointAssignment,
    legacy: ScoringPolicy,
    *,
    state: Literal["pending", "in_flight"] = "pending",
) -> DispatchCapacityJob:
    """Derive exact deadlines/identity from an already verified unsigned body.

    This checks structural membership and transport binding, not signatures or
    finality. The caller must validate the publication before reserving capacity.
    """
    if assignment not in publication.assignments:
        raise ValueError("capacity assignment is absent from its publication")
    request = assignment.request
    transport_hash = scoring_policy_hash(legacy)
    if (
        publication.legacy_policy_sha256 != transport_hash
        or request.scoring_policy_hash != transport_hash
    ):
        raise ValueError("capacity request transport policy mismatch")
    matching = [
        s.submission
        for s in publication.submissions
        if digest(s.submission) == assignment.submission_sha256
    ]
    if len(matching) != 1:
        raise ValueError("capacity assignment requires its exact miner submission")
    response_close = QUICKNET_GENESIS_MS + (request.response_close_round - 1) * QUICKNET_PERIOD_MS
    issue_close = (
        response_close - ceil_div(legacy.clock.response_window_seconds, 3) * QUICKNET_PERIOD_MS
    )
    return DispatchCapacityJob(
        assignment_key=scheduled_assignment_key(publication, assignment),
        miner_account=identity(matching[0].hotkey),
        publication_sha256=digest(publication),
        issued_block=request.issued_block,
        deadline_block=request.deadline_block,
        issue_close_ms=issue_close,
        response_close_ms=response_close,
        state=state,
    )


def plan_dispatch_capacity(
    jobs,
    *,
    limits: DispatchTimingLimits,
    budget: DispatchTimingBudget,
    now_ms: int,
    observed_block: int,
    additional_inbox_publications: int = 0,
    maximum_inbox_files: int = MAXIMUM_INBOX_FILES,
) -> DispatchCapacityPlan:
    """Reject a whole workload unless its conservative envelope fits every job.

    Count all local new/reserved/pending jobs, not just this proposal. Extra inbox
    files include historical publications that a restarted dispatcher re-ingests.
    The caller must hold its capacity transaction while reading that inventory.

    The envelope first charges all ingestion, serialized proofs and grace probes
    without taking overlap credit. With a slot for every distinct miner, HTTP
    work is bounded by the longest miner chain: only one task per miner can run.
    Otherwise use the list-scheduling bound W/C + (1-1/C)L: C actual task slots,
    W total padded work, L the longest miner chain. Each job includes a full
    cursor sweep delay, including a wrap, to cover
    the dispatcher's bounded page scan and polling rather than assuming immediate
    refill. An extra full HTTP timeout covers the last permissible start. This is
    intentionally conservative; it is not an optimal ordering or a throughput
    measurement. Failed proofs/ingestion invalidate the qualification assumptions.
    """
    limits = DispatchTimingLimits.model_validate_json(canonical_json_bytes(limits))
    budget = DispatchTimingBudget.model_validate_json(canonical_json_bytes(budget))
    validate_inbox_capacity(maximum_inbox_files)
    for name, value in (("now_ms", now_ms), ("observed_block", observed_block)):
        if type(value) is not int or not 0 <= value <= 2**53 - 1:
            raise ValueError(f"dispatch {name} must be a bounded nonnegative integer")
    if (
        type(additional_inbox_publications) is not int
        or not 0 <= additional_inbox_publications <= maximum_inbox_files
    ):
        raise ValueError("dispatch additional inbox count is invalid")
    work = []
    for index, job in enumerate(jobs):
        if index >= _MAXIMUM_JOBS:
            raise ValueError("dispatch workload exceeds its assignment bound")
        work.append(DispatchCapacityJob.model_validate_json(canonical_json_bytes(job)))
    if len({j.assignment_key for j in work}) != len(work):
        raise ValueError("dispatch workload repeats an assignment identity")
    publications = len({j.publication_sha256 for j in work}) + additional_inbox_publications
    if publications > maximum_inbox_files:
        raise ValueError("dispatch workload exceeds the publication inbox bound")
    for job in work:
        if job.issued_block > observed_block:
            raise ValueError("dispatch assignment issuance is not yet finalized")
        if observed_block > job.deadline_block:
            raise ValueError("dispatch assignment block deadline has elapsed")
    count = len(work)
    miners = Counter(j.miner_account for j in work)
    longest = max(miners.values(), default=0)
    scans = ceil_div(count, limits.page_size) + 1 if count else 0
    poll = limits.poll_seconds * 1000
    timeout = limits.request_timeout_seconds * 1000
    # A restarted worker repeats discovery grace and all inbox observations.
    # Each unsuccessful grace probe itself performs a serialized header proof.
    probes = ceil_div(limits.discovery_grace_seconds * 1000, poll) + 1
    serial = (
        (
            budget.publication_delay_ms
            + publications * (budget.publication_ingestion_ms + poll + budget.local_cycle_ms)
            + publications * probes * budget.proof_collection_ms
            + publications * limits.discovery_grace_seconds * 1000
            + count
            * (budget.proof_collection_ms + budget.origin_collection_ms + budget.local_cycle_ms)
        )
        if count
        else 0
    )
    padded = timeout + scans * (poll + budget.local_cycle_ms)
    # Count miners from the complete workload, including already in-flight jobs.
    # poll_once retires done tasks before admission and never starts a second
    # task for a busy miner. Enough slots therefore eliminate HTTP contention;
    # serialized I/O and cursor-sweep delays remain charged above and below.
    if len(miners) <= limits.maximum_concurrency:
        parallel = longest * padded
    else:
        parallel = ceil_div(
            (count + (limits.maximum_concurrency - 1) * longest) * padded,
            limits.maximum_concurrency,
        )
    last_start = now_ms + serial + parallel
    last_finish = last_start + timeout if count else now_ms
    finish_block = (
        observed_block
        + (
            budget.finality_headroom_blocks
            + ceil_div(
                (last_finish - now_ms) * budget.block_advance_numerator,
                budget.block_advance_denominator_ms,
            )
        )
        if count
        else observed_block
    )
    for job in work:
        if job.state == "pending" and last_start >= job.issue_close_ms:
            raise ValueError("dispatch workload cannot fit its original issue window")
        if last_finish >= job.response_close_ms:
            raise ValueError("dispatch workload cannot fit its original response window")
        if finish_block > job.deadline_block:
            raise ValueError("dispatch workload cannot fit its original block deadline")
    return DispatchCapacityPlan(
        profile_sha256=timing_profile_sha256(limits, budget),
        assignment_count=count,
        pending_count=sum(j.state == "pending" for j in work),
        publication_count=publications,
        maximum_miner_assignments=longest,
        scan_cycles=scans,
        serial_overhead_ms=serial,
        parallel_work_ms=parallel,
        last_start_upper_bound_ms=last_start,
        last_finish_upper_bound_ms=last_finish,
        finish_block_upper_bound=finish_block,
    )
