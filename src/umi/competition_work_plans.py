"""Reference-free work proposals derived from a quorum cutoff and owned issuance.

These builders do not load wallets, sign, execute, publish or transmit work.
Signing and delivery must retain these exact bytes and original deadlines.
"""

from __future__ import annotations

from collections import Counter
from typing import Annotated, Literal

from pydantic import Field

from .competition_authorization import (
    EndpointAssignment,
    EndpointAuthorizationCase,
    EndpointAuthorizationPublication,
    SignedEndpointAuthorization,
    assignment_batch_id,
    assignment_challenge_id,
    validate_publication,
    validate_publication_body,
)
from .competition_chain import CompetitionChainConfig
from .competition_evaluator import EvaluationOrder, validate_order_body
from .competition_execution import ExecutionCase
from .competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    verify_cutoff_publication,
)
from .competition_runner import OfflineRuntime
from .competition_scheduling import _clock
from .open_competition import (
    DEPENDENCE_POLICY_SCHEMA,
    CompetitionPolicy,
    EvaluationSuite,
    Hotkey,
    ModelBundle,
    SignedSubmission,
    digest,
    has_case_coverage,
    identity,
    validate_bundle_policy,
    validate_suite_profile,
)
from .policy import ScoringPolicy, require_live_chain_observation, scoring_policy_hash
from .private_files import Directory
from .protocol import (
    PROTOCOL_VERSION,
    Hex32,
    StrictProtocolModel,
    Task,
    TranslationRequest,
    Video,
    canonical_json_bytes,
)
from .validator_plans import VerifiedFinalizedBlock
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

MAX_BYTES = 16 * 1024**2


class WorkPlan(StrictProtocolModel):
    schema_: Literal["umi-round-work-plan/1"] = Field(alias="schema")
    cutoff: SignedCutoffPublication
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=512)]
    incumbent: ModelBundle
    runtime: OfflineRuntime
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]
    evaluators: Annotated[tuple[Hotkey, ...], Field(min_length=1, max_length=64)]
    chain_submission_authorized: Literal[False] = False


class RoundWorkConfig(StrictProtocolModel):
    state_directory: Directory
    asset_directory: Directory
    order_directory: Directory
    publication_directory: Directory
    transport_chain: CompetitionChainConfig
    legacy_policy_sha256: Hex32
    minimum_issue_ms: Annotated[int, Field(ge=1, le=300_000)]


class RoundWorkAssets(StrictProtocolModel):
    schema_: Literal["umi-round-work-assets/1"] = Field(alias="schema")
    suite_sha256: Hex32
    incumbent: ModelBundle
    runtime: OfflineRuntime
    videos: Annotated[tuple[Video, ...], Field(min_length=3, max_length=2048)]


def evaluator_selection(policy, submissions, cutoff):
    """Canonical independent representatives who actually endorsed the cutoff."""
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    miners = {identity(s.submission.hotkey) for s in submissions}
    forbidden = {groups[k] for k in miners if k in groups}
    endorsed = {identity(s.hotkey) for s in cutoff.signatures}
    selected, seen = [], set()
    for evaluator in sorted(policy.evaluators, key=lambda e: identity(e.hotkey)):
        group = evaluator.control_group
        if (
            identity(evaluator.hotkey) not in endorsed
            or identity(evaluator.hotkey) in miners
            or group in forbidden
            or group in seen
        ):
            continue
        selected.append(evaluator.hotkey)
        seen.add(group)
        if len(selected) == policy.required_evaluator_groups:
            break
    if len(selected) != policy.required_evaluator_groups:
        raise ValueError("work plan lacks eligible independent evaluator groups")
    return tuple(selected)


def validate_work_plan(plan, policy):
    raw = canonical_json_bytes(plan)
    if len(raw) > MAX_BYTES:
        raise ValueError("work plan exceeds its byte bound")
    plan = WorkPlan.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    verify_cutoff_publication(
        plan.cutoff,
        policy=policy,
        submissions=plan.submissions,
        limits=PublicationReplayLimits(
            maximum_roster_bytes=MAX_BYTES,
            maximum_certificate_bytes=MAX_BYTES,
            maximum_evidence_bytes=MAX_BYTES,
        ),
    )
    round_ = plan.cutoff.publication.round
    if (
        digest(plan.runtime) != round_.runtime_sha256
        or digest(plan.incumbent) != round_.incumbent_model_sha256
    ):
        raise ValueError("work plan runtime or incumbent differs from the cutoff")
    validate_bundle_policy(plan.incumbent, policy)
    if plan.evaluators != evaluator_selection(policy, plan.submissions, plan.cutoff):
        raise ValueError("work plan evaluator selection differs from the canonical groups")
    video_counts = Counter(case.video_sha256 for case in plan.cases)
    if (
        len({c.case_id for c in plan.cases}) != len(plan.cases)
        or (policy.schema_ != DEPENDENCE_POLICY_SCHEMA and len(video_counts) != len(plan.cases))
        or any(count > 2 for count in video_counts.values())
        or not has_case_coverage(plan.cases, policy)
    ):
        raise ValueError("work plan cases have invalid identity or stratum coverage")
    return plan


def prepare_work_plan(*, cutoff, submissions, suite, incumbent, runtime, policy):
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    validate_suite_profile(suite, policy)
    plan = validate_work_plan(
        WorkPlan(
            schema="umi-round-work-plan/1",
            cutoff=cutoff,
            submissions=tuple(submissions),
            incumbent=incumbent,
            runtime=runtime,
            cases=tuple(
                ExecutionCase(
                    case_id=c.case_id,
                    video_sha256=c.video_sha256,
                    stratum=c.stratum,
                )
                for c in suite.cases
            ),
            evaluators=evaluator_selection(policy, submissions, cutoff),
        ),
        policy,
    )
    if (
        suite.policy_sha256 != digest(policy)
        or digest(suite) != plan.cutoff.publication.round.suite_sha256
    ):
        raise ValueError("work plan suite differs from the frozen cutoff")
    return plan


def _verified_transport_block(block, legacy):
    if not isinstance(block, VerifiedFinalizedBlock):
        raise TypeError("work preparation requires process-owned verified transport blocks")
    if block.scoring_policy_hash != scoring_policy_hash(legacy):
        raise ValueError("work preparation transport block policy differs")
    require_live_chain_observation(legacy, block.chain_observation)
    pin = legacy.implementation_pins.finality_verifier
    if pin is None or block.finality_verifier_sha256 not in pin.release_sha256_by_target.values():
        raise ValueError("work preparation finality verifier differs")


def endpoint_proposals(
    *,
    plan,
    policy,
    legacy,
    videos,
    announcement,
    issuance,
    now_ms,
    minimum_issue_ms,
    submission_sha256=None,
    verification_head=None,
):
    """Build one miner-audience proposal per endpoint from a current owned window.

    The caller obtains both blocks from its own transport-bound provider. A
    remotely supplied block dictionary must never be promoted to this type.
    Rechecking an existing proposal may supply a fresh owned verification head
    while retaining its original issuance and all original window boundaries.
    """
    plan = validate_work_plan(plan, policy)
    legacy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy))
    if policy.schema_ == DEPENDENCE_POLICY_SCHEMA and legacy.clock.issue_allowance_seconds != 5400:
        raise ValueError("dependence work requires the signed 5400-second issue allowance")
    for block in (announcement, issuance):
        _verified_transport_block(block, legacy)
    if (
        type(now_ms) is not int
        or now_ms < 0
        or (
            type(minimum_issue_ms) is not int
            or not 1 <= minimum_issue_ms < legacy.clock.issue_allowance_seconds * 1000
        )
    ):
        raise ValueError("work preparation needs explicit bounded issue-time allowance")
    if verification_head is None:
        if not now_ms - 60_000 <= issuance.timestamp_ms <= now_ms + 5_000:
            raise ValueError("work preparation issuance is not fresh")
    else:
        _verified_transport_block(verification_head, legacy)
        if (
            verification_head.height < issuance.height
            or verification_head.timestamp_ms < issuance.timestamp_ms
            or not now_ms - 60_000 <= verification_head.timestamp_ms <= now_ms + 5_000
            or (verification_head.height == issuance.height and verification_head != issuance)
        ):
            raise ValueError("work verification head is stale or inconsistent with issuance")
    if (
        issuance.height < legacy.activation_block
        or announcement.timestamp_ms > issuance.timestamp_ms
    ):
        raise ValueError("work preparation transport blocks are out of order")
    index = (issuance.height - legacy.activation_block) // legacy.clock.window_stride_blocks
    expected_announcement = legacy.activation_block + index * legacy.clock.window_stride_blocks
    if announcement.height != expected_announcement:
        raise ValueError("work preparation has the wrong window announcement")
    schedule = _clock(legacy).derive(
        index,
        netuid=policy.netuid,
        announcement_block_hash=announcement.block_hash,
        announcement_timestamp_ms=announcement.timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(legacy),
    )
    selection_ms = QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS
    issue_close_ms = QUICKNET_GENESIS_MS + (schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    if (
        issuance.height <= schedule.closing_block
        or not selection_ms <= issuance.timestamp_ms < issue_close_ms
        or now_ms + minimum_issue_ms >= issue_close_ms
    ):
        raise ValueError("work preparation lacks a usable original issue window")
    round_ = plan.cutoff.publication.round
    if (
        not round_.submission_close_block
        < issuance.height
        < (issuance.height + schedule.response_deadline_blocks)
        <= round_.evaluation_close_block
    ):
        raise ValueError("transport window does not fit the frozen evaluation window")
    if not isinstance(videos, tuple) or len(videos) != len(plan.cases):
        raise ValueError("work preparation requires one video descriptor per case")
    videos = tuple(Video.model_validate_json(canonical_json_bytes(v)) for v in videos)
    if any(
        v.sha256 != c.video_sha256 or v.size_bytes > plan.runtime.maximum_video_bytes
        for c, v in zip(plan.cases, videos, strict=True)
    ):
        raise ValueError("work preparation video identity or byte limit differs")
    cases = tuple(EndpointAuthorizationCase(**c.model_dump()) for c in plan.cases)
    result = []
    for sub in sorted(plan.submissions, key=lambda s: digest(s.submission)):
        if sub.submission.track != "endpoint":
            continue
        if submission_sha256 is not None and digest(sub.submission) != submission_sha256:
            continue
        assignments = []
        for evaluator in plan.evaluators:
            ids = dict(
                policy_sha256=digest(policy),
                round_sha256=digest(round_),
                submission_sha256=digest(sub.submission),
                evaluator_hotkey=evaluator,
            )
            for case, video in zip(cases, videos, strict=True):
                assignments.append(
                    EndpointAssignment(
                        submission_sha256=ids["submission_sha256"],
                        case_sha256=digest(case),
                        evaluator_hotkey=evaluator,
                        request=TranslationRequest(
                            protocol=PROTOCOL_VERSION,
                            window_id=schedule.window_id,
                            batch_id=assignment_batch_id(**ids),
                            challenge_id=assignment_challenge_id(**ids, case_sha256=digest(case)),
                            issued_block=issuance.height,
                            issued_block_hash=issuance.block_hash,
                            deadline_block=issuance.height + schedule.response_deadline_blocks,
                            response_close_round=schedule.response_close_round,
                            reveal_round=schedule.reveal_round,
                            video=video,
                            task=Task(
                                source_language="ase", target_language="en", stratum=case.stratum
                            ),
                            scoring_policy_hash=scoring_policy_hash(legacy),
                        ),
                    )
                )
        result.append(
            validate_publication_body(
                EndpointAuthorizationPublication(
                    schema="umi-endpoint-authorization-publication/1",
                    policy_sha256=digest(policy),
                    legacy_policy_sha256=scoring_policy_hash(legacy),
                    round=round_,
                    submissions=(sub,),
                    cases=cases,
                    assignments=tuple(assignments),
                ),
                policy,
                legacy,
            )
        )
    if submission_sha256 is not None and len(result) != 1:
        raise ValueError("work preparation selected an unknown endpoint submission")
    return tuple(result)


def evaluation_order_proposals(*, plan, policy, publications=(), legacy=None):
    """Derive model orders and orders for endpoints whose authorization is signed."""
    plan = validate_work_plan(plan, policy)
    if not isinstance(publications, tuple) or len(publications) > 256:
        raise ValueError("work preparation requires bounded endpoint publications")
    by_submission = {}
    for publication in publications:
        publication = SignedEndpointAuthorization.model_validate_json(
            canonical_json_bytes(publication)
        )
        if legacy is None:
            raise ValueError("endpoint orders need their transport policy")
        publication = validate_publication(publication, policy, legacy)
        body = publication.publication
        if body.round != plan.cutoff.publication.round or len(body.submissions) != 1:
            raise ValueError("work preparation requires the exact round and one miner audience")
        key = digest(body.submissions[0].submission)
        if key in by_submission or body.submissions[0] not in plan.submissions:
            raise ValueError("work preparation has duplicate or unrelated endpoint authorization")
        by_submission[key] = publication
    result = []
    for sub in sorted(plan.submissions, key=lambda s: digest(s.submission)):
        publication = by_submission.get(digest(sub.submission))
        if sub.submission.track == "endpoint" and publication is None:
            continue
        result.append(
            validate_order_body(
                EvaluationOrder(
                    schema="umi-evaluation-order/1",
                    round=plan.cutoff.publication.round,
                    submission=sub,
                    incumbent=plan.incumbent,
                    runtime=plan.runtime,
                    cases=plan.cases,
                    evaluators=plan.evaluators,
                    publication=publication,
                ),
                policy,
                legacy,
            )
        )
    return tuple(result)
