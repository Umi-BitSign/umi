"""Quorum-signed, reference-free successor assignments on the legacy transport.

The immutable publication authorizes only exact requests from authenticated
evaluators. Actual block/Quicknet admission still comes from the concrete
ProofBackedMinerWindowAuthority and its process-owned finalized-block source.
This module has no wallet loading, dynamic assignment feed or weight capability.

The configured serving origin must match the miner-signed submission. That is
deployment configuration, not a proof of the chain-announced Axon. Local first
observation is checked for a usable issue window but is not independently proven
publication timing. Those two production evidence gates remain separate.
This finite no-weight profile has no durable first-publication timestamp: on
reload, elapsed issue slots are excluded while future slots remain usable.
Elapsed slots and cached responses never become newly authorized assignments.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field

from .config import Limits
from .miner_admission import (
    MinerAdmissionError,
    MinerWindowAdmission,
    ProofBackedMinerWindowAuthority,
)
from .open_competition import (
    DEPENDENCE_POLICY_SCHEMA,
    CompetitionPolicy,
    EvaluationRound,
    EvaluationSuite,
    Hotkey,
    Signature,
    SignedSubmission,
    Stratum,
    digest,
    has_case_coverage,
    identity,
    validate_suite_profile,
    verify_signature,
)
from .policy import SINGLE_EVALUATOR_TRANSPORT_SCHEMA, ScoringPolicy, scoring_policy_hash
from .protocol import (
    Hex32,
    StrictProtocolModel,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
    request_digest,
)
from .validator_plans import VerifiedFinalizedAnnouncementPort
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div
from .competition_policy_lineage import submission_policy_admitted

MAX_AUTHORIZATION_BYTES = 16 * 1024**2


def validate_transport_cohort(policy: CompetitionPolicy, transport: ScoringPolicy) -> None:
    """Bind the explicit single-evaluator transport to the same competition signer."""
    if transport.schema_ != SINGLE_EVALUATOR_TRANSPORT_SCHEMA:
        return
    if (
        len(transport.validator_registry) != 1
        or len(policy.evaluators) != 1
        or policy.required_evaluator_groups != 1
        or identity(transport.validator_registry[0].validator_hotkey)
        != identity(policy.evaluators[0].hotkey)
    ):
        raise ValueError("single-evaluator transport and competition cohort must match")


class EndpointAuthorizationCase(StrictProtocolModel):
    case_id: Hex32
    video_sha256: Hex32
    stratum: Stratum


class EndpointAssignment(StrictProtocolModel):
    submission_sha256: Hex32
    case_sha256: Hex32
    evaluator_hotkey: Hotkey
    request: TranslationRequest


class EndpointAuthorizationPublication(StrictProtocolModel):
    schema_: Literal["umi-endpoint-authorization-publication/1"] = Field(alias="schema")
    profile: Literal["legacy-transport-successor-no-weight/1"] = (
        "legacy-transport-successor-no-weight/1"
    )
    no_weight: Literal[True] = True
    policy_sha256: Hex32
    legacy_policy_sha256: Hex32
    round: EvaluationRound
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=256)]
    cases: Annotated[tuple[EndpointAuthorizationCase, ...], Field(min_length=3, max_length=2048)]
    assignments: Annotated[tuple[EndpointAssignment, ...], Field(min_length=3, max_length=4096)]


class SignedEndpointAuthorization(StrictProtocolModel):
    publication: EndpointAuthorizationPublication
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def _assignment_ids(
    policy_sha256: str,
    round_sha256: str,
    submission_sha256: str,
    evaluator_hotkey: str,
) -> list[str]:
    for value in (policy_sha256, round_sha256, submission_sha256):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("assignment identity requires lowercase SHA-256 digests")
    return [policy_sha256, round_sha256, submission_sha256, identity(evaluator_hotkey)]


def assignment_batch_id(
    *, policy_sha256: str, round_sha256: str, submission_sha256: str, evaluator_hotkey: str
) -> str:
    value = _assignment_ids(policy_sha256, round_sha256, submission_sha256, evaluator_hotkey)
    return base64url_encode(
        hashlib.sha256(b"umi-endpoint-batch-v1\0" + canonical_json_bytes(value)).digest()[:16]
    )


def assignment_challenge_id(
    *,
    policy_sha256: str,
    round_sha256: str,
    submission_sha256: str,
    case_sha256: str,
    evaluator_hotkey: str,
) -> str:
    value = _assignment_ids(policy_sha256, round_sha256, submission_sha256, evaluator_hotkey)
    if (
        not isinstance(case_sha256, str)
        or len(case_sha256) != 64
        or any(c not in "0123456789abcdef" for c in case_sha256)
    ):
        raise ValueError("case identity requires a lowercase SHA-256 digest")
    return base64url_encode(
        hashlib.sha256(
            b"umi-endpoint-challenge-v1\0" + canonical_json_bytes([*value, case_sha256])
        ).digest()[:16]
    )


def _origin(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(ord(c) < 33 for c in value)
    ):
        raise ValueError("serving origin must be a credential-free HTTPS origin")
    _ = parsed.port


def _check_quotas(publication, legacy_policy, limits, *, miner_account=None) -> None:
    submissions = {digest(s.submission): s.submission for s in publication.submissions}
    per_validator, per_miner = Counter(), Counter()
    videos = defaultdict(set)
    for assignment in publication.assignments:
        sub = submissions[assignment.submission_sha256]
        miner = identity(sub.hotkey)
        if miner_account is not None and miner != miner_account:
            continue
        request = assignment.request
        window = (
            request.issued_block - legacy_policy.activation_block
        ) // legacy_policy.clock.window_stride_blocks
        key = (miner, window, identity(assignment.evaluator_hotkey))
        per_validator[key] += 1
        per_miner[(miner, window)] += 1
        videos[key].add(request.video.sha256)
        if (
            len(canonical_json_bytes(request)) > limits.maximum_request_body_bytes
            or request.video.size_bytes > limits.maximum_clip_size_bytes
        ):
            raise ValueError("authorized request exceeds transport resource limits")
    if (
        any(n > limits.maximum_assignments_per_validator_window for n in per_validator.values())
        or any(n > limits.maximum_total_assignments_per_window for n in per_miner.values())
        or any(len(v) > limits.maximum_unique_videos_per_validator_window for v in videos.values())
    ):
        raise ValueError("authorization exceeds per-window assignment/video quotas")


def validate_publication(
    publication: SignedEndpointAuthorization,
    policy: CompetitionPolicy,
    legacy_policy: ScoringPolicy,
) -> SignedEndpointAuthorization:
    """Authenticate the complete static mapping; no finality is inferred here."""
    raw = canonical_json_bytes(publication)
    if len(raw) > MAX_AUTHORIZATION_BYTES:
        raise ValueError("endpoint authorization exceeds its byte bound")
    publication = SignedEndpointAuthorization.model_validate_json(raw)
    body = validate_publication_body(publication.publication, policy, legacy_policy)
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen_keys, seen_groups = set(), set()
    miner_keys = {identity(s.submission.hotkey) for s in body.submissions}
    for signature in publication.signatures:
        key = identity(signature.hotkey)
        if key not in groups or key in seen_keys or groups[key] in seen_groups or key in miner_keys:
            raise ValueError("unauthorized, duplicate or self-authorizing publication signer")
        verify_signature(body, signature)
        seen_keys.add(key)
        seen_groups.add(groups[key])
    if len(seen_groups) < policy.required_evaluator_groups:
        raise ValueError("publication lacks independent evaluator quorum")
    return publication


def scheduled_assignment_key(body, assignment) -> str:
    """Local assignment identity, unchanged by re-signing or attempted retiming."""
    return hashlib.sha256(
        b"umi-scheduled-endpoint-assignment-v1\0"
        + canonical_json_bytes(
            [
                body.policy_sha256,
                digest(body.round),
                assignment.submission_sha256,
                identity(assignment.evaluator_hotkey),
                assignment.case_sha256,
            ]
        )
    ).hexdigest()


def validate_publication_body(
    body: EndpointAuthorizationPublication, policy: CompetitionPolicy, legacy_policy: ScoringPolicy
) -> EndpointAuthorizationPublication:
    """Check an unsigned proposal. This never grants transmission authority."""
    raw = canonical_json_bytes(body)
    if len(raw) > MAX_AUTHORIZATION_BYTES:
        raise ValueError("endpoint authorization exceeds its byte bound")
    body = EndpointAuthorizationPublication.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    legacy_policy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
    validate_transport_cohort(policy, legacy_policy)
    policy_sha = digest(policy)
    round_, legacy_sha = body.round, scoring_policy_hash(legacy_policy)
    if (
        body.policy_sha256 != policy_sha
        or round_.policy_sha256 != policy_sha
        or body.legacy_policy_sha256 != legacy_sha
        or legacy_sha == policy_sha
        or round_.runtime_sha256 != policy.evaluation_runtime_sha256
    ):
        raise ValueError("authorization policy, transport or runtime binding mismatch")
    if not (
        policy.valid_from_block
        <= round_.submission_close_block
        < round_.evaluation_close_block
        < round_.reveal_block
        <= round_.valid_through_block
        <= policy.valid_through_block
    ):
        raise ValueError("authorization round is outside the competition policy")
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    miner_keys = {identity(s.submission.hotkey) for s in body.submissions}
    submissions = {digest(s.submission): s.submission for s in body.submissions}
    if len(submissions) != len(body.submissions) or len(miner_keys) != len(body.submissions):
        raise ValueError("publication has duplicate submissions or miner identities")
    if len(submissions) > policy.maximum_uids:
        raise ValueError("publication exceeds the policy miner bound")
    for sub_sha, sub in submissions.items():
        if (
            sub.track != "endpoint"
            or not submission_policy_admitted(policy, sub.policy_sha256)
            or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
            or sub_sha not in round_.roster
            or not policy.valid_from_block <= sub.valid_from_block <= round_.submission_close_block
            or not round_.evaluation_close_block
            <= sub.valid_through_block
            <= policy.valid_through_block
            or sub.valid_through_block - sub.valid_from_block
            > policy.maximum_submission_lifetime_blocks
        ):
            raise ValueError("publication contains an ineligible endpoint submission")
        _origin(sub.endpoint_url)
    cases = {digest(c): c for c in body.cases}
    video_counts = Counter(c.video_sha256 for c in body.cases)
    if (
        len({c.case_id for c in body.cases}) != len(body.cases)
        or (policy.schema_ != DEPENDENCE_POLICY_SCHEMA and len(video_counts) != len(body.cases))
        or any(count > 2 for count in video_counts.values())
        or not has_case_coverage(body.cases, policy)
    ):
        raise ValueError("authorization has invalid cases, videos or coverage")
    legacy_keys = {identity(v.validator_hotkey) for v in legacy_policy.validator_registry}
    assignments, covered, assigned_groups = set(), defaultdict(set), defaultdict(set)
    wire_ids = set()
    for assignment in body.assignments:
        sub = submissions.get(assignment.submission_sha256)
        case = cases.get(assignment.case_sha256)
        evaluator = identity(assignment.evaluator_hotkey)
        request = assignment.request
        if (
            sub is None
            or case is None
            or evaluator not in groups
            or evaluator not in legacy_keys
            or evaluator == identity(sub.hotkey)
            or request.scoring_policy_hash != legacy_sha
            or request.video.sha256 != case.video_sha256
            or request.task.stratum != case.stratum
        ):
            raise ValueError("assignment case, submission, evaluator or transport mismatch")
        ids = {
            "policy_sha256": policy_sha,
            "round_sha256": digest(round_),
            "submission_sha256": assignment.submission_sha256,
            "evaluator_hotkey": assignment.evaluator_hotkey,
        }
        if request.batch_id != assignment_batch_id(
            **ids
        ) or request.challenge_id != assignment_challenge_id(
            **ids, case_sha256=assignment.case_sha256
        ):
            raise ValueError("wire IDs do not bind the exact successor assignment")
        if not (
            round_.submission_close_block
            < request.issued_block
            < request.deadline_block
            <= round_.evaluation_close_block
            and request.issued_block >= legacy_policy.activation_block
        ):
            raise ValueError("assignment block interval is outside the evaluation round")
        video_url = urlsplit(request.video.url)
        if (
            video_url.scheme != "https"
            or not video_url.hostname
            or video_url.username is not None
            or video_url.password is not None
            or video_url.fragment
            or len(request.video.url) > 4096
            or any(ord(c) < 33 for c in request.video.url)
        ):
            raise ValueError("assignment video must use a bounded credential-free HTTPS URL")
        key = (assignment.submission_sha256, evaluator, assignment.case_sha256)
        wire_key = (identity(sub.hotkey), evaluator, request_digest(request))
        if key in assignments or wire_key in wire_ids:
            raise ValueError("duplicate endpoint assignment or wire request")
        assignments.add(key)
        wire_ids.add(wire_key)
        covered[(assignment.submission_sha256, evaluator)].add(assignment.case_sha256)
        assigned_groups[assignment.submission_sha256].add(groups[evaluator])
    if any(value != set(cases) for value in covered.values()) or any(
        len(assigned_groups[sub_sha]) < policy.required_evaluator_groups for sub_sha in submissions
    ):
        raise ValueError("each endpoint needs complete case coverage by independent evaluators")
    _check_quotas(body, legacy_policy, Limits.from_policy(legacy_policy))
    return body


def validate_publication_suite(
    publication, suite: EvaluationSuite, policy: CompetitionPolicy
) -> None:
    """Check the signed reference-free case list against the suite after reveal."""
    publication = SignedEndpointAuthorization.model_validate_json(canonical_json_bytes(publication))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    validate_suite_profile(suite, policy)
    body = publication.publication
    if (
        body.policy_sha256 != digest(policy)
        or suite.policy_sha256 != digest(policy)
        or digest(suite) != body.round.suite_sha256
        or body.cases
        != tuple(
            EndpointAuthorizationCase(
                case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum
            )
            for c in suite.cases
        )
    ):
        raise ValueError("publication cases differ from the committed revealed suite")


class EndpointAuthorizationAuthority:
    """One immutable signed publication; authenticated caller identity is required.

    The miner must pass its verified btauth caller, not a claimed header. Durable
    nonce/retry/resource ledgers still run after this admission. No publication
    can bypass the concrete legacy schedule authority or create a weight path.
    """

    def __init__(
        self,
        policy: CompetitionPolicy,
        legacy_policy: ScoringPolicy,
        publication: SignedEndpointAuthorization,
        finalized_blocks: VerifiedFinalizedAnnouncementPort,
        miner_hotkey: str,
        model_revision: str,
        serving_origin: str,
    ):
        self._policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self._legacy_policy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
        self._publication = validate_publication(publication, self._policy, self._legacy_policy)
        body = self._publication.publication
        matches = [
            s.submission
            for s in body.submissions
            if identity(s.submission.hotkey) == identity(miner_hotkey)
        ]
        if len(matches) != 1 or matches[0].model_revision != model_revision:
            raise ValueError("local miner identity/revision does not match the publication")
        _origin(serving_origin)
        if matches[0].endpoint_url != serving_origin:
            raise ValueError("local serving origin differs from the miner-signed submission")
        self._miner_hotkey, self._model_revision, self._serving_origin = (
            miner_hotkey,
            model_revision,
            serving_origin,
        )
        self._legacy = ProofBackedMinerWindowAuthority(
            policy=self._legacy_policy, finalized_blocks=finalized_blocks
        )
        sub_sha = digest(matches[0])
        local_assignments = {
            (identity(a.evaluator_hotkey), request_digest(a.request)): a
            for a in body.assignments
            if a.submission_sha256 == sub_sha
        }
        self._assignments = {}
        self._first_observed_ms = time.time_ns() // 1_000_000
        for key, assignment in local_assignments.items():
            issue_close_round = assignment.request.response_close_round - ceil_div(
                legacy_policy.clock.response_window_seconds, QUICKNET_PERIOD_MS // 1000
            )
            issue_close_ms = QUICKNET_GENESIS_MS + (issue_close_round - 1) * QUICKNET_PERIOD_MS
            if issue_close_round > 0 and self._first_observed_ms < issue_close_ms:
                self._assignments[key] = assignment
        if not self._assignments:
            raise ValueError("publication was first observed after all usable local issue windows")
        self._elapsed_assignments = len(local_assignments) - len(self._assignments)

    @property
    def policy_sha256(self) -> str:
        return digest(self._policy)

    @property
    def transport_policy_sha256(self) -> str:
        return scoring_policy_hash(self._legacy_policy)

    @property
    def publication_sha256(self) -> str:
        return digest(self._publication.publication)

    @property
    def miner_hotkey(self) -> str:
        return self._miner_hotkey

    @property
    def model_revision(self) -> str:
        return self._model_revision

    @property
    def serving_origin(self) -> str:
        return self._serving_origin

    @property
    def allowed_validator_hotkeys(self) -> frozenset[str]:
        return frozenset(a.evaluator_hotkey for a in self._assignments.values())

    def status(self) -> dict:
        return {
            "profile": "legacy-transport-successor-no-weight/1",
            "no_weight": True,
            "chain_submission_authorized": False,
            "chain_announced_origin_verified": False,
            "publication_timing_proven": False,
            "publication_first_observed_unix_ms": self._first_observed_ms,
            "policy_sha256": self.policy_sha256,
            "transport_policy_sha256": self.transport_policy_sha256,
            "publication_sha256": self.publication_sha256,
            "serving_origin": self.serving_origin,
            "authorized_assignments": len(self._assignments),
            "elapsed_assignments_excluded": self._elapsed_assignments,
        }

    def validate_runtime(
        self,
        *,
        miner_hotkey: str,
        model_revision: str,
        transport_policy_sha256: str,
        allowed_validator_hotkeys: frozenset[str],
        limits: Limits,
    ) -> None:
        validate_runtime_binding(
            policy=self._policy,
            legacy_policy=self._legacy_policy,
            expected_miner=self.miner_hotkey,
            expected_revision=self.model_revision,
            required_validators=self.allowed_validator_hotkeys,
            miner_hotkey=miner_hotkey,
            model_revision=model_revision,
            transport_policy_sha256=transport_policy_sha256,
            allowed_validator_hotkeys=allowed_validator_hotkeys,
            limits=limits,
        )
        _check_quotas(
            self._publication.publication,
            self._legacy_policy,
            limits,
            miner_account=identity(self.miner_hotkey),
        )

    def contains(self, request: TranslationRequest, *, validator_hotkey: str) -> bool:
        return (identity(validator_hotkey), request_digest(request)) in self._assignments

    async def authorize(
        self, request: TranslationRequest, *, validator_hotkey: str
    ) -> MinerWindowAdmission:
        try:
            request = TranslationRequest.model_validate_json(canonical_json_bytes(request))
            evaluator = identity(validator_hotkey)
        except (ValueError, TypeError) as error:
            raise MinerAdmissionError("endpoint_authorization_request_invalid") from error
        assignment = self._assignments.get((evaluator, request_digest(request)))
        if assignment is None or canonical_json_bytes(assignment.request) != canonical_json_bytes(
            request
        ):
            raise MinerAdmissionError("endpoint_assignment_not_authorized")
        # This performs actual owned-finality checks. The publication's hashes
        # and local timing observation are never substituted for chain evidence.
        return await self._legacy.authorize(request)


def validate_runtime_binding(
    *,
    policy,
    legacy_policy,
    expected_miner,
    expected_revision,
    required_validators,
    miner_hotkey,
    model_revision,
    transport_policy_sha256,
    allowed_validator_hotkeys,
    limits,
):
    """Shared binding checks for static and feed-backed no-weight miners."""
    if (
        identity(miner_hotkey) != identity(expected_miner)
        or model_revision != expected_revision
        or transport_policy_sha256 != scoring_policy_hash(legacy_policy)
    ):
        raise ValueError(
            "runtime identity, revision or transport policy differs from authorization"
        )
    if not isinstance(allowed_validator_hotkeys, frozenset) or not isinstance(limits, Limits):
        raise TypeError("runtime must provide an immutable validator allowlist and explicit Limits")
    limits = Limits(**asdict(limits))
    actual = {identity(k) for k in allowed_validator_hotkeys}
    permitted = {identity(v.validator_hotkey) for v in legacy_policy.validator_registry}
    required = {identity(k) for k in required_validators}
    if not required <= actual <= permitted:
        raise ValueError("runtime validator allowlist omits assignments or adds unknown validators")
    if (
        limits.inference_timeout_seconds * 1000 > policy.maximum_inference_ms
        or limits.maximum_hypothesis_utf8_bytes > policy.maximum_output_bytes
    ):
        raise ValueError("runtime inference/output limits exceed the competition policy")
    legacy_limits = Limits.from_policy(legacy_policy)
    for name in (
        "maximum_request_body_bytes",
        "maximum_response_body_bytes",
        "maximum_response_plaintext_bytes",
        "maximum_http_header_bytes",
        "maximum_clip_size_bytes",
        "maximum_hypothesis_utf8_bytes",
        "maximum_hypothesis_tokens",
        "maximum_hypothesis_graphemes",
        "maximum_request_transmissions_per_assignment",
        "maximum_response_bodies_per_assignment",
        "maximum_video_fetch_attempts_per_actor",
        "maximum_assignment_wire_bytes",
        "maximum_assignments_per_validator_window",
        "maximum_total_assignments_per_window",
        "maximum_unique_videos_per_validator_window",
        "maximum_retained_video_bytes_per_validator_window",
        "maximum_unique_videos_per_window",
        "maximum_retained_video_bytes",
        "maximum_active_windows",
        "maximum_nonce_rows_per_validator",
        "maximum_nonce_rows_total",
        "maximum_nonce_database_bytes",
        "btauth_max_age_seconds",
        "btauth_allowed_skew_seconds",
    ):
        if getattr(limits, name) > getattr(legacy_limits, name):
            raise ValueError("runtime limits exceed legacy transport quotas")
