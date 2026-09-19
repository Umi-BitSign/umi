"""Structural canonical-byte bounds for one evaluator's complete artifact set.

The calculation covers both scored and void outcomes, including peer copies.
It allocates no maximum-sized evidence objects and creates no signatures. These
are logical journal-body allowances; execution time and filesystem space need
separate admission checks.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import get_args

from .competition_authorization import MAX_AUTHORIZATION_BYTES, EndpointAuthorizationPublication
from .competition_endpoint_execution import MAX_PAIRED_BYTES
from .competition_evaluator import order_from_unsigned_inputs
from .competition_evaluator_capacity import ArtifactReservation, OrderReservation
from .competition_execution import ModelEvaluationJob, execution_key
from .competition_runner import OfflineCaseExecution
from .competition_void import MAX_VOID_BYTES, VoidReason
from .competition_work_plans import WorkPlan, validate_work_plan
from .config import Limits
from .open_competition import CaseOutput, CompetitionPolicy, SignedSubmission, digest, identity
from .policy import ScoringPolicy
from .private_files import MAX_PRIVATE_BYTES
from .protocol import canonical_json_bytes

_BLOCK_BYTES = 16  # len(str(2**53 - 1))
_DIGEST_BYTES = 66  # A quoted 64-character lowercase digest.
_HOTKEY_BYTES = 66  # The protocol's maximum ASCII account length, including quotes.
_TRANSCRIPT_LIMIT = 1024**2


@dataclass(frozen=True)
class OrderBudget:
    reservation: OrderReservation
    job: ModelEvaluationJob
    order_body_bytes: int
    maximum_certificate_bytes: int
    maximum_independent_bytes: int
    maximum_void_bytes: int


def _length(value: object) -> int:
    return len(canonical_json_bytes(value))


def json_size(value: object) -> int:
    """Exact canonical size for fixed, already-known fields."""
    return _length(value)


def array_bound(sizes: Iterable[int]) -> int:
    """Encoded JSON array size from already-encoded element sizes."""
    count = total = 0
    for size in sizes:
        if type(size) is not int or size < 0:
            raise ValueError("invalid encoded element size")
        count += 1
        total += size
    return 2 + total + max(0, count - 1)


def repeated_array_bound(size: int, count: int) -> int:
    if type(size) is not int or size < 0 or type(count) is not int or count < 0:
        raise ValueError("invalid repeated array dimensions")
    return 2 + count * size + max(0, count - 1)


def object_bound(fields: Mapping[str, int]) -> int:
    """Encoded JSON object size, including field names and punctuation."""
    if any(
        type(key) is not str or type(size) is not int or size < 0 for key, size in fields.items()
    ):
        raise ValueError("invalid encoded object fields")
    return (
        2 + sum(_length(key) + 1 + size for key, size in fields.items()) + max(0, len(fields) - 1)
    )


def _text_bound(maximum_utf8_bytes: int) -> int:
    # Every input byte can be an ASCII control character encoded as six bytes.
    return 2 + 6 * maximum_utf8_bytes


def signature_bound() -> int:
    return object_bound({"hotkey": _HOTKEY_BYTES, "scheme": 9, "signature": 132})


def _bounded(name: str, size: int, maximum: int = MAX_PRIVATE_BYTES) -> int:
    if size > maximum:
        raise ValueError(f"{name} structural capacity bound exceeds {maximum} bytes")
    return size


def _boundary_bound() -> int:
    return object_bound(
        {
            "source": _length("verifier_attested_finality"),
            "block": _BLOCK_BYTES,
            "block_hash": 68,
            "state_root": 68,
            "snapshot_sha256": _DIGEST_BYTES,
            "evidence_sha256": _DIGEST_BYTES,
        }
    )


def _case_output_bound(maximum_output_bytes: int) -> int:
    return max(
        object_bound(
            {
                "case_id": _DIGEST_BYTES,
                "status": _length(status),
                "hypothesis": _text_bound(maximum_output_bytes) if status == "ok" else 2,
                "elapsed_ms": _length(86_400_000),
            }
        )
        for status in get_args(CaseOutput.model_fields["status"].annotation)
    )


def _step_bound(maximum_output_bytes: int) -> int:
    execution = object_bound(
        {
            "schema": _length("umi-offline-case-execution/1"),
            "model_sha256": _DIGEST_BYTES,
            "runtime_sha256": _DIGEST_BYTES,
            "video_sha256": _DIGEST_BYTES,
            "output": _case_output_bound(maximum_output_bytes),
            "stdout_hex": 2 + 2 * (maximum_output_bytes + 1),
            "reason": max(
                _length(reason)
                for reason in get_args(OfflineCaseExecution.model_fields["reason"].annotation)
            ),
            "returncode": max(_length(value) for value in (-65536, 65536, None)),
        }
    )
    return object_bound(
        {
            "role": max(_length("candidate"), _length("incumbent")),
            "started": _boundary_bound(),
            "finished": _boundary_bound(),
            "execution": execution,
        }
    )


def _pulse_bound(number: int) -> int:
    return object_bound({"round": _length(number), "randomness": _DIGEST_BYTES, "signature": 98})


def _transcript_bound(assignment, limits: Limits) -> int:
    request_bytes = _length(assignment.request)
    if request_bytes > limits.maximum_request_body_bytes:
        raise ValueError("endpoint request exceeds its transport byte limit")
    response_hex = 2 + 2 * limits.maximum_response_body_bytes
    timestamp = 22  # Replay accepts at most 20 decimal characters, plus quotes.
    return _bounded(
        "endpoint transcript",
        object_bound(
            {
                "schema": _length("umi-endpoint-dispatch-transcript/1"),
                "assignment_key": _DIGEST_BYTES,
                "publication_sha256": _DIGEST_BYTES,
                "case_id": _DIGEST_BYTES,
                "origin_evidence_sha256": _DIGEST_BYTES,
                "origin_block": _BLOCK_BYTES,
                "request_hex": 2 + 2 * request_bytes,
                "auth_headers": 6 * limits.maximum_http_header_bytes + 49,
                "limits": _length(asdict(limits)),
                "started_at_unix_ns": timestamp,
                "finished_at_unix_ns": timestamp,
                "received_at_unix_ns": timestamp,
                "envelope_hex": response_hex,
                "response_signature": _text_bound(130),
                "received_body_prefix_hex": response_hex,
                "received_bytes_sha256": _DIGEST_BYTES,
                "failure_code": _text_bound(128),
                "no_weight": _length(True),
                "evidence_verified": _length(False),
                "chain_submission_authorized": _length(False),
            }
        ),
        _TRANSCRIPT_LIMIT,
    )


def _dispatch_bound(assignment, limits: Limits) -> int:
    return object_bound(
        {
            "assignment_key": _DIGEST_BYTES,
            "transcript_hex": 2 + 2 * _transcript_bound(assignment, limits),
            "reveal_pulse": _pulse_bound(assignment.request.reveal_round),
        }
    )


def _result_bound(outputs: int) -> int:
    return object_bound(
        {
            "schema": _length("umi-competition-result/1"),
            **dict.fromkeys(
                (
                    "round_sha256",
                    "submission_sha256",
                    "model_revision",
                    "incumbent_model_sha256",
                    "runtime_sha256",
                ),
                _DIGEST_BYTES,
            ),
            "finished_block": _BLOCK_BYTES,
            "candidate": outputs,
            "incumbent": outputs,
        }
    )


def _run_bound(outputs: int) -> int:
    return object_bound(
        {
            "schema": _length("umi-competition-evaluator-run/1"),
            "evaluator_hotkey": _HOTKEY_BYTES,
            **dict.fromkeys(
                (
                    "policy_sha256",
                    "round_sha256",
                    "submission_sha256",
                    "common_result_sha256",
                    "suite_sha256",
                    "model_revision",
                    "incumbent_model_sha256",
                    "runtime_sha256",
                    "execution_evidence_sha256",
                ),
                _DIGEST_BYTES,
            ),
            "started_block": _BLOCK_BYTES,
            "finished_block": _BLOCK_BYTES,
            "candidate": outputs,
            "incumbent": outputs,
        }
    )


def _observation_bound(schema: str, evaluator_hotkey: str) -> int:
    return object_bound(
        {
            "schema": _length(schema),
            "evaluator_hotkey": _length(evaluator_hotkey),
            **dict.fromkeys(
                (
                    "policy_sha256",
                    "round_sha256",
                    "order_sha256",
                    "submission_sha256",
                    "evidence_sha256",
                ),
                _DIGEST_BYTES,
            ),
            "observed": _boundary_bound(),
            "chain_submission_authorized": _length(False),
        }
    )


def evaluator_order_budget(
    *,
    plan: WorkPlan,
    submission: SignedSubmission,
    policy: CompetitionPolicy,
    evaluator_hotkey: str,
    endpoint_publication_body: EndpointAuthorizationPublication | None = None,
    legacy_policy: ScoringPolicy | None = None,
    retain_settlement_review: bool = False,
) -> OrderBudget:
    """Authenticate the frozen plan and derive its complete artifact allowance."""
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    plan = validate_work_plan(plan, policy)
    return order_budget_for_validated_plan(
        plan=plan,
        submission=submission,
        policy=policy,
        evaluator_hotkey=evaluator_hotkey,
        endpoint_publication_body=endpoint_publication_body,
        legacy_policy=legacy_policy,
        retain_settlement_review=retain_settlement_review,
    )


def order_budget_for_validated_plan(
    *,
    plan: WorkPlan,
    submission: SignedSubmission,
    policy: CompetitionPolicy,
    evaluator_hotkey: str,
    endpoint_publication_body: EndpointAuthorizationPublication | None = None,
    legacy_policy: ScoringPolicy | None = None,
    retain_settlement_review: bool = False,
) -> OrderBudget:
    """Internal cohort path after the caller authenticates the complete plan.

    The caller must have applied ``validate_work_plan(plan, policy)`` to these
    unchanged objects. Membership, nomination, job and unsigned publication
    bindings are still checked for this order. This avoids revalidating a full
    roster and cutoff signatures for each member of one authenticated cohort.

    The reservation's ``order_sha256`` is the unsigned ``order_binding``, not
    the future signed-order digest. Conflict artifacts have no finite inventory.
    """
    if type(retain_settlement_review) is not bool:
        raise ValueError("settlement review retention must be explicit")
    fields, job = order_from_unsigned_inputs(
        plan=plan,
        submission=submission,
        policy=policy,
        evaluator_hotkey=evaluator_hotkey,
        endpoint_publication=endpoint_publication_body,
        legacy_policy=legacy_policy,
    )
    evaluators = fields["evaluators"]
    cohort_size = len(evaluators)
    signer_groups = len({e.control_group for e in policy.evaluators})
    signature = signature_bound()
    publication = None
    publication_bytes = _length(None)
    if legacy_policy is not None:
        legacy_policy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
    # A combined worker retains its configured legacy policy in model-track
    # void evidence too, even though model execution uses no endpoint transport.
    transport_bytes = _length(legacy_policy)
    limits = None
    if fields["publication"] is not None:
        publication = EndpointAuthorizationPublication.model_validate_json(
            canonical_json_bytes(fields["publication"])
        )
        if legacy_policy is None:
            raise ValueError("endpoint budget requires its legacy policy")
        limits = Limits.from_policy(legacy_policy)
        publication_bytes = _bounded(
            "signed endpoint publication",
            object_bound(
                {
                    "publication": _length(publication),
                    "signatures": repeated_array_bound(signature, signer_groups),
                }
            ),
            MAX_AUTHORIZATION_BYTES,
        )
    order_fields = {key: _length(value) for key, value in fields.items() if key != "publication"}
    order_fields["publication"] = publication_bytes
    order_body_bytes = _bounded("evaluation order", object_bound(order_fields))
    signed_order = _bounded(
        "signed evaluation order",
        object_bound(
            {
                "order": order_body_bytes,
                "signatures": repeated_array_bound(signature, signer_groups),
            }
        ),
    )
    # Only the evaluator account spelling varies between exact peer jobs.
    job_bytes = _length(job) - _length(job.evaluator_hotkey) + _HOTKEY_BYTES
    cases = len(job.cases)
    step = _step_bound(policy.maximum_output_bytes)
    execution = object_bound(
        {
            "schema": _length(
                "umi-model-execution-evidence/1"
                if publication is None
                else "umi-endpoint-incumbent-evidence/1"
            ),
            "job": job_bytes,
            "steps": repeated_array_bound(step, cases * (2 if publication is None else 1)),
            "chain_submission_authorized": _length(False),
        }
    )
    announcements = {}
    pulses = {}
    submission_sha256 = digest(job.submission.submission)
    for evaluator in evaluators:
        key = identity(evaluator)
        evidence = execution
        if publication is not None:
            assert limits is not None
            assigned = tuple(
                a
                for a in publication.assignments
                if identity(a.evaluator_hotkey) == key and a.submission_sha256 == submission_sha256
            )
            if len(assigned) != cases:
                raise ValueError("endpoint budget requires every assigned case for each evaluator")
            evidence = _bounded(
                "paired endpoint evidence",
                object_bound(
                    {
                        "schema": _length("umi-endpoint-paired-evidence/1"),
                        "incumbent": execution,
                        "publication": publication_bytes,
                        "legacy_policy": transport_bytes,
                        "dispatches": array_bound(_dispatch_bound(a, limits) for a in assigned),
                        "chain_submission_authorized": _length(False),
                    }
                ),
                MAX_PAIRED_BYTES,
            )
            if key == identity(evaluator_hotkey):
                pulses = {
                    "pulse:" + str(a.request.reveal_round): _pulse_bound(a.request.reveal_round)
                    for a in assigned
                }
        announcement = _bounded(
            "execution announcement",
            object_bound(
                {
                    "schema": _length("umi-execution-announcement/1"),
                    "order_sha256": _DIGEST_BYTES,
                    "evaluator_hotkey": _HOTKEY_BYTES,
                    "evidence": evidence,
                }
            ),
        )
        announcements[key] = (
            announcement,
            _bounded(
                "signed execution announcement",
                object_bound({"announcement": announcement, "signature": signature}),
            ),
        )
    outputs = repeated_array_bound(_case_output_bound(policy.maximum_output_bytes), cases)
    result = _result_bound(outputs)
    run = _run_bound(outputs)
    signed_run = object_bound({"run": run, "signature": signature})
    vote = object_bound(
        {
            "schema": _length("umi-evaluation-vote/1"),
            "order_sha256": _DIGEST_BYTES,
            "result": result,
            "result_signature": signature,
            "run": signed_run,
        }
    )
    independent = _bounded(
        "independent evaluation evidence",
        object_bound(
            {
                "schema": _length("umi-competition-independent-evaluation/1"),
                "attested_result": object_bound(
                    {
                        "result": result,
                        "signatures": repeated_array_bound(signature, cohort_size),
                    }
                ),
                "evaluator_runs": repeated_array_bound(signed_run, cohort_size),
            }
        ),
    )
    void = _bounded(
        "evaluation void proposal",
        object_bound(
            {
                "schema": _length("umi-competition-evaluation-void/1"),
                **dict.fromkeys(
                    (
                        "policy_sha256",
                        "round_sha256",
                        "order_sha256",
                        "submission_sha256",
                        "suite_sha256",
                    ),
                    _DIGEST_BYTES,
                ),
                "reason": max(_length(reason) for reason in get_args(VoidReason)),
                "observations": array_bound(signed for _, signed in announcements.values()),
                "chain_submission_authorized": _length(False),
            }
        ),
        MAX_VOID_BYTES,
    )
    void_vote = object_bound({"void": void, "signature": signature})
    void_certificate = _bounded(
        "evaluation void certificate",
        object_bound({"void": void, "signatures": repeated_array_bound(signature, cohort_size)}),
        MAX_VOID_BYTES,
    )
    void_evidence = _bounded(
        "void evaluation evidence",
        object_bound(
            {
                "schema": _length("umi-competition-void-evidence/1"),
                "order": signed_order,
                "certificate": void_certificate,
                "legacy_policy": transport_bytes,
            }
        ),
    )
    observation = _observation_bound("umi-independent-evidence-observation/1", evaluator_hotkey)
    void_observation = _observation_bound("umi-void-evidence-observation/1", evaluator_hotkey)
    own, own_signed = announcements[identity(evaluator_hotkey)]
    artifacts = {
        **pulses,
        "announcement_intent": own,
        "announcement": own_signed,
        **{"peer_execution:" + key: signed for key, (_, signed) in announcements.items()},
        "result_intent": result,
        "run_intent": run,
        "vote": vote,
        **{"peer_vote:" + identity(e): vote for e in evaluators},
        "independent": independent,
        "independent_observation": observation,
        "void_intent": void,
        "void_vote": void_vote,
        **{"peer_void_vote:" + identity(e): void_vote for e in evaluators},
        "void": void_evidence,
        "void_observation": void_observation,
    }
    if retain_settlement_review:
        artifacts.update(review_retention=observation, void_review_retention=void_observation)
    # The review store can accumulate every authorized signer's certificate,
    # independently of the nominated execution cohort. SQL metadata is separate.
    certificate = object_bound(
        {"result": result, "signatures": repeated_array_bound(signature, len(policy.evaluators))}
    )
    return OrderBudget(
        reservation=OrderReservation(
            slot=execution_key(job),
            order_sha256=digest(fields),
            maximum_bytes=signed_order,
            artifacts=tuple(
                ArtifactReservation(kind, _bounded(kind, size))
                for kind, size in sorted(artifacts.items())
            ),
        ),
        job=job,
        order_body_bytes=order_body_bytes,
        maximum_certificate_bytes=_bounded("result certificate", certificate),
        maximum_independent_bytes=independent,
        maximum_void_bytes=void_evidence,
    )
