"""Restore successful local untimed model quality into prospective receipts.

The owned collection intent proves that this validator completed quality before
collecting its matching certificate. A remote certificate alone is insufficient.
Restore only unchanged native inputs and existing execution verification; no
quality calculation, proof replay, signature creation or journal rewrite occurs.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

from .competition_verification_reuse import (
    VerificationReceiptUnavailable,
    cached_verification_only,
    selected_verification_reuse,
)
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_SOURCE = ContextVar("retained_quality_migration", default=None)
_MAXIMUM_PARTICIPANTS = 512
_MAXIMUM_RECORD_BYTES = 512 * 1024


def _require(value, reason):
    if not value:
        raise VerificationReceiptUnavailable("retained quality migration: " + reason)


class _RetainedOutcomes:
    def __init__(self, journal, binding, reuse, require_completed):
        self.journal = journal
        self.binding = canonical_json_bytes(binding)
        self.reuse = reuse
        self.require_completed = require_completed
        self.indices = {}

    def _binding(self, db):
        _require(selected_verification_reuse() is self.reuse, "native owner changed")
        rows = db.execute(
            "SELECT LENGTH(body),substr(body,1,16385) FROM binding LIMIT 2"
        ).fetchall()
        _require(
            len(rows) == 1 and rows[0][0] <= 16384 and bytes(rows[0][1]) == self.binding,
            "local journal binding changed",
        )

    def _index(self, scope):
        if scope in self.indices:
            return self.indices[scope]
        # Inspect only the two bounded native completion kinds. A surviving
        # certificate with a missing intent is damage, never fresh scoring.
        # Remote certificates in the object archive are not local completions.
        with self.journal.read_transaction(coordinated=True) as db:
            self._binding(db)
            rows = []
            for kind, prefix in (
                ("closed_quality_collect_intent", "$"),
                ("closed_quality_certificate", "$.result"),
            ):
                batch = db.execute(
                    "SELECT id,json_extract(CAST(body AS TEXT),?),LENGTH(body) "
                    "FROM records WHERE kind=? "
                    "AND json_extract(CAST(body AS TEXT),?)=? "
                    "AND json_extract(CAST(body AS TEXT),?)=? "
                    "AND json_extract(CAST(body AS TEXT),?)=? "
                    "AND json_extract(CAST(body AS TEXT),?)=? ORDER BY id LIMIT ?",
                    (
                        prefix + ".submission_sha256",
                        kind,
                        prefix + ".policy_sha256",
                        scope[0],
                        prefix + ".round_sha256",
                        scope[1],
                        prefix + ".suite_sha256",
                        scope[2],
                        prefix + ".request_closure_sha256",
                        scope[3],
                        _MAXIMUM_PARTICIPANTS + 1,
                    ),
                ).fetchall()
                _require(
                    len(batch) <= _MAXIMUM_PARTICIPANTS, "completion inventory exceeds roster bound"
                )
                rows.extend(batch)
        index = {}
        for key, submission, size in rows:
            _require(
                type(submission) is str
                and len(submission) == 64
                and type(key) is str
                and len(key) == 64
                and 0 < size <= _MAXIMUM_RECORD_BYTES,
                "intent identity or size invalid",
            )
            _require(index.get(submission, key) == key, "conflicting successful local outcomes")
            index[submission] = key
        self.indices[scope] = index
        return index

    def _read(self, key):
        with self.journal.read_transaction(coordinated=True) as db:
            self._binding(db)
            rows = tuple(
                self.journal._copy_raw(db, kind, key, maximum_bytes=_MAXIMUM_RECORD_BYTES)
                for kind in ("closed_quality_collect_intent", "closed_quality_certificate")
            )
        _require(
            all(raw is not None for raw in rows), "successful local intent/certificate missing"
        )
        return tuple(
            self.journal._check_record_bytes(raw, kind)
            for raw, kind in zip(
                rows, ("closed_quality_collect_intent", "closed_quality_certificate"), strict=True
            )
        )

    def read(self, scope, submission):
        key = self._index(scope).get(submission)
        if key is None:
            return None
        from .competition_cohort_quality import ClosedParticipantQuality
        from .competition_cohort_quality_signing import CertifiedClosedQuality

        raw_intent, raw_certificate = original = self._read(key)
        result = ClosedParticipantQuality.model_validate_json(raw_intent)
        certificate = CertifiedClosedQuality.model_validate_json(raw_certificate)
        _require(
            digest(result) == key
            and canonical_json_bytes(result) == raw_intent
            and canonical_json_bytes(certificate) == raw_certificate
            and canonical_json_bytes(certificate.result) == raw_intent,
            "certificate differs from successful local intent",
        )
        return key, result, certificate, original

    def recheck(self, key, original):
        _require(self._read(key) == original, "local completion changed during migration")


@contextmanager
def retained_quality_migration(journal, binding, *, verification_reuse, require_completed=False):
    """Select the real local owner only; an exported certificate is not a source."""
    _require(type(require_completed) is bool, "explicit migration mode required")
    _require(selected_verification_reuse() is verification_reuse, "native owner is not selected")
    previous = _SOURCE.get()
    if previous is not None:
        _require(
            previous.journal is journal
            and previous.reuse is verification_reuse
            and previous.binding == canonical_json_bytes(binding)
            and previous.require_completed == require_completed,
            "nested owner changed",
        )
        yield
        return
    token = _SOURCE.set(_RetainedOutcomes(journal, binding, verification_reuse, require_completed))
    try:
        yield
    finally:
        _SOURCE.reset(token)


def retained_quality_owner_operation(function):
    """Run inside the settlement service's existing verification-owner scope."""

    @wraps(function)
    async def run(self, *args, **kwargs):
        if selected_verification_reuse() is None:
            # Unselected legacy/fake graph ports have no receipt to migrate.
            # The restoration callback itself remains unavailable to them.
            return await function(self, *args, **kwargs)
        with retained_quality_migration(
            self.journal,
            self._quality_migration_binding,
            verification_reuse=self.verification_reuse,
        ):
            return await function(self, *args, **kwargs)

    return run


def restore_closed_participant_quality(
    member,
    round_,
    suite,
    policy,
    authority,
    request_closure_sha256,
    track,
    opened_at,
    closed_at,
    cpu_efficiency_enabled,
    objects,
    *,
    pulses,
    history,
    expected_tip_sha256,
    current_block,
):
    """Native receipt callback: return None only when no applicable old work exists."""
    source = _SOURCE.get()
    if source is None:
        return None
    if track != "model" or cpu_efficiency_enabled:
        _require(not source.require_completed, "unsupported retained quality contract")
        return None
    from .competition_cohort_endpoint_archive import read_endpoint_object
    from .competition_cohort_execution_journal import CohortExecutionAssignment
    from .competition_cohort_orders import recoverable_order_job
    from .competition_cohort_quality import measured_observation, observations_sha256
    from .competition_cohort_recovery import ModelRewardCohortAuthority, verify_recovery_quorum
    from .competition_cohort_request_terminal import (
        SignedRequestTerminal,
        parse_request_execution_archive,
        replay_archived_execution,
    )

    scope = (digest(policy), digest(round_), digest(suite), request_closure_sha256)
    selected = source.read(scope, member.submission_sha256)
    if selected is None:
        _require(not source.require_completed, "successful local outcome unavailable")
        return None
    key, result, certificate, original = selected
    _require(
        isinstance(authority.authority, ModelRewardCohortAuthority)
        and result.schema_ == "umi-cohort-closed-quality/2"
        and result.quality_rule == "paired_baseline_metric/1"
        and result.track == "model"
        and result.cpu_efficiency is None
        and (
            result.policy_sha256,
            result.round_sha256,
            result.suite_sha256,
            result.request_closure_sha256,
        )
        == scope
        and result.submission_sha256 == member.submission_sha256
        and result.order_sha256 == member.order_sha256,
        "retained result differs from current immutable quality inputs",
    )
    wanted = tuple(
        (identity(ref.evaluator_hotkey), ref.terminal_sha256) for ref in member.evaluators
    )
    _require(
        tuple((identity(run.evaluator_hotkey), run.terminal_sha256) for run in result.runs)
        == wanted
        and tuple(identity(signature.hotkey) for signature in certificate.signatures)
        == tuple(who for who, _ in wanted)
        and identity(result.hotkey) not in {who for who, _ in wanted},
        "retained certificate changed assigned evaluators",
    )
    verify_recovery_quorum(result, certificate.signatures, policy)

    # The native decorator captures these header reads and the exact existing
    # execution receipt dependencies. A missing or changed receipt refuses
    # before either step verification or quality computation can run.
    with cached_verification_only():
        for ref, run in zip(member.evaluators, result.runs, strict=True):
            signed = SignedRequestTerminal.model_validate_json(
                read_endpoint_object(objects, ref.terminal_sha256)
            )
            terminal = signed.terminal
            assignment = CohortExecutionAssignment.model_validate_json(
                read_endpoint_object(objects, terminal.assignment_sha256)
            )
            order = assignment.certificate.order
            job = recoverable_order_job(order, ref.evaluator_hotkey)
            _require(
                terminal.endpoint_archive_sha256 is None
                and identity(signed.signature.hotkey) == identity(ref.evaluator_hotkey)
                and digest(assignment.certificate) == result.order_sha256
                and digest(order.submission.submission) == result.submission_sha256
                and identity(order.submission.submission.hotkey) == identity(result.hotkey)
                and order.submission.submission.track == "model"
                and order.round == round_
                and [(c.case_id, c.video_sha256, c.stratum) for c in suite.cases]
                == [(c.case_id, c.video_sha256, c.stratum) for c in job.cases],
                "retained terminal differs from its exact model assignment",
            )
            archive = parse_request_execution_archive(
                read_endpoint_object(objects, terminal.execution_archive_sha256)
            )
            _require(
                archive.assignment_sha256 == terminal.assignment_sha256,
                "execution archive changed its assignment",
            )
            outputs = replay_archived_execution(
                job, archive, objects, policy, started_after=opened_at, finished_by=closed_at
            )
            candidate = tuple(
                measured_observation(output, policy) for output in outputs["candidate"]
            )
            incumbent = tuple(
                measured_observation(output, policy) for output in outputs["incumbent"]
            )
            reason = (
                "infrastructure_failure"
                if any(o.status == "infrastructure_failure" for o in (*candidate, *incumbent))
                else "incumbent_failure"
                if any(o.resource_eligible is not True for o in incumbent)
                else None
            )
            _require(
                run.candidate_basis == "measured_model_execution"
                and run.cpu_efficiency is None
                and run.candidate_observations_sha256 == observations_sha256(candidate)
                and run.incumbent_observations_sha256 == observations_sha256(incumbent)
                and run.reason == reason,
                "retained outcome observations changed",
            )
    source.recheck(key, original)
    return result
