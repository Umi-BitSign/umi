"""Real signatures, retained Quicknet verification and offline response decryption."""

import hashlib
from fractions import Fraction
from types import SimpleNamespace

import bittensor as bt
import pytest

from umi.competition_cohort_endpoint_archive import (
    EndpointReplayArchive,
    endpoint_archive_cases,
)
from umi.competition_cohort_endpoint_decision import (
    CohortEndpointCaseReview,
    certify_case_decision,
    validate_case_review,
)
from umi.competition_cohort_endpoint_quality import replay_endpoint_archive_quality
from umi.competition_cohort_endpoint_retirement import CohortRetiredEndpointCase
from umi.competition_cohort_endpoint_selection import (
    CohortEndpointRecoverySelection,
    CohortRecoveredEndpointCase,
    selection_grant,
)
from umi.competition_cohort_endpoint_terminal import EndpointTerminalCase, EndpointTerminalSelection
from umi.competition_cohort_execution_journal import CohortExecutionAssignment
from umi.competition_cohort_order_queue import SignedOrderDeliveryReceipt, delivery_receipt
from umi.competition_cohort_order_signer import CohortOrderParticipant, order_slot
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.config import Limits
from umi.drand import DrandVerificationError
from umi.endpoint_response_recovery import RecoveredEndpointResponse
from umi.endpoint_retirement import EndpointRetirementReceipt, SignedEndpointRetirementReceipt
from umi.miner import _signed_envelope
from umi.open_competition import CaseOutput, digest, sign_object
from umi.protocol import canonical_json_bytes, request_digest

from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_disposition import order
from .test_competition_cohort_endpoint import base_policy as base_policy
from .test_competition_cohort_endpoint import endpoint as endpoint
from .test_competition_cohort_endpoint import legacy_scenario as legacy_scenario
from .test_competition_cohort_endpoint import policy as policy
from .test_competition_cohort_endpoint import receipt_scenario as receipt_scenario
from .test_competition_cohort_endpoint import recovery as recovery
from .test_competition_cohort_endpoint import runtime as runtime
from .test_competition_cohort_recovery import signatures
from .test_component_run import response_plaintext
from .test_drand import ROUND, pulse_record
from .test_open_competition import wallet


def archive(
    s,
    *,
    delay_hours=10,
    failure=None,
    observed_block=1511,
    evaluator_name="Charlie",
    miner_name="Alice",
    assignment=None,
):
    a = next(
        x
        for x in s["endpoints"]
        if x.incumbent.job.evaluator_hotkey == wallet(evaluator_name).hotkey.ss58_address
    )
    if assignment is None:
        certificate = order(s)
        receipt = delivery_receipt(certificate, a.incumbent.job.evaluator_hotkey)
        assignment = CohortExecutionAssignment(
            certificate=certificate,
            participant=CohortOrderParticipant(
                **{k: s[k] for k in ("consent", "admission", "admission_snapshot")}
            ),
            delivery=SignedOrderDeliveryReceipt(
                receipt=receipt, signature=sign_object(receipt, wallet(evaluator_name))
            ),
        )
    selected = CohortEndpointRecoverySelection(
        schema="umi-cohort-endpoint-recovery-selection/1",
        assignment_slot=order_slot(assignment.certificate.order),
        order=a.order,
        transport_policy=a.transport_policy,
    )
    grant = selection_grant(selected, assignment)
    objects, cases = {}, []

    def put(value):
        objects[digest(value)] = canonical_json_bytes(value)
        return digest(value)

    for i, (request, transcript) in enumerate(
        zip(a.order.order.requests, a.transcripts, strict=True)
    ):
        raw, signature = bytes.fromhex(transcript.envelope_hex), transcript.response_signature
        if i == 0 and failure is not None:
            plain = response_plaintext(
                request,
                validator_hotkey=a.incumbent.job.evaluator_hotkey,
                miner_hotkey=wallet(miner_name).hotkey.ss58_address,
            ).model_copy(
                update={
                    "model_revision": a.incumbent.job.submission.submission.model_revision,
                    "hypothesis": "hello",
                    **failure,
                }
            )
            miner = SimpleNamespace(
                wallet=wallet(miner_name),
                hotkey_ss58=wallet(miner_name).hotkey.ss58_address,
                signature_scheme="sr25519",
                limits=Limits.from_policy(a.transport_policy),
            )
            raw, signature = _signed_envelope(miner, request, plain)
        recovered = CohortRecoveredEndpointCase(
            schema="umi-cohort-recovered-endpoint-case/1",
            selection_sha256=digest(selected),
            case_id=transcript.case_id,
            origin_evidence_sha256="12" * 32,
            response=RecoveredEndpointResponse(
                schema="umi-recovered-endpoint-response/1",
                envelope_hex=raw.hex(),
                signature=signature,
                retrieval_started_at_unix_ns=str(
                    int(transcript.started_at_unix_ns) + delay_hours * 3600 * 10**9
                ),
                retrieved_at_unix_ns=str(
                    int(transcript.finished_at_unix_ns) + delay_hours * 3600 * 10**9
                ),
            ),
        )
        retirement = EndpointRetirementReceipt(
            schema="umi-endpoint-retirement/1",
            grant_sha256=digest(grant),
            request_digest=request_digest(request),
            miner_hotkey=wallet(miner_name).hotkey.ss58_address,
            evaluator_hotkey=a.incumbent.job.evaluator_hotkey,
            result="response_retained",
            response_sha256=hashlib.sha256(raw).hexdigest(),
        )
        review = CohortEndpointCaseReview(
            schema="umi-cohort-endpoint-case-review/1",
            assignment=assignment,
            selection=selected,
            retirement=CohortRetiredEndpointCase(
                schema="umi-cohort-retired-endpoint-case/1",
                selection_sha256=digest(selected),
                case_id=transcript.case_id,
                origin_evidence_sha256="12" * 32,
                observed_block=observed_block,
                observed_round=ROUND,
                retirement=SignedEndpointRetirementReceipt(
                    receipt=retirement,
                    signature=sign_object(retirement, wallet(miner_name)),
                ),
            ),
            recovered=recovered,
        )
        _, body = validate_case_review(review, s["policy"])
        decision = certify_case_decision(review, signatures(body), s["policy"])
        cases.append(
            EndpointTerminalCase(
                case_id=transcript.case_id,
                selection_slot=selected.assignment_slot,
                selection_sha256=digest(selected),
                review_sha256=put(review),
                decision_sha256=put(decision),
            )
        )
    terminal = EndpointTerminalSelection(
        schema="umi-cohort-endpoint-terminal-selection/1",
        assignment_sha256=put(assignment),
        job_sha256=digest(a.incumbent.job),
        cases=tuple(cases),
    )
    root = EndpointReplayArchive(
        schema="umi-cohort-endpoint-replay-archive/1",
        assignment_sha256=digest(assignment),
        terminal_sha256=put(terminal),
    )
    return root, objects, terminal


def replay(s, root, objects, **updates):
    context = dict(
        suite=s["suite"],
        policy=s["policy"],
        history=s["history"],
        pulses=lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(s["history"]),
        current_block=5000,
    )
    context.update(updates)
    return replay_endpoint_archive_quality(root, objects.__getitem__, **context)


@pytest.mark.parametrize("delay_hours", [0, 10, 48, 24 * 365])
def test_recovery_delay_does_not_change_content_quality(endpoint, monkeypatch, delay_hours):
    root, objects, _ = archive(endpoint, delay_hours=delay_hours)
    before = dict(objects)

    def no_network(*args, **kwargs):
        raise AssertionError("retained replay must stay offline")

    monkeypatch.setattr(bt.timelock, "decrypt", no_network)
    monkeypatch.setattr("httpx.Client.send", no_network)
    monkeypatch.setattr("httpx.AsyncClient.send", no_network)
    result = replay(endpoint, root, objects, current_block=10**6)
    assert all(Fraction(int(c.numerator), int(c.denominator)) == 1 for c in result.cases)
    assert all(c.elapsed_ms is None and not c.original_receipt_timing_proven for c in result.cases)
    assert result.timing_class == "original_timing_unverified"
    assert not result.chain_submission_authorized and not result.service_credit_authorized
    assert objects == before
    with pytest.raises(ValueError):
        CaseOutput.model_validate_json(canonical_json_bytes(result.cases[0]))


@pytest.mark.parametrize(
    "failure,reason",
    [
        (
            {
                "status": "error",
                "hypothesis": None,
                "model_revision": None,
                "error_code": "inference_failed",
            },
            "signed_miner_error",
        ),
        ({"model_revision": "ee" * 32}, "model_revision_mismatch"),
    ],
)
def test_signed_failures_survive_long_recovery(endpoint, failure, reason):
    root, objects, _ = archive(endpoint, delay_hours=48, failure=failure)
    result = replay(endpoint, root, objects)
    assert result.cases[0].reason_code == reason and result.cases[0].numerator == "0"
    assert all(c.numerator == c.denominator for c in result.cases[1:])


@pytest.mark.parametrize("object_kind", ["assignment", "terminal", "review", "decision"])
def test_missing_or_corrupted_object_is_pending_not_a_zero(endpoint, object_kind):
    root, objects, terminal = archive(endpoint)
    key = {
        "assignment": root.assignment_sha256,
        "terminal": root.terminal_sha256,
        "review": terminal.cases[-1].review_sha256,
        "decision": terminal.cases[-1].decision_sha256,
    }[object_kind]
    original = objects.pop(key)
    with pytest.raises(KeyError):
        replay(endpoint, root, objects)
    objects[key] = original + b" "
    with pytest.raises(ValueError, match="bounded identity"):
        replay(endpoint, root, objects)


def test_partial_or_reordered_manifest_cannot_score(endpoint):
    root, objects, terminal = archive(endpoint)
    for cases in (terminal.cases[:-1], terminal.cases[::-1], terminal.cases + terminal.cases[:1]):
        changed = terminal.model_copy(update={"cases": cases})
        objects[digest(changed)] = canonical_json_bytes(changed)
        with pytest.raises(ValueError, match="exact complete assignment"):
            replay(endpoint, root.model_copy(update={"terminal_sha256": digest(changed)}), objects)


def test_missing_or_invalid_reveal_cannot_score(endpoint):
    root, objects, _ = archive(endpoint)

    def missing(_):
        raise FileNotFoundError("pulse unavailable")

    with pytest.raises(FileNotFoundError):
        replay(endpoint, root, objects, pulses=missing)
    with pytest.raises(DrandVerificationError):
        replay(
            endpoint,
            root,
            objects,
            pulses=lambda _: RetainedRevealPulse(**{**pulse_record(), "signature": "00" * 48}),
        )
    with pytest.raises(ValueError):
        replay(endpoint, root, objects, current_block=1500)


def test_revoked_authority_cannot_score(endpoint):
    root, objects, _ = archive(endpoint)
    history = transition(endpoint["history"], endpoint["policy"], "revoke", 5000)
    with pytest.raises(ValueError):
        replay(endpoint, root, objects, history=history, expected_tip_sha256=tip(history))


def test_archive_replay_rechecks_quorum(endpoint):
    root, objects, terminal = archive(endpoint)
    import json

    ref = terminal.cases[0]
    cert = json.loads(objects[ref.decision_sha256])
    cert["signatures"] = cert["signatures"][:1]
    objects[digest(cert)] = canonical_json_bytes(cert)
    changed = terminal.model_copy(
        update={
            "cases": (ref.model_copy(update={"decision_sha256": digest(cert)}), *terminal.cases[1:])
        }
    )
    objects[digest(changed)] = canonical_json_bytes(changed)
    with pytest.raises(ValueError):
        tuple(
            endpoint_archive_cases(
                root.model_copy(update={"terminal_sha256": digest(changed)}),
                objects.__getitem__,
                endpoint["policy"],
            )
        )


@pytest.mark.parametrize("block", [0, 10**6])
def test_signed_observation_outside_request_phases_cannot_score(endpoint, block):
    root, objects, _ = archive(endpoint, observed_block=block)
    with pytest.raises(ValueError, match="outside certified request phases"):
        replay(endpoint, root, objects)


def test_missing_decryption_implementation_is_not_a_miner_zero(endpoint, monkeypatch):
    root, objects, _ = archive(endpoint)
    monkeypatch.setattr("bittensor_core.decrypt_with_signature", None)
    with pytest.raises(RuntimeError, match="primitive is unavailable"):
        replay(endpoint, root, objects)


@pytest.mark.parametrize("error", [TimeoutError, MemoryError, OSError])
def test_decryption_resource_failure_remains_pending(endpoint, monkeypatch, error):
    root, objects, _ = archive(endpoint)

    def unavailable(*args):
        raise error("local resource unavailable")

    with monkeypatch.context() as m:
        m.setattr("bittensor_core.decrypt_with_signature", unavailable)
        with pytest.raises(error):
            replay(endpoint, root, objects)
    assert all(c.numerator == c.denominator for c in replay(endpoint, root, objects).cases)
