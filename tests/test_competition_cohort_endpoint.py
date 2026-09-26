"""Native signatures and offline timelock replay after recoverable phase delays."""

import hashlib
from fractions import Fraction
from types import SimpleNamespace

import bittensor as bt
import pytest

from umi.competition_cohort_endpoint import (
    RecoverableEndpointOrder,
    RecoverableEndpointPairedEvidence,
    RecoverableEndpointTranscript,
    SignedRecoverableEndpointOrder,
    endpoint_attempt_wire_ids,
    endpoint_obligation_sha256,
    recoverable_endpoint_observations,
)
from umi.competition_cohort_outcomes import (
    RecoverableExecutedEvaluation,
    recoverable_run_record_from_evidence,
    replay_recoverable_executed_evaluation,
)
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.competition_evidence import IndependentEvaluationEvidence
from umi.config import Limits
from umi.drand import DrandVerificationError
from umi.miner import _signed_envelope
from umi.open_competition import digest, identity
from umi.policy import ScoringPolicy, ValidatorRegistryEntry, scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator import prepare_request_attempt

from .factories import challenge_request
from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_execution import (
    base_policy as base_policy,
)
from .test_competition_cohort_execution import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_execution import (
    policy as policy,
)
from .test_competition_cohort_execution import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_execution import (
    recovery as recovery,
)
from .test_competition_cohort_execution import (
    runtime as runtime,
)
from .test_competition_cohort_execution import (
    setup_scenario,
)
from .test_competition_cohort_recovery import signatures
from .test_competition_dispatch import dispatch_legacy_policy
from .test_competition_endpoint import _FINISH_NS, _START_NS
from .test_competition_evidence import signed_run
from .test_competition_execution import boundary
from .test_component_run import response_plaintext
from .test_drand import ROUND, pulse_record
from .test_open_competition import wallet


@pytest.fixture
def endpoint(receipt_scenario, tmp_path, runtime, monkeypatch):
    s = setup_scenario(receipt_scenario, tmp_path, runtime, mode="endpoint_incumbent")
    transport = dispatch_legacy_policy()
    registry = tuple(
        sorted(
            (
                ValidatorRegistryEntry(
                    validator_hotkey=wallet(name).hotkey.ss58_address,
                    administrator_id=f"{index + 100:064x}",
                )
                for index, name in enumerate(("Charlie", "Dave", "Eve", "Ferdie"))
            ),
            key=lambda v: identity(v.validator_hotkey),
        )
    )
    transport = ScoringPolicy.model_validate_json(
        canonical_json_bytes(transport.model_copy(update={"validator_registry": list(registry)}))
    )
    monkeypatch.setattr(bt.timelock, "current_round", lambda: ROUND - 10)
    miner = SimpleNamespace(
        wallet=wallet("Alice"),
        hotkey_ss58=wallet("Alice").hotkey.ss58_address,
        signature_scheme="sr25519",
        limits=Limits.from_policy(transport),
    )
    artifacts = []
    for incumbent, name in zip(s["artifacts"], ("Charlie", "Dave"), strict=True):
        job = incumbent.job
        requests = []
        transcripts = []
        for case in job.cases:
            batch, challenge = endpoint_attempt_wire_ids(job, 1, case.case_id)
            request = challenge_request(stratum=case.stratum, reveal_round=ROUND)
            request = request.model_copy(
                update={
                    "issued_block": 1500,
                    "deadline_block": 1510,
                    "batch_id": batch,
                    "challenge_id": challenge,
                    "scoring_policy_hash": scoring_policy_hash(transport),
                    "video": request.video.model_copy(update={"sha256": case.video_sha256}),
                }
            )
            prepared = prepare_request_attempt(
                request,
                wallet=wallet(name),
                miner_hotkey=job.submission.submission.hotkey,
                nonce_ns=_START_NS,
            )
            plain = response_plaintext(
                request,
                validator_hotkey=prepared.validator_hotkey,
                miner_hotkey=prepared.miner_hotkey,
            ).model_copy(
                update={
                    "model_revision": job.submission.submission.model_revision,
                    "hypothesis": "hello",
                }
            )
            raw, signature = _signed_envelope(miner, request, plain)
            requests.append(request)
            transcripts.append(
                RecoverableEndpointTranscript(
                    case_id=case.case_id,
                    request_hex=prepared.request_bytes.hex(),
                    auth_headers=prepared.auth_headers,
                    origin=boundary(1500),
                    started_at_unix_ns=str(_START_NS),
                    finished_at_unix_ns=str(_FINISH_NS),
                    received_at_unix_ns=str(_FINISH_NS),
                    envelope_hex=raw.hex(),
                    response_signature=signature,
                    received_body_prefix_hex=raw.hex(),
                    received_bytes_sha256=hashlib.sha256(raw).hexdigest(),
                    failure_code=None,
                    reveal_pulse=RetainedRevealPulse(**pulse_record()),
                )
            )
        body = RecoverableEndpointOrder(
            schema="umi-recoverable-endpoint-order/1",
            job=job,
            transport_policy_sha256=scoring_policy_hash(transport),
            attempt_number=1,
            requests=tuple(requests),
        )
        artifacts.append(
            RecoverableEndpointPairedEvidence(
                schema="umi-recoverable-endpoint-paired-evidence/1",
                incumbent=incumbent,
                order=SignedRecoverableEndpointOrder(order=body, signatures=signatures(body)),
                transport_policy=transport,
                transcripts=tuple(transcripts),
            )
        )
    s["endpoints"] = tuple(artifacts)
    return s


def context(s, **updates):
    values = {
        k: s[k]
        for k in ("suite", "policy", "consent", "admission", "admission_snapshot", "history")
    }
    values.update(expected_tip_sha256=tip(s["history"]), current_block=5000)
    values.update(updates)
    return values


def observe(s, evidence=None, **updates):
    return recoverable_endpoint_observations(evidence or s["endpoints"][0], **context(s, **updates))


def receipt_bundle(s):
    runs = []
    for artifact, name in zip(s["endpoints"], ("Charlie", "Dave"), strict=True):
        body = recoverable_run_record_from_evidence(artifact, s["attested"].result, **context(s))
        runs.append(signed_run(body, name))
    return RecoverableExecutedEvaluation(
        schema="umi-recoverable-executed-evaluation/1",
        receipts=IndependentEvaluationEvidence(
            schema="umi-competition-independent-evaluation/1",
            attested_result=s["attested"],
            evaluator_runs=tuple(runs),
        ),
        executions=s["endpoints"],
    )


def test_real_endpoint_crypto_and_incumbent_replay_after_original_expiry(endpoint, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline evidence replay must not perform network I/O")

    monkeypatch.setattr(bt.timelock, "decrypt", forbidden)
    monkeypatch.setattr("httpx.Client.send", forbidden)
    monkeypatch.setattr("httpx.AsyncClient.send", forbidden)
    evidence = receipt_bundle(endpoint)
    original = canonical_json_bytes(evidence)
    for block in (5000, 10**6):
        candidate, incumbent = replay_recoverable_executed_evaluation(
            evidence,
            endpoint["signed"],
            endpoint["round_"],
            **context(endpoint, current_block=block),
        )
        assert set(candidate.values()) == {Fraction(1)}
        assert set(incumbent.values()) == {Fraction(0)}
    assert canonical_json_bytes(evidence) == original


def test_attempt_ids_change_while_obligation_does_not(endpoint):
    job = endpoint["endpoints"][0].incumbent.job
    case = job.cases[0].case_id
    obligation = endpoint_obligation_sha256(job, case)
    assert endpoint_attempt_wire_ids(job, 1, case) != endpoint_attempt_wire_ids(job, 2, case)
    assert endpoint_obligation_sha256(job, case) == obligation


@pytest.mark.parametrize(
    "damage",
    [
        "request_bytes",
        "auth_signature",
        "origin",
        "historical_origin",
        "case",
        "missing",
        "duplicate",
        "transport",
        "assignment_video",
        "wire_identity",
        "early",
        "late",
        "attempt_number",
        "order_signature",
        "envelope_digest",
        "pulse",
        "duplicate_headers",
        "header_case_alias",
    ],
)
def test_corrupt_transport_or_assignment_never_becomes_a_scored_response(endpoint, damage):
    artifact = endpoint["endpoints"][0]
    rows = list(artifact.transcripts)
    row = rows[0]
    body = artifact.order.order
    if damage == "request_bytes":
        rows[0] = row.model_copy(update={"request_hex": "7b7d"})
    elif damage == "auth_signature":
        headers = tuple(
            (k, "0" * 128 if "signature" in k.lower() else v) for k, v in row.auth_headers
        )
        rows[0] = row.model_copy(update={"auth_headers": headers})
    elif damage == "origin":
        rows[0] = row.model_copy(update={"origin": boundary(1511)})
    elif damage == "historical_origin":
        rows[0] = row.model_copy(
            update={
                "origin": row.origin.model_copy(update={"source": "verified_finalized_ancestry"})
            }
        )
    elif damage == "case":
        rows[0] = row.model_copy(update={"case_id": "ff" * 32})
    elif damage == "missing":
        rows = rows[:-1]
    elif damage == "duplicate":
        rows[1] = rows[0]
    elif damage == "duplicate_headers":
        rows[0] = row.model_copy(update={"auth_headers": (*row.auth_headers, row.auth_headers[0])})
    elif damage == "header_case_alias":
        name, value = row.auth_headers[0]
        rows[0] = row.model_copy(
            update={"auth_headers": (*row.auth_headers, (name.upper(), value))}
        )
    elif damage == "transport":
        body = body.model_copy(update={"transport_policy_sha256": "ff" * 32})
    elif damage in ("assignment_video", "wire_identity", "early", "late"):
        request = body.requests[0]
        changes = {
            "assignment_video": {"video": request.video.model_copy(update={"sha256": "ff" * 32})},
            "wire_identity": {"challenge_id": body.requests[1].challenge_id},
            "early": {"issued_block": 390},
            "late": {"deadline_block": 1681},
        }[damage]
        body = body.model_copy(
            update={"requests": (request.model_copy(update=changes), *body.requests[1:])}
        )
    elif damage == "attempt_number":
        body = body.model_copy(update={"attempt_number": 2})
    elif damage == "envelope_digest":
        rows[0] = row.model_copy(update={"received_bytes_sha256": "ff" * 32})
    elif damage == "pulse":
        rows[0] = row.model_copy(
            update={"reveal_pulse": row.reveal_pulse.model_copy(update={"signature": "00" * 48})}
        )
    signed = SignedRecoverableEndpointOrder(order=body, signatures=signatures(body))
    if damage == "order_signature":
        signed = signed.model_copy(update={"signatures": signed.signatures[:1]})
    artifact = artifact.model_copy(update={"order": signed, "transcripts": tuple(rows)})
    with pytest.raises(DrandVerificationError if damage == "pulse" else ValueError):
        observe(endpoint, artifact)


def test_unauthenticated_transport_failure_is_preserved_for_void_review(endpoint):
    artifact = endpoint["endpoints"][0]
    rows = list(artifact.transcripts)
    rows[0] = rows[0].model_copy(
        update={
            "received_at_unix_ns": None,
            "envelope_hex": None,
            "response_signature": None,
            "received_body_prefix_hex": None,
            "received_bytes_sha256": None,
            "failure_code": "request_transport_failed",
            "reveal_pulse": None,
        }
    )
    artifact = artifact.model_copy(update={"transcripts": tuple(rows)})
    view = observe(endpoint, artifact)
    assert view.candidate[0].status == "infrastructure_failure"
    common = endpoint["attested"].result.model_copy(update={"candidate": view.candidate})
    with pytest.raises(ValueError):
        recoverable_run_record_from_evidence(artifact, common, **context(endpoint))


def test_endpoint_replay_requires_current_unrevoked_history_and_reveal(endpoint):
    h = endpoint["history"]
    pending = h.model_copy(update={"transitions": h.transitions[:-1]})
    with pytest.raises(ValueError, match="closure"):
        observe(endpoint, history=pending, expected_tip_sha256=tip(pending))
    with pytest.raises(ValueError, match="current tip"):
        observe(endpoint, expected_tip_sha256=tip(pending))
    revoked = transition(h, endpoint["policy"], "revoke", 1800)
    with pytest.raises(ValueError, match="revoked"):
        observe(endpoint, history=revoked, expected_tip_sha256=tip(revoked))


@pytest.mark.parametrize(
    "damage", ["missing", "duplicate", "changed_transcript", "changed_receipt"]
)
def test_signed_endpoint_receipts_require_the_exact_complete_artifact(endpoint, damage):
    evidence = receipt_bundle(endpoint)
    artifacts = list(evidence.executions)
    runs = list(evidence.receipts.evaluator_runs)
    if damage == "missing":
        artifacts.pop()
    elif damage == "duplicate":
        artifacts[1] = artifacts[0]
    elif damage == "changed_transcript":
        artifact = artifacts[0]
        row = artifact.transcripts[0].model_copy(update={"received_bytes_sha256": "ff" * 32})
        artifacts[0] = artifact.model_copy(update={"transcripts": (row, *artifact.transcripts[1:])})
        # Re-sign the new artifact digest: digest agreement alone must not pass.
        runs[0] = signed_run(
            runs[0].run.model_copy(
                update={
                    "execution_evidence_sha256": digest(artifacts[0]),
                }
            ),
            "Charlie",
        )
    elif damage == "changed_receipt":
        runs[0] = signed_run(runs[0].run.model_copy(update={"started_block": 1499}), "Charlie")
    evidence = evidence.model_copy(
        update={
            "executions": tuple(artifacts),
            "receipts": evidence.receipts.model_copy(update={"evaluator_runs": tuple(runs)}),
        }
    )
    with pytest.raises(ValueError):
        replay_recoverable_executed_evaluation(
            evidence, endpoint["signed"], endpoint["round_"], **context(endpoint)
        )


def test_signed_miner_error_remains_a_miner_failure_not_a_transport_void(endpoint):
    artifact = endpoint["endpoints"][0]
    job = artifact.incumbent.job
    request = artifact.order.order.requests[0]
    plain = response_plaintext(
        request,
        validator_hotkey=job.evaluator_hotkey,
        miner_hotkey=job.submission.submission.hotkey,
    ).model_copy(
        update={
            "status": "error",
            "hypothesis": None,
            "error_code": "inference_failed",
            "model_revision": job.submission.submission.model_revision,
        }
    )
    miner = SimpleNamespace(
        wallet=wallet("Alice"),
        hotkey_ss58=job.submission.submission.hotkey,
        signature_scheme="sr25519",
        limits=Limits.from_policy(artifact.transport_policy),
    )
    raw, signature = _signed_envelope(miner, request, plain)
    row = artifact.transcripts[0].model_copy(
        update={
            "envelope_hex": raw.hex(),
            "response_signature": signature,
            "received_body_prefix_hex": raw.hex(),
            "received_bytes_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    artifact = artifact.model_copy(update={"transcripts": (row, *artifact.transcripts[1:])})
    view = observe(endpoint, artifact)
    assert view.candidate[0].status == "miner_failure"
    assert view.candidate[0].hypothesis == ""
    common = endpoint["attested"].result.model_copy(update={"candidate": view.candidate})
    receipt = recoverable_run_record_from_evidence(artifact, common, **context(endpoint))
    assert receipt.candidate[0] == view.candidate[0]
