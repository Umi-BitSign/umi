from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from umi.anchors import (
    AssignmentAnchorRecord,
    RequestAnchorRecord,
    ResponseAnchorRecord,
    SealedResponseRecord,
    assignment_set_root,
    request_set_root,
    response_set_root,
)
from umi.crypto import seal_response, sign_response_digest
from umi.protocol import (
    PROTOCOL_VERSION,
    RESPONSE_ENVELOPE_SCHEMA,
    RESPONSE_TLE_PROFILE,
    ResponseEnvelope,
    canonical_json_bytes,
    request_digest,
)
from umi.validator import prepare_request_attempt
from umi.validator_assignments import (
    WINDOW_SCHEMA,
    AssignmentConflict,
    AssignmentPhaseError,
    AssignmentStoreError,
    AttemptOutcomeInput,
    TranscriptPhase,
    TranscriptWindowSpec,
    ValidatorAssignmentStore,
    deterministic_assignment_id,
)

from .factories import TEST_REVEAL_ROUND, challenge_request, dev_wallet

VALIDATOR_WALLET = dev_wallet("//Alice")
MINER_WALLET = dev_wallet("//Bob")
VALIDATOR = VALIDATOR_WALLET.hotkey.ss58_address
MINER = MINER_WALLET.hotkey.ss58_address
REVEAL_ROUND = TEST_REVEAL_ROUND
RESPONSE_CLOSE_ROUND = REVEAL_ROUND - 2
ISSUE_CLOSE_ROUND = RESPONSE_CLOSE_ROUND - 1


def _spec(
    *,
    assignments: int = 1,
    transmissions: int = 2,
    prefix_bytes: int = 32,
) -> TranscriptWindowSpec:
    return TranscriptWindowSpec(
        schema=WINDOW_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=challenge_request(1, reveal_round=REVEAL_ROUND).window_id,
        validator_hotkey=VALIDATOR,
        expected_assignment_count=assignments,
        maximum_request_transmissions_per_assignment=transmissions,
        issue_close_round=ISSUE_CLOSE_ROUND,
        response_close_round=RESPONSE_CLOSE_ROUND,
        reveal_round=REVEAL_ROUND,
        maximum_request_body_bytes=64 * 1024,
        maximum_response_body_bytes=64 * 1024,
        maximum_retained_prefix_bytes=prefix_bytes,
    )


def _prepared(index: int, nonce: int):
    return prepare_request_attempt(
        challenge_request(index, reveal_round=REVEAL_ROUND),
        wallet=VALIDATOR_WALLET,
        miner_hotkey=MINER,
        nonce_ns=nonce,
    )


def _outer_invalid(prefix: bytes, *, recorded_round: int | None = None) -> AttemptOutcomeInput:
    return AttemptOutcomeInput(
        sealed_response_record=SealedResponseRecord.model_validate(
            {
                "disposition": "outer_invalid",
                "receipt_metadata": {"reason": "malformed_envelope"},
                "received_bytes_sha256": hashlib.sha256(prefix).hexdigest(),
            }
        ),
        recorded_at_round=recorded_round or RESPONSE_CLOSE_ROUND - 1,
        received_block=105,
        received_round=RESPONSE_CLOSE_ROUND - 1,
        body_or_prefix=prefix,
    )


def _missing() -> AttemptOutcomeInput:
    return AttemptOutcomeInput(
        sealed_response_record=SealedResponseRecord.model_validate(
            {
                "disposition": "missing",
                "receipt_metadata": {"boundary": "response_close"},
            }
        ),
        recorded_at_round=RESPONSE_CLOSE_ROUND,
    )


def _late(prefix: bytes) -> AttemptOutcomeInput:
    return AttemptOutcomeInput(
        sealed_response_record=SealedResponseRecord.model_validate(
            {
                "disposition": "late",
                "receipt_metadata": {"boundary": "response_close"},
                "received_bytes_sha256": hashlib.sha256(prefix).hexdigest(),
            }
        ),
        recorded_at_round=RESPONSE_CLOSE_ROUND,
        received_block=105,
        received_round=RESPONSE_CLOSE_ROUND,
        body_or_prefix=prefix,
    )


def _sealed(prepared, *, received_block: int = 105) -> AttemptOutcomeInput:
    sealed = seal_response(b'{"status":"ok"}', reveal_round=REVEAL_ROUND)
    envelope = ResponseEnvelope.model_validate(
        {
            "schema": RESPONSE_ENVELOPE_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": prepared.request.window_id,
            "batch_id": prepared.request.batch_id,
            "challenge_id": prepared.request.challenge_id,
            "request_digest": request_digest(prepared.request),
            "issued_block_hash": prepared.request.issued_block_hash,
            "validator_hotkey": prepared.validator_hotkey,
            "serving_hotkey": prepared.miner_hotkey,
            "response_tle_profile": RESPONSE_TLE_PROFILE,
            "response_reveal_round": prepared.request.reveal_round,
            "encrypted_response": sealed.portable_b64,
            "encrypted_response_sha256": sealed.sha256_hex,
            "signature_scheme": "sr25519",
        }
    )
    scheme, signature = sign_response_digest(MINER_WALLET, envelope)
    body = canonical_json_bytes(envelope)
    record = SealedResponseRecord.model_validate(
        {
            "disposition": "sealed",
            "receipt_metadata": {
                "received_block": received_block,
                "received_round": RESPONSE_CLOSE_ROUND - 1,
            },
            "wire_envelope_sha256": hashlib.sha256(body).hexdigest(),
            "signature_scheme": scheme,
            "serving_hotkey": MINER,
            "signature": signature,
        }
    )
    return AttemptOutcomeInput(
        sealed_response_record=record,
        recorded_at_round=RESPONSE_CLOSE_ROUND - 1,
        received_block=received_block,
        received_round=RESPONSE_CLOSE_ROUND - 1,
        body_or_prefix=body,
    )


def _new_store(tmp_path: Path, spec: TranscriptWindowSpec) -> ValidatorAssignmentStore:
    store = ValidatorAssignmentStore(tmp_path / "transcripts")
    store.create_window(spec)
    return store


def test_full_transcript_lifecycle_reproduces_all_anchor_roots_and_restarts(
    tmp_path: Path,
) -> None:
    spec = _spec(assignments=2)
    store = _new_store(tmp_path, spec)
    first = store.add_assignment(
        spec.window_id,
        _prepared(1, 100),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    second = store.add_assignment(
        spec.window_id,
        _prepared(2, 200),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    assignment_frozen = store.freeze_assignments(
        spec.window_id,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )

    assert store.claim_for_send(
        first.assignment_id,
        0,
        operation_id="send.first.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    ).should_send
    assert store.claim_for_send(
        second.assignment_id,
        0,
        operation_id="send.second.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    ).should_send
    first_failure = store.record_outcome(first.assignment_id, 0, _outer_invalid(b"bad"))
    retry_prepared = _prepared(1, 101)
    retry = store.add_retry(
        first.assignment_id,
        retry_prepared,
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    )
    assert retry.attempt_index == 1
    assert store.claim_for_send(
        first.assignment_id,
        1,
        operation_id="send.first.1",
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    ).should_send

    request_frozen = store.freeze_requests(
        spec.window_id,
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    )
    final = store.record_outcome(first.assignment_id, 1, _sealed(retry_prepared))
    store.record_outcome(second.assignment_id, 0, _missing())
    response_frozen = store.freeze_responses(
        spec.window_id,
        observed_round=RESPONSE_CLOSE_ROUND,
    )

    first_attempts = store.list_attempts(first.assignment_id)
    second_attempts = store.list_attempts(second.assignment_id)
    assignment_records = (
        AssignmentAnchorRecord(first_attempts[0].prepared.auth_evidence),
        AssignmentAnchorRecord(second_attempts[0].prepared.auth_evidence),
    )
    request_records = (
        RequestAnchorRecord(tuple(item.prepared.auth_evidence for item in first_attempts)),
        RequestAnchorRecord(tuple(item.prepared.auth_evidence for item in second_attempts)),
    )
    response_records = (
        ResponseAnchorRecord(
            request_records[0].leaf,
            first_attempts[1].outcome.sealed_response_record,
        ),
        ResponseAnchorRecord(
            request_records[1].leaf,
            second_attempts[0].outcome.sealed_response_record,
        ),
    )
    assert (
        assignment_frozen.root
        == assignment_set_root(
            assignment_records,
            window_id=spec.window_id,
            validator_hotkey=VALIDATOR,
        ).hex()
    )
    assert (
        request_frozen.root
        == request_set_root(
            request_records,
            assignments=assignment_records,
            window_id=spec.window_id,
            validator_hotkey=VALIDATOR,
        ).hex()
    )
    assert (
        response_frozen.root
        == response_set_root(
            response_records,
            request_records=request_records,
            window_id=spec.window_id,
            validator_hotkey=VALIDATOR,
        ).hex()
    )
    assert first_failure.outcome.sealed_response_record.disposition == "outer_invalid"
    assert final.final
    assert store.load_window(spec.window_id).phase is TranscriptPhase.RESPONSES_FROZEN

    restarted = ValidatorAssignmentStore(tmp_path / "transcripts")
    snapshot = restarted.load_window(spec.window_id)
    assert snapshot.assignment_root == assignment_frozen.root
    assert snapshot.request_root == request_frozen.root
    assert snapshot.response_root == response_frozen.root
    restarted_retry = restarted.list_attempts(first.assignment_id)[1]
    assert canonical_json_bytes(restarted_retry.prepared.request) == retry_prepared.request_bytes
    prepared_evidence = restarted.read_evidence(restarted_retry.prepared_evidence_ref)
    assert hashlib.sha256(prepared_evidence).hexdigest() == (
        restarted_retry.prepared_evidence_ref.sha256
    )
    assert restarted_retry.outcome_evidence_ref is not None
    outcome_evidence = restarted.read_evidence(restarted_retry.outcome_evidence_ref)
    assert hashlib.sha256(outcome_evidence).hexdigest() == (
        restarted_retry.outcome_evidence_ref.sha256
    )


def test_deterministic_identity_and_initial_add_are_idempotent(tmp_path: Path) -> None:
    spec = _spec()
    store = _new_store(tmp_path, spec)
    prepared = _prepared(1, 100)
    first = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    repeated = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    assert first.assignment_id == deterministic_assignment_id(prepared)
    assert repeated == first

    conflicting = _prepared(1, 101)
    with pytest.raises(AssignmentConflict, match="another initial attempt"):
        store.add_assignment(
            spec.window_id,
            conflicting,
            observed_round=ISSUE_CLOSE_ROUND - 1,
        )

    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    assert (
        store.add_assignment(
            spec.window_id,
            prepared,
            observed_round=ISSUE_CLOSE_ROUND,
        )
        == first
    )


def test_assignment_set_must_be_complete_and_frozen_before_any_send(tmp_path: Path) -> None:
    spec = _spec(assignments=2)
    store = _new_store(tmp_path, spec)
    assignment = store.add_assignment(
        spec.window_id,
        _prepared(1, 100),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    with pytest.raises(AssignmentPhaseError, match="open issuance phase"):
        store.claim_for_send(
            assignment.assignment_id,
            0,
            operation_id="send.0",
            observed_round=ISSUE_CLOSE_ROUND - 1,
        )
    with pytest.raises(AssignmentConflict, match="cardinality"):
        store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)


def test_send_claim_is_one_way_and_idempotent_without_authorizing_resend(tmp_path: Path) -> None:
    spec = _spec()
    store = _new_store(tmp_path, spec)
    attempt = store.add_assignment(
        spec.window_id,
        _prepared(1, 100),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    first = store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    repeated = store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    assert first.should_send
    assert not repeated.should_send
    with pytest.raises(AssignmentConflict, match="another operation"):
        store.claim_for_send(
            attempt.assignment_id,
            0,
            operation_id="send.different",
            observed_round=ISSUE_CLOSE_ROUND - 1,
        )


def test_retry_requires_outcome_and_fresh_increasing_auth_then_stops_at_ceiling(
    tmp_path: Path,
) -> None:
    spec = _spec(transmissions=2)
    store = _new_store(tmp_path, spec)
    initial_prepared = _prepared(1, 100)
    initial = store.add_assignment(
        spec.window_id,
        initial_prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    store.claim_for_send(
        initial.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    with pytest.raises(AssignmentPhaseError, match="preceding attempt outcome"):
        store.add_retry(
            initial.assignment_id,
            _prepared(1, 101),
            observed_round=RESPONSE_CLOSE_ROUND - 1,
        )
    store.record_outcome(initial.assignment_id, 0, _outer_invalid(b"bad"))
    with pytest.raises(AssignmentConflict, match="fresh authentication"):
        store.add_retry(
            initial.assignment_id,
            initial_prepared,
            observed_round=RESPONSE_CLOSE_ROUND - 1,
        )
    with pytest.raises(AssignmentConflict, match="fresh and increasing"):
        store.add_retry(
            initial.assignment_id,
            _prepared(1, 99),
            observed_round=RESPONSE_CLOSE_ROUND - 1,
        )
    retry_prepared = _prepared(1, 101)
    retry = store.add_retry(
        initial.assignment_id,
        retry_prepared,
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    )
    assert (
        store.add_retry(
            initial.assignment_id,
            retry_prepared,
            observed_round=RESPONSE_CLOSE_ROUND - 1,
        )
        == retry
    )
    store.claim_for_send(
        initial.assignment_id,
        1,
        operation_id="send.1",
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    )
    store.record_outcome(initial.assignment_id, 1, _outer_invalid(b"no"))
    with pytest.raises(AssignmentPhaseError, match="ceiling"):
        store.add_retry(
            initial.assignment_id,
            _prepared(1, 102),
            observed_round=RESPONSE_CLOSE_ROUND - 1,
        )


def test_structurally_valid_timely_sealed_response_is_final_and_forbids_retry(
    tmp_path: Path,
) -> None:
    spec = _spec(transmissions=3)
    store = _new_store(tmp_path, spec)
    prepared = _prepared(1, 100)
    attempt = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    final = store.record_outcome(attempt.assignment_id, 0, _sealed(prepared))
    assert final.final
    with pytest.raises(AssignmentPhaseError, match="valid final"):
        store.add_retry(
            attempt.assignment_id,
            _prepared(1, 101),
            observed_round=RESPONSE_CLOSE_ROUND - 1,
        )


def test_failure_prefix_missing_and_late_markers_are_bounded_and_timed(tmp_path: Path) -> None:
    spec = _spec(prefix_bytes=3)
    store = _new_store(tmp_path, spec)
    prepared = _prepared(1, 100)
    attempt = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    with pytest.raises(AssignmentConflict, match="retention ceiling"):
        store.record_outcome(attempt.assignment_id, 0, _outer_invalid(b"four"))

    bad_missing = AttemptOutcomeInput(
        sealed_response_record=_missing().sealed_response_record,
        recorded_at_round=RESPONSE_CLOSE_ROUND - 1,
    )
    with pytest.raises(AssignmentPhaseError, match="before response close"):
        store.record_outcome(attempt.assignment_id, 0, bad_missing)
    with pytest.raises(AssignmentConflict, match="inside both"):
        store.record_outcome(
            attempt.assignment_id,
            0,
            AttemptOutcomeInput(
                sealed_response_record=_late(b"x").sealed_response_record,
                recorded_at_round=RESPONSE_CLOSE_ROUND - 1,
                received_block=105,
                received_round=RESPONSE_CLOSE_ROUND - 1,
                body_or_prefix=b"x",
            ),
        )
    recorded = store.record_outcome(attempt.assignment_id, 0, _late(b"x"))
    assert recorded.outcome.retained_body.size_bytes == 1


def test_outcome_is_exactly_once_and_conflicting_receipt_is_fatal(tmp_path: Path) -> None:
    spec = _spec()
    store = _new_store(tmp_path, spec)
    attempt = store.add_assignment(
        spec.window_id,
        _prepared(1, 100),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    outcome = _outer_invalid(b"bad")
    first = store.record_outcome(attempt.assignment_id, 0, outcome)
    assert store.record_outcome(attempt.assignment_id, 0, outcome) == first
    with pytest.raises(AssignmentConflict, match="another outcome"):
        store.record_outcome(attempt.assignment_id, 0, _outer_invalid(b"new"))


def test_restart_at_each_open_phase_preserves_one_way_operations(tmp_path: Path) -> None:
    spec = _spec(transmissions=2)
    root = tmp_path / "transcripts"
    store = ValidatorAssignmentStore(root)
    store.create_window(spec)
    initial_prepared = _prepared(1, 100)
    initial = store.add_assignment(
        spec.window_id,
        initial_prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)

    store = ValidatorAssignmentStore(root)
    claim = store.claim_for_send(
        initial.assignment_id,
        0,
        operation_id="send.initial",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    assert claim.should_send
    store.record_outcome(initial.assignment_id, 0, _outer_invalid(b"bad"))
    retry_prepared = _prepared(1, 101)
    retry = store.add_retry(
        initial.assignment_id,
        retry_prepared,
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    )

    store = ValidatorAssignmentStore(root)
    assert not store.claim_for_send(
        initial.assignment_id,
        0,
        operation_id="send.initial",
        observed_round=RESPONSE_CLOSE_ROUND,
    ).should_send
    assert store.claim_for_send(
        retry.assignment_id,
        1,
        operation_id="send.retry",
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    ).should_send
    requests = store.freeze_requests(
        spec.window_id,
        observed_round=RESPONSE_CLOSE_ROUND - 1,
    )

    store = ValidatorAssignmentStore(root)
    final_input = _sealed(retry_prepared)
    final = store.record_outcome(initial.assignment_id, 1, final_input)
    responses = store.freeze_responses(
        spec.window_id,
        observed_round=RESPONSE_CLOSE_ROUND,
    )
    assert final.final
    assert store.record_outcome(initial.assignment_id, 1, final_input) == final
    assert (
        store.freeze_requests(
            spec.window_id,
            observed_round=REVEAL_ROUND,
        )
        == requests
    )
    assert (
        store.freeze_responses(
            spec.window_id,
            observed_round=REVEAL_ROUND,
        )
        == responses
    )


def test_receipt_cannot_predate_request_issuance(tmp_path: Path) -> None:
    spec = _spec()
    store = _new_store(tmp_path, spec)
    prepared = _prepared(1, 100)
    attempt = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    invalid = _sealed(prepared, received_block=prepared.request.issued_block - 1)
    with pytest.raises(AssignmentConflict, match="predates request issuance"):
        store.record_outcome(attempt.assignment_id, 0, invalid)


def test_request_and_response_freeze_boundaries_and_bijections_fail_closed(
    tmp_path: Path,
) -> None:
    spec = _spec()
    store = _new_store(tmp_path, spec)
    attempt = store.add_assignment(
        spec.window_id,
        _prepared(1, 100),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    with pytest.raises(AssignmentConflict, match="unissued"):
        store.freeze_requests(spec.window_id, observed_round=RESPONSE_CLOSE_ROUND - 1)
    store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_requests(spec.window_id, observed_round=RESPONSE_CLOSE_ROUND - 1)
    with pytest.raises(AssignmentConflict, match="one outcome"):
        store.freeze_responses(spec.window_id, observed_round=RESPONSE_CLOSE_ROUND)
    store.record_outcome(attempt.assignment_id, 0, _missing())
    with pytest.raises(AssignmentPhaseError, match="after response close"):
        store.freeze_responses(spec.window_id, observed_round=RESPONSE_CLOSE_ROUND - 1)
    store.freeze_responses(spec.window_id, observed_round=RESPONSE_CLOSE_ROUND)


def test_invalid_sealed_body_cannot_be_recorded_as_structurally_valid(tmp_path: Path) -> None:
    spec = _spec()
    store = _new_store(tmp_path, spec)
    prepared = _prepared(1, 100)
    attempt = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    store.claim_for_send(
        attempt.assignment_id,
        0,
        operation_id="send.0",
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    valid = _sealed(prepared)
    tampered = b"x" + valid.body_or_prefix[1:]
    invalid = AttemptOutcomeInput(
        sealed_response_record=valid.sealed_response_record.model_copy(
            update={"wire_envelope_sha256": hashlib.sha256(tampered).hexdigest()}
        ),
        recorded_at_round=valid.recorded_at_round,
        received_block=valid.received_block,
        received_round=valid.received_round,
        body_or_prefix=tampered,
    )
    with pytest.raises(AssignmentConflict, match="response envelope is invalid"):
        store.record_outcome(attempt.assignment_id, 0, invalid)


def test_restart_detects_content_object_and_sqlite_root_tampering(tmp_path: Path) -> None:
    spec = _spec()
    root = tmp_path / "objects"
    store = _new_store(root, spec)
    prepared = _prepared(1, 100)
    attempt = store.add_assignment(
        spec.window_id,
        prepared,
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    frozen = store.freeze_assignments(spec.window_id, observed_round=ISSUE_CLOSE_ROUND - 1)
    object_path = root / "transcripts" / "objects" / frozen.evidence_sha256
    original = object_path.read_bytes()
    object_path.write_bytes(b"tampered")
    with pytest.raises(AssignmentStoreError, match="name does not match"):
        ValidatorAssignmentStore(root / "transcripts")
    object_path.write_bytes(original)

    database = root / "transcripts" / "transcripts.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE windows SET assignment_root = ? WHERE window_id = ?",
        ("ff" * 32, spec.window_id),
    )
    connection.commit()
    connection.close()
    with pytest.raises(AssignmentStoreError, match="root does not reproduce"):
        ValidatorAssignmentStore(root / "transcripts")
    assert attempt.assignment_id


def test_restart_detects_cross_assignment_evidence_pointer_substitution(
    tmp_path: Path,
) -> None:
    spec = _spec(assignments=2)
    root = tmp_path / "transcripts"
    store = ValidatorAssignmentStore(root)
    store.create_window(spec)
    first = store.add_assignment(
        spec.window_id,
        _prepared(1, 100),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )
    second = store.add_assignment(
        spec.window_id,
        _prepared(2, 200),
        observed_round=ISSUE_CLOSE_ROUND - 1,
    )

    database = root / "transcripts.sqlite3"
    connection = sqlite3.connect(database)
    second_reference = connection.execute(
        """
        SELECT prepared_sha256, prepared_size_bytes FROM attempts
        WHERE assignment_id = ? AND attempt_index = 0
        """,
        (second.assignment_id,),
    ).fetchone()
    connection.execute(
        """
        UPDATE attempts SET prepared_sha256 = ?, prepared_size_bytes = ?
        WHERE assignment_id = ? AND attempt_index = 0
        """,
        (*second_reference, first.assignment_id),
    )
    connection.commit()
    connection.close()

    with pytest.raises(AssignmentStoreError, match="disagrees with its row"):
        ValidatorAssignmentStore(root)


def test_sqlite_authority_uses_wal_full_sync_and_foreign_keys(tmp_path: Path) -> None:
    spec = _spec()
    root = tmp_path / "transcripts"
    _new_store(tmp_path, spec)
    connection = sqlite3.connect(root / "transcripts.sqlite3")
    assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    connection.execute("PRAGMA synchronous = FULL")
    assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    connection.execute("PRAGMA foreign_keys = ON")
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    connection.close()
