from __future__ import annotations

import asyncio
import hashlib
import json
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from bittensor import UnsignedExtrinsic

from umi.config import Limits
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator import (
    PreparedRequestAttempt,
    QueryOutcome,
    prepare_request_attempt,
    send_prepared_request,
)
from umi.validator_adapters import CompleteStageEffect
from umi.validator_assignments import (
    WINDOW_SCHEMA,
    TranscriptMaterialBinding,
    TranscriptPhase,
    TranscriptWindowSpec,
    ValidatorAssignmentStore,
)
from umi.validator_extrinsics import (
    PREPARED_CALL_SCHEMA,
    RECONCILIATION_SCHEMA,
    SUBMISSION_SCHEMA,
    ExtrinsicOperation,
    ExtrinsicPorts,
    PreparedCallEvidence,
    ReconcileOutcome,
    ReconcileQuery,
    ReconciliationEvidence,
    SubmissionEvidence,
    ValidatorExtrinsicJournal,
)
from umi.validator_journal import (
    StageObjectInput,
    StageReceipt,
    ValidatorStageJournal,
)
from umi.validator_state import (
    STAGE_ORDER,
    ControlState,
    PauseScope,
    StageEvidence,
    StageWorkItem,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_transcript_effects import (
    AssignmentTranscriptEffect,
    RequestTranscriptEffect,
    SealedResponseTranscriptEffect,
    TranscriptAssignment,
    TranscriptEffectBindingError,
    TranscriptEffectPending,
    TranscriptEffectPorts,
    TranscriptExecutionMaterial,
    TranscriptExecutionPlan,
    TranscriptReplayError,
    TranscriptStageReplay,
    VerifiedAnchorFinality,
    VerifiedProtocolObservation,
    replay_transcript_stage_receipt,
    replay_transcript_stage_record,
)

from .factories import POLICY_HASH, TEST_REVEAL_ROUND, challenge_request, dev_wallet

VALIDATOR_WALLET = dev_wallet("//Alice")
MINER_WALLET = dev_wallet("//Bob")
VALIDATOR = VALIDATOR_WALLET.hotkey.ss58_address
MINER = MINER_WALLET.hotkey.ss58_address
REVEAL_ROUND = TEST_REVEAL_ROUND
RESPONSE_CLOSE_ROUND = REVEAL_ROUND - 2
ISSUE_CLOSE_ROUND = RESPONSE_CLOSE_ROUND - 1
SIGNATURE = b"s" * 64


def _execution_plan(
    *,
    assignment_count: int = 1,
    transmissions: int = 1,
) -> TranscriptExecutionPlan:
    assignments = []
    for index in range(1, assignment_count + 1):
        prepared = prepare_request_attempt(
            challenge_request(index, reveal_round=REVEAL_ROUND),
            wallet=VALIDATOR_WALLET,
            miner_hotkey=MINER,
            nonce_ns=1_000 + index,
        )
        assignments.append(
            TranscriptAssignment(
                prepared,
                f"https://miner-{index}.example",
            )
        )
    ordered = tuple(sorted(assignments, key=lambda item: item.assignment_id))
    return TranscriptExecutionPlan(
        spec=TranscriptWindowSpec(
            schema=WINDOW_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=ordered[0].initial_attempt.request.window_id,
            validator_hotkey=VALIDATOR,
            expected_assignment_count=assignment_count,
            maximum_request_transmissions_per_assignment=transmissions,
            issue_close_round=ISSUE_CLOSE_ROUND,
            response_close_round=RESPONSE_CLOSE_ROUND,
            reveal_round=REVEAL_ROUND,
            maximum_request_body_bytes=64 * 1024,
            maximum_response_body_bytes=64 * 1024,
            maximum_retained_prefix_bytes=64,
        ),
        assignments=ordered,
    )


def _work(plan: TranscriptExecutionPlan, stage: WindowStage) -> StageWorkItem:
    schedule = WindowPlan(
        window_id=plan.spec.window_id,
        window_index=0,
        scoring_policy_hash=POLICY_HASH,
        announcement_block=1_000,
        proposal_close_block=1_030,
        closing_block=1_045,
        selection_round=plan.spec.issue_close_round - 10,
        issue_close_round=plan.spec.issue_close_round,
        response_close_round=plan.spec.response_close_round,
        reveal_round=plan.spec.reveal_round,
    )
    prior = tuple(
        StageEvidence(
            window_id=plan.spec.window_id,
            stage=prior_stage,
            evidence_sha256=hashlib.sha256(f"test-prefix:{prior_stage.value}".encode()).hexdigest(),
            recorded_at_unix_ns=1,
        )
        for prior_stage in STAGE_ORDER[: STAGE_ORDER.index(stage)]
    )
    return StageWorkItem(
        window=WindowRecord(
            plan=schedule,
            stage=stage,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=0,
        ),
        completed_evidence=prior,
        controls=(
            ControlState(PauseScope.WINDOW_INTAKE, ()),
            ControlState(PauseScope.WEIGHT_SUBMISSION, ()),
        ),
    )


class FactPort:
    def __init__(self, plan: TranscriptExecutionPlan) -> None:
        self.plan = plan
        self.overrides: dict[str, int] = {}
        self.calls: list[str] = []

    async def __call__(
        self,
        boundary: str,
        _work: StageWorkItem,
    ) -> VerifiedProtocolObservation:
        self.calls.append(boundary)
        observed_round = self.overrides.get(boundary)
        if observed_round is None:
            if boundary in {"response_freeze", "response_set_anchor_submit"}:
                observed_round = self.plan.spec.response_close_round
            elif boundary in {"retry_prepare", "response_receipt"}:
                observed_round = self.plan.spec.response_close_round - 1
            else:
                observed_round = self.plan.spec.issue_close_round - 1
        sequence = len(self.calls)
        return VerifiedProtocolObservation(
            finalized_block=105,
            finalized_block_hash="0x" + f"{sequence:064x}",
            quicknet_round=observed_round,
            evidence_bytes=f"observation:{boundary}:{sequence}".encode(),
        )


def _binding(unsigned: UnsignedExtrinsic, signature: bytes) -> dict[str, str]:
    return {
        "unsigned_record_sha256": hashlib.sha256(
            canonical_json_bytes(unsigned.to_dict())
        ).hexdigest(),
        "payload_sha256": hashlib.sha256(unsigned.payload).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }


class AnchorChain:
    """Exact fake anchor capability; it cannot prepare a weight operation."""

    def __init__(self, plan: TranscriptExecutionPlan) -> None:
        self.plan = plan
        self.anchor_port_calls: list[str] = []
        self.prepared_operations: list[ExtrinsicOperation] = []
        self.submit_calls: list[str] = []
        self.reconcile_calls: defaultdict[str, int] = defaultdict(int)
        self.finalized_round_overrides: dict[str, int] = {}

    def ports(
        self,
        operation: ExtrinsicOperation,
        _work: StageWorkItem,
    ) -> ExtrinsicPorts:
        self.anchor_port_calls.append(operation.operation)

        async def prepare(requested: ExtrinsicOperation) -> UnsignedExtrinsic:
            assert requested == operation
            self.prepared_operations.append(requested)
            call_data = b"\x06" + bytes.fromhex(requested.request.field.sha256)
            return UnsignedExtrinsic(
                call_data=call_data,
                address=VALIDATOR,
                public_key=b"p" * 32,
                crypto_type=1,
                era={"period": 64, "current": 100},
                nonce=len(self.prepared_operations),
                tip=0,
                tip_asset_id=None,
                genesis_hash="0x" + "77" * 32,
                era_block_hash="0x" + "88" * 32,
                spec_version=449,
                transaction_version=1,
                metadata_hash=None,
                payload=b"payload:" + call_data,
                payload_json={"method": "0x" + call_data.hex()},
                included_in_extrinsic=b"included",
                included_in_signed_data=b"signed",
            )

        async def verify_prepared_call(
            requested: ExtrinsicOperation,
            unsigned: UnsignedExtrinsic,
        ) -> PreparedCallEvidence:
            assert requested == operation
            return PreparedCallEvidence(
                schema=PREPARED_CALL_SCHEMA,
                operation_id=requested.operation_id,
                call_data_sha256=hashlib.sha256(unsigned.call_data).hexdigest(),
                call_data_size_bytes=len(unsigned.call_data),
                module="Commitments",
                function="set_commitment",
                netuid=78,
                anchor_kind=requested.request.anchor_kind,
                field_sha256=requested.request.field.sha256,
                runtime_spec_version=unsigned.spec_version,
                transaction_version=unsigned.transaction_version,
                runtime_metadata_sha256="99" * 32,
            )

        async def sign(payload: bytes, operation_id: str) -> bytes:
            assert operation_id == operation.operation_id
            assert payload.startswith(b"payload:")
            return SIGNATURE

        async def submit(
            unsigned: UnsignedExtrinsic,
            signature: bytes,
        ) -> SubmissionEvidence:
            assert signature == SIGNATURE
            self.submit_calls.append(operation.operation)
            return SubmissionEvidence(
                schema=SUBMISSION_SCHEMA,
                operation_id=operation.operation_id,
                extrinsic_hash="0x" + operation.operation_id,
                **_binding(unsigned, signature),
            )

        async def reconcile(query: ReconcileQuery) -> ReconciliationEvidence:
            self.reconcile_calls[operation.operation_id] += 1
            count = self.reconcile_calls[operation.operation_id]
            outcome = (
                ReconcileOutcome.NOT_FOUND if count == 1 else ReconcileOutcome.FINALIZED_SUCCESS
            )
            scan = {"kind": "test-anchor-scan", "count": count}
            included = outcome is ReconcileOutcome.FINALIZED_SUCCESS
            return ReconciliationEvidence(
                schema=RECONCILIATION_SCHEMA,
                operation_id=operation.operation_id,
                outcome=outcome.value,
                finalized_head_block=120 if included else 105,
                finalized_head_hash="0x" + ("ab" if included else "ac") * 32,
                scan_start_block=query.era_birth_block,
                scan_end_block=min(
                    120 if included else 105,
                    query.era_death_block - 1,
                ),
                scan=scan,
                scan_sha256=hashlib.sha256(canonical_json_bytes(scan)).hexdigest(),
                extrinsic_hash=("0x" + operation.operation_id if included else None),
                inclusion_block=110 if included else None,
                inclusion_block_hash=("0x" + "ad" * 32 if included else None),
                **_binding(query.unsigned, query.signature),
            )

        return ExtrinsicPorts(
            prepare=prepare,
            verify_prepared_call=verify_prepared_call,
            sign=sign,
            submit=submit,
            reconcile=reconcile,
        )

    async def verify_finality(
        self,
        operation: ExtrinsicOperation,
        frozen,
        entry,
        _work: StageWorkItem,
    ) -> VerifiedAnchorFinality:
        reconciliation = entry.receipt.reconciliation
        assert reconciliation is not None
        kind = operation.request.anchor_kind
        if kind == "assignment_set":
            inclusion_round = self.plan.spec.issue_close_round - 1
            finalized_round = inclusion_round
        elif kind == "request_set":
            inclusion_round = self.plan.spec.response_close_round - 1
            finalized_round = inclusion_round
        else:
            inclusion_round = self.plan.spec.response_close_round
            finalized_round = self.plan.spec.reveal_round - 1
        finalized_round = self.finalized_round_overrides.get(kind, finalized_round)
        return VerifiedAnchorFinality(
            anchor_kind=kind,
            root=frozen.root,
            operation_id=operation.operation_id,
            inclusion_block=reconciliation.inclusion_block,
            inclusion_block_hash=reconciliation.inclusion_block_hash,
            inclusion_round=inclusion_round,
            finalized_head_block=reconciliation.finalized_head_block,
            finalized_head_hash=reconciliation.finalized_head_hash,
            finalized_round=finalized_round,
            evidence_bytes=f"finality:{kind}:{frozen.root}".encode(),
        )


def _ports(
    plan: TranscriptExecutionPlan,
    facts: FactPort,
    chain: AnchorChain,
    *,
    transport=None,
    prepare_retry=None,
    material_sha256: str = "31" * 32,
    material_receipt_sha256: str = "32" * 32,
    pool_stage_evidence_sha256: str = "33" * 32,
    anchor_ports=None,
) -> TranscriptEffectPorts:
    async def plan_port(_work: StageWorkItem) -> TranscriptExecutionMaterial:
        return TranscriptExecutionMaterial(
            plan=plan,
            material_sha256=material_sha256,
            material_receipt_sha256=material_receipt_sha256,
            pool_stage_evidence_sha256=pool_stage_evidence_sha256,
        )

    async def release(_work: StageWorkItem, _reason: str) -> int:
        return 1_500

    return TranscriptEffectPorts(
        plan=plan_port,
        observe=facts,
        anchor_ports=anchor_ports or chain.ports,
        verify_anchor=chain.verify_finality,
        audit_release_block=release,
        transport=transport,
        prepare_retry=prepare_retry,
    )


def _stores(tmp_path: Path):
    return (
        ValidatorAssignmentStore(tmp_path / "transcripts"),
        ValidatorExtrinsicJournal(tmp_path / "extrinsics"),
    )


async def _complete_effect(effect, *, operation_id: str, work: StageWorkItem):
    for _attempt in range(6):
        try:
            return await effect.perform(operation_id=operation_id, work=work)
        except TranscriptEffectPending:
            continue
    raise AssertionError("effect did not complete within the bounded fake-chain advances")


def _record_stage_result(journal: ValidatorStageJournal, result):
    return journal.record(
        window_id=result.window_id,
        stage=result.stage,
        operation_id=result.operation_id,
        objects=result.objects,
        metadata=result.metadata,
    )


def _record_transcript_prefix(
    journal: ValidatorStageJournal,
    window_id: str,
    *,
    include_assignment: bool,
) -> None:
    journal.record(
        window_id=window_id,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="stage.pool",
        objects=(StageObjectInput(b"pool-prefix", "application/octet-stream"),),
    )
    if include_assignment:
        journal.record(
            window_id=window_id,
            stage=WindowStage.ASSIGNMENT,
            operation_id="stage.assignment-prefix",
            objects=(StageObjectInput(b"assignment-prefix", "application/octet-stream"),),
        )


def _receipt_payloads(record, journal: ValidatorStageJournal) -> dict[str, bytes]:
    return {
        reference.sha256: journal.read_object(reference) for reference in record.receipt.objects
    }


def _freeze_assignments(
    store: ValidatorAssignmentStore,
    plan: TranscriptExecutionPlan,
) -> None:
    store.create_window(plan.spec)
    for assignment in plan.assignments:
        store.add_assignment(
            plan.spec.window_id,
            assignment.initial_attempt,
            observed_round=plan.spec.issue_close_round - 1,
        )
    store.freeze_assignments(
        plan.spec.window_id,
        observed_round=plan.spec.issue_close_round - 1,
    )


def _outer_invalid(prepared: PreparedRequestAttempt) -> QueryOutcome:
    return QueryOutcome(
        request=prepared.request,
        auth_headers=dict(prepared.auth_headers),
        received_at_unix_ns=None,
        envelope_bytes=None,
        envelope=None,
        response_signature=None,
        sealed_response=None,
        failure_code="transport_error",
    )


@pytest.mark.asyncio
async def test_assignment_receipt_is_self_contained_and_replays_without_store(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    effect = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
        maximum_anchor_advances=4,
    )
    result = await _complete_effect(
        effect,
        operation_id="stage.self-contained-assignment",
        work=_work(plan, WindowStage.ASSIGNMENT),
    )
    assert isinstance(result.decision, CompleteStageEffect)

    journal = ValidatorStageJournal(tmp_path / "stage-journal")
    _record_transcript_prefix(journal, plan.spec.window_id, include_assignment=False)
    record = _record_stage_result(journal, result)
    replay = replay_transcript_stage_record(record, journal)

    assert isinstance(replay, TranscriptStageReplay)
    assert replay.stage is WindowStage.ASSIGNMENT
    assert replay.root == result.metadata["anchor_root"]
    assert replay.assignment_count == 1
    assert replay.material_binding.material_sha256 == "31" * 32
    attempt = store.list_attempts(plan.assignments[0].assignment_id)[0]
    listed = {reference.sha256 for reference in record.receipt.objects}
    assert attempt.prepared_evidence_ref.sha256 in listed
    assert hashlib.sha256(attempt.prepared.request_bytes).hexdigest() in listed
    assert hashlib.sha256(canonical_json_bytes(plan.spec)).hexdigest() in listed


@pytest.mark.asyncio
async def test_request_receipt_recursively_carries_outcome_prefix_and_replays(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    prefix = b"bounded-prefix"

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return QueryOutcome(
            request=prepared.request,
            auth_headers=dict(prepared.auth_headers),
            received_at_unix_ns="123",
            envelope_bytes=None,
            envelope=None,
            response_signature=None,
            sealed_response=None,
            failure_code="resource_limit",
            received_bytes_sha256=hashlib.sha256(prefix).hexdigest(),
            received_body_prefix=prefix,
        )

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
        maximum_anchor_advances=4,
    )
    result = await _complete_effect(
        effect,
        operation_id="stage.self-contained-request",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)

    journal = ValidatorStageJournal(tmp_path / "stage-journal")
    _record_transcript_prefix(journal, plan.spec.window_id, include_assignment=True)
    record = _record_stage_result(journal, result)
    replay = replay_transcript_stage_record(record, journal)

    assert replay.stage is WindowStage.REQUEST_TRANSCRIPT
    assert replay.root == result.metadata["anchor_root"]
    assert replay.attempt_count == 1
    attempt = store.list_attempts(plan.assignments[0].assignment_id)[0]
    assert attempt.outcome_evidence_ref is not None
    assert attempt.outcome is not None and attempt.outcome.retained_body is not None
    listed = {reference.sha256 for reference in record.receipt.objects}
    assert attempt.outcome_evidence_ref.sha256 in listed
    assert attempt.outcome.retained_body.sha256 in listed
    assert (
        journal.read_object(
            next(
                reference
                for reference in record.receipt.objects
                if reference.sha256 == attempt.outcome.retained_body.sha256
            )
        )
        == prefix
    )

    response_effect = SealedResponseTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
        maximum_anchor_advances=4,
    )
    response_result = await _complete_effect(
        response_effect,
        operation_id="stage.self-contained-response",
        work=_work(plan, WindowStage.SEALED_RESPONSE),
    )
    response_record = _record_stage_result(journal, response_result)
    response_replay = replay_transcript_stage_record(response_record, journal)
    assert response_replay.stage is WindowStage.SEALED_RESPONSE
    assert response_replay.root == response_result.metadata["anchor_root"]
    assert attempt.outcome.retained_body.sha256 in {
        reference.sha256 for reference in response_record.receipt.objects
    }


@pytest.mark.asyncio
async def test_replay_fails_on_tampered_or_missing_nested_request_and_body(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    prefix = b"receipt-prefix"

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return QueryOutcome(
            request=prepared.request,
            auth_headers=dict(prepared.auth_headers),
            received_at_unix_ns="456",
            envelope_bytes=None,
            envelope=None,
            response_signature=None,
            sealed_response=None,
            failure_code="resource_limit",
            received_bytes_sha256=hashlib.sha256(prefix).hexdigest(),
            received_body_prefix=prefix,
        )

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
        maximum_anchor_advances=4,
    )
    result = await _complete_effect(
        effect,
        operation_id="stage.replay-tamper",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    journal = ValidatorStageJournal(tmp_path / "stage-journal")
    _record_transcript_prefix(journal, plan.spec.window_id, include_assignment=True)
    record = _record_stage_result(journal, result)
    payloads = _receipt_payloads(record, journal)
    attempt = store.list_attempts(plan.assignments[0].assignment_id)[0]
    prepared = json.loads(store.read_evidence(attempt.prepared_evidence_ref))
    request_digest_hex = prepared["request_object"]["sha256"]
    assert attempt.outcome is not None and attempt.outcome.retained_body is not None
    body_digest = attempt.outcome.retained_body.sha256

    for missing_digest in (request_digest_hex, body_digest):
        receipt_document = record.receipt.model_dump(mode="json", by_alias=True)
        receipt_document["objects"] = [
            item for item in receipt_document["objects"] if item["sha256"] != missing_digest
        ]
        missing_receipt = StageReceipt.model_validate(receipt_document)
        missing_payloads = {
            digest: payload for digest, payload in payloads.items() if digest != missing_digest
        }
        with pytest.raises(TranscriptReplayError, match="referenced_object_missing"):
            replay_transcript_stage_receipt(missing_receipt, missing_payloads)

    tampered_payloads = dict(payloads)
    tampered_payloads[body_digest] = b"x" * len(tampered_payloads[body_digest])
    with pytest.raises(TranscriptReplayError, match="receipt_object_digest_mismatch"):
        replay_transcript_stage_receipt(record.receipt, tampered_payloads)


@pytest.mark.asyncio
async def test_three_effects_survive_restart_without_resending_claimed_attempt(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    transport_calls = 0

    async def hanging_transport(*_args) -> QueryOutcome:
        nonlocal transport_calls
        transport_calls += 1
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    store, extrinsics = _stores(tmp_path)
    assignment = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^assignment_set_anchor_pending$",
    ):
        await assignment.perform(
            operation_id="stage.assignment",
            work=_work(plan, WindowStage.ASSIGNMENT),
        )
    attempt = store.list_attempts(plan.assignments[0].assignment_id)[0]
    assert not attempt.issued
    assert store.load_window(plan.spec.window_id).phase is TranscriptPhase.ASSIGNMENTS_FROZEN

    store, extrinsics = _stores(tmp_path)
    assignment = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    assignment_result = await assignment.perform(
        operation_id="stage.assignment",
        work=_work(plan, WindowStage.ASSIGNMENT),
    )
    assert isinstance(assignment_result.decision, CompleteStageEffect)

    request = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=hanging_transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=0.01,
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^request_set_anchor_pending$",
    ):
        await request.perform(
            operation_id="stage.request",
            work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
        )
    assert transport_calls == 1
    issued = store.list_attempts(plan.assignments[0].assignment_id)[0]
    assert issued.issued and issued.outcome is not None
    assert issued.outcome.sealed_response_record.disposition == "outer_invalid"
    assert issued.outcome.sealed_response_record.receipt_metadata["failure_code"] == (
        "transport_timeout"
    )
    assert store.load_window(plan.spec.window_id).phase is TranscriptPhase.REQUESTS_FROZEN

    store, extrinsics = _stores(tmp_path)

    async def forbidden_resend(*_args) -> QueryOutcome:
        raise AssertionError("a durable claim must not be resent")

    request = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=forbidden_resend),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    request_result = await request.perform(
        operation_id="stage.request",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(request_result.decision, CompleteStageEffect)
    assert transport_calls == 1

    response = SealedResponseTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^response_set_anchor_pending$",
    ):
        await response.perform(
            operation_id="stage.response",
            work=_work(plan, WindowStage.SEALED_RESPONSE),
        )
    outcome = store.list_attempts(plan.assignments[0].assignment_id)[0].outcome
    assert outcome is not None
    assert outcome.sealed_response_record.disposition == "outer_invalid"

    store, extrinsics = _stores(tmp_path)
    response = SealedResponseTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    response_result = await response.perform(
        operation_id="stage.response",
        work=_work(plan, WindowStage.SEALED_RESPONSE),
    )
    assert isinstance(response_result.decision, CompleteStageEffect)
    assert store.load_window(plan.spec.window_id).phase is TranscriptPhase.RESPONSES_FROZEN
    assert [operation.operation for operation in chain.prepared_operations] == [
        "assignment_anchor",
        "request_anchor",
        "response_anchor",
    ]
    assert all(
        operation.request.call == "Commitments.set_commitment" and operation.request.netuid == 78
        for operation in chain.prepared_operations
    )


@pytest.mark.asyncio
async def test_request_issuance_starts_concurrently_and_honors_bound(
    tmp_path: Path,
) -> None:
    plan = _execution_plan(assignment_count=6)
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    entered_bound = asyncio.Event()
    release = asyncio.Event()
    active = 0
    maximum_active = 0
    calls = 0

    async def blocking_transport(
        prepared: PreparedRequestAttempt,
        *_args,
    ) -> QueryOutcome:
        nonlocal active, maximum_active, calls
        calls += 1
        active += 1
        maximum_active = max(maximum_active, active)
        if active == 2:
            entered_bound.set()
        try:
            await release.wait()
            return _outer_invalid(prepared)
        finally:
            active -= 1

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=blocking_transport),
        maximum_transport_concurrency=2,
        transport_timeout_seconds=1,
    )
    task = asyncio.create_task(
        effect.perform(
            operation_id="stage.concurrent-request",
            work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
        )
    )
    await asyncio.wait_for(entered_bound.wait(), timeout=1)
    assert calls == 2
    assert maximum_active == 2
    assert (
        sum(
            store.list_attempts(assignment.assignment_id)[0].issued
            for assignment in plan.assignments
        )
        == 2
    )
    release.set()
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^request_set_anchor_pending$",
    ):
        await asyncio.wait_for(task, timeout=2)
    assert calls == len(plan.assignments)
    assert maximum_active == 2
    assert all(
        store.list_attempts(assignment.assignment_id)[0].issued for assignment in plan.assignments
    )


@pytest.mark.asyncio
async def test_request_stage_never_opens_anchor_after_response_close(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    facts.overrides["request_freeze"] = plan.spec.response_close_round
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return _outer_invalid(prepared)

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    result = await effect.perform(
        operation_id="stage.late-request-freeze",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert result.metadata["transcript_abort_reason_code"] == ("request_freeze_deadline_missed")
    assert chain.anchor_port_calls == []
    assert store.load_window(plan.spec.window_id).phase is TranscriptPhase.ASSIGNMENTS_FROZEN


@pytest.mark.asyncio
async def test_frozen_request_root_cannot_be_submitted_after_close(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    facts.overrides["request_stage"] = plan.spec.response_close_round
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    assignment = plan.assignments[0]
    store.claim_for_send(
        assignment.assignment_id,
        0,
        operation_id="manual.send",
        observed_round=plan.spec.issue_close_round - 1,
    )
    store.freeze_requests(
        plan.spec.window_id,
        observed_round=plan.spec.response_close_round - 1,
    )

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    result = await effect.perform(
        operation_id="stage.closed-anchor",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert result.metadata["transcript_abort_reason_code"] == (
        "request_anchor_submission_deadline_missed"
    )
    assert chain.anchor_port_calls == []
    assert chain.submit_calls == []


@pytest.mark.asyncio
async def test_request_anchor_rechecks_boundary_at_actual_submit(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    facts.overrides["request_set_anchor_submit"] = plan.spec.response_close_round
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return _outer_invalid(prepared)

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    result = await effect.perform(
        operation_id="stage.submit-race",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert result.metadata["transcript_abort_reason_code"] == (
        "request_anchor_submission_deadline_missed"
    )
    assert chain.prepared_operations[0].operation == "request_anchor"
    assert chain.submit_calls == []


@pytest.mark.asyncio
async def test_request_retries_use_fresh_auth_and_stop_at_policy_ceiling(
    tmp_path: Path,
) -> None:
    plan = _execution_plan(transmissions=2)
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    transport_calls = 0

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        nonlocal transport_calls
        transport_calls += 1
        return _outer_invalid(prepared)

    async def retry(
        assignment: TranscriptAssignment,
        _previous,
        next_attempt_index: int,
        _work: StageWorkItem,
    ) -> PreparedRequestAttempt:
        assert next_attempt_index == 1
        return prepare_request_attempt(
            assignment.initial_attempt.request,
            wallet=VALIDATOR_WALLET,
            miner_hotkey=MINER,
            nonce_ns=9_000,
        )

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(
            plan,
            facts,
            chain,
            transport=transport,
            prepare_retry=retry,
        ),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^request_set_anchor_pending$",
    ):
        await effect.perform(
            operation_id="stage.retry-request",
            work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
        )
    attempts = store.list_attempts(plan.assignments[0].assignment_id)
    assert transport_calls == 2
    assert len(attempts) == 2
    assert all(attempt.issued for attempt in attempts)
    assert [attempt.prepared.auth_evidence.auth_record.nonce_int for attempt in attempts] == [
        1_001,
        9_000,
    ]


@pytest.mark.asyncio
async def test_submitted_assignment_anchor_can_reconcile_after_issue_close(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    effect = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^assignment_set_anchor_pending$",
    ):
        await effect.perform(
            operation_id="stage.assignment-reconcile",
            work=_work(plan, WindowStage.ASSIGNMENT),
        )
    assert chain.submit_calls == ["assignment_anchor"]

    facts.overrides["assignment_freeze"] = plan.spec.issue_close_round + 1
    restarted = AssignmentTranscriptEffect(
        assignments=ValidatorAssignmentStore(tmp_path / "transcripts"),
        extrinsics=ValidatorExtrinsicJournal(tmp_path / "extrinsics"),
        ports=_ports(plan, facts, chain),
    )
    result = await restarted.perform(
        operation_id="stage.assignment-reconcile",
        work=_work(plan, WindowStage.ASSIGNMENT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert chain.submit_calls == ["assignment_anchor"]


@pytest.mark.asyncio
async def test_response_effect_waits_for_close_without_writing_missing(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    facts.overrides["response_freeze"] = plan.spec.response_close_round - 1
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    assignment = plan.assignments[0]
    store.claim_for_send(
        assignment.assignment_id,
        0,
        operation_id="manual.send",
        observed_round=plan.spec.issue_close_round - 1,
    )
    store.freeze_requests(
        plan.spec.window_id,
        observed_round=plan.spec.response_close_round - 1,
    )
    effect = SealedResponseTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    with pytest.raises(TranscriptEffectPending, match=r"^response_close_pending$"):
        await effect.perform(
            operation_id="stage.early-response",
            work=_work(plan, WindowStage.SEALED_RESPONSE),
        )
    assert store.list_attempts(assignment.assignment_id)[0].outcome is None
    assert chain.anchor_port_calls == []


@pytest.mark.asyncio
async def test_crash_after_claim_before_transport_skips_without_request_anchor(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    assignment = plan.assignments[0]
    store.claim_for_send(
        assignment.assignment_id,
        0,
        operation_id="send.crashed-process",
        observed_round=plan.spec.issue_close_round - 1,
    )

    async def forbidden_transport(*_args) -> QueryOutcome:
        raise AssertionError("orphaned claims must never be resent")

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=forbidden_transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    result = await effect.perform(
        operation_id="stage.crash-recovery",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert result.metadata["transcript_abort_reason_code"] == "issuance_outcome_unknown"
    assert chain.anchor_port_calls == []
    assert store.load_window(plan.spec.window_id).phase is TranscriptPhase.ASSIGNMENTS_FROZEN


@pytest.mark.asyncio
async def test_two_adapter_instances_cannot_freeze_while_transport_in_flight(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    first_store, first_extrinsics = _stores(tmp_path)
    _freeze_assignments(first_store, plan)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocking_transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        entered.set()
        await release.wait()
        return _outer_invalid(prepared)

    first = RequestTranscriptEffect(
        assignments=first_store,
        extrinsics=first_extrinsics,
        ports=_ports(plan, facts, chain, transport=blocking_transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=2,
    )
    first_task = asyncio.create_task(
        first.perform(
            operation_id="stage.first-owner",
            work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)

    second = RequestTranscriptEffect(
        assignments=ValidatorAssignmentStore(tmp_path / "transcripts"),
        extrinsics=ValidatorExtrinsicJournal(tmp_path / "extrinsics"),
        ports=_ports(plan, facts, chain, transport=blocking_transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=2,
    )
    with pytest.raises(TranscriptEffectPending, match=r"^request_stage_lease_pending$"):
        await second.perform(
            operation_id="stage.second-owner",
            work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
        )
    assert first_store.load_window(plan.spec.window_id).phase is (
        TranscriptPhase.ASSIGNMENTS_FROZEN
    )
    assert chain.anchor_port_calls == []

    release.set()
    with pytest.raises(TranscriptEffectPending, match=r"^request_set_anchor_pending$"):
        await asyncio.wait_for(first_task, timeout=2)


@pytest.mark.asyncio
@pytest.mark.parametrize("changed_field", ["origin", "limits"])
async def test_changed_origin_or_limits_cannot_replace_bound_window_material(
    tmp_path: Path,
    changed_field: str,
) -> None:
    original = _execution_plan()
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, original)
    store.bind_window_material(
        original.spec.window_id,
        TranscriptMaterialBinding(
            material_sha256="31" * 32,
            material_receipt_sha256="32" * 32,
            pool_stage_evidence_sha256="33" * 32,
        ),
    )
    if changed_field == "origin":
        changed_assignments = tuple(
            TranscriptAssignment(
                assignment.initial_attempt,
                assignment.miner_url + ":8443",
            )
            for assignment in original.assignments
        )
        changed = TranscriptExecutionPlan(original.spec, changed_assignments)
    else:
        changed = TranscriptExecutionPlan(
            original.spec.model_copy(update={"maximum_retained_prefix_bytes": 32}),
            original.assignments,
        )
    facts = FactPort(changed)
    chain = AnchorChain(changed)

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return _outer_invalid(prepared)

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(
            changed,
            facts,
            chain,
            transport=transport,
            material_sha256="41" * 32,
            material_receipt_sha256="42" * 32,
        ),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    result = await effect.perform(
        operation_id=f"stage.changed-{changed_field}",
        work=_work(changed, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert result.metadata["transcript_abort_reason_code"] == "request_transcript_fault"
    assert chain.anchor_port_calls == []


@pytest.mark.asyncio
async def test_request_policy_hash_must_match_work_policy(tmp_path: Path) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)
    work = _work(plan, WindowStage.REQUEST_TRANSCRIPT)
    work = replace(
        work,
        window=replace(
            work.window,
            plan=replace(work.window.plan, scoring_policy_hash="ef" * 32),
        ),
    )

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return _outer_invalid(prepared)

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
    )
    with pytest.raises(TranscriptEffectBindingError, match="scoring policy"):
        await effect.perform(operation_id="stage.policy-mismatch", work=work)
    assert chain.anchor_port_calls == []


@pytest.mark.asyncio
async def test_request_anchor_included_before_close_may_finalize_after_close(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    chain.finalized_round_overrides["request_set"] = plan.spec.response_close_round
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)

    async def transport(prepared: PreparedRequestAttempt, *_args) -> QueryOutcome:
        return _outer_invalid(prepared)

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=1,
        maximum_anchor_advances=4,
    )
    result = await effect.perform(
        operation_id="stage.request-finality-after-close",
        work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
    )
    assert isinstance(result.decision, CompleteStageEffect)
    assert result.metadata["inclusion_round"] == plan.spec.response_close_round - 1
    assert result.metadata["finalized_round"] == plan.spec.response_close_round


@pytest.mark.asyncio
async def test_real_oversized_send_preserves_resource_limit_prefix_in_transcript(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store, extrinsics = _stores(tmp_path)
    _freeze_assignments(store, plan)

    class OneChunkStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 100

        async def aclose(self) -> None:
            return None

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-UMI-Signature": "0x" + "00" * 64},
            stream=OneChunkStream(),
        )

    async def transport(
        prepared: PreparedRequestAttempt,
        assignment_id: str,
        miner_url: str,
        _work: StageWorkItem,
    ) -> QueryOutcome:
        return await send_prepared_request(
            prepared,
            miner_url=miner_url,
            limits=Limits(maximum_response_body_bytes=10),
            timeout_seconds=1,
            transport=httpx.MockTransport(handler),
            assignment_id=assignment_id,
        )

    effect = RequestTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, transport=transport),
        maximum_transport_concurrency=1,
        transport_timeout_seconds=2,
    )
    with pytest.raises(TranscriptEffectPending, match=r"^request_set_anchor_pending$"):
        await effect.perform(
            operation_id="stage.oversized-response",
            work=_work(plan, WindowStage.REQUEST_TRANSCRIPT),
        )
    attempt = store.list_attempts(plan.assignments[0].assignment_id)[0]
    assert attempt.outcome is not None
    assert attempt.outcome.sealed_response_record.disposition == "resource_limit"
    assert attempt.outcome.retained_body is not None
    assert store.read_evidence(attempt.outcome.retained_body) == b"x" * 10


@pytest.mark.asyncio
async def test_prepare_timeout_is_pending_and_pollable_recovery_succeeds(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store = ValidatorAssignmentStore(tmp_path / "transcripts")
    extrinsics = ValidatorExtrinsicJournal(
        tmp_path / "extrinsics",
        port_timeout_seconds=0.01,
    )

    def hanging_anchor_ports(operation: ExtrinsicOperation, work: StageWorkItem):
        ports = chain.ports(operation, work)

        async def prepare(_operation: ExtrinsicOperation) -> UnsignedExtrinsic:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        return replace(ports, prepare=prepare)

    timed_out = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, anchor_ports=hanging_anchor_ports),
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^assignment_set_anchor_port_pending$",
    ):
        await timed_out.perform(
            operation_id="stage.prepare-timeout",
            work=_work(plan, WindowStage.ASSIGNMENT),
        )
    assert store.load_window(plan.spec.window_id).phase is TranscriptPhase.ASSIGNMENTS_FROZEN

    recovered = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
        maximum_anchor_advances=4,
    )
    result = await recovered.perform(
        operation_id="stage.prepare-timeout",
        work=_work(plan, WindowStage.ASSIGNMENT),
    )
    assert isinstance(result.decision, CompleteStageEffect)


@pytest.mark.asyncio
async def test_reconcile_timeout_preserves_submitted_anchor_for_later_poll(
    tmp_path: Path,
) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    store = ValidatorAssignmentStore(tmp_path / "transcripts")
    extrinsics = ValidatorExtrinsicJournal(
        tmp_path / "extrinsics",
        port_timeout_seconds=0.01,
    )
    initial = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    with pytest.raises(TranscriptEffectPending, match=r"^assignment_set_anchor_pending$"):
        await initial.perform(
            operation_id="stage.reconcile-timeout",
            work=_work(plan, WindowStage.ASSIGNMENT),
        )
    operation = chain.prepared_operations[0]
    assert extrinsics.load(operation).state.value == "submitted"

    def hanging_anchor_ports(requested: ExtrinsicOperation, work: StageWorkItem):
        ports = chain.ports(requested, work)

        async def reconcile(_query: ReconcileQuery) -> ReconciliationEvidence:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        return replace(ports, reconcile=reconcile)

    timed_out = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, anchor_ports=hanging_anchor_ports),
    )
    with pytest.raises(
        TranscriptEffectPending,
        match=r"^assignment_set_anchor_port_pending$",
    ):
        await timed_out.perform(
            operation_id="stage.reconcile-timeout",
            work=_work(plan, WindowStage.ASSIGNMENT),
        )
    assert extrinsics.load(operation).state.value == "submitted"

    recovered = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain),
    )
    result = await recovered.perform(
        operation_id="stage.reconcile-timeout",
        work=_work(plan, WindowStage.ASSIGNMENT),
    )
    assert isinstance(result.decision, CompleteStageEffect)


def test_sync_transport_is_rejected_before_it_can_block() -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    called = False

    def sync_transport(*_args) -> QueryOutcome:
        nonlocal called
        called = True
        raise AssertionError("sync transport must never run")

    with pytest.raises(TypeError, match="transport port must be an async callable"):
        _ports(plan, facts, chain, transport=sync_transport)
    assert not called


@pytest.mark.asyncio
async def test_sync_guarded_submit_is_rejected_before_it_can_block(tmp_path: Path) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    called = False

    def sync_anchor_ports(operation: ExtrinsicOperation, work: StageWorkItem):
        ports = chain.ports(operation, work)

        def submit(_unsigned: UnsignedExtrinsic, _signature: bytes) -> SubmissionEvidence:
            nonlocal called
            called = True
            raise AssertionError("sync submit must never run")

        return replace(ports, submit=submit)

    store, extrinsics = _stores(tmp_path)
    effect = AssignmentTranscriptEffect(
        assignments=store,
        extrinsics=extrinsics,
        ports=_ports(plan, facts, chain, anchor_ports=sync_anchor_ports),
    )
    with pytest.raises(TranscriptEffectBindingError, match="submit port must be an async"):
        await effect.perform(
            operation_id="stage.sync-submit",
            work=_work(plan, WindowStage.ASSIGNMENT),
        )
    assert not called


def test_transport_resource_bounds_are_closed(tmp_path: Path) -> None:
    plan = _execution_plan()
    facts = FactPort(plan)
    chain = AnchorChain(plan)
    with pytest.raises(ValueError, match="maximum_transport_concurrency"):
        RequestTranscriptEffect(
            assignments=ValidatorAssignmentStore(tmp_path / "transcripts"),
            extrinsics=ValidatorExtrinsicJournal(tmp_path / "extrinsics"),
            ports=_ports(plan, facts, chain),
            maximum_transport_concurrency=0,
            transport_timeout_seconds=1,
        )
