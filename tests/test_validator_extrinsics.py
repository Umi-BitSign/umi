from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from pathlib import Path

import pytest
from bittensor import UnsignedExtrinsic

from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_extrinsics import (
    ANCHOR_INTENT_SCHEMA,
    OPERATION_SCHEMA,
    PREPARED_CALL_SCHEMA,
    RECONCILIATION_SCHEMA,
    SUBMISSION_SCHEMA,
    ExtrinsicJournalConflict,
    ExtrinsicJournalError,
    ExtrinsicOperation,
    ExtrinsicPorts,
    ExtrinsicPortTimeout,
    ExtrinsicState,
    PreparedCallEvidence,
    ReconcileOutcome,
    ReconcileQuery,
    ReconciliationEvidence,
    SubmissionEvidence,
    ValidatorExtrinsicJournal,
    mortal_era_bounds,
)

WINDOW_ID = "11" * 32
FINALIZED_HASH = "0x" + "22" * 32
INCLUSION_HASH = "0x" + "33" * 32
EXTRINSIC_HASH = "0x" + "44" * 32
OTHER_EXTRINSIC_HASH = "0x" + "55" * 32
SIGNATURE = b"s" * 64


def _operation(*, request_value: int = 1) -> ExtrinsicOperation:
    field_sha256 = request_value.to_bytes(32, "big").hex()
    return ExtrinsicOperation(
        schema=OPERATION_SCHEMA,
        protocol=PROTOCOL_VERSION,
        operation="assignment_anchor",
        window_id=WINDOW_ID,
        validator_hotkey="5Validator",
        request={
            "schema": ANCHOR_INTENT_SCHEMA,
            "call": "Commitments.set_commitment",
            "netuid": 78,
            "anchor_kind": "assignment_set",
            "field": {"type": "Data::Sha256", "sha256": field_sha256},
        },
    )


def _unsigned(*, payload: bytes = b"exact signing payload") -> UnsignedExtrinsic:
    return UnsignedExtrinsic(
        call_data=b"\x01\x02\x03",
        address="5Validator",
        public_key=b"p" * 32,
        crypto_type=1,
        era={"period": 64, "current": 100},
        nonce=7,
        tip=0,
        tip_asset_id=None,
        genesis_hash="0x" + "77" * 32,
        era_block_hash="0x" + "88" * 32,
        spec_version=449,
        transaction_version=1,
        metadata_hash=None,
        payload=payload,
        payload_json={"method": "0x010203", "nonce": "0x00000007"},
        included_in_extrinsic=b"included",
        included_in_signed_data=b"signed",
    )


def _binding(unsigned: UnsignedExtrinsic, signature: bytes) -> dict[str, str]:
    record_bytes = canonical_json_bytes(unsigned.to_dict())
    return {
        "unsigned_record_sha256": hashlib.sha256(record_bytes).hexdigest(),
        "payload_sha256": hashlib.sha256(unsigned.payload).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }


def _prepared_call(
    operation: ExtrinsicOperation,
    unsigned: UnsignedExtrinsic,
    **changes: object,
) -> PreparedCallEvidence:
    values: dict[str, object] = {
        "schema": PREPARED_CALL_SCHEMA,
        "operation_id": operation.operation_id,
        "call_data_sha256": hashlib.sha256(unsigned.call_data).hexdigest(),
        "call_data_size_bytes": len(unsigned.call_data),
        "module": "Commitments",
        "function": "set_commitment",
        "netuid": 78,
        "anchor_kind": operation.request.anchor_kind,
        "field_sha256": operation.request.field.sha256,
        "runtime_spec_version": unsigned.spec_version,
        "transaction_version": unsigned.transaction_version,
        "runtime_metadata_sha256": "99" * 32,
    }
    values.update(changes)
    return PreparedCallEvidence.model_validate(values)


def _scan_fields(label: str) -> dict[str, object]:
    scan = {"decoder": "test-finalized-scan/1", "label": label}
    return {
        "scan": scan,
        "scan_sha256": hashlib.sha256(canonical_json_bytes(scan)).hexdigest(),
    }


class FakePorts:
    def __init__(self, outcomes: tuple[ReconcileOutcome, ...]) -> None:
        self.unsigned = _unsigned()
        self.outcomes = deque(outcomes)
        self.prepare_calls = 0
        self.sign_calls = 0
        self.submit_calls = 0
        self.reconcile_calls = 0
        self.signed_payloads: list[bytes] = []
        self.submitted_records: list[dict] = []
        self.submitted_signatures: list[bytes] = []
        self.submit_error = False

    async def prepare(self, operation: ExtrinsicOperation) -> UnsignedExtrinsic:
        assert operation == _operation()
        self.prepare_calls += 1
        return self.unsigned

    async def verify_prepared_call(
        self,
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
    ) -> PreparedCallEvidence:
        return _prepared_call(operation, unsigned)

    async def sign(self, payload: bytes, operation_id: str) -> bytes:
        assert operation_id == _operation().operation_id
        self.sign_calls += 1
        self.signed_payloads.append(payload)
        return SIGNATURE

    async def submit(
        self,
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> SubmissionEvidence:
        self.submit_calls += 1
        self.submitted_records.append(unsigned.to_dict())
        self.submitted_signatures.append(signature)
        if self.submit_error:
            raise ConnectionError("ambiguous transport failure")
        return SubmissionEvidence(
            schema=SUBMISSION_SCHEMA,
            operation_id=_operation().operation_id,
            extrinsic_hash=EXTRINSIC_HASH,
            **_binding(unsigned, signature),
        )

    async def reconcile(self, query: ReconcileQuery) -> ReconciliationEvidence:
        self.reconcile_calls += 1
        outcome = self.outcomes.popleft()
        extrinsic_hash = query.expected_extrinsic_hash
        inclusion_block = None
        inclusion_hash = None
        if outcome in {
            ReconcileOutcome.FINALIZED_SUCCESS,
            ReconcileOutcome.FINALIZED_FAILURE,
        }:
            extrinsic_hash = extrinsic_hash or EXTRINSIC_HASH
            inclusion_block = 120
            inclusion_hash = INCLUSION_HASH
        return ReconciliationEvidence(
            schema=RECONCILIATION_SCHEMA,
            operation_id=query.operation.operation_id,
            outcome=outcome.value,
            finalized_head_block=130,
            finalized_head_hash=FINALIZED_HASH,
            scan_start_block=query.era_birth_block,
            scan_end_block=min(130, query.era_death_block - 1),
            extrinsic_hash=extrinsic_hash,
            inclusion_block=inclusion_block,
            inclusion_block_hash=inclusion_hash,
            **_scan_fields(outcome.value),
            **_binding(query.unsigned, query.signature),
        )

    def bundle(self, *, derive_hash: bool = False) -> ExtrinsicPorts:
        async def derive(unsigned: UnsignedExtrinsic, signature: bytes) -> str:
            assert unsigned.to_dict() == self.unsigned.to_dict()
            assert signature == SIGNATURE
            return EXTRINSIC_HASH

        return ExtrinsicPorts(
            prepare=self.prepare,
            verify_prepared_call=self.verify_prepared_call,
            sign=self.sign,
            submit=self.submit,
            reconcile=self.reconcile,
            derive_signed_hash=derive if derive_hash else None,
        )


async def _prepare_and_sign(
    journal: ValidatorExtrinsicJournal,
    fake: FakePorts,
    *,
    derive_hash: bool = False,
) -> None:
    assert (await journal.advance(_operation(), fake.bundle(derive_hash=derive_hash))).state is (
        ExtrinsicState.PREPARED
    )
    assert (await journal.advance(_operation(), fake.bundle(derive_hash=derive_hash))).state is (
        ExtrinsicState.SIGNED
    )


async def test_complete_lifecycle_uses_exact_sdk_payload_and_persisted_material(
    tmp_path: Path,
) -> None:
    root = tmp_path / "journal"
    fake = FakePorts(
        (
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.FINALIZED_SUCCESS,
        )
    )
    journal = ValidatorExtrinsicJournal(root)

    await _prepare_and_sign(journal, fake)
    submitted = await journal.advance(_operation(), fake.bundle())
    finalized = await journal.advance(_operation(), fake.bundle())

    assert submitted.state is ExtrinsicState.SUBMITTED
    assert finalized.state is ExtrinsicState.FINALIZED_SUCCESS
    assert fake.signed_payloads == [fake.unsigned.payload]
    assert fake.submitted_records == [fake.unsigned.to_dict()]
    assert fake.submitted_signatures == [SIGNATURE]
    assert (fake.prepare_calls, fake.sign_calls, fake.submit_calls, fake.reconcile_calls) == (
        1,
        1,
        1,
        2,
    )
    assert [entry.state for entry in journal.history(_operation())] == [
        ExtrinsicState.PREPARED,
        ExtrinsicState.SIGNED,
        ExtrinsicState.SIGNED,
        ExtrinsicState.SUBMITTED,
        ExtrinsicState.FINALIZED_SUCCESS,
    ]
    assert all(
        entry.path.name == f"{entry.receipt_sha256}.json" for entry in journal.history(_operation())
    )

    restarted = ValidatorExtrinsicJournal(root)
    terminal = await restarted.advance(_operation(), fake.bundle())
    assert terminal.state is ExtrinsicState.FINALIZED_SUCCESS
    assert fake.submit_calls == 1


async def test_restart_after_sign_never_prepares_or_signs_again(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))
    journal = ValidatorExtrinsicJournal(root)
    await _prepare_and_sign(journal, fake)

    restarted = ValidatorExtrinsicJournal(root)
    submitted = await restarted.advance(_operation(), fake.bundle())

    assert submitted.state is ExtrinsicState.SUBMITTED
    assert fake.prepare_calls == 1
    assert fake.sign_calls == 1
    assert fake.submit_calls == 1
    assert fake.submitted_records == [fake.unsigned.to_dict()]
    assert fake.submitted_signatures == [SIGNATURE]


async def test_same_process_concurrent_advances_do_not_block_the_event_loop(
    tmp_path: Path,
) -> None:
    fake = FakePorts(())
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_prepare(operation: ExtrinsicOperation) -> UnsignedExtrinsic:
        fake.prepare_calls += 1
        entered.set()
        await release.wait()
        return fake.unsigned

    ports = fake.bundle()
    ports = ExtrinsicPorts(
        prepare=slow_prepare,
        verify_prepared_call=ports.verify_prepared_call,
        sign=ports.sign,
        submit=ports.submit,
        reconcile=ports.reconcile,
    )
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    first = asyncio.create_task(journal.advance(_operation(), ports))
    await asyncio.wait_for(entered.wait(), timeout=1)
    second = asyncio.create_task(journal.advance(_operation(), ports))

    # If the second coroutine entered blocking flock, this timer could not run.
    await asyncio.wait_for(asyncio.sleep(0.01), timeout=1)
    release.set()
    results = await asyncio.wait_for(asyncio.gather(first, second), timeout=1)

    assert [entry.state for entry in results] == [
        ExtrinsicState.PREPARED,
        ExtrinsicState.SIGNED,
    ]
    assert fake.prepare_calls == 1
    assert fake.sign_calls == 1


@pytest.mark.parametrize("timeout", [0, -1, True, 301, float("inf"), float("nan")])
def test_port_timeout_must_be_finite_positive_and_bounded(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ValueError, match="port timeout"):
        ValidatorExtrinsicJournal(
            tmp_path / str(timeout),
            port_timeout_seconds=timeout,  # type: ignore[arg-type]
        )


async def test_prepare_timeout_leaves_no_signable_receipt(tmp_path: Path) -> None:
    fake = FakePorts(())
    never = asyncio.Event()

    async def hanging_prepare(operation: ExtrinsicOperation) -> UnsignedExtrinsic:
        await never.wait()
        return fake.unsigned

    base = fake.bundle()
    ports = ExtrinsicPorts(
        prepare=hanging_prepare,
        verify_prepared_call=base.verify_prepared_call,
        sign=base.sign,
        submit=base.submit,
        reconcile=base.reconcile,
    )
    journal = ValidatorExtrinsicJournal(
        tmp_path / "prepare-timeout",
        port_timeout_seconds=0.01,
    )
    with pytest.raises(ExtrinsicPortTimeout, match="prepare port"):
        await journal.advance(_operation(), ports)
    assert journal.load(_operation()) is None
    assert fake.sign_calls == 0


async def test_reconcile_timeout_does_not_mutate_or_submit(tmp_path: Path) -> None:
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(
        tmp_path / "reconcile-timeout",
        port_timeout_seconds=0.01,
    )
    await _prepare_and_sign(journal, fake)
    history_length = len(journal.history(_operation()))
    never = asyncio.Event()

    async def hanging_reconcile(query: ReconcileQuery) -> ReconciliationEvidence:
        await never.wait()
        raise AssertionError("unreachable")

    base = fake.bundle()
    ports = ExtrinsicPorts(
        prepare=base.prepare,
        verify_prepared_call=base.verify_prepared_call,
        sign=base.sign,
        submit=base.submit,
        reconcile=hanging_reconcile,
    )
    with pytest.raises(ExtrinsicPortTimeout, match="reconcile port"):
        await journal.advance(_operation(), ports)
    assert len(journal.history(_operation())) == history_length
    assert fake.submit_calls == 0


async def test_submit_timeout_is_durable_unknown_and_never_rebroadcast(
    tmp_path: Path,
) -> None:
    fake = FakePorts(
        (
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.FINALIZED_FAILURE,
        )
    )
    journal = ValidatorExtrinsicJournal(
        tmp_path / "submit-timeout",
        port_timeout_seconds=0.01,
    )
    await _prepare_and_sign(journal, fake)
    never = asyncio.Event()
    submit_calls = 0

    async def hanging_submit(
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> SubmissionEvidence:
        nonlocal submit_calls
        submit_calls += 1
        await never.wait()
        raise AssertionError("unreachable")

    base = fake.bundle()
    ports = ExtrinsicPorts(
        prepare=base.prepare,
        verify_prepared_call=base.verify_prepared_call,
        sign=base.sign,
        submit=hanging_submit,
        reconcile=base.reconcile,
    )
    ambiguous = await journal.advance(_operation(), ports)
    assert ambiguous.state is ExtrinsicState.UNKNOWN
    assert ambiguous.receipt.reason_code == "submit_outcome_unknown"
    history_length = len(journal.history(_operation()))

    pending = await journal.advance(_operation(), ports)
    assert pending.receipt_sha256 == ambiguous.receipt_sha256
    assert len(journal.history(_operation())) == history_length
    assert submit_calls == 1

    terminal = await journal.advance(_operation(), ports)
    assert terminal.state is ExtrinsicState.FINALIZED_FAILURE
    assert submit_calls == 1


async def test_crash_after_broadcast_reconciles_before_any_rebroadcast(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    fake = FakePorts(
        (
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.FINALIZED_SUCCESS,
        )
    )

    class SimulatedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_submit_return_before_receipt":
            raise SimulatedCrash

    journal = ValidatorExtrinsicJournal(root, crash_hook=crash)
    await _prepare_and_sign(journal, fake)
    with pytest.raises(SimulatedCrash):
        await journal.advance(_operation(), fake.bundle())
    assert fake.submit_calls == 1
    assert ValidatorExtrinsicJournal(root).load(_operation()).state is ExtrinsicState.SIGNED

    restarted = ValidatorExtrinsicJournal(root)
    terminal = await restarted.advance(_operation(), fake.bundle())
    assert terminal.state is ExtrinsicState.FINALIZED_SUCCESS
    assert fake.reconcile_calls == 2
    assert fake.submit_calls == 1
    assert fake.sign_calls == 1


async def test_restart_reuses_unsigned_after_prepared_receipt_crash(tmp_path: Path) -> None:
    root = tmp_path / "prepared"
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))

    class SimulatedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_prepared_receipt":
            raise SimulatedCrash

    journal = ValidatorExtrinsicJournal(root, crash_hook=crash)
    with pytest.raises(SimulatedCrash):
        await journal.advance(_operation(), fake.bundle())

    restarted = ValidatorExtrinsicJournal(root)
    assert restarted.load(_operation()).state is ExtrinsicState.PREPARED
    assert (await restarted.advance(_operation(), fake.bundle())).state is ExtrinsicState.SIGNED
    assert fake.prepare_calls == 1
    assert fake.sign_calls == 1


async def test_restart_reuses_signature_after_signed_receipt_crash(tmp_path: Path) -> None:
    root = tmp_path / "signed"
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))

    class SimulatedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_signed_receipt":
            raise SimulatedCrash

    journal = ValidatorExtrinsicJournal(root, crash_hook=crash)
    assert (await journal.advance(_operation(), fake.bundle())).state is ExtrinsicState.PREPARED
    with pytest.raises(SimulatedCrash):
        await journal.advance(_operation(), fake.bundle())

    restarted = ValidatorExtrinsicJournal(root)
    assert restarted.load(_operation()).state is ExtrinsicState.SIGNED
    assert (await restarted.advance(_operation(), fake.bundle())).state is (
        ExtrinsicState.SUBMITTED
    )
    assert fake.prepare_calls == 1
    assert fake.sign_calls == 1


async def test_crash_after_reconciliation_reconciles_again_before_submit(tmp_path: Path) -> None:
    root = tmp_path / "reconciled"
    fake = FakePorts((ReconcileOutcome.NOT_FOUND, ReconcileOutcome.NOT_FOUND))

    class SimulatedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_reconciliation_receipt":
            raise SimulatedCrash

    journal = ValidatorExtrinsicJournal(root, crash_hook=crash)
    await _prepare_and_sign(journal, fake)
    with pytest.raises(SimulatedCrash):
        await journal.advance(_operation(), fake.bundle())
    assert fake.submit_calls == 0

    restarted = ValidatorExtrinsicJournal(root)
    submitted = await restarted.advance(_operation(), fake.bundle())
    assert submitted.state is ExtrinsicState.SUBMITTED
    assert fake.reconcile_calls == 2
    assert fake.submit_calls == 1


async def test_crash_after_submitted_receipt_does_not_rebroadcast_finalized_call(
    tmp_path: Path,
) -> None:
    root = tmp_path / "submitted"
    fake = FakePorts(
        (
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.FINALIZED_SUCCESS,
        )
    )

    class SimulatedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_submitted_receipt":
            raise SimulatedCrash

    journal = ValidatorExtrinsicJournal(root, crash_hook=crash)
    await _prepare_and_sign(journal, fake)
    with pytest.raises(SimulatedCrash):
        await journal.advance(_operation(), fake.bundle())
    assert ValidatorExtrinsicJournal(root).load(_operation()).state is (ExtrinsicState.SUBMITTED)

    restarted = ValidatorExtrinsicJournal(root)
    assert (await restarted.advance(_operation(), fake.bundle())).state is (
        ExtrinsicState.FINALIZED_SUCCESS
    )
    assert fake.submit_calls == 1


async def test_not_found_after_submit_polls_without_receipt_growth_or_rebroadcast(
    tmp_path: Path,
) -> None:
    fake = FakePorts(
        (
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.NOT_FOUND,
            ReconcileOutcome.FINALIZED_FAILURE,
        )
    )
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    await _prepare_and_sign(journal, fake)

    assert (await journal.advance(_operation(), fake.bundle())).state is ExtrinsicState.SUBMITTED
    assert (await journal.advance(_operation(), fake.bundle())).state is ExtrinsicState.SUBMITTED
    assert (await journal.advance(_operation(), fake.bundle())).state is (
        ExtrinsicState.FINALIZED_FAILURE
    )
    assert fake.reconcile_calls == 3
    assert fake.submit_calls == 1
    assert fake.submitted_records == [fake.unsigned.to_dict()]
    assert fake.submitted_signatures == [SIGNATURE]
    assert [entry.state for entry in journal.history(_operation())] == [
        ExtrinsicState.PREPARED,
        ExtrinsicState.SIGNED,
        ExtrinsicState.SIGNED,
        ExtrinsicState.SUBMITTED,
        ExtrinsicState.FINALIZED_FAILURE,
    ]


async def test_mortal_era_expiry_fails_closed_without_submission(tmp_path: Path) -> None:
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))

    async def expired_reconcile(query: ReconcileQuery) -> ReconciliationEvidence:
        assert query.era_death_block == 164
        return ReconciliationEvidence(
            schema=RECONCILIATION_SCHEMA,
            operation_id=query.operation.operation_id,
            outcome=ReconcileOutcome.NOT_FOUND.value,
            finalized_head_block=query.era_death_block,
            finalized_head_hash=FINALIZED_HASH,
            scan_start_block=query.era_birth_block,
            scan_end_block=query.era_death_block - 1,
            extrinsic_hash=query.expected_extrinsic_hash,
            **_scan_fields("expired"),
            **_binding(query.unsigned, query.signature),
        )

    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    await _prepare_and_sign(journal, fake)
    ports = fake.bundle()
    ports = ExtrinsicPorts(
        prepare=ports.prepare,
        verify_prepared_call=ports.verify_prepared_call,
        sign=ports.sign,
        submit=ports.submit,
        reconcile=expired_reconcile,
    )
    expired = await journal.advance(_operation(), ports)
    assert expired.state is ExtrinsicState.EXPIRED
    assert expired.receipt.reason_code == "mortal_era_expired"
    assert fake.submit_calls == 0
    assert (await journal.advance(_operation(), ports)).state is ExtrinsicState.EXPIRED


async def test_unknown_reconcile_and_submit_outcomes_are_fail_closed(tmp_path: Path) -> None:
    fake = FakePorts((ReconcileOutcome.UNKNOWN, ReconcileOutcome.NOT_FOUND))
    journal = ValidatorExtrinsicJournal(tmp_path / "reconcile")
    await _prepare_and_sign(journal, fake)
    unknown = await journal.advance(_operation(), fake.bundle())
    assert unknown.state is ExtrinsicState.UNKNOWN
    assert fake.submit_calls == 0
    submitted = await journal.advance(_operation(), fake.bundle())
    assert submitted.state is ExtrinsicState.SUBMITTED

    fake2 = FakePorts((ReconcileOutcome.NOT_FOUND,))
    fake2.submit_error = True
    journal2 = ValidatorExtrinsicJournal(tmp_path / "submit")
    await _prepare_and_sign(journal2, fake2)
    ambiguous = await journal2.advance(_operation(), fake2.bundle())
    assert ambiguous.state is ExtrinsicState.UNKNOWN
    assert ambiguous.receipt.reason_code == "submit_outcome_unknown"
    assert fake2.submit_calls == 1


async def test_sdk_hash_derivation_is_persisted_and_conflicts_fail(tmp_path: Path) -> None:
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    await _prepare_and_sign(journal, fake, derive_hash=True)
    signed = journal.load(_operation())
    assert signed is not None
    assert signed.receipt.expected_signed_extrinsic_hash == EXTRINSIC_HASH

    async def conflicting_submit(
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> SubmissionEvidence:
        return SubmissionEvidence(
            schema=SUBMISSION_SCHEMA,
            operation_id=_operation().operation_id,
            extrinsic_hash=OTHER_EXTRINSIC_HASH,
            **_binding(unsigned, signature),
        )

    ports = fake.bundle(derive_hash=True)
    ports = ExtrinsicPorts(
        prepare=ports.prepare,
        verify_prepared_call=ports.verify_prepared_call,
        sign=ports.sign,
        submit=conflicting_submit,
        reconcile=ports.reconcile,
        derive_signed_hash=ports.derive_signed_hash,
    )
    with pytest.raises(ExtrinsicJournalConflict, match="another signed extrinsic"):
        await journal.advance(_operation(), ports)


async def test_submit_and_reconcile_bindings_cannot_change(tmp_path: Path) -> None:
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))
    journal = ValidatorExtrinsicJournal(tmp_path / "submit")
    await _prepare_and_sign(journal, fake)

    async def conflicting_submit(
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> SubmissionEvidence:
        binding = _binding(unsigned, signature)
        binding["signature_sha256"] = "bb" * 32
        return SubmissionEvidence(
            schema=SUBMISSION_SCHEMA,
            operation_id=_operation().operation_id,
            extrinsic_hash=EXTRINSIC_HASH,
            **binding,
        )

    ports = fake.bundle()
    with pytest.raises(ExtrinsicJournalConflict, match="another signature"):
        await journal.advance(
            _operation(),
            ExtrinsicPorts(
                prepare=ports.prepare,
                verify_prepared_call=ports.verify_prepared_call,
                sign=ports.sign,
                submit=conflicting_submit,
                reconcile=ports.reconcile,
            ),
        )

    fake2 = FakePorts(())
    journal2 = ValidatorExtrinsicJournal(tmp_path / "reconcile")
    await _prepare_and_sign(journal2, fake2)

    async def conflicting_reconcile(query: ReconcileQuery) -> ReconciliationEvidence:
        binding = _binding(query.unsigned, query.signature)
        binding["payload_sha256"] = "cc" * 32
        return ReconciliationEvidence(
            schema=RECONCILIATION_SCHEMA,
            operation_id=query.operation.operation_id,
            outcome=ReconcileOutcome.NOT_FOUND.value,
            finalized_head_block=130,
            finalized_head_hash=FINALIZED_HASH,
            scan_start_block=query.era_birth_block,
            scan_end_block=min(130, query.era_death_block - 1),
            **_scan_fields("binding-conflict"),
            **binding,
        )

    ports2 = fake2.bundle()
    with pytest.raises(ExtrinsicJournalConflict, match="another payload"):
        await journal2.advance(
            _operation(),
            ExtrinsicPorts(
                prepare=ports2.prepare,
                verify_prepared_call=ports2.verify_prepared_call,
                sign=ports2.sign,
                submit=ports2.submit,
                reconcile=conflicting_reconcile,
            ),
        )


async def test_incomplete_or_regressing_finalized_scans_are_fatal(tmp_path: Path) -> None:
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(tmp_path / "incomplete")
    await _prepare_and_sign(journal, fake)

    async def incomplete(query: ReconcileQuery) -> ReconciliationEvidence:
        return ReconciliationEvidence(
            schema=RECONCILIATION_SCHEMA,
            operation_id=query.operation.operation_id,
            outcome=ReconcileOutcome.NOT_FOUND.value,
            finalized_head_block=130,
            finalized_head_hash=FINALIZED_HASH,
            scan_start_block=query.era_birth_block + 1,
            scan_end_block=130,
            **_scan_fields("incomplete"),
            **_binding(query.unsigned, query.signature),
        )

    ports = fake.bundle()
    with pytest.raises(ExtrinsicJournalConflict, match="complete finalized mortal era"):
        await journal.advance(
            _operation(),
            ExtrinsicPorts(
                prepare=ports.prepare,
                verify_prepared_call=ports.verify_prepared_call,
                sign=ports.sign,
                submit=ports.submit,
                reconcile=incomplete,
            ),
        )
    assert fake.submit_calls == 0

    fake2 = FakePorts((ReconcileOutcome.NOT_FOUND,))
    journal2 = ValidatorExtrinsicJournal(tmp_path / "regression")
    await _prepare_and_sign(journal2, fake2)
    assert (await journal2.advance(_operation(), fake2.bundle())).state is (
        ExtrinsicState.SUBMITTED
    )
    history_length = len(journal2.history(_operation()))

    async def regressing(query: ReconcileQuery) -> ReconciliationEvidence:
        return ReconciliationEvidence(
            schema=RECONCILIATION_SCHEMA,
            operation_id=query.operation.operation_id,
            outcome=ReconcileOutcome.NOT_FOUND.value,
            finalized_head_block=129,
            finalized_head_hash="0x" + "ab" * 32,
            scan_start_block=query.era_birth_block,
            scan_end_block=129,
            extrinsic_hash=query.expected_extrinsic_hash,
            **_scan_fields("regressing"),
            **_binding(query.unsigned, query.signature),
        )

    ports2 = fake2.bundle()
    with pytest.raises(ExtrinsicJournalConflict, match="head regresses"):
        await journal2.advance(
            _operation(),
            ExtrinsicPorts(
                prepare=ports2.prepare,
                verify_prepared_call=ports2.verify_prepared_call,
                sign=ports2.sign,
                submit=ports2.submit,
                reconcile=regressing,
            ),
        )
    assert len(journal2.history(_operation())) == history_length


async def test_finalized_inclusion_outside_mortal_era_is_fatal(tmp_path: Path) -> None:
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    await _prepare_and_sign(journal, fake)

    async def outside_era(query: ReconcileQuery) -> ReconciliationEvidence:
        return ReconciliationEvidence(
            schema=RECONCILIATION_SCHEMA,
            operation_id=query.operation.operation_id,
            outcome=ReconcileOutcome.FINALIZED_SUCCESS.value,
            finalized_head_block=170,
            finalized_head_hash=FINALIZED_HASH,
            scan_start_block=query.era_birth_block,
            scan_end_block=query.era_death_block - 1,
            extrinsic_hash=EXTRINSIC_HASH,
            inclusion_block=query.era_death_block,
            inclusion_block_hash=INCLUSION_HASH,
            **_scan_fields("outside-era"),
            **_binding(query.unsigned, query.signature),
        )

    ports = fake.bundle()
    with pytest.raises(ExtrinsicJournalConflict, match="outside the mortal era"):
        await journal.advance(
            _operation(),
            ExtrinsicPorts(
                prepare=ports.prepare,
                verify_prepared_call=ports.verify_prepared_call,
                sign=ports.sign,
                submit=ports.submit,
                reconcile=outside_era,
            ),
        )
    assert fake.submit_calls == 0


async def test_operation_id_is_deterministic_and_mismatched_expectation_is_fatal(
    tmp_path: Path,
) -> None:
    assert _operation().operation_id == _operation().operation_id
    assert _operation(request_value=2).operation_id != _operation().operation_id
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    with pytest.raises(ExtrinsicJournalConflict, match="expected operation ID"):
        await journal.advance(
            _operation(),
            fake.bundle(),
            expected_operation_id="ee" * 32,
        )
    assert fake.prepare_calls == 0


def test_operation_schema_is_a_hard_shadow_anchor_interlock() -> None:
    base = _operation().model_dump(mode="json", by_alias=True)
    base["operation"] = "commit_timelocked_mechanism_weights"
    with pytest.raises(ValueError, match="literal"):
        ExtrinsicOperation.model_validate(base)

    mismatch = _operation().model_dump(mode="json", by_alias=True)
    mismatch["operation"] = "response_anchor"
    with pytest.raises(ValueError, match="kind disagree"):
        ExtrinsicOperation.model_validate(mismatch)


async def test_prepared_call_decode_must_match_raw_bytes_and_anchor_intent(
    tmp_path: Path,
) -> None:
    fake = FakePorts(())
    base = fake.bundle()

    async def wrong_field(
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
    ) -> PreparedCallEvidence:
        return _prepared_call(operation, unsigned, field_sha256="aa" * 32)

    ports = ExtrinsicPorts(
        prepare=base.prepare,
        verify_prepared_call=wrong_field,
        sign=base.sign,
        submit=base.submit,
        reconcile=base.reconcile,
    )
    journal = ValidatorExtrinsicJournal(tmp_path / "wrong-field")
    with pytest.raises(ExtrinsicJournalConflict, match="closed anchor intent"):
        await journal.advance(_operation(), ports)
    assert journal.load(_operation()) is None
    assert fake.sign_calls == 0

    fake2 = FakePorts(())
    fake2.unsigned.payload_json["method"] = "0xdead"
    journal2 = ValidatorExtrinsicJournal(tmp_path / "payload-method")
    with pytest.raises(ExtrinsicJournalConflict, match="exact prepared call bytes"):
        await journal2.advance(_operation(), fake2.bundle())
    assert journal2.load(_operation()) is None
    assert fake2.sign_calls == 0


async def test_prepared_call_evidence_is_persisted_before_signing(tmp_path: Path) -> None:
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    prepared = await journal.advance(_operation(), fake.bundle())
    assert prepared.state is ExtrinsicState.PREPARED
    assert prepared.receipt.prepared_call == _prepared_call(_operation(), fake.unsigned)
    assert (
        prepared.receipt.prepared_call_sha256
        == hashlib.sha256(canonical_json_bytes(prepared.receipt.prepared_call)).hexdigest()
    )
    assert fake.sign_calls == 0


async def test_invalid_signatures_and_immortal_preparations_never_broadcast(
    tmp_path: Path,
) -> None:
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(tmp_path / "signature")
    await journal.advance(_operation(), fake.bundle())

    async def short_sign(payload: bytes, operation_id: str) -> bytes:
        return b"bad"

    ports = fake.bundle()
    with pytest.raises(ExtrinsicJournalError, match="64- or 65-byte"):
        await journal.advance(
            _operation(),
            ExtrinsicPorts(
                prepare=ports.prepare,
                verify_prepared_call=ports.verify_prepared_call,
                sign=short_sign,
                submit=ports.submit,
                reconcile=ports.reconcile,
            ),
        )
    assert fake.submit_calls == 0

    fake2 = FakePorts(())
    fake2.unsigned.era = "00"
    journal2 = ValidatorExtrinsicJournal(tmp_path / "immortal")
    with pytest.raises(ExtrinsicJournalError, match="mortal"):
        await journal2.advance(_operation(), fake2.bundle())
    assert fake2.sign_calls == 0
    assert fake2.submit_calls == 0


async def test_content_tampering_and_receipt_forks_fail_on_restart(tmp_path: Path) -> None:
    root = tmp_path / "tamper"
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(root)
    prepared = await journal.advance(_operation(), fake.bundle())
    encoded = prepared.path.read_bytes()
    decoded = json.loads(encoded)
    decoded["unsigned_record"]["nonce"] = 8
    prepared.path.write_bytes(canonical_json_bytes(decoded))
    with pytest.raises(ExtrinsicJournalError, match="filename"):
        ValidatorExtrinsicJournal(root)

    fork_root = tmp_path / "fork"
    journal2 = ValidatorExtrinsicJournal(fork_root)
    prepared2 = await journal2.advance(_operation(), fake.bundle())
    decoded2 = json.loads(prepared2.path.read_bytes())
    decoded2["payload_sha256"] = "ff" * 32
    fork_bytes = canonical_json_bytes(decoded2)
    fork_digest = hashlib.sha256(fork_bytes).hexdigest()
    (prepared2.path.parent / f"{fork_digest}.json").write_bytes(fork_bytes)
    with pytest.raises(ExtrinsicJournalError, match="invalid"):
        ValidatorExtrinsicJournal(fork_root)


async def test_forged_submission_cannot_skip_durable_prebroadcast_scan(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    fake = FakePorts((ReconcileOutcome.NOT_FOUND,))
    journal = ValidatorExtrinsicJournal(root)
    await _prepare_and_sign(journal, fake)
    await journal.advance(_operation(), fake.bundle())
    history = journal.history(_operation())
    assert [entry.state for entry in history] == [
        ExtrinsicState.PREPARED,
        ExtrinsicState.SIGNED,
        ExtrinsicState.SIGNED,
        ExtrinsicState.SUBMITTED,
    ]

    forged = json.loads(history[-1].path.read_bytes())
    forged["sequence"] = 2
    forged["previous_receipt_sha256"] = history[1].receipt_sha256
    forged_bytes = canonical_json_bytes(forged)
    forged_digest = hashlib.sha256(forged_bytes).hexdigest()
    for entry in history[2:]:
        entry.path.unlink()
    (history[0].path.parent / f"{forged_digest}.json").write_bytes(forged_bytes)

    with pytest.raises(ExtrinsicJournalConflict, match="pre-broadcast reconciliation"):
        ValidatorExtrinsicJournal(root)


async def test_prepared_unsigned_must_name_the_operation_validator(tmp_path: Path) -> None:
    fake = FakePorts(())
    fake.unsigned.address = "5OtherValidator"
    journal = ValidatorExtrinsicJournal(tmp_path / "journal")
    with pytest.raises(ExtrinsicJournalConflict, match="another validator"):
        await journal.advance(_operation(), fake.bundle())
    assert journal.load(_operation()) is None
    assert fake.sign_calls == 0
    assert fake.submit_calls == 0


async def test_fsynced_pending_receipt_is_promoted_on_restart(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    fake = FakePorts(())
    journal = ValidatorExtrinsicJournal(root)
    prepared = await journal.advance(_operation(), fake.bundle())
    pending = prepared.path.parent / f".pending-{prepared.receipt_sha256}-crash"
    prepared.path.rename(pending)

    restarted = ValidatorExtrinsicJournal(root)
    loaded = restarted.load(_operation())
    assert loaded is not None
    assert loaded.state is ExtrinsicState.PREPARED
    assert loaded.path.exists()
    assert not pending.exists()


def test_mortal_era_bounds_match_sdk_quantization_and_reject_bad_eras() -> None:
    unsigned = _unsigned()
    assert mortal_era_bounds(unsigned) == (100, 164)
    unsigned.era = {"period": 8192, "current": 10001}
    assert mortal_era_bounds(unsigned) == (10000, 18192)
    unsigned.era = {"period": 63, "current": 100}
    with pytest.raises(ExtrinsicJournalError, match="period"):
        mortal_era_bounds(unsigned)
    unsigned.era = "00"
    with pytest.raises(ExtrinsicJournalError, match="mortal"):
        mortal_era_bounds(unsigned)
