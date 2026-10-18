"""Real sr25519 and SQLite; synthetic codec, finality and transport ports.

No fixture envelope is a Substrate transaction or reaches a real network.
This qualifies the execution owner, not a released image or installed migration.
"""

import hashlib
import json
import time

import bittensor as bt
import pytest

from tests.factories import dev_wallet
from tests.test_registration_bridge import BLOCK
from tests.test_translation_reference_state import read, reference_case, signing_case
from tests.test_translation_reference_transactions import advance
from umi.bootstrap_weight_operator import BootstrapExtrinsicReference
from umi.crypto import sign_response_digest
from umi.mortal_receipts import VerifiedMortalReceipt
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.signed_extrinsic import exact_signed_extrinsic
from umi.translation_reference_execution import run_reference_iteration
from umi.translation_reference_policy import (
    ApprovedTranslationReferencePolicy,
    SignedTranslationReferencePolicy,
    reference_policy_sha256,
    reference_policy_signature_digest,
    verify_reference_policy,
)
from umi.translation_reference_state import TranslationReferenceError
from umi.translation_reference_transactions import ReferenceWeightJournal

__all__ = ["reference_case", "signing_case"]


def jsonable(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    return value


@pytest.fixture
def execution_case(reference_case, monkeypatch, tmp_path):
    case = reference_case
    authority = dev_wallet("//ReferenceExecutionPolicyAuthority")

    def approve_policy(values):
        policy = ApprovedTranslationReferencePolicy.model_validate(values)
        signed = SignedTranslationReferencePolicy(
            schema="umi-signed-translation-reference-policy/1",
            policy=policy,
            authority_hotkey=authority.hotkey.ss58_address,
            signature_scheme="sr25519",
            signature=sign_response_digest(authority, reference_policy_signature_digest(policy))[1],
        )
        return verify_reference_policy(
            canonical_json_bytes(signed),
            expected_policy_sha256=reference_policy_sha256(policy),
            expected_authority_hotkey=authority.hotkey.ss58_address,
        )

    fields = case.policy.model_dump(mode="python", by_alias=True)
    fields.update(
        schema="umi-translation-reference-policy/2",
        row_rule="exact_proven_and_authority_approved_reference_row/1",
        expected_row_sha256=hashlib.sha256(canonical_json_bytes(case.row)).hexdigest(),
    )
    case.approve_policy = approve_policy
    case.policy = approve_policy(fields)
    wallet = dev_wallet("//ReferenceExecutionFixture")
    writer = wallet.hotkey.ss58_address
    case.obs = case.obs.model_copy(update={"validator_hotkey": writer})
    old_account = case.account_key
    from umi.encoding import account_id32

    case.account_key = b"System.Account:" + account_id32(writer)
    case.values[case.account_key] = case.values.pop(old_account)
    case.set_value("Uids", 54, 78, writer)
    case.set_value("Keys", writer, 78, 54)
    import umi.runtime_metadata as metadata

    original = metadata.bittensor_core.Runtime

    class Codec(original):
        def compose_call(self, module, function, params):
            return canonical_json_bytes({"module": module, "function": function, "params": params})

        def signature_payload(self, call, **options):
            return canonical_json_bytes({"call": call.hex(), **jsonable(options)})

        def encode_signed_extrinsic(self, call, **options):
            encoded = b"fixture-only:" + canonical_json_bytes(
                {"call": call.hex(), **jsonable(options)}
            )
            return encoded, hashlib.blake2b(encoded, digest_size=32).digest()

        def decode_extrinsic(self, encoded, strict):
            assert strict is True and encoded.startswith(b"fixture-only:")
            value = json.loads(encoded[len(b"fixture-only:") :])
            scheme = {0: "Ed25519", 1: "Sr25519"}[value["signature_version"]]
            return {
                "era": (value["era"]["period"], value["era"]["current"] % value["era"]["period"]),
                "nonce": value["nonce"],
                "extrinsic_hash": exact_signed_extrinsic(encoded).extrinsic_hash,
                "address": bt.sp_core.Keypair(
                    public_key=bytes.fromhex(value["public_key"])
                ).ss58_address,
                "signature": {scheme: "0x" + value["signature"]},
            }

    monkeypatch.setattr(metadata.bittensor_core, "Runtime", Codec)
    case.journal = ReferenceWeightJournal(
        tmp_path / "worker", validator_hotkey=writer, maximum_bytes=4 * 1024**2
    )
    case.wallet = wallet

    class Ports:
        expected_validator_hotkey = writer
        verifier_semantics_sha256 = "a" * 64

        def __init__(self):
            self.started = time.monotonic()
            self.events, self.transmissions = [], []
            self.signatures = self.signer_loads = self.receipt_reads = 0
            self.legacy_checks = self.guard_calls = 0
            self.owner_ok = True
            self.legacy_ok = True
            self.guard_failure_at = None
            self.no_receipt = False
            self.lost_reply = False
            self.bad_receipt = False
            self.receipt_value = None

        def clock(self):
            return case.now

        def elapsed_seconds(self):
            return time.monotonic() - self.started

        def progress(self, value):
            self.events.append(value)

        def require_owner(self):
            if not self.owner_ok:
                raise TranslationReferenceError("fixture_owner_lost")

        async def state(self, policy):
            assert policy == case.policy
            return await read(case)

        async def signing_state(self):
            return await case.reader._signing.read(writer)

        async def legacy_gate(self, state):
            self.legacy_checks += 1
            if not self.legacy_ok:
                raise TranslationReferenceError("fixture_legacy_unresolved")

        async def guard(self, intent):
            self.require_owner()
            self.guard_calls += 1
            if self.guard_failure_at == self.guard_calls:
                raise TranslationReferenceError("fixture_directive_expired")
            assert intent.block <= case.head.number < intent.block + 8

        def signer(self):
            self.signer_loads += 1
            ports = self

            class Signer:
                ss58_address = writer
                crypto_type = 1

                def sign(self, payload):
                    pending = case.journal.pending()
                    assert pending is not None and pending.signed is None
                    ports.signatures += 1
                    return bytes(wallet.hotkey.sign(payload))

            return Signer()

        async def submit(self, encoded, signer, timeout_seconds):
            assert timeout_seconds == 60 and signer.ss58_address == writer
            pending = case.journal.pending()
            assert pending.signed.encoded == encoded.hex()
            self.transmissions.append(encoded)
            if not self.no_receipt:
                block = case.head.number + 1
                case.updates[54] = block
                case.set_value("LastUpdate", case.updates)
                case.set_value("Weights", list(map(list, pending.intent.row)), 78, 54)
                advance(case, block - BLOCK, nonce=pending.intent.nonce + 1)
                state = await read(case)
                self.receipt_value = VerifiedMortalReceipt(
                    BootstrapExtrinsicReference(
                        extrinsic_id=f"{block}-0002",
                        block_number=block,
                        extrinsic_index=2,
                        block_hash=case.head.block_hash,
                    ),
                    True,
                    pending.signed.extrinsic_hash,
                    state.signing.runtime.snapshot,
                )
            if self.lost_reply:
                raise TimeoutError("private fixture text must not be logged")

        async def receipt(self, query):
            self.receipt_reads += 1
            if self.bad_receipt and self.receipt_value is not None:
                from dataclasses import replace

                return replace(self.receipt_value, signed_extrinsic_hash="0x" + "f0" * 32)
            return self.receipt_value

    case.ports = Ports()
    return case


async def iterate(case):
    return await run_reference_iteration(case.policy, journal=case.journal, ports=case.ports)


@pytest.mark.asyncio
async def test_signs_once_only_after_intent_and_retains_before_transmission(execution_case):
    case = execution_case
    result = await iterate(case)
    assert result["status"] == "finalized_row_verified"
    assert case.ports.signatures == len(case.ports.transmissions) == 1
    assert not result["independent_cohort_certification_claimed"]
    pending = case.journal.pending()
    assert case.journal.journal.get("reference_native_receipt", digest(pending.intent))[
        "successful"
    ]
    before = case.ports.receipt_reads
    assert (await iterate(case))["status"] == "finalized_row_verified"
    assert case.ports.receipt_reads == before  # Durable unchanged native verdict reused.
    assert case.ports.signatures == len(case.ports.transmissions) == 1
    assert all("elapsed_seconds" in event for event in case.ports.events)


@pytest.mark.asyncio
async def test_lost_sdk_reply_does_not_hide_native_confirmed_publication(execution_case):
    case = execution_case
    case.ports.lost_reply = True
    assert (await iterate(case))["status"] == "finalized_row_verified"
    assert case.ports.signatures == len(case.ports.transmissions) == 1
    assert "private fixture text" not in str(case.ports.events)


@pytest.mark.asyncio
async def test_unknown_send_is_not_rebroadcast_after_fresh_process_journal_open(execution_case):
    case = execution_case
    case.ports.no_receipt = case.ports.lost_reply = True
    assert (await iterate(case))["status"] == "submitted_outcome_unknown"
    original = case.journal.pending()
    case.journal = ReferenceWeightJournal(
        case.journal.journal.root,
        validator_hotkey=case.ports.expected_validator_hotkey,
        maximum_bytes=4 * 1024**2,
    )
    assert (await iterate(case))["status"] == "awaiting_original_attempt_fence"
    assert case.journal.pending() == original
    assert case.ports.signatures == len(case.ports.transmissions) == 1


@pytest.mark.asyncio
async def test_same_worker_follows_signed_future_cohort_policy_after_fresh_nonce_fence(
    execution_case,
):
    case = execution_case
    assert (await iterate(case))["status"] == "finalized_row_verified"
    original = case.journal.pending()
    advance(case, 110, nonce=8)
    case.updates[200] = BLOCK + 109
    case.set_value("LastUpdate", case.updates)
    case.set_value("Weights", [[uid, 65535 if uid == 119 else 0] for uid in range(256)], 78, 200)
    with pytest.raises(TranslationReferenceError, match="not_approved_by_release_authority"):
        await iterate(case)
    assert case.ports.signatures == 1
    fields = case.policy.model_dump(mode="python", by_alias=True)
    row = [[uid, 65535 if uid == 119 else 0] for uid in range(256)]
    fields.update(
        first_cohort_sequence=6,
        minimum_reference_update_block=BLOCK + 109,
        expected_row_sha256=hashlib.sha256(canonical_json_bytes(row)).hexdigest(),
    )
    case.policy = case.approve_policy(fields)
    assert (await iterate(case))["status"] == "finalized_row_verified"
    newer = case.journal.pending()
    assert newer.intent.previous_intent_sha256 == digest(original.intent)
    assert newer.intent.row[119][1] == 65535 and newer.intent.nonce == 8
    assert case.ports.signatures == len(case.ports.transmissions) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["owner", "legacy", "before_sign", "before_send"])
async def test_owner_legacy_and_directive_gates_prevent_unauthorized_transmission(
    execution_case, failure
):
    case = execution_case
    if failure == "owner":
        case.ports.owner_ok = False
    elif failure == "legacy":
        case.ports.legacy_ok = False
    else:
        case.ports.guard_failure_at = 2 if failure == "before_sign" else 3
    with pytest.raises(TranslationReferenceError):
        await iterate(case)
    assert not case.ports.transmissions
    if failure in {"owner", "legacy"}:
        assert case.ports.signer_loads == 0 and case.journal.pending() is None
    if failure == "before_send":
        assert case.journal.pending().signed is not None
        assert (await iterate(case))["status"] == "awaiting_original_attempt_fence"
        assert case.ports.signatures == 1


@pytest.mark.asyncio
async def test_native_receipt_for_another_transaction_never_proves_the_row(execution_case):
    case = execution_case
    case.ports.bad_receipt = True
    with pytest.raises(TranslationReferenceError, match="receipt_attempt_mismatch"):
        await iterate(case)
    assert case.ports.signatures == len(case.ports.transmissions) == 1
    assert (
        case.journal.journal.get("reference_native_receipt", digest(case.journal.pending().intent))
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing", ["reference_native_receipt", "reference_native_receipt_acceptance", "both"]
)
async def test_completed_receipt_damage_is_reported_without_repeating_native_proofs(
    execution_case, missing
):
    case = execution_case
    assert (await iterate(case))["status"] == "finalized_row_verified"
    key = digest(case.journal.pending().intent)
    before = case.ports.receipt_reads
    with case.journal.journal.transaction() as db:
        if missing == "both":
            db.execute(
                "DELETE FROM records WHERE kind IN (?,?) AND id=?",
                (
                    "reference_native_receipt",
                    "reference_native_receipt_acceptance",
                    key,
                ),
            )
        else:
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (missing, key))
    with pytest.raises(TranslationReferenceError, match="verification_repair_required"):
        await iterate(case)
    assert case.ports.receipt_reads == before
    assert case.ports.signatures == len(case.ports.transmissions) == 1


@pytest.mark.asyncio
async def test_explicit_receipt_index_repair_reuses_original_native_verdict_and_repeats(
    execution_case,
):
    case = execution_case
    assert (await iterate(case))["status"] == "finalized_row_verified"
    before = case.ports.receipt_reads
    with case.journal.journal.transaction() as db:
        db.execute("DELETE FROM reference_receipt_index")
    with pytest.raises(TranslationReferenceError, match="verification_repair_required"):
        await iterate(case)
    for _ in range(2):
        events = []
        case.journal = ReferenceWeightJournal(
            case.journal.journal.root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
            repair_head_index=True,
            progress=events.append,
        )
        assert (await iterate(case))["status"] == "finalized_row_verified"
        assert events[-1]["stage"] == "reference_receipt_index_repair"
        assert events[-1]["status"] == "completed" and events[-1]["eta_seconds"] == 0
    assert case.ports.receipt_reads == before


@pytest.mark.asyncio
async def test_interrupted_receipt_index_repair_rolls_back_and_missing_verdict_needs_restore(
    execution_case,
):
    case = execution_case
    assert (await iterate(case))["status"] == "finalized_row_verified"
    key = digest(case.journal.pending().intent)

    def interrupt(event):
        if event.get("stage") == "reference_receipt_index_repair" and event["completed"]:
            raise InterruptedError("interrupted metadata repair")

    with pytest.raises(InterruptedError):
        ReferenceWeightJournal(
            case.journal.journal.root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
            repair_head_index=True,
            progress=interrupt,
        )
    assert (await iterate(case))["status"] == "finalized_row_verified"
    with case.journal.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='reference_native_receipt' AND id=?", (key,))
    with pytest.raises(ValueError, match="restoration required"):
        ReferenceWeightJournal(
            case.journal.journal.root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
            repair_head_index=True,
        )
