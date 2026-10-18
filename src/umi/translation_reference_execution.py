"""One owned follower iteration; release authentication and I/O are separate.

Only a newly reserved, natively encoded attempt may be transmitted. A retained
attempt is never retransmitted, even after a lost reply. Native receipt and
current-row checks establish publication separately from mortality fencing.
"""

from __future__ import annotations

from datetime import datetime
from functools import partial
from typing import Protocol

from pydantic import Field, ValidationError, model_validator

from .bootstrap_weight_operator import BootstrapExtrinsicReference
from .bridge.signing import BridgeSigningState
from .chain_evidence import FinalizedSnapshotRef
from .concurrency import run_owned_thread
from .encoding import account_id32
from .mortal_receipts import MortalReceiptQuery, VerifiedMortalReceipt
from .open_competition import digest
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .signed_extrinsic import encode_verified_mortal_call
from .translation_reference_policy import TranslationReferencePolicy, reference_policy_sha256
from .translation_reference_state import TranslationReferenceError, TranslationReferenceState
from .translation_reference_transactions import (
    ReferenceWeightIntent,
    ReferenceWeightJournal,
    reference_weight_intent,
)


class ReferenceNativeReceipt(StrictProtocolModel):
    schema_: str = Field(alias="schema")
    intent_sha256: Hex32
    policy_sha256: Hex32
    verifier_semantics_sha256: Hex32
    signed_extrinsic_hash: BlockHash
    receipt: BootstrapExtrinsicReference
    successful: bool
    owned_head: FinalizedSnapshotRef

    @model_validator(mode="after")
    def bindings(self):
        if (
            self.schema_ != "umi-reference-native-receipt/1"
            or self.receipt.block_number > self.owned_head.block_number
            or (
                self.receipt.block_number == self.owned_head.block_number
                and self.receipt.block_hash != self.owned_head.block_hash
            )
        ):
            raise ValueError("reference native receipt has invalid finalized bounds")
        return self


class ReferenceExecutionPorts(Protocol):
    """The production driver owns all these resources until cancellation drains."""

    expected_validator_hotkey: str
    verifier_semantics_sha256: str

    def clock(self) -> datetime: ...
    def elapsed_seconds(self) -> float: ...
    def require_owner(self) -> None: ...
    def progress(self, value: dict) -> None: ...
    async def state(self, policy: TranslationReferencePolicy) -> TranslationReferenceState: ...
    async def signing_state(self) -> BridgeSigningState: ...
    async def legacy_gate(self, state: TranslationReferenceState) -> None: ...
    async def guard(self, intent: ReferenceWeightIntent) -> None: ...
    def signer(self): ...
    async def submit(self, encoded: bytes, signer, timeout_seconds: int) -> None: ...
    async def receipt(self, query: MortalReceiptQuery) -> VerifiedMortalReceipt | None: ...


def _event(ports, stage, *, completed=0, total=1, retrying=False, **fields):
    ports.progress(
        {
            "stage": stage,
            "completed": completed,
            "total": total,
            "percent": 100 * completed / total if total else 100,
            "elapsed_seconds": ports.elapsed_seconds(),
            "eta_seconds": 0 if completed == total else None,
            "planning_seconds": None if completed == total or retrying else [1, 120],
            "eta_basis": "bounded native stage planning range; finality and rollout ETA separate",
            "stalled": retrying,
            "retrying": retrying,
            **fields,
        }
    )


def _require_binding(ports, state, journal):
    if account_id32(state.signing.validator_hotkey) != account_id32(
        ports.expected_validator_hotkey
    ):
        raise TranslationReferenceError("reference_owned_signer_changed")
    if account_id32(journal.hotkey) != account_id32(ports.expected_validator_hotkey):
        raise TranslationReferenceError("reference_journal_signer_changed")


async def _retain_receipt(ports, journal, pending):
    """Reuse successful native inclusion checks bound to exact original bytes."""
    if pending.signed is None:
        return None
    intent, signed = pending.intent, pending.signed
    key = digest(intent)

    existing, accepted = await run_owned_thread(partial(journal.native_receipt, key))
    if (existing is None) != (accepted is None):
        raise TranslationReferenceError("reference_receipt_verification_repair_required")
    if existing is not None:
        expected_acceptance = {
            "schema": "umi-reference-native-receipt-acceptance/1",
            "intent_sha256": key,
            "receipt_sha256": sha256_hex(canonical_json_bytes(existing)),
            "verifier_semantics_sha256": ports.verifier_semantics_sha256,
        }
        if accepted != expected_acceptance:
            raise TranslationReferenceError("reference_receipt_verification_repair_required")
        try:
            parsed = ReferenceNativeReceipt.model_validate_json(canonical_json_bytes(existing))
            existing = parsed.model_dump(mode="json", by_alias=True)
        except (ValidationError, ValueError, TypeError) as error:
            raise TranslationReferenceError(
                "reference_receipt_verification_repair_required"
            ) from error
        if (
            set(existing)
            != {
                "schema",
                "intent_sha256",
                "policy_sha256",
                "verifier_semantics_sha256",
                "signed_extrinsic_hash",
                "receipt",
                "successful",
                "owned_head",
            }
            or existing["schema"] != "umi-reference-native-receipt/1"
            or existing["intent_sha256"] != key
            or existing["policy_sha256"] != intent.policy_sha256
            or existing["verifier_semantics_sha256"] != ports.verifier_semantics_sha256
            or existing["signed_extrinsic_hash"] != signed.extrinsic_hash
            or type(existing["successful"]) is not bool
            or not intent.block
            < parsed.receipt.block_number
            < intent.block + intent.mortality_period
        ):
            raise TranslationReferenceError("reference_receipt_verification_repair_required")
        return existing
    query = MortalReceiptQuery(
        schema="umi-mortal-receipt-query/1",
        birth_block=intent.block,
        birth_hash=intent.block_hash,
        mortality_period=intent.mortality_period,
        signed_extrinsic=signed.encoded,
    )
    _event(ports, "reference_native_receipt")
    proven = await ports.receipt(query)
    ports.require_owner()
    if proven is None:
        return None
    if (
        type(proven) is not VerifiedMortalReceipt
        or proven.signed_extrinsic_hash != signed.extrinsic_hash
        or type(proven.successful) is not bool
        or not intent.block < proven.receipt.block_number < intent.block + intent.mortality_period
        or proven.owned_head.block_number < proven.receipt.block_number
    ):
        raise TranslationReferenceError("reference_native_receipt_attempt_mismatch")
    result = ReferenceNativeReceipt(
        schema="umi-reference-native-receipt/1",
        intent_sha256=key,
        policy_sha256=intent.policy_sha256,
        verifier_semantics_sha256=ports.verifier_semantics_sha256,
        signed_extrinsic_hash=signed.extrinsic_hash,
        receipt=proven.receipt,
        successful=proven.successful,
        owned_head=proven.owned_head,
    ).model_dump(mode="json", by_alias=True)
    acceptance = {
        "schema": "umi-reference-native-receipt-acceptance/1",
        "intent_sha256": key,
        "receipt_sha256": sha256_hex(canonical_json_bytes(result)),
        "verifier_semantics_sha256": ports.verifier_semantics_sha256,
    }
    await run_owned_thread(
        partial(
            journal.retain_native_receipt,
            key,
            result,
            acceptance,
        )
    )
    _event(ports, "reference_native_receipt", completed=1)
    return result


async def _current_row(ports, policy, journal, pending, receipt):
    if not receipt["successful"]:
        return {"status": "finalized_dispatch_failed", "intent_sha256": digest(pending.intent)}
    state = await ports.state(policy)
    _require_binding(ports, state, journal)
    decision = state.decision(policy, now=ports.clock())
    own = next(
        r
        for r in state.rows.reads
        if r.spec.item == "Weights" and r.spec.params == (78, decision.writer_uid)
    )
    row = state.signing.runtime.decode_storage(own.spec.pallet, own.spec.item, own.raw_value)
    if (
        state.signing.runtime.snapshot.block_number < receipt["receipt"]["block_number"]
        or decision.writer_last_update != receipt["receipt"]["block_number"]
        or tuple(sorted(map(tuple, row))) != pending.intent.row
    ):
        raise TranslationReferenceError("reference_finalized_row_not_visible")
    _event(
        ports,
        "reference_finalized_current_row",
        completed=1,
        weight_update_block=decision.writer_last_update,
    )
    return {
        "status": "finalized_row_verified",
        "intent_sha256": digest(pending.intent),
        "weight_update_block": decision.writer_last_update,
        "independent_cohort_certification_claimed": False,
    }


async def run_reference_iteration(
    policy: TranslationReferencePolicy,
    *,
    journal: ReferenceWeightJournal,
    ports: ReferenceExecutionPorts,
):
    """Run only under an authenticated fixed release and original process lock.

    The driver authenticates policy, owns the finality stream and reconciles the
    installed legacy layout. Test port injection is not a deployment interface.
    """
    ports.require_owner()
    pending = await run_owned_thread(journal.pending)
    if pending is not None and pending.end is None:
        signing = await ports.signing_state()
        ports.require_owner()
        if (
            signing.runtime.snapshot.block_number
            < pending.intent.block + pending.intent.mortality_period
        ):
            receipt = await _retain_receipt(ports, journal, pending)
            if receipt is not None:
                return await _current_row(ports, policy, journal, pending, receipt)
            remaining = (
                pending.intent.block
                + pending.intent.mortality_period
                - signing.runtime.snapshot.block_number
            )
            _event(
                ports,
                "reference_original_attempt_fence",
                retrying=True,
                remaining_blocks=remaining,
                planning_seconds=12 * remaining,
                planning_basis="remaining mortal blocks at 12 seconds per block; not calibrated",
            )
            return {"status": "awaiting_original_attempt_fence", "remaining_blocks": remaining}
        _event(ports, "reference_original_attempt_reconciliation")
        pending = await run_owned_thread(partial(journal.fence_expired, signing, now=ports.clock()))
        _event(ports, "reference_original_attempt_reconciliation", completed=1)
    state = await ports.state(policy)
    ports.require_owner()
    _require_binding(ports, state, journal)
    decision = state.decision(policy, now=ports.clock())
    if decision.action != "submit":
        _event(
            ports,
            "reference_following",
            completed=1,
            next_action_block=decision.next_action_block,
            reference_last_update=decision.reference_last_update,
        )
        return {"status": "following_reference", "next_action_block": decision.next_action_block}
    _event(ports, "reference_legacy_ownership")
    await ports.legacy_gate(state)
    ports.require_owner()
    _event(ports, "reference_legacy_ownership", completed=1)
    intent = reference_weight_intent(
        state,
        policy,
        now=ports.clock(),
        previous_intent_sha256=None if pending is None else digest(pending.intent),
    )
    if intent.policy_sha256 != reference_policy_sha256(policy):
        raise TranslationReferenceError("reference_policy_changed_before_signing")
    await ports.guard(intent)
    await run_owned_thread(partial(journal.reserve, intent))
    _event(ports, "reference_new_weight_attempt", completed=1, total=4)
    signer = await run_owned_thread(ports.signer)
    if account_id32(signer.ss58_address) != account_id32(ports.expected_validator_hotkey):
        raise TranslationReferenceError("reference_wallet_signer_changed")
    ports.require_owner()
    await ports.guard(intent)
    # Recheck the immutable selection and freshness after every yielding stage.
    if intent != reference_weight_intent(
        state, policy, now=ports.clock(), previous_intent_sha256=intent.previous_intent_sha256
    ):
        raise TranslationReferenceError("reference_intent_changed_before_signing")
    encoded = await run_owned_thread(
        partial(
            encode_verified_mortal_call,
            intent.call(),
            runtime=state.signing.runtime,
            signer=signer,
            validator_hotkey=intent.validator_hotkey,
            nonce=intent.nonce,
            mortality_period=intent.mortality_period,
            genesis_hash=policy.genesis_hash,
        )
    )
    ports.require_owner()
    pending = await run_owned_thread(partial(journal.retain_signed, intent, encoded))
    _event(ports, "reference_new_weight_attempt", completed=2, total=4)
    await ports.guard(intent)
    ports.require_owner()
    try:
        await ports.submit(encoded, signer, policy.submission_timeout_seconds)
    except Exception as error:
        # An SDK reply is never a finalized outcome; the exact bytes stay pending.
        _event(
            ports,
            "reference_transmission_unconfirmed",
            retrying=True,
            error_type=type(error).__name__,
        )
    _event(ports, "reference_new_weight_attempt", completed=3, total=4)
    receipt = await _retain_receipt(ports, journal, pending)
    if receipt is None:
        return {"status": "submitted_outcome_unknown", "intent_sha256": digest(intent)}
    result = await _current_row(ports, policy, journal, pending, receipt)
    _event(ports, "reference_new_weight_attempt", completed=4, total=4)
    return result
