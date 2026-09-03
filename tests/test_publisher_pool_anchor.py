from __future__ import annotations

import inspect
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import pytest
from bittensor import UnsignedExtrinsic
from pydantic import ValidationError

from tests.factories import dev_wallet
from tests.test_policy import make_policy
from tests.test_publisher_availability import (
    _context,
    _fake_inspect_factory,
    _qualify,
    _window,
    _write_bundle,
)
from umi.protocol import canonical_json_bytes
from umi.publisher_availability import (
    build_certified_release,
    validate_candidate_bundle,
)
from umi.publisher_pool_anchor import (
    POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS,
    ClosingAnchorEvidence,
    PoolAnchorEvidence,
    PoolAnchorPending,
    PublisherPoolAnchorError,
    PublisherPoolAnchorOperator,
    load_pool_anchor_material,
)
from umi.publisher_pool_anchor_cli import (
    EXECUTION_ACKNOWLEDGEMENT,
    OPERATOR_CONFIG_SCHEMA,
    PublisherPoolAnchorOperatorConfig,
    _advance_until_terminal,
    run_cli,
)
from umi.validator_extrinsics import ExtrinsicPorts, ExtrinsicState, mortal_era_bounds


def _material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    policy = make_policy()
    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window, publisher_count=2)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded, policy=policy, context=_context(loaded, policy, 0)
    )
    receipts = [
        _qualify(tmp_path / f"validator-{index}", validated, policy, index)[0] for index in range(3)
    ]
    return policy, build_certified_release(validated, receipts, policy=policy)


def test_exact_intent_is_bound_to_release_and_closed_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    publisher = material.anchor_intents[0].publisher_hotkey
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=publisher,
    )
    assert loaded.operation.operation == "publisher_pool_anchor"
    assert loaded.operation.request.anchor_kind == "publisher_pool"
    assert loaded.operation.request.call == "Commitments.set_commitment"
    assert loaded.operation.request.field.type_ == "Data::Sha256"
    assert loaded.operation.request.field.sha256 == loaded.intent.pool_manifest_sha256
    assert loaded.binding.field_count == 1
    assert loaded.binding.weight_submission_capability is False


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("wrong_publisher", "configured_publisher_intent_missing"),
        ("changed_intent", "anchor_intents_release_mismatch"),
        ("changed_release", "anchor_intents_release_mismatch"),
        ("active_policy", "pool_anchor_requires_shadow_policy"),
    ],
)
def test_binding_rejects_wrong_or_changed_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    reason: str,
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    publisher = material.anchor_intents[0].publisher_hotkey
    policy_bytes = canonical_json_bytes(policy)
    release_bytes = material.release_bytes
    intents_bytes = material.anchor_intents_bytes
    if mutation == "wrong_publisher":
        publisher = dev_wallet("//WrongPublisher").hotkey.ss58_address
    elif mutation == "changed_intent":
        document = json.loads(intents_bytes)
        document[0]["closing_block"] += 1
        intents_bytes = canonical_json_bytes(document)
    elif mutation == "changed_release":
        document = material.release.model_copy(update={"anchor_intents_sha256": "11" * 32})
        release_bytes = canonical_json_bytes(document)
    else:
        policy_bytes = canonical_json_bytes(
            policy.model_copy(update={"translation_weights_active": True})
        )
    with pytest.raises(PublisherPoolAnchorError, match=reason):
        load_pool_anchor_material(
            policy_bytes=policy_bytes,
            certified_release_bytes=release_bytes,
            anchor_intents_bytes=intents_bytes,
            configured_publisher_hotkey=publisher,
        )


def test_reordered_intents_are_rejected_even_with_matching_release_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    reversed_bytes = canonical_json_bytes(
        [item.model_dump(mode="json", by_alias=True) for item in reversed(material.anchor_intents)]
    )
    release = material.release.model_copy(
        update={"anchor_intents_sha256": __import__("hashlib").sha256(reversed_bytes).hexdigest()}
    )
    with pytest.raises(PublisherPoolAnchorError, match="anchor_intents_order_invalid"):
        load_pool_anchor_material(
            policy_bytes=canonical_json_bytes(policy),
            certified_release_bytes=canonical_json_bytes(release),
            anchor_intents_bytes=reversed_bytes,
            configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
        )


def test_check_and_dry_run_do_not_write_sign_or_broadcast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    paths = {}
    for name, raw in {
        "policy": canonical_json_bytes(policy),
        "release": material.release_bytes,
        "intents": material.anchor_intents_bytes,
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        paths[name] = path
    before = sorted(item.relative_to(tmp_path) for item in tmp_path.rglob("*"))
    args = [
        "--policy",
        str(paths["policy"]),
        "--certified-release",
        str(paths["release"]),
        "--anchor-intents",
        str(paths["intents"]),
        "--publisher-hotkey",
        material.anchor_intents[0].publisher_hotkey,
    ]
    assert run_cli([*args, "--check"]) == 0
    assert run_cli([*args, "--dry-run"]) == 0
    after = sorted(item.relative_to(tmp_path) for item in tmp_path.rglob("*"))
    assert after == before
    output = capsys.readouterr().out
    assert '"broadcast_performed":false' in output
    assert '"writes_performed":false' in output
    source = inspect.getsource(__import__("umi.publisher_pool_anchor_cli", fromlist=["*"]))
    assert "set_weights" not in source
    assert "commit_timelocked" not in source
    assert "submit_signature" not in source


def test_execute_requires_both_narrow_acknowledgements_before_client_or_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    paths = {}
    for name, raw in {
        "policy": canonical_json_bytes(policy),
        "release": material.release_bytes,
        "intents": material.anchor_intents_bytes,
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        paths[name] = path

    def forbidden_client(_network):
        raise AssertionError("client must not be created before acknowledgement")

    result = run_cli(
        [
            "--policy",
            str(paths["policy"]),
            "--certified-release",
            str(paths["release"]),
            "--anchor-intents",
            str(paths["intents"]),
            "--publisher-hotkey",
            material.anchor_intents[0].publisher_hotkey,
            "--execute",
        ],
        client_factory=forbidden_client,
    )
    assert result == 2
    assert not (tmp_path / "publisher-anchor").exists()


def test_unexpected_execution_failure_is_stable_json_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    paths = {}
    for name, raw in {
        "policy": canonical_json_bytes(policy),
        "release": material.release_bytes,
        "intents": material.anchor_intents_bytes,
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        paths[name] = path
    loaded = load_pool_anchor_material(
        policy_bytes=paths["policy"].read_bytes(),
        certified_release_bytes=paths["release"].read_bytes(),
        anchor_intents_bytes=paths["intents"].read_bytes(),
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    config = PublisherPoolAnchorOperatorConfig(
        schema=OPERATOR_CONFIG_SCHEMA,
        protocol="umi-asl/0.1",
        network="finney",
        publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
        wallet_name="umi",
        wallet_hotkey_name="publisher",
        wallet_path=str(tmp_path / "wallets"),
        state_root=str(tmp_path / "state"),
        target_triple="aarch64-apple-darwin",
        storage_proof_verifier_binary=str(tmp_path / "proof"),
        finality_verifier_binary=str(tmp_path / "finality"),
        finality_chain_spec_path=str(tmp_path / "chain.json"),
        maximum_advances=1,
        poll_seconds=1,
        translation_weights_active=False,
        weight_submission_capability=False,
    )
    config_path = tmp_path / "operator.json"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o600)

    async def boom(*_args, **_kwargs):
        raise RuntimeError("secret details")

    monkeypatch.setattr("umi.publisher_pool_anchor_cli._execute", boom)
    result = run_cli(
        [
            "--policy",
            str(paths["policy"]),
            "--certified-release",
            str(paths["release"]),
            "--anchor-intents",
            str(paths["intents"]),
            "--publisher-hotkey",
            loaded.intent.publisher_hotkey,
            "--operator-config",
            str(config_path),
            "--execute",
            "--acknowledgement",
            EXECUTION_ACKNOWLEDGEMENT,
            "--ack-operation-id",
            loaded.operation.operation_id,
        ]
    )
    assert result == 2
    error = capsys.readouterr().err
    assert '"reason_code":"pool_anchor_execution_failed"' in error
    assert '"broadcast_performed":"unknown"' in error
    assert "secret details" not in error
    assert "Traceback" not in error


def test_intent_cannot_claim_weight_or_broadcast_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy, material = _material(tmp_path, monkeypatch)
    document = material.anchor_intents[0].model_dump(mode="json", by_alias=True)
    document["weight_submission_capability"] = True
    with pytest.raises(ValidationError):
        type(material.anchor_intents[0]).model_validate(document)


class _StopJournal:
    def load(self, _operation):
        return None

    def history(self, _operation):
        return ()

    async def advance(self, *_args, **_kwargs):
        raise RuntimeError("journal_reached")


class _AnchorPorts:
    def __init__(self, signer: bytes):
        self.signer_account_id32 = signer
        self.submit_calls = 0

    def for_operation(self, _operation):
        async def submit(_unsigned, _signature):
            self.submit_calls += 1
            return object()

        return ExtrinsicPorts(
            prepare=lambda _operation: object(),
            verify_prepared_call=lambda _operation, _unsigned: object(),
            sign=lambda _payload, _operation_id: b"0" * 64,
            submit=submit,
            reconcile=lambda _query: object(),
        )


class _UnusedClosing:
    async def prove_closing_anchor(self, _intent, _entry):
        raise AssertionError("closing proof must follow finalized success")


class _FinalEntry:
    state = ExtrinsicState.FINALIZED_SUCCESS
    receipt_sha256 = "55" * 32

    def __init__(self, closing_block: int):
        self.receipt = SimpleNamespace(
            era_birth_block=closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS,
            era_death_block=closing_block,
        )


class _FinalJournal:
    def __init__(self, closing_block: int):
        self.entry = _FinalEntry(closing_block)
        self.advance_calls = 0

    def load(self, _operation):
        return self.entry

    def history(self, _operation):
        return ()

    async def advance(self, operation, _ports, *, expected_operation_id):
        self.advance_calls += 1
        assert expected_operation_id == operation.operation_id
        return self.entry


class _FinalityHead:
    def __init__(self, *heights: int):
        self.heights = list(heights)
        self.calls = 0

    async def finalized_head_height(self) -> int:
        self.calls += 1
        if not self.heights:
            raise AssertionError("unexpected finalized-head read")
        if len(self.heights) == 1:
            return self.heights[0]
        return self.heights.pop(0)


class _StaticJournal:
    def __init__(
        self,
        state: ExtrinsicState | None,
        *,
        closing_block: int | None = None,
        result=None,
        invoke_submit=False,
        submit_unsigned=None,
    ):
        self.current = (
            None
            if state is None
            else SimpleNamespace(
                state=state,
                receipt=SimpleNamespace(
                    submission=None,
                    reason_code=None,
                    era_birth_block=(closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS),
                    era_death_block=closing_block,
                ),
            )
        )
        self.result = result
        self.invoke_submit = invoke_submit
        self.submit_unsigned = submit_unsigned
        self.advance_calls = 0

    def load(self, _operation):
        return self.current

    def history(self, _operation):
        return () if self.current is None else (self.current,)

    async def advance(self, operation, ports, *, expected_operation_id):
        self.advance_calls += 1
        assert expected_operation_id == operation.operation_id
        if self.invoke_submit:
            await ports.submit(self.submit_unsigned, b"0" * 64)
        return self.result


def _publisher_unsigned(loaded, *, current: int) -> UnsignedExtrinsic:
    return UnsignedExtrinsic(
        call_data=b"\x01",
        address=loaded.intent.publisher_hotkey,
        public_key=bytes.fromhex(loaded.binding.publisher_account_id32),
        crypto_type=1,
        era={"period": POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS, "current": current},
        nonce=0,
        tip=0,
        tip_asset_id=None,
        genesis_hash="0x" + "11" * 32,
        era_block_hash="0x" + "22" * 32,
        spec_version=1,
        transaction_version=1,
        metadata_hash=None,
        payload=b"payload",
        payload_json={"method": "0x01"},
        included_in_extrinsic=b"",
        included_in_signed_data=b"",
    )


def test_late_first_execution_is_rejected_before_prepare_or_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    journal = _StaticJournal(None)
    last_safe = loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
    operator = PublisherPoolAnchorOperator(
        tmp_path / "late-first",
        journal=journal,  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=_FinalityHead(last_safe + 1),
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(PublisherPoolAnchorError, match="pool_anchor_submission_window_closed"):
        __import__("asyncio").run(operator.advance(loaded))
    assert journal.advance_calls == 0
    assert not (operator.root / "binding.json").exists()


def test_prepared_restart_cannot_sign_or_submit_after_submission_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    journal = _StaticJournal(
        ExtrinsicState.PREPARED,
        closing_block=loaded.intent.closing_block,
    )
    operator = PublisherPoolAnchorOperator(
        tmp_path / "late-prepared",
        journal=journal,  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=_FinalityHead(loaded.intent.closing_block),
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(PublisherPoolAnchorError, match="pool_anchor_submission_window_closed"):
        __import__("asyncio").run(operator.advance(loaded))
    assert journal.advance_calls == 0


def test_prepared_anchor_with_mortal_era_past_close_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    journal = _StaticJournal(
        ExtrinsicState.PREPARED,
        closing_block=loaded.intent.closing_block,
    )
    journal.current.receipt.era_birth_block = loaded.intent.closing_block - 4
    journal.current.receipt.era_death_block = loaded.intent.closing_block + 60
    finality = _FinalityHead()
    operator = PublisherPoolAnchorOperator(
        tmp_path / "long-era",
        journal=journal,  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=finality,
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(PublisherPoolAnchorError, match="pool_anchor_mortal_era_exceeds_close"):
        __import__("asyncio").run(operator.advance(loaded))
    assert journal.advance_calls == 0
    assert finality.calls == 0


def test_publisher_mortal_era_is_exclusively_dead_at_closing_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    last_safe = loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
    birth, death = mortal_era_bounds(_publisher_unsigned(loaded, current=last_safe))
    assert birth == last_safe
    assert death == loaded.intent.closing_block
    assert loaded.binding.mortal_era_period_blocks == 4
    assert loaded.binding.last_safe_finalized_height == last_safe


def test_deadline_is_rechecked_immediately_before_network_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    last_safe = loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
    journal = _StaticJournal(
        None,
        invoke_submit=True,
        submit_unsigned=_publisher_unsigned(loaded, current=last_safe),
    )
    anchor_ports = _AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32))
    operator = PublisherPoolAnchorOperator(
        tmp_path / "deadline-race",
        journal=journal,  # type: ignore[arg-type]
        anchor_ports=anchor_ports,
        submission_finality=_FinalityHead(last_safe, last_safe + 1),
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(PublisherPoolAnchorError, match="pool_anchor_submission_window_closed"):
        __import__("asyncio").run(operator.advance(loaded))
    assert journal.advance_calls == 1
    assert anchor_ports.submit_calls == 0


def test_submitted_restart_can_reconcile_after_submission_window_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    journal = _StaticJournal(
        ExtrinsicState.SUBMITTED,
        closing_block=loaded.intent.closing_block,
        result=_FinalEntry(loaded.intent.closing_block),
    )
    finality = _FinalityHead(loaded.intent.closing_block)
    operator = PublisherPoolAnchorOperator(
        tmp_path / "submitted-restart",
        journal=journal,  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=finality,
        closing_proofs=_Closing(),
    )
    result = __import__("asyncio").run(operator.advance(loaded))
    assert isinstance(result, PoolAnchorEvidence)
    assert journal.advance_calls == 1
    assert finality.calls == 1


class _Closing:
    def __init__(self):
        self.calls = 0

    async def prove_closing_anchor(self, intent, _entry):
        self.calls += 1
        return ClosingAnchorEvidence(
            closing_block=intent.closing_block,
            closing_block_hash="0x" + "11" * 32,
            finality_evidence_sha256="22" * 32,
            pallet="Commitments",
            storage_item="CommitmentOf",
            netuid=78,
            publisher_hotkey=intent.publisher_hotkey,
            field_count=1,
            field_type="Data::Sha256",
            field_sha256=intent.pool_manifest_sha256,
            storage_key_hex="0x01",
            storage_value_hex="0x01",
            storage_proof_sha256="44" * 32,
            proof_verified=True,
        )


class _ClosingFailure:
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        self.calls = 0

    async def prove_closing_anchor(self, _intent, _entry):
        self.calls += 1
        raise PublisherPoolAnchorError(self.reason_code)


def test_early_finalized_inclusion_is_durable_pending_until_closing_finality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    state = tmp_path / "early-inclusion"
    signer = bytes.fromhex(loaded.binding.publisher_account_id32)
    first_closing = _Closing()
    first_journal = _FinalJournal(loaded.intent.closing_block)
    first = PublisherPoolAnchorOperator(
        state,
        journal=first_journal,  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(signer),
        submission_finality=_FinalityHead(loaded.intent.closing_block - 1),
        closing_proofs=first_closing,
    )

    pending = __import__("asyncio").run(first.advance(loaded))

    assert pending == PoolAnchorPending(
        reason_code="closing_finality_pending",
        operation_id=loaded.operation.operation_id,
        binding_sha256=__import__("hashlib").sha256(loaded.binding_bytes).hexdigest(),
        final_receipt_sha256="55" * 32,
        closing_block=loaded.intent.closing_block,
        observed_finalized_height=loaded.intent.closing_block - 1,
    )
    assert first_journal.advance_calls == 0
    assert first_closing.calls == 0
    assert (state / "binding.json").read_bytes() == loaded.binding_bytes
    assert not (state / "evidence.json").exists()

    restarted_closing = _Closing()
    restarted_journal = _FinalJournal(loaded.intent.closing_block)
    restarted = PublisherPoolAnchorOperator(
        state,
        journal=restarted_journal,  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(signer),
        submission_finality=_FinalityHead(
            loaded.intent.closing_block - 1,
            loaded.intent.closing_block,
        ),
        closing_proofs=restarted_closing,
    )
    replayed_pending = __import__("asyncio").run(restarted.advance(loaded))
    completed = __import__("asyncio").run(restarted.advance(loaded))

    assert replayed_pending == pending
    assert isinstance(completed, PoolAnchorEvidence)
    assert restarted_journal.advance_calls == 0
    assert restarted_closing.calls == 1
    assert (state / "evidence.json").read_bytes() == canonical_json_bytes(completed)


def test_closing_proof_failure_is_terminal_only_after_closing_height(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    closing = _ClosingFailure("closing_proof_mismatch")
    operator = PublisherPoolAnchorOperator(
        tmp_path / "proof-failure",
        journal=_FinalJournal(loaded.intent.closing_block),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=_FinalityHead(
            loaded.intent.closing_block - 1,
            loaded.intent.closing_block,
        ),
        closing_proofs=closing,
    )

    pending = __import__("asyncio").run(operator.advance(loaded))
    assert isinstance(pending, PoolAnchorPending)
    assert closing.calls == 0
    with pytest.raises(PublisherPoolAnchorError, match="closing_proof_mismatch"):
        __import__("asyncio").run(operator.advance(loaded))
    assert closing.calls == 1


def test_cli_pending_polls_do_not_consume_journal_advance_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    completed = __import__("asyncio").run(
        PublisherPoolAnchorOperator(
            tmp_path / "completed",
            journal=_FinalJournal(loaded.intent.closing_block),  # type: ignore[arg-type]
            anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
            submission_finality=_FinalityHead(loaded.intent.closing_block),
            closing_proofs=_Closing(),
        ).advance(loaded)
    )
    assert isinstance(completed, PoolAnchorEvidence)
    pending = PoolAnchorPending(
        reason_code="closing_finality_pending",
        operation_id=loaded.operation.operation_id,
        binding_sha256=__import__("hashlib").sha256(loaded.binding_bytes).hexdigest(),
        final_receipt_sha256="55" * 32,
        closing_block=loaded.intent.closing_block,
        observed_finalized_height=loaded.intent.closing_block - 1,
    )

    class _SequenceOperator:
        def __init__(self):
            self.results = [pending, pending, pending, completed]
            self.calls = 0

        async def advance(self, _loaded):
            result = self.results[self.calls]
            self.calls += 1
            return result

    sleeps: list[float] = []

    async def no_wait(seconds: float) -> None:
        sleeps.append(seconds)

    sequence = _SequenceOperator()
    result = __import__("asyncio").run(
        _advance_until_terminal(
            sequence,  # type: ignore[arg-type]
            loaded,
            maximum_advances=1,
            poll_seconds=0.25,
            sleep=no_wait,
        )
    )

    assert result == completed
    assert sequence.calls == 4
    assert sleeps == [0.25, 0.25, 0.25]


def test_fake_ports_complete_and_replay_exact_terminal_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    state = tmp_path / "anchor-state"
    signer = bytes.fromhex(loaded.binding.publisher_account_id32)
    first = PublisherPoolAnchorOperator(
        state,
        journal=_FinalJournal(loaded.intent.closing_block),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(signer),
        submission_finality=_FinalityHead(loaded.intent.closing_block),
        closing_proofs=_Closing(),
    )
    result = __import__("asyncio").run(first.advance(loaded))
    assert isinstance(result, PoolAnchorEvidence)
    assert (state / "evidence.json").read_bytes() == canonical_json_bytes(result)
    restarted = PublisherPoolAnchorOperator(
        state,
        journal=_FinalJournal(loaded.intent.closing_block),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(signer),
        submission_finality=_FinalityHead(loaded.intent.closing_block),
        closing_proofs=_Closing(),
    )
    assert __import__("asyncio").run(restarted.advance(loaded)) == result
    (state / "evidence.json").write_bytes(b"{}")
    with pytest.raises(PublisherPoolAnchorError, match="pool_anchor_evidence_tampered"):
        __import__("asyncio").run(restarted.advance(loaded))


def test_durable_window_claim_survives_restart_and_blocks_changed_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    state = tmp_path / "anchor-state"
    operator = PublisherPoolAnchorOperator(
        state,
        journal=_StopJournal(),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=_FinalityHead(
            loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
        ),
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(RuntimeError, match="journal_reached"):
        __import__("asyncio").run(operator.advance(loaded))
    restarted = PublisherPoolAnchorOperator(
        state,
        journal=_StopJournal(),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=_FinalityHead(
            loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
        ),
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(RuntimeError, match="journal_reached"):
        __import__("asyncio").run(restarted.advance(loaded))
    changed_binding = loaded.binding.model_copy(update={"certified_release_sha256": "44" * 32})
    changed = replace(
        loaded,
        binding=changed_binding,
        binding_bytes=canonical_json_bytes(changed_binding),
    )
    with pytest.raises(PublisherPoolAnchorError, match="pool_anchor_equivocation"):
        __import__("asyncio").run(restarted.advance(changed))


def test_wrong_signer_is_rejected_before_state_or_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    state = tmp_path / "anchor-state"
    operator = PublisherPoolAnchorOperator(
        state,
        journal=_StopJournal(),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(b"z" * 32),
        submission_finality=_FinalityHead(0),
        closing_proofs=_UnusedClosing(),
    )
    with pytest.raises(PublisherPoolAnchorError, match="publisher_signer_mismatch"):
        __import__("asyncio").run(operator.advance(loaded))
    assert not (state / "binding.json").exists()


def test_exact_closing_proof_binding_rejects_changed_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, material = _material(tmp_path, monkeypatch)
    loaded = load_pool_anchor_material(
        policy_bytes=canonical_json_bytes(policy),
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        configured_publisher_hotkey=material.anchor_intents[0].publisher_hotkey,
    )
    operator = PublisherPoolAnchorOperator(
        tmp_path / "anchor-state",
        journal=_StopJournal(),  # type: ignore[arg-type]
        anchor_ports=_AnchorPorts(bytes.fromhex(loaded.binding.publisher_account_id32)),
        submission_finality=_FinalityHead(
            loaded.intent.closing_block - POOL_ANCHOR_SUBMISSION_HEADROOM_BLOCKS
        ),
        closing_proofs=_UnusedClosing(),
    )
    closing = ClosingAnchorEvidence(
        closing_block=loaded.intent.closing_block,
        closing_block_hash="0x" + "11" * 32,
        finality_evidence_sha256="22" * 32,
        pallet="Commitments",
        storage_item="CommitmentOf",
        netuid=78,
        publisher_hotkey=loaded.intent.publisher_hotkey,
        field_count=1,
        field_type="Data::Sha256",
        field_sha256="33" * 32,
        storage_key_hex="0x01",
        storage_value_hex="0x01",
        storage_proof_sha256="44" * 32,
        proof_verified=True,
    )
    with pytest.raises(PublisherPoolAnchorError, match="closing_proof_mismatch"):
        operator._validate_closing(loaded, closing)
