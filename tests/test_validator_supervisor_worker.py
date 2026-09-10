from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path

import pytest

from tests.factories import dev_wallet
from tests.test_bootstrap_direct_weights import (
    BLOCK_HASH,
    NOW,
    _operational,
    _permitted_case,
    _preflight,
    _snapshot,
)
from tests.test_observer_bootstrap_service_feed import _terminal_records
from umi import validator_supervisor_worker as worker_module
from umi.bootstrap_direct_weights import (
    DIRECT_SUBMISSION_JOURNAL_SCHEMA,
    DIRECT_TRANSITION_PROFILE,
    DirectBootstrapSubmissionJournal,
    build_direct_bootstrap_call_material,
    classify_direct_bootstrap_application,
    validate_direct_bootstrap_preflight,
)
from umi.bootstrap_weight_operator import (
    BootstrapExtrinsicReference,
    BootstrapManifestAnchorObservation,
    BootstrapOperatorError,
)
from umi.encoding import account_id32
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_adapters import OwnedFinalizedBlock, SupervisorReleaseManifest
from umi.validator_supervisor_publication import (
    parse_canonical_signed_supervisor_bootstrap_result,
)
from umi.validator_supervisor_worker import (
    WORKER_JOURNAL_SCHEMA,
    SupervisorBootstrapPublicationReceipt,
    SupervisorWorkerEnvironment,
    SupervisorWorkerError,
    SupervisorWorkerJournal,
    run_bootstrap_worker,
)

_PRODUCTION_RESULT_PUBLISHER = worker_module._publish_completed_bootstrap_result


@pytest.fixture(autouse=True)
def _isolate_result_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    async def skip_publication(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(
        worker_module,
        "_publish_completed_bootstrap_result",
        skip_publication,
    )


class _FinalityReader:
    def __init__(self, *blocks: int | OwnedFinalizedBlock) -> None:
        self.blocks: asyncio.Queue[OwnedFinalizedBlock] = asyncio.Queue()
        if not blocks or not isinstance(blocks[0], OwnedFinalizedBlock):
            self.blocks.put_nowait(OwnedFinalizedBlock(125, BLOCK_HASH))
        for item in blocks:
            block = (
                item
                if isinstance(item, OwnedFinalizedBlock)
                else OwnedFinalizedBlock(item, "0x" + f"{item:064x}")
            )
            if block.number != 125 or self.blocks.empty():
                self.blocks.put_nowait(block)
        self.stopped = False

    async def read_finalized_identity(self) -> OwnedFinalizedBlock:
        return await self.blocks.get()

    async def stop(self) -> None:
        self.stopped = True


def _environment(
    validator_hotkey: str,
    *,
    policy_sha256: str,
    release_manifest_sha256: str,
    directive_sha256: str = "91" * 32,
    sequence: int = 2,
) -> SupervisorWorkerEnvironment:
    return SupervisorWorkerEnvironment(
        mode="bootstrap_service_weights",
        directive_sha256=directive_sha256,
        policy_sha256=policy_sha256,
        release_manifest_sha256=release_manifest_sha256,
        sequence=sequence,
        valid_from_block=125,
        valid_through_block=155,
        expected_validator_hotkey=validator_hotkey,
        wallet_hotkey_name="default",
    )


def _worker_files(tmp_path: Path, signed, authorization, drain):
    release_root = tmp_path / "release"
    input_root = tmp_path / "operator-inputs"
    state_root = tmp_path / "state"
    release_root.mkdir()
    (input_root / "bootstrap").mkdir(parents=True)
    state_root.mkdir(mode=0o700)
    release = SupervisorReleaseManifest(
        schema="umi-validator-supervisor-release-manifest/1",
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256="22" * 32,
        oci_archive_sha256="33" * 32,
        oci_archive_size_bytes=100,
        target_platform="linux/amd64",
        umi_git_revision=authorization.umi_git_revision,
        umi_source_tree_sha256="44" * 32,
        entrypoint_profile="umi-bootstrap-weight-validator/2",
        state_schema_minimum=1,
        state_schema_maximum=1,
    )
    release_bytes = canonical_json_bytes(release)
    release_path = release_root / "release-manifest.json"
    release_path.write_bytes(release_bytes)
    (input_root / "bootstrap" / "signed-manifest.json").write_bytes(canonical_json_bytes(signed))
    (input_root / "bootstrap" / "direct-transition-authorization.json").write_bytes(
        canonical_json_bytes(authorization)
    )
    (input_root / "bootstrap" / "drain-checkpoint.json").write_bytes(canonical_json_bytes(drain))
    revision_path = tmp_path / "image-revision"
    revision_path.write_text(authorization.umi_git_revision + "\n", encoding="ascii")
    return release_path, input_root, state_root, hashlib.sha256(release_bytes).hexdigest()


def _terminal_artifacts(
    signed,
    authorization,
    owner,
    participants,
    *,
    activity_cutoff_blocks: int = 360,
):
    anchor = BootstrapExtrinsicReference(
        extrinsic_id="126-0001",
        block_number=126,
        extrinsic_index=1,
        block_hash="0x" + "14" * 32,
    )
    anchor_observation = BootstrapManifestAnchorObservation(
        manifest_sha256=signed.manifest_sha256,
        anchor=anchor,
        observation_block=127,
        observation_block_hash="0x" + "15" * 32,
        stored_commitment_block=126,
        field_count=1,
        field_type="Data::Sha256",
        field_sha256=signed.manifest_sha256,
        sdk_finalized_read_verified=True,
        storage_proofs_verified=False,
    )
    preflight = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(
            participants,
            block_number=127,
            block_hash="0x" + "15" * 32,
            blocks_since_last_step=27,
            activity_cutoff_blocks=activity_cutoff_blocks,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=authorization.validator_hotkey,
        now=NOW,
    )
    material, _call = build_direct_bootstrap_call_material(
        _operational(signed, preflight), manifest_anchor=anchor_observation
    )
    weight_call = BootstrapExtrinsicReference(
        extrinsic_id="130-0002",
        block_number=130,
        extrinsic_index=2,
        block_hash="0x" + "16" * 32,
    )
    updated = [
        item.model_copy(update={"last_update": 130})
        if item.uid == authorization.validator_uid
        else item
        for item in participants
    ]
    observed = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(
            updated,
            block_number=130,
            block_hash="0x" + "13" * 32,
            validator_mechid0_row=material.expected_applied_row,
            active_mechid0_row_hotkeys=[authorization.validator_hotkey],
            blocks_since_last_step=30,
            activity_cutoff_blocks=activity_cutoff_blocks,
        ),
        authorization=authorization,
        subnet_owner_hotkey=owner.hotkey.ss58_address,
        validator_hotkey=authorization.validator_hotkey,
        now=NOW,
        require_submission_ready=False,
    )
    receipt = classify_direct_bootstrap_application(
        material,
        anchor=anchor,
        weight_call=weight_call,
        observation=observed,
        created_at=NOW,
    )
    return material, receipt


def _write_terminal_outputs(outputs, authorization, material, receipt) -> None:
    outputs.call_material.write_bytes(canonical_json_bytes(material))
    outputs.receipt.write_bytes(canonical_json_bytes(receipt))
    outputs.operator_state.mkdir(mode=0o700, exist_ok=True)
    authorization_sha256 = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
    direct_journal = DirectBootstrapSubmissionJournal(
        schema=DIRECT_SUBMISSION_JOURNAL_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        submission_id=authorization.submission_id,
        phase="applied",
        manifest_sha256=receipt.manifest_sha256,
        transition_authorization_sha256=authorization_sha256,
        validator_hotkey=receipt.validator_hotkey,
        anchor=receipt.anchor,
        call_material_sha256=receipt.call_material_sha256,
        weight_call=receipt.weight_call,
        receipt_sha256=hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        updated_at=NOW,
    )
    journal_path = outputs.operator_state / (
        f"direct-{authorization_sha256}-{account_id32(receipt.validator_hotkey).hex()}.json"
    )
    journal_path.write_bytes(canonical_json_bytes(direct_journal))


@pytest.mark.asyncio
async def test_direct_worker_completes_once_and_reboot_recovers_without_retry(
    tmp_path: Path,
) -> None:
    signed, authorization, owner, participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    material, receipt = _terminal_artifacts(signed, authorization, owner, participants)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    environment = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    calls = 0

    async def preflighter(*_args):
        return drain

    async def submitter(
        _inputs,
        _environment,
        outputs,
        _wallet,
        before_first_effect,
        finalized_snapshot_guard,
    ):
        nonlocal calls
        calls += 1
        await finalized_snapshot_guard(
            drain.chain.snapshot.block_number,
            drain.chain.snapshot.block_hash,
            16,
        )
        before_first_effect()
        _write_terminal_outputs(outputs, authorization, material, receipt)
        return receipt

    first = await run_bootstrap_worker(
        environment,
        release_manifest_path=release,
        operator_input_root=inputs,
        state_root=state,
        image_revision_path=tmp_path / "image-revision",
        finality_reader=_FinalityReader(126),
        wallet_loader=lambda _environment: owner,
        preflighter=preflighter,
        submitter=submitter,
        remain_until_expiry=False,
    )
    assert first.phase == "completed"
    assert calls == 1

    transaction = state / "bootstrap-transactions" / environment.directive_sha256
    interrupted = first.model_copy(
        update={
            "phase": "effect_intent",
            "receipt_sha256": None,
            "call_material_sha256": None,
        }
    )
    (transaction / "journal.json").chmod(0o600)
    (transaction / "journal.json").write_bytes(canonical_json_bytes(interrupted))
    (transaction / "journal.json").chmod(0o400)

    second = await run_bootstrap_worker(
        environment,
        release_manifest_path=release,
        operator_input_root=inputs,
        state_root=state,
        image_revision_path=tmp_path / "image-revision",
        finality_reader=_FinalityReader(131),
        wallet_loader=lambda _environment: owner,
        preflighter=preflighter,
        submitter=submitter,
        remain_until_expiry=False,
    )
    assert second.phase == "completed"
    assert calls == 1
    assert os.stat(transaction / "journal.json").st_mode & 0o077 == 0

    (transaction / "submission-receipt.json").write_bytes(b"{}")
    with pytest.raises(SupervisorWorkerError, match="worker_completed_state_invalid"):
        await run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(132),
            wallet_loader=lambda _environment: owner,
            preflighter=preflighter,
            submitter=submitter,
            remain_until_expiry=False,
        )
    assert calls == 1


@pytest.mark.asyncio
async def test_direct_worker_accepts_a_target_bound_nonowner_validator(
    tmp_path: Path,
) -> None:
    signed, authorization, owner, validator, participants, preflight = _permitted_case()
    drain = _operational(signed, preflight)
    material, receipt = _terminal_artifacts(
        signed,
        authorization,
        owner,
        participants,
        activity_cutoff_blocks=360,
    )
    release, inputs, state, release_sha256 = _worker_files(
        tmp_path,
        signed,
        authorization,
        drain,
    )
    environment = _environment(
        validator.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )

    async def preflighter(*_args):
        return drain

    async def submitter(
        _inputs,
        _environment,
        outputs,
        _wallet,
        before_first_effect,
        finalized_snapshot_guard,
    ):
        await finalized_snapshot_guard(
            drain.chain.snapshot.block_number,
            drain.chain.snapshot.block_hash,
            16,
        )
        before_first_effect()
        _write_terminal_outputs(outputs, authorization, material, receipt)
        return receipt

    result = await run_bootstrap_worker(
        environment,
        release_manifest_path=release,
        operator_input_root=inputs,
        state_root=state,
        image_revision_path=tmp_path / "image-revision",
        finality_reader=_FinalityReader(126),
        wallet_loader=lambda _environment: validator,
        preflighter=preflighter,
        submitter=submitter,
        remain_until_expiry=False,
    )

    assert result.phase == "completed"
    assert receipt.validator_uid == 200
    assert receipt.validator_hotkey == validator.hotkey.ss58_address


@pytest.mark.asyncio
async def test_completed_worker_persists_and_retries_terminal_result_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        owner_fence,
        signed,
        authorization,
        material,
        receipt,
        _direct_journal,
        _owner,
        _participants,
    ) = _terminal_records(permitted=True)
    validator = dev_wallet("//DirectBootstrapPermittedValidator")
    drain = material.operational_preflight
    release, inputs, state, release_sha256 = _worker_files(
        tmp_path,
        signed,
        authorization,
        drain,
    )
    (inputs / "bootstrap" / "owner-fence-receipt.json").write_bytes(
        canonical_json_bytes(owner_fence)
    )
    environment = _environment(
        validator.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    secret_path = tmp_path / "bootstrap-result-upload.key"
    secret_path.write_text("41" * 32 + "\n", encoding="ascii")
    secret_path.chmod(0o600)
    chain_calls = 0
    upload_bodies: list[bytes] = []

    async def preflighter(*_args):
        return drain

    async def submitter(
        _inputs,
        _environment,
        outputs,
        _wallet,
        before_first_effect,
        finalized_snapshot_guard,
    ):
        nonlocal chain_calls
        chain_calls += 1
        await finalized_snapshot_guard(
            drain.chain.snapshot.block_number,
            drain.chain.snapshot.block_hash,
            16,
        )
        before_first_effect()
        _write_terminal_outputs(outputs, authorization, material, receipt)
        return receipt

    def uploader(body: bytes, **kwargs):
        upload_bodies.append(body)
        assert kwargs == {
            "submission_id": authorization.submission_id,
            "upload_origin": worker_module.WORKER_BOOTSTRAP_RESULT_UPLOAD_ORIGIN,
            "public_origin": worker_module.WORKER_BOOTSTRAP_RESULT_PUBLIC_ORIGIN,
            "secret": b"A" * 32,
        }
        if len(upload_bodies) == 1:
            raise RuntimeError("transient upload failure")
        digest = hashlib.sha256(body).hexdigest()
        return (
            digest,
            len(body),
            f"{worker_module.WORKER_BOOTSTRAP_RESULT_PUBLIC_ORIGIN}"
            f"/validator-bootstrap-results/{authorization.submission_id}.json",
        )

    monkeypatch.setattr(
        worker_module,
        "_publish_completed_bootstrap_result",
        _PRODUCTION_RESULT_PUBLISHER,
    )
    monkeypatch.setattr(
        worker_module,
        "WORKER_BOOTSTRAP_RESULT_UPLOAD_SECRET",
        secret_path,
    )
    monkeypatch.setattr(worker_module, "upload_validator_bootstrap_result", uploader)
    finalized = OwnedFinalizedBlock(
        drain.chain.snapshot.block_number,
        drain.chain.snapshot.block_hash,
    )
    common = {
        "release_manifest_path": release,
        "operator_input_root": inputs,
        "state_root": state,
        "image_revision_path": tmp_path / "image-revision",
        "wallet_loader": lambda _environment: validator,
        "preflighter": preflighter,
        "submitter": submitter,
        "remain_until_expiry": False,
    }

    with pytest.raises(SupervisorWorkerError, match="worker_result_publication_failed"):
        await run_bootstrap_worker(
            environment,
            finality_reader=_FinalityReader(finalized),
            **common,
        )
    transaction = state / "bootstrap-transactions" / environment.directive_sha256
    journal = SupervisorWorkerJournal.model_validate_json(
        (transaction / "journal.json").read_bytes()
    )
    assert journal.phase == "completed"
    assert chain_calls == 1
    assert len(upload_bodies) == 1
    signed_result_path = transaction / "signed-bootstrap-result.json"
    signed_result_bytes = signed_result_path.read_bytes()
    signed_result = parse_canonical_signed_supervisor_bootstrap_result(signed_result_bytes)
    assert signed_result.result.directive_sha256 == environment.directive_sha256
    assert signed_result.result.submission_id == authorization.submission_id
    assert signed_result.signer_hotkey == validator.hotkey.ss58_address
    assert not (transaction / "publication-receipt.json").exists()

    second = await run_bootstrap_worker(
        environment,
        finality_reader=_FinalityReader(finalized),
        **common,
    )
    assert second.phase == "completed"
    assert chain_calls == 1
    assert upload_bodies == [signed_result_bytes, signed_result_bytes]
    publication_path = transaction / "publication-receipt.json"
    publication_bytes = publication_path.read_bytes()
    publication = SupervisorBootstrapPublicationReceipt.model_validate_json(publication_bytes)
    assert publication_bytes == canonical_json_bytes(publication)
    assert publication.signed_result_sha256 == hashlib.sha256(signed_result_bytes).hexdigest()

    third = await run_bootstrap_worker(
        environment,
        finality_reader=_FinalityReader(finalized),
        **common,
    )
    assert third.phase == "completed"
    assert chain_calls == 1
    assert len(upload_bodies) == 2


@pytest.mark.asyncio
async def test_transition_authorization_is_single_use_across_directives(tmp_path: Path) -> None:
    signed, authorization, owner, participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    material, receipt = _terminal_artifacts(signed, authorization, owner, participants)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    first = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    calls = 0

    async def submitter(
        _inputs,
        _environment,
        outputs,
        _wallet,
        before_first_effect,
        finalized_snapshot_guard,
    ):
        nonlocal calls
        calls += 1
        await finalized_snapshot_guard(
            drain.chain.snapshot.block_number,
            drain.chain.snapshot.block_hash,
            16,
        )
        before_first_effect()
        _write_terminal_outputs(outputs, authorization, material, receipt)
        return receipt

    async def preflighter(*_args):
        return drain

    await run_bootstrap_worker(
        first,
        release_manifest_path=release,
        operator_input_root=inputs,
        state_root=state,
        image_revision_path=tmp_path / "image-revision",
        finality_reader=_FinalityReader(126),
        wallet_loader=lambda _environment: owner,
        preflighter=preflighter,
        submitter=submitter,
        remain_until_expiry=False,
    )

    second = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
        directive_sha256="92" * 32,
        sequence=3,
    )
    with pytest.raises(
        SupervisorWorkerError,
        match="worker_transition_authorization_already_claimed",
    ):
        await run_bootstrap_worker(
            second,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(126),
            wallet_loader=lambda _environment: owner,
            preflighter=preflighter,
            submitter=submitter,
            remain_until_expiry=False,
        )
    assert calls == 1
    assert len(list((state / "bootstrap-authorizations").glob("claim-*.json"))) == 1


@pytest.mark.asyncio
async def test_inner_read_only_failure_remains_retryable_until_effect_intent(
    tmp_path: Path,
) -> None:
    signed, authorization, owner, participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    material, receipt = _terminal_artifacts(signed, authorization, owner, participants)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    environment = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    calls = 0

    async def submitter(
        _inputs,
        _environment,
        outputs,
        _wallet,
        before_first_effect,
        _finalized_snapshot_guard,
    ):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise BootstrapOperatorError("synthetic_read_only_preflight_failed")
        before_first_effect()
        _write_terminal_outputs(outputs, authorization, material, receipt)
        return receipt

    async def preflighter(*_args):
        return drain

    arguments = dict(
        release_manifest_path=release,
        operator_input_root=inputs,
        state_root=state,
        image_revision_path=tmp_path / "image-revision",
        wallet_loader=lambda _environment: owner,
        preflighter=preflighter,
        submitter=submitter,
        remain_until_expiry=False,
    )
    with pytest.raises(SupervisorWorkerError, match="synthetic_read_only_preflight_failed"):
        await run_bootstrap_worker(
            environment,
            finality_reader=_FinalityReader(126),
            **arguments,
        )
    transaction = state / "bootstrap-transactions" / environment.directive_sha256
    journal = SupervisorWorkerJournal.model_validate_json(
        (transaction / "journal.json").read_bytes(), strict=True
    )
    assert journal.phase == "prepared"
    assert not list((state / "bootstrap-authorizations").glob("claim-*.json"))

    result = await run_bootstrap_worker(
        environment,
        finality_reader=_FinalityReader(126),
        **arguments,
    )
    assert result.phase == "completed"
    assert calls == 2


@pytest.mark.asyncio
async def test_direct_worker_expiry_marks_inflight_ambiguous_and_never_retries(
    tmp_path: Path,
) -> None:
    signed, authorization, owner, _participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    environment = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    started = asyncio.Event()
    calls = 0

    async def preflighter(*_args):
        return drain

    async def interrupted(
        _inputs,
        _environment,
        _outputs,
        _wallet,
        before_first_effect,
        finalized_snapshot_guard,
    ):
        nonlocal calls
        calls += 1
        await finalized_snapshot_guard(
            drain.chain.snapshot.block_number,
            drain.chain.snapshot.block_hash,
            16,
        )
        before_first_effect()
        started.set()
        await asyncio.Event().wait()

    finality = _FinalityReader(126)
    task = asyncio.create_task(
        run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=finality,
            wallet_loader=lambda _environment: owner,
            preflighter=preflighter,
            submitter=interrupted,
            remain_until_expiry=False,
        )
    )
    await started.wait()
    finality.blocks.put_nowait(OwnedFinalizedBlock(155, "0x" + f"{155:064x}"))
    with pytest.raises(SupervisorWorkerError, match="worker_effect_ambiguous"):
        await task

    transaction = state / "bootstrap-transactions" / environment.directive_sha256
    journal = SupervisorWorkerJournal.model_validate_json(
        (transaction / "journal.json").read_bytes(), strict=True
    )
    assert journal.phase == "ambiguous"
    assert journal.reason_code == "directive_lease_expired"

    with pytest.raises(SupervisorWorkerError, match="worker_effect_ambiguous"):
        await run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(132),
            wallet_loader=lambda _environment: owner,
            preflighter=preflighter,
            submitter=interrupted,
            remain_until_expiry=False,
        )
    assert calls == 1


@pytest.mark.asyncio
async def test_direct_worker_rejects_wrong_wallet_before_effect(tmp_path: Path) -> None:
    signed, authorization, owner, _participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    environment = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    called = False

    async def submitter(*_args):
        nonlocal called
        called = True

    async def preflighter(*_args):
        return drain

    with pytest.raises(SupervisorWorkerError, match="worker_wallet_hotkey_mismatch"):
        await run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(126),
            wallet_loader=lambda _environment: dev_wallet("//WrongWorkerWallet"),
            preflighter=preflighter,
            submitter=submitter,
            remain_until_expiry=False,
        )
    assert not called


@pytest.mark.asyncio
async def test_direct_worker_rejects_fresh_state_ahead_of_owned_finality(
    tmp_path: Path,
) -> None:
    signed, authorization, owner, _participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    environment = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    ahead = drain.model_copy(
        update={
            "chain": drain.chain.model_copy(
                update={"snapshot": drain.chain.snapshot.model_copy(update={"block_number": 127})}
            )
        }
    )
    called = False

    async def preflighter(*_args):
        return ahead

    async def submitter(*_args):
        nonlocal called
        called = True

    with pytest.raises(SupervisorWorkerError, match="worker_drain_checkpoint_binding_mismatch"):
        await run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(126),
            wallet_loader=lambda _environment: owner,
            preflighter=preflighter,
            submitter=submitter,
            remain_until_expiry=False,
        )
    assert not called


@pytest.mark.asyncio
async def test_direct_worker_rejects_subnet_owner_rotation_after_drain_checkpoint(
    tmp_path: Path,
) -> None:
    signed, authorization, _owner, validator, participants, preflight = _permitted_case()
    drain = _operational(signed, preflight)
    release, inputs, state, release_sha256 = _worker_files(
        tmp_path,
        signed,
        authorization,
        drain,
    )
    environment = _environment(
        validator.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    new_owner = dev_wallet("//RotatedDirectBootstrapOwner")
    rotated = list(participants)
    rotated[0] = rotated[0].model_copy(update={"hotkey": new_owner.hotkey.ss58_address})
    fresh_chain = validate_direct_bootstrap_preflight(
        signed,
        _snapshot(rotated),
        authorization=authorization,
        subnet_owner_hotkey=new_owner.hotkey.ss58_address,
        validator_hotkey=validator.hotkey.ss58_address,
        now=NOW,
    )
    fresh = _operational(signed, fresh_chain)
    called = False

    async def preflighter(*_args):
        return fresh

    async def submitter(*_args):
        nonlocal called
        called = True

    with pytest.raises(SupervisorWorkerError, match="worker_drain_checkpoint_changed"):
        await run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(126),
            wallet_loader=lambda _environment: validator,
            preflighter=preflighter,
            submitter=submitter,
            remain_until_expiry=False,
        )
    assert not called


@pytest.mark.asyncio
async def test_direct_worker_rejects_sdk_snapshot_hash_not_owned_by_grandpa(
    tmp_path: Path,
) -> None:
    signed, authorization, owner, _participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    release, inputs, state, release_sha256 = _worker_files(tmp_path, signed, authorization, drain)
    environment = _environment(
        owner.hotkey.ss58_address,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256=release_sha256,
    )
    called = False

    async def submitter(*_args):
        nonlocal called
        called = True

    async def preflighter(*_args):
        return drain

    with pytest.raises(SupervisorWorkerError, match="worker_finality_snapshot_mismatch"):
        await run_bootstrap_worker(
            environment,
            release_manifest_path=release,
            operator_input_root=inputs,
            state_root=state,
            image_revision_path=tmp_path / "image-revision",
            finality_reader=_FinalityReader(OwnedFinalizedBlock(125, "0x" + "ff" * 32)),
            wallet_loader=lambda _environment: owner,
            preflighter=preflighter,
            submitter=submitter,
            remain_until_expiry=False,
        )
    assert not called


@pytest.mark.asyncio
async def test_shadow_and_translation_worker_modes_fail_closed() -> None:
    validator = dev_wallet("//UnsupportedSupervisorWorkerMode")
    for mode in ("inactive_shadow", "translation_weights", "hold"):
        environment = SupervisorWorkerEnvironment(
            mode=mode,
            directive_sha256="11" * 32,
            policy_sha256="22" * 32,
            release_manifest_sha256="33" * 32,
            sequence=2,
            valid_from_block=120,
            valid_through_block=200,
            expected_validator_hotkey=validator.hotkey.ss58_address,
            wallet_hotkey_name="default",
        )
        with pytest.raises(SupervisorWorkerError, match="worker_mode_unimplemented"):
            await run_bootstrap_worker(environment)


def test_worker_environment_accepts_only_the_fixed_container_contract() -> None:
    validator = dev_wallet("//SupervisorWorkerEnvironmentValidator")
    values = {
        "UMI_SUPERVISOR_DIRECTIVE_SHA256": "11" * 32,
        "UMI_SUPERVISOR_POLICY_SHA256": "22" * 32,
        "UMI_SUPERVISOR_SEQUENCE": "2",
        "UMI_SUPERVISOR_VALID_FROM_BLOCK": "120",
        "UMI_SUPERVISOR_VALID_THROUGH_BLOCK": "200",
        "UMI_RELEASE_MANIFEST_SHA256": "33" * 32,
        "UMI_NETWORK": "finney",
        "UMI_NETUID": "78",
        "UMI_MECHANISM_ID": "0",
        "UMI_WALLET_PATH": "/run/umi/wallets",
        "UMI_WALLET_NAME": "runtime",
        "UMI_WALLET_HOTKEY": "default",
        "UMI_EXPECTED_VALIDATOR_HOTKEY": validator.hotkey.ss58_address,
        "UMI_OPERATOR_INPUT_ROOT": "/run/umi/operator-inputs",
        "UMI_WORKER_STATE_ROOT": "/var/lib/umi-worker",
        "UMI_RELEASE_MANIFEST": "/run/umi/release/release-manifest.json",
    }
    result = SupervisorWorkerEnvironment.from_environ("run-bootstrap-service-weights", values)
    assert result.expected_validator_hotkey == validator.hotkey.ss58_address

    values["UMI_NETUID"] = "79"
    with pytest.raises(SupervisorWorkerError, match="worker_environment_invalid"):
        SupervisorWorkerEnvironment.from_environ("run-bootstrap-service-weights", values)


def test_supervisor_worker_image_is_fixed_immutable_and_owns_finality() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "deploy/linux-validator-supervisor-worker/Dockerfile").read_text()

    assert "rust:1.98.0-bookworm@sha256:" in dockerfile
    assert (
        "python:3.12.14-slim-bookworm@sha256:"
        "782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254"
    ) in dockerfile
    assert "ADD --checksum=sha256:f280b687" in dockerfile
    assert "/opt/umi/bin/umi-grandpa-finality-observer --conformance-self-test" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/umi-simple-bootstrap-validator"]' in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'vision.umi.entrypoint-profile="umi-simple-bootstrap-validator/1"' in dockerfile
    assert "linux/amd64|linux/arm64" in dockerfile
    assert 'test "${TARGETPLATFORM}" = "linux/amd64"' not in dockerfile


def test_supervisor_worker_image_sources_are_in_the_allowlisted_docker_context() -> None:
    root = Path(__file__).resolve().parents[1]
    patterns = (root / ".dockerignore").read_text().splitlines()
    required = (
        "!deploy/linux-validator-supervisor-worker/Dockerfile",
        "!rust/grandpa-finality-observer/Cargo.toml",
        "!rust/grandpa-finality-observer/Cargo.lock",
        "!rust/grandpa-finality-observer/build.rs",
        "!rust/grandpa-finality-observer/rust-toolchain.toml",
        "!rust/grandpa-finality-observer/src/**",
        "!rust/grandpa-finality-observer/fixtures/**",
        "!rust/grandpa-finality-observer/vendor/**",
    )

    assert all(item in patterns for item in required)
    assert patterns.index("!rust/grandpa-finality-observer/vendor/**") < patterns.index(
        "**/target/"
    )


def test_supervisor_worker_release_workflow_is_manual_pinned_and_artifact_only() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/validator-supervisor-worker-release.yml").read_text()

    assert "workflow_dispatch:" in workflow
    assert "contents: read" in workflow
    assert "ref: ${{ inputs.revision }}" in workflow
    assert "persist-credentials: false" in workflow
    assert workflow.count("platform: linux/amd64") == 1
    assert workflow.count("platform: linux/arm64") == 1
    assert "runner: ubuntu-24.04-arm" in workflow
    assert "--provenance=false" in workflow
    assert "type=oci,name=${IMAGE_TAG},dest=${ARCHIVE}" in workflow
    assert "oci_manifest_sha256" in workflow
    assert "oci_archive_sha256" in workflow
    assert "oci_archive_size_bytes" in workflow
    assert "/opt/umi/bin/umi-grandpa-finality-observer" in workflow
    assert 'docker cp "${container_id}:/usr/local/bin/uv"' in workflow
    assert '"uv 0.12.9"' in workflow
    assert "uv_sha256" in workflow
    assert "uv_size_bytes" in workflow
    assert "docker cp" in workflow
    assert "umi-validator-supervisor-host-artifact-build/1" in workflow
    assert "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105" in workflow
    assert '"out/${FINALITY_BASE}" --conformance-self-test' in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "compression-level: 0" in workflow
    action_references = [
        line.split("@", 1)[1].split(" ", 1)[0] for line in workflow.splitlines() if "uses:" in line
    ]
    assert action_references
    assert all(
        len(reference) == 40 and set(reference) <= set("0123456789abcdef")
        for reference in action_references
    )
    assert "\n  push:" not in workflow
    assert "packages: write" not in workflow
    assert "docker push" not in workflow
    assert "--push" not in workflow
    assert "docker/login-action" not in workflow
    assert "build-release-bundle" not in workflow


def test_worker_journal_rejects_completion_without_durable_outputs() -> None:
    validator = dev_wallet("//SupervisorWorkerJournalValidator")
    with pytest.raises(ValueError, match="completed worker journal"):
        SupervisorWorkerJournal(
            schema=WORKER_JOURNAL_SCHEMA,
            state_schema_version=1,
            mode="bootstrap_service_weights",
            directive_sha256="11" * 32,
            policy_sha256="22" * 32,
            release_manifest_sha256="33" * 32,
            sequence=2,
            valid_from_block=120,
            valid_through_block=200,
            validator_hotkey=validator.hotkey.ss58_address,
            manifest_input_sha256="44" * 32,
            transition_authorization_input_sha256="55" * 32,
            drain_checkpoint_input_sha256="66" * 32,
            phase="completed",
            intent_finalized_block=130,
            receipt_sha256=None,
            call_material_sha256=None,
            reason_code=None,
        )
