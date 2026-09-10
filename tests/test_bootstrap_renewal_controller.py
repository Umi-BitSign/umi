from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.factories import dev_wallet
from tests.test_bootstrap_direct_weights import (
    NOW,
    _operational,
    _permitted_case,
)
from tests.test_bootstrap_direct_weights import _snapshot as _bootstrap_snapshot
from tests.test_observer_bootstrap_service_feed import _terminal_records
from umi.bootstrap_direct_weights import (
    DIRECT_SUBMISSION_JOURNAL_SCHEMA,
    DIRECT_TRANSITION_PROFILE,
    DirectBootstrapOperationalPreflight,
    DirectBootstrapSubmissionJournal,
    build_direct_bootstrap_call_material,
    classify_direct_bootstrap_application,
    sign_direct_transition_authorization,
    validate_direct_bootstrap_preflight,
)
from umi.bootstrap_renewal_controller import (
    BOOTSTRAP_RENEWAL_CONFIG_SCHEMA,
    PINNED_BOOTSTRAP_WORKER_REVISION,
    UID200_SUBMISSION_NAMESPACE,
    BootstrapRenewalConfig,
    BootstrapRenewalController,
    BootstrapRenewalError,
    CoordinatorWalletBinding,
    PinnedFile,
    RenewalProcessLock,
    RootOwnedDirectiveFeedPublisher,
    validate_renewal_snapshot,
)
from umi.bootstrap_weight_operator import (
    BootstrapChainSnapshot,
    BootstrapExtrinsicReference,
    BootstrapManifestAnchorObservation,
)
from umi.crypto import sign_response_digest
from umi.encoding import account_id32
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_CONFIG_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SignedSupervisorDirective,
    SupervisorAuthority,
    SupervisorDirective,
    SupervisorDirectiveSignature,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
    supervisor_directive_digest,
    supervisor_directive_sha256,
)
from umi.validator_supervisor_adapters import (
    SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
    SupervisorBootstrapInputBundle,
)
from umi.validator_supervisor_publication import (
    SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
    SignedSupervisorBootstrapResult,
    SupervisorBootstrapResult,
    sign_supervisor_bootstrap_result,
)

INPUT_ORIGIN = "https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev"
UPLOAD_ORIGIN = "https://umi-public-pilot-upload.example.workers.dev"
RESULT_ORIGIN = INPUT_ORIGIN
CHANNEL_ID = "91" * 32


def _pin(root: Path, name: str, value: object) -> PinnedFile:
    payload = canonical_json_bytes(value)
    path = root / name
    path.write_bytes(payload)
    path.chmod(0o400)
    return PinnedFile(path=str(path), sha256=hashlib.sha256(payload).hexdigest())


def _sign_directive(directive: SupervisorDirective, wallet: object) -> SignedSupervisorDirective:
    scheme, signature = sign_response_digest(wallet, supervisor_directive_digest(directive))
    return SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=supervisor_directive_sha256(directive),
        directive_digest=supervisor_directive_digest(directive).hex(),
        signatures=[
            SupervisorDirectiveSignature(
                hotkey=wallet.hotkey.ss58_address,
                signature_scheme=scheme,
                signature=signature,
            )
        ],
    )


@dataclass
class RenewalCase:
    config: BootstrapRenewalConfig
    coordinator: object
    validator: object
    owner: object
    participants: list[object]
    expected_row: list[list[int]]
    seed_result: SignedSupervisorBootstrapResult
    seed_history: list[SignedSupervisorDirective]
    snapshot: BootstrapChainSnapshot
    published: list[str]
    results: dict[str, bytes]

    async def read_chain(self) -> BootstrapChainSnapshot:
        return self.snapshot

    async def build_operational(
        self,
        authorization: object,
        snapshot: BootstrapChainSnapshot,
    ) -> DirectBootstrapOperationalPreflight:
        preflight = validate_direct_bootstrap_preflight(
            self.seed_result.result.signed_manifest,
            snapshot,
            authorization=authorization,
            subnet_owner_hotkey=self.owner.hotkey.ss58_address,
            validator_hotkey=self.validator.hotkey.ss58_address,
            now=NOW,
        )
        return _operational(self.seed_result.result.signed_manifest, preflight)

    async def publish_input(self, source: Path, digest: str, size: int) -> str:
        payload = source.read_bytes()
        assert hashlib.sha256(payload).hexdigest() == digest
        assert len(payload) == size
        self.published.append(digest)
        return f"{INPUT_ORIGIN}/validator-bootstrap-inputs/{digest}.json"

    async def fetch_result(self, submission_id: str) -> bytes | None:
        return self.results.get(submission_id)

    def set_snapshot(
        self, *, block: int, last_update: int | None = None, **changes: object
    ) -> None:
        update = last_update if last_update is not None else self.validator_last_update
        participants = [
            item.model_copy(update={"last_update": update}) if item.uid == 200 else item
            for item in self.participants
        ]
        values: dict[str, object] = {
            "block_number": block,
            "block_hash": "0x" + f"{block % 255:02x}" * 32,
            "weights_set_rate_limit": 100,
            "validator_mechid0_row": self.expected_row,
            "active_mechid0_row_hotkeys": [self.validator.hotkey.ss58_address],
            "blocks_since_last_step": min(block, 100),
        }
        values.update(changes)
        self.snapshot = _bootstrap_snapshot(participants, **values)

    @property
    def validator_last_update(self) -> int:
        return next(item.last_update for item in self.snapshot.participants if item.uid == 200)


def _make_case(tmp_path: Path) -> RenewalCase:
    coordinator = dev_wallet("//DirectBootstrapCoordinator")
    signed, _old_authorization, owner, validator, participants, _old_preflight = _permitted_case()
    seed_submission_id = "ab" * 32
    authorization = sign_direct_transition_authorization(
        signed,
        weights_version_key=1 << 32,
        submission_id=seed_submission_id,
        umi_git_revision=PINNED_BOOTSTRAP_WORKER_REVISION,
        signed_at_block=125,
        valid_from_block=125,
        expires_at_block=155,
        validator_hotkey=validator.hotkey.ss58_address,
        validator_uid=200,
        wallet=coordinator,
    )
    owner_fence, _signed, _authorization, material, receipt, journal, _owner, _items = (
        _terminal_records(
            base_case=(signed, authorization, owner, participants),
        )
    )
    release = SupervisorReleaseTarget(
        artifact_type="oci",
        release_bundle_url="https://api.umi.vision/releases/renewal-worker/release.tar",
        release_bundle_sha256="31" * 32,
        release_bundle_size_bytes=1024,
        release_manifest_sha256="32" * 32,
        release_authority_hotkey=coordinator.hotkey.ss58_address,
        release_authority_signature_scheme="sr25519",
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256="33" * 32,
        target_platform="linux/amd64",
        umi_git_revision=PINNED_BOOTSTRAP_WORKER_REVISION,
        umi_source_tree_sha256="34" * 32,
        entrypoint_profile="umi-bootstrap-weight-validator/2",
        state_schema_minimum=1,
        state_schema_maximum=1,
    )
    seed_bundle = SupervisorBootstrapInputBundle(
        schema=SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
        profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
        signed_manifest=signed,
        transition_authorization=authorization,
        drain_checkpoint=material.operational_preflight,
        owner_fence_receipt=owner_fence,
    )
    seed_bundle_bytes = canonical_json_bytes(seed_bundle)
    seed_bundle_sha256 = hashlib.sha256(seed_bundle_bytes).hexdigest()
    input_target = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
        bundle_url=f"{INPUT_ORIGIN}/validator-bootstrap-inputs/{seed_bundle_sha256}.json",
        bundle_sha256=seed_bundle_sha256,
        bundle_size_bytes=len(seed_bundle_bytes),
    )
    first = _sign_directive(
        SupervisorDirective(
            schema=SUPERVISOR_DIRECTIVE_SCHEMA,
            channel_id=CHANNEL_ID,
            sequence=1,
            previous_directive_sha256=None,
            issued_at_block=125,
            valid_from_block=125,
            valid_through_block=50_519,
            network="finney",
            netuid=78,
            mechanism_id=0,
            mode="hold",
            validator_hotkeys=[validator.hotkey.ss58_address],
            policy_sha256=None,
            release=None,
            operator_inputs=None,
        ),
        coordinator,
    )
    second = _sign_directive(
        SupervisorDirective(
            schema=SUPERVISOR_DIRECTIVE_SCHEMA,
            channel_id=CHANNEL_ID,
            sequence=2,
            previous_directive_sha256=first.directive_sha256,
            issued_at_block=127,
            valid_from_block=127,
            valid_through_block=155,
            network="finney",
            netuid=78,
            mechanism_id=0,
            mode="bootstrap_service_weights",
            validator_hotkeys=[validator.hotkey.ss58_address],
            policy_sha256=signed.manifest.policy_sha256,
            release=release,
            operator_inputs=input_target,
        ),
        coordinator,
    )
    third = _sign_directive(
        SupervisorDirective(
            schema=SUPERVISOR_DIRECTIVE_SCHEMA,
            channel_id=CHANNEL_ID,
            sequence=3,
            previous_directive_sha256=second.directive_sha256,
            issued_at_block=128,
            valid_from_block=128,
            valid_through_block=155,
            network="finney",
            netuid=78,
            mechanism_id=0,
            mode="bootstrap_service_weights",
            validator_hotkeys=[validator.hotkey.ss58_address],
            policy_sha256=signed.manifest.policy_sha256,
            release=release,
            operator_inputs=input_target,
        ),
        coordinator,
    )
    seed_result = sign_supervisor_bootstrap_result(
        SupervisorBootstrapResult(
            schema=SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
            directive_sha256=third.directive_sha256,
            release_manifest_sha256=release.release_manifest_sha256,
            validator_hotkey=validator.hotkey.ss58_address,
            submission_id=seed_submission_id,
            owner_fence_receipt=owner_fence,
            signed_manifest=signed,
            transition_authorization=authorization,
            drain_checkpoint=material.operational_preflight,
            call_material=material,
            submission_receipt=receipt,
            submission_journal=journal,
            created_at=NOW,
        ),
        wallet=validator,
    )
    expected_row = material.expected_applied_row
    active_participants = [
        item.model_copy(update={"last_update": receipt.observed_last_update})
        if item.uid == 200
        else item
        for item in participants
    ]
    snapshot = _bootstrap_snapshot(
        active_participants,
        block_number=receipt.observed_last_update + 99,
        block_hash="0x" + "35" * 32,
        weights_set_rate_limit=100,
        validator_mechid0_row=expected_row,
        active_mechid0_row_hotkeys=[validator.hotkey.ss58_address],
        blocks_since_last_step=99,
    )
    static_root = tmp_path / "static"
    static_root.mkdir()
    supervisor = ValidatorSupervisorConfig(
        schema=SUPERVISOR_CONFIG_SCHEMA,
        network="finney",
        netuid=78,
        mechanism_id=0,
        validator_hotkey=validator.hotkey.ss58_address,
        channel_id=CHANNEL_ID,
        signature_threshold=1,
        trusted_authorities=[
            SupervisorAuthority(
                hotkey=coordinator.hotkey.ss58_address,
                signature_scheme="sr25519",
            )
        ],
        allowed_oci_repositories=["ghcr.io/umi-bitsign/umi-validator"],
        release_origins=["https://api.umi.vision", INPUT_ORIGIN],
        target_platform="linux/amd64",
        state_schema_version=1,
        directive_url="https://api.umi.vision/api/v1/validator-directives/test",
        poll_seconds=30,
        container_runtime="/usr/bin/podman",
        state_root="/var/lib/test-supervisor-state",
        worker_state_root="/var/lib/test-supervisor-worker",
        release_root="/var/lib/test-supervisor-releases",
        operator_input_root="/var/lib/test-supervisor-inputs",
        finality_verifier_binary="/opt/test/finality",
        finality_verifier_sha256="36" * 32,
        finality_chain_spec_path="/opt/test/finney.json",
        worker_cpu_millis=8000,
        worker_memory_bytes=12 * 1024**3,
        worker_pids_limit=512,
        worker_uid=65_532,
        worker_gid=65_532,
        wallet={"path": "/var/lib/test-wallet", "name": "vali", "hotkey": "default"},
        allowed_modes=["hold", "bootstrap_service_weights"],
    )
    route_root = tmp_path / "routes"
    route_root.mkdir(mode=0o755)
    feed = RootOwnedDirectiveFeedPublisher(
        route_root,
        trusted_owner_uid=os.geteuid(),
    )
    history = [first, second, third]
    account = account_id32(validator.hotkey.ss58_address).hex()
    for sequence in (1, 2, 3):
        path = (
            route_root
            / account
            / "after"
            / str(sequence)
            / (f"{history[sequence - 1].directive_sha256}.json")
        )
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        feed._write_new_public(
            path,
            canonical_json_bytes(feed.page_for_cursor(history, sequence)),
        )
    config = BootstrapRenewalConfig(
        schema=BOOTSTRAP_RENEWAL_CONFIG_SCHEMA,
        network="finney",
        netuid=78,
        mechanism_id=0,
        validator_uid=200,
        validator_hotkey=validator.hotkey.ss58_address,
        coordinator_hotkey=coordinator.hotkey.ss58_address,
        submission_id_prefix=UID200_SUBMISSION_NAMESPACE,
        worker_umi_git_revision=PINNED_BOOTSTRAP_WORKER_REVISION,
        signed_manifest=_pin(static_root, "manifest.json", signed),
        owner_fence_receipt=_pin(static_root, "fence.json", owner_fence),
        release_target=_pin(static_root, "release.json", release),
        validator_supervisor_config=_pin(static_root, "supervisor.json", supervisor),
        seed_directives=[
            _pin(static_root, "directive-1.json", first),
            _pin(static_root, "directive-2.json", second),
            _pin(static_root, "directive-3.json", third),
        ],
        seed_result_submission_id=seed_submission_id,
        coordinator_wallet=CoordinatorWalletBinding(
            path="/tmp/test-wallets",
            name="coordinator",
            hotkey="default",
        ),
        input_upload_secret_path="/tmp/test-input-upload.key",
        input_upload_origin=UPLOAD_ORIGIN,
        input_public_origin=INPUT_ORIGIN,
        result_public_origin=RESULT_ORIGIN,
        state_root=str(tmp_path / "state"),
        directive_route_root=str(route_root),
        poll_seconds=5,
        authorization_lifetime_blocks=48,
        maximum_checkpoint_age_blocks=4,
        minimum_deadline_headroom_blocks=48,
    )
    return RenewalCase(
        config=config,
        coordinator=coordinator,
        validator=validator,
        owner=owner,
        participants=participants,
        expected_row=expected_row,
        seed_result=seed_result,
        seed_history=history,
        snapshot=snapshot,
        published=[],
        results={seed_submission_id: canonical_json_bytes(seed_result)},
    )


def _controller(case: RenewalCase, *, suffix: str = "01" * 16) -> BootstrapRenewalController:
    return BootstrapRenewalController(
        case.config,
        wallet=case.coordinator,
        chain_reader=case.read_chain,
        operational_builder=case.build_operational,
        input_publisher=case.publish_input,
        result_fetcher=case.fetch_result,
        feed_publisher=RootOwnedDirectiveFeedPublisher(
            Path(case.config.directive_route_root),
            trusted_owner_uid=os.geteuid(),
        ),
        random_suffix=lambda: suffix,
    )


def _result_for_transaction(
    case: RenewalCase,
    controller: BootstrapRenewalController,
    *,
    weight_block: int,
) -> SignedSupervisorBootstrapResult:
    state = controller._load_state()
    transaction = state.transaction
    assert transaction is not None
    authorization = controller._load_transaction_artifact(
        transaction,
        "transition-authorization.json",
        type(case.seed_result.result.transition_authorization),
    )
    checkpoint = controller._load_transaction_artifact(
        transaction,
        "drain-checkpoint.json",
        DirectBootstrapOperationalPreflight,
    )
    checkpoint_block = checkpoint.chain.snapshot.block_number
    anchor = BootstrapExtrinsicReference(
        extrinsic_id=f"{checkpoint_block - 2}-0001",
        block_number=checkpoint_block - 2,
        extrinsic_index=1,
        block_hash="0x" + "41" * 32,
    )
    anchor_observation = BootstrapManifestAnchorObservation(
        manifest_sha256=case.seed_result.result.signed_manifest.manifest_sha256,
        anchor=anchor,
        observation_block=checkpoint_block - 1,
        observation_block_hash="0x" + "42" * 32,
        stored_commitment_block=checkpoint_block - 2,
        field_count=1,
        field_type="Data::Sha256",
        field_sha256=case.seed_result.result.signed_manifest.manifest_sha256,
        sdk_finalized_read_verified=True,
        storage_proofs_verified=False,
    )
    material, _call = build_direct_bootstrap_call_material(
        checkpoint,
        manifest_anchor=anchor_observation,
    )
    weight_call = BootstrapExtrinsicReference(
        extrinsic_id=f"{weight_block}-0002",
        block_number=weight_block,
        extrinsic_index=2,
        block_hash="0x" + "43" * 32,
    )
    case.set_snapshot(block=weight_block, last_update=weight_block)
    observation = validate_direct_bootstrap_preflight(
        case.seed_result.result.signed_manifest,
        case.snapshot,
        authorization=authorization,
        subnet_owner_hotkey=case.owner.hotkey.ss58_address,
        validator_hotkey=case.validator.hotkey.ss58_address,
        now=NOW,
        require_submission_ready=False,
    )
    receipt = classify_direct_bootstrap_application(
        material,
        anchor=anchor,
        weight_call=weight_call,
        observation=observation,
        created_at=NOW,
    )
    material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    authorization_sha256 = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
    journal = DirectBootstrapSubmissionJournal(
        schema=DIRECT_SUBMISSION_JOURNAL_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        submission_id=authorization.submission_id,
        phase="applied",
        manifest_sha256=case.seed_result.result.signed_manifest.manifest_sha256,
        transition_authorization_sha256=authorization_sha256,
        validator_hotkey=case.validator.hotkey.ss58_address,
        anchor=anchor,
        call_material_sha256=material_sha256,
        weight_call=weight_call,
        receipt_sha256=receipt_sha256,
        updated_at=NOW,
    )
    return sign_supervisor_bootstrap_result(
        SupervisorBootstrapResult(
            schema=SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
            directive_sha256=transaction.directive_sha256,
            release_manifest_sha256=controller.release_target.release_manifest_sha256,
            validator_hotkey=case.validator.hotkey.ss58_address,
            submission_id=transaction.submission_id,
            owner_fence_receipt=controller.owner_fence_receipt,
            signed_manifest=controller.signed_manifest,
            transition_authorization=authorization,
            drain_checkpoint=checkpoint,
            call_material=material,
            submission_receipt=receipt,
            submission_journal=journal,
            created_at=NOW,
        ),
        wallet=case.validator,
    )


@pytest.mark.asyncio
async def test_controller_recovers_each_phase_and_renews_only_after_rate_limit(
    tmp_path: Path,
) -> None:
    case = _make_case(tmp_path)
    controller = _controller(case)
    state = await controller.initialize()
    assert state is not None
    assert state.head_sequence == 3

    waiting = await controller.step()
    assert waiting.status == "waiting_for_rate_limit"
    case.set_snapshot(block=state.last_update_block + 100)

    prepared = await controller.step()
    assert prepared.status == "prepared"
    transaction = controller._load_state().transaction
    assert transaction is not None
    assert transaction.submission_id == UID200_SUBMISSION_NAMESPACE + "01" * 16

    controller = _controller(case)
    uploaded = await controller.step()
    assert uploaded.status == "input_published"
    assert case.published == [transaction.input_bundle_sha256]

    controller = _controller(case)
    published = await controller.step()
    assert published.status == "directive_published"

    controller = _controller(case)
    pending = await controller.step()
    assert pending.reason_code == "renewal_result_pending"
    result = _result_for_transaction(case, controller, weight_block=state.last_update_block + 104)
    case.results[transaction.submission_id] = canonical_json_bytes(result)

    controller = _controller(case)
    verified = await controller.step()
    assert verified.status == "result_verified"
    final = controller._load_state()
    assert final.head_sequence == 4
    assert final.transaction is None
    assert final.last_update_block == state.last_update_block + 104


@pytest.mark.asyncio
async def test_expired_directive_without_effect_advances_history_but_never_reuses_it(
    tmp_path: Path,
) -> None:
    case = _make_case(tmp_path)
    controller = _controller(case)
    state = await controller.initialize()
    assert state is not None
    case.set_snapshot(block=state.last_update_block + 100)
    assert (await controller.step()).status == "prepared"
    assert (await controller.step()).status == "input_published"
    assert (await controller.step()).status == "directive_published"
    transaction = controller._load_state().transaction
    assert transaction is not None

    case.set_snapshot(block=transaction.valid_through_block + 1)
    expired = await controller.step()
    assert expired.status == "retry_after_no_effect"
    recovered = controller._load_state()
    assert recovered.head_sequence == 4
    assert recovered.transaction is None
    assert recovered.abandoned_submission_count == 1

    retry_controller = _controller(case, suffix="02" * 16)
    retry = await retry_controller.step()
    assert retry.status == "prepared"
    assert retry_controller._load_state().transaction.directive_sequence == 5


@pytest.mark.asyncio
async def test_changed_last_update_without_signed_result_is_terminally_ambiguous(
    tmp_path: Path,
) -> None:
    case = _make_case(tmp_path)
    controller = _controller(case)
    state = await controller.initialize()
    assert state is not None
    case.set_snapshot(block=state.last_update_block + 100)
    await controller.step()
    await controller.step()
    await controller.step()
    transaction = controller._load_state().transaction
    assert transaction is not None

    case.set_snapshot(
        block=transaction.valid_through_block + 1,
        last_update=transaction.checkpoint_block + 2,
    )
    status = await controller.step()
    assert status.status == "terminal"
    assert status.reason_code == "renewal_effect_ambiguous_after_result_expiry"


def test_snapshot_rejects_other_active_validator_and_mapping_drift(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    owner_hotkey = case.owner.hotkey.ss58_address
    with pytest.raises(BootstrapRenewalError) as pending:
        validate_renewal_snapshot(
            case.snapshot.model_copy(update={"total_pending_commit_count": 1}),
            signed_manifest=case.seed_result.result.signed_manifest,
            subnet_owner_hotkey=owner_hotkey,
            validator_hotkey=case.validator.hotkey.ss58_address,
            validator_uid=200,
        )
    assert pending.value.reason_code == "renewal_pending_entry_exists"

    participants = [
        item.model_copy(
            update={"validator_permit": True, "last_update": case.snapshot.block_number}
        )
        if item.uid == 201
        else item
        for item in case.snapshot.participants
    ]
    with pytest.raises(BootstrapRenewalError) as other:
        validate_renewal_snapshot(
            case.snapshot.model_copy(update={"participants": participants}),
            signed_manifest=case.seed_result.result.signed_manifest,
            subnet_owner_hotkey=owner_hotkey,
            validator_hotkey=case.validator.hotkey.ss58_address,
            validator_uid=200,
        )
    assert other.value.reason_code == "renewal_other_active_validator"

    with pytest.raises(BootstrapRenewalError) as owner:
        validate_renewal_snapshot(
            case.snapshot,
            signed_manifest=case.seed_result.result.signed_manifest,
            subnet_owner_hotkey=dev_wallet("//ChangedOwner").hotkey.ss58_address,
            validator_hotkey=case.validator.hotkey.ss58_address,
            validator_uid=200,
        )
    assert owner.value.reason_code == "renewal_owner_mapping_changed"


def test_feed_publication_rejects_a_concurrent_page_change(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    controller = _controller(case)
    state_root = Path(case.config.state_root)
    state_root.mkdir(mode=0o700)
    controller.history_root.mkdir(mode=0o700)
    controller.transactions_root.mkdir(mode=0o700)
    history = case.seed_history
    account = account_id32(case.validator.hotkey.ss58_address).hex()
    route = (
        Path(case.config.directive_route_root)
        / account
        / "after"
        / "1"
        / f"{history[0].directive_sha256}.json"
    )
    alternate = RootOwnedDirectiveFeedPublisher.page_for_cursor(history[:1], 1)
    route.chmod(0o600)
    route.write_bytes(canonical_json_bytes(alternate))
    route.chmod(0o444)
    next_directive = _sign_directive(
        history[-1].directive.model_copy(
            update={
                "sequence": 4,
                "previous_directive_sha256": history[-1].directive_sha256,
            }
        ),
        case.coordinator,
    )

    with pytest.raises(BootstrapRenewalError) as raced:
        controller.feed.publish(history, next_directive)
    assert raced.value.reason_code == "renewal_directive_page_race"


def test_process_lock_is_single_instance(tmp_path: Path) -> None:
    first = RenewalProcessLock(tmp_path)
    second = RenewalProcessLock(tmp_path)
    first.acquire()
    try:
        with pytest.raises(BootstrapRenewalError) as locked:
            second.acquire()
        assert locked.value.reason_code == "renewal_controller_already_running"
    finally:
        first.close()

    second.acquire()
    second.close()
