from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

import umi.registration_bridge as registration_bridge
import umi.validator_supervisor_cli as supervisor_cli
from tests.test_validator_supervisor import (
    _config as directive_config,
)
from tests.test_validator_supervisor import (
    _directive,
    _operator_inputs,
    _release,
    _signed,
)
from tests.test_validator_supervisor_adapters import _config as adapter_config
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.protocol import canonical_json_bytes
from umi.registration_bridge import (
    REGISTRATION_BRIDGE_COORDINATOR,
    REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK,
    REGISTRATION_BRIDGE_POLICY_BODY_SCHEMA,
    REGISTRATION_BRIDGE_POLICY_SCHEMA,
    REGISTRATION_BRIDGE_PROFILE,
    REGISTRATION_BRIDGE_STOP_SUBMITTING_BLOCK,
    RegistrationBridgePolicyBody,
    SignedRegistrationBridgePolicy,
    registration_bridge_policy_sha256,
)
from umi.validator_supervisor import (
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SupervisorDirective,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    advance_supervisor_directive_state,
    parse_canonical_signed_supervisor_directive,
)
from umi.validator_supervisor_adapters import (
    REGISTRATION_BRIDGE_POLICY_RELATIVE_PATH,
    REGISTRATION_BRIDGE_WORKER_ENTRYPOINT,
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
    WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH,
    WORKER_OPERATOR_INPUT_PATH,
    WORKER_STATE_PATH,
    RootlessPodmanWorkerAdapter,
    StagedSupervisorRelease,
    SupervisorRegistrationBridgeInputBundle,
    SupervisorReleaseManifest,
    ValidatorSupervisorAdapterError,
    _parse_bootstrap_input_bundle,
)
from umi.validator_supervisor_runtime import SupervisorWorkerActivation

REVISION = "66" * 20
POLICY_SIGNATURE = "0x" + "11" * 64
VALID_FROM_BLOCK = 9_060_000
VALID_THROUGH_BLOCK = 9_070_000


@pytest.fixture(autouse=True)
def _accept_only_the_fixture_policy_signature(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        registration_bridge,
        "verify_response_signature",
        lambda _digest, **values: values.get("signature") == POLICY_SIGNATURE,
    )
    yield
    for path in sorted(tmp_path.rglob("*"), reverse=True):
        try:
            if stat.S_ISDIR(path.lstat().st_mode):
                path.chmod(0o700)
        except FileNotFoundError:
            pass


@pytest.fixture
def signed_bridge_policy() -> SignedRegistrationBridgePolicy:
    body = RegistrationBridgePolicyBody(
        schema=REGISTRATION_BRIDGE_POLICY_BODY_SCHEMA,
        profile=REGISTRATION_BRIDGE_PROFILE,
        coordinator_hotkey=REGISTRATION_BRIDGE_COORDINATOR,
        network="finney",
        genesis_hash=f"0x{FINNEY_GENESIS_HASH}",
        netuid=78,
        mechanism_id=0,
        umi_git_revision=REVISION,
        valid_from_block=VALID_FROM_BLOCK,
        stop_submitting_block=REGISTRATION_BRIDGE_STOP_SUBMITTING_BLOCK,
        hard_sunset_block=REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK,
        reward_rule="equal_live_coldkey_groups/1",
        grouping_rule="registered_hotkey_owner_account_id32/1",
        allocation_rule="equal_group_budget_min_size_divmod_uid_order/1",
        exclude_uid_zero=True,
        exclude_validator_permits=True,
        exclude_subnet_owner_hotkeys=True,
        require_validator_permit=True,
        require_registration_before_submission=True,
        require_public_pilot_replay=False,
        require_fresh_endpoint_health=True,
        require_public_ip_https_axon=True,
        health_path="/healthz",
        health_status_code=200,
        health_timeout_seconds=5,
        health_batch_timeout_seconds=90,
        health_concurrency=16,
        health_maximum_body_bytes=16_384,
        health_ttl_seconds=120,
        tls_verification="system_trust_store/1",
        allow_redirects=False,
        maximum_raw_weight=65_535,
        required_runtime_spec_version=455,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        required_commit_reveal_version=4,
        required_reveal_period_epochs=1,
        weights_version_key=2**32,
        required_tempo=360,
        required_activity_cutoff_factor_milli=1000,
        required_activity_cutoff_blocks=360,
        required_weights_set_rate_limit=100,
        required_min_allowed_weights=256,
        required_max_allowed_uids=256,
        maximum_finalized_age_seconds=120,
        refresh_margin_blocks=120,
        submission_era_period=8,
        submission_timeout_seconds=60,
        submission_headroom_blocks=64,
    )
    return SignedRegistrationBridgePolicy(
        schema=REGISTRATION_BRIDGE_POLICY_SCHEMA,
        body=body,
        signature_scheme="sr25519",
        signature=POLICY_SIGNATURE,
    )


def _bridge_bundle(
    signed_policy: SignedRegistrationBridgePolicy,
) -> SupervisorRegistrationBridgeInputBundle:
    return SupervisorRegistrationBridgeInputBundle(
        schema=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
        profile=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
        signed_policy=signed_policy,
    )


def _bridge_release(
    config,
    manifest: SupervisorReleaseManifest,
    *,
    release_payload: bytes,
) -> SupervisorReleaseTarget:
    manifest_payload = canonical_json_bytes(manifest)
    return SupervisorReleaseTarget(
        artifact_type="oci",
        release_bundle_url="https://api.umi.vision/releases/registration-bridge.bin",
        release_bundle_sha256=hashlib.sha256(release_payload).hexdigest(),
        release_bundle_size_bytes=len(release_payload),
        release_manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        release_authority_hotkey=config.trusted_authorities[0].hotkey,
        release_authority_signature_scheme="sr25519",
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256=manifest.oci_manifest_sha256,
        target_platform=manifest.target_platform,
        umi_git_revision=manifest.umi_git_revision,
        umi_source_tree_sha256=manifest.umi_source_tree_sha256,
        entrypoint_profile=REGISTRATION_BRIDGE_PROFILE,
        state_schema_minimum=1,
        state_schema_maximum=1,
    )


class _BundleHTTPS:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def download_file(
        self,
        url: str,
        *,
        destination: Path,
        maximum_bytes: int,
        expected_size_bytes: int,
        expected_sha256: str,
    ) -> None:
        assert url == "https://api.umi.vision/releases/registration-bridge-inputs.json"
        assert len(self.payload) <= maximum_bytes
        assert len(self.payload) == expected_size_bytes
        assert hashlib.sha256(self.payload).hexdigest() == expected_sha256
        destination.write_bytes(self.payload)


async def _staged_bridge_case(
    root: Path,
    signed_policy: SignedRegistrationBridgePolicy,
    *,
    release_revision: str = REVISION,
) -> tuple[
    RootlessPodmanWorkerAdapter,
    StagedSupervisorRelease,
    SupervisorWorkerActivation,
]:
    config = adapter_config(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    release_root = root / "staged"
    release_root.mkdir(mode=0o700)
    bundle = _bridge_bundle(signed_policy)
    bundle_payload = canonical_json_bytes(bundle)
    input_target = SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
        bundle_url="https://api.umi.vision/releases/registration-bridge-inputs.json",
        bundle_sha256=hashlib.sha256(bundle_payload).hexdigest(),
        bundle_size_bytes=len(bundle_payload),
    )
    adapter = RootlessPodmanWorkerAdapter(config, https=_BundleHTTPS(bundle_payload))
    await adapter._stage_operator_inputs(release_root, input_target)

    archive_payload = b"bounded-registration-bridge-oci-archive"
    manifest = SupervisorReleaseManifest(
        schema="umi-validator-supervisor-release-manifest/1",
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256="55" * 32,
        oci_archive_sha256=hashlib.sha256(archive_payload).hexdigest(),
        oci_archive_size_bytes=len(archive_payload),
        target_platform="linux/amd64",
        umi_git_revision=release_revision,
        umi_source_tree_sha256="77" * 32,
        entrypoint_profile=REGISTRATION_BRIDGE_PROFILE,
        state_schema_minimum=1,
        state_schema_maximum=1,
    )
    release_payload = b"immutable-framed-release-cache"
    release = _bridge_release(config, manifest, release_payload=release_payload)
    manifest_path = release_root / "release-manifest.json"
    archive_path = release_root / "image.oci.tar"
    release_bundle_path = release_root / "release-bundle.bin"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    archive_path.write_bytes(archive_payload)
    release_bundle_path.write_bytes(release_payload)
    for path in (manifest_path, archive_path, release_bundle_path):
        path.chmod(0o400)
    release_root.chmod(0o500)
    staged = StagedSupervisorRelease(
        root=release_root,
        manifest_path=manifest_path,
        archive_path=archive_path,
        image_reference=f"{release.oci_repository}@sha256:{release.oci_manifest_sha256}",
        manifest=manifest,
        operator_input_root=release_root / "operator-inputs",
    )
    activation = SupervisorWorkerActivation(
        mode="bootstrap_service_weights",
        sequence=2,
        directive_sha256="99" * 32,
        policy_sha256=registration_bridge_policy_sha256(signed_policy),
        valid_from_block=VALID_FROM_BLOCK,
        valid_through_block=VALID_THROUGH_BLOCK,
        release=release,
        operator_inputs=input_target,
    )
    return adapter, staged, activation


def test_bridge_profile_is_a_distinct_authenticated_v3_transition(
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    first = _signed()
    old_bytes = canonical_json_bytes(first)
    assert canonical_json_bytes(parse_canonical_signed_supervisor_directive(old_bytes)) == old_bytes

    second_directive = _directive(
        sequence=2,
        previous_directive_sha256=first.directive_sha256,
        issued_at_block=121,
        valid_from_block=130,
        valid_through_block=200,
        validator_scope="any_permitted_sn78",
        validator_hotkeys=[],
        policy_sha256=registration_bridge_policy_sha256(signed_bridge_policy),
        release=_release(entrypoint_profile=REGISTRATION_BRIDGE_PROFILE),
        operator_inputs=_operator_inputs(profile=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE),
    )
    second = _signed(second_directive)
    config = directive_config()
    first_state = advance_supervisor_directive_state(
        first,
        config=config,
        finalized_block=120,
        prior_state=None,
    )
    second_state = advance_supervisor_directive_state(
        second,
        config=config,
        finalized_block=140,
        prior_state=first_state,
    )

    assert second_state.accepted_sequence == 2
    assert second.directive.previous_directive_sha256 == first_state.accepted_directive_sha256
    assert (
        second_state.accepted_operator_input_sha256
        == second_directive.operator_inputs.bundle_sha256
    )


@pytest.mark.parametrize(
    ("validator_scope", "release_profile", "input_profile"),
    [
        (
            "explicit_hotkeys",
            REGISTRATION_BRIDGE_PROFILE,
            SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
        ),
        (
            "any_permitted_sn78",
            REGISTRATION_BRIDGE_PROFILE,
            "umi-simple-bootstrap-common-inputs/1",
        ),
        (
            "any_permitted_sn78",
            "umi-simple-bootstrap-validator/1",
            SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
        ),
    ],
)
def test_bridge_profile_cannot_reinterpret_an_existing_scope_or_input(
    validator_scope: str,
    release_profile: str,
    input_profile: str,
) -> None:
    with pytest.raises(ValidationError):
        SupervisorDirective.model_validate(
            _directive().model_dump(mode="python", by_alias=True)
            | {
                "validator_scope": validator_scope,
                "validator_hotkeys": (
                    [_directive().validator_hotkeys[0]]
                    if validator_scope == "explicit_hotkeys"
                    else []
                ),
                "release": _release(entrypoint_profile=release_profile),
                "operator_inputs": _operator_inputs(profile=input_profile),
            }
        )


def test_bridge_bundle_parser_authenticates_canonical_signed_policy(
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    bundle = _bridge_bundle(signed_bridge_policy)
    payload = canonical_json_bytes(bundle)
    assert _parse_bootstrap_input_bundle(payload) == bundle
    assert (
        registration_bridge_policy_sha256(signed_bridge_policy)
        == hashlib.sha256(canonical_json_bytes(signed_bridge_policy)).hexdigest()
    )

    changed = bundle.model_dump(mode="python", by_alias=True)
    changed["signed_policy"]["signature"] = "0x" + "22" * 64
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_bundle_invalid",
    ):
        _parse_bootstrap_input_bundle(canonical_json_bytes(changed))

    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_bundle_noncanonical",
    ):
        _parse_bootstrap_input_bundle(
            json.dumps(bundle.model_dump(mode="json", by_alias=True), indent=2).encode()
        )


@pytest.mark.asyncio
async def test_bridge_staging_is_exact_read_only_and_detects_tree_tamper(
    tmp_path: Path,
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    adapter, staged, activation = await _staged_bridge_case(tmp_path, signed_bridge_policy)
    await adapter._verify_staged_operator_inputs(staged, activation.operator_inputs)

    input_root = staged.operator_input_root
    assert input_root is not None
    policy_root = input_root / "registration-bridge"
    policy_path = input_root / REGISTRATION_BRIDGE_POLICY_RELATIVE_PATH
    assert {path.name for path in input_root.iterdir()} == {"registration-bridge"}
    assert {path.name for path in policy_root.iterdir()} == {"registration-bridge-policy.json"}
    assert policy_path.read_bytes() == canonical_json_bytes(signed_bridge_policy)
    assert stat.S_IMODE(input_root.stat().st_mode) == 0o500
    assert stat.S_IMODE(policy_root.stat().st_mode) == 0o500
    assert stat.S_IMODE(policy_path.stat().st_mode) == 0o400

    policy_root.chmod(0o700)
    (policy_root / "unsigned-host-override.json").write_bytes(b"{}")
    policy_root.chmod(0o500)
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_file_set_mismatch",
    ):
        await adapter._verify_staged_operator_inputs(staged, activation.operator_inputs)

    policy_root.chmod(0o700)
    (policy_root / "unsigned-host-override.json").unlink()
    policy_path.unlink()
    policy_path.symlink_to("/etc/passwd")
    policy_root.chmod(0o500)
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_file_unsafe",
    ):
        await adapter._verify_staged_operator_inputs(staged, activation.operator_inputs)


@pytest.mark.asyncio
async def test_bridge_release_binds_signed_policy_digest_revision_and_full_interval(
    tmp_path: Path,
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    adapter, staged, activation = await _staged_bridge_case(
        tmp_path / "valid", signed_bridge_policy
    )
    await adapter._verify_staged_release(staged, activation)

    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_release_binding_mismatch",
    ):
        await adapter._verify_staged_release(
            staged,
            replace(activation, policy_sha256="ab" * 32),
        )

    wrong_adapter, wrong_staged, wrong_activation = await _staged_bridge_case(
        tmp_path / "revision",
        signed_bridge_policy,
        release_revision="aa" * 20,
    )
    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_release_binding_mismatch",
    ):
        await wrong_adapter._verify_staged_release(wrong_staged, wrong_activation)

    with pytest.raises(
        ValidatorSupervisorAdapterError,
        match="operator_input_release_binding_mismatch",
    ):
        await adapter._verify_staged_release(
            staged,
            replace(
                activation,
                valid_through_block=REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK,
            ),
        )


@pytest.mark.asyncio
async def test_bridge_dispatch_uses_only_fixed_entrypoint_mounts_and_release_pins(
    tmp_path: Path,
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    adapter, staged, activation = await _staged_bridge_case(tmp_path, signed_bridge_policy)
    arguments = adapter._worker_arguments(staged, activation)
    encoded = "\n".join(arguments)
    assert "/tmp:rw,noexec,nosuid,nodev,size=268435456" in arguments
    assert (
        "/run/umi-finality:rw,exec,nosuid,nodev,size=67108864,"
        f"uid={adapter.config.worker_uid},gid={adapter.config.worker_gid},mode=0700"
    ) in arguments

    assert arguments[arguments.index("--entrypoint") + 1] == REGISTRATION_BRIDGE_WORKER_ENTRYPOINT
    assert (
        f"UMI_BRIDGE_POLICY_PATH={WORKER_OPERATOR_INPUT_PATH}/"
        f"{REGISTRATION_BRIDGE_POLICY_RELATIVE_PATH}"
    ) in arguments
    assert f"UMI_SUPERVISOR_POLICY_SHA256={activation.policy_sha256}" in arguments
    assert f"UMI_GIT_REVISION={activation.release.umi_git_revision}" in arguments
    assert "UMI_IMAGE_REVISION_PATH=/opt/umi-image-revision" in arguments
    assert f"UMI_IMAGE_SOURCE_TREE_SHA256={activation.release.umi_source_tree_sha256}" in arguments
    assert f"UMI_EXPECTED_VALIDATOR_HOTKEY={adapter.config.validator_hotkey}" in arguments
    assert f"UMI_HOTKEY={adapter.config.wallet.hotkey}" in arguments
    assert "UMI_MANIFEST_PATH=" not in encoded
    assert WORKER_BOOTSTRAP_RESULT_UPLOAD_CREDENTIAL_PATH not in encoded
    assert (
        f"type=bind,src={adapter.config.worker_state_root},dst={WORKER_STATE_PATH},"
        "ro=false,bind-propagation=private"
    ) in arguments
    assert (
        f"type=bind,src={staged.operator_input_root},dst={WORKER_OPERATOR_INPUT_PATH},"
        "ro=true,bind-propagation=private"
    ) in arguments
    assert arguments[-4:] == (
        staged.image_reference,
        "run",
        "--state-dir",
        WORKER_STATE_PATH,
    )


def test_cli_builds_only_the_signed_bridge_policy_bundle(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    policy_path = tmp_path / "signed-policy.json"
    bundle_path = tmp_path / "bundle.json"
    target_path = tmp_path / "target.json"
    policy_path.write_bytes(canonical_json_bytes(signed_bridge_policy))

    assert (
        supervisor_cli.run_cli(
            [
                "build-registration-bridge-input-bundle",
                "--signed-policy",
                str(policy_path),
                "--bundle-url",
                "https://api.umi.vision/releases/registration-bridge-inputs.json",
                "--output",
                str(bundle_path),
                "--target-output",
                str(target_path),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    bundle = _parse_bootstrap_input_bundle(bundle_path.read_bytes())
    target = SupervisorOperatorInputTarget.model_validate_json(target_path.read_bytes())

    assert isinstance(bundle, SupervisorRegistrationBridgeInputBundle)
    assert bundle.signed_policy == signed_bridge_policy
    assert target.profile == SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE
    assert target.bundle_sha256 == hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    assert result["bundle_sha256"] == target.bundle_sha256


@pytest.mark.asyncio
async def test_common_switch_preflight_accepts_only_the_bound_bridge_pair(
    monkeypatch: pytest.MonkeyPatch,
    signed_bridge_policy: SignedRegistrationBridgePolicy,
) -> None:
    config = directive_config()
    initial = _signed(
        _directive(
            mode="hold",
            validator_scope="any_permitted_sn78",
            validator_hotkeys=[],
            policy_sha256=None,
            release=None,
            operator_inputs=None,
        )
    )
    current = _signed(
        _directive(
            sequence=2,
            previous_directive_sha256=initial.directive_sha256,
            issued_at_block=121,
            valid_from_block=130,
            valid_through_block=200,
            validator_scope="any_permitted_sn78",
            validator_hotkeys=[],
            policy_sha256=registration_bridge_policy_sha256(signed_bridge_policy),
            release=_release(entrypoint_profile=REGISTRATION_BRIDGE_PROFILE),
            operator_inputs=_operator_inputs(profile=SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE),
        )
    )
    payload = canonical_json_bytes(
        {
            "schema": SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
            "after_sequence": 0,
            "after_directive_sha256": None,
            "directives": [
                initial.model_dump(mode="json", by_alias=True),
                current.model_dump(mode="json", by_alias=True),
            ],
            "more": False,
            "head": current.model_dump(mode="json", by_alias=True),
        }
    )
    activations: list[SupervisorWorkerActivation] = []

    class Adapter:
        def __init__(self, received_config) -> None:
            assert received_config is config

        async def check_host(self) -> None:
            return None

        async def public_status(self) -> dict[str, object]:
            return {"managed_container_present": False}

        async def preflight_activation(self, *, activation: SupervisorWorkerActivation) -> None:
            activations.append(activation)

    class Fetcher:
        def __init__(self, received_config) -> None:
            assert received_config is config

        async def fetch_directive_page(self, **cursor) -> bytes:
            assert cursor == {"after_sequence": 0, "after_directive_sha256": None}
            return payload

    class Finality:
        def __init__(self, received_config) -> None:
            assert received_config is config
            self.heights = iter((140, 141))

        async def read_finalized_block(self) -> int:
            return next(self.heights)

        async def stop(self) -> None:
            return None

    monkeypatch.setattr(supervisor_cli, "load_validator_supervisor_config", lambda _path: config)
    monkeypatch.setattr(supervisor_cli, "_validate_linux_systemd_profile", lambda _config: None)
    monkeypatch.setattr(supervisor_cli, "RootlessPodmanWorkerAdapter", Adapter)
    monkeypatch.setattr(supervisor_cli, "HTTPSDirectiveFetcher", Fetcher)
    monkeypatch.setattr(supervisor_cli, "FinneyFinalizedBlockReader", Finality)

    result = await supervisor_cli._preflight_common_switch(Path("/unused/config.json"))

    assert result["status"] == "common_switch_preflight_ok"
    assert [item.release.entrypoint_profile for item in activations] == [
        REGISTRATION_BRIDGE_PROFILE
    ]
    assert activations[0].operator_inputs.profile == SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE
