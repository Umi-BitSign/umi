from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import pytest

import umi.grandpa_finality as grandpa_finality
from umi.encoding import account_id32
from umi.grandpa_finality import (
    CARGO_LOCK_SHA256,
    FIXTURE_SET_SHA256,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
)
from umi.mirror_readiness import (
    build_mirror_readiness_set,
    check_readiness_input,
    sign_mirror_readiness,
)
from umi.mirror_service import MirrorServiceCheckResult
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.publisher_availability import build_certified_release, validate_candidate_bundle
from umi.validator_live import (
    FORBIDDEN_WEIGHT_CAPABILITY_NAMES,
    LIVE_SHADOW_MODE,
    LiveValidatorProductionDependencies,
    build_live_validator_primer,
    build_production_live_validator,
    run_cli,
)
from umi.validator_live_ports import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
    MirrorDiscoveryRule,
)
from umi.validator_operator import (
    LIVE_OPERATOR_CONFIG_SCHEMA,
    MIRROR_REQUEST_HEADERS_SCHEMA,
    LiveValidatorOperatorConfig,
    LiveValidatorOperatorError,
    MirrorOriginRequestHeaders,
    MirrorRequestHeaders,
    PrivateBittensorAnchorFactory,
    build_live_operator_dependencies,
    configure_operator,
    load_live_operator_config,
    load_operator_artifacts,
    run_installed_operator,
)
from umi.validator_state import STAGE_ORDER
from umi.validator_transcript_ports import (
    SignedValidatorCapacityStatement,
    ValidatorCapacitySetEvidence,
    ValidatorCapacityStatement,
    ValidatorResourceCapacities,
    validator_capacity_set_root,
)

from .factories import dev_wallet
from .test_policy import _live_shadow_policy_data
from .test_publisher_availability import (
    _context,
    _fake_inspect_factory,
    _qualify,
    _window,
    _write_bundle,
)
from .test_validator_live import _config


def _operator_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ScoringPolicy, object, LiveValidatorOperatorConfig]:
    monkeypatch.setattr("umi.validator_live.sys.platform", "linux")
    monkeypatch.setattr("umi.validator_live.platform.machine", lambda: "aarch64")
    policy_data = _live_shadow_policy_data()
    proof_binary = (tmp_path / "proof-verifier").resolve()
    finality_binary = (tmp_path / "finality-verifier").resolve()
    chain_spec = (tmp_path / "chain-spec.json").resolve()
    proof_binary.write_bytes(b"#!/bin/sh\nexit 1\n")
    finality_binary.write_bytes(b"#!/bin/sh\nexit 1\n")
    chain_spec.write_bytes(b'{"name":"pinned-test-chain"}')
    proof_binary.chmod(0o755)
    finality_binary.chmod(0o755)
    target = "aarch64-unknown-linux-musl"
    proof_releases = policy_data["implementation_pins"]["storage_proof_verifier"][
        "release_sha256_by_target"
    ]
    finality_releases = policy_data["implementation_pins"]["finality_verifier"][
        "release_sha256_by_target"
    ]
    proof_releases.clear()
    finality_releases.clear()
    proof_releases[target] = hashlib.sha256(proof_binary.read_bytes()).hexdigest()
    finality_releases[target] = hashlib.sha256(finality_binary.read_bytes()).hexdigest()
    policy_data["implementation_pins"]["finality_verifier"]["chain_spec_sha256"] = hashlib.sha256(
        chain_spec.read_bytes()
    ).hexdigest()
    policy_data["implementation_pins"]["finality_verifier"].update(
        {
            "source_revision": SOURCE_REVISION,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "cargo_lock_sha256": CARGO_LOCK_SHA256,
            "finality_fixture_set_sha256": FIXTURE_SET_SHA256,
        }
    )
    provisional = ScoringPolicy.model_validate(policy_data)
    wallet_by_account = {
        account_id32(dev_wallet(f"//Validator{index}").hotkey.ss58_address): dev_wallet(
            f"//Validator{index}"
        )
        for index in range(4)
    }
    signed: list[SignedValidatorCapacityStatement] = []
    for entry in provisional.validator_registry:
        statement = ValidatorCapacityStatement(
            schema="umi-validator-capacity/1",
            validator_hotkey=entry.validator_hotkey,
            hardware_class="operator-mac",
            region_class="operator-premises",
            meter_adapter_version="meter@sha256:" + "31" * 32,
            capacities=ValidatorResourceCapacities(
                cpu_core_milliseconds_per_window=100_000_000,
                accelerator_milliseconds_per_window=0,
                peak_host_memory_bytes=256 * 1024**3,
                peak_accelerator_memory_bytes=0,
                retained_storage_bytes=8 * 1024**3,
            ),
        )
        wallet = wallet_by_account[account_id32(entry.validator_hotkey)]
        digest = hashlib.sha256(
            b"umi-validator-capacity-v1\0" + canonical_json_bytes(statement)
        ).digest()
        signature = bytes(wallet.hotkey.sign(digest))
        signed.append(
            SignedValidatorCapacityStatement(
                statement=statement,
                signature_scheme="sr25519",
                signature="0x" + signature.hex(),
            )
        )
    signed.sort(key=lambda item: account_id32(item.statement.validator_hotkey))
    capacity = ValidatorCapacitySetEvidence(
        schema="umi-validator-capacity-set-evidence/1",
        protocol=PROTOCOL_VERSION,
        statements=signed,
    )
    origins = [
        "https://mirror-a.example",
        "https://mirror-b.example",
        "https://mirror-c.example",
    ]
    delivery_origins = [
        "https://delivery-a.example",
        "https://delivery-b.example",
        "https://delivery-c.example",
    ]
    discovery = MirrorDiscoveryRule(
        schema=MIRROR_DISCOVERY_SCHEMA,
        protocol=PROTOCOL_VERSION,
        authentication_profile=(
            provisional.implementation_pins.rules.mirror_authentication_profile
        ),
        index_path_template=DEFAULT_MIRROR_INDEX_PATH,
        delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
        origins=origins,
        delivery_origins=delivery_origins,
    )
    discovery_bytes = canonical_json_bytes(discovery)
    policy_data["validator_capacity_set_root"] = validator_capacity_set_root(capacity)
    policy_data["implementation_pins"]["rules"]["mirror_discovery_rule_sha256"] = hashlib.sha256(
        discovery_bytes
    ).hexdigest()
    policy = ScoringPolicy.model_validate(policy_data)
    live_config = _config(tmp_path, policy)

    window = _window(policy, reveal_round=bt.timelock.current_round() + 300)
    loaded = _write_bundle(tmp_path / "candidate", policy, window, publisher_count=2)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    validated = validate_candidate_bundle(
        loaded,
        policy=policy,
        context=_context(loaded, policy, 0),
    )
    receipts = [
        _qualify(tmp_path / f"availability-{index}", validated, policy, index)[0]
        for index in range(3)
    ]
    material = build_certified_release(validated, receipts, policy=policy)
    receipt_by_account = {account_id32(item.validator_hotkey): item for item in receipts}
    credential_hotkeys = tuple(
        item.validator_hotkey
        for item in sorted(
            policy.validator_registry, key=lambda item: account_id32(item.validator_hotkey)
        )
    )
    readiness_statements = []
    for origin, delivery_origin, account in zip(
        origins,
        delivery_origins,
        sorted(receipt_by_account),
        strict=True,
    ):
        receipt = receipt_by_account[account]
        receipt_bytes = canonical_json_bytes(receipt)
        check = MirrorServiceCheckResult(
            scoring_policy_sha256=scoring_policy_hash(policy),
            discovery_rule_sha256=hashlib.sha256(discovery_bytes).hexdigest(),
            certified_release_sha256=hashlib.sha256(material.release_bytes).hexdigest(),
            anchor_intents_sha256=hashlib.sha256(material.anchor_intents_bytes).hexdigest(),
            mirror_index_sha256=hashlib.sha256(material.mirror_index_bytes).hexdigest(),
            window_id=window.window_id,
            window_index=window.window_index,
            retrieval_origin=origin,
            delivery_origin=delivery_origin,
            credential_validator_hotkeys=credential_hotkeys,
        )
        checked = check_readiness_input(check, receipt_bytes)
        wallet = wallet_by_account[account]
        readiness_statements.append(
            sign_mirror_readiness(
                checked,
                signature_scheme="sr25519",
                sign_digest=lambda digest, wallet=wallet: bytes(wallet.hotkey.sign(digest)),
            )
        )
    readiness = build_mirror_readiness_set(
        policy=policy,
        certified_release_bytes=material.release_bytes,
        anchor_intents_bytes=material.anchor_intents_bytes,
        discovery_rule_bytes=discovery_bytes,
        qualification_receipt_bytes=[canonical_json_bytes(item) for item in receipts],
        statements=readiness_statements,
    )

    capacity_path = (tmp_path / "capacity.json").resolve()
    discovery_path = (tmp_path / "discovery.json").resolve()
    headers_path = (tmp_path / "headers.json").resolve()
    readiness_path = (tmp_path / "mirror-readiness.json").resolve()
    capacity_path.write_bytes(canonical_json_bytes(capacity))
    discovery_path.write_bytes(discovery_bytes)
    readiness_path.write_bytes(canonical_json_bytes(readiness))
    headers_path.write_bytes(
        canonical_json_bytes(
            MirrorRequestHeaders(
                schema=MIRROR_REQUEST_HEADERS_SCHEMA,
                readiness_set_path=str(readiness_path),
                origins=[
                    MirrorOriginRequestHeaders(
                        origin=origin,
                        headers={"Authorization": f"Bearer private-test-token-{index}"},
                    )
                    for index, origin in enumerate(origins)
                ],
            )
        )
    )
    headers_path.chmod(0o600)
    operator_config = LiveValidatorOperatorConfig(
        schema=LIVE_OPERATOR_CONFIG_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mode=LIVE_SHADOW_MODE,
        network="finney",
        wallet_name="validator",
        wallet_hotkey_name="default",
        wallet_path=str((tmp_path / "wallets").resolve()),
        validator_capacity_set_path=str(capacity_path),
        mirror_discovery_rule_path=str(discovery_path),
        mirror_request_headers_path=str(headers_path),
    )
    return policy, live_config, operator_config


def _install_test_chain_constants(
    monkeypatch: pytest.MonkeyPatch,
    policy: ScoringPolicy,
) -> None:
    """Bind the unit-test chain fixture at the production constructor boundary."""

    pin = policy.implementation_pins.finality_verifier
    assert pin is not None
    monkeypatch.setattr(
        grandpa_finality,
        "FINNEY_CHAIN_SPEC_SOURCE_REVISION",
        pin.chain_spec_source_revision,
    )
    monkeypatch.setattr(grandpa_finality, "FINNEY_CHAIN_SPEC_SHA256", pin.chain_spec_sha256)
    monkeypatch.setattr(grandpa_finality, "FINNEY_GENESIS_HASH", pin.expected_genesis_hash)
    monkeypatch.setattr(
        grandpa_finality,
        "FINNEY_BOOTSTRAP_BLOCK_NUMBER",
        pin.bootstrap_block_number,
    )
    monkeypatch.setattr(
        grandpa_finality,
        "FINNEY_BOOTSTRAP_BLOCK_HASH",
        pin.bootstrap_block_hash,
    )


def test_operator_config_and_artifacts_are_canonical_policy_bound_and_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, live_config, operator_config = _operator_material(tmp_path, monkeypatch)
    config_path = (tmp_path / "operator.json").resolve()
    config_path.write_bytes(canonical_json_bytes(operator_config))

    loaded = load_live_operator_config(config_path)
    artifacts = load_operator_artifacts(
        policy=policy,
        live_config=live_config,
        operator_config=loaded,
    )

    assert artifacts.capacity_set.policy_hash == scoring_policy_hash(policy)
    assert artifacts.mirror_request_headers == {
        f"https://mirror-{letter}.example": {"Authorization": f"Bearer private-test-token-{index}"}
        for index, letter in enumerate(("a", "b", "c"))
    }
    assert hashlib.sha256(artifacts.mirror_discovery_rule_bytes).hexdigest() == (
        policy.implementation_pins.rules.mirror_discovery_rule_sha256
    )

    config_path.write_bytes(canonical_json_bytes(operator_config) + b"\n")
    with pytest.raises(LiveValidatorOperatorError) as noncanonical:
        load_live_operator_config(config_path)
    assert noncanonical.value.reason_code == "operator_config_noncanonical"

    headers_path = Path(operator_config.mirror_request_headers_path)
    headers_path.chmod(0o644)
    with pytest.raises(LiveValidatorOperatorError) as public_secret:
        load_operator_artifacts(
            policy=policy,
            live_config=live_config,
            operator_config=operator_config,
        )
    assert public_secret.value.reason_code == "mirror_request_headers_unsafe"

    headers_path.chmod(0o600)
    headers_path.write_bytes(
        canonical_json_bytes(
            MirrorRequestHeaders(
                schema=MIRROR_REQUEST_HEADERS_SCHEMA,
                readiness_set_path=str((tmp_path / "mirror-readiness.json").resolve()),
                origins=[
                    MirrorOriginRequestHeaders(
                        origin="https://mirror-a.example",
                        headers={"Authorization": "Bearer only-one-origin"},
                    )
                ],
            )
        )
    )
    with pytest.raises(LiveValidatorOperatorError) as missing_origin:
        load_operator_artifacts(
            policy=policy,
            live_config=live_config,
            operator_config=operator_config,
        )
    assert missing_origin.value.reason_code == "mirror_request_headers_origin_set_mismatch"

    with pytest.raises(ValueError, match="must not share"):
        MirrorRequestHeaders(
            schema=MIRROR_REQUEST_HEADERS_SCHEMA,
            readiness_set_path=str((tmp_path / "mirror-readiness.json").resolve()),
            origins=[
                MirrorOriginRequestHeaders(
                    origin=origin,
                    headers={"Authorization": "Bearer shared-secret"},
                )
                for origin in (
                    "https://mirror-a.example",
                    "https://mirror-b.example",
                )
            ],
        )


def test_private_anchor_factory_accepts_exact_v11_client_and_hides_generic_capabilities() -> None:
    client = bt.Client("finney")
    wallet = dev_wallet("//Validator0")
    signer = bt.resolve_signer(wallet, role="hotkey")

    factory = PrivateBittensorAnchorFactory(client, signer)

    assert not hasattr(factory, "client")
    assert not hasattr(factory, "signer")
    assert not hasattr(factory, "submit_weights")
    asyncio.run(client.close())


def test_operator_dependencies_assemble_complete_offline_runtime_without_weight_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, live_config, operator_config = _operator_material(tmp_path, monkeypatch)
    _install_test_chain_constants(monkeypatch, policy)
    monkeypatch.setattr(
        "umi.validator_live._execute_packaged_conformance",
        lambda _policy, _config: None,
    )
    client = bt.Client("finney")
    wallet = next(
        dev_wallet(f"//Validator{index}")
        for index in range(4)
        if account_id32(dev_wallet(f"//Validator{index}").hotkey.ss58_address)
        == account_id32(live_config.validator_hotkey)
    )

    dependencies = build_live_operator_dependencies(
        live_config=live_config,
        operator_config=operator_config,
        policy=policy,
        client=client,
        wallet=wallet,
    )

    assert dependencies.missing_capability_codes() == ()
    assert dependencies.invalid_capability_codes() == ()
    assert FORBIDDEN_WEIGHT_CAPABILITY_NAMES.isdisjoint(
        LiveValidatorProductionDependencies.__dataclass_fields__
    )
    runtime = build_production_live_validator(
        config=live_config,
        dependencies=dependencies,
    )
    try:
        assert runtime.configured_stages == STAGE_ORDER
        assert not any(hasattr(runtime, name) for name in FORBIDDEN_WEIGHT_CAPABILITY_NAMES)
    finally:
        runtime.close()
        asyncio.run(client.close())


def test_primer_assembles_without_operator_config_wallet_or_mirror_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, live_config, operator_config = _operator_material(tmp_path, monkeypatch)
    _install_test_chain_constants(monkeypatch, policy)
    monkeypatch.setattr(
        "umi.validator_live._execute_packaged_conformance",
        lambda _policy, _config: None,
    )
    headers_path = Path(operator_config.mirror_request_headers_path)
    readiness_path = Path(
        MirrorRequestHeaders.model_validate_json(headers_path.read_bytes()).readiness_set_path
    )
    headers_path.unlink()
    readiness_path.unlink()

    primer = build_live_validator_primer(config=live_config)
    try:
        assert primer.control_plane.active_window() is None
        assert primer.policy_hash == scoring_policy_hash(policy)
        assert primer.paths.control_plane.is_file()
        assert primer.paths.protocol_state.is_file()
        assert primer.paths.finality_state.is_file()
        assert primer.paths.plan_observations.is_file()
        assert primer.paths.stage_journal.is_dir()
        assert not hasattr(primer, "wallet")
        assert not hasattr(primer, "mirror")
        assert not hasattr(primer, "anchor_ports")
        assert not hasattr(primer, "transport")
    finally:
        primer.close()


def test_configure_materializes_canonical_no_weight_documents_from_supplied_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    policy, live_config, operator_config = _operator_material(tmp_path, monkeypatch)
    policy_path = Path(live_config.policy_path)
    live_output = (tmp_path / "configured" / "live.json").resolve()
    operator_output = (tmp_path / "configured" / "operator.json").resolve()

    result = configure_operator(
        [
            "--policy",
            str(policy_path),
            "--conformance-release-root",
            live_config.conformance_release_root,
            "--state-root",
            live_config.state_root,
            "--validator-hotkey",
            live_config.validator_hotkey,
            "--target-triple",
            live_config.target_triple,
            "--storage-proof-verifier",
            live_config.storage_proof_verifier_binary,
            "--finality-verifier",
            live_config.finality_verifier_binary,
            "--finality-chain-spec",
            live_config.finality_chain_spec_path,
            "--signature-scheme",
            live_config.signature_scheme,
            "--umi-revision",
            live_config.umi_revision,
            "--wallet-name",
            operator_config.wallet_name,
            "--wallet-hotkey-name",
            operator_config.wallet_hotkey_name,
            "--wallet-path",
            operator_config.wallet_path,
            "--validator-capacity-set",
            operator_config.validator_capacity_set_path,
            "--mirror-discovery-rule",
            operator_config.mirror_discovery_rule_path,
            "--mirror-request-headers",
            operator_config.mirror_request_headers_path,
            "--live-config-output",
            str(live_output),
            "--operator-config-output",
            str(operator_output),
        ]
    )

    assert result == 0
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "configured"
    assert document["scoring_policy_sha256"] == scoring_policy_hash(policy)
    assert document["translation_weights_active"] is False
    assert live_output.read_bytes() == canonical_json_bytes(json.loads(live_output.read_bytes()))
    assert operator_output.read_bytes() == canonical_json_bytes(
        json.loads(operator_output.read_bytes())
    )
    assert stat_mode(live_output) == 0o600
    assert stat_mode(operator_output) == 0o600


class _Client:
    network = "finney"
    endpoint = "wss://entrypoint-finney.opentensor.ai:443"

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.connected = False

    async def connect(self):
        self.events.append("connect")
        self.connected = True
        return self

    async def close(self):
        self.events.append("close")
        self.connected = False


class _ColdSubstrate:
    class _Raw:
        async def rpc_request(self, _method, _params):
            raise AssertionError("--check must not issue JSON-RPC")

    raw = _Raw()

    async def compose(self, *_args, **_kwargs):
        raise AssertionError("--check must not compose an anchor")

    async def prepare(self, *_args, **_kwargs):
        raise AssertionError("--check must not prepare an anchor")

    async def submit_signature(self, *_args, **_kwargs):
        raise AssertionError("--check must not submit an anchor")


class _ColdClient(_Client):
    _substrate = _ColdSubstrate()

    async def connect(self):
        raise AssertionError("--check must not connect the Bittensor client")


class _Runtime:
    configured_stages = STAGE_ORDER
    scoring_policy_hash = "42" * 32

    def __init__(self, client: _Client, events: list[str]) -> None:
        self.client = client
        self.events = events

    async def run(self, _stop, *, poll_seconds: float):
        assert self.client.connected
        assert poll_seconds > 0
        self.events.append("run")

    def close(self):
        self.events.append("runtime_close")


def test_full_installed_check_assembles_cold_without_chain_or_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    policy, live_config, operator_config = _operator_material(tmp_path, monkeypatch)
    _install_test_chain_constants(monkeypatch, policy)
    monkeypatch.setattr(
        "umi.validator_live._execute_packaged_conformance",
        lambda _policy, _config: None,
    )
    live_path = (tmp_path / "live.json").resolve()
    operator_path = (tmp_path / "operator.json").resolve()
    live_path.write_bytes(canonical_json_bytes(live_config))
    operator_path.write_bytes(canonical_json_bytes(operator_config))
    wallet = next(
        dev_wallet(f"//Validator{index}")
        for index in range(4)
        if account_id32(dev_wallet(f"//Validator{index}").hotkey.ss58_address)
        == account_id32(live_config.validator_hotkey)
    )
    monkeypatch.setattr("umi.validator_operator.bt.Wallet", lambda **_kwargs: wallet)
    events: list[str] = []
    client = _ColdClient(events)

    result = asyncio.run(
        run_installed_operator(
            config_path=live_path,
            operator_config_path=operator_path,
            check=True,
            client_factory=lambda _network: client,
        )
    )

    assert result == 0
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "ready"
    assert document["configured_stages"] == [stage.value for stage in STAGE_ORDER]
    assert document["weight_submission_capability"] is False
    assert events == ["close"]


def test_full_installed_check_still_rejects_missing_mirror_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    _policy, live_config, operator_config = _operator_material(tmp_path, monkeypatch)
    live_path = (tmp_path / "live.json").resolve()
    operator_path = (tmp_path / "operator.json").resolve()
    live_path.write_bytes(canonical_json_bytes(live_config))
    operator_path.write_bytes(canonical_json_bytes(operator_config))
    headers = MirrorRequestHeaders.model_validate_json(
        Path(operator_config.mirror_request_headers_path).read_bytes()
    )
    Path(headers.readiness_set_path).unlink()
    wallet = next(
        dev_wallet(f"//Validator{index}")
        for index in range(4)
        if account_id32(dev_wallet(f"//Validator{index}").hotkey.ss58_address)
        == account_id32(live_config.validator_hotkey)
    )
    monkeypatch.setattr("umi.validator_operator.bt.Wallet", lambda **_kwargs: wallet)
    events: list[str] = []

    result = asyncio.run(
        run_installed_operator(
            config_path=live_path,
            operator_config_path=operator_path,
            check=True,
            client_factory=lambda _network: _ColdClient(events),
        )
    )

    assert result == 2
    assert json.loads(capsys.readouterr().err)["reason_code"] == (
        "mirror_readiness_set_unavailable"
    )
    assert events == ["close"]


@pytest.mark.parametrize("check", [True, False])
def test_installed_operator_owns_client_connection_lifetime(
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
    capsys,
) -> None:
    events: list[str] = []
    client = _Client(events)
    live_config = SimpleNamespace(poll_seconds=0.01)
    operator_config = SimpleNamespace(network="finney")
    policy = object()

    monkeypatch.setattr(
        "umi.validator_operator.load_live_validator_config", lambda _path: live_config
    )
    monkeypatch.setattr("umi.validator_operator.load_live_policy", lambda _config: policy)
    monkeypatch.setattr(
        "umi.validator_operator.load_live_operator_config", lambda _path: operator_config
    )

    def dependencies(**kwargs):
        assert kwargs["client"] is client
        assert client.connected is (not check)
        events.append("dependencies")
        return LiveValidatorProductionDependencies()

    monkeypatch.setattr("umi.validator_operator.build_live_operator_dependencies", dependencies)
    runtime = _Runtime(client, events)
    monkeypatch.setattr(
        "umi.validator_operator.build_production_live_validator", lambda **_kwargs: runtime
    )

    result = asyncio.run(
        run_installed_operator(
            config_path="unused-live.json",
            operator_config_path="unused-operator.json",
            check=check,
            client_factory=lambda _network: client,
        )
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out)["weight_submission_capability"] is False
    if check:
        assert events == ["dependencies", "runtime_close", "close"]
    else:
        assert events == ["connect", "dependencies", "run", "runtime_close", "close"]


def test_installed_cli_routes_operator_config_without_python_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    async def run_operator(**kwargs):
        calls.append(kwargs)
        return 7

    monkeypatch.setattr("umi.validator_operator.run_installed_operator", run_operator)

    assert (
        run_cli(
            [
                "--config",
                "/absolute/live.json",
                "--operator-config",
                "/absolute/operator.json",
                "--check",
            ]
        )
        == 7
    )
    assert calls == [
        {
            "config_path": Path("/absolute/live.json"),
            "operator_config_path": Path("/absolute/operator.json"),
            "check": True,
        }
    ]


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
