from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import bittensor as bt
import pytest
import rfc8785
from packaging.requirements import Requirement
from pydantic import ValidationError

import umi.conformance as conformance
import umi.rust_license as rust_license_module
import umi.shadow_release as shadow_release_module
import umi.validator_live as validator_live_module

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from umi.conformance import (
    ConformanceBinaryPins,
    ConformanceCaseResult,
    ConformanceExecution,
    ConformanceExecutionReport,
    ConformanceFixturePaths,
)
from umi.encoding import account_id32
from umi.grandpa_finality import (
    EVIDENCE_CLASS,
    RECORD_SCHEMA,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
    GrandpaFinalityObserver,
)
from umi.policy import (
    PolicyClock,
    PolicyLimits,
    PolicyThresholds,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ValidatorRegistryEntry,
)
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.release_chain_evidence import (
    RELEASE_OBSERVATION_EVIDENCE_PROFILE,
    RELEASE_OBSERVATION_EVIDENCE_SCHEMA,
    RUNTIME_METADATA_AUTHENTICATION,
    RUNTIME_VERSION_AUTHENTICATION,
)
from umi.shadow_release import (
    _LIVE_CAPTURE_AUTHORITY,
    BuiltMinerFinalityArtifact,
    BuiltShadowRelease,
    FinalizedReleaseObservation,
    FinalManifestAuthorityAttestation,
    LiveReleaseObservationCapture,
    LiveShadowReleaseInput,
    OperatorMaterializationBindings,
    ReleaseRelativeOperatorConfig,
    ReleaseRelativeValidatorConfig,
    ResolvedMinerRelease,
    ShadowReleaseError,
    _finality_source_tree_sha256,
    _umi_source_tree_sha256_from_wheel,
    _verify_packaged_policy_bindings,
    build_miner_finality_artifact,
    build_shadow_release,
    collect_live_release_observation,
    emit_miner_finality_artifact,
    emit_release_authority_request,
    emit_shadow_release_signing_stage,
    final_manifest_authority_request,
    finalize_main,
    finalize_shadow_release,
    main,
    materialize_operator_main,
    materialize_private_operator_configs,
    prepare_shadow_release,
    release_authority_request,
    verify_miner_release_target,
    verify_shadow_release_directory,
    verify_shadow_release_signing_stage,
)
from umi.substrate_proof import SubprocessStorageProofVerifier
from umi.validator_live import (
    LiveValidatorConfig,
    LiveValidatorConfigError,
    load_live_policy,
    validate_live_startup,
)
from umi.validator_live_ports import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
)
from umi.validator_operator import LiveValidatorOperatorConfig
from umi.validator_transcript_ports import (
    SignedValidatorCapacityStatement,
    ValidatorCapacitySetEvidence,
    ValidatorCapacityStatement,
    ValidatorResourceCapacities,
)

_TRANSCRIPT_DOMAIN = b"umi-grandpa-finality-attestation-v1\0"
_TEST_BOOTSTRAP_BLOCK = 998
_TEST_BOOTSTRAP_HASH = "0x" + "48" * 32
_RELEASE_PROOF_SIDECAR = (
    Path(__file__).parent / "fixtures" / "release_proof_sidecar_fake.sh"
).resolve()


class _FakeRuntime:
    def __init__(
        self,
        _metadata: bytes = b"test-metadata",
        spec_version: int = 452,
        transaction_version: int = 1,
        **_kwargs: object,
    ) -> None:
        self.spec_version = spec_version
        self.transaction_version = transaction_version

    def storage_key(self, pallet: str, item: str, params: list[object]) -> bytes:
        return hashlib.sha256(
            b"umi-test-release-storage-v1\0"
            + canonical_json_bytes({"item": item, "pallet": pallet, "params": params})
        ).digest()

    def storage_entry(self, _pallet: str, item: str) -> Any:
        return SimpleNamespace(modifier="Optional", default_bytes=b"", value_type=item)

    def decode(self, _value_type: str, encoded: bytes, *, strict: bool) -> object:
        assert strict
        return json.loads(encoded)

    def constant(self, pallet: str, name: str) -> int:
        assert (pallet, name) == ("System", "SS58Prefix")
        return 42


def _release_observation_evidence(
    *,
    block: dict[str, object],
    metadata: bytes,
    attestation: bytes,
    validators: list[ValidatorRegistryEntry],
    publishers: list[PublisherRegistryEntry],
    collateral_floor: int,
) -> bytes:
    runtime = _FakeRuntime()
    permits = [True] * len(validators) + [False] * len(publishers)
    values: list[tuple[str, str, tuple[object, ...], object]] = [
        ("System", "LastRuntimeUpgrade", (), {"spec_name": "node-subtensor", "spec_version": 452}),
        ("SubtensorModule", "NetworksAdded", (78,), True),
        ("SubtensorModule", "SubtokenEnabled", (78,), True),
        ("SubtensorModule", "FirstEmissionBlockNumber", (78,), 999),
        ("SubtensorModule", "MechanismCountCurrent", (78,), 1),
        ("SubtensorModule", "CommitRevealWeightsEnabled", (78,), True),
        ("SubtensorModule", "CommitRevealWeightsVersion", (), 4),
        ("SubtensorModule", "SubnetworkN", (78,), len(permits)),
        ("SubtensorModule", "ValidatorPermit", (78,), permits),
    ]
    for uid, entry in enumerate(validators):
        values.extend(
            (
                ("SubtensorModule", "Uids", (78, entry.validator_hotkey), uid),
                ("SubtensorModule", "Keys", (78, uid), entry.validator_hotkey),
            )
        )
    for offset, entry in enumerate(publishers, start=len(validators)):
        values.extend(
            (
                ("SubtensorModule", "Uids", (78, entry.publisher_hotkey), offset),
                ("SubtensorModule", "Keys", (78, offset), entry.publisher_hotkey),
                ("SubtensorModule", "Owner", (entry.publisher_hotkey,), entry.owner_coldkey),
                (
                    "SubtensorModule",
                    "MinerCollateral",
                    (78, entry.publisher_hotkey, entry.owner_coldkey),
                    {
                        "drain_ratio": 0,
                        "earned": 0,
                        "locked": collateral_floor,
                        "min_locked": collateral_floor,
                    },
                ),
            )
        )
    claims = []
    for pallet, item, params, value in values:
        key = runtime.storage_key(pallet, item, list(params))
        claims.append(
            {
                "item": item,
                "pallet": pallet,
                "params": list(params),
                "raw_value": "0x" + canonical_json_bytes(value).hex(),
                "storage_key": "0x" + key.hex(),
            }
        )
    claims.sort(key=lambda item: bytes.fromhex(item["storage_key"][2:]))
    runtime_version = canonical_json_bytes(
        {"specVersion": 452, "stateVersion": 1, "transactionVersion": 1}
    )
    return canonical_json_bytes(
        {
            "block_hash": block["hash"],
            "block_number": block["number"],
            "evidence_profile": RELEASE_OBSERVATION_EVIDENCE_PROFILE,
            "finality_attestation_sha256": hashlib.sha256(attestation).hexdigest(),
            "mechanism_id": 0,
            "netuid": 78,
            "network": "finney",
            "parent_hash": block["parent_hash"],
            "proof_batches": [
                {
                    "claims": claims,
                    "proof_nodes": ["0x" + b"release-observation-proof-v1".hex()],
                }
            ],
            "protocol": PROTOCOL_VERSION,
            "runtime": {
                "metadata_authentication": RUNTIME_METADATA_AUTHENTICATION,
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "runtime_version": "0x" + runtime_version.hex(),
                "spec_version": 452,
                "ss58_prefix": 42,
                "state_version": 1,
                "transaction_version": 1,
                "version_authentication": RUNTIME_VERSION_AUTHENTICATION,
            },
            "schema": RELEASE_OBSERVATION_EVIDENCE_SCHEMA,
            "state_root": block["state_root"],
            "timestamp_ms": block["timestamp_ms"],
            "total_unique_storage_keys": len(claims),
        }
    )


def _wallet(uri: str) -> Any:
    pair = bt.sp_core.Keypair.create_from_uri(uri)
    return SimpleNamespace(hotkey=pair)


def _compact(value: int) -> bytes:
    if value < 1 << 6:
        return bytes([value << 2])
    if value < 1 << 14:
        return ((value << 2) | 1).to_bytes(2, "little")
    return ((value << 2) | 2).to_bytes(4, "little")


def _write(path: Path, payload: bytes, *, executable: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o500 if executable else 0o400)
    return path.resolve()


def _write_finality_emitter(path: Path, record: bytes) -> Path:
    if b"'" in record or b"\n" in record:
        raise ValueError("fixture record cannot be embedded in a single-quoted shell string")
    path.chmod(0o600)
    path.write_bytes(b"#!/bin/sh\nset -eu\ncat >/dev/null\nprintf '%s\\n' '" + record + b"'\n")
    path.chmod(0o500)
    return path.resolve()


def _fake_uv(path: Path, *, version: str = "0.12.9") -> Path:
    return _write(
        path,
        (
            "#!/bin/sh\n"
            "set -eu\n"
            'if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then\n'
            f"  printf 'uv {version}\\n'\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$#" -ge 1 ] && [ "$1" = "lock" ]; then exit 0; fi\n'
            "exit 64\n"
        ).encode(),
        executable=True,
    )


def _static_elf(*, machine: int, salt: bytes, program_type: int = 1) -> bytes:
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[52:54] = (64).to_bytes(2, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (1).to_bytes(2, "little")
    program = bytearray(56)
    program[:4] = program_type.to_bytes(4, "little")
    program[4:8] = (5).to_bytes(4, "little")
    return bytes(header + program) + salt


def _arm64_mach_o(*, salt: bytes) -> bytes:
    header = bytearray(32)
    header[:4] = b"\xcf\xfa\xed\xfe"
    header[4:8] = (0x0100000C).to_bytes(4, "little")
    header[8:12] = (0).to_bytes(4, "little")
    header[12:16] = (2).to_bytes(4, "little")
    return bytes(header) + salt


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100444 << 16
            archive.writestr(info, payload)
    return output.getvalue()


def _wheel(
    path: Path,
    source_root: Path,
    *,
    entry_point_override: tuple[str, str] | None = None,
    extra_members: dict[str, bytes] | None = None,
    metadata_requirement: str | None = None,
    corrupt_record: bool = False,
) -> Path:
    repository_root = source_root.parents[1]
    project = tomllib.loads((repository_root / "pyproject.toml").read_text())["project"]
    dist_info = "umi_subnet-0.1.0.dist-info"
    members: list[tuple[str, bytes]] = [
        (
            "umi/" + source.relative_to(source_root).as_posix(),
            source.read_bytes(),
        )
        for source in sorted(source_root.rglob("*.py"))
    ]
    requirements = [str(Requirement(value)) for value in project["dependencies"]]
    extras: list[str] = []
    for extra, values in project["optional-dependencies"].items():
        extras.append(extra)
        requirements.extend(str(Requirement(f'{value}; extra == "{extra}"')) for value in values)
    if metadata_requirement is not None:
        requirements.append(metadata_requirement)
    metadata_lines = [
        "Metadata-Version: 2.5",
        f"Name: {project['name']}",
        f"Version: {project['version']}",
        f"Summary: {project['description']}",
        f"License-Expression: {project['license']}",
        "License-File: LICENSE",
        f"Requires-Python: {project['requires-python']}",
        *(f"Requires-Dist: {value}" for value in requirements),
        *(f"Provides-Extra: {value}" for value in extras),
        "Description-Content-Type: text/markdown",
    ]
    members.append(
        (
            f"{dist_info}/METADATA",
            "\n".join(metadata_lines).encode()
            + b"\n\n"
            + (repository_root / "README.md").read_bytes(),
        )
    )
    members.append(
        (
            f"{dist_info}/WHEEL",
            b"Wheel-Version: 1.0\n"
            b"Generator: hatchling 1.32.0\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n",
        )
    )
    scripts = dict(project["scripts"])
    if entry_point_override is not None:
        scripts[entry_point_override[0]] = entry_point_override[1]
    entry_points = "[console_scripts]\n" + "".join(
        f"{name} = {target}\n" for name, target in sorted(scripts.items())
    )
    members.append((f"{dist_info}/entry_points.txt", entry_points.encode()))
    members.append((f"{dist_info}/licenses/LICENSE", (repository_root / "LICENSE").read_bytes()))
    members.extend(sorted((extra_members or {}).items()))

    record_name = f"{dist_info}/RECORD"
    record_lines = []
    for name, payload in members:
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        record_lines.append(f"{name},sha256={digest},{len(payload)}\n")
    record_lines.append(f"{record_name},,\n")
    record = "".join(record_lines).encode()
    if corrupt_record:
        record = record.replace(b"sha256=", b"sha256=A", 1)
    members.append((record_name, record))

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, payload)
    path.chmod(0o400)
    return path.resolve()


def _block(number: int) -> dict[str, object]:
    parent = bytes.fromhex("19" * 32)
    encoded = (
        parent + _compact(number) + bytes.fromhex("2a" * 32) + bytes.fromhex("2b" * 32) + b"\x00"
    )
    return {
        "number": number,
        "hash": "0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest(),
        "parent_hash": "0x" + parent.hex(),
        "state_root": "0x" + "2a" * 32,
        "extrinsics_root": "0x" + "2b" * 32,
        "scale_header": "0x" + encoded.hex(),
        "timestamp_ms": number * 12_000,
    }


def _finality_record(
    *,
    binary: Path,
    chain_spec: Path,
    genesis_hash: str,
    block: dict[str, object],
) -> bytes:
    observer = GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=hashlib.sha256(chain_spec.read_bytes()).hexdigest(),
        expected_genesis_hash=genesis_hash,
        bootstrap_block_number=_TEST_BOOTSTRAP_BLOCK,
        bootstrap_block_hash=_TEST_BOOTSTRAP_HASH,
    )
    config, _encoded = observer._config(
        minimum_finalized_block=int(block["number"]),
        maximum_records=1,
        startup_timeout_seconds=30,
    )
    unsigned: dict[str, object] = {
        "schema": RECORD_SCHEMA,
        "request_id": config["request_id"],
        "evidence_class": EVIDENCE_CLASS,
        "offline_finality_proof": False,
        "source_revision": SOURCE_REVISION,
        "sequence": 0,
        "chain_spec_sha256": config["chain_spec_sha256"],
        "genesis_hash": config["expected_genesis_hash"],
        "bootstrap_block_number": config["bootstrap_block_number"],
        "bootstrap_block_hash": config["bootstrap_block_hash"],
        "bootstrap_source": "grandpa_checkpoint",
        "bootstrap_selected": True,
        "startup_finalized_block_number": block["number"],
        "startup_finalized_block_hash": block["hash"],
        "block": block,
        "ancestry": [
            {
                "number": block["number"],
                "hash": block["hash"],
                "parent_hash": block["parent_hash"],
            }
        ],
        "ancestry_complete_since_previous": False,
        "previous_finalized_hash": None,
        "previous_transcript_digest": "0" * 64,
    }
    return rfc8785.dumps(
        {
            **unsigned,
            "transcript_digest": hashlib.sha256(
                _TRANSCRIPT_DOMAIN + rfc8785.dumps(unsigned)
            ).hexdigest(),
        }
    )


def _capacity_set(validator_wallets: list[Any]) -> bytes:
    signed: list[SignedValidatorCapacityStatement] = []
    for wallet in sorted(
        validator_wallets, key=lambda item: account_id32(item.hotkey.ss58_address)
    ):
        statement = ValidatorCapacityStatement(
            schema="umi-validator-capacity/1",
            validator_hotkey=wallet.hotkey.ss58_address,
            hardware_class="mac-studio-m4-ultra",
            region_class="operator-premises-us-east",
            meter_adapter_version="umi-meter/1@sha256:"
            + hashlib.sha256(wallet.hotkey.ss58_address.encode()).hexdigest(),
            capacities=ValidatorResourceCapacities(
                cpu_core_milliseconds_per_window=100_000_000,
                accelerator_milliseconds_per_window=0,
                peak_host_memory_bytes=256 * 1024**3,
                peak_accelerator_memory_bytes=0,
                retained_storage_bytes=8 * 1024**3,
            ),
        )
        digest = hashlib.sha256(
            b"umi-validator-capacity-v1\0" + canonical_json_bytes(statement)
        ).digest()
        signed.append(
            SignedValidatorCapacityStatement(
                statement=statement,
                signature_scheme="sr25519",
                signature="0x" + bytes(wallet.hotkey.sign(digest)).hex(),
            )
        )
    evidence = ValidatorCapacitySetEvidence(
        schema="umi-validator-capacity-set-evidence/1",
        protocol=PROTOCOL_VERSION,
        statements=signed,
    )
    return canonical_json_bytes(evidence)


@pytest.fixture
def release_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture]:
    monkeypatch.setattr("umi.release_chain_evidence.bittensor_core.Runtime", _FakeRuntime)

    def execute_fixture_conformance(
        fixture_paths: ConformanceFixturePaths,
        *,
        binaries: ConformanceBinaryPins,
    ) -> ConformanceExecution:
        fixture_digests = {
            category: hashlib.sha256(getattr(fixture_paths, category).read_bytes()).hexdigest()
            for category in (
                "normalization",
                "media",
                "timelock",
                "chain",
                "live_chain",
                "storage_proof",
                "finality",
            )
        }
        binary_digests: dict[str, str] = {}
        for name in ("ffmpeg", "ffprobe", "storage_proof_verifier", "finality_verifier"):
            path = getattr(binaries, f"{name}_path")
            expected = getattr(binaries, f"{name}_sha256")
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
            if observed != expected:
                raise conformance.ConformanceError(f"{name}_digest_mismatch")
            binary_digests[name] = observed
        cases = [
            ConformanceCaseResult(
                category=category,
                case_id=case_id,
                output_sha256=hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "binary_sha256_by_name": binary_digests,
                            "case_id": case_id,
                            "category": category,
                            "fixture_sha256": fixture_digests[category],
                        }
                    )
                ).hexdigest(),
            )
            for category, case_id in conformance._all_case_keys()
        ]
        report = ConformanceExecutionReport(
            schema="umi-conformance-execution-report/1",
            verified=True,
            fixture_sha256_by_category=fixture_digests,
            binary_sha256_by_name=binary_digests,
            cases=cases,
        )
        encoded = canonical_json_bytes(report)
        return ConformanceExecution(
            report=report,
            canonical_report_bytes=encoded,
            report_sha256=hashlib.sha256(encoded).hexdigest(),
        )

    monkeypatch.setattr("umi.shadow_release.execute_conformance_suite", execute_fixture_conformance)
    monkeypatch.setattr("umi.validator_live.execute_conformance_suite", execute_fixture_conformance)
    original_invoke_staged = SubprocessStorageProofVerifier._invoke_staged

    def run_fixture_source(
        verifier: SubprocessStorageProofVerifier,
        _staged_binary: Path,
        *,
        request_bytes: bytes,
        request_id: str,
    ) -> bool:
        # macOS can quarantine-delay each freshly copied shell fixture. The
        # verifier's dedicated tests cover staged execution; release tests need
        # the deterministic protocol fake after the staging integrity check.
        return original_invoke_staged(
            verifier,
            verifier.binary_path,
            request_bytes=request_bytes,
            request_id=request_id,
        )

    monkeypatch.setattr(SubprocessStorageProofVerifier, "_invoke_staged", run_fixture_source)

    def fixture_observer_from_pin(
        _cls: type[GrandpaFinalityObserver],
        pin: Any,
        *,
        target_triple: str,
        binary_path: Path,
        chain_spec_path: Path,
        **_kwargs: object,
    ) -> GrandpaFinalityObserver:
        return GrandpaFinalityObserver(
            binary_path=binary_path,
            expected_binary_sha256=pin.release_sha256_by_target[target_triple],
            chain_spec_path=chain_spec_path,
            expected_chain_spec_sha256=pin.chain_spec_sha256,
            expected_genesis_hash="0x" + pin.expected_genesis_hash,
            bootstrap_block_number=pin.bootstrap_block_number,
            bootstrap_block_hash="0x" + pin.bootstrap_block_hash,
        )

    monkeypatch.setattr(
        GrandpaFinalityObserver,
        "from_policy_pin",
        classmethod(fixture_observer_from_pin),
    )

    repository_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(
        shadow_release_module,
        "_verified_clean_repository_revision",
        lambda root: "ab" * 20 if root == repository_root else "",
    )

    def fixture_rust_license_closure(
        *,
        source_root: Path,
        repository_root: Path,
        target_triple: str,
        binary_name: str,
        expected_root_package: str,
    ) -> bytes:
        assert source_root.is_dir()
        assert repository_root == Path(__file__).resolve().parents[1]
        assert target_triple in {
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-musl",
        }
        assert binary_name == expected_root_package
        return _zip_bytes(
            {
                "fixture.json": canonical_json_bytes(
                    {"binary_name": binary_name, "target_triple": target_triple}
                )
            }
        )

    def verify_fixture_rust_license_closure(
        payload: bytes,
        *,
        cargo_lock_bytes: bytes,
        target_triple: str,
        binary_name: str,
    ) -> None:
        assert payload
        assert cargo_lock_bytes.startswith(b"# This file is automatically")
        assert target_triple in {
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-musl",
        }
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            fixture = json.loads(archive.read("fixture.json"))
        assert fixture == {"binary_name": binary_name, "target_triple": target_triple}

    monkeypatch.setattr(
        shadow_release_module,
        "build_rust_license_closure",
        fixture_rust_license_closure,
    )
    monkeypatch.setattr(
        shadow_release_module,
        "verify_rust_license_closure",
        verify_fixture_rust_license_closure,
    )
    source_root = repository_root / "src" / "umi"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    target_triple = "aarch64-unknown-linux-musl"
    observation_block = 1_000
    minimum_release_lead_blocks = PolicyClock.launch().window_stride_blocks
    activation_block = observation_block + minimum_release_lead_blocks
    block = _block(observation_block)
    monkeypatch.setattr(
        "umi.shadow_release._finalization_clock_ms",
        lambda: int(block["timestamp_ms"]) + 10,
    )
    genesis = "0x" + hashlib.sha256(b"finney-genesis-test").hexdigest()

    validators = [_wallet(f"//ReleaseValidator{index}") for index in range(4)]
    validator_registry = [
        ValidatorRegistryEntry(
            validator_hotkey=wallet.hotkey.ss58_address,
            administrator_id=hashlib.sha256(f"validator-admin-{index}".encode()).hexdigest(),
        )
        for index, wallet in enumerate(validators)
    ]
    validator_registry.sort(key=lambda item: account_id32(item.validator_hotkey))

    group_wallets = [_wallet(f"//ReleaseGroup{index}") for index in range(3)]
    publisher_wallets = [_wallet(f"//ReleasePublisher{index}") for index in range(3)]
    groups = [
        PublisherControlGroup(
            control_group_id=hashlib.sha256(f"group-{index}".encode()).hexdigest(),
            administrator=wallet.hotkey.ss58_address,
        )
        for index, wallet in enumerate(group_wallets)
    ]
    groups.sort(key=lambda item: bytes.fromhex(item.control_group_id))
    group_wallet_by_address = {wallet.hotkey.ss58_address: wallet for wallet in group_wallets}
    publishers = []
    for group, publisher_wallet in zip(groups, publisher_wallets, strict=True):
        publishers.append(
            PublisherRegistryEntry(
                publisher_hotkey=publisher_wallet.hotkey.ss58_address,
                owner_coldkey=group.administrator,
                control_group_id=group.control_group_id,
            )
        )
    publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))

    finality_binary = _write(
        artifact_root / "finality-observer",
        b"#!/bin/sh\nexit 99\n",
        executable=True,
    )
    proof_binary = _RELEASE_PROOF_SIDECAR
    ffmpeg = _write(
        artifact_root / "ffmpeg",
        _static_elf(machine=183, salt=b"ffmpeg-test-static-runtime"),
        executable=True,
    )
    ffprobe = _write(
        artifact_root / "ffprobe",
        _static_elf(machine=183, salt=b"ffprobe-test-static-runtime"),
        executable=True,
    )
    media_license_bundle = _write(
        artifact_root / "media-runtime-licenses.zip",
        _zip_bytes(
            {
                "LICENSES/DEPENDENCIES.md": b"No enabled third-party libraries in test build.\n",
                "LICENSES/FFmpeg.txt": b"FFmpeg test redistribution notice.\n",
            }
        ),
    )
    test_media_source = b"test-only FFmpeg source archive bytes\n"
    test_media_source_digest = hashlib.sha256(test_media_source).hexdigest()
    monkeypatch.setattr(
        shadow_release_module,
        "_PINNED_FFMPEG_SOURCE_SHA256",
        test_media_source_digest,
    )
    media_source_bundle = _write(
        artifact_root / "media-runtime-source.zip",
        _zip_bytes(
            {
                "BUILD.md": b"Deterministic test-only static build instructions.\n",
                "SOURCES/ffmpeg-8.0.1.tar.xz": test_media_source,
                "SOURCE-MANIFEST.sha256": (
                    test_media_source_digest + "  SOURCES/ffmpeg-8.0.1.tar.xz\n"
                ).encode(),
            }
        ),
    )
    media_runtime_manifest = _write(
        artifact_root / "media-runtime-closure.json",
        canonical_json_bytes(
            {
                "corresponding_source_bundle_sha256": hashlib.sha256(
                    media_source_bundle.read_bytes()
                ).hexdigest(),
                "ffmpeg_binary_sha256": hashlib.sha256(ffmpeg.read_bytes()).hexdigest(),
                "ffmpeg_configuration": "--disable-shared --enable-static --disable-autodetect",
                "ffmpeg_version": "8.0.1",
                "ffprobe_binary_sha256": hashlib.sha256(ffprobe.read_bytes()).hexdigest(),
                "license_bundle_sha256": hashlib.sha256(
                    media_license_bundle.read_bytes()
                ).hexdigest(),
                "license_expression": "LGPL-2.1-or-later",
                "linkage": "static-elf-without-pt-interp-or-pt-dynamic",
                "profile": "target-bound-static-elf-media-runtime/1",
                "redistribution_reviewed": True,
                "runtime_dependencies": [],
                "schema": "umi-media-runtime-closure/1",
                "target_triple": target_triple,
            }
        ),
    )
    chain_spec = _write(
        artifact_root / "finney.json",
        canonical_json_bytes({"id": "finney-test", "name": "Finney test"}),
    )
    attestation = _write(
        artifact_root / "finality-attestation.json",
        _finality_record(
            binary=finality_binary,
            chain_spec=chain_spec,
            genesis_hash=genesis,
            block=block,
        ),
    )
    _write_finality_emitter(finality_binary, attestation.read_bytes())
    attestation.chmod(0o600)
    attestation.write_bytes(
        _finality_record(
            binary=finality_binary,
            chain_spec=chain_spec,
            genesis_hash=genesis,
            block=block,
        )
    )
    attestation.chmod(0o400)
    _write_finality_emitter(finality_binary, attestation.read_bytes())
    capacity_set = _write(
        artifact_root / "validator-capacity.json",
        _capacity_set(validators),
    )
    mirror_rule = _write(
        artifact_root / "mirror-discovery.json",
        canonical_json_bytes(
            {
                "authentication_profile": "umi-authenticated-content-mirror/1",
                "delivery_issuance_path": DEFAULT_DELIVERY_ISSUANCE_PATH,
                "delivery_origins": [
                    "https://delivery-a.example",
                    "https://delivery-b.example",
                ],
                "index_path_template": DEFAULT_MIRROR_INDEX_PATH,
                "origins": ["https://mirror-a.example", "https://mirror-b.example"],
                "protocol": PROTOCOL_VERSION,
                "schema": MIRROR_DISCOVERY_SCHEMA,
            }
        ),
    )
    fixture_names = (
        "normalization",
        "frame",
        "timelock",
        "chain",
        "live-chain",
        "storage-proof",
    )
    fixture_paths = {
        name: _write(
            artifact_root / f"{name}.json",
            canonical_json_bytes(
                {"fixture": name, "nonce": hashlib.sha256(("fixture-" + name).encode()).hexdigest()}
            ),
        )
        for name in fixture_names
    }
    finality_fixture = (
        repository_root / "rust" / "grandpa-finality-observer" / "fixtures" / "finality-v1.json"
    ).resolve()
    wheel = _wheel(artifact_root / "umi_subnet-0.1.0-py3-none-any.whl", source_root)
    lockfile = _write(
        artifact_root / "uv.lock",
        (repository_root / "uv.lock").read_bytes(),
    )
    uv_binary = _fake_uv(artifact_root / "uv")
    uv_binary_digest = hashlib.sha256(uv_binary.read_bytes()).hexdigest()
    uv_archive_digest = hashlib.sha256(
        b"uv 0.12.9 aarch64-unknown-linux-musl upstream archive"
    ).hexdigest()
    uv_source_digest = hashlib.sha256(b"uv 0.12.9 upstream source").hexdigest()
    monkeypatch.setitem(
        shadow_release_module._PINNED_UV_BINARY_SHA256_BY_TARGET,
        target_triple,
        uv_binary_digest,
    )
    monkeypatch.setitem(
        shadow_release_module._PINNED_UV_ARCHIVE_SHA256_BY_TARGET,
        target_triple,
        uv_archive_digest,
    )
    monkeypatch.setattr(
        shadow_release_module,
        "_PINNED_UV_SOURCE_ARCHIVE_SHA256",
        uv_source_digest,
    )
    uv_license = _write(
        artifact_root / "uv-LICENSE",
        b"Test fixture for upstream Apache-2.0 OR MIT uv license texts.\n",
    )
    monkeypatch.setattr(
        shadow_release_module,
        "_PINNED_UV_LICENSE_SHA256",
        hashlib.sha256(uv_license.read_bytes()).hexdigest(),
    )
    uv_provenance = _write(
        artifact_root / "uv-provenance.json",
        canonical_json_bytes(
            {
                "binary_archive_sha256": uv_archive_digest,
                "binary_archive_url": (
                    "https://github.com/astral-sh/uv/releases/download/0.12.9/"
                    "uv-aarch64-unknown-linux-musl.tar.gz"
                ),
                "binary_sha256": uv_binary_digest,
                "license_expression": "Apache-2.0 OR MIT",
                "license_sha256": hashlib.sha256(uv_license.read_bytes()).hexdigest(),
                "schema": "umi-uv-tool-provenance/1",
                "source_archive_sha256": uv_source_digest,
                "source_archive_url": (
                    "https://github.com/astral-sh/uv/releases/download/0.12.9/source.tar.gz"
                ),
                "target_triple": target_triple,
                "tool": "uv",
                "version": "0.12.9",
            }
        ),
    )
    metadata = _write(
        artifact_root / "metadata.scale",
        b"meta" + hashlib.sha256(b"runtime-metadata").digest(),
    )
    release_observation_evidence = _write(
        artifact_root / "release-observation-chain-evidence.json",
        _release_observation_evidence(
            block=block,
            metadata=metadata.read_bytes(),
            attestation=attestation.read_bytes(),
            validators=validator_registry,
            publishers=publishers,
            collateral_floor=1_000_000_000,
        ),
    )
    cost_schedule = _write(
        artifact_root / "cost-schedule.json",
        canonical_json_bytes(
            {
                "class_price_rule": "greatest-of-three-independent-list-prices/1",
                "classes": [
                    {
                        "accelerator_count": 0,
                        "accelerator_memory_bytes": 0,
                        "cpu_core_count": 64,
                        "hardware_class": "mac-studio-m4-ultra",
                        "host_memory_bytes": 256 * 1024**3,
                        "list_prices": [
                            {
                                "captured_at_ms": block["timestamp_ms"],
                                "content_sha256": hashlib.sha256(
                                    f"cost-source-{index}".encode()
                                ).hexdigest(),
                                "price_minor_units_per_window": 100 + index,
                                "source_id": f"source-{index}",
                                "url": f"https://prices-{index}.example/mac-studio",
                            }
                            for index in range(3)
                        ],
                        "provisioned_storage_bytes": 8 * 1024**3,
                        "region_class": "operator-premises-us-east",
                        "selected_price_minor_units_per_window": 102,
                        "unit_definition": "one complete 360-block validator window",
                    }
                ],
                "currency_minor_units_per_major": 100,
                "executable_alpha_quote_function": "policy-pinned executable pool quote",
                "reporting_currency": "USD",
                "schema": "umi-validator-cost-schedule/1",
                "tao_price_observation_rule": "least of three spot observations",
            }
        ),
    )
    disclosures = {
        group.control_group_id: _write(
            artifact_root / f"disclosure-{group.control_group_id}.json",
            canonical_json_bytes(
                {
                    "control_group_id": group.control_group_id,
                    "disclosure": hashlib.sha256(group.control_group_id.encode()).hexdigest(),
                }
            ),
        )
        for group in groups
    }
    capacity_inputs = [
        {
            "control_group_id": group.control_group_id,
            "issued_block": observation_block,
            "issued_block_hash": block["hash"],
            "valid_from_block": activation_block,
            "valid_through_block": activation_block + 1_800 * 360,
            "control_disclosure_path": str(disclosures[group.control_group_id]),
            "signature_scheme": "sr25519",
            "signature": None,
        }
        for group in groups
    ]
    operators = [
        {
            "validator_hotkey": entry.validator_hotkey,
            "signature_scheme": "sr25519",
        }
        for entry in validator_registry
    ]
    release_root = (tmp_path / "public-release").resolve()
    data = {
        "schema": "umi-live-shadow-release-input/1",
        "protocol": PROTOCOL_VERSION,
        "mode": "live_shadow_calibration",
        "network": "finney",
        "translation_weights_active": False,
        "repository_root": str(repository_root),
        "release_install_root": str(release_root),
        "target_triple": target_triple,
        "activation_block": activation_block,
        "minimum_release_lead_blocks": minimum_release_lead_blocks,
        "maximum_finalized_head_age_ms": 120_000,
        "minimum_publisher_collateral_alpha_rao": 1_000_000_000,
        "soak_start_window_index": 7,
        "clock": PolicyClock.launch().model_dump(mode="json"),
        "limits": PolicyLimits.launch().model_dump(mode="json"),
        "thresholds": PolicyThresholds.launch().model_dump(mode="json"),
        "observation": {
            "network": "finney",
            "block_number": observation_block,
            "block_hash": block["hash"],
            "parent_hash": block["parent_hash"],
            "state_root": block["state_root"],
            "runtime_query_block_hash": block["hash"],
            "topology_query_block_hash": block["hash"],
            "runtime_metadata_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
            "finality_attestation_sha256": hashlib.sha256(attestation.read_bytes()).hexdigest(),
            "timestamp_ms": block["timestamp_ms"],
            "observed_at_ms": block["timestamp_ms"] + 1,
            "genesis_block_hash": genesis,
            "runtime_spec_version": 452,
            "transaction_version": 1,
            "state_version": 1,
            "subtensor_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
            "netuid": 78,
            "mechanism_id": 0,
            "mechanism_count": 1,
            "commit_reveal_enabled": True,
            "commit_reveal_version": 4,
            "subnet_active": True,
            "translation_weights_active": False,
            "target_block_interval_seconds": 12,
        },
        "artifacts": {
            "python_wheel": str(wheel),
            "python_lockfile": str(lockfile),
            "uv_binary": str(uv_binary),
            "uv_license": str(uv_license),
            "uv_provenance": str(uv_provenance),
            "ffmpeg_binary": str(ffmpeg),
            "ffprobe_binary": str(ffprobe),
            "media_runtime_manifest": str(media_runtime_manifest),
            "media_runtime_license_bundle": str(media_license_bundle),
            "media_runtime_source_bundle": str(media_source_bundle),
            "runtime_metadata": str(metadata),
            "validator_capacity_set": str(capacity_set),
            "validator_cost_schedule": str(cost_schedule),
            "mirror_discovery_rule": str(mirror_rule),
            "normalization_fixture_set": str(fixture_paths["normalization"]),
            "frame_digest_fixture_set": str(fixture_paths["frame"]),
            "portable_envelope_fixture_set": str(fixture_paths["timelock"]),
            "chain_fixture_set": str(fixture_paths["chain"]),
            "live_chain_fixture_set": str(fixture_paths["live-chain"]),
            "storage_proof_fixture_set": str(fixture_paths["storage-proof"]),
            "finality_fixture_set": str(finality_fixture),
            "storage_proof_verifier_binary": str(proof_binary),
            "finality_verifier_binary": str(finality_binary),
            "finality_chain_spec": str(chain_spec),
            "finality_attestation": str(attestation),
            "release_observation_chain_evidence": str(release_observation_evidence),
        },
        "storage_proof": {
            "polkadot_sdk_revision": "cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a",
            "source_root": str((repository_root / "rust" / "substrate-proof-verifier").resolve()),
        },
        "finality": {
            "source_root": str((repository_root / "rust" / "grandpa-finality-observer").resolve()),
            "chain_spec_source_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
            "replay": {
                "maximum_records": 1,
                "startup_timeout_seconds": 30,
                "bootstrap_kind": "grandpa_warp_sync_checkpoint",
                "bootstrap_block_number": _TEST_BOOTSTRAP_BLOCK,
                "bootstrap_block_hash": _TEST_BOOTSTRAP_HASH[2:],
            },
        },
        "validator_registry": [item.model_dump(mode="json") for item in validator_registry],
        "control_group_registry": [item.model_dump(mode="json") for item in groups],
        "publisher_registry": [item.model_dump(mode="json") for item in publishers],
        "publisher_capacities": capacity_inputs,
        "release_authority": {
            "authority_hotkey": validators[0].hotkey.ss58_address,
            "signature_scheme": "sr25519",
            "signature": None,
        },
        "operators": operators,
    }
    unsigned = LiveShadowReleaseInput.model_validate(data)
    prepared = prepare_shadow_release(unsigned, now_ms=block["timestamp_ms"] + 10)
    signatures: dict[str, str] = {}
    for request in prepared.signing_requests:
        wallet = group_wallet_by_address[request.administrator]
        signatures[request.control_group_id] = (
            "0x" + bytes(wallet.hotkey.sign(bytes.fromhex(request.digest))).hex()
        )
    data["publisher_capacities"] = [
        {**item, "signature": signatures[item["control_group_id"]]} for item in capacity_inputs
    ]
    unsigned_release = LiveShadowReleaseInput.model_validate(data)
    authority_request = release_authority_request(
        prepare_shadow_release(unsigned_release, now_ms=block["timestamp_ms"] + 10)
    )
    data["release_authority"]["signature"] = (
        "0x" + bytes(validators[0].hotkey.sign(bytes.fromhex(authority_request.digest))).hex()
    )
    descriptor = LiveShadowReleaseInput.model_validate(data)
    capture = LiveReleaseObservationCapture(
        observation=descriptor.observation,
        finality_attestation=attestation.read_bytes(),
        chain_evidence=release_observation_evidence.read_bytes(),
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )
    return descriptor, release_root, block["timestamp_ms"] + 10, capture


def _descriptor_with_darwin_miner(
    descriptor: LiveShadowReleaseInput,
    tmp_path: Path,
    *,
    now_ms: int,
) -> tuple[LiveShadowReleaseInput, bytes]:
    repository = Path(descriptor.repository_root)
    source_root = repository / "rust" / "grandpa-finality-observer"
    fixture_bytes = (source_root / "fixtures" / "finality-v1.json").read_bytes()
    target = "aarch64-apple-darwin"
    native_artifact = os.environ.get("UMI_TEST_NATIVE_DARWIN_FINALITY_ARTIFACT_DIR")
    if native_artifact is not None:
        artifact_root = Path(native_artifact).resolve(strict=True)
        binary = artifact_root / "umi-grandpa-finality-observer"
        report = artifact_root / "miner-finality-build-report.json"
        license_closure = artifact_root / "finality-third-party-licenses.zip"
        native_report = shadow_release_module.MinerFinalityBuildReport.model_validate_json(
            report.read_bytes()
        )
        self_test_bytes = canonical_json_bytes(native_report.self_test)
    else:
        fixture = conformance.FinalityFixtures.model_validate_json(fixture_bytes)
        self_test = {
            "case_ids": [
                "checkpoint-header-positive",
                "contiguous-first-positive",
                "contiguous-second-positive",
                "finney-checkpoint-positive",
                "missing-prefix-negative",
                "truncated-header-negative",
            ],
            "finney_checkpoint_canonical_sha256": fixture.finney_checkpoint_fixture.sha256,
            "fixture_canonical_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
            "ok": True,
            "schema": "umi-grandpa-finality-conformance-result/1",
        }
        self_test_bytes = canonical_json_bytes(self_test)
        artifact_root = tmp_path / "darwin-miner"
        binary = _write(
            artifact_root / "umi-grandpa-finality-observer",
            _arm64_mach_o(salt=b"darwin-miner-finality-fixture"),
            executable=True,
        )
        license_closure = _write(
            artifact_root / "finality-third-party-licenses.zip",
            _zip_bytes(
                {
                    "fixture.json": canonical_json_bytes(
                        {
                            "binary_name": "umi-grandpa-finality-observer",
                            "target_triple": target,
                        }
                    )
                }
            ),
        )
        report = _write(
            artifact_root / "miner-finality-build-report.json",
            canonical_json_bytes(
                {
                    "binary_format": "mach-o-64-arm64-executable",
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "binary_size_bytes": len(binary.read_bytes()),
                    "finality_cargo_lock_sha256": hashlib.sha256(
                        (source_root / "Cargo.lock").read_bytes()
                    ).hexdigest(),
                    "finality_fixture_set_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
                    "finality_source_revision": shadow_release_module.FINALITY_SOURCE_REVISION,
                    "finality_source_tree_sha256": (
                        shadow_release_module.FINALITY_SOURCE_TREE_SHA256
                    ),
                    "host_architecture": "arm64",
                    "host_operating_system": "darwin",
                    "license_closure_sha256": hashlib.sha256(
                        license_closure.read_bytes()
                    ).hexdigest(),
                    "media_runtime_included": False,
                    "role": "miner-finality-only",
                    "schema": "umi-miner-finality-build-report/1",
                    "self_test": self_test,
                    "self_test_output_sha256": hashlib.sha256(self_test_bytes).hexdigest(),
                    "target_triple": target,
                    "umi_git_revision": "ab" * 20,
                    "validator_runtime_supported": False,
                }
            ),
        )
    values = descriptor.model_dump(mode="json", by_alias=True)
    values["miner_finality_targets"] = [
        {
            "binary_path": str(binary),
            "build_report_path": str(report),
            "expected_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "expected_build_report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "expected_license_closure_sha256": hashlib.sha256(
                license_closure.read_bytes()
            ).hexdigest(),
            "license_closure_path": str(license_closure),
            "target_triple": target,
        }
    ]
    for item in values["publisher_capacities"]:
        item["signature"] = None
    values["release_authority"]["signature"] = None
    unsigned = LiveShadowReleaseInput.model_validate(values)
    prepared = prepare_shadow_release(unsigned, now_ms=now_ms)
    group_wallets = [_wallet(f"//ReleaseGroup{index}") for index in range(3)]
    wallets_by_account = {
        account_id32(wallet.hotkey.ss58_address): wallet for wallet in group_wallets
    }
    signatures = {
        request.control_group_id: "0x"
        + bytes(
            wallets_by_account[account_id32(request.administrator)].hotkey.sign(
                bytes.fromhex(request.digest)
            )
        ).hex()
        for request in prepared.signing_requests
    }
    for item in values["publisher_capacities"]:
        item["signature"] = signatures[item["control_group_id"]]
    capacity_signed = LiveShadowReleaseInput.model_validate(values)
    authority_request = release_authority_request(
        prepare_shadow_release(capacity_signed, now_ms=now_ms)
    )
    authority_wallet = _wallet("//ReleaseValidator0")
    values["release_authority"]["signature"] = (
        "0x" + bytes(authority_wallet.hotkey.sign(bytes.fromhex(authority_request.digest))).hex()
    )
    return LiveShadowReleaseInput.model_validate(values), self_test_bytes


def _final_authority(build: BuiltShadowRelease) -> FinalManifestAuthorityAttestation:
    request = final_manifest_authority_request(build.manifest)
    wallet = _wallet("//ReleaseValidator0")
    assert account_id32(wallet.hotkey.ss58_address) == account_id32(request.authority_hotkey)
    return FinalManifestAuthorityAttestation(
        schema="umi-live-shadow-final-manifest-authority/1",
        authority_hotkey=request.authority_hotkey,
        signature_scheme=request.signature_scheme,
        unsigned_manifest_sha256=request.unsigned_manifest_sha256,
        digest=request.digest,
        signature="0x" + bytes(wallet.hotkey.sign(bytes.fromhex(request.digest))).hex(),
    )


def test_release_build_is_deterministic_inactive_and_contains_no_secrets(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    first = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    second = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)

    assert first.files == second.files
    assert first.policy.translation_weights_active is False
    assert first.manifest.translation_weights_active is False
    assert first.manifest.activation_block == descriptor.activation_block
    assert first.manifest.minimum_release_lead_blocks == descriptor.minimum_release_lead_blocks
    assert first.manifest.umi_git_revision == "ab" * 20
    assert first.manifest.release_observation_block == descriptor.observation.block_number
    assert first.manifest.release_observation_block_hash == descriptor.observation.block_hash
    assert first.manifest.observation_verification_profile == (
        "direct-hash-pinned-smoldot-p2p-plus-layout-v1-release-observation-state/1"
    )
    assert first.manifest.supplied_observation_role == ("capacity-signing-baseline-replay-only/1")
    assert first.manifest.runtime_metadata_authentication == RUNTIME_METADATA_AUTHENTICATION
    assert first.manifest.runtime_version_authentication == RUNTIME_VERSION_AUTHENTICATION
    assert first.manifest.public_artifacts_include_operator_configuration is True
    assert first.manifest.operator_configuration_profile == "release-relative-public-template/1"
    assert first.manifest.artifact_packaging_profile == "target-bound-static-runtime-closure/1"
    assert first.manifest.release_authenticity_profile == (
        "same-expected-hotkey-signed-static-intent-and-final-manifest/1"
    )
    assert first.manifest.release_authority.authority_hotkey == (
        descriptor.release_authority.authority_hotkey
    )
    assert "input_descriptor_sha256" not in first.manifest.model_dump(mode="json")
    assert "release-manifest.unsigned.json" in first.files
    assert "release-manifest-signing-request.json" in first.files
    assert "release-manifest.json" not in first.files
    assert len([name for name in first.files if name.startswith("operator-templates/")]) == 8
    validator_template_bytes = next(
        payload
        for name, payload in first.files.items()
        if name.endswith(".validator-template.json")
    )
    validator_template = json.loads(validator_template_bytes)
    assert validator_template["transport_timeout_seconds"] == 90.0
    assert validator_template["umi_revision"].startswith(
        "git:" + "ab" * 20 + ";source-tree-sha256:"
    )
    assert len([name for name in first.files if name.startswith("publisher-capacity/")]) == 3
    assert "replay_release_observation_chain_evidence" in {
        item.label for item in first.manifest.external_artifacts
    }
    assert "release-observation/chain-evidence.json" in first.files
    assert "release-observation/finality-attestation.json" in first.files
    assert "conformance-execution-report.json" in first.files
    report_bytes = first.files["conformance-execution-report.json"]
    report = ConformanceExecutionReport.model_validate_json(report_bytes)
    assert canonical_json_bytes(report) == report_bytes
    assert report.verified is True
    assert len(report.cases) == 34
    assert hashlib.sha256(report_bytes).hexdigest() == (
        first.manifest.conformance_execution_report_sha256
    )
    assert first.policy.implementation_pins.conformance_execution_report_sha256 == (
        first.manifest.conformance_execution_report_sha256
    )
    external_by_label = {item.label: item for item in first.manifest.external_artifacts}
    assert {
        "uv_binary",
        "uv_license",
        "uv_provenance",
        "media_runtime_manifest",
        "media_runtime_license_bundle",
        "media_runtime_source_bundle",
        "storage_proof_license_closure",
        "finality_license_closure",
    }.issubset(external_by_label)
    assert (
        first.files[external_by_label["third_party_notices"].relative_path]
        == (Path(descriptor.repository_root) / "THIRD_PARTY_NOTICES.md").read_bytes()
    )
    finality_bundle = first.files[external_by_label["finality_source_bundle"].relative_path]
    with zipfile.ZipFile(io.BytesIO(finality_bundle)) as archive:
        names = set(archive.namelist())
        assert "grandpa-finality-observer/Cargo.lock" in names
        assert "grandpa-finality-observer/vendor/PATCHES.md" in names
        assert "grandpa-finality-observer/vendor/smoldot-2.2.0/LICENSE" in names
        assert "grandpa-finality-observer/vendor/smoldot-light-1.3.2/LICENSE" in names
        assert "grandpa-finality-observer/vendor/subxt-lightclient-0.50.3/LICENSE" in names
        assert "grandpa-finality-observer/SOURCE-MANIFEST.sha256" in names
    for artifact in first.manifest.external_artifacts:
        assert artifact.relative_path.startswith(f"artifacts/sha256/{artifact.sha256}/")
        assert first.files[artifact.relative_path]
        assert hashlib.sha256(first.files[artifact.relative_path]).hexdigest() == artifact.sha256
    documents = [
        json.loads(payload)
        for relative, payload in first.files.items()
        if relative.endswith(".json")
    ]
    assert all("private_key" not in document for document in documents)
    assert all("mnemonic" not in document for document in documents)
    assert all(b"private-local-value" not in payload for payload in first.files.values())

    wheel_record = external_by_label["python_wheel"]
    assert _umi_source_tree_sha256_from_wheel(first.files[wheel_record.relative_path]) == (
        first.policy.implementation_pins.umi_source_tree_sha256
    )

    prepared = prepare_shadow_release(descriptor, now_ms=now_ms)
    for request in prepared.signing_requests:
        assert request.statement.issued_block == descriptor.observation.block_number
        assert request.statement.issued_block_hash == descriptor.observation.block_hash
        assert request.statement.valid_from_block == descriptor.activation_block


def test_default_release_preserves_the_single_linux_validator_target(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    assert "miner_finality_targets" not in descriptor.model_dump(mode="json", by_alias=True)

    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    finality = build.policy.implementation_pins.finality_verifier
    proof = build.policy.implementation_pins.storage_proof_verifier
    assert finality is not None and proof is not None
    assert (
        set(finality.release_sha256_by_target)
        == set(proof.release_sha256_by_target)
        == {"aarch64-unknown-linux-musl"}
    )
    assert not any(path.startswith("miner-templates/") for path in build.files)


def test_release_rejects_darwin_artifact_that_disagrees_with_trusted_handoff_digest(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    descriptor, _self_test_bytes = _descriptor_with_darwin_miner(
        descriptor,
        tmp_path,
        now_ms=now_ms,
    )
    values = descriptor.model_dump(mode="json", by_alias=True)
    values["miner_finality_targets"][0]["expected_binary_sha256"] = hashlib.sha256(
        b"wrong trusted handoff binary"
    ).hexdigest()
    mismatched = LiveShadowReleaseInput.model_validate(values)

    with pytest.raises(ShadowReleaseError) as raised:
        prepare_shadow_release(mismatched, now_ms=now_ms)
    assert raised.value.reason_code == "miner_finality_input_digest_mismatch"


def test_signed_release_can_add_a_native_darwin_miner_finality_target(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    native_artifact = os.environ.get("UMI_TEST_NATIVE_DARWIN_FINALITY_ARTIFACT_DIR")
    if native_artifact is not None:
        artifact_root = Path(native_artifact).resolve(strict=True)
        native_report = shadow_release_module.MinerFinalityBuildReport.model_validate_json(
            (artifact_root / "miner-finality-build-report.json").read_bytes()
        )
        repository_root = Path(descriptor.repository_root)
        monkeypatch.setattr(
            shadow_release_module,
            "_verified_clean_repository_revision",
            lambda root: native_report.umi_git_revision if root == repository_root else "",
        )
        fixture_license_verifier = shadow_release_module.verify_rust_license_closure

        def verify_target_license_closure(
            payload: bytes,
            *,
            cargo_lock_bytes: bytes,
            target_triple: str,
            binary_name: str,
        ) -> None:
            if target_triple == "aarch64-apple-darwin":
                rust_license_module.verify_rust_license_closure(
                    payload,
                    cargo_lock_bytes=cargo_lock_bytes,
                    target_triple=target_triple,
                    binary_name=binary_name,
                )
                return
            fixture_license_verifier(
                payload,
                cargo_lock_bytes=cargo_lock_bytes,
                target_triple=target_triple,
                binary_name=binary_name,
            )

        monkeypatch.setattr(
            shadow_release_module,
            "verify_rust_license_closure",
            verify_target_license_closure,
        )
    descriptor, self_test_bytes = _descriptor_with_darwin_miner(
        descriptor,
        tmp_path,
        now_ms=now_ms,
    )
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    finality = build.policy.implementation_pins.finality_verifier
    proof = build.policy.implementation_pins.storage_proof_verifier
    assert finality is not None and proof is not None
    assert set(finality.release_sha256_by_target) == {
        "aarch64-apple-darwin",
        "aarch64-unknown-linux-musl",
    }
    assert set(proof.release_sha256_by_target) == {"aarch64-unknown-linux-musl"}
    template_path = "miner-templates/aarch64-apple-darwin.json"
    assert json.loads(build.files[template_path]) == {
        "finality_build_report": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "miner_finality_build_report.aarch64-apple-darwin"
        ),
        "finality_chain_spec_path": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "finality_chain_spec"
        ),
        "finality_license_closure": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "miner_finality_license_closure.aarch64-apple-darwin"
        ),
        "finality_verifier_binary": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "miner_finality_verifier.aarch64-apple-darwin"
        ),
        "initial_minimum_finalized_block": descriptor.activation_block - 1,
        "minimum_validator_transport_concurrency": 32,
        "minimum_validator_transport_timeout_seconds": 90.0,
        "mirror_discovery_rule_path": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "mirror_discovery_rule"
        ),
        "policy_path": "scoring-policy.json",
        "protocol": PROTOCOL_VERSION,
        "pyproject": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "pyproject"
        ),
        "python_lockfile": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "python_lockfile"
        ),
        "python_wheel": next(
            item.relative_path
            for item in build.manifest.external_artifacts
            if item.label == "python_wheel"
        ),
        "role": "miner",
        "schema": "umi-miner-live-config-template/1",
        "scoring_policy_sha256": build.manifest.scoring_policy_sha256,
        "target_triple": "aarch64-apple-darwin",
        "translation_weights_active": False,
        "umi_git_revision": build.manifest.umi_git_revision,
        "umi_revision": (
            "git:"
            + build.manifest.umi_git_revision
            + ";source-tree-sha256:"
            + build.manifest.umi_source_tree_sha256
        ),
        "umi_source_tree_sha256": build.manifest.umi_source_tree_sha256,
        "validator_runtime_supported": False,
    }

    stage_root = (tmp_path / "darwin-miner-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    finalize_shadow_release(
        stage_root,
        final_authority=_final_authority(build),
        emit_dir=release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )
    external = {item.label: item for item in build.manifest.external_artifacts}
    source_binary = (
        release_root / external["miner_finality_verifier.aarch64-apple-darwin"].relative_path
    )
    expected_binary = source_binary.read_bytes()
    source_template = release_root / template_path
    unsafe_parent = tmp_path / "group-writable-resolved-parent"
    unsafe_parent.mkdir(mode=0o770)
    unsafe_parent.chmod(0o770)
    with pytest.raises(ShadowReleaseError) as unsafe_output:
        verify_miner_release_target(
            release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
            target_triple="aarch64-apple-darwin",
            output_dir=unsafe_parent / "darwin-release",
        )
    assert unsafe_output.value.reason_code == "resolved_miner_output_parent_unsafe"

    original_verify = shadow_release_module._verify_unsigned_release_contents

    def verify_then_replace_sources(**kwargs: Any) -> dict[str, bytes]:
        verified = original_verify(**kwargs)
        source_template.chmod(0o644)
        source_template.write_bytes(b"{}")
        source_template.chmod(0o444)
        source_binary.chmod(0o755)
        source_binary.write_bytes(_arm64_mach_o(salt=b"post-verification-swap"))
        source_binary.chmod(0o555)
        return verified

    monkeypatch.setattr(
        shadow_release_module,
        "_verify_unsigned_release_contents",
        verify_then_replace_sources,
    )
    original_run = subprocess.run

    def native_self_test(command: list[str], **kwargs: object) -> Any:
        if command[-1] == "--conformance-self-test":
            executed = Path(command[0])
            assert release_root not in executed.parents
            assert executed.read_bytes() == expected_binary
            return SimpleNamespace(returncode=0, stdout=self_test_bytes + b"\n")
        return original_run(command, **kwargs)

    if native_artifact is None:
        monkeypatch.setattr(shadow_release_module.subprocess, "run", native_self_test)
        monkeypatch.setattr(shadow_release_module.sys, "platform", "darwin")
        monkeypatch.setattr(shadow_release_module.platform, "machine", lambda: "arm64")
    output_parent = tmp_path / "resolved-miner-releases"
    output_parent.mkdir(mode=0o700)
    output_parent.chmod(0o700)
    output = output_parent / "darwin-release"
    resolved = verify_miner_release_target(
        release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        target_triple="aarch64-apple-darwin",
        output_dir=output,
    )
    assert isinstance(resolved, ResolvedMinerRelease)
    assert resolved.target_triple == "aarch64-apple-darwin"
    assert resolved.minimum_validator_transport_concurrency == 32
    assert resolved.minimum_validator_transport_timeout_seconds == 90.0
    assert resolved.umi_git_revision == build.manifest.umi_git_revision
    assert resolved.umi_source_tree_sha256 == build.manifest.umi_source_tree_sha256
    assert Path(resolved.mirror_discovery_rule_path).name == "mirror-discovery-rule.json"
    assert Path(resolved.finality_verifier_binary).read_bytes() == expected_binary
    assert resolved.validator_runtime_supported is False
    assert stat.S_IMODE(output.stat().st_mode) == 0o555
    returned_paths = (
        resolved.policy_path,
        resolved.python_wheel,
        resolved.python_lockfile,
        resolved.pyproject,
        resolved.mirror_discovery_rule_path,
        resolved.finality_verifier_binary,
        resolved.finality_chain_spec_path,
        resolved.finality_build_report,
        resolved.finality_license_closure,
    )
    for value in returned_paths:
        path = Path(value)
        assert output in path.parents
        assert not path.is_symlink()
        assert stat.S_ISREG(path.stat().st_mode)
        expected_mode = 0o555 if path == Path(resolved.finality_verifier_binary) else 0o444
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode
    assert (output / "resolved-miner-release.json").read_bytes() == canonical_json_bytes(resolved)


def test_native_miner_finality_artifact_is_self_tested_and_emitted_immutably(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, _release_root, _now_ms, _capture = release_environment
    repository = Path(descriptor.repository_root)
    fixture_bytes = (
        repository / "rust" / "grandpa-finality-observer" / "fixtures" / "finality-v1.json"
    ).read_bytes()
    fixture = conformance.FinalityFixtures.model_validate_json(fixture_bytes)
    self_test_bytes = canonical_json_bytes(
        {
            "case_ids": [
                "checkpoint-header-positive",
                "contiguous-first-positive",
                "contiguous-second-positive",
                "finney-checkpoint-positive",
                "missing-prefix-negative",
                "truncated-header-negative",
            ],
            "finney_checkpoint_canonical_sha256": fixture.finney_checkpoint_fixture.sha256,
            "fixture_canonical_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
            "ok": True,
            "schema": "umi-grandpa-finality-conformance-result/1",
        }
    )
    binary = _write(
        tmp_path / "native-finality",
        _arm64_mach_o(salt=b"native-build-fixture"),
        executable=True,
    )
    monkeypatch.setattr(shadow_release_module.sys, "platform", "darwin")
    monkeypatch.setattr(shadow_release_module.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(
        shadow_release_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=self_test_bytes + b"\n",
        ),
    )

    artifact = build_miner_finality_artifact(
        repository_root=repository,
        binary_path=binary,
    )
    assert isinstance(artifact, BuiltMinerFinalityArtifact)
    assert artifact.report.target_triple == "aarch64-apple-darwin"
    assert artifact.report.validator_runtime_supported is False
    output = (tmp_path / "sealed-native-finality").resolve()
    emit_miner_finality_artifact(artifact, output)
    assert (output / "miner-finality-build-report.json").read_bytes() == artifact.report_bytes
    assert (output / "umi-grandpa-finality-observer").read_bytes() == artifact.binary
    assert (output.stat().st_mode & 0o777) == 0o555
    assert ((output / "umi-grandpa-finality-observer").stat().st_mode & 0o777) == 0o555
    assert ((output / "miner-finality-build-report.json").stat().st_mode & 0o777) == 0o444


def test_installed_binding_recomputes_source_pin_from_packaged_wheel(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    wrong_source = hashlib.sha256(b"different-wheel-source").hexdigest()
    pins = build.policy.implementation_pins.model_copy(
        update={"umi_source_tree_sha256": wrong_source}
    )
    policy = build.policy.model_copy(update={"implementation_pins": pins})
    manifest = build.manifest.model_copy(update={"umi_source_tree_sha256": wrong_source})
    external = {item.label: item for item in manifest.external_artifacts}
    payloads = dict(build.files)
    payloads[external["umi_source_tree"].relative_path] = wrong_source.encode()

    with pytest.raises(ShadowReleaseError, match="release_source_artifact_binding_mismatch"):
        _verify_packaged_policy_bindings(
            manifest=manifest,
            policy=policy,
            external=external,
            payload_by_path=payloads,
        )


def _replace_release_wheel(
    descriptor: LiveShadowReleaseInput,
    wheel: Path,
) -> LiveShadowReleaseInput:
    return descriptor.model_copy(
        update={
            "artifacts": descriptor.artifacts.model_copy(
                update={"python_wheel": str(wheel.resolve())}
            )
        }
    )


def test_release_rejects_wheel_with_appended_pth_and_attacker_module(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    source_root = Path(descriptor.repository_root) / "src" / "umi"
    wheel = _wheel(
        tmp_path / "umi_subnet-0.1.0-py3-none-any.whl",
        source_root,
        extra_members={
            "auto_import_attacker.pth": b"import attacker\n",
            "attacker.py": b"raise RuntimeError('executed from wheel')\n",
        },
    )

    with pytest.raises(ShadowReleaseError, match="python_wheel_archive_layout_mismatch"):
        prepare_shadow_release(_replace_release_wheel(descriptor, wheel), now_ms=now_ms)


def test_release_rejects_repointed_console_entry_point_with_valid_record(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    source_root = Path(descriptor.repository_root) / "src" / "umi"
    wheel = _wheel(
        tmp_path / "umi_subnet-0.1.0-py3-none-any.whl",
        source_root,
        entry_point_override=("umi-miner", "umi.attacker:main"),
    )

    with pytest.raises(ShadowReleaseError, match="python_wheel_entry_points_mismatch"):
        prepare_shadow_release(_replace_release_wheel(descriptor, wheel), now_ms=now_ms)


def test_release_rejects_added_distribution_requirement_with_valid_record(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    source_root = Path(descriptor.repository_root) / "src" / "umi"
    wheel = _wheel(
        tmp_path / "umi_subnet-0.1.0-py3-none-any.whl",
        source_root,
        metadata_requirement="attacker-package==1",
    )

    with pytest.raises(ShadowReleaseError, match="python_wheel_requirements_mismatch"):
        prepare_shadow_release(_replace_release_wheel(descriptor, wheel), now_ms=now_ms)


def test_release_rejects_incorrect_wheel_record(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    source_root = Path(descriptor.repository_root) / "src" / "umi"
    wheel = _wheel(
        tmp_path / "umi_subnet-0.1.0-py3-none-any.whl",
        source_root,
        corrupt_record=True,
    )

    with pytest.raises(ShadowReleaseError, match="python_wheel_record_mismatch"):
        prepare_shadow_release(_replace_release_wheel(descriptor, wheel), now_ms=now_ms)


def test_release_requires_repository_exact_lockfile_bytes(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    altered = _write(
        tmp_path / "uv.lock",
        Path(descriptor.artifacts.python_lockfile).read_bytes() + b"\n# byte drift\n",
    )
    candidate = descriptor.model_copy(
        update={
            "artifacts": descriptor.artifacts.model_copy(update={"python_lockfile": str(altered)})
        }
    )

    with pytest.raises(ShadowReleaseError, match="python_lockfile_repository_mismatch"):
        prepare_shadow_release(candidate, now_ms=now_ms)


def test_lockfile_source_policy_rejects_non_pypi_package_source() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    lock = (
        (repository_root / "uv.lock")
        .read_bytes()
        .replace(
            b'source = { registry = "https://pypi.org/simple" }',
            b'source = { registry = "https://packages.attacker.invalid/simple" }',
            1,
        )
    )

    with pytest.raises(ShadowReleaseError, match="python_lockfile_source_policy_invalid"):
        shadow_release_module._validate_uv_lock_source_policy(
            lock,
            (repository_root / "pyproject.toml").read_bytes(),
        )


def test_packaged_uv_must_report_exact_version_and_check_lock(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    wrong_uv = _fake_uv(tmp_path / "uv", version="0.12.8")

    with pytest.raises(ShadowReleaseError, match="uv_binary_version_mismatch"):
        shadow_release_module._run_pinned_uv_lock_check(
            wrong_uv.read_bytes(),
            target_triple="aarch64-unknown-linux-musl",
            pyproject_bytes=(repository_root / "pyproject.toml").read_bytes(),
            lock_bytes=(repository_root / "uv.lock").read_bytes(),
        )


def test_uv_provenance_rejects_binary_outside_reviewed_upstream_release() -> None:
    target = "x86_64-unknown-linux-musl"
    with pytest.raises(ValidationError, match="reviewed upstream release"):
        shadow_release_module.UvToolProvenance.model_validate(
            {
                "binary_archive_sha256": (
                    shadow_release_module._PINNED_UV_ARCHIVE_SHA256_BY_TARGET[target]
                ),
                "binary_archive_url": (
                    f"https://github.com/astral-sh/uv/releases/download/0.12.9/uv-{target}.tar.gz"
                ),
                "binary_sha256": hashlib.sha256(b"not the upstream uv binary").hexdigest(),
                "license_expression": "Apache-2.0 OR MIT",
                "license_sha256": hashlib.sha256(b"combined upstream licenses").hexdigest(),
                "schema": "umi-uv-tool-provenance/1",
                "source_archive_sha256": (shadow_release_module._PINNED_UV_SOURCE_ARCHIVE_SHA256),
                "source_archive_url": (
                    "https://github.com/astral-sh/uv/releases/download/0.12.9/source.tar.gz"
                ),
                "target_triple": target,
                "tool": "uv",
                "version": "0.12.9",
            }
        )


def test_repository_revision_requires_committed_source_and_docs(tmp_path: Path) -> None:
    repository = (tmp_path / "release-repository").resolve()
    repository.mkdir()
    for relative in (
        "src/umi/__init__.py",
        "docs/OPERATOR.md",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
    ):
        _write(repository / relative, (relative + "\n").encode())
    for arguments in (
        ("init",),
        ("config", "user.email", "release-test@example.invalid"),
        ("config", "user.name", "Release Test"),
        ("add", "."),
        ("commit", "-m", "release fixture"),
    ):
        subprocess.run(
            ["git", "-C", str(repository), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
        )

    revision = shadow_release_module._verified_clean_repository_revision(repository)
    assert len(revision) == 40
    assert all(character in "0123456789abcdef" for character in revision)

    guide = repository / "docs" / "OPERATOR.md"
    guide.chmod(0o600)
    guide.write_bytes(b"uncommitted documentation change\n")
    guide.chmod(0o400)
    with pytest.raises(ShadowReleaseError, match="repository_worktree_not_clean"):
        shadow_release_module._verified_clean_repository_revision(repository)


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"#!/opt/homebrew/bin/ffmpeg\n", "ffmpeg_binary_not_static_elf"),
        (
            _static_elf(machine=183, salt=b"dynamic", program_type=3),
            "ffmpeg_binary_dynamic_linkage_forbidden",
        ),
    ],
)
def test_media_runtime_rejects_host_or_dynamically_linked_binary(
    payload: bytes,
    reason: str,
) -> None:
    with pytest.raises(ShadowReleaseError, match=reason):
        shadow_release_module._static_elf_machine(payload, label="ffmpeg_binary")


def test_media_runtime_requires_actual_corresponding_source_members() -> None:
    ffmpeg = _static_elf(machine=62, salt=b"ffmpeg")
    ffprobe = _static_elf(machine=62, salt=b"ffprobe")
    licenses = _zip_bytes(
        {
            "LICENSES/DEPENDENCIES.md": b"reviewed dependency list\n",
            "LICENSES/FFmpeg.txt": b"applicable FFmpeg license\n",
        }
    )
    sources = _zip_bytes(
        {
            "BUILD.md": b"complete build recipe\n",
            "SOURCE-MANIFEST.sha256": b"no source entries\n",
        }
    )
    manifest = canonical_json_bytes(
        {
            "corresponding_source_bundle_sha256": hashlib.sha256(sources).hexdigest(),
            "ffmpeg_binary_sha256": hashlib.sha256(ffmpeg).hexdigest(),
            "ffmpeg_configuration": "--disable-shared --enable-static",
            "ffmpeg_version": "8.0.1",
            "ffprobe_binary_sha256": hashlib.sha256(ffprobe).hexdigest(),
            "license_bundle_sha256": hashlib.sha256(licenses).hexdigest(),
            "license_expression": "LGPL-2.1-or-later",
            "linkage": "static-elf-without-pt-interp-or-pt-dynamic",
            "profile": "target-bound-static-elf-media-runtime/1",
            "redistribution_reviewed": True,
            "runtime_dependencies": [],
            "schema": "umi-media-runtime-closure/1",
            "target_triple": "x86_64-unknown-linux-musl",
        }
    )

    with pytest.raises(
        ShadowReleaseError,
        match="media_runtime_source_bundle_sources_missing",
    ):
        shadow_release_module._validate_packaged_media_runtime(
            target_triple="x86_64-unknown-linux-musl",
            ffmpeg_bytes=ffmpeg,
            ffprobe_bytes=ffprobe,
            manifest_bytes=manifest,
            license_bundle_bytes=licenses,
            source_bundle_bytes=sources,
        )


@pytest.mark.asyncio
async def test_live_release_collection_runs_observer_rpc_and_proof_verifier(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, _release_root, now_ms, baseline_capture = release_environment
    prepared = prepare_shadow_release(descriptor, now_ms=now_ms)
    evidence = json.loads(baseline_capture.chain_evidence)
    storage_by_key = {
        claim["storage_key"]: claim["raw_value"]
        for batch in evidence["proof_batches"]
        for claim in batch["claims"]
    }
    metadata_hex = "0x" + Path(descriptor.artifacts.runtime_metadata).read_bytes().hex()
    calls: list[tuple[str, list[object]]] = []

    class FakeRaw:
        async def rpc_request(self, method: str, params: list[object]) -> object:
            calls.append((method, params))
            if method == "chain_getHeader":
                return {
                    "number": hex(descriptor.observation.block_number),
                    "parentHash": descriptor.observation.parent_hash,
                    "stateRoot": descriptor.observation.state_root,
                }
            if method == "chain_getBlockHash":
                return descriptor.observation.block_hash
            if method == "state_getRuntimeVersion":
                return {"specVersion": 452, "stateVersion": 1, "transactionVersion": 1}
            if method == "state_getMetadata":
                return metadata_hex
            if method == "state_getStorageAt":
                return storage_by_key[str(params[0])]
            if method == "state_getReadProof":
                return {
                    "at": descriptor.observation.block_hash,
                    "proof": ["0x" + b"release-observation-proof-v1".hex()],
                }
            raise AssertionError(f"unexpected RPC method: {method}")

        async def request(self, method: str, params: list[object]) -> object:
            return await self.rpc_request(method, params)

    class FakeClient:
        def __init__(self, network: str) -> None:
            assert network == "finney"
            self._substrate = SimpleNamespace(raw=FakeRaw())
            self.connected = False
            self.closed = False

        async def connect(self) -> FakeClient:
            self.connected = True
            return self

        async def close(self) -> None:
            self.closed = True

    clients: list[FakeClient] = []

    def client_factory(network: str) -> FakeClient:
        client = FakeClient(network)
        clients.append(client)
        return client

    def fixture_observer(
        cls: type[GrandpaFinalityObserver],
        pin: object,
        *,
        target_triple: str,
        binary_path: str,
        chain_spec_path: str,
        **_kwargs: object,
    ) -> object:
        assert target_triple == descriptor.target_triple
        observer = cls(
            binary_path=binary_path,
            expected_binary_sha256=pin.release_sha256_by_target[target_triple],
            chain_spec_path=chain_spec_path,
            expected_chain_spec_sha256=pin.chain_spec_sha256,
            expected_genesis_hash="0x" + pin.expected_genesis_hash,
            bootstrap_block_number=pin.bootstrap_block_number,
            bootstrap_block_hash="0x" + pin.bootstrap_block_hash,
            record_timeout_seconds=10,
        )

        class FixtureObserver:
            def attestations(
                self,
                *,
                minimum_finalized_block: int,
                maximum_records: int,
                startup_timeout_seconds: int,
            ) -> object:
                return iter(
                    (
                        observer.validate_attestation(
                            baseline_capture.finality_attestation,
                            minimum_finalized_block=minimum_finalized_block,
                            maximum_records=maximum_records,
                            startup_timeout_seconds=startup_timeout_seconds,
                            expected_sequence=0,
                            previous_hash=None,
                            previous_digest="0" * 64,
                            previous_number=None,
                            previous_timestamp_ms=None,
                        ),
                    )
                )

        return FixtureObserver()

    monkeypatch.setattr(bt, "Client", client_factory)
    monkeypatch.setattr(
        "umi.shadow_release.BittensorRawJsonRpc",
        lambda client: client._substrate.raw,
    )
    monkeypatch.setattr(
        bt,
        "Subtensor",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("live release collection must use the async Client API")
        ),
    )
    monkeypatch.setattr(
        GrandpaFinalityObserver,
        "from_policy_pin",
        classmethod(fixture_observer),
    )
    monkeypatch.setattr("umi.shadow_release.time.time_ns", lambda: now_ms * 1_000_000)
    capture = await collect_live_release_observation(prepared)

    assert (
        capture.observation.model_copy(
            update={"observed_at_ms": descriptor.observation.observed_at_ms}
        )
        == descriptor.observation
    )
    assert capture.finality_attestation == baseline_capture.finality_attestation
    assert json.loads(capture.chain_evidence)["proof_batches"] != evidence["proof_batches"]
    assert clients and clients[0].connected and clients[0].closed
    assert [method for method, _params in calls].count("state_getReadProof") == 3

    stale_now_ms = (
        descriptor.observation.timestamp_ms + descriptor.maximum_finalized_head_age_ms + 1
    )
    monkeypatch.setattr("umi.shadow_release.time.time_ns", lambda: stale_now_ms * 1_000_000)
    with pytest.raises(ShadowReleaseError, match="live_release_finalized_head_stale"):
        await collect_live_release_observation(prepared)


def test_final_build_rejects_tampered_live_capture(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment

    supplied_replay = LiveReleaseObservationCapture(
        observation=capture.observation,
        finality_attestation=capture.finality_attestation,
        chain_evidence=capture.chain_evidence,
    )
    with pytest.raises(ShadowReleaseError, match="live_release_capture_not_direct"):
        build_shadow_release(descriptor, live_capture=supplied_replay, now_ms=now_ms)

    document = json.loads(capture.chain_evidence)
    mechanism = next(
        claim
        for batch in document["proof_batches"]
        for claim in batch["claims"]
        if claim["item"] == "MechanismCountCurrent"
    )
    mechanism["raw_value"] = "0x" + canonical_json_bytes(2).hex()
    false_topology = LiveReleaseObservationCapture(
        observation=capture.observation,
        finality_attestation=capture.finality_attestation,
        chain_evidence=canonical_json_bytes(document),
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )
    with pytest.raises(ShadowReleaseError, match="release_observation_mechanism_topology_mismatch"):
        build_shadow_release(descriptor, live_capture=false_topology, now_ms=now_ms)

    document = json.loads(capture.chain_evidence)
    document["block_hash"] = "0x" + "61" * 32
    false_header = LiveReleaseObservationCapture(
        observation=capture.observation,
        finality_attestation=capture.finality_attestation,
        chain_evidence=canonical_json_bytes(document),
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )
    with pytest.raises(
        ShadowReleaseError,
        match="live_release_chain_evidence_observation_mismatch",
    ):
        build_shadow_release(descriptor, live_capture=false_header, now_ms=now_ms)

    false_finality = LiveReleaseObservationCapture(
        observation=capture.observation,
        finality_attestation=capture.finality_attestation + b" ",
        chain_evidence=capture.chain_evidence,
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )
    with pytest.raises(ShadowReleaseError, match="live_release_finality_digest_mismatch"):
        build_shadow_release(descriptor, live_capture=false_finality, now_ms=now_ms)

    late_observation = FinalizedReleaseObservation.model_validate(
        {
            **capture.observation.model_dump(mode="json"),
            "block_number": capture.observation.block_number + 1,
        }
    )
    late_capture = LiveReleaseObservationCapture(
        observation=late_observation,
        finality_attestation=capture.finality_attestation,
        chain_evidence=capture.chain_evidence,
        _authority=_LIVE_CAPTURE_AUTHORITY,
    )
    with pytest.raises(
        ShadowReleaseError,
        match="live_release_observation_has_insufficient_activation_lead",
    ):
        build_shadow_release(descriptor, live_capture=late_capture, now_ms=now_ms)


def test_finality_source_pin_covers_vendored_rust_source(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    source = repository_root / "rust" / "grandpa-finality-observer"
    copied = tmp_path / "finality-source"
    copied.mkdir()
    for name in ("Cargo.toml", "build.rs", "rust-toolchain.toml"):
        shutil.copy2(source / name, copied / name)
    shutil.copytree(source / "src", copied / "src")
    shutil.copytree(source / "vendor", copied / "vendor")

    assert _finality_source_tree_sha256(copied) == SOURCE_TREE_SHA256
    vendored_rust = copied / "vendor" / "smoldot-light-1.3.2" / "src" / "lib.rs"
    vendored_rust.write_bytes(vendored_rust.read_bytes() + b"\n// source-pin mutation\n")
    assert _finality_source_tree_sha256(copied) != SOURCE_TREE_SHA256


def test_release_rejects_missing_or_invalid_capacity_signatures(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    values = descriptor.model_dump(mode="json", by_alias=True)
    values["publisher_capacities"][0]["signature"] = None
    missing = LiveShadowReleaseInput.model_validate(values)
    with pytest.raises(ShadowReleaseError, match="publisher_capacity_signature_missing"):
        build_shadow_release(missing, live_capture=capture, now_ms=now_ms)

    values["publisher_capacities"][0]["signature"] = "0x" + "01" * 64
    invalid = LiveShadowReleaseInput.model_validate(values)
    with pytest.raises(ShadowReleaseError, match="publisher_capacity_signature_invalid"):
        build_shadow_release(invalid, live_capture=capture, now_ms=now_ms)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["publisher_capacities"][0]["issued_block"] += 1
    wrong_issuance = LiveShadowReleaseInput.model_validate(values)
    with pytest.raises(ShadowReleaseError, match="publisher_capacity_release_observation_mismatch"):
        prepare_shadow_release(wrong_issuance, now_ms=now_ms)


def test_release_requires_historical_observation_and_deployment_lead(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, _now_ms, _capture = release_environment
    values = descriptor.model_dump(mode="json", by_alias=True)
    values["activation_block"] = values["observation"]["block_number"]
    with pytest.raises(ValidationError, match="release observation must precede"):
        LiveShadowReleaseInput.model_validate(values)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["activation_block"] -= 1
    with pytest.raises(ValidationError, match="does not provide the declared release lead"):
        LiveShadowReleaseInput.model_validate(values)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["minimum_release_lead_blocks"] = PolicyClock.launch().window_stride_blocks - 1
    with pytest.raises(ValidationError, match="greater than or equal to 360"):
        LiveShadowReleaseInput.model_validate(values)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["minimum_release_lead_blocks"] += 1
    values["activation_block"] += 1
    boundary = LiveShadowReleaseInput.model_validate(values)
    assert (
        boundary.activation_block - boundary.observation.block_number
        == boundary.minimum_release_lead_blocks
    )

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["operators"][0]["wallet_path"] = "/builder/private/wallet"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LiveShadowReleaseInput.model_validate(values)

    with pytest.raises(ValidationError, match="wallet name is not canonical"):
        OperatorMaterializationBindings(
            schema="umi-validator-operator-local-bindings/1",
            validator_hotkey=descriptor.operators[0].validator_hotkey,
            state_root="/operator/private/state",
            wallet_name="invalid wallet name",
            wallet_hotkey_name="umi-validator",
            wallet_path="/operator/private/wallet",
            mirror_request_headers_path="/operator/private/headers.json",
        )


def test_release_rejects_mixed_and_weight_active_observations(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    values = descriptor.model_dump(mode="json", by_alias=True)
    values["observation"]["runtime_query_block_hash"] = "0x" + "31" * 32
    with pytest.raises(ValidationError, match="runtime and topology observations"):
        LiveShadowReleaseInput.model_validate(values)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["translation_weights_active"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        LiveShadowReleaseInput.model_validate(values)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["limits"]["miner_panel_size"] = 31
    with pytest.raises(ValidationError, match=r"version 0\.1 launch profile"):
        LiveShadowReleaseInput.model_validate(values)

    values = descriptor.model_dump(mode="json", by_alias=True)
    values["observation"]["observed_at_ms"] = now_ms + 300_001
    future = LiveShadowReleaseInput.model_validate(values)
    with pytest.raises(ShadowReleaseError, match="observation_from_future"):
        prepare_shadow_release(future, now_ms=now_ms)


def test_release_rejects_artifact_and_release_observation_evidence_tamper(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    evidence_path = Path(descriptor.artifacts.release_observation_chain_evidence)
    evidence = json.loads(evidence_path.read_bytes())
    evidence["proof_batches"][0]["proof_nodes"] = ["0x" + b"wrong-proof".hex()]
    evidence_path.chmod(0o600)
    evidence_path.write_bytes(canonical_json_bytes(evidence))
    evidence_path.chmod(0o400)
    with pytest.raises(ShadowReleaseError, match="release_observation_storage_proof_failed"):
        build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)


def test_release_rejects_descriptor_evidence_header_and_runtime_mismatch(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    evidence_path = Path(descriptor.artifacts.release_observation_chain_evidence)
    evidence = json.loads(evidence_path.read_bytes())
    evidence["block_hash"] = "0x" + "61" * 32
    evidence_path.chmod(0o600)
    evidence_path.write_bytes(canonical_json_bytes(evidence))
    evidence_path.chmod(0o400)
    with pytest.raises(
        ShadowReleaseError, match="release_observation_chain_evidence_observation_mismatch"
    ):
        build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)

    evidence["block_hash"] = descriptor.observation.block_hash
    runtime_version = canonical_json_bytes(
        {"specVersion": 452, "stateVersion": 1, "transactionVersion": 2}
    )
    evidence["runtime"]["runtime_version"] = "0x" + runtime_version.hex()
    evidence["runtime"]["transaction_version"] = 2
    evidence_path.chmod(0o600)
    evidence_path.write_bytes(canonical_json_bytes(evidence))
    evidence_path.chmod(0o400)
    with pytest.raises(
        ShadowReleaseError, match="release_observation_chain_evidence_observation_mismatch"
    ):
        build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)


def test_installed_release_path_rejects_false_mechanism_count(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    evidence_path = Path(descriptor.artifacts.release_observation_chain_evidence)
    evidence = json.loads(evidence_path.read_bytes())
    claim = next(
        claim
        for claim in evidence["proof_batches"][0]["claims"]
        if claim["item"] == "MechanismCountCurrent"
    )
    claim["raw_value"] = "0x" + canonical_json_bytes(2).hex()
    evidence_path.chmod(0o600)
    evidence_path.write_bytes(canonical_json_bytes(evidence))
    evidence_path.chmod(0o400)
    with pytest.raises(ShadowReleaseError, match="release_observation_mechanism_topology_mismatch"):
        build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)


def test_release_rejects_finality_artifact_tamper(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment

    attestation = Path(descriptor.artifacts.finality_attestation)
    attestation.chmod(0o600)
    attestation.write_bytes(canonical_json_bytes({"tampered": True}))
    attestation.chmod(0o400)
    with pytest.raises(ShadowReleaseError, match="finality_attestation_digest_mismatch"):
        build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)


def test_release_rejects_repeated_artifacts_and_unpriced_capacity(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    normalization = Path(descriptor.artifacts.normalization_fixture_set)
    frame = Path(descriptor.artifacts.frame_digest_fixture_set)
    normalization.chmod(0o600)
    normalization.write_bytes(frame.read_bytes())
    normalization.chmod(0o400)
    with pytest.raises(ShadowReleaseError, match="repeated_artifact_digest"):
        prepare_shadow_release(descriptor, now_ms=now_ms)


def test_release_requires_executed_conformance(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment

    def fail_conformance(
        _fixture_paths: ConformanceFixturePaths,
        *,
        binaries: ConformanceBinaryPins,
    ) -> ConformanceExecution:
        del binaries
        raise conformance.ConformanceError("test_fixture_failure")

    monkeypatch.setattr("umi.shadow_release.execute_conformance_suite", fail_conformance)
    with pytest.raises(
        ShadowReleaseError,
        match="conformance_execution_failed:test_fixture_failure",
    ):
        prepare_shadow_release(descriptor, now_ms=now_ms)


def test_release_rejects_capacity_above_costed_hardware(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    schedule_path = Path(descriptor.artifacts.validator_cost_schedule)
    schedule = json.loads(schedule_path.read_bytes())
    schedule["classes"][0]["cpu_core_count"] = 1
    schedule_path.chmod(0o600)
    schedule_path.write_bytes(canonical_json_bytes(schedule))
    schedule_path.chmod(0o400)
    with pytest.raises(ShadowReleaseError, match="validator_cpu_capacity_exceeds_cost_class"):
        prepare_shadow_release(descriptor, now_ms=now_ms)


def test_emit_is_atomic_refuses_overwrite_and_check_writes_nothing(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "release-signing-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    assert (stage_root / "release-manifest.unsigned.json").read_bytes() == canonical_json_bytes(
        build.manifest
    )
    with pytest.raises(ShadowReleaseError, match="emit_directory_exists"):
        emit_shadow_release_signing_stage(build, stage_root)
    with pytest.raises(ShadowReleaseError, match="overlaps_protected_path"):
        emit_shadow_release_signing_stage(build, release_root)

    unsigned, signing_request = verify_shadow_release_signing_stage(
        stage_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        now_ms=now_ms,
    )
    assert unsigned == build.manifest
    assert signing_request == final_manifest_authority_request(build.manifest)
    finalized = finalize_shadow_release(
        stage_root,
        final_authority=_final_authority(build),
        emit_dir=release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )
    assert (release_root / "release-manifest.json").read_bytes() == canonical_json_bytes(finalized)
    assert not (release_root / "release-manifest.unsigned.json").exists()
    with pytest.raises(ShadowReleaseError, match="final_release_directory_exists"):
        finalize_shadow_release(
            stage_root,
            final_authority=_final_authority(build),
            emit_dir=release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        )

    descriptor_bytes = canonical_json_bytes(
        [item.model_dump(mode="json") for item in descriptor.operators]
    )
    for private_key in (
        b'"state_root"',
        b'"wallet_name"',
        b'"wallet_hotkey_name"',
        b'"wallet_path"',
        b'"mirror_request_headers_path"',
    ):
        assert private_key not in descriptor_bytes

    template_files = [
        path for path in (release_root / "operator-templates").iterdir() if path.is_file()
    ]
    validator_templates = {
        path.name: ReleaseRelativeValidatorConfig.model_validate_json(path.read_bytes())
        for path in template_files
        if path.name.endswith(".validator-template.json")
    }
    operator_templates = {
        path.name: ReleaseRelativeOperatorConfig.model_validate_json(path.read_bytes())
        for path in template_files
        if path.name.endswith(".operator-template.json")
    }
    assert len(validator_templates) == len(descriptor.validator_registry)
    assert len(operator_templates) == len(descriptor.validator_registry)
    template_bytes = b"\n".join(path.read_bytes() for path in template_files)
    assert str(release_root).encode() not in template_bytes
    assert descriptor.repository_root.encode() not in template_bytes
    for builder_path in descriptor.artifacts.model_dump(mode="json").values():
        assert builder_path.encode() not in template_bytes
    assert all(not Path(item.policy_path).is_absolute() for item in validator_templates.values())

    relocated_release = (tmp_path / "relocated-public-release").resolve()
    shutil.copytree(release_root, relocated_release)
    materialized_root = (tmp_path / "materialized-operator-config").resolve()
    selected_operator = descriptor.operators[0]
    local_bindings = OperatorMaterializationBindings(
        schema="umi-validator-operator-local-bindings/1",
        validator_hotkey=selected_operator.validator_hotkey,
        state_root=str((tmp_path / "operator-private-state").resolve()),
        wallet_name="release-validator",
        wallet_hotkey_name="umi-validator",
        wallet_path=str((tmp_path / "operator-private-wallet").resolve()),
        mirror_request_headers_path=str((tmp_path / "operator-private-headers.json").resolve()),
    )
    startup_conformance_calls = 0
    startup_conformance = validator_live_module.execute_conformance_suite

    def record_startup_conformance(
        fixture_paths: ConformanceFixturePaths,
        *,
        binaries: ConformanceBinaryPins,
    ) -> ConformanceExecution:
        nonlocal startup_conformance_calls
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:  # pragma: no cover - this is the production boundary under test
            raise AssertionError("startup conformance ran inside the operator event loop")
        startup_conformance_calls += 1
        return startup_conformance(fixture_paths, binaries=binaries)

    monkeypatch.setattr(
        "umi.validator_live.execute_conformance_suite",
        record_startup_conformance,
    )
    monkeypatch.setattr(validator_live_module.sys, "platform", "linux")
    monkeypatch.setattr(validator_live_module.platform, "machine", lambda: "aarch64")
    materialize_private_operator_configs(
        relocated_release,
        local_bindings,
        materialized_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )
    assert startup_conformance_calls == 1
    materialized_files = [path for path in materialized_root.rglob("*") if path.is_file()]
    assert len(materialized_files) == 2
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in materialized_files)
    validator_files = {
        path.name: LiveValidatorConfig.model_validate_json(path.read_bytes())
        for path in materialized_files
        if path.name.endswith(".validator.json")
    }
    operator_files = {
        path.name: LiveValidatorOperatorConfig.model_validate_json(path.read_bytes())
        for path in materialized_files
        if path.name.endswith(".operator.json")
    }
    assert len(validator_files) == 1
    assert len(operator_files) == 1
    packaged_by_label = {
        item.label: relocated_release / item.relative_path
        for item in build.manifest.external_artifacts
    }
    for config in validator_files.values():
        assert config.translation_weights_active is False
        assert config.conformance_release_root == str(relocated_release)
        assert config.policy_path == str(relocated_release / "scoring-policy.json")
        assert config.scoring_policy_sha256 == build.manifest.scoring_policy_sha256
        assert config.initial_minimum_finalized_block == descriptor.activation_block - 1
        assert (
            Path(config.storage_proof_verifier_binary)
            == packaged_by_label["storage_proof_verifier_binary"]
        )
        assert (
            Path(config.finality_verifier_binary) == packaged_by_label["finality_verifier_binary"]
        )
        assert Path(config.finality_chain_spec_path) == packaged_by_label["finality_chain_spec"]
        loaded_policy = load_live_policy(config)
        runtime_validation = validate_live_startup(config, loaded_policy)
        assert (
            runtime_validation.finality_verifier_sha256
            == hashlib.sha256(Path(config.finality_verifier_binary).read_bytes()).hexdigest()
        )
    selected_config = next(iter(validator_files.values()))
    selected_policy = load_live_policy(selected_config)

    async def validate_from_operator_loop():
        return validate_live_startup(selected_config, selected_policy)

    async_validation = asyncio.run(validate_from_operator_loop())
    assert async_validation.finality_verifier_sha256 == (
        hashlib.sha256(Path(selected_config.finality_verifier_binary).read_bytes()).hexdigest()
    )

    def divergent_startup_conformance(
        fixture_paths: ConformanceFixturePaths,
        *,
        binaries: ConformanceBinaryPins,
    ) -> ConformanceExecution:
        observed = startup_conformance(fixture_paths, binaries=binaries)
        first, *rest = observed.report.cases
        report = observed.report.model_copy(
            update={"cases": [first.model_copy(update={"output_sha256": "ab" * 32}), *rest]}
        )
        encoded = canonical_json_bytes(report)
        return ConformanceExecution(
            report=report,
            canonical_report_bytes=encoded,
            report_sha256=hashlib.sha256(encoded).hexdigest(),
        )

    monkeypatch.setattr(
        "umi.validator_live.execute_conformance_suite",
        divergent_startup_conformance,
    )
    with pytest.raises(
        LiveValidatorConfigError,
        match="conformance_report_reproduction_mismatch",
    ):
        validate_live_startup(selected_config, selected_policy)
    assert {item.validator_hotkey for item in validator_files.values()} == {
        selected_operator.validator_hotkey
    }
    for config in operator_files.values():
        assert (
            Path(config.validator_capacity_set_path) == packaged_by_label["validator_capacity_set"]
        )
        assert Path(config.mirror_discovery_rule_path) == packaged_by_label["mirror_discovery_rule"]

    descriptor_values = descriptor.model_dump(mode="json", by_alias=True)
    descriptor_values["release_install_root"] = str((tmp_path / "check-output").resolve())
    checked = LiveShadowReleaseInput.model_validate(descriptor_values)
    input_path = _write(
        tmp_path / "release-input.json",
        canonical_json_bytes(checked),
    )

    async def forbidden_live_capture(_prepared: object) -> LiveReleaseObservationCapture:
        raise AssertionError("--check must not run the network collector")

    monkeypatch.setattr(
        "umi.shadow_release.collect_live_release_observation",
        forbidden_live_capture,
    )
    assert main([str(input_path), "--check"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["translation_weights_active"] is False
    assert output["release_authority"] is False
    assert output["live_observation_collected"] is False
    assert not Path(checked.release_install_root).exists()


def test_release_authority_request_and_installed_verifier_fail_closed(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, _capture = release_environment
    prepared = prepare_shadow_release(descriptor, now_ms=now_ms)
    request_path = (tmp_path / "release-authority-request.json").resolve()
    request = emit_release_authority_request(prepared, request_path)
    assert request_path.read_bytes() == canonical_json_bytes(request)
    assert request.digest == release_authority_request(prepared).digest
    assert descriptor.release_authority.signature.encode() not in request_path.read_bytes()


def test_installed_release_verifies_tree_authority_and_live_evidence(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "installed-verifier-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    finalized = finalize_shadow_release(
        stage_root,
        final_authority=_final_authority(build),
        emit_dir=release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )

    class AcceptFixtureProof:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def verify_many(self, **_kwargs: object) -> bool:
            return True

    def fixture_observer_from_pin(
        _cls: type[GrandpaFinalityObserver],
        pin: Any,
        *,
        target_triple: str,
        binary_path: Path,
        chain_spec_path: Path,
        **_kwargs: object,
    ) -> GrandpaFinalityObserver:
        return GrandpaFinalityObserver(
            binary_path=binary_path,
            expected_binary_sha256=pin.release_sha256_by_target[target_triple],
            chain_spec_path=chain_spec_path,
            expected_chain_spec_sha256=pin.chain_spec_sha256,
            expected_genesis_hash="0x" + pin.expected_genesis_hash,
            bootstrap_block_number=pin.bootstrap_block_number,
            bootstrap_block_hash="0x" + pin.bootstrap_block_hash,
        )

    monkeypatch.setattr("umi.shadow_release.SubprocessStorageProofVerifier", AcceptFixtureProof)
    monkeypatch.setattr(
        GrandpaFinalityObserver,
        "from_policy_pin",
        classmethod(fixture_observer_from_pin),
    )
    verified = verify_shadow_release_directory(
        release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        now_ms=now_ms,
    )
    assert verified == finalized

    wrong_authority = _wallet("//WrongReleaseAuthority").hotkey.ss58_address
    with pytest.raises(ShadowReleaseError, match="release_authority_untrusted"):
        verify_shadow_release_directory(
            release_root,
            expected_authority_hotkey=wrong_authority,
            now_ms=now_ms,
        )

    wheel = next(
        release_root / item.relative_path
        for item in build.manifest.external_artifacts
        if item.label == "python_wheel"
    )
    wheel.chmod(0o644)
    wheel.write_bytes(wheel.read_bytes() + b"tamper")
    wheel.chmod(0o444)
    with pytest.raises(ShadowReleaseError, match="release_artifact_digest_mismatch"):
        verify_shadow_release_directory(
            release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
            now_ms=now_ms,
        )


def test_installed_verifier_reruns_packaged_conformance(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "conformance-rerun-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    finalize_shadow_release(
        stage_root,
        final_authority=_final_authority(build),
        emit_dir=release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )

    execute = shadow_release_module.execute_conformance_suite

    def divergent_conformance(
        fixture_paths: ConformanceFixturePaths,
        *,
        binaries: ConformanceBinaryPins,
    ) -> ConformanceExecution:
        observed = execute(fixture_paths, binaries=binaries)
        first, *rest = observed.report.cases
        changed = first.model_copy(update={"output_sha256": "de" * 32})
        report = ConformanceExecutionReport(
            schema="umi-conformance-execution-report/1",
            verified=True,
            fixture_sha256_by_category=observed.report.fixture_sha256_by_category,
            binary_sha256_by_name=observed.report.binary_sha256_by_name,
            cases=[changed, *rest],
        )
        encoded = canonical_json_bytes(report)
        return ConformanceExecution(
            report=report,
            canonical_report_bytes=encoded,
            report_sha256=hashlib.sha256(encoded).hexdigest(),
        )

    monkeypatch.setattr(
        "umi.shadow_release.execute_conformance_suite",
        divergent_conformance,
    )
    with pytest.raises(
        ShadowReleaseError,
        match="release_conformance_report_reproduction_mismatch",
    ):
        verify_shadow_release_directory(
            release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
            now_ms=now_ms,
        )


def test_final_manifest_signature_rejects_wrong_signer_tamper_and_stale_stage(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "authority-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    valid = _final_authority(build)

    wrong_wallet = _wallet("//WrongFinalReleaseAuthority")
    wrong = valid.model_copy(
        update={
            "authority_hotkey": wrong_wallet.hotkey.ss58_address,
            "signature": "0x" + bytes(wrong_wallet.hotkey.sign(bytes.fromhex(valid.digest))).hex(),
        }
    )
    with pytest.raises(ShadowReleaseError, match="release_authority_untrusted"):
        finalize_shadow_release(
            stage_root,
            final_authority=wrong,
            emit_dir=release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        )
    invalid = valid.model_copy(update={"signature": "0x" + "01" * 64})
    with pytest.raises(ShadowReleaseError, match="release_final_authority_signature_invalid"):
        finalize_shadow_release(
            stage_root,
            final_authority=invalid,
            emit_dir=release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        )
    stale_now = capture.observation.timestamp_ms + descriptor.maximum_finalized_head_age_ms + 1
    monkeypatch.setattr("umi.shadow_release._finalization_clock_ms", lambda: stale_now)
    with pytest.raises(ShadowReleaseError, match="release_observation_expired"):
        finalize_shadow_release(
            stage_root,
            final_authority=valid,
            emit_dir=release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        )

    monkeypatch.setattr("umi.shadow_release._finalization_clock_ms", lambda: now_ms)
    finalized = finalize_shadow_release(
        stage_root,
        final_authority=valid,
        emit_dir=release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )
    values = finalized.model_dump(mode="json", by_alias=True)
    values["release_observation_observed_at_ms"] += 1
    tampered = canonical_json_bytes(values)
    manifest_path = release_root / "release-manifest.json"
    manifest_path.chmod(0o644)
    manifest_path.write_bytes(tampered)
    manifest_path.chmod(0o444)
    with pytest.raises(ShadowReleaseError, match="release_final_authority_attestation_mismatch"):
        verify_shadow_release_directory(
            release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
            now_ms=now_ms,
        )


def test_final_release_interruption_leaves_no_partial_destination(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "interrupted-finalize-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)

    def interrupt(_source: Path, _destination: Path) -> None:
        raise OSError("simulated interrupted atomic publication")

    monkeypatch.setattr("umi.shadow_release._replace_final_release_directory", interrupt)
    with pytest.raises(ShadowReleaseError, match="final_release_emit_failed"):
        finalize_shadow_release(
            stage_root,
            final_authority=_final_authority(build),
            emit_dir=release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        )
    assert not release_root.exists()
    assert not list(release_root.parent.glob(f".{release_root.name}.tmp-*"))


def test_final_release_rechecks_head_age_immediately_before_publication(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "delayed-finalize-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    fresh_ms = capture.observation.timestamp_ms + 10
    stale_ms = capture.observation.timestamp_ms + descriptor.maximum_finalized_head_age_ms + 1
    readings = iter((fresh_ms, stale_ms))
    monkeypatch.setattr("umi.shadow_release._finalization_clock_ms", lambda: next(readings))

    with pytest.raises(ShadowReleaseError, match="release_observation_expired"):
        finalize_shadow_release(
            stage_root,
            final_authority=_final_authority(build),
            emit_dir=release_root,
            expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
        )
    assert not release_root.exists()
    assert not list(release_root.parent.glob(f".{release_root.name}.tmp-*"))


def test_release_rejects_missing_invalid_authority_and_stale_live_capture(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    missing = descriptor.model_copy(
        update={
            "release_authority": descriptor.release_authority.model_copy(update={"signature": None})
        }
    )
    with pytest.raises(ShadowReleaseError, match="release_authority_signature_missing"):
        build_shadow_release(missing, live_capture=capture, now_ms=now_ms)

    invalid = descriptor.model_copy(
        update={
            "release_authority": descriptor.release_authority.model_copy(
                update={"signature": "0x" + "01" * 64}
            )
        }
    )
    with pytest.raises(ShadowReleaseError, match="release_authority_signature_invalid"):
        build_shadow_release(invalid, live_capture=capture, now_ms=now_ms)

    stale_now = capture.observation.timestamp_ms + descriptor.maximum_finalized_head_age_ms + 1
    with pytest.raises(ShadowReleaseError, match="live_release_capture_expired"):
        build_shadow_release(descriptor, live_capture=capture, now_ms=stale_now)


def test_cli_final_actions_collect_live_observation_in_same_invocation(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validator_live_module.sys, "platform", "linux")
    monkeypatch.setattr(validator_live_module.platform, "machine", lambda: "aarch64")
    descriptor, release_root, _now_ms, capture = release_environment
    input_path = _write(
        tmp_path / "final-release-input.json",
        canonical_json_bytes(descriptor),
    )
    collected: list[str] = []

    async def live_capture(_prepared: object) -> LiveReleaseObservationCapture:
        collected.append("capture")
        return capture

    monkeypatch.setattr("umi.shadow_release.collect_live_release_observation", live_capture)
    monkeypatch.setattr(
        "umi.shadow_release.time.time_ns",
        lambda: capture.observation.observed_at_ms * 1_000_000,
    )

    stage_root = (tmp_path / "cli-release-stage").resolve()
    assert main([str(input_path), "--stage-dir", str(stage_root)]) == 0
    public_summary = json.loads(capsys.readouterr().out)
    assert public_summary["release_observation_block"] == capture.observation.block_number
    assert public_summary["staged"] is True
    assert collected == ["capture"]
    assert (stage_root / "release-observation" / "chain-evidence.json").read_bytes() == (
        capture.chain_evidence
    )

    signing_request = json.loads(
        (stage_root / "release-manifest-signing-request.json").read_bytes()
    )
    authority_wallet = _wallet("//ReleaseValidator0")
    response = FinalManifestAuthorityAttestation(
        schema="umi-live-shadow-final-manifest-authority/1",
        authority_hotkey=signing_request["authority_hotkey"],
        signature_scheme=signing_request["signature_scheme"],
        unsigned_manifest_sha256=signing_request["unsigned_manifest_sha256"],
        digest=signing_request["digest"],
        signature="0x"
        + bytes(authority_wallet.hotkey.sign(bytes.fromhex(signing_request["digest"]))).hex(),
    )
    response_path = _write(
        tmp_path / "final-manifest-authority.json",
        canonical_json_bytes(response),
    )
    assert (
        finalize_main(
            [
                str(stage_root),
                "--signature-response",
                str(response_path),
                "--emit-dir",
                str(release_root),
                "--expected-authority-hotkey",
                descriptor.release_authority.authority_hotkey,
            ]
        )
        == 0
    )
    finalized_summary = json.loads(capsys.readouterr().out)
    assert finalized_summary["translation_weights_active"] is False

    selected = descriptor.operators[0]
    bindings = OperatorMaterializationBindings(
        schema="umi-validator-operator-local-bindings/1",
        validator_hotkey=selected.validator_hotkey,
        state_root=str((tmp_path / "cli-operator-state").resolve()),
        wallet_name="release-validator",
        wallet_hotkey_name="umi-validator",
        wallet_path=str((tmp_path / "cli-operator-wallet").resolve()),
        mirror_request_headers_path=str((tmp_path / "cli-operator-headers.json").resolve()),
    )
    bindings_path = _write(
        tmp_path / "operator-local-bindings.json",
        canonical_json_bytes(bindings),
    )
    materialized_root = (tmp_path / "cli-materialized-operator").resolve()
    assert (
        materialize_operator_main(
            [
                str(release_root),
                "--expected-authority-hotkey",
                descriptor.release_authority.authority_hotkey,
                "--local-bindings",
                str(bindings_path),
                "--emit-dir",
                str(materialized_root),
            ]
        )
        == 0
    )
    materialized_summary = json.loads(capsys.readouterr().out)
    assert materialized_summary["translation_weights_active"] is False
    assert len([path for path in materialized_root.rglob("*") if path.is_file()]) == 2


def test_materializer_verifies_release_before_reading_private_bindings(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    stage_root = (tmp_path / "verify-before-bindings-stage").resolve()
    emit_shadow_release_signing_stage(build, stage_root)
    finalize_shadow_release(
        stage_root,
        final_authority=_final_authority(build),
        emit_dir=release_root,
        expected_authority_hotkey=descriptor.release_authority.authority_hotkey,
    )
    manifest_path = release_root / "release-manifest.json"
    manifest_path.chmod(0o644)
    manifest_path.write_bytes(b"{}")
    manifest_path.chmod(0o444)
    private_read_attempted = False

    def reject_private_read(*_args: object, **_kwargs: object) -> bytes:
        nonlocal private_read_attempted
        private_read_attempted = True
        raise AssertionError("private bindings were read before release verification")

    monkeypatch.setattr("umi.shadow_release._read_private_file", reject_private_read)
    result = materialize_operator_main(
        [
            str(release_root),
            "--expected-authority-hotkey",
            descriptor.release_authority.authority_hotkey,
            "--local-bindings",
            str((tmp_path / "must-not-be-read.json").resolve()),
            "--emit-dir",
            str((tmp_path / "must-not-exist").resolve()),
        ]
    )
    assert result == 2
    assert private_read_attempted is False
    assert "release_manifest_invalid" in capsys.readouterr().err


def test_capacity_signing_pass_collects_live_baseline_and_emits_descriptor_patch(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, _release_root, _now_ms, capture = release_environment
    values = descriptor.model_dump(mode="json", by_alias=True)
    missing_attestation = (tmp_path / "not-created" / "finality-attestation.json").resolve()
    missing_evidence = (tmp_path / "not-created" / "chain-evidence.json").resolve()
    values["artifacts"]["finality_attestation"] = str(missing_attestation)
    values["artifacts"]["release_observation_chain_evidence"] = str(missing_evidence)
    candidate = LiveShadowReleaseInput.model_validate(values)
    input_path = _write(
        tmp_path / "capacity-release-input.json",
        canonical_json_bytes(candidate),
    )
    signing_root = (tmp_path / "capacity-signing").resolve()
    collected: list[str] = []

    async def live_capture(_prepared: object) -> LiveReleaseObservationCapture:
        collected.append("capture")
        return capture

    monkeypatch.setattr("umi.shadow_release.collect_live_release_observation", live_capture)
    monkeypatch.setattr(
        "umi.shadow_release.time.time_ns",
        lambda: capture.observation.observed_at_ms * 1_000_000,
    )

    assert main([str(input_path), "--capacity-signing-dir", str(signing_root)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["live_observation_collected"] is True
    assert summary["release_observation_block"] == capture.observation.block_number
    assert summary["release_observation_block_hash"] == capture.observation.block_hash
    assert summary["signing_request_count"] == 3
    assert collected == ["capture"]
    assert signing_root.stat().st_mode & 0o777 == 0o700
    assert all(
        path.stat().st_mode & 0o777 == 0o600 for path in signing_root.rglob("*") if path.is_file()
    )

    patch = json.loads((signing_root / "release-baseline-patch.json").read_bytes())
    assert patch["schema"] == "umi-live-shadow-release-baseline-patch/1"
    assert patch["observation"] == capture.observation.model_dump(mode="json")
    assert patch["artifact_replacements"] == {
        "finality_attestation": str(
            signing_root / "release-observation" / "finality-attestation.json"
        ),
        "release_observation_chain_evidence": str(
            signing_root / "release-observation" / "chain-evidence.json"
        ),
    }
    assert Path(patch["artifact_replacements"]["finality_attestation"]).read_bytes() == (
        capture.finality_attestation
    )
    assert (
        Path(patch["artifact_replacements"]["release_observation_chain_evidence"]).read_bytes()
        == capture.chain_evidence
    )
    baselined_path = signing_root / patch["baselined_release_input"]
    assert (
        hashlib.sha256(baselined_path.read_bytes()).hexdigest()
        == patch["baselined_release_input_sha256"]
    )
    baselined, baselined_bytes = (
        LiveShadowReleaseInput.model_validate_json(baselined_path.read_bytes()),
        baselined_path.read_bytes(),
    )
    assert canonical_json_bytes(baselined) == baselined_bytes
    assert baselined.observation == capture.observation
    assert (
        baselined.artifacts.finality_attestation
        == patch["artifact_replacements"]["finality_attestation"]
    )
    assert all(item.signature is None for item in baselined.publisher_capacities)
    replay_prepared = prepare_shadow_release(baselined)
    assert (
        canonical_json_bytes(replay_prepared.policy)
        == (signing_root / "scoring-policy.json").read_bytes()
    )
    requests = [
        json.loads(path.read_bytes())
        for path in sorted((signing_root / "publisher-capacity-signing").glob("*.json"))
    ]
    assert len(requests) == 3
    assert requests == [
        item.model_dump(mode="json", by_alias=True) for item in replay_prepared.signing_requests
    ]
    for request in requests:
        assert request["statement"]["issued_block"] == capture.observation.block_number
        assert request["statement"]["issued_block_hash"] == capture.observation.block_hash
        assert request["statement"]["valid_from_block"] == candidate.activation_block

    with pytest.raises(ShadowReleaseError, match="replay_finality_attestation_unavailable"):
        prepare_shadow_release(candidate)


def test_emit_rejects_a_manually_reconstructed_build(
    release_environment: tuple[LiveShadowReleaseInput, Path, int, LiveReleaseObservationCapture],
    tmp_path: Path,
) -> None:
    descriptor, _release_root, now_ms, capture = release_environment
    build = build_shadow_release(descriptor, live_capture=capture, now_ms=now_ms)
    reconstructed = BuiltShadowRelease(
        policy=build.policy,
        manifest=build.manifest,
        release_install_root=str((tmp_path / "forged-public").resolve()),
        files=build.files,
        file_modes=build.file_modes,
    )
    with pytest.raises(ShadowReleaseError, match="shadow_release_build_not_live_authorized"):
        emit_shadow_release_signing_stage(
            reconstructed,
            (tmp_path / "forged-stage").resolve(),
        )
