"""Installed operator composition for the no-weight live-shadow validator.

The live validator deliberately keeps generic wallets and chain clients out of
its runtime injection surface.  This module is the one installed-process
boundary that opens the operator-selected Bittensor v11 client and wallet and
narrows them to the exact anchor, request-authentication, manifest-signing, and
read-only JSON-RPC adapters accepted by :mod:`umi.validator_live`.

No type in this module constructs, signs, or submits a weight call.  The only
extrinsic adapter it creates is the policy-bound three-anchor implementation.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import stat
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal

import bittensor as bt
from pydantic import Field, model_validator
from typing_extensions import Self

from .encoding import account_id32
from .mirror_readiness import (
    MAX_MIRROR_READINESS_BYTES,
    MirrorReadinessError,
    VerifiedLiveMirrorReadiness,
    verify_live_mirror_readiness,
)
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_anchor_composition import build_production_bittensor_anchor_ports
from .validator_chain import BittensorRawJsonRpc
from .validator_delivery import normalized_https_origin, validate_mirror_discovery_quorum
from .validator_live import (
    LIVE_SHADOW_MODE,
    LIVE_VALIDATOR_CONFIG_SCHEMA,
    LiveValidatorConfig,
    LiveValidatorError,
    LiveValidatorInvalidCapabilities,
    LiveValidatorMissingCapabilities,
    LiveValidatorProductionDependencies,
    LiveValidatorRuntime,
    PrivateBtauthTranscriptFactory,
    PrivateValidatorManifestSigner,
    ProductionAnchorContext,
    build_production_live_validator,
    load_live_policy,
    load_live_validator_config,
)
from .validator_live_ports import MirrorDiscoveryRule
from .validator_transcript_ports import VerifiedValidatorCapacitySet

LIVE_OPERATOR_CONFIG_SCHEMA = "umi-validator-live-operator-config/1"
MIRROR_REQUEST_HEADERS_SCHEMA = "umi-mirror-request-headers/2"
MAX_OPERATOR_CONFIG_BYTES = 256 * 1024
MAX_OPERATOR_ARTIFACT_BYTES = 4 * 1024 * 1024

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "te",
        "transfer-encoding",
        "upgrade",
    }
)


class LiveValidatorOperatorError(LiveValidatorError):
    """A stable, non-sensitive operator-composition failure."""


class MirrorOriginRequestHeaders(StrictProtocolModel):
    """Private headers usable at exactly one normalized retrieval origin."""

    origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    headers: Annotated[dict[str, str], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def validate_headers(self) -> Self:
        if normalized_https_origin(self.origin) != self.origin:
            raise ValueError("mirror request-header origin is not normalized HTTPS")
        seen: set[str] = set()
        for name, value in self.headers.items():
            lower = name.lower()
            if (
                _HEADER_NAME_RE.fullmatch(name) is None
                or lower in seen
                or lower in _FORBIDDEN_HEADERS
                or "\r" in value
                or "\n" in value
            ):
                raise ValueError("mirror request header is invalid")
            seen.add(lower)
        return self


class MirrorRequestHeaders(StrictProtocolModel):
    """Canonical per-origin private headers for the pinned mirror set."""

    schema_: Literal[MIRROR_REQUEST_HEADERS_SCHEMA] = Field(alias="schema")
    readiness_set_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    origins: Annotated[list[MirrorOriginRequestHeaders], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def validate_origins(self) -> Self:
        readiness_path = Path(self.readiness_set_path)
        if not readiness_path.is_absolute() or readiness_path != Path(
            os.path.normpath(readiness_path)
        ):
            raise ValueError("mirror readiness-set path must be absolute and normalized")
        values = [item.origin for item in self.origins]
        if values != sorted(values) or len(set(values)) != len(values):
            raise ValueError("mirror request-header origins must be unique and sorted")
        authorization_values: list[str] = []
        for item in self.origins:
            matches = [
                value for name, value in item.headers.items() if name.lower() == "authorization"
            ]
            if len(matches) != 1:
                raise ValueError("each mirror origin requires one Authorization header")
            authorization_values.extend(matches)
        if len(set(authorization_values)) != len(authorization_values):
            raise ValueError("mirror origins must not share an Authorization credential")
        return self


class LiveValidatorOperatorConfig(StrictProtocolModel):
    """Canonical local references needed to open one operator session."""

    schema_: Literal[LIVE_OPERATOR_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    network: Literal["finney"]
    wallet_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_hotkey_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    validator_capacity_set_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    mirror_discovery_rule_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    mirror_request_headers_path: Annotated[str, Field(min_length=1, max_length=4_096)]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if _NAME_RE.fullmatch(self.wallet_name) is None:
            raise ValueError("wallet name is not canonical")
        if _NAME_RE.fullmatch(self.wallet_hotkey_name) is None:
            raise ValueError("wallet hotkey name is not canonical")
        paths = tuple(
            Path(value)
            for value in (
                self.wallet_path,
                self.validator_capacity_set_path,
                self.mirror_discovery_rule_path,
                self.mirror_request_headers_path,
            )
        )
        if any(not path.is_absolute() for path in paths):
            raise ValueError("operator paths must be absolute")
        if any(path != Path(os.path.normpath(path)) for path in paths):
            raise ValueError("operator paths must be lexically normalized")
        artifact_paths = paths[1:]
        if len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("operator artifact paths must be distinct")
        return self


@dataclass(frozen=True, slots=True)
class LoadedOperatorArtifacts:
    """Exact immutable artifacts bound to one policy."""

    capacity_set: VerifiedValidatorCapacitySet
    mirror_discovery_rule_bytes: bytes
    mirror_request_headers: Mapping[str, Mapping[str, str]]
    mirror_readiness: VerifiedLiveMirrorReadiness


class PrivateBittensorAnchorFactory:
    """Narrow one private Bittensor client and hotkey to UMI anchor calls."""

    __slots__ = ("__client", "__signer")

    def __init__(self, client: Any, signer: Any) -> None:
        try:
            substrate = client._substrate
            signer_address = signer.ss58_address
            signer_public_key = signer.public_key
        except Exception as error:
            raise TypeError("operator client or signer does not implement Bittensor v11") from error
        if any(
            not callable(getattr(substrate, name, None))
            for name in ("compose", "prepare", "submit_signature")
        ):
            raise TypeError("operator client lacks the Bittensor v11 substrate surface")
        if account_id32(signer_address) != bytes(signer_public_key):
            raise ValueError("operator signer address and public key disagree")
        self.__client = client
        self.__signer = signer

    def __call__(self, context: ProductionAnchorContext):
        if not isinstance(context, ProductionAnchorContext):
            raise TypeError("context must be ProductionAnchorContext")
        return build_production_bittensor_anchor_ports(
            policy=context.policy,
            target_triple=context.config.target_triple,
            subtensor=self.__client,
            signer=self.__signer,
            journal=context.extrinsic_journal,
            sidecar_root=context.paths.anchor_sidecars,
            finality=context.finality,
            storage_proof_verifier=context.storage_proof_verifier,
            finality_verifier_sha256=context.finality_verifier_sha256,
        )


def load_live_operator_config(path: str | Path) -> LiveValidatorOperatorConfig:
    """Load one stable, canonical operator document without following a symlink."""

    encoded = _read_stable_file(
        Path(path),
        maximum_bytes=MAX_OPERATOR_CONFIG_BYTES,
        label="operator_config",
        private=False,
    )
    try:
        document = json.loads(encoded)
        config = LiveValidatorOperatorConfig.model_validate(document)
    except Exception as error:
        raise LiveValidatorOperatorError("operator_config_invalid") from error
    if canonical_json_bytes(config) != encoded:
        raise LiveValidatorOperatorError("operator_config_noncanonical")
    return config


def load_operator_artifacts(
    *,
    policy: ScoringPolicy,
    live_config: LiveValidatorConfig,
    operator_config: LiveValidatorOperatorConfig,
) -> LoadedOperatorArtifacts:
    """Authenticate all file-backed operator inputs against policy bytes."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if not isinstance(live_config, LiveValidatorConfig):
        raise TypeError("live_config must be a LiveValidatorConfig")
    if not isinstance(operator_config, LiveValidatorOperatorConfig):
        raise TypeError("operator_config must be a LiveValidatorOperatorConfig")
    _require_operator_paths_outside_state(live_config, operator_config)
    capacity_bytes = _read_stable_file(
        Path(operator_config.validator_capacity_set_path),
        maximum_bytes=MAX_OPERATOR_ARTIFACT_BYTES,
        label="validator_capacity_set",
        private=False,
    )
    discovery_bytes = _read_stable_file(
        Path(operator_config.mirror_discovery_rule_path),
        maximum_bytes=MAX_OPERATOR_ARTIFACT_BYTES,
        label="mirror_discovery_rule",
        private=False,
    )
    headers_bytes = _read_stable_file(
        Path(operator_config.mirror_request_headers_path),
        maximum_bytes=MAX_OPERATOR_CONFIG_BYTES,
        label="mirror_request_headers",
        private=True,
    )
    try:
        capacity_set = VerifiedValidatorCapacitySet(policy, capacity_bytes)
    except Exception as error:
        raise LiveValidatorOperatorError("validator_capacity_set_invalid") from error
    try:
        discovery = MirrorDiscoveryRule.model_validate_json(discovery_bytes)
    except Exception as error:
        raise LiveValidatorOperatorError("mirror_discovery_rule_invalid") from error
    if canonical_json_bytes(discovery) != discovery_bytes:
        raise LiveValidatorOperatorError("mirror_discovery_rule_noncanonical")
    expected_discovery = policy.implementation_pins.rules.mirror_discovery_rule_sha256
    if hashlib.sha256(discovery_bytes).hexdigest() != expected_discovery:
        raise LiveValidatorOperatorError("mirror_discovery_rule_policy_mismatch")
    try:
        validate_mirror_discovery_quorum(policy, discovery)
    except (TypeError, ValueError) as error:
        raise LiveValidatorOperatorError("mirror_discovery_quorum_invalid") from error
    try:
        headers = MirrorRequestHeaders.model_validate_json(headers_bytes)
    except Exception as error:
        raise LiveValidatorOperatorError("mirror_request_headers_invalid") from error
    if canonical_json_bytes(headers) != headers_bytes:
        raise LiveValidatorOperatorError("mirror_request_headers_noncanonical")
    if [item.origin for item in headers.origins] != discovery.origins:
        raise LiveValidatorOperatorError("mirror_request_headers_origin_set_mismatch")
    header_map = MappingProxyType(
        {item.origin: MappingProxyType(dict(item.headers)) for item in headers.origins}
    )
    readiness_bytes = _read_stable_file(
        Path(headers.readiness_set_path),
        maximum_bytes=MAX_MIRROR_READINESS_BYTES,
        label="mirror_readiness_set",
        private=False,
    )
    try:
        readiness = verify_live_mirror_readiness(
            policy=policy,
            discovery_rule_bytes=discovery_bytes,
            readiness_set_bytes=readiness_bytes,
        )
    except MirrorReadinessError as error:
        raise LiveValidatorOperatorError(error.reason_code) from error
    return LoadedOperatorArtifacts(
        capacity_set=capacity_set,
        mirror_discovery_rule_bytes=discovery_bytes,
        mirror_request_headers=header_map,
        mirror_readiness=readiness,
    )


def build_live_operator_dependencies(
    *,
    live_config: LiveValidatorConfig,
    operator_config: LiveValidatorOperatorConfig,
    policy: ScoringPolicy,
    client: Any,
    wallet: Any | None = None,
) -> LiveValidatorProductionDependencies:
    """Narrow one connected or cold Bittensor v11 client to production ports.

    Construction is inert.  A cold ``bt.Client`` is valid for ``--check``;
    normal execution calls this only while the same client is connected.
    """

    if getattr(bt, "__version__", None) != "11.1.0":
        raise LiveValidatorOperatorError("bittensor_version_mismatch")
    if getattr(client, "network", None) != operator_config.network:
        raise LiveValidatorOperatorError("bittensor_network_mismatch")
    live_chain = policy.implementation_pins.live_chain
    if live_chain is None or live_chain.network != operator_config.network:
        raise LiveValidatorOperatorError("operator_network_policy_mismatch")
    selected_wallet = wallet or bt.Wallet(
        name=operator_config.wallet_name,
        hotkey=operator_config.wallet_hotkey_name,
        path=operator_config.wallet_path,
    )
    try:
        signer = bt.resolve_signer(selected_wallet, role="hotkey")
        signer_hotkey = signer.ss58_address
    except Exception as error:
        raise LiveValidatorOperatorError("validator_hotkey_unavailable") from error
    if account_id32(signer_hotkey) != account_id32(live_config.validator_hotkey):
        raise LiveValidatorOperatorError("validator_hotkey_mismatch")
    artifacts = load_operator_artifacts(
        policy=policy,
        live_config=live_config,
        operator_config=operator_config,
    )
    return LiveValidatorProductionDependencies(
        raw_json_rpc=BittensorRawJsonRpc(client),
        anchor_ports_factory=PrivateBittensorAnchorFactory(client, signer),
        transcript_ports_factory=PrivateBtauthTranscriptFactory(selected_wallet),
        validator_capacity_set=artifacts.capacity_set,
        mirror_discovery_rule_bytes=artifacts.mirror_discovery_rule_bytes,
        mirror_request_headers=artifacts.mirror_request_headers,
        mirror_readiness=artifacts.mirror_readiness,
        manifest_signer=PrivateValidatorManifestSigner(
            selected_wallet,
            validator_hotkey=live_config.validator_hotkey,
            signature_scheme=live_config.signature_scheme,
        ),
    )


async def run_installed_operator(
    *,
    config_path: str | Path,
    operator_config_path: str | Path,
    check: bool,
    client_factory: Any = bt.Client,
) -> int:
    """Run the installed operator path with one correctly scoped client lifetime."""

    runtime: LiveValidatorRuntime | None = None
    client: Any | None = None
    try:
        live_config = load_live_validator_config(config_path)
        policy = load_live_policy(live_config)
        operator_config = load_live_operator_config(operator_config_path)
        client = client_factory(operator_config.network)
        if not check:
            connected = await client.connect()
            if connected is not client:
                raise LiveValidatorOperatorError("bittensor_client_connection_invalid")
        dependencies = build_live_operator_dependencies(
            live_config=live_config,
            operator_config=operator_config,
            policy=policy,
            client=client,
        )
        runtime = build_production_live_validator(
            config=live_config,
            dependencies=dependencies,
        )
        print(
            canonical_json_bytes(
                {
                    "configured_stages": [stage.value for stage in runtime.configured_stages],
                    "mode": LIVE_SHADOW_MODE,
                    "network": operator_config.network,
                    "scoring_policy_sha256": runtime.scoring_policy_hash,
                    "status": "ready",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8")
        )
        if check:
            return 0
        await _run_until_signal(runtime, poll_seconds=live_config.poll_seconds)
        return 0
    except LiveValidatorMissingCapabilities as error:
        _print_error(error.reason_code, missing_capabilities=list(error.missing_codes))
        return 2
    except LiveValidatorInvalidCapabilities as error:
        _print_error(error.reason_code, invalid_capabilities=list(error.invalid_codes))
        return 2
    except LiveValidatorError as error:
        _print_error(error.reason_code)
        return 2
    except Exception:
        _print_error("operator_runtime_failed")
        return 2
    finally:
        if runtime is not None:
            runtime.close()
        if client is not None:
            with suppress(Exception):
                await client.close()


def configure_operator(argv: Sequence[str] | None = None) -> int:
    """Materialize canonical config documents from explicit operator inputs."""

    args = _configure_parser().parse_args(argv)
    try:
        policy_bytes = _read_stable_file(
            args.policy,
            maximum_bytes=MAX_OPERATOR_ARTIFACT_BYTES,
            label="policy",
            private=False,
        )
        try:
            policy = ScoringPolicy.model_validate_json(policy_bytes)
        except Exception as error:
            raise LiveValidatorOperatorError("policy_invalid") from error
        if canonical_json_bytes(policy) != policy_bytes:
            raise LiveValidatorOperatorError("policy_noncanonical")
        if policy.translation_weights_active is not False:
            raise LiveValidatorOperatorError("policy_weights_active")
        live_config = LiveValidatorConfig(
            schema=LIVE_VALIDATOR_CONFIG_SCHEMA,
            protocol=PROTOCOL_VERSION,
            mode=LIVE_SHADOW_MODE,
            translation_weights_active=False,
            policy_path=str(args.policy),
            scoring_policy_sha256=scoring_policy_hash(policy),
            conformance_release_root=str(args.conformance_release_root),
            state_root=str(args.state_root),
            validator_hotkey=args.validator_hotkey,
            target_triple=args.target_triple,
            storage_proof_verifier_binary=str(args.storage_proof_verifier),
            finality_verifier_binary=str(args.finality_verifier),
            finality_chain_spec_path=str(args.finality_chain_spec),
            initial_minimum_finalized_block=policy.activation_block - 1,
            signature_scheme=args.signature_scheme,
            umi_revision=args.umi_revision,
            maximum_transport_concurrency=args.maximum_transport_concurrency,
            transport_timeout_seconds=args.transport_timeout_seconds,
            stage_port_timeout_seconds=args.stage_port_timeout_seconds,
            maximum_anchor_advances=args.maximum_anchor_advances,
            poll_seconds=args.poll_seconds,
        )
        operator_config = LiveValidatorOperatorConfig(
            schema=LIVE_OPERATOR_CONFIG_SCHEMA,
            protocol=PROTOCOL_VERSION,
            mode=LIVE_SHADOW_MODE,
            network="finney",
            wallet_name=args.wallet_name,
            wallet_hotkey_name=args.wallet_hotkey_name,
            wallet_path=str(args.wallet_path),
            validator_capacity_set_path=str(args.validator_capacity_set),
            mirror_discovery_rule_path=str(args.mirror_discovery_rule),
            mirror_request_headers_path=str(args.mirror_request_headers),
        )
        # Exercise the same live-profile and registry checks as the runner.  A
        # local rehearsal policy is never promoted into an operator document.
        load_live_policy(live_config)
        # Validate public and private artifact bindings before writing either
        # output. Wallet resolution remains a run-time operation and may prompt.
        load_operator_artifacts(
            policy=policy,
            live_config=live_config,
            operator_config=operator_config,
        )
        outputs = (args.live_config_output, args.operator_config_output)
        inputs = {
            args.policy,
            args.storage_proof_verifier,
            args.finality_verifier,
            args.finality_chain_spec,
            args.validator_capacity_set,
            args.mirror_discovery_rule,
            args.mirror_request_headers,
        }
        if outputs[0] == outputs[1] or any(output in inputs for output in outputs):
            raise LiveValidatorOperatorError("operator_output_path_conflict")
        _write_new_private_file(args.live_config_output, canonical_json_bytes(live_config))
        try:
            _write_new_private_file(
                args.operator_config_output,
                canonical_json_bytes(operator_config),
            )
        except BaseException:
            with suppress(OSError):
                args.live_config_output.unlink()
            raise
        print(
            canonical_json_bytes(
                {
                    "live_config": str(args.live_config_output),
                    "operator_config": str(args.operator_config_output),
                    "scoring_policy_sha256": scoring_policy_hash(policy),
                    "status": "configured",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8")
        )
        return 0
    except LiveValidatorError as error:
        _print_error(error.reason_code)
        return 2
    except (OSError, ValueError):
        _print_error("operator_configuration_failed")
        return 2


def _require_operator_paths_outside_state(
    live_config: LiveValidatorConfig,
    operator_config: LiveValidatorOperatorConfig,
) -> None:
    state = Path(live_config.state_root)
    inputs = tuple(
        Path(value)
        for value in (
            operator_config.wallet_path,
            operator_config.validator_capacity_set_path,
            operator_config.mirror_discovery_rule_path,
            operator_config.mirror_request_headers_path,
        )
    )
    if any(path == state or state in path.parents or path in state.parents for path in inputs):
        raise LiveValidatorOperatorError("operator_artifact_state_overlap")


def _read_stable_file(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
    private: bool,
) -> bytes:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise LiveValidatorOperatorError(f"{label}_path_invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LiveValidatorOperatorError(f"{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        unsafe_mode = before.st_mode & (0o077 if private else 0o022)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or unsafe_mode
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise LiveValidatorOperatorError(f"{label}_unsafe")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int]:
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)

    if identity(before) != identity(after) or len(encoded) != before.st_size:
        raise LiveValidatorOperatorError(f"{label}_changed")
    if len(encoded) > maximum_bytes:
        raise LiveValidatorOperatorError(f"{label}_unsafe")
    return encoded


def _write_new_private_file(path: Path, encoded: bytes) -> None:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise LiveValidatorOperatorError("output_path_invalid")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o022
    ):
        raise LiveValidatorOperatorError("output_directory_unsafe")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short configuration write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        with suppress(OSError):
            path.unlink()
        raise
    else:
        os.close(descriptor)


async def _run_until_signal(runtime: LiveValidatorRuntime, *, poll_seconds: float) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for item in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(item, stop.set)
            installed.append(item)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await runtime.run(stop, poll_seconds=poll_seconds)
    finally:
        stop.set()
        for item in installed:
            loop.remove_signal_handler(item)


def _print_error(reason_code: str, **extra: Any) -> None:
    document = {
        **extra,
        "reason_code": reason_code,
        "status": "blocked",
        "translation_weights_active": False,
        "weight_submission_capability": False,
    }
    print(canonical_json_bytes(document).decode("utf-8"), file=sys.stderr)


def _configure_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create canonical operator files for a supplied UMI live-shadow policy"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--conformance-release-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--target-triple", required=True)
    parser.add_argument("--storage-proof-verifier", type=Path, required=True)
    parser.add_argument("--finality-verifier", type=Path, required=True)
    parser.add_argument("--finality-chain-spec", type=Path, required=True)
    parser.add_argument("--signature-scheme", choices=("sr25519", "ed25519"), required=True)
    parser.add_argument("--umi-revision", required=True)
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--wallet-hotkey-name", required=True)
    parser.add_argument("--wallet-path", type=Path, required=True)
    parser.add_argument("--validator-capacity-set", type=Path, required=True)
    parser.add_argument("--mirror-discovery-rule", type=Path, required=True)
    parser.add_argument("--mirror-request-headers", type=Path, required=True)
    parser.add_argument("--live-config-output", type=Path, required=True)
    parser.add_argument("--operator-config-output", type=Path, required=True)
    parser.add_argument("--maximum-transport-concurrency", type=int, default=8)
    parser.add_argument("--transport-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--stage-port-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--maximum-anchor-advances", type=int, default=4)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    return parser


def main() -> None:
    raise SystemExit(configure_operator())


__all__ = [
    "LIVE_OPERATOR_CONFIG_SCHEMA",
    "MIRROR_REQUEST_HEADERS_SCHEMA",
    "LiveValidatorOperatorConfig",
    "LiveValidatorOperatorError",
    "LoadedOperatorArtifacts",
    "MirrorOriginRequestHeaders",
    "MirrorRequestHeaders",
    "PrivateBittensorAnchorFactory",
    "build_live_operator_dependencies",
    "configure_operator",
    "load_live_operator_config",
    "load_operator_artifacts",
    "run_installed_operator",
]
