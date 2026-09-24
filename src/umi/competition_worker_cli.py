"""Fixed successor container entrypoints, without caller-selected paths or commands.

Replay uses only authenticated local inputs and its private journal. Weights
add the configured validator hotkey and application-bound Finney transport;
the CLI does not claim to enforce a kernel network allowlist.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    validate_owned_weight_observation,
)
from .competition_package import load_competition_package
from .competition_package_reuse import package_verification_session
from .competition_reward_continuity import authorized_reward_row
from .competition_weights import (
    BittensorCompetitionWeightTransport,
    CompetitionWeightWorker,
    signed_competition_weight_authorization_digest,
    validate_weight_preflight,
    verify_competition_weight_authorization,
)
from .competition_worker import CompetitionReplayWorker, CompetitionWorkerCapacity
from .encoding import account_id32
from .open_competition import Registration
from .protocol import StrictProtocolModel, canonical_json_bytes

WORKER_PACKAGE_ROOT = Path("/run/umi-successor-activation/current/package")
WORKER_REPLAY_STATE_ROOT = Path("/var/lib/umi-competition/replay")
WORKER_WEIGHTS_STATE_ROOT = Path("/var/lib/umi-competition/weights")
WORKER_FINALITY_STATE_ROOT = Path("/var/lib/umi-competition/finality")
WORKER_HOTKEY_FILE = Path("/run/umi-successor-hotkey/hotkey")
WORKER_FINALITY_BINARY = Path("/opt/umi/bin/umi-grandpa-finality-observer")
WORKER_PROOF_BINARY = Path("/opt/umi/bin/umi-substrate-proof-verifier")
WORKER_RUNTIME_METADATA_BINARY = Path("/opt/umi/bin/umi-runtime-metadata")
WORKER_CHAIN_SPEC = Path("/opt/umi/raw_spec_finney.json")
_MAX_KEYFILE_BYTES = 128 * 1024
_MAX_STDOUT_BYTES = 128 * 1024


class SuccessorWeightExecutionConfig(StrictProtocolModel):
    maximum_attempts: Annotated[int, Field(ge=1, le=65536)]
    maximum_evidence_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)]
    submission_timeout_seconds: Annotated[int, Field(ge=1, le=3600)]
    chain: CompetitionChainConfig

    @model_validator(mode="after")
    def fixed_paths_and_target(self) -> Self:
        if self.chain.runtime_metadata_binary not in (None, str(WORKER_RUNTIME_METADATA_BINARY)):
            raise ValueError("runtime metadata executor must use the fixed worker path")
        observed = (
            self.chain.finality_binary,
            self.chain.proof_binary,
            self.chain.chain_spec,
            self.chain.state_directory,
        )
        expected = tuple(
            str(path)
            for path in (
                WORKER_FINALITY_BINARY,
                WORKER_PROOF_BINARY,
                WORKER_CHAIN_SPEC,
                WORKER_FINALITY_STATE_ROOT,
            )
        )
        if observed != expected or self.chain.target_triple not in {
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        }:
            raise ValueError("successor chain execution paths or platform are not fixed")
        return self


class SuccessorWorkerExecutionConfig(StrictProtocolModel):
    """Per-run settings authenticated by the host within installed quota ceilings."""

    schema_: Literal["umi-successor-worker-execution-config/1"] = Field(alias="schema")
    replay_capacity: CompetitionWorkerCapacity
    weights: SuccessorWeightExecutionConfig | None


def _load_hotkey(expected_hotkey: str):
    # No Wallet constructor, coldkey lookup, password environment or prompt.
    # Only the already-approved hotkey file is mounted into this worker.
    from bittensor.keyfiles import (
        deserialize_keypair_from_keyfile_data,
        keyfile_data_is_encrypted,
    )

    from .competition_upgrade import _fingerprint, _open_without_links

    descriptor = _open_without_links(WORKER_HOTKEY_FILE)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) != 0o400
            or not 0 < before.st_size <= _MAX_KEYFILE_BYTES
        ):
            raise ValueError("successor hotkey mount is unsafe")
        body = bytearray()
        while chunk := os.read(descriptor, min(8192, _MAX_KEYFILE_BYTES + 1 - len(body))):
            body.extend(chunk)
            if len(body) > _MAX_KEYFILE_BYTES:
                raise ValueError("successor hotkey mount exceeds its bound")
        if len(body) != before.st_size or _fingerprint(os.fstat(descriptor)) != _fingerprint(
            before
        ):
            raise ValueError("successor hotkey mount changed while reading")
    finally:
        os.close(descriptor)
    try:
        if keyfile_data_is_encrypted(bytes(body)):
            raise ValueError("successor hotkey must be unlocked by its operator before staging")
        signer = deserialize_keypair_from_keyfile_data(bytes(body))
        if account_id32(signer.ss58_address) != account_id32(expected_hotkey):
            raise ValueError("successor hotkey differs from its installed identity")
        if signer.crypto_type not in {0, 1}:
            raise ValueError("successor hotkey has an unsupported signing scheme")
        return signer
    finally:
        # Best-effort cleanup of this mutable read buffer, not a claim that
        # Python or the SDK can erase all private-key copies from memory.
        body[:] = b"\x00" * len(body)


def _load_inputs():
    from .competition_host_upgrade import load_successor_worker_inputs

    return load_successor_worker_inputs()


def _activate(inputs, observation):
    from .competition_host_activation import activate_successor_worker

    # The fixed mounts were fully verified before collecting this proof. A
    # reload here would replay the package inside the observation's TTL.
    return activate_successor_worker(inputs, owned_observation=observation)


async def run_worker(mode: Literal["competition_replay", "competition_weights"]):
    if sys.platform != "linux":
        raise ValueError("successor worker requires its approved Linux container")
    inputs = _load_inputs()
    inputs.recheck()
    if mode not in {"competition_replay", "competition_weights"} or inputs.profile != mode:
        raise ValueError("successor command differs from its authenticated profile")
    config = SuccessorWorkerExecutionConfig.model_validate_json(
        canonical_json_bytes(inputs.worker_execution_config)
    )
    directive = inputs.directive
    target = directive.replay_package
    if target is None or directive.mode != mode:
        raise ValueError("successor worker directive lacks its fixed replay target")
    if (config.weights is not None) != (mode == "competition_weights"):
        raise ValueError("successor execution configuration expands its profile")
    if mode == "competition_replay" and inputs.authorization is not None:
        raise ValueError("wallet-free replay cannot carry weight authorization")
    replay = CompetitionReplayWorker(
        WORKER_REPLAY_STATE_ROOT,
        package_limits=target.limits,
        capacity=config.replay_capacity,
    )
    inputs.recheck()
    replay_result = replay.run(
        WORKER_PACKAGE_ROOT,
        expected_package_sha256=target.package_sha256,
        expected_policy_sha256=target.policy_sha256,
        observed_release=inputs.release_identity,
    )
    if mode == "competition_replay":
        inputs.recheck()
        return replay_result
    assert config.weights is not None
    authorization = inputs.authorization
    if authorization is None:
        raise ValueError("weight execution lacks separate signed authorization")
    package = load_competition_package(
        WORKER_PACKAGE_ROOT,
        expected_package_sha256=target.package_sha256,
        expected_policy_sha256=target.policy_sha256,
        observed_release=inputs.release_identity,
        limits=target.limits,
    )
    body = verify_competition_weight_authorization(
        authorization,
        trusted_authority_hotkeys=tuple(inputs.authority_hotkeys),
        package=package,
    )
    chain_config = config.weights.chain
    if (
        chain_config.chain_pin != directive.chain.chain_pin
        or chain_config.target_triple != inputs.release_identity.target_triple
    ):
        raise ValueError("successor observer differs from installed release or directive")
    chain = FinalizedCompetitionWeightProvider(chain_config, package.policy)
    try:
        await chain.start()
        recipients = tuple(
            Registration(uid=item.uid, hotkey=item.hotkey)
            for item in authorized_reward_row(package, body).allocations
        )
        observation = await chain.wait_weights_ready(inputs.validator_hotkey, recipients)
        validate_owned_weight_observation(observation)
        validate_weight_preflight(package, body, observation, chain_config, submission=False)
        inputs.recheck()
        activation = _activate(inputs, observation)
        if (
            activation.directive_sha256 != inputs.directive_sha256
            or activation.config_sha256 != inputs.config_sha256
            or activation.validator_hotkey != inputs.validator_hotkey
            or activation.package_sha256 != target.package_sha256
            or activation.authorization_sha256
            != signed_competition_weight_authorization_digest(authorization)
        ):
            raise ValueError("successor activation changed during observer startup")
        signer = _load_hotkey(inputs.validator_hotkey)
        inputs.recheck()
        worker = CompetitionWeightWorker(
            WORKER_WEIGHTS_STATE_ROOT,
            package_limits=target.limits,
            replay_worker=replay,
            maximum_attempts=config.weights.maximum_attempts,
            maximum_evidence_bytes=config.weights.maximum_evidence_bytes,
            submission_timeout_seconds=config.weights.submission_timeout_seconds,
        )
        return await worker.run(
            WORKER_PACKAGE_ROOT,
            authorization=authorization,
            activation=activation,
            wallet=signer,
            chain=chain,
            transport=BittensorCompetitionWeightTransport(
                endpoint=chain_config.rpc_url,
                fallback_endpoints=chain_config.proof_rpc_fallback_urls,
            ),
        )
    finally:
        await chain.aclose()


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="umi-competition-worker",
        description="Run one installed successor replay or weight profile",
        allow_abbrev=False,
    )
    parser.add_argument("mode", choices=("competition_replay", "competition_weights"))
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    os.umask(0o077)
    try:
        with package_verification_session():
            result = asyncio.run(run_worker(args.mode))
        encoded = canonical_json_bytes(result)
        if len(encoded) > _MAX_STDOUT_BYTES:
            raise ValueError("successor worker result exceeds its output bound")
        print(encoded.decode("utf-8"))
        if hasattr(result, "current_status"):
            return 3 if result.current_status.held else 0
        return 0 if result.exact_row_currently_applied else 3
    except Exception:
        # Exceptions can contain RPC URLs, filesystem paths or keyfile content.
        # Detailed evidence belongs in the bounded private journals, not stdout.
        print("successor worker failed; inspect local bounded status", file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
