"""Read-only owned chain capture before the successor receipt exists.

The privileged migration runs this inside its private mount namespace. Signed
host helpers are bound at the existing fixed paths, and a separate private
upgrade cache is bound at the fixed finality path. This module neither creates
those mounts nor rewrites the observer configuration to point somewhere else.
It never opens a wallet, signs, submits, or constructs an installed capability.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
import weakref
from pathlib import Path

from .competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_host_activation import _require_readonly_filesystem
from .competition_host_anchor import (
    _read_source,
    _recheck_source,
    _require_private_control_parent,
)
from .competition_host_artifacts import (
    SignedSuccessorHostArtifact,
    VerifiedHostTree,
    parse_signed_host_artifact,
    verify_host_artifact_authority,
)
from .competition_host_switch import _root_directory
from .competition_host_upgrade import HostUpgradeError, StoppedSupervisor, _require_root_linux
from .competition_supervisor import (
    MAX_SUCCESSOR_DOCUMENT_BYTES,
    parse_canonical_successor_operator_consent,
)
from .competition_supervisor_observer import (
    HOST_OBSERVER_FILENAME,
    MAX_HOST_OBSERVER_CONFIG_BYTES,
    parse_successor_host_observer_config,
)
from .competition_upgrade import _open_without_links
from .competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
)
from .encoding import account_id32
from .open_competition import digest
from .protocol import canonical_json_bytes
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    parse_canonical_validator_supervisor_config,
)

_OBSERVERS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _observer_binding(value):
    sources = tuple(
        (
            id(source),
            source.path,
            source.payload,
            source.identity,
            source.maximum_bytes,
            source.modes,
        )
        for source in (value._consent, value._observer, value._source)
    )
    return (
        id(value._stopped),
        value._stopped._binding,
        id(value._tree),
        value._tree._binding,
        sources,
        value._resources,
        value._cache,
        value._cache_identity,
        id(value._lock),
    )


def _issued(value, *, allow_closed=False):
    state = _OBSERVERS.get(value)
    if (
        type(value) is not StoppedUpgradeObserver
        or state is None
        or state[0] != _observer_binding(value)
        or (state[1] and not allow_closed)
    ):
        raise HostUpgradeError("upgrade observer is absent, altered or closed")
    return state


def _same_mount(source: Path, mounted: Path, *, directory: bool, mode: int) -> None:
    descriptors = []
    try:
        for path in (source, mounted):
            parent = _root_directory(path.parent)
            os.close(parent)
            descriptor = _open_without_links(path)
            descriptors.append(descriptor)
            info = os.fstat(descriptor)
            if (
                not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != mode
                or (not directory and info.st_nlink != 1)
            ):
                raise HostUpgradeError("upgrade observer mount has unsafe ownership or type")
        source_info, mounted_info = (os.fstat(item) for item in descriptors)
        if (source_info.st_dev, source_info.st_ino) != (mounted_info.st_dev, mounted_info.st_ino):
            raise HostUpgradeError("upgrade observer fixed mount differs from its exact source")
        if not directory:
            _require_readonly_filesystem(mounted)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


class StoppedUpgradeObserver:
    """Collect owned recovery proofs using authenticated pre-install controls."""

    def __init__(
        self,
        *,
        stopped: StoppedSupervisor,
        host_tree: VerifiedHostTree,
        signed_host: SignedSuccessorHostArtifact,
        operator_consent_path: Path,
        observer_config_path: Path,
    ):
        _require_root_linux()
        if type(stopped) is not StoppedSupervisor or type(host_tree) is not VerifiedHostTree:
            raise TypeError(
                "upgrade observer requires genuine stopped-host and source capabilities"
            )
        stopped.recheck_stopped()
        host_tree.recheck()
        if (
            operator_consent_path.name != "operator-consent.json"
            or observer_config_path.name != HOST_OBSERVER_FILENAME
            or operator_consent_path.parent != observer_config_path.parent
        ):
            raise HostUpgradeError("upgrade observer controls need their fixed private paths")
        _require_private_control_parent(operator_consent_path.parent)
        sealed = frozenset({0o400, 0o440, 0o444})
        self._consent = _read_source(
            operator_consent_path, maximum_bytes=MAX_SUCCESSOR_DOCUMENT_BYTES, modes=sealed
        )
        self._observer = _read_source(
            observer_config_path, maximum_bytes=MAX_HOST_OBSERVER_CONFIG_BYTES, modes=sealed
        )
        self._source = _read_source(
            stopped._lease.config_path,
            maximum_bytes=MAX_SUPERVISOR_DOCUMENT_BYTES,
            modes=frozenset({0o400, 0o440, 0o600, 0o640}),
        )
        consent = parse_canonical_successor_operator_consent(self._consent.payload)
        config = parse_canonical_validator_supervisor_config(self._source.payload)
        observer = parse_successor_host_observer_config(self._observer.payload)
        signed_host = parse_signed_host_artifact(canonical_json_bytes(signed_host))
        verify_host_artifact_authority(
            signed_host,
            config=config,
            expected_manifest_sha256=consent.approved_host_manifest_sha256,
        )
        if (
            hashlib.sha256(self._source.payload).hexdigest() != stopped.config_sha256
            or consent.source_config_sha256 != stopped.config_sha256
            or consent.channel_id != config.channel_id
            or consent.validator_hotkey != config.validator_hotkey
            or account_id32(config.validator_hotkey) != account_id32(stopped.validator_hotkey)
            or consent.predecessor_sequence != stopped.accepted_sequence
            or consent.predecessor_directive_sha256 != stopped.accepted_directive_sha256
            or consent.predecessor_signed_directive_sha256
            != stopped.accepted_signed_directive_sha256
            or consent.predecessor_accepted_at_finalized_block
            != stopped.accepted_at_finalized_block
            or consent.target_platform != config.target_platform
            or host_tree.target_platform != config.target_platform
            or host_tree.manifest_sha256 != consent.approved_host_manifest_sha256
            or host_tree.umi_git_revision != signed_host.manifest.umi_git_revision
            or observer.chain.target_triple
            != {
                "linux/amd64": "x86_64-unknown-linux-gnu",
                "linux/arm64": "aarch64-unknown-linux-gnu",
            }[config.target_platform]
        ):
            raise HostUpgradeError("upgrade observer controls describe another installation")
        records = {item.path: item for item in signed_host.manifest.files}
        self._resources = (
            (
                host_tree.path / "artifacts/umi-grandpa-finality-observer",
                WORKER_FINALITY_BINARY,
                observer.chain.finality_pin.release_sha256_by_target[observer.chain.target_triple],
                0o555,
            ),
            (
                host_tree.path / "artifacts/umi-substrate-proof-verifier",
                WORKER_PROOF_BINARY,
                observer.chain.proof_binary_sha256,
                0o555,
            ),
            (
                host_tree.path / "artifacts/raw_spec_finney.json",
                WORKER_CHAIN_SPEC,
                observer.chain.finality_pin.chain_spec_sha256,
                0o444,
            ),
        )
        for source, _, sha, mode in self._resources:
            record = records.get(str(source.relative_to(host_tree.path)))
            if record is None or record.sha256 != sha or record.mode != mode:
                raise HostUpgradeError("upgrade observer helper is absent from the signed host")
        # This cache belongs to the root migration only. It never shares the
        # service/worker cache or requires changing the signed fixed path.
        self._cache = operator_consent_path.parent / "finality-state"
        for protected in (
            config.state_root,
            config.worker_state_root,
            config.release_root,
            config.operator_input_root,
            config.wallet.path,
        ):
            other = Path(protected)
            if self._cache == other or self._cache in other.parents or other in self._cache.parents:
                raise HostUpgradeError("upgrade observer cache overlaps an installed root")
        self._stopped, self._tree = stopped, host_tree
        self._lock = asyncio.Lock()
        self._cache_identity = None
        self._verify_inputs()
        self._cache_identity = self._cache_id()
        _OBSERVERS[self] = (_observer_binding(self), False)
        self._recheck()

    def _cache_id(self):
        descriptor = _open_without_links(self._cache)
        try:
            info = os.fstat(descriptor)
            return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)
        finally:
            os.close(descriptor)

    def _verify_inputs(self) -> None:
        _require_root_linux()
        self._stopped.recheck_stopped()
        self._tree.recheck()
        for source in (self._consent, self._observer, self._source):
            _recheck_source(source)
        for source, mounted, _, mode in self._resources:
            _same_mount(source, mounted, directory=False, mode=mode)
        _same_mount(self._cache, WORKER_FINALITY_STATE_ROOT, directory=True, mode=0o700)
        if self._cache_identity is not None and self._cache_id() != self._cache_identity:
            raise HostUpgradeError("upgrade observer cache was replaced")

    def _recheck(self) -> None:
        _issued(self)
        self._verify_inputs()
        _issued(self)

    async def observe(self) -> OwnedCompetitionChainObservation:
        _issued(self)
        async with self._lock:
            self._recheck()
            selected = parse_successor_host_observer_config(self._observer.payload)
            provider = FinalizedCompetitionWeightProvider(selected.chain, selected.policy)
            try:
                await provider.start()
                observation = await provider.wait_weights_ready(self._stopped.validator_hotkey, ())
            finally:
                await provider.aclose()
            # Slow provider shutdown and root-tree checks precede the final
            # freshness check. They cannot lend time to an expired proof.
            self._recheck()
            validate_owned_weight_observation(observation)
            if (
                account_id32(observation.validator_hotkey)
                != account_id32(self._stopped.validator_hotkey)
                or observation.chain_config_sha256 != digest(selected.chain)
                or observation.block < self._stopped.accepted_at_finalized_block
            ):
                raise HostUpgradeError("upgrade proof differs from its stopped installation")
            return observation

    async def aclose(self) -> None:
        _issued(self, allow_closed=True)
        async with self._lock:
            state = _issued(self, allow_closed=True)
            _OBSERVERS[self] = (state[0], True)
