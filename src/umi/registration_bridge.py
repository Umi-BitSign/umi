"""Signed availability bridge for registered SN78 miners.

This is not model evaluation, pilot admission, or the open competition protocol.
The owned verifier authenticates the finalized block identity; storage values are
internally checked, block-pinned SDK reads, not storage-proof verification.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import os
import platform
import stat
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import bittensor as bt
import httpx
from bittensor._generated import storage

from .bootstrap_weight_operator import (
    BootstrapExtrinsicReference as BootstrapExtrinsicReference,
)
from .bootstrap_weight_operator import (
    _block_time,
    _bool,
    _datetime_ms,
    _participants,
    _pending_commit_summary,
    _uint,
    _validate_finalized_block,
)
from .bridge.journal import (
    REGISTRATION_BRIDGE_JOURNAL_SCHEMA as REGISTRATION_BRIDGE_JOURNAL_SCHEMA,
)
from .bridge.journal import (
    RegistrationBridgeAttempt as RegistrationBridgeAttempt,
)
from .bridge.journal import (
    RegistrationBridgeChurnAttempt as RegistrationBridgeChurnAttempt,
)
from .bridge.journal import (
    RegistrationBridgeJournal as RegistrationBridgeJournal,
)
from .bridge.journal import (
    _new_attempt as _new_attempt,
)
from .bridge.journal import (
    reconcile_registration_bridge_journal as reconcile_registration_bridge_journal,
)
from .bridge.journal_history import reconcile_archived_transition, validate_next_journal
from .bridge.native import receipt_reader, signing_reader

# Preserve the public bridge API while policy and selection remain independently testable.
from .bridge.policy import (
    MAX_DOCUMENT_BYTES as MAX_DOCUMENT_BYTES,
)
from .bridge.policy import (
    MAX_JSON_INTEGER as MAX_JSON_INTEGER,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_COORDINATOR as REGISTRATION_BRIDGE_COORDINATOR,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK as REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_POLICY_BODY_SCHEMA as REGISTRATION_BRIDGE_POLICY_BODY_SCHEMA,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_POLICY_SCHEMA as REGISTRATION_BRIDGE_POLICY_SCHEMA,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_PROFILE as REGISTRATION_BRIDGE_PROFILE,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_SIGNATURE_DOMAIN as REGISTRATION_BRIDGE_SIGNATURE_DOMAIN,
)
from .bridge.policy import (
    REGISTRATION_BRIDGE_STOP_SUBMITTING_BLOCK as REGISTRATION_BRIDGE_STOP_SUBMITTING_BLOCK,
)
from .bridge.policy import (
    PositiveInt as PositiveInt,
)
from .bridge.policy import (
    RegistrationBridgeError as RegistrationBridgeError,
)
from .bridge.policy import (
    RegistrationBridgeFrozenPolicyBody as RegistrationBridgeFrozenPolicyBody,
)
from .bridge.policy import (
    RegistrationBridgeFundingPolicyBody as RegistrationBridgeFundingPolicyBody,
)
from .bridge.policy import (
    RegistrationBridgeOngoingPolicyBody as RegistrationBridgeOngoingPolicyBody,
)
from .bridge.policy import (
    RegistrationBridgePolicyBody as RegistrationBridgePolicyBody,
)
from .bridge.policy import (
    SignedRegistrationBridgePolicy as SignedRegistrationBridgePolicy,
)
from .bridge.policy import (
    UInt as UInt,
)
from .bridge.policy import (
    _canonical_object as _canonical_object,
)
from .bridge.policy import (
    _require as _require,
)
from .bridge.policy import (
    parse_registration_bridge_policy as parse_registration_bridge_policy,
)
from .bridge.policy import (
    registration_bridge_policy_digest as registration_bridge_policy_digest,
)
from .bridge.policy import (
    registration_bridge_policy_sha256 as registration_bridge_policy_sha256,
)
from .bridge.policy import (
    sign_registration_bridge_policy as sign_registration_bridge_policy,
)
from .bridge.policy import (
    verify_registration_bridge_policy as verify_registration_bridge_policy,
)
from .bridge.selection import (
    RegistrationBridgeDecision as RegistrationBridgeDecision,
)
from .bridge.selection import (
    RegistrationBridgeHealth as RegistrationBridgeHealth,
)
from .bridge.selection import (
    RegistrationBridgeObservation as RegistrationBridgeObservation,
)
from .bridge.selection import (
    RegistrationBridgeParticipant as RegistrationBridgeParticipant,
)
from .bridge.selection import (
    _bridge_public_origin as _bridge_public_origin,
)
from .bridge.selection import (
    _coldkey_group_row as _coldkey_group_row,
)
from .bridge.selection import (
    _coldkey_ip_groups as _coldkey_ip_groups,
)
from .bridge.selection import (
    _equal_group_row as _equal_group_row,
)
from .bridge.selection import (
    _health_registration_identity as _health_registration_identity,
)
from .bridge.selection import (
    _registered_candidates as _registered_candidates,
)
from .bridge.selection import (
    _validate_row as _validate_row,
)
from .bridge.selection import (
    registration_bridge_roster_sha256 as registration_bridge_roster_sha256,
)
from .bridge.selection import (
    validate_registration_bridge_chain as validate_registration_bridge_chain,
)
from .bridge.selection import (
    validate_registration_bridge_observation as validate_registration_bridge_observation,
)
from .bridge.submission import build_registration_bridge_call as build_registration_bridge_call
from .bridge.submission import (
    persist,
    recover_transaction,
    submit_transaction,
    validate_active_observation,
)
from .bridge.submission import submission_freshness as _submission_freshness  # noqa: F401
from .bridge.transactions import (
    BridgeJournal,
    RegistrationBridgeTransactionJournal,
    parse_bridge_journal,
    reconcile_transaction_journal,
)
from .concurrency import run_owned_thread
from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH
from .protocol import canonical_json_bytes
from .signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES
from .simple_bootstrap_validator import (
    SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
    SimpleBootstrapJournal,
    _account_bytes,
    _runtime_spec_version,
    verify_simple_bootstrap_checkout,
)

# Retain every transition and its recovery protections. These are resource
# ceilings, not a retention policy; archival needs a separate verified design.
MAX_HISTORY_FILES = 4096
MAX_HISTORY_BYTES = 512 * 1024 * 1024
_FINALITY_HASHES = {
    "x86_64": "cd696ea86acd691112413a7909b6bf469f90042747c87b9350f01dacfe4ae8c3",
    "aarch64": "b263758fb273aed83868e986f4738ff14008996b200226e34c14633a863e5587",
}


async def _health_request(origin: str) -> bytes:
    _require(_bridge_public_origin(origin) == origin, "health_origin_invalid")
    endpoint = origin + "/healthz"
    async with (
        httpx.AsyncClient(timeout=5.0, follow_redirects=False, trust_env=False) as client,
        client.stream(
            "GET", endpoint, headers={"accept": "application/json", "accept-encoding": "identity"}
        ) as response,
    ):
        _require(
            response.status_code == 200 and httpx.URL(response.url) == httpx.URL(endpoint),
            "health_endpoint_unavailable",
        )
        # Certificate-chain and exact IP identity verification are httpx defaults.
        _require(
            response.headers.get("content-encoding", "identity").lower() == "identity",
            "health_compressed_body_rejected",
        )
        body = bytearray()
        async for chunk in response.aiter_raw(chunk_size=8192):
            _require(len(body) + len(chunk) <= 16_384, "health_body_limit")
            body.extend(chunk)
        return bytes(body)


async def probe_registration_bridge_health(
    observation: RegistrationBridgeObservation,
    *,
    clock: Callable[[], datetime],
    request: Callable[[str], Any] | None = None,
) -> list[RegistrationBridgeHealth]:
    """Probe the complete candidate batch; never pay a timeout-truncated prefix."""
    request = request or _health_request
    semaphore = asyncio.Semaphore(16)

    async def probe(participant):
        async with semaphore:
            try:
                body = await asyncio.wait_for(request(participant.origin), timeout=5.0)
                _require(type(body) is bytes and len(body) <= 16_384, "health_body_limit")
                available, digest = True, hashlib.sha256(body).hexdigest()
            except (httpx.HTTPError, asyncio.TimeoutError, RegistrationBridgeError, OSError):
                available, digest = False, None
            return RegistrationBridgeHealth(
                uid=participant.uid,
                hotkey=participant.hotkey,
                origin=participant.origin,
                checked_at_unix_ms=_datetime_ms(clock()),
                available=available,
                reason_code="http_200" if available else "endpoint_unavailable",
                body_sha256=digest,
            )

    candidates = [p for p in _registered_candidates(observation) if p.origin is not None]
    try:
        return list(
            await asyncio.wait_for(asyncio.gather(*(probe(p) for p in candidates)), timeout=90)
        )
    except asyncio.TimeoutError as error:
        raise RegistrationBridgeError("health_batch_incomplete") from error


async def _registration_bindings(pinned, participants):
    """Read the pinned roster in bounded batches, not 1,024 point requests."""
    direct = storage.SubtensorModule
    columns = (
        (direct.Keys, [[78, p.uid] for p in participants]),
        (direct.Uids, [[78, p.hotkey] for p in participants]),
        (direct.BlockAtRegistration, [[78, p.uid] for p in participants]),
        (direct.Owner, [[p.hotkey] for p in participants]),
    )
    values = []
    for item, params in columns:
        column = []
        for offset in range(0, len(params), 64):
            batch = params[offset : offset + 64]
            result = await pinned.query_batch(item, batch)
            _require(
                isinstance(result, list) and len(result) == len(batch),
                "registration_binding_batch_shape",
            )
            column.extend(result)
        values.append(column)
    return list(zip(*values, strict=True))


class BittensorRegistrationBridgeChain:
    """Owned finality identities with all mutable RPC reads pinned to that identity."""

    def __init__(
        self,
        *,
        client_factory=None,
        finality_reader=None,
        clock=None,
        signing_reader_factory=None,
        receipt_reader_factory=None,
    ):
        self.client_factory = client_factory or (lambda network: bt.Client(network))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._signing_reader_factory = signing_reader_factory or signing_reader
        self._receipt_reader_factory = receipt_reader_factory or receipt_reader
        self._receipt_reader = None
        if finality_reader is None:
            # Host adapters import our policy schemas; keep this runtime import lazy.
            from .validator_supervisor_adapters import FinneyFinalizedBlockReader

            architecture = platform.machine()
            _require(
                platform.system() == "Linux" and architecture in _FINALITY_HASHES,
                "native_finality_platform_unsupported",
            )
            staging_directory = Path("/run/umi-finality/stage")
            staging_directory.mkdir(mode=0o700, exist_ok=True)
            finality_reader = FinneyFinalizedBlockReader(
                SimpleNamespace(
                    finality_verifier_binary="/opt/umi/bin/umi-grandpa-finality-observer",
                    finality_verifier_sha256=_FINALITY_HASHES[architecture],
                    finality_chain_spec_path="/opt/umi/finney.json",
                    finality_staging_directory=str(staging_directory),
                ),
                timeout_seconds=120.0,
            )
        self.finality = finality_reader

    async def aclose(self):
        await self.finality.stop()

    async def verify_finalized_receipt_with_client(self, client, receipt, *, observation):
        _require(receipt.block_number <= observation.block_number, "receipt_not_yet_finalized")
        pinned = await client.at(receipt.block_number)
        _require(
            getattr(pinned, "block", None) == receipt.block_number,
            "receipt_snapshot_block_mismatch",
        )
        info = await pinned.block_info()
        _require(
            getattr(info, "hash", None) == receipt.block_hash, "retained_receipt_hash_mismatch"
        )
        # The block is at or below our owned finalized head on the same pinned
        # Finney client. This authenticates the saved receipt's chain position;
        # its effect is separately checked in the owned-head snapshot.
        _validate_finalized_block(
            SimpleNamespace(raw=getattr(info, "header", None)), info, receipt.block_number
        )

    async def observation_with_client(self, client, *, validator_hotkey: str):
        substrate = getattr(client, "_substrate", None)
        _require(await substrate.block_hash(0) == f"0x{FINNEY_GENESIS_HASH}", "chain_not_finney")
        owned = await self.finality.read_finalized_identity()
        return await self._observation_at(client, validator_hotkey=validator_hotkey, owned=owned)

    async def signing_observation_with_client(self, client, *, validator_hotkey: str):
        substrate = getattr(client, "_substrate", None)
        _require(await substrate.block_hash(0) == f"0x{FINNEY_GENESIS_HASH}", "chain_not_finney")
        reader = await run_owned_thread(
            partial(
                self._signing_reader_factory,
                client=client,
                finality=self.finality,
                clock=self.clock,
            )
        )
        signing = await reader.read(validator_hotkey)
        snapshot = signing.runtime.snapshot
        observation = await self._observation_at(
            client,
            validator_hotkey=validator_hotkey,
            owned=SimpleNamespace(number=snapshot.block_number, block_hash=snapshot.block_hash),
        )
        _require(
            observation.block_timestamp_ms == signing.timestamp_ms,
            "bridge_signing_timestamp_mismatch",
        )
        return observation, signing

    async def exact_receipt_with_client(self, client, journal):
        # The read-only RPC adapter owns its endpoint, not an SDK session. Keep
        # one reader across loop iterations so bounded timeouts retain progress.
        if self._receipt_reader is None:
            self._receipt_reader = await run_owned_thread(
                partial(self._receipt_reader_factory, client=client, finality=self.finality)
            )
        return await self._receipt_reader.find(journal)

    async def _observation_at(self, client, *, validator_hotkey, owned):
        substrate = getattr(client, "_substrate", None)
        pinned = await client.at(owned.number)
        _require(getattr(pinned, "block", None) == owned.number, "snapshot_block_mismatch")
        direct = storage.SubtensorModule
        fields = (
            ("mechanism_count", direct.MechanismCountCurrent, [78]),
            ("commit_reveal_enabled", direct.CommitRevealWeightsEnabled, [78]),
            ("commit_reveal_version", direct.CommitRevealWeightsVersion, None),
            ("reveal_period_epochs", direct.RevealPeriodEpochs, [78]),
            ("weights_version_key", direct.WeightsVersionKey, [78]),
            ("min_allowed_weights", direct.MinAllowedWeights, [78]),
            ("max_weights_limit", direct.MaxWeightsLimit, [78]),
            ("max_allowed_uids", direct.MaxAllowedUids, [78]),
            ("weights_set_rate_limit", direct.WeightsSetRateLimit, [78]),
            ("activity_cutoff_factor_milli", direct.ActivityCutoffFactorMilli, [78]),
            ("tempo", direct.Tempo, [78]),
        )
        (
            info,
            metagraph,
            permits,
            updates,
            owner_coldkey,
            owner_hotkey,
            upgrade,
            pending,
            older_pending,
            block_time,
            values,
        ) = await asyncio.gather(
            pinned.block_info(),
            pinned.subnets.metagraph(netuid=78, commitments=False),
            pinned.query(direct.ValidatorPermit, [78]),
            pinned.query(direct.LastUpdate, [78]),
            pinned.query(direct.SubnetOwner, [78]),
            pinned.query(direct.SubnetOwnerHotkey, [78]),
            pinned.query(storage.System.LastRuntimeUpgrade),
            pinned.read("timelocked_weight_commits", netuid=78, mechid=0),
            asyncio.gather(
                *(
                    pinned.query_map(item, [78])
                    for item in (
                        direct.WeightCommits,
                        direct.CRV3WeightCommits,
                        direct.CRV3WeightCommitsV2,
                    )
                )
            ),
            _block_time(substrate),
            asyncio.gather(
                *(
                    pinned.query(item, params) if params is not None else pinned.query(item)
                    for _, item, params in fields
                )
            ),
        )
        _require(getattr(info, "hash", None) == owned.block_hash, "owned_finality_hash_mismatch")
        block_hash, timestamp_ms = _validate_finalized_block(
            SimpleNamespace(raw=getattr(info, "header", None)), info, owned.number
        )
        base = _participants(
            metagraph, block_number=owned.number, permits=permits, last_updates=updates
        )
        _require([p.uid for p in base] == list(range(256)), "registered_uid_domain_changed")
        writer = [p for p in base if account_id32(p.hotkey) == account_id32(validator_hotkey)]
        _require(len(writer) == 1, "validator_not_registered")
        owner_address = bt.sp_core.Keypair(public_key=_account_bytes(owner_hotkey)).ss58_address
        cold_address = bt.sp_core.Keypair(public_key=_account_bytes(owner_coldkey)).ss58_address
        owner_keys, row, binding_values = await asyncio.gather(
            pinned.query(direct.OwnedHotkeys, [cold_address]),
            pinned.query(direct.Weights, [78, writer[0].uid]),
            _registration_bindings(pinned, base),
        )
        owner_keys = getattr(owner_keys, "value", owner_keys)
        _require(
            isinstance(owner_keys, (list, tuple)) and len(owner_keys) <= 4095,
            "owner_hotkey_set_invalid",
        )
        owners = {
            bt.sp_core.Keypair(public_key=_account_bytes(key)).ss58_address for key in owner_keys
        }
        owners.add(owner_address)
        participants = []
        for p, (key, uid, registered, coldkey) in zip(base, binding_values, strict=True):
            _require(
                _account_bytes(key) == account_id32(p.hotkey)
                and _uint(uid, "reverse_uid_invalid") == p.uid,
                "registered_hotkey_binding_changed",
            )
            origin = p.origin
            if origin is not None:
                try:
                    origin = _bridge_public_origin(origin)
                except (ValueError, RegistrationBridgeError):
                    origin = None
            participants.append(
                RegistrationBridgeParticipant(
                    uid=p.uid,
                    hotkey=p.hotkey,
                    coldkey=bt.sp_core.Keypair(public_key=_account_bytes(coldkey)).ss58_address,
                    validator_permit=p.validator_permit,
                    last_update=p.last_update,
                    registered_at_block=_uint(registered, "registration_block_invalid"),
                    origin=origin,
                )
            )
        raw_row = getattr(row, "value", row)
        _require(isinstance(raw_row, (list, tuple)) and len(raw_row) <= 256, "row_shape")
        parsed_row = [
            [_uint(pair[0], "row_uid", maximum=255), _uint(pair[1], "row_weight", maximum=65535)]
            for pair in raw_row
            if isinstance(pair, (list, tuple)) and len(pair) == 2
        ]
        _require(len(parsed_row) == len(raw_row), "row_shape")
        pending_count, _ = _pending_commit_summary(pending, validator_hotkey=validator_hotkey)
        for records in older_pending:
            _require(isinstance(records, list) and len(records) <= 4096, "pending_map_invalid")
            for record in records:
                _require(
                    isinstance(record, (tuple, list))
                    and len(record) == 2
                    and isinstance(record[1], (tuple, list))
                    and len(record[1]) <= 4096,
                    "pending_map_invalid",
                )
                pending_count += len(record[1])
        parameters = {
            name: (_bool(value, name) if name == "commit_reveal_enabled" else _uint(value, name))
            for (name, _, _), value in zip(fields, values, strict=True)
        }
        return RegistrationBridgeObservation(
            network="finney",
            genesis_hash=f"0x{FINNEY_GENESIS_HASH}",
            block_number=owned.number,
            block_hash=block_hash,
            block_timestamp_ms=timestamp_ms,
            runtime_spec_version=_runtime_spec_version(upgrade),
            block_time_seconds=block_time,
            total_pending_commit_count=pending_count,
            subnet_owner_hotkey=owner_address,
            owner_associated_hotkeys=sorted(owners, key=account_id32),
            participants=participants,
            validator_hotkey=writer[0].hotkey,
            validator_row=parsed_row,
            **parameters,
        )


def _read_bytes(path: Path, *, private: bool, optional: bool = False) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return None
        raise
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= MAX_DOCUMENT_BYTES,
            "state_file_unsafe",
        )
        if private:
            _require(
                before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
                "state_file_permissions",
            )
        payload = handle.read(MAX_DOCUMENT_BYTES + 1)
        after = os.fstat(handle.fileno())
        _require(
            (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and len(payload) == before.st_size,
            "state_file_changed",
        )
        return payload


def _write_new(path: Path, payload: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RegistrationBridgeState:
    """Same service.lock inode as the old worker, with separate durable journals."""

    def __init__(self, root: Path):
        self.root = root
        self.path = root / "registration-bridge-journal.json"
        self.descriptor = -1
        self._root_identity = None
        self._expected = None

    def __enter__(self):
        _require(self.root.is_absolute() and self.root.resolve() == self.root, "state_path_unsafe")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.root.lstat()
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "state_root_unsafe",
        )
        self._root_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
        )
        self.descriptor = os.open(
            self.root / "service.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
        )
        try:
            meta = os.fstat(self.descriptor)
            _require(
                stat.S_ISREG(meta.st_mode)
                and meta.st_uid == os.geteuid()
                and meta.st_nlink == 1
                and stat.S_IMODE(meta.st_mode) == 0o600,
                "service_lock_unsafe",
            )
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = -1
            raise
        self._expected = self._snapshot()
        return self

    def __exit__(self, *_args):
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def require_locked(self):
        _require(self.descriptor >= 0, "state_lock_not_held")
        root = self.root.lstat()
        _require(
            self.root.resolve() == self.root
            and (root.st_dev, root.st_ino, root.st_uid, root.st_gid, root.st_mode)
            == self._root_identity,
            "state_root_changed",
        )
        actual = (self.root / "service.lock").lstat()
        held = os.fstat(self.descriptor)
        _require(
            (actual.st_dev, actual.st_ino) == (held.st_dev, held.st_ino)
            and stat.S_ISREG(actual.st_mode)
            and actual.st_uid == os.geteuid()
            and actual.st_nlink == held.st_nlink == 1
            and stat.S_IMODE(actual.st_mode) == 0o600,
            "state_lock_replaced",
        )

    def _snapshot(self):
        self.require_locked()
        result = {}
        paths = [
            self.path,
            self.root / "journal.json",
            self.root / "registration-bridge-legacy-journal.json",
        ]
        history = self.root / "registration-bridge-history"
        if os.path.lexists(history):
            meta = history.lstat()
            _require(
                stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o700,
                "history_root_unsafe",
            )
            result[history.name] = (
                meta.st_dev,
                meta.st_ino,
                meta.st_uid,
                meta.st_gid,
                meta.st_mode,
            )
            with os.scandir(history) as entries:
                for count, entry in enumerate(entries, 1):
                    _require(count <= MAX_HISTORY_FILES, "history_capacity_reached")
                    paths.append(Path(entry.path))
        total = 0
        for path in paths:
            raw = _read_bytes(path, private=True, optional=True)
            if raw is None:
                result[str(path.relative_to(self.root))] = None
                continue
            total += len(raw)
            _require(total <= MAX_HISTORY_BYTES, "history_byte_capacity_reached")
            meta = path.lstat()
            result[str(path.relative_to(self.root))] = (
                meta.st_dev,
                meta.st_ino,
                meta.st_uid,
                meta.st_gid,
                meta.st_mode,
                meta.st_nlink,
                meta.st_size,
                meta.st_mtime_ns,
                meta.st_ctime_ns,
                hashlib.sha256(raw).hexdigest(),
            )
        return result

    def require_unchanged(self):
        _require(
            self._expected is not None and self._snapshot() == self._expected,
            "retained_state_changed",
        )

    def _audit_history(self, current, legacy_raw):
        archive = _read_bytes(
            self.root / "registration-bridge-legacy-journal.json", private=True, optional=True
        )
        _require(archive == legacy_raw, "legacy_archive_changed")
        history = self.root / "registration-bridge-history"
        groups = {}
        if history.exists():
            with os.scandir(history) as entries:
                for count, entry in enumerate(entries, 1):
                    _require(count <= MAX_HISTORY_FILES, "history_capacity_reached")
                    raw = _read_bytes(Path(entry.path), private=True)
                    retained = parse_bridge_journal(raw)
                    _require(
                        canonical_json_bytes(retained) == raw
                        and retained.attempt is not None
                        and retained.validator_hotkey == current.validator_hotkey
                        and retained.legacy_journal_sha256 == current.legacy_journal_sha256,
                        "history_binding_changed",
                    )
                    _require(
                        entry.name == f"{retained.attempt.attempt_id}-{retained.phase}.json",
                        "history_filename_changed",
                    )
                    groups.setdefault(retained.attempt.attempt_id, {})[retained.phase] = retained
        return reconcile_archived_transition(current, groups)

    def load(self):
        self.require_unchanged()
        raw = _read_bytes(self.path, private=True, optional=True)
        if raw is None:
            return None
        return parse_bridge_journal(raw)

    def legacy(self):
        self.require_unchanged()
        raw = _read_bytes(self.root / "journal.json", private=True, optional=True)
        return raw, None if raw is None else hashlib.sha256(raw).hexdigest()

    def store(self, journal: BridgeJournal, *, archive: bool = False):
        self.require_unchanged()
        raw = canonical_json_bytes(journal)
        journal = parse_bridge_journal(raw)
        previous_raw = _read_bytes(self.path, private=True, optional=True)
        previous = None if previous_raw is None else parse_bridge_journal(previous_raw)
        validate_next_journal(
            previous,
            journal,
            archive=archive,
        )
        if type(journal) is RegistrationBridgeTransactionJournal and (
            previous.attempt is None or previous.attempt.attempt_id != journal.attempt.attempt_id
        ):
            self._require_transaction_headroom(raw)
        if archive and journal.attempt is not None:
            history = self.root / "registration-bridge-history"
            history.mkdir(mode=0o700, exist_ok=True)
            meta = history.lstat()
            _require(
                stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o700,
                "history_root_unsafe",
            )
            total = 0
            with os.scandir(history) as entries:
                for count, entry in enumerate(entries, start=1):
                    _require(count < MAX_HISTORY_FILES, "history_capacity_reached")
                    item = entry.stat(follow_symlinks=False)
                    _require(
                        stat.S_ISREG(item.st_mode)
                        and item.st_uid == os.geteuid()
                        and item.st_nlink == 1,
                        "history_file_unsafe",
                    )
                    total += item.st_size
                    _require(total + len(raw) <= MAX_HISTORY_BYTES, "history_byte_capacity_reached")
            path = history / f"{journal.attempt.attempt_id}-{journal.phase}.json"
            existing = _read_bytes(path, private=True, optional=True)
            if existing is None:
                _write_new(path, raw)
            else:
                _require(existing == raw, "history_record_changed")
            # A retry may observe a file whose preceding directory sync failed.
            # Matching bytes alone do not establish durable publication.
            _fsync(history)
        temporary = self.root / f".registration-bridge-{os.getpid()}-{os.urandom(8).hex()}.tmp"
        _write_new(temporary, raw)
        # All runtime state writers share service.lock; existing legacy bytes are never touched.
        os.replace(temporary, self.path)
        _fsync(self.root)
        self._expected = self._snapshot()

    def _require_transaction_headroom(self, preparing: bytes) -> None:
        """Reserve configured capacity before any new-format signing intent.

        The service lock and unchanged-state check serialize all writers. Seven
        archive slots cover every phase (including both exclusive resolutions).
        The byte allowance includes maximum encoded bytes and bounded receipt,
        expiry and counter fields. Disk space can still be consumed externally;
        I/O failures retain the existing journal and never authorize a retry.
        """
        maximum_record = len(preparing) + 2 * MAX_SIGNED_EXTRINSIC_BYTES + 4096
        _require(maximum_record <= MAX_DOCUMENT_BYTES, "transaction_document_headroom_insufficient")
        history_count = sum(
            name.startswith("registration-bridge-history/") for name in self._expected
        )
        _require(
            history_count + 7 <= MAX_HISTORY_FILES, "transaction_history_file_headroom_insufficient"
        )
        used = sum(
            item[6]
            for name, item in self._expected.items()
            if item is not None and name != "registration-bridge-history"
        )
        _require(
            used + 8 * maximum_record <= MAX_HISTORY_BYTES,
            "transaction_history_byte_headroom_insufficient",
        )
        available = os.statvfs(self.root)
        _require(
            available.f_bavail * available.f_frsize >= 9 * maximum_record,
            "transaction_disk_headroom_insufficient",
        )

    def initialize(self, observation: RegistrationBridgeObservation, *, now: datetime):
        raw, digest = self.legacy()
        existing = self.load()
        if existing is not None:
            _require(existing.legacy_journal_sha256 == digest, "legacy_journal_changed")
            recovered = self._audit_history(existing, raw)
            if recovered != existing:
                self.store(recovered, archive=True)
            return recovered
        # A missing current journal never resets retained attempts or a prior
        # completed handoff, including a crash between archive and journal write.
        _require(
            not (self.root / "registration-bridge-history").exists()
            and not (self.root / "registration-bridge-legacy-journal.json").exists(),
            "bridge_journal_missing_with_retained_state",
        )
        if raw is not None:
            _canonical_object(raw)
            legacy = SimpleBootstrapJournal.model_validate_json(raw)
            _require(
                canonical_json_bytes(legacy) == raw
                and legacy.validator_hotkey == observation.validator_hotkey
                and legacy.manifest_sha256 == SIMPLE_BOOTSTRAP_MANIFEST_SHA256,
                "legacy_journal_binding_changed",
            )
            _require(
                legacy.phase == "applied" and legacy.weight_call is not None,
                "legacy_attempt_not_proven_terminal",
            )
            writer = next(
                p for p in observation.participants if p.hotkey == observation.validator_hotkey
            )
            old_row = [[uid, 65535 if uid in {6, 247} else 0] for uid in range(256)]
            _require(
                observation.validator_row == old_row
                and writer.last_update > legacy.prior_last_update
                and writer.last_update >= legacy.preflight_block
                and observation.block_number
                >= (legacy.observation_block or legacy.preflight_block),
                "legacy_terminal_effect_not_visible",
            )
            if legacy.weight_call is not None:
                _require(
                    writer.last_update == legacy.weight_call.block_number,
                    "legacy_receipt_lastupdate_changed",
                )
            archive = self.root / "registration-bridge-legacy-journal.json"
            prior = _read_bytes(archive, private=True, optional=True)
            if prior is None:
                _write_new(archive, raw)
                _fsync(self.root)
                self._expected = self._snapshot()
            else:
                _require(prior == raw, "legacy_archive_changed")
        else:
            writer = next(
                p for p in observation.participants if p.hotkey == observation.validator_hotkey
            )
            _require(
                not observation.validator_row and writer.last_update <= writer.registered_at_block,
                "legacy_journal_missing_for_existing_writer",
            )
        journal = RegistrationBridgeJournal(
            schema=REGISTRATION_BRIDGE_JOURNAL_SCHEMA,
            validator_hotkey=observation.validator_hotkey,
            legacy_journal_sha256=digest,
            phase="idle",
            attempt=None,
            weight_call=None,
            last_observed_block=observation.block_number,
            last_observed_block_hash=observation.block_hash,
            updated_at_unix_ms=_datetime_ms(now),
        )
        self.store(journal)
        return journal


async def run_registration_bridge_iteration(
    policy,
    *,
    wallet,
    chain,
    state,
    expected_revision,
    directive_valid_from,
    directive_valid_through,
    request=None,
):
    state.require_unchanged()
    _validate_directive_interval(policy, directive_valid_from, directive_valid_through)
    signer = bt.resolve_signer(wallet, role="hotkey")
    async with chain.client_factory("finney") as client:
        before = await chain.observation_with_client(client, validator_hotkey=signer.ss58_address)
        state.require_unchanged()
        _require(
            directive_valid_from <= before.block_number <= directive_valid_through,
            "supervisor_directive_inactive",
        )
        validate_registration_bridge_chain(
            policy, before, expected_revision=expected_revision, now=chain.clock()
        )
        # History verification is bounded but disk-heavy; initialization may
        # also write the first journal. Keep it off the event loop and drain
        # cancellation before the caller can release service.lock.
        journal = await run_owned_thread(partial(state.initialize, before, now=chain.clock()))
        if type(journal) is RegistrationBridgeTransactionJournal and journal.phase in {
            "preparing",
            "signed",
            "submitting",
            "outcome_unknown",
            "receipt_returned",
        }:
            journal, refreshed = await recover_transaction(
                journal, state=state, chain=chain, client=client
            )
            _require(refreshed.block_number >= before.block_number, "journal_finality_rollback")
            _require(
                refreshed.block_number != before.block_number
                or refreshed.block_hash == before.block_hash,
                "journal_finality_equivocation",
            )
            before = refreshed
            validate_active_observation(
                policy,
                before,
                chain,
                expected_revision,
                directive_valid_from,
                directive_valid_through,
            )
        elif journal.phase in {"submitting", "outcome_unknown"}:
            # Recover only a finalized, exact, successful call from this attempt.
            # The helper never signs or broadcasts. If proof is absent, retain the
            # original durable hold below.
            from .registration_bridge_recover import recover_with_client

            with contextlib.suppress(RegistrationBridgeError):
                journal, _ = await recover_with_client(state, journal, before, client, chain)
        if type(journal) is RegistrationBridgeJournal and journal.phase == "receipt_returned":
            # A full retained-history audit can outlive the snapshot's freshness
            # limit. Reobserve after it; never relax the age or receipt checks.
            refreshed = await chain.observation_with_client(
                client, validator_hotkey=signer.ss58_address
            )
            state.require_unchanged()
            _require(refreshed.block_number >= before.block_number, "journal_finality_rollback")
            _require(
                refreshed.block_number != before.block_number
                or refreshed.block_hash == before.block_hash,
                "journal_finality_equivocation",
            )
            before = refreshed
            _require(
                directive_valid_from <= before.block_number <= directive_valid_through,
                "supervisor_directive_inactive",
            )
            await chain.verify_finalized_receipt_with_client(
                client, journal.weight_call, observation=before
            )
            state.require_unchanged()
            validate_registration_bridge_chain(
                policy, before, expected_revision=expected_revision, now=chain.clock()
            )
        reconciled = reconcile_transaction_journal(journal, before, now=chain.clock())
        await persist(state, reconciled, archive=reconciled.phase != journal.phase)
        journal = reconciled
        if before.block_number + policy.body.submission_headroom_blocks >= min(
            policy.body.submission_limit, directive_valid_through + 1
        ):
            return {
                "status": "retiring",
                "reason_code": "submission_cutoff_reached",
                "finalized_block": before.block_number,
            }
        health = await probe_registration_bridge_health(before, clock=chain.clock, request=request)
        state.require_unchanged()
        fresh = await chain.observation_with_client(client, validator_hotkey=signer.ss58_address)
        state.require_unchanged()
        validate_active_observation(
            policy, fresh, chain, expected_revision, directive_valid_from, directive_valid_through
        )
        decision = validate_registration_bridge_observation(
            policy,
            fresh,
            health,
            expected_revision=expected_revision,
            now=chain.clock(),
            health_observation=before,
        )
        journal = reconcile_transaction_journal(journal, fresh, now=chain.clock())
        await persist(state, journal)
        if fresh.block_number + policy.body.submission_headroom_blocks >= min(
            policy.body.submission_limit, directive_valid_through + 1
        ):
            return {
                "status": "retiring",
                "reason_code": "submission_cutoff_reached",
                "finalized_block": fresh.block_number,
            }
        if decision.action != "submit":
            return {
                "status": decision.action,
                "reason_code": decision.reason_code,
                "eligible_count": decision.eligible_count,
                "eligible_coldkey_count": decision.eligible_coldkey_count,
                "finalized_block": fresh.block_number,
            }
        # Idle polls do not execute runtime Wasm or collect signing proofs.
        # A due submission selects a new proven head and rechecks the roster,
        # health, policy and rate limit there before any durable signing intent.
        fresh, signing = await chain.signing_observation_with_client(
            client, validator_hotkey=signer.ss58_address
        )
        state.require_unchanged()
        validate_active_observation(
            policy, fresh, chain, expected_revision, directive_valid_from, directive_valid_through
        )
        decision = validate_registration_bridge_observation(
            policy,
            fresh,
            health,
            expected_revision=expected_revision,
            now=chain.clock(),
            health_observation=before,
        )
        journal = reconcile_transaction_journal(journal, fresh, now=chain.clock())
        await persist(state, journal)
        if fresh.block_number + policy.body.submission_headroom_blocks >= min(
            policy.body.submission_limit, directive_valid_through + 1
        ):
            return {
                "status": "retiring",
                "reason_code": "submission_cutoff_reached",
                "finalized_block": fresh.block_number,
            }
        if decision.action != "submit":
            return {
                "status": decision.action,
                "reason_code": decision.reason_code,
                "eligible_count": decision.eligible_count,
                "eligible_coldkey_count": decision.eligible_coldkey_count,
                "finalized_block": fresh.block_number,
            }
        applied, after = await submit_transaction(
            policy,
            observation=fresh,
            health=health,
            health_observation=before,
            decision=decision,
            signing_state=signing,
            previous=journal,
            signer=signer,
            state=state,
            chain=chain,
            client=client,
            expected_revision=expected_revision,
            directive_valid_from=directive_valid_from,
            directive_valid_through=directive_valid_through,
        )
        return {
            "status": "submitted",
            "reason_code": "exact_bridge_row_finalized",
            "eligible_count": decision.eligible_count,
            "eligible_coldkey_count": decision.eligible_coldkey_count,
            "finalized_block": after.block_number,
            "weight_block": applied.weight_call.block_number,
        }


def _validate_directive_interval(policy, valid_from, valid_through):
    _require(
        type(valid_from) is int
        and type(valid_through) is int
        and policy.body.valid_from_block <= valid_from <= valid_through < policy.body.sunset_limit,
        "supervisor_interval_mismatch",
    )


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "check"):
        command = commands.add_parser(name)
        command.add_argument("--policy", type=Path)
        command.add_argument("--state-dir", type=Path, default=Path("/var/lib/umi-worker"))
        command.add_argument("--poll-seconds", type=int, default=30)
        command.add_argument("--once", action="store_true")
    return parser


async def _run_cli(args):
    path = args.policy or Path(os.environ.get("UMI_BRIDGE_POLICY_PATH", ""))
    _require(path.is_absolute(), "policy_path_missing")
    policy = parse_registration_bridge_policy(_read_bytes(path, private=False))
    revision = verify_simple_bootstrap_checkout()
    _require(policy.body.umi_git_revision == revision, "policy_revision_mismatch")
    _require(
        os.environ.get("UMI_SUPERVISOR_POLICY_SHA256") == registration_bridge_policy_sha256(policy),
        "supervisor_policy_binding_mismatch",
    )
    valid_from = int(os.environ.get("UMI_SUPERVISOR_VALID_FROM_BLOCK", "0"))
    valid_through = int(os.environ.get("UMI_SUPERVISOR_VALID_THROUGH_BLOCK", "0"))
    _validate_directive_interval(policy, valid_from, valid_through)
    expected_hotkey = os.environ.get("UMI_EXPECTED_VALIDATOR_HOTKEY", "")
    account_id32(expected_hotkey)
    _require(15 <= args.poll_seconds <= 300, "poll_interval_invalid")
    chain = BittensorRegistrationBridgeChain()
    try:
        if args.command == "check":
            async with chain.client_factory("finney") as client:
                before = await chain.observation_with_client(
                    client, validator_hotkey=expected_hotkey
                )
                validate_registration_bridge_chain(
                    policy, before, expected_revision=revision, now=chain.clock()
                )
                health = await probe_registration_bridge_health(before, clock=chain.clock)
                fresh = await chain.observation_with_client(
                    client, validator_hotkey=expected_hotkey
                )
                decision = validate_registration_bridge_observation(
                    policy,
                    fresh,
                    health,
                    expected_revision=revision,
                    now=chain.clock(),
                    health_observation=before,
                )
                print(
                    canonical_json_bytes(
                        {
                            "status": "checked",
                            "action": decision.action,
                            "eligible_count": decision.eligible_count,
                            "eligible_coldkey_count": decision.eligible_coldkey_count,
                            "finalized_block": fresh.block_number,
                        }
                    ).decode()
                )
                return 0
        names = {
            name: os.environ.get(name, "")
            for name in ("UMI_WALLET_PATH", "UMI_WALLET_NAME", "UMI_WALLET_HOTKEY")
        }
        _require(all(names.values()), "hotkey_wallet_configuration_missing")
        wallet = bt.Wallet(
            path=names["UMI_WALLET_PATH"],
            name=names["UMI_WALLET_NAME"],
            hotkey=names["UMI_WALLET_HOTKEY"],
        )
        _require(
            bt.resolve_signer(wallet, role="hotkey").ss58_address == expected_hotkey,
            "validator_hotkey_mismatch",
        )
        with RegistrationBridgeState(args.state_dir.resolve()) as state:
            while True:
                try:
                    result = await run_registration_bridge_iteration(
                        policy,
                        wallet=wallet,
                        chain=chain,
                        state=state,
                        expected_revision=revision,
                        directive_valid_from=valid_from,
                        directive_valid_through=valid_through,
                    )
                    print(canonical_json_bytes(result).decode(), flush=True)
                except Exception as error:
                    print(
                        canonical_json_bytes(
                            {
                                "status": "held",
                                "reason_code": getattr(
                                    error, "reason_code", "bridge_iteration_failed"
                                ),
                            }
                        ).decode(),
                        flush=True,
                    )
                    if args.once:
                        return 2
                else:
                    if args.once or result["status"] == "retiring":
                        return 0
                await asyncio.sleep(args.poll_seconds)
    finally:
        await chain.aclose()


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        return asyncio.run(_run_cli(args))
    except Exception as error:
        print(
            canonical_json_bytes(
                {
                    "status": "held",
                    "reason_code": getattr(error, "reason_code", "bridge_startup_failed"),
                }
            ).decode()
        )
        return 2


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
