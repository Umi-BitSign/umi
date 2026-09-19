"""Separately authorized successor rows with durable, single-use chain effects.

The settlement package remains a no-weight replay artifact. A host-authenticated
activation and a stopped historical recovery capability are additionally needed.
Only an exact raw mechanism-0 call can be signed; unknown submissions are never
automatically resent, including after authorization expiry.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import importlib.metadata
import os
import sqlite3
import stat
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Literal

import bittensor as bt
from pydantic import Field, model_serializer, model_validator
from typing_extensions import Self

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_package import (
    _TREE_NAMES,
    CompetitionPackageLimits,
    CompetitionReleaseIdentity,
    VerifiedCompetitionPackage,
    _check_exact_tree,
    _file_identity,
    _opened_sealed_directory,
    competition_release_identity_digest,
    load_competition_package,
)
from .competition_worker import (
    CompetitionReplayWorker,
    _open_directory_without_links,
    _open_private_regular_file,
    _prepare_private_directory,
    _verify_sqlite_family,
)
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .open_competition import Hex32, Hotkey, Registration, Signature, StrictProtocolModel, digest
from .policy import LiveChainObservationPin
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext
from .signed_extrinsic import encode_mortal_call, exact_signed_extrinsic

Block = Annotated[int, Field(ge=0, le=2**53 - 1)]
_AUTH_DOMAIN = b"umi-competition-weight-authorization-v1\0"
_JOURNAL_LIMIT = 256 * 1024


def _recovery_package_snapshot(path: Path) -> tuple:
    """Integrity only; full byte/signature verification must bracket this check."""
    with _opened_sealed_directory(path) as root:
        before = _file_identity(os.fstat(root))
        _check_exact_tree(root)
        result = []
        for name in sorted(_TREE_NAMES):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o400
                ):
                    raise ValueError("stopped recovery package is not sealed")
                result.append((name, _file_identity(info)))
            finally:
                os.close(descriptor)
        if _file_identity(os.fstat(root)) != before:
            raise ValueError("stopped recovery package changed while inspecting it")
        return before, tuple(result)


def _recovery_journal_snapshot(path: Path, *, allow_absent_root: bool = False) -> tuple:
    """Bounded metadata check for an already-audited SQLite family, not authority."""
    try:
        root = _open_directory_without_links(path.parent)
    except FileNotFoundError:
        if allow_absent_root:
            return ("absent",)
        raise
    try:
        info = os.fstat(root)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("stopped recovery journal parent is not private")
        before = _file_identity(info)
        result = []
        for suffix in ("", "-journal", "-wal", "-shm"):
            name = path.name + suffix
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
            except FileNotFoundError:
                if not suffix:
                    raise ValueError("stopped recovery journal disappeared") from None
                result.append((suffix, None))
                continue
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise ValueError("stopped recovery journal is not private")
                result.append((suffix, _file_identity(info)))
            finally:
                os.close(descriptor)
        if _file_identity(os.fstat(root)) != before:
            raise ValueError("stopped recovery journal changed while inspecting it")
        return before, tuple(result)
    finally:
        os.close(root)


class CompetitionWeightAuthorizationBody(StrictProtocolModel):
    schema_: Literal["umi-competition-weight-authorization/1"] = Field(alias="schema")
    authorization_id: Hex32
    validator_scope: Literal["any_permitted_sn78"]
    policy_sha256: Hex32
    package_sha256: Hex32
    settlement_sha256: Hex32
    projection_sha256: Hex32
    release_identity_sha256: Hex32
    predecessor_directive_sha256: Hex32
    required_recovery_profile: Literal["stopped_bootstrap_recovery/1"]
    chain_pin: LiveChainObservationPin
    required_finality_verifier_sha256_by_target: Annotated[
        dict[str, Hex32], Field(min_length=1, max_length=8)
    ]
    required_storage_proof_verifier_sha256_by_target: Annotated[
        dict[str, Hex32], Field(min_length=1, max_length=8)
    ]
    required_runtime_metadata_executor_sha256_by_target: (
        Annotated[dict[str, Hex32], Field(min_length=1, max_length=8)] | None
    ) = None
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    signed_at_block: Block
    valid_from_block: Block
    valid_through_block: Block
    weights_version_key: Annotated[int, Field(ge=1, le=2**64 - 1)]
    required_min_allowed_weights: Annotated[int, Field(ge=1, le=256)]
    required_max_allowed_uids: Annotated[int, Field(ge=1, le=256)]
    required_max_weights_limit: Annotated[int, Field(ge=1, le=65535)]
    required_weights_rate_limit: Annotated[int, Field(ge=0, le=2**53 - 1)]
    required_mechanism_count: Literal[1]
    required_commit_reveal_enabled: Literal[False]
    mortality_period: Annotated[int, Field(ge=4, le=4096)]
    late_conflict_action: Literal["hold_no_automatic_correction"]

    @model_serializer(mode="wrap")
    def preserve_legacy_authorization(self, handler):
        value = handler(self)
        if self.required_runtime_metadata_executor_sha256_by_target is None:
            value.pop("required_runtime_metadata_executor_sha256_by_target", None)
        return value

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        pins = self.required_runtime_metadata_executor_sha256_by_target
        if pins is not None and (
            set(pins) != set(self.required_finality_verifier_sha256_by_target)
            or set(pins) != set(self.required_storage_proof_verifier_sha256_by_target)
        ):
            raise ValueError("runtime execution must cover every authorized verifier target")
        if not self.signed_at_block <= self.valid_from_block < self.valid_through_block:
            raise ValueError("invalid successor authorization interval")
        if self.mortality_period & (self.mortality_period - 1):
            raise ValueError("mortality period must be an exact power of two")
        if self.mortality_period > self.valid_through_block - self.valid_from_block:
            raise ValueError("authorization cannot contain a full mortal submission era")
        if self.required_min_allowed_weights > self.required_max_allowed_uids:
            raise ValueError("minimum weights exceeds authorized UID domain")
        return self


class SignedCompetitionWeightAuthorization(StrictProtocolModel):
    schema_: Literal["umi-signed-competition-weight-authorization/1"] = Field(alias="schema")
    authorization: CompetitionWeightAuthorizationBody
    signature: Signature


def validate_runtime_execution_authorization(chain_config, authorization) -> None:
    """A new signed executor pin is required to opt out of exact-runtime mode."""
    pins = authorization.required_runtime_metadata_executor_sha256_by_target
    if pins is None:
        if chain_config.runtime_metadata_binary is not None:
            raise ValueError("runtime execution is absent from signed authorization")
        return
    target = chain_config.target_triple
    if (
        target not in pins
        or chain_config.runtime_metadata_binary is None
        or chain_config.runtime_metadata_binary_sha256 != pins[target]
        or chain_config.storage_codec_metadata_path is not None
    ):
        raise ValueError("runtime execution differs from signed authorization")


def _signing_runtime_identity(runtime) -> tuple:
    """Compare signing semantics across blocks, excluding changing proof roots."""
    execution = (
        (runtime.executor_sha256, hashlib.sha256(runtime.code_evidence.value).hexdigest())
        if isinstance(runtime, ExecutedRuntimeContext)
        else None
    )
    return runtime.storage_codec_mode, runtime.pin, runtime.runtime_version_bytes, execution


def _validate_signing_runtime(runtime, authorization) -> None:
    pins = authorization.required_runtime_metadata_executor_sha256_by_target
    if pins is None:
        if runtime.storage_codec_mode != "exact_runtime":
            raise ValueError("a storage-only codec cannot authorize transaction encoding")
    elif (
        type(runtime) is not ExecutedRuntimeContext or runtime.executor_sha256 not in pins.values()
    ):
        raise ValueError("signed runtime execution is missing or has a different executor")


def competition_weight_authorization_digest(body: CompetitionWeightAuthorizationBody) -> str:
    body = CompetitionWeightAuthorizationBody.model_validate_json(canonical_json_bytes(body))
    return hashlib.sha256(_AUTH_DOMAIN + canonical_json_bytes(body)).hexdigest()


def signed_competition_weight_authorization_digest(
    signed: SignedCompetitionWeightAuthorization,
) -> str:
    signed = SignedCompetitionWeightAuthorization.model_validate_json(canonical_json_bytes(signed))
    return hashlib.sha256(canonical_json_bytes(signed)).hexdigest()


def sign_competition_weight_authorization(body, wallet) -> SignedCompetitionWeightAuthorization:
    """Offline hotkey signing only; callers supply their explicitly selected signer."""
    body = CompetitionWeightAuthorizationBody.model_validate_json(canonical_json_bytes(body))
    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme, signature = sign_response_digest(wallet, competition_weight_authorization_digest(body))
    return SignedCompetitionWeightAuthorization(
        schema="umi-signed-competition-weight-authorization/1",
        authorization=body,
        signature=Signature(hotkey=signer.ss58_address, scheme=scheme, signature=signature),
    )


def verify_competition_weight_authorization(
    signed: SignedCompetitionWeightAuthorization,
    *,
    trusted_authority_hotkeys: tuple[str, ...],
    package: VerifiedCompetitionPackage,
) -> CompetitionWeightAuthorizationBody:
    signed = SignedCompetitionWeightAuthorization.model_validate_json(canonical_json_bytes(signed))
    body, signature = signed.authorization, signed.signature
    if account_id32(signature.hotkey) not in {
        account_id32(key) for key in trusted_authority_hotkeys
    }:
        raise ValueError("weight authorization signer is not trusted by the installed host")
    if not verify_response_signature(
        competition_weight_authorization_digest(body),
        hotkey_ss58=signature.hotkey,
        scheme=signature.scheme,
        signature=signature.signature,
    ):
        raise ValueError("invalid successor weight authorization signature")
    manifest, policy = package.manifest, package.policy
    for actual, expected in (
        (body.policy_sha256, manifest.policy_sha256),
        (body.package_sha256, package.package_sha256),
        (body.settlement_sha256, manifest.settlement_sha256),
        (body.projection_sha256, manifest.projection_sha256),
        (body.release_identity_sha256, manifest.release_identity_sha256),
    ):
        if actual != expected:
            raise ValueError("successor authorization binds different replay inputs")
    if (
        not policy.valid_from_block
        <= body.valid_from_block
        < body.valid_through_block
        <= policy.valid_through_block
    ):
        raise ValueError("successor authorization exceeds policy validity")
    if not (
        package.retained_settlement.observed_block <= body.signed_at_block
        and body.valid_through_block
        <= package.settlement_certificate.publication.round.valid_through_block
    ):
        raise ValueError("successor authorization exceeds settlement round validity")
    if (policy.endpoint_reward_bps, policy.model_reward_bps) != (7000, 3000):
        raise ValueError("joint launch requires the approved 70/30 reward policy")
    if package.retained_settlement.promotion_head.contributor_hotkey is None:
        destination = policy.unallocated_model_burn
        if (
            destination is None
            or package.retained_settlement.registration_snapshot.burn_destination != destination
        ):
            raise ValueError(
                "joint launch requires a qualifying contributor or verified model burn"
            )
    return body


class CompetitionWeightOutcome(StrictProtocolModel):
    schema_: Literal["umi-competition-weight-outcome/1"] = Field(alias="schema")
    authorization_id: Hex32
    validator_hotkey: Hotkey
    status: Literal[
        "applied", "recovered_effect", "expired_unconsumed_nonce", "unknown", "held_conflict"
    ]
    finalized_block: Block
    finalized_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    exact_row_currently_applied: bool
    submitted_by_this_attempt: bool
    extrinsic_sha256: Hex32 | None
    chain_evidence_sha256: Hex32
    automatic_retry_permitted: Literal[False] = False


class _WeightAttempt(StrictProtocolModel):
    schema_: Literal["umi-competition-weight-attempt/1"] = Field(alias="schema")
    authorization_id: Hex32
    authorization_sha256: Hex32
    validator_hotkey: Hotkey
    recovery_checkpoint_sha256: Hex32
    chain_config_sha256: Hex32
    phase: Literal[
        "intent", "signed", "applied", "recovered_effect", "expired_unconsumed_nonce", "unknown"
    ]
    preflight_block: Block
    preflight_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    prior_last_update: Block
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    era_death: Block
    chain_evidence_sha256: Hex32
    publication_journal_status_sha256: Hex32
    signed_extrinsic: (
        Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{2})+$", max_length=131074)] | None
    )

    @model_validator(mode="after")
    def frozen_effect(self) -> Self:
        if not self.prior_last_update <= self.preflight_block < self.era_death:
            raise ValueError("invalid retained successor effect interval")
        if self.phase == "intent" and self.signed_extrinsic is not None:
            raise ValueError("unsigned intent contains a signed extrinsic")
        if (
            self.phase in {"signed", "applied", "recovered_effect"}
            and self.signed_extrinsic is None
        ):
            raise ValueError("successor effect lacks retained signed bytes")
        return self


def validate_weight_preflight(
    package, authorization, observation, chain_config, *, submission: bool
):
    validate_owned_weight_observation(observation)
    policy, row = package.policy, package.retained_settlement.projection
    if observation.chain_config_sha256 != digest(
        chain_config
    ) or chain_config.policy_sha256 != digest(policy):
        raise ValueError("weight observation belongs to another installed chain configuration")
    if chain_config.chain_pin != authorization.chain_pin:
        raise ValueError("signed successor runtime pin differs from owned provider")
    validate_runtime_execution_authorization(chain_config, authorization)
    _validate_signing_runtime(observation.runtime, authorization)
    target = chain_config.target_triple
    if (
        authorization.required_finality_verifier_sha256_by_target.get(target)
        != chain_config.finality_pin.release_sha256_by_target.get(target)
        or authorization.required_storage_proof_verifier_sha256_by_target.get(target)
        != chain_config.proof_binary_sha256
    ):
        raise ValueError("successor finality or proof verifier pin mismatch")
    if not observation.validator_permit:
        raise ValueError("successor validator has no finalized permit")
    if observation.block < package.retained_settlement.observed_block:
        raise ValueError("successor preflight predates the settlement")
    registrations = {item.uid: account_id32(item.hotkey) for item in observation.registrations}
    for item in row.allocations:
        if registrations.get(item.uid) != account_id32(item.hotkey):
            raise ValueError("settlement recipient registration changed")
    if package.policy.unallocated_model_burn is not None and (
        observation.burn_destination != package.policy.unallocated_model_burn
    ):
        raise ValueError("model burn destination changed before weight submission")
    expected_tuple = (
        authorization.required_mechanism_count,
        authorization.required_commit_reveal_enabled,
        authorization.weights_version_key,
        authorization.required_min_allowed_weights,
        authorization.required_max_allowed_uids,
        authorization.required_max_weights_limit,
        authorization.required_weights_rate_limit,
    )
    actual_tuple = (
        observation.mechanism_count,
        observation.commit_reveal_enabled,
        observation.weights_version_key,
        observation.min_allowed_weights,
        observation.max_allowed_uids,
        observation.max_weights_limit,
        observation.weights_rate_limit,
    )
    if actual_tuple != expected_tuple:
        raise ValueError("successor chain hyperparameter tuple changed")
    if (
        tuple(row.uids) != tuple(range(policy.maximum_uids))
        or len(row.weights) != policy.maximum_uids
    ):
        raise ValueError("successor row does not preserve the exact complete UID domain")
    if (
        policy.maximum_uids != observation.max_allowed_uids
        or len(row.weights) < observation.min_allowed_weights
        or policy.maximum_uids > observation.registered_uid_count
    ):
        raise ValueError("successor row does not fit finalized chain bounds")
    if (
        not row.weights
        or max(row.weights) * 65535 > sum(row.weights) * observation.max_weights_limit
    ):
        raise ValueError("successor maximum normalized weight exceeds finalized limit")
    if submission and (
        not authorization.valid_from_block <= observation.block
        or observation.block + authorization.mortality_period > authorization.valid_through_block
    ):
        raise ValueError("successor authorization is inactive or lacks mortal headroom")
    if (
        submission
        and observation.validator_last_update + observation.weights_rate_limit > observation.block
    ):
        raise ValueError("successor validator weight rate limit has not elapsed")


def build_competition_weight_call(
    package: VerifiedCompetitionPackage, body: CompetitionWeightAuthorizationBody
):
    row = package.retained_settlement.projection
    call = bt.calls.SubtensorModule.set_mechanism_weights(
        netuid=78,
        mecid=0,
        dests=list(row.uids),
        weights=list(row.weights),
        version_key=body.weights_version_key,
    )
    expected = {
        "netuid": 78,
        "mecid": 0,
        "dests": list(row.uids),
        "weights": list(row.weights),
        "version_key": body.weights_version_key,
    }
    if (
        call.module != "SubtensorModule"
        or call.function != "set_mechanism_weights"
        or call.params != expected
    ):
        raise ValueError("raw successor call was changed or zero-filtered")
    return call


class BittensorCompetitionWeightTransport:
    """Encode using the owned runtime, submit exact signed bytes via SDK 11.1.0."""

    def __init__(self, *, endpoint: str, client_factory=None):
        if importlib.metadata.version("bittensor") != "11.1.0":
            raise ValueError("successor weight transport requires pinned Bittensor 11.1.0")
        if not endpoint.startswith("wss://"):
            raise ValueError("successor submission endpoint must use wss")
        self.endpoint = endpoint
        self.client_factory = client_factory or bt.Subtensor

    @staticmethod
    def encode(call, body, observation, signer, *, projection) -> bytes:
        validate_owned_weight_observation(observation)
        _validate_signing_runtime(observation.runtime, body)
        if digest(projection) != body.projection_sha256 or (
            call.module != "SubtensorModule"
            or call.function != "set_mechanism_weights"
            or call.params
            != {
                "netuid": 78,
                "mecid": 0,
                "dests": list(projection.uids),
                "weights": list(projection.weights),
                "version_key": body.weights_version_key,
            }
        ):
            raise ValueError("successor signing only accepts the exact authorized raw row")
        return encode_mortal_call(
            call,
            runtime=observation.runtime,
            signer=signer,
            validator_hotkey=observation.validator_hotkey,
            nonce=observation.validator_nonce,
            mortality_period=body.mortality_period,
            genesis_hash=observation.genesis_hash,
        )

    async def submit(self, encoded: bytes, signer):
        extrinsic = exact_signed_extrinsic(encoded)
        async with self.client_factory(self.endpoint, retry_forever=False) as client:
            # No submit_call re-composition, nonce lookup, era selection or retry.
            return await client._substrate.submit_signed(
                extrinsic,
                signer,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )


class CompetitionWeightWorker:
    def __init__(
        self,
        state_root: Path,
        *,
        package_limits: CompetitionPackageLimits,
        replay_worker: CompetitionReplayWorker,
        maximum_attempts: int,
        maximum_evidence_bytes: int,
        submission_timeout_seconds: int,
    ):
        if type(maximum_attempts) is not int or not 1 <= maximum_attempts <= 65536:
            raise ValueError("explicit weight attempt capacity is required")
        if (
            type(maximum_evidence_bytes) is not int
            or not 1024 <= maximum_evidence_bytes <= 16 * 1024**3
        ):
            raise ValueError("explicit bounded weight evidence capacity is required")
        if (
            type(submission_timeout_seconds) is not int
            or not 1 <= submission_timeout_seconds <= 3600
        ):
            raise ValueError("explicit bounded submission timeout is required")
        self.state_root = _prepare_private_directory(state_root, "weight state")
        self.path = self.state_root / "competition-weights.sqlite3"
        self.lock_path = self.state_root / "competition-weights.lock"
        root_fd = _open_directory_without_links(self.state_root)
        try:
            for path in (self.path, self.lock_path):
                CompetitionReplayWorker._prepare_state_file(root_fd, path.name)
        finally:
            os.close(root_fd)
        self.package_limits, self.replay_worker = package_limits, replay_worker
        self.maximum_attempts, self.submission_timeout_seconds = (
            maximum_attempts,
            submission_timeout_seconds,
        )
        self.maximum_evidence_bytes = maximum_evidence_bytes
        with self._lock(), self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS binding "
                "(hotkey TEXT PRIMARY KEY, maximum_attempts INTEGER NOT NULL, "
                "maximum_evidence_bytes INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS attempts "
                "(id TEXT PRIMARY KEY, body BLOB NOT NULL, sha256 TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS evidence (sha256 TEXT PRIMARY KEY, body BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS highwater (id INTEGER PRIMARY KEY CHECK(id=1), "
                "block INTEGER NOT NULL, hash TEXT NOT NULL)"
            )
            db.execute("CREATE TABLE IF NOT EXISTS held_policies (policy TEXT PRIMARY KEY)")

    @contextmanager
    def _lock(self):
        descriptor = _open_private_regular_file(self.lock_path, "weight lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield descriptor
        finally:
            os.close(descriptor)

    @contextmanager
    def _db(self):
        _verify_sqlite_family(self.path, "weight journal")
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _save(self, attempt):
        with self._db() as db:
            self._save_to_db(db, attempt)

    @staticmethod
    def _save_to_db(db, attempt):
        model = _WeightAttempt.model_validate_json(canonical_json_bytes(attempt))
        encoded = canonical_json_bytes(model)
        if len(encoded) > _JOURNAL_LIMIT:
            raise ValueError("successor attempt exceeds journal bound")
        db.execute(
            "INSERT INTO attempts VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET body=excluded.body, sha256=excluded.sha256",
            (attempt["authorization_id"], encoded, hashlib.sha256(encoded).hexdigest()),
        )

    def _load(self, validator_hotkey, authorization_id, observation):
        with self._db() as db:
            self._check_journal_binding(db, validator_hotkey)
            self._record_head(db, observation)
            result = self._inspect_attempts(db, validator_hotkey, authorization_id)
            self._retain_observation(db, observation)
            return result

    def _check_journal_binding(self, db, validator_hotkey):
        expected = (validator_hotkey, self.maximum_attempts, self.maximum_evidence_bytes)
        binding = db.execute(
            "SELECT hotkey, maximum_attempts, maximum_evidence_bytes FROM binding"
        ).fetchall()
        if not binding:
            db.execute("INSERT INTO binding VALUES (?, ?, ?)", expected)
        elif binding != [expected]:
            raise ValueError("successor journal belongs to another hotkey or capacity")

    @staticmethod
    def _record_head(db, observation):
        prior_head = db.execute("SELECT block, hash FROM highwater WHERE id=1").fetchone()
        if prior_head and (
            observation.block < prior_head[0]
            or (observation.block == prior_head[0] and observation.block_hash != prior_head[1])
        ):
            raise ValueError("successor finalized state rolled back or changed")
        db.execute(
            "INSERT INTO highwater VALUES (1, ?, ?) ON CONFLICT(id) "
            "DO UPDATE SET block=excluded.block, hash=excluded.hash",
            (observation.block, observation.block_hash),
        )

    def _inspect_attempts(self, db, validator_hotkey, authorization_id):
        records = db.execute("SELECT id, length(body) FROM attempts").fetchall()
        if len(records) > self.maximum_attempts or any(
            not 0 < size <= _JOURNAL_LIMIT for _, size in records
        ):
            raise ValueError("successor journal is oversized")
        result = None
        for key, _ in records:
            raw, expected_sha256 = db.execute(
                "SELECT body, sha256 FROM attempts WHERE id=?", (key,)
            ).fetchone()
            if hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise ValueError("successor attempt bytes are corrupt")
            model = _WeightAttempt.model_validate_json(raw)
            item = model.model_dump(mode="json", by_alias=True)
            if canonical_json_bytes(item) != raw or item.get("authorization_id") != key:
                raise ValueError("successor journal is corrupt")
            if item["validator_hotkey"] != validator_hotkey:
                raise ValueError("successor journal attempt binds another hotkey")
            if (
                db.execute(
                    "SELECT 1 FROM evidence WHERE sha256=?", (item["chain_evidence_sha256"],)
                ).fetchone()
                is None
            ):
                raise ValueError("successor attempt lost its retained preflight evidence")
            if key != authorization_id and item["phase"] not in {
                "applied",
                "recovered_effect",
                "expired_unconsumed_nonce",
            }:
                raise ValueError("another successor attempt still has unresolved effects")
            if key == authorization_id:
                result = item
        if result is None and len(records) >= self.maximum_attempts:
            raise ValueError("successor attempt capacity is exhausted; retain all history")
        return result

    def _retain_observation(self, db, observation):
        known, total = self._audit_evidence(db)
        self._append_observation(db, observation, known, total)

    def _audit_evidence(self, db):
        entries = db.execute("SELECT sha256, length(body) FROM evidence").fetchall()
        total = sum(size for _, size in entries)
        if total > self.maximum_evidence_bytes or any(
            not 0 < size <= 32 * 1024**2 for _, size in entries
        ):
            raise ValueError("retained successor chain evidence is oversized")
        known = set()
        for identity, _ in entries:
            raw = db.execute("SELECT body FROM evidence WHERE sha256=?", (identity,)).fetchone()[0]
            if hashlib.sha256(raw).hexdigest() != identity:
                raise ValueError("retained successor chain evidence is corrupt")
            known.add(identity)
        return known, total

    def _append_observation(self, db, observation, known, total):
        for raw in (observation.evidence, observation.runtime.metadata_bytes):
            identity = hashlib.sha256(raw).hexdigest()
            if identity in known:
                continue
            if not 0 < len(raw) <= 32 * 1024**2 or total + len(raw) > self.maximum_evidence_bytes:
                raise ValueError("successor chain evidence capacity is exhausted")
            db.execute("INSERT INTO evidence VALUES (?, ?)", (identity, raw))
            total += len(raw)
            known.add(identity)

    async def run(
        self,
        package_path: Path,
        *,
        authorization: SignedCompetitionWeightAuthorization,
        activation: Any,
        wallet: Any,
        chain: FinalizedCompetitionWeightProvider,
        transport: BittensorCompetitionWeightTransport,
    ) -> CompetitionWeightOutcome:
        # Imports avoid coupling the historical recovery implementation to the
        # live successor submit path. Neither capability is deserialized here.
        from .competition_host_upgrade import validate_authenticated_successor_activation

        context = activation
        validate_authenticated_successor_activation(
            context,
            validator_hotkey=context.validator_hotkey,
            directive_sha256=context.directive_sha256,
            package_sha256=authorization.authorization.package_sha256,
            authorization_sha256=signed_competition_weight_authorization_digest(authorization),
            expected_profile="competition_weights",
        )
        release = context.release_identity
        if not isinstance(release, CompetitionReleaseIdentity):
            raise ValueError("host activation lacks authenticated release identity")
        if (
            competition_release_identity_digest(release)
            != authorization.authorization.release_identity_sha256
        ):
            raise ValueError("host release differs from successor authorization")
        package = load_competition_package(
            package_path,
            expected_package_sha256=authorization.authorization.package_sha256,
            expected_policy_sha256=authorization.authorization.policy_sha256,
            observed_release=release,
            limits=self.package_limits,
        )
        body = verify_competition_weight_authorization(
            authorization,
            trusted_authority_hotkeys=tuple(context.authority_hotkeys),
            package=package,
        )
        hotkey = context.validator_hotkey
        signer = bt.resolve_signer(wallet, role="hotkey")
        if account_id32(signer.ss58_address) != account_id32(hotkey):
            raise ValueError("installed hotkey differs from successor activation")
        recipients = tuple(
            Registration(uid=item.uid, hotkey=item.hotkey)
            for item in package.retained_settlement.projection.allocations
        )
        expected_row = tuple(
            zip(
                package.retained_settlement.projection.uids,
                package.retained_settlement.projection.weights,
                strict=True,
            )
        )
        auth_digest = competition_weight_authorization_digest(body)
        call = build_competition_weight_call(package, body)
        with self._lock():
            # Package replay is intentionally expensive and may outlive the
            # activation's original proof. Finish it before taking the proof
            # used for this attempt, then reauthorize the same mounted inputs.
            replay = self.replay_worker.run(
                package_path,
                expected_package_sha256=body.package_sha256,
                expected_policy_sha256=body.policy_sha256,
                observed_release=release,
            )
            observation = await chain.collect_weights(hotkey, recipients)
            validate_weight_preflight(package, body, observation, chain.config, submission=False)
            context = context.refresh(owned_observation=observation)
            recovery_checkpoint = context.validate_retained_recovery(
                context.checkpoint_sha256, hotkey, body.predecessor_directive_sha256
            )
            if observation.block < recovery_checkpoint.finalized_block:
                raise ValueError("successor observation predates historical recovery")
            attempt = self._load(hotkey, body.authorization_id, observation)
            if attempt is not None and (
                attempt["authorization_sha256"] != auth_digest
                or attempt["recovery_checkpoint_sha256"] != context.checkpoint_sha256
                or attempt["chain_config_sha256"] != digest(chain.config)
            ):
                raise ValueError("single-use successor authorization or recovery binding changed")
            self.replay_worker.verify_publication_unchanged(replay)
            if replay.current_status.held:
                with self._db() as db:
                    db.execute(
                        "INSERT OR IGNORE INTO held_policies VALUES (?)", (body.policy_sha256,)
                    )
                if attempt is not None:
                    # Record any now-known effect even while refusing all new
                    # writes. Conflict handling never sends a corrective row.
                    self._recover(attempt, body, hotkey, observation, expected_row)
                return self._outcome(
                    body, hotkey, "held_conflict", observation, expected_row, attempt, False
                )
            with self._db() as db:
                held = db.execute(
                    "SELECT 1 FROM held_policies WHERE policy=?", (body.policy_sha256,)
                ).fetchone()
            if held is not None:
                return self._outcome(
                    body, hotkey, "held_conflict", observation, expected_row, attempt, False
                )
            if attempt is not None:
                return self._recover(attempt, body, hotkey, observation, expected_row)
            validate_weight_preflight(package, body, observation, chain.config, submission=True)
            validate_authenticated_successor_activation(
                context,
                validator_hotkey=hotkey,
                directive_sha256=context.directive_sha256,
                package_sha256=body.package_sha256,
                authorization_sha256=signed_competition_weight_authorization_digest(authorization),
                expected_profile="competition_weights",
            )
            attempt = {
                "schema": "umi-competition-weight-attempt/1",
                "authorization_id": body.authorization_id,
                "authorization_sha256": auth_digest,
                "validator_hotkey": hotkey,
                "recovery_checkpoint_sha256": context.checkpoint_sha256,
                "chain_config_sha256": digest(chain.config),
                "phase": "intent",
                "preflight_block": observation.block,
                "preflight_hash": observation.block_hash,
                "prior_last_update": observation.validator_last_update,
                "nonce": observation.validator_nonce,
                "era_death": observation.block + body.mortality_period,
                "chain_evidence_sha256": observation.evidence_sha256,
                "publication_journal_status_sha256": (
                    replay.current_status.publication_journal_status_sha256
                ),
                "signed_extrinsic": None,
            }
            self._save(attempt)  # Durable before signing or a possible network effect.
            encoded = transport.encode(
                call,
                body,
                observation,
                signer,
                projection=package.retained_settlement.projection,
            )
            attempt.update(phase="signed", signed_extrinsic="0x" + encoded.hex())
            self._save(attempt)  # Exact bytes retained before any submission.
            # Do not spend a mortal transaction's lifetime replaying unchanged
            # evidence. A changed journal gets a diagnostic replay, but those
            # already signed bytes are never broadcast on that changed path.
            current_replay = replay
            publication_changed = False
            try:
                self.replay_worker.verify_publication_unchanged(replay)
            except ValueError:
                publication_changed = True
                current_replay = self.replay_worker.run(
                    package_path,
                    expected_package_sha256=body.package_sha256,
                    expected_policy_sha256=body.policy_sha256,
                    observed_release=release,
                )
            # Signing may be slow. Recheck current chain state without altering
            # the frozen nonce, era, call, or durable signed extrinsic bytes.
            before_send = await chain.collect_weights(hotkey, recipients)
            validate_weight_preflight(package, body, before_send, chain.config, submission=True)
            self._load(hotkey, body.authorization_id, before_send)
            context = context.refresh(owned_observation=before_send)
            if (
                before_send.validator_nonce != attempt["nonce"]
                or before_send.validator_uid != observation.validator_uid
                or before_send.block >= attempt["era_death"]
                or _signing_runtime_identity(before_send.runtime)
                != _signing_runtime_identity(observation.runtime)
            ):
                raise ValueError("signed successor preflight changed before broadcast")
            validate_authenticated_successor_activation(
                context,
                validator_hotkey=hotkey,
                directive_sha256=context.directive_sha256,
                package_sha256=body.package_sha256,
                authorization_sha256=signed_competition_weight_authorization_digest(authorization),
                expected_profile="competition_weights",
            )
            self.replay_worker.verify_publication_unchanged(current_replay)
            if current_replay.current_status.held:
                with self._db() as db:
                    db.execute(
                        "INSERT OR IGNORE INTO held_policies VALUES (?)", (body.policy_sha256,)
                    )
                return self._outcome(
                    body, hotkey, "held_conflict", before_send, expected_row, attempt, False
                )
            if publication_changed:
                raise ValueError("publication journal changed after signing; broadcast refused")
            validate_owned_weight_observation(before_send)
            try:
                await asyncio.wait_for(
                    transport.submit(encoded, signer),
                    timeout=self.submission_timeout_seconds,
                )
            except BaseException:
                attempt["phase"] = "unknown"
                self._save(attempt)
                raise
            # Never trust an SDK success flag as finalized proof of application.
            after = await chain.collect_weights(hotkey, recipients)
            validate_weight_preflight(package, body, after, chain.config, submission=False)
            self._load(hotkey, body.authorization_id, after)
            outcome = self._recover(attempt, body, hotkey, after, expected_row)
            return outcome.model_copy(update={"submitted_by_this_attempt": True})

    async def reconcile_stopped(
        self,
        package_path: Path,
        *,
        authorization: SignedCompetitionWeightAuthorization,
        installation: Any,
        release: CompetitionReleaseIdentity,
        chain_config: CompetitionChainConfig,
        observe: Callable[[], Awaitable[OwnedCompetitionChainObservation]],
        finalized_floor: tuple[int, str],
    ) -> tuple[CompetitionWeightOutcome | None, OwnedCompetitionChainObservation]:
        """Reconcile retained bytes without a signer or transaction transport.

        The caller must establish process absence before taking this journal
        lock. Local terminal-state writes preserve every attempt and evidence
        record; this method cannot create a new attempt or broadcast anything.
        Expired signed authority may justify recovery, never a new submission.
        The floor is only a monotonic lower bound. All current-state decisions
        use the owned proof captured after slow package and journal validation.
        """
        from .competition_host_activation import validate_authenticated_successor_installation

        validate_authenticated_successor_installation(installation)
        if (
            type(finalized_floor) is not tuple
            or len(finalized_floor) != 2
            or type(finalized_floor[0]) is not int
            or not 0 <= finalized_floor[0] < 2**53
            or not isinstance(finalized_floor[1], str)
            or len(finalized_floor[1]) != 66
            or not finalized_floor[1].startswith("0x")
            or any(c not in "0123456789abcdef" for c in finalized_floor[1][2:])
        ):
            raise ValueError("invalid stopped recovery finalized floor")
        # Take private parsed copies before awaiting an external observer.
        chain_config = CompetitionChainConfig.model_validate_json(
            canonical_json_bytes(chain_config)
        )
        authorization = SignedCompetitionWeightAuthorization.model_validate_json(
            canonical_json_bytes(authorization)
        )
        package_snapshot = _recovery_package_snapshot(package_path)
        package = load_competition_package(
            package_path,
            expected_package_sha256=authorization.authorization.package_sha256,
            expected_policy_sha256=authorization.authorization.policy_sha256,
            observed_release=release,
            limits=self.package_limits,
        )
        body = verify_competition_weight_authorization(
            authorization,
            trusted_authority_hotkeys=tuple(
                entry.hotkey for entry in installation.config.trusted_authorities
            ),
            package=package,
        )
        if _recovery_package_snapshot(package_path) != package_snapshot:
            raise ValueError("stopped recovery package changed during verification")
        hotkey = installation.config.validator_hotkey
        checkpoint_sha256 = installation.checkpoint_sha256
        checkpoint_block = installation.checkpoint_finalized_block
        configuration_sha256 = digest(chain_config)
        authorization_sha256 = competition_weight_authorization_digest(body)
        row = tuple(
            zip(
                package.retained_settlement.projection.uids,
                package.retained_settlement.projection.weights,
                strict=True,
            )
        )
        with self._lock() as lock_descriptor, self._db() as db:
            lock_identity = _file_identity(os.fstat(lock_descriptor))
            self._check_journal_binding(db, hotkey)
            journal_snapshot = _recovery_journal_snapshot(self.path)
            attempt = self._inspect_attempts(db, hotkey, body.authorization_id)
            known, total = self._audit_evidence(db)
            if _recovery_journal_snapshot(self.path) != journal_snapshot:
                raise ValueError("stopped recovery journal changed during verification")
            if attempt is not None and (
                attempt["authorization_sha256"] != authorization_sha256
                or attempt["chain_config_sha256"] != configuration_sha256
                or attempt["recovery_checkpoint_sha256"] != checkpoint_sha256
            ):
                raise ValueError("stopped successor recovery binding changed")
            observation = await observe()
            validate_owned_weight_observation(observation)
            validate_authenticated_successor_installation(installation)
            current_lock = _open_private_regular_file(self.lock_path, "stopped recovery lock")
            try:
                if (
                    _file_identity(os.fstat(lock_descriptor)) != lock_identity
                    or _file_identity(os.fstat(current_lock)) != lock_identity
                ):
                    raise ValueError("stopped recovery lock changed while held")
            finally:
                os.close(current_lock)
            if (
                account_id32(observation.validator_hotkey) != account_id32(hotkey)
                or observation.genesis_hash.removeprefix("0x")
                != chain_config.chain_pin.genesis_block_hash
                or observation.block < max(finalized_floor[0], checkpoint_block)
                or (
                    observation.block == finalized_floor[0]
                    and observation.block_hash != finalized_floor[1]
                )
            ):
                raise ValueError(
                    "stopped recovery proof changed validator, chain or finalized floor"
                )
            if _recovery_package_snapshot(package_path) != package_snapshot:
                raise ValueError("stopped recovery package changed after verification")
            if _recovery_journal_snapshot(self.path) != journal_snapshot:
                raise ValueError("stopped recovery journal changed after verification")
            validate_weight_preflight(package, body, observation, chain_config, submission=False)
            self._record_head(db, observation)
            self._append_observation(db, observation, known, total)
            validate_owned_weight_observation(observation)
            outcome = (
                None
                if attempt is None
                else self._recover(attempt, body, hotkey, observation, row, database=db)
            )
            return outcome, observation

    def _recover(self, attempt, body, hotkey, observation, row, *, database=None):
        if attempt["phase"] in {"applied", "recovered_effect", "expired_unconsumed_nonce"}:
            return self._outcome(body, hotkey, attempt["phase"], observation, row, attempt, False)
        if (
            attempt["signed_extrinsic"] is not None
            and observation.validator_row == row
            and attempt["preflight_block"]
            < observation.validator_last_update
            < attempt["era_death"]
            and observation.validator_nonce > attempt["nonce"]
        ):
            status = "recovered_effect"
        elif (
            observation.block >= attempt["era_death"]
            and observation.validator_nonce == attempt["nonce"]
        ):
            # The retained mortal bytes cannot create a future effect, and this
            # nonce is still available in the current finalized account state.
            # This is not an archival proof that no past effect ever occurred
            # (for example, across account reaping). Never retry this authority.
            status = "expired_unconsumed_nonce"
        else:
            status = "unknown"
        attempt["phase"] = status
        if database is None:
            self._save(attempt)
        else:
            self._save_to_db(database, attempt)
        return self._outcome(body, hotkey, status, observation, row, attempt, False)

    @staticmethod
    def _outcome(body, hotkey, status, observation, row, attempt, submitted):
        encoded = None if attempt is None else attempt.get("signed_extrinsic")
        return CompetitionWeightOutcome(
            schema="umi-competition-weight-outcome/1",
            authorization_id=body.authorization_id,
            validator_hotkey=hotkey,
            status=status,
            finalized_block=observation.block,
            finalized_block_hash=observation.block_hash,
            exact_row_currently_applied=observation.validator_row == row,
            submitted_by_this_attempt=submitted,
            extrinsic_sha256=None
            if encoded is None
            else hashlib.sha256(bytes.fromhex(encoded[2:])).hexdigest(),
            chain_evidence_sha256=observation.evidence_sha256,
        )
