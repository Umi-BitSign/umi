"""Finalized, read-only Bittensor collection for the public observer API.

This module deliberately exposes no wallet, intent, extrinsic, or broadcast
surface. Every value in one snapshot is read through a single finalized
``Snapshot`` from the pinned Bittensor client.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import math
import os
import re
import tempfile
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from typing import Any, Protocol

from .observer_models import (
    ChainNetworkSnapshot,
    ChainParticipant,
    ChainParticipantMetrics,
    EpochState,
    ExactExchangeRate,
    ExactNormalizedMetric,
    ExactTokenAmount,
    FinalizedBlock,
    NetworkCounts,
    NetworkHyperparameters,
    ObserverSnapshot,
    SourceProvenance,
    UmiTranslationMetrics,
)

_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_MAX_U64 = (1 << 64) - 1
_PER_U16_DENOMINATOR = 65_535
_RUNTIME_CACHE_ENV = "BITTENSOR_RUNTIME_CACHE_DIR"
_runtime_cache_directory: tempfile.TemporaryDirectory[str] | None = None


class ChainCollectionError(RuntimeError):
    """A stable, non-sensitive failure raised when a chain snapshot is unusable."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ChainCollector(Protocol):
    """Mockable interface consumed by the observer snapshot cache."""

    async def collect(self) -> ObserverSnapshot:
        """Return one internally consistent finalized-chain snapshot."""


def _default_client_factory(network: str) -> Any:
    # Import lazily so schema and API tests do not connect to a chain merely by
    # importing this module.
    global _runtime_cache_directory

    # Bittensor 11.1 otherwise stores downloaded runtime metadata under
    # ~/.bittensor/runtime-cache. Keep the observer's cache in its own ephemeral,
    # process-private directory unless the operator explicitly configured the
    # SDK's supported override. Retain the TemporaryDirectory handle for the
    # process lifetime so metadata remains available while the client is active.
    if not os.getenv(_RUNTIME_CACHE_ENV):
        if _runtime_cache_directory is None:
            _runtime_cache_directory = tempfile.TemporaryDirectory(
                prefix="umi-observer-runtime-cache-"
            )
        os.environ[_RUNTIME_CACHE_ENV] = _runtime_cache_directory.name

    import bittensor as bt

    class ReadOnlyObserverClient(bt.Client):
        async def connect(self) -> Any:
            # Bittensor 11.1 normally refreshes a display-only token-symbol disk
            # cache in Client.connect(). Observer values come from raw fields, so
            # connect the pinned transport directly and skip that unrelated write.
            await self._substrate.connect()
            return self

    return ReadOnlyObserverClient(network)


def _pinned_storage_descriptors() -> tuple[Any, Any, Any, Any]:
    """Descriptors pinned by the repository's exact Bittensor dependency."""

    from bittensor._generated import storage

    return (
        storage.System.LastRuntimeUpgrade,
        storage.SubtensorModule.CommitRevealWeightsVersion,
        storage.SubtensorModule.MaxMechanismCount,
        storage.SubtensorModule.NetworksAdded,
    )


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_U64,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChainCollectionError(f"invalid_{field}")
    if value < minimum or value > maximum:
        raise ChainCollectionError(f"invalid_{field}")
    return value


def _optional_integer(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_U64,
) -> int | None:
    if value is None:
        return None
    return _integer(value, field, minimum=minimum, maximum=maximum)


def _block_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or _BLOCK_HASH_RE.fullmatch(value) is None:
        raise ChainCollectionError(f"invalid_{field}")
    return value


def _mapping(value: Any, field: str) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise ChainCollectionError(f"invalid_{field}")
    return value


def _sequence(value: Any, field: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ChainCollectionError(f"invalid_{field}")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ChainCollectionError(f"invalid_{field}")
    return value


def _boolean_flag(value: Any, field: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ChainCollectionError(f"invalid_{field}")


def _optional_public_text(value: Any, field: str, *, maximum_bytes: int = 512) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ChainCollectionError(f"invalid_{field}")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ChainCollectionError(f"invalid_{field}")
    if any(ord(character) < 0x20 and character not in "\t\n\r" for character in value):
        raise ChainCollectionError(f"invalid_{field}")
    return value or None


def _hotkey(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ChainCollectionError("invalid_participant_hotkey")
    if not value.isascii() or any(character.isspace() for character in value):
        raise ChainCollectionError("invalid_participant_hotkey")
    return value


def _utc_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ChainCollectionError(f"invalid_{field}")
    return value.astimezone(timezone.utc)


def _decimal_ratio(numerator: int, denominator: int) -> str:
    if numerator < 0 or denominator <= 0:
        raise ChainCollectionError("invalid_decimal_ratio")
    with localcontext() as context:
        context.prec = 50
        rendered = format(Decimal(numerator) / Decimal(denominator), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _raw_metric(metagraph: Any, key: str, uid: int) -> int | None:
    """Read one raw PerU16 value without accepting the SDK's padded float zero."""

    raw = getattr(metagraph, "raw", None)
    if not isinstance(raw, Mapping):
        return None
    values = raw.get(key)
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        return None
    if uid >= len(values) or values[uid] is None:
        return None
    return _integer(values[uid], f"{key}_metric", maximum=_PER_U16_DENOMINATOR)


def _raw_balance_rao(metagraph: Any, key: str, uid: int) -> int | None:
    """Read one raw balance without accepting the SDK's padded zero value."""

    raw = getattr(metagraph, "raw", None)
    if not isinstance(raw, Mapping):
        return None
    values = raw.get(key)
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        return None
    if uid >= len(values) or values[uid] is None:
        return None
    return _integer(values[uid], f"{key}_rao")


def _required_raw_column(
    metagraph: Any,
    key: str,
    expected_length: int,
) -> Sequence[Any]:
    raw = getattr(metagraph, "raw", None)
    if not isinstance(raw, Mapping):
        raise ChainCollectionError("invalid_metagraph_raw")
    if key not in raw:
        raise ChainCollectionError(f"missing_metagraph_raw_{key}")
    values = _sequence(raw[key], f"metagraph_raw_{key}")
    if len(values) != expected_length:
        raise ChainCollectionError(f"metagraph_raw_{key}_length_mismatch")
    return values


async def _first_finalized_header(client: Any, timeout_seconds: float) -> Any:
    stream: AsyncIterator[Any] = client.blocks(finalized=True)
    try:
        return await asyncio.wait_for(anext(stream), timeout=timeout_seconds)
    except asyncio.TimeoutError as error:
        raise ChainCollectionError("finalized_head_timeout") from error
    finally:
        close = getattr(stream, "aclose", None)
        if close is not None:
            with contextlib.suppress(Exception):
                result = close()
                if inspect.isawaitable(result):
                    await result


def _normalized_metric(raw: int | None) -> ExactNormalizedMetric | None:
    if raw is None:
        return None
    return ExactNormalizedMetric(
        raw_numerator=str(raw),
        display_decimal=_decimal_ratio(raw, _PER_U16_DENOMINATOR),
    )


def _token_amount(raw: int | None, *, asset: str) -> ExactTokenAmount | None:
    if raw is None:
        return None
    if asset not in {"tao", "subnet_alpha"}:
        raise ChainCollectionError("invalid_token_asset")
    return ExactTokenAmount.model_validate({"raw": str(raw), "asset": asset}, strict=True)


def _hyperparameter_integer(
    hyperparameters: Mapping[Any, Any],
    name: str,
    unavailable_fields: set[str],
    *,
    public_name: str | None = None,
) -> int | None:
    value = _optional_integer(hyperparameters.get(name), f"hyperparameter_{name}")
    if value is None:
        unavailable_fields.add(f"hyperparameters.{public_name or name}")
    return value


def _identity_name(metagraph: Any, unavailable_fields: set[str]) -> str | None:
    identity = getattr(metagraph, "identity", None)
    if identity is None:
        unavailable_fields.add("identity")
        return None
    identity_map = _mapping(identity, "subnet_identity")
    name = _optional_public_text(identity_map.get("subnet_name"), "subnet_identity_name")
    if name is None:
        unavailable_fields.add("identity")
    return name


def _exchange_rate(metagraph: Any, unavailable_fields: set[str]) -> ExactExchangeRate | None:
    raw = getattr(metagraph, "raw", None)
    if not isinstance(raw, Mapping):
        unavailable_fields.add("price")
        return None
    tao_in = _optional_integer(raw.get("tao_in"), "tao_reserve_rao")
    alpha_in = _optional_integer(raw.get("alpha_in"), "alpha_reserve_rao")
    if tao_in is None or alpha_in in (None, 0):
        unavailable_fields.add("price")
        return None
    return ExactExchangeRate(
        tao_reserve_rao=str(tao_in),
        subnet_alpha_reserve_rao=str(alpha_in),
        display_decimal=_decimal_ratio(tao_in, alpha_in),
    )


def _count_pending_commits(value: Any) -> int:
    commits_by_epoch = _mapping(value, "pending_weight_commits")
    total = 0
    for epoch, entries in commits_by_epoch.items():
        _integer(epoch, "pending_weight_commit_epoch")
        entry_values = _sequence(entries, "pending_weight_commit_entries")
        for entry in entry_values:
            _mapping(entry, "pending_weight_commit_entry")
        total += len(entry_values)
        if total > _MAX_U64:
            raise ChainCollectionError("invalid_pending_weight_commit_count")
    return total


def _participant(metagraph: Any, neuron: Any, block_number: int) -> ChainParticipant:
    uid = _integer(getattr(neuron, "uid", None), "participant_uid", maximum=(1 << 32) - 1)
    participant_count = len(getattr(metagraph, "neurons", ()))
    raw_hotkey = _hotkey(str(_required_raw_column(metagraph, "hotkeys", participant_count)[uid]))
    hotkey = _hotkey(getattr(neuron, "hotkey", None))
    if hotkey != raw_hotkey:
        raise ChainCollectionError("participant_hotkey_raw_mismatch")
    typed_active = _boolean(getattr(neuron, "active", None), "participant_active")
    active = _boolean_flag(
        _required_raw_column(metagraph, "active", participant_count)[uid],
        "participant_raw_active",
    )
    if active is None or active != typed_active:
        raise ChainCollectionError("participant_active_raw_mismatch")
    typed_validator_permit = _boolean(
        getattr(neuron, "validator_permit", None),
        "participant_validator_permit",
    )
    validator_permit = _boolean_flag(
        _required_raw_column(metagraph, "validator_permit", participant_count)[uid],
        "participant_raw_validator_permit",
    )
    if validator_permit is None or validator_permit != typed_validator_permit:
        raise ChainCollectionError("participant_validator_permit_raw_mismatch")
    registration_block = _integer(
        _required_raw_column(metagraph, "block_at_registration", participant_count)[uid],
        "participant_raw_registration_block",
    )
    if registration_block != _integer(
        getattr(neuron, "block_at_registration", None),
        "participant_registration_block",
    ):
        raise ChainCollectionError("participant_registration_block_raw_mismatch")
    last_update_block = _integer(
        _required_raw_column(metagraph, "last_update", participant_count)[uid],
        "participant_raw_last_update_block",
    )
    if last_update_block != _integer(
        getattr(neuron, "last_update", None),
        "participant_last_update_block",
    ):
        raise ChainCollectionError("participant_last_update_block_raw_mismatch")
    if registration_block > block_number or last_update_block > block_number:
        raise ChainCollectionError("participant_block_after_snapshot")

    metric_keys = {
        "rank": "rank",
        "trust": "trust",
        "consensus": "consensus",
        "incentive": "incentives",
        "dividends": "dividends",
        "pruning_score": "pruning_score",
    }
    metrics = {
        field: _normalized_metric(_raw_metric(metagraph, raw_key, uid))
        for field, raw_key in metric_keys.items()
    }
    metrics.update(
        {
            "emission": _token_amount(
                _raw_balance_rao(metagraph, "emission", uid),
                asset="subnet_alpha",
            ),
            "alpha_stake": _token_amount(
                _raw_balance_rao(metagraph, "alpha_stake", uid),
                asset="subnet_alpha",
            ),
            "tao_stake": _token_amount(
                _raw_balance_rao(metagraph, "tao_stake", uid),
                asset="tao",
            ),
            "total_stake": _token_amount(
                _raw_balance_rao(metagraph, "total_stake", uid),
                asset="subnet_alpha",
            ),
        }
    )

    return ChainParticipant(
        uid=uid,
        hotkey=hotkey,
        role="validator" if validator_permit else "miner",
        chain_active=active,
        validator_permit=validator_permit,
        registration_block=str(registration_block),
        last_update_block=str(last_update_block),
        last_update_age_blocks=str(block_number - last_update_block),
        serving_announced=getattr(neuron, "axon", None) is not None,
        chain_metrics=ChainParticipantMetrics.model_validate(metrics, strict=True),
        umi_translation=UmiTranslationMetrics(
            availability="unavailable",
            reason_code="released_umi_score_evidence_unavailable",
            miner_root=None,
            accuracy=None,
            utility=None,
            rank=None,
            audit_bundle_sha256=None,
            audit_release_block=None,
        ),
    )


class BittensorChainCollector:
    """Collect one public snapshot from a finalized Bittensor block."""

    def __init__(
        self,
        *,
        network: str = "finney",
        netuid: int = 78,
        finalized_head_timeout_seconds: float = 20.0,
        maximum_participants: int = 4_096,
        client_factory: Callable[[str], Any] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if netuid != 78:
            raise ValueError("the observer API is pinned to SN78")
        if not isinstance(network, str) or not network or len(network) > 256:
            raise ValueError("network must be a non-empty Bittensor network name")
        if (
            isinstance(finalized_head_timeout_seconds, bool)
            or not isinstance(finalized_head_timeout_seconds, (int, float))
            or not math.isfinite(finalized_head_timeout_seconds)
            or finalized_head_timeout_seconds <= 0
            or finalized_head_timeout_seconds > 300
        ):
            raise ValueError("finalized head timeout must be in (0, 300] seconds")
        if (
            isinstance(maximum_participants, bool)
            or not isinstance(maximum_participants, int)
            or maximum_participants <= 0
            or maximum_participants > 65_536
        ):
            raise ValueError("maximum_participants must be in [1, 65536]")
        self.network = network
        self.netuid = netuid
        self.finalized_head_timeout_seconds = float(finalized_head_timeout_seconds)
        self.maximum_participants = maximum_participants
        self._client_factory = client_factory or _default_client_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def collect(self) -> ObserverSnapshot:
        """Read every observer field from one finalized, pinned snapshot."""

        try:
            async with self._client_factory(self.network) as client:
                return await self._collect_from_client(client)
        except asyncio.CancelledError:
            raise
        except ChainCollectionError:
            raise
        except Exception as error:
            raise ChainCollectionError("chain_collection_failed") from error

    async def _collect_from_client(self, client: Any) -> ObserverSnapshot:
        header = await _first_finalized_header(
            client,
            self.finalized_head_timeout_seconds,
        )
        block_number = _integer(getattr(header, "number", None), "finalized_block_number")
        snapshot = await client.at(block_number)
        if _integer(getattr(snapshot, "block", None), "snapshot_block_number") != block_number:
            raise ChainCollectionError("snapshot_block_mismatch")

        # block_info is deliberately called on the pinned Snapshot. Calling it
        # on the head client here would reintroduce a mixed-head race.
        block_info = await snapshot.block_info()
        finalized_block = self._validate_finalized_block(header, block_info, block_number)

        (
            metagraph,
            hyperparameter_value,
            epoch_value,
            mechanism_count_value,
            mechanism_split_value,
            commit_reveal_value,
            reveal_period_value,
            subnet_emission_value,
            pending_commits_value,
            runtime_upgrade_value,
            commit_reveal_version_value,
            maximum_mechanism_count_value,
            subnet_exists_value,
        ) = await asyncio.gather(
            snapshot.subnets.metagraph(netuid=self.netuid, commitments=False),
            snapshot.read("subnet_hyperparameters", netuid=self.netuid),
            snapshot.read("epoch_status", netuid=self.netuid),
            snapshot.read("mechanism_count", netuid=self.netuid),
            snapshot.read("mechanism_emission_split", netuid=self.netuid),
            snapshot.read("commit_reveal_enabled", netuid=self.netuid),
            snapshot.read("reveal_period", netuid=self.netuid),
            snapshot.read("subnet_emission_enabled", netuid=self.netuid),
            snapshot.read("timelocked_weight_commits", netuid=self.netuid, mechid=0),
            *self._storage_reads(snapshot),
        )
        if metagraph is None:
            raise ChainCollectionError("subnet_not_found")
        hyperparameters = _mapping(hyperparameter_value, "subnet_hyperparameters")
        epoch = _mapping(epoch_value, "epoch_status")

        self._validate_metagraph(metagraph, block_number)
        epoch_state = self._build_epoch(metagraph, hyperparameters, epoch, block_number)
        mechanism_count = _integer(
            mechanism_count_value,
            "mechanism_count",
            minimum=1,
            maximum=65_535,
        )
        maximum_mechanism_count = _optional_integer(
            maximum_mechanism_count_value,
            "maximum_mechanism_count",
            minimum=1,
            maximum=65_535,
        )
        if maximum_mechanism_count is not None and mechanism_count > maximum_mechanism_count:
            raise ChainCollectionError("mechanism_count_exceeds_global_maximum")
        mechanism_split = self._build_mechanism_split(
            mechanism_split_value,
            mechanism_count,
        )
        commit_reveal_enabled = _boolean_flag(
            commit_reveal_value,
            "commit_reveal_enabled",
        )
        reveal_period = _optional_integer(
            reveal_period_value,
            "reveal_period",
        )
        if commit_reveal_enabled and (reveal_period is None or reveal_period == 0):
            raise ChainCollectionError("invalid_enabled_reveal_period")
        pending_commit_count = _count_pending_commits(pending_commits_value)
        subnet_emission_enabled = _boolean_flag(
            subnet_emission_value,
            "subnet_emission_enabled",
        )
        runtime_upgrade = _mapping(runtime_upgrade_value, "last_runtime_upgrade")
        runtime_spec_version = _optional_integer(
            runtime_upgrade.get("spec_version"),
            "runtime_spec_version",
        )
        commit_reveal_version = _optional_integer(
            commit_reveal_version_value,
            "commit_reveal_version",
            maximum=65_535,
        )
        subnet_exists = _boolean_flag(subnet_exists_value, "subnet_exists")

        participants = tuple(
            sorted(
                (
                    _participant(metagraph, neuron, block_number)
                    for neuron in getattr(metagraph, "neurons", ())
                ),
                key=lambda participant: (participant.uid, participant.hotkey),
            )
        )
        if len(participants) > self.maximum_participants:
            raise ChainCollectionError("participant_limit_exceeded")
        if len({participant.uid for participant in participants}) != len(participants):
            raise ChainCollectionError("duplicate_participant_uid")
        if len({participant.hotkey for participant in participants}) != len(participants):
            raise ChainCollectionError("duplicate_participant_hotkey")

        unavailable_fields: set[str] = {"epoch.seconds_remaining"}
        network = self._build_network(
            metagraph=metagraph,
            hyperparameters=hyperparameters,
            epoch=epoch_state,
            mechanism_count=mechanism_count,
            maximum_mechanism_count=maximum_mechanism_count,
            mechanism_split=mechanism_split,
            commit_reveal_enabled=commit_reveal_enabled,
            commit_reveal_version=commit_reveal_version,
            reveal_period=reveal_period,
            pending_commit_count=pending_commit_count,
            runtime_spec_version=runtime_spec_version,
            subnet_exists=subnet_exists,
            subnet_emission_enabled=subnet_emission_enabled,
            participants=participants,
            unavailable_fields=unavailable_fields,
        )
        collected_at = _utc_datetime(self._clock(), "collection_timestamp")
        source = SourceProvenance(
            source_id=f"bittensor-finalized-sn{self.netuid}",
            source_kind="chain_finalized",
            verification_status="finalized_read",
            block=finalized_block,
        )
        return ObserverSnapshot(
            collected_at=collected_at,
            sources=(source,),
            network=network,
            participants=participants,
        )

    def _storage_reads(self, snapshot: Any) -> tuple[Any, Any, Any, Any]:
        runtime_upgrade, commit_reveal_version, max_mechanisms, networks_added = (
            _pinned_storage_descriptors()
        )
        return (
            snapshot.query(runtime_upgrade),
            snapshot.query(commit_reveal_version),
            snapshot.query(max_mechanisms),
            snapshot.query(networks_added, [self.netuid]),
        )

    @staticmethod
    def _validate_finalized_block(
        subscription_header: Any,
        block_info: Any,
        block_number: int,
    ) -> FinalizedBlock:
        if _integer(getattr(block_info, "number", None), "block_info_number") != block_number:
            raise ChainCollectionError("block_info_number_mismatch")
        subscription_raw = _mapping(
            getattr(subscription_header, "raw", None),
            "subscription_header",
        )
        info_header = _mapping(getattr(block_info, "header", None), "block_info_header")
        if _integer(subscription_raw.get("number"), "subscription_header_number") != block_number:
            raise ChainCollectionError("subscription_header_number_mismatch")
        if _integer(info_header.get("number"), "block_info_header_number") != block_number:
            raise ChainCollectionError("block_info_header_number_mismatch")

        block_hash = _block_hash(getattr(block_info, "hash", None), "finalized_block_hash")
        parent_hash = _block_hash(
            getattr(subscription_header, "parent_hash", None),
            "finalized_parent_hash",
        )
        subscription_parent = _block_hash(
            subscription_raw.get("parentHash"),
            "subscription_parent_hash",
        )
        info_parent = _block_hash(info_header.get("parentHash"), "block_info_parent_hash")
        if len({parent_hash, subscription_parent, info_parent}) != 1:
            raise ChainCollectionError("finalized_parent_hash_mismatch")

        subscription_state_root = _block_hash(
            subscription_raw.get("stateRoot"),
            "subscription_state_root",
        )
        info_state_root = _block_hash(info_header.get("stateRoot"), "block_info_state_root")
        if subscription_state_root != info_state_root:
            raise ChainCollectionError("finalized_state_root_mismatch")

        subscription_extrinsics_root = _block_hash(
            subscription_raw.get("extrinsicsRoot"),
            "subscription_extrinsics_root",
        )
        info_extrinsics_root = _block_hash(
            info_header.get("extrinsicsRoot"),
            "block_info_extrinsics_root",
        )
        if subscription_extrinsics_root != info_extrinsics_root:
            raise ChainCollectionError("finalized_extrinsics_root_mismatch")
        header_hash = info_header.get("hash")
        if (
            header_hash is not None
            and _block_hash(header_hash, "block_info_embedded_hash") != block_hash
        ):
            raise ChainCollectionError("finalized_block_hash_mismatch")

        return FinalizedBlock(
            number=str(block_number),
            hash=block_hash,
            parent_hash=parent_hash,
            state_root=subscription_state_root,
            timestamp=_utc_datetime(getattr(block_info, "timestamp", None), "block_timestamp"),
        )

    def _validate_metagraph(self, metagraph: Any, block_number: int) -> None:
        if _integer(getattr(metagraph, "netuid", None), "metagraph_netuid") != self.netuid:
            raise ChainCollectionError("metagraph_netuid_mismatch")
        if _integer(getattr(metagraph, "mechid", None), "metagraph_mechanism") != 0:
            raise ChainCollectionError("metagraph_mechanism_mismatch")
        if _integer(getattr(metagraph, "block", None), "metagraph_block") != block_number:
            raise ChainCollectionError("metagraph_block_mismatch")
        neurons = getattr(metagraph, "neurons", None)
        if isinstance(neurons, (str, bytes, bytearray)) or not isinstance(neurons, Sequence):
            raise ChainCollectionError("invalid_metagraph_neurons")
        if len(neurons) > self.maximum_participants:
            raise ChainCollectionError("participant_limit_exceeded")
        declared_uids = _integer(
            getattr(metagraph, "num_uids", None),
            "metagraph_num_uids",
            maximum=65_536,
        )
        if declared_uids != len(neurons):
            raise ChainCollectionError("metagraph_participant_count_mismatch")
        maximum_uids = _integer(
            getattr(metagraph, "max_uids", None),
            "metagraph_max_uids",
            maximum=65_536,
        )
        if maximum_uids and declared_uids > maximum_uids:
            raise ChainCollectionError("metagraph_maximum_uids_exceeded")
        for key in (
            "hotkeys",
            "active",
            "validator_permit",
            "block_at_registration",
            "last_update",
            "axons",
        ):
            _required_raw_column(metagraph, key, declared_uids)

    @staticmethod
    def _build_epoch(
        metagraph: Any,
        hyperparameters: Mapping[Any, Any],
        epoch: Mapping[Any, Any],
        block_number: int,
    ) -> EpochState:
        if _integer(epoch.get("netuid"), "epoch_netuid") != 78:
            raise ChainCollectionError("epoch_netuid_mismatch")
        if _integer(epoch.get("block"), "epoch_block") != block_number:
            raise ChainCollectionError("epoch_block_mismatch")
        tempo = _integer(epoch.get("tempo"), "epoch_tempo", minimum=1)
        metagraph_tempo = _integer(getattr(metagraph, "tempo", None), "metagraph_tempo")
        hyperparameter_tempo = _optional_integer(
            hyperparameters.get("tempo"),
            "hyperparameter_tempo",
        )
        if tempo != metagraph_tempo or (
            hyperparameter_tempo is not None and tempo != hyperparameter_tempo
        ):
            raise ChainCollectionError("epoch_tempo_mismatch")

        last_epoch_block = _integer(epoch.get("last_epoch_block"), "epoch_last_block")
        blocks_since_last_step = _integer(
            epoch.get("blocks_since_last_step"),
            "epoch_blocks_since_last_step",
        )
        if last_epoch_block != _integer(
            getattr(metagraph, "last_step", None),
            "metagraph_last_step",
        ):
            raise ChainCollectionError("epoch_last_step_mismatch")
        if blocks_since_last_step != _integer(
            getattr(metagraph, "blocks_since_last_step", None),
            "metagraph_blocks_since_last_step",
        ):
            raise ChainCollectionError("epoch_blocks_since_last_step_mismatch")

        next_epoch_start = _integer(
            epoch.get("next_epoch_start_block"),
            "epoch_next_start_block",
        )
        pending_epoch_at = _optional_integer(epoch.get("pending_epoch_at"), "epoch_pending_at")
        blocks_remaining = _integer(epoch.get("blocks_remaining"), "epoch_blocks_remaining")
        expected_remaining = max(0, next_epoch_start - block_number)
        if blocks_remaining != expected_remaining:
            raise ChainCollectionError("epoch_blocks_remaining_mismatch")

        return EpochState(
            epoch_index=str(_integer(epoch.get("epoch_index"), "epoch_index")),
            tempo_blocks=str(tempo),
            last_epoch_block=str(last_epoch_block),
            next_epoch_start_block=str(next_epoch_start),
            pending_epoch_at=None if pending_epoch_at is None else str(pending_epoch_at),
            blocks_since_last_step=str(blocks_since_last_step),
            blocks_remaining=str(blocks_remaining),
            # epoch_status derives this value from a client block-time cache,
            # not from storage at the pinned block. Do not publish it as a
            # finalized-chain fact.
            seconds_remaining=None,
        )

    @staticmethod
    def _build_mechanism_split(
        raw_value: Any,
        mechanism_count: int,
    ) -> ExactNormalizedMetric | None:
        values = _sequence(raw_value, "mechanism_emission_split")
        if not values:
            return None
        if len(values) != mechanism_count:
            raise ChainCollectionError("mechanism_emission_split_length_mismatch")
        split = _integer(
            values[0],
            "mechanism_zero_emission_split",
            maximum=_PER_U16_DENOMINATOR,
        )
        return _normalized_metric(split)

    @staticmethod
    def _build_network(
        *,
        metagraph: Any,
        hyperparameters: Mapping[Any, Any],
        epoch: EpochState,
        mechanism_count: int,
        maximum_mechanism_count: int | None,
        mechanism_split: ExactNormalizedMetric | None,
        commit_reveal_enabled: bool | None,
        commit_reveal_version: int | None,
        reveal_period: int | None,
        pending_commit_count: int,
        runtime_spec_version: int | None,
        subnet_exists: bool | None,
        subnet_emission_enabled: bool | None,
        participants: tuple[ChainParticipant, ...],
        unavailable_fields: set[str],
    ) -> ChainNetworkSnapshot:
        name = _optional_public_text(getattr(metagraph, "name", None), "subnet_name")
        symbol = _optional_public_text(
            getattr(metagraph, "symbol", None),
            "subnet_symbol",
            maximum_bytes=64,
        )
        if name is None:
            unavailable_fields.add("name")
        if symbol is None:
            unavailable_fields.add("symbol")
        identity = _identity_name(metagraph, unavailable_fields)
        price = _exchange_rate(metagraph, unavailable_fields)
        if mechanism_split is None:
            unavailable_fields.add("mechanism_emission_split")
        if commit_reveal_enabled is None:
            unavailable_fields.add("commit_reveal_enabled")
        if commit_reveal_version is None:
            unavailable_fields.add("commit_reveal_version")
        if maximum_mechanism_count is None:
            unavailable_fields.add("maximum_mechanism_count")
        if reveal_period in (None, 0):
            reveal_period = None
            unavailable_fields.add("reveal_period_epochs")
        if runtime_spec_version is None:
            unavailable_fields.add("runtime_spec_version")
        if subnet_exists is None:
            unavailable_fields.add("subnet_exists")
        if subnet_emission_enabled is None:
            unavailable_fields.add("subnet_emission_enabled")

        hyperparameter_commit_reveal = _boolean_flag(
            hyperparameters.get("commit_reveal_weights_enabled"),
            "hyperparameter_commit_reveal_enabled",
        )
        if (
            hyperparameter_commit_reveal is not None
            and commit_reveal_enabled is not None
            and hyperparameter_commit_reveal != commit_reveal_enabled
        ):
            raise ChainCollectionError("commit_reveal_enabled_mismatch")
        hyperparameter_reveal_period = _optional_integer(
            hyperparameters.get("commit_reveal_period"),
            "hyperparameter_commit_reveal_period",
        )
        if (
            hyperparameter_reveal_period is not None
            and reveal_period is not None
            and hyperparameter_reveal_period != reveal_period
        ):
            raise ChainCollectionError("reveal_period_mismatch")

        subnet_started = _boolean_flag(
            hyperparameters.get("subnet_is_active"),
            "subnet_started",
        )
        if subnet_started is None:
            unavailable_fields.add("subnet_started")

        min_allowed_weights = _hyperparameter_integer(
            hyperparameters,
            "min_allowed_weights",
            unavailable_fields,
        )
        weights_version = _hyperparameter_integer(
            hyperparameters,
            "weights_version",
            unavailable_fields,
            public_name="weights_version_key",
        )
        weights_rate_limit = _hyperparameter_integer(
            hyperparameters,
            "weights_rate_limit",
            unavailable_fields,
            public_name="weights_rate_limit_blocks",
        )
        immunity_period = _hyperparameter_integer(
            hyperparameters,
            "immunity_period",
            unavailable_fields,
            public_name="immunity_period_blocks",
        )
        activity_cutoff = _hyperparameter_integer(
            hyperparameters,
            "activity_cutoff",
            unavailable_fields,
            public_name="activity_cutoff_blocks",
        )
        maximum_weight_raw = _optional_integer(
            hyperparameters.get("max_weights_limit"),
            "hyperparameter_max_weights_limit",
            maximum=_PER_U16_DENOMINATOR,
        )
        maximum_weight = _normalized_metric(maximum_weight_raw)
        if maximum_weight is None:
            unavailable_fields.add("hyperparameters.maximum_weight")

        maximum_uids = _integer(
            getattr(metagraph, "max_uids", None),
            "metagraph_max_uids",
            maximum=65_536,
        )
        if maximum_uids == 0:
            maximum_uids_value = None
            unavailable_fields.add("counts.maximum_uids")
        else:
            maximum_uids_value = maximum_uids

        validator_count = sum(participant.validator_permit for participant in participants)
        active_count = sum(participant.chain_active for participant in participants)
        serving_count = sum(participant.serving_announced for participant in participants)
        return ChainNetworkSnapshot(
            name=name,
            symbol=symbol,
            identity=identity,
            runtime_spec_version=(
                None if runtime_spec_version is None else str(runtime_spec_version)
            ),
            mechanism_count=mechanism_count,
            maximum_mechanism_count=maximum_mechanism_count,
            mechanism_emission_split=mechanism_split,
            commit_reveal_enabled=commit_reveal_enabled,
            commit_reveal_version=(
                None if commit_reveal_version is None else str(commit_reveal_version)
            ),
            reveal_period_epochs=None if reveal_period is None else str(reveal_period),
            pending_weight_commit_count=pending_commit_count,
            subnet_exists=subnet_exists,
            subnet_started=subnet_started,
            subnet_emission_enabled=subnet_emission_enabled,
            price=price,
            epoch=epoch,
            counts=NetworkCounts(
                registered=len(participants),
                chain_active=active_count,
                miners=len(participants) - validator_count,
                validators=validator_count,
                serving_announced=serving_count,
                maximum_uids=maximum_uids_value,
            ),
            hyperparameters=NetworkHyperparameters(
                min_allowed_weights=min_allowed_weights,
                weights_version_key=(None if weights_version is None else str(weights_version)),
                weights_rate_limit_blocks=(
                    None if weights_rate_limit is None else str(weights_rate_limit)
                ),
                immunity_period_blocks=(None if immunity_period is None else str(immunity_period)),
                activity_cutoff_blocks=(None if activity_cutoff is None else str(activity_cutoff)),
                maximum_weight=maximum_weight,
            ),
            unavailable_fields=tuple(sorted(unavailable_fields)),
        )
