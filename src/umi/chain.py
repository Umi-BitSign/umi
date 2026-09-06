"""Read-only Bittensor discovery for the UMI component runtime."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import ipaddress
import math
import re
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH

_BLOCK_HASH = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_BYTES = re.compile(r"^0x(?:[0-9a-f]{2})+$")
_FINNEY_GENESIS_HASH = f"0x{FINNEY_GENESIS_HASH}"
_MAX_HEADER_BYTES = 1024 * 1024
_MAX_FINALIZED_FUTURE_SKEW_MS = 30_000
_MAX_FINALIZED_HEAD_AGE_MS = 120_000


@dataclass(frozen=True)
class MinerEndpoint:
    hotkey: str
    uid: int
    origin: str
    validator_permit: bool


@dataclass(frozen=True, slots=True)
class FinalizedMinerEndpoint:
    """One public miner origin resolved from a single finalized SDK snapshot."""

    hotkey: str
    uid: int
    origin: str
    validator_permit: bool
    network: Literal["finney"]
    genesis_block_hash: str
    finalized_block_number: int
    finalized_block_hash: str
    finalized_block_timestamp_ms: int


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"finalized miner discovery returned invalid {label}")
    return value


def _block_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _BLOCK_HASH.fullmatch(value) is None:
        raise ValueError(f"finalized miner discovery returned invalid {label}")
    return value


def _mapping(value: Any, label: str) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"finalized miner discovery returned invalid {label}")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError(f"finalized miner discovery returned invalid {label}")
    return value


def _scale_compact_u64(value: Any, label: str) -> bytes:
    integer = _integer(value, label)
    if integer > (1 << 64) - 1:
        raise ValueError(f"finalized miner discovery returned invalid {label}")
    if integer < 1 << 6:
        return bytes((integer << 2,))
    if integer < 1 << 14:
        return ((integer << 2) | 1).to_bytes(2, "little")
    if integer < 1 << 30:
        return ((integer << 2) | 2).to_bytes(4, "little")
    encoded = integer.to_bytes((integer.bit_length() + 7) // 8, "little")
    return bytes((((len(encoded) - 4) << 2) | 3,)) + encoded


def _hex_bytes(value: Any, label: str, *, maximum_bytes: int) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) > 2 + maximum_bytes * 2
        or _HEX_BYTES.fullmatch(value) is None
    ):
        raise ValueError(f"finalized miner discovery returned invalid {label}")
    return bytes.fromhex(value[2:])


def _header_hash(header: Mapping[Any, Any], label: str) -> str:
    """Hash one JSON-RPC header from its canonical SCALE encoding."""

    digest = _mapping(header.get("digest"), f"{label} digest")
    logs = _sequence(digest.get("logs"), f"{label} digest logs")
    encoded = bytearray()
    encoded.extend(bytes.fromhex(_block_hash(header.get("parentHash"), f"{label} parent hash")[2:]))
    encoded.extend(_scale_compact_u64(header.get("number"), f"{label} number"))
    encoded.extend(bytes.fromhex(_block_hash(header.get("stateRoot"), f"{label} state root")[2:]))
    encoded.extend(
        bytes.fromhex(_block_hash(header.get("extrinsicsRoot"), f"{label} extrinsics root")[2:])
    )
    encoded.extend(_scale_compact_u64(len(logs), f"{label} digest count"))
    for index, log in enumerate(logs):
        encoded.extend(
            _hex_bytes(
                log,
                f"{label} digest log {index}",
                maximum_bytes=_MAX_HEADER_BYTES - len(encoded),
            )
        )
    return "0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest()


async def _connected_block_hash(client: Any, block: int) -> str:
    """Read a block hash through the SDK's connected Substrate contract."""

    substrate = getattr(client, "_substrate", None)
    reader = getattr(substrate, "block_hash", None)
    if not callable(reader):
        raise ValueError("finalized miner discovery cannot verify chain identity")
    return _block_hash(await reader(block), "connected block hash")


async def _finalized_header(client: Any, timeout_seconds: float) -> Any:
    stream: AsyncIterator[Any] = client.blocks(finalized=True)
    try:
        return await asyncio.wait_for(anext(stream), timeout_seconds)
    except asyncio.TimeoutError as error:
        raise RuntimeError("finalized miner discovery timed out") from error
    finally:
        close = getattr(stream, "aclose", None)
        if close is not None:
            with contextlib.suppress(Exception):
                result = close()
                if inspect.isawaitable(result):
                    await result


def _timestamp_ms(value: Any) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("finalized miner discovery returned invalid block timestamp")
    utc = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = utc - epoch
    milliseconds = delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000
    if milliseconds < 0:
        raise ValueError("finalized miner discovery returned a pre-epoch block timestamp")
    return milliseconds


def _public_axon_origin(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("miner hotkey has no valid served endpoint")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("miner served endpoint contains a control character")
    candidate = value if value.startswith("https://") else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        raise ValueError("miner served endpoint is not a public IP and port") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65_535
        or not address.is_global
    ):
        raise ValueError("miner served endpoint is not a public IP and port")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"https://{host}:{port}"


def _default_client_factory(network: str) -> Any:
    import bittensor as bt

    return bt.Client(network)


async def discover_miner_finalized(
    hotkey: str,
    *,
    network: Literal["finney"] = "finney",
    netuid: int = 78,
    finalized_timeout_seconds: float = 20.0,
    client_factory: Callable[[str], Any] | None = None,
    now: datetime | None = None,
) -> FinalizedMinerEndpoint:
    """Resolve one SN78 miner and axon from one internally checked finalized block.

    This is a Finney-genesis-bound finalized SDK observation, not a storage-proof
    verification. The returned block identity lets public evidence state that
    boundary exactly.
    """

    if netuid != 78:
        raise ValueError("the version 0.1 component profile is pinned to SN78")
    if network != "finney":
        raise ValueError("public finalized miner discovery is pinned to Finney")
    if (
        isinstance(finalized_timeout_seconds, bool)
        or not isinstance(finalized_timeout_seconds, (int, float))
        or not math.isfinite(finalized_timeout_seconds)
        or not 0 < finalized_timeout_seconds <= 300
    ):
        raise ValueError("finalized timeout must be finite and in (0, 300]")
    try:
        expected_account = account_id32(hotkey)
    except ValueError as error:
        raise ValueError("miner hotkey is not a valid SS58 account") from error
    now_ms = None if now is None else _timestamp_ms(now)

    factory = client_factory or _default_client_factory
    async with factory(network) as client:
        genesis_hash = await _connected_block_hash(client, 0)
        if genesis_hash != _FINNEY_GENESIS_HASH:
            raise ValueError("finalized miner discovery is not connected to Finney")
        header = await _finalized_header(client, float(finalized_timeout_seconds))
        block_number = _integer(getattr(header, "number", None), "block number")
        snapshot = await client.at(block_number)
        if _integer(getattr(snapshot, "block", None), "snapshot block") != block_number:
            raise ValueError("finalized miner snapshot block mismatch")
        block_info, metagraph = await asyncio.gather(
            snapshot.block_info(),
            snapshot.subnets.metagraph(netuid=netuid, commitments=False),
        )

    if block_info is None or metagraph is None:
        raise ValueError("finalized miner snapshot is incomplete")
    if _integer(getattr(block_info, "number", None), "block-info number") != block_number:
        raise ValueError("finalized miner block-info number mismatch")
    header_raw = _mapping(getattr(header, "raw", None), "subscription header")
    info_header = _mapping(getattr(block_info, "header", None), "block-info header")
    if _integer(header_raw.get("number"), "subscription header number") != block_number:
        raise ValueError("finalized miner subscription header number mismatch")
    if _integer(info_header.get("number"), "block-info header number") != block_number:
        raise ValueError("finalized miner block-info header number mismatch")
    for field, label in (
        ("parentHash", "parent hash"),
        ("stateRoot", "state root"),
        ("extrinsicsRoot", "extrinsics root"),
    ):
        if _block_hash(header_raw.get(field), label) != _block_hash(info_header.get(field), label):
            raise ValueError(f"finalized miner {label} mismatch")
    parent_hash = _block_hash(getattr(header, "parent_hash", None), "header parent hash")
    if parent_hash != _block_hash(header_raw.get("parentHash"), "subscription parent hash"):
        raise ValueError("finalized miner parent hash mismatch")
    finalized_hash = _block_hash(getattr(block_info, "hash", None), "block hash")
    if _header_hash(header_raw, "subscription header") != finalized_hash:
        raise ValueError("finalized miner subscription header hash mismatch")
    if _header_hash(info_header, "block-info header") != finalized_hash:
        raise ValueError("finalized miner block-info header hash mismatch")
    embedded_hash = info_header.get("hash")
    if (
        embedded_hash is not None
        and _block_hash(embedded_hash, "embedded block hash") != finalized_hash
    ):
        raise ValueError("finalized miner block hash mismatch")
    finalized_timestamp_ms = _timestamp_ms(getattr(block_info, "timestamp", None))
    observed_now_ms = _timestamp_ms(datetime.now(timezone.utc)) if now_ms is None else now_ms
    if finalized_timestamp_ms < observed_now_ms - _MAX_FINALIZED_HEAD_AGE_MS:
        raise ValueError("finalized miner discovery returned a stale finalized head")
    if finalized_timestamp_ms > observed_now_ms + _MAX_FINALIZED_FUTURE_SKEW_MS:
        raise ValueError("finalized miner discovery returned a future-dated finalized head")

    if _integer(getattr(metagraph, "netuid", None), "metagraph netuid") != netuid:
        raise ValueError("finalized miner metagraph netuid mismatch")
    if _integer(getattr(metagraph, "mechid", None), "metagraph mechanism") != 0:
        raise ValueError("finalized miner metagraph mechanism mismatch")
    if _integer(getattr(metagraph, "block", None), "metagraph block") != block_number:
        raise ValueError("finalized miner metagraph block mismatch")
    neurons = _sequence(getattr(metagraph, "neurons", None), "metagraph neurons")
    if _integer(getattr(metagraph, "num_uids", None), "metagraph UID count") != len(neurons):
        raise ValueError("finalized miner metagraph UID count mismatch")
    raw = _mapping(getattr(metagraph, "raw", None), "metagraph raw values")
    raw_hotkeys = _sequence(raw.get("hotkeys"), "metagraph raw hotkeys")
    raw_permits = _sequence(raw.get("validator_permit"), "metagraph raw validator permits")
    if len(raw_hotkeys) != len(neurons) or len(raw_permits) != len(neurons):
        raise ValueError("finalized miner metagraph raw column length mismatch")

    matches: list[Any] = []
    for neuron in neurons:
        try:
            neuron_account = account_id32(str(getattr(neuron, "hotkey", "")))
        except ValueError:
            continue
        if neuron_account == expected_account:
            matches.append(neuron)
    if len(matches) != 1:
        raise ValueError("miner hotkey is not uniquely registered on SN78")
    neuron = matches[0]
    uid = _integer(getattr(neuron, "uid", None), "miner UID")
    if uid >= len(neurons):
        raise ValueError("miner UID is outside the finalized metagraph")
    try:
        raw_account = account_id32(str(raw_hotkeys[uid]))
    except ValueError as error:
        raise ValueError("finalized metagraph raw hotkey is invalid") from error
    if raw_account != expected_account:
        raise ValueError("finalized metagraph UID does not bind the requested hotkey")
    raw_permit = raw_permits[uid]
    typed_permit = getattr(neuron, "validator_permit", None)
    if not isinstance(raw_permit, bool) or not isinstance(typed_permit, bool):
        raise ValueError("finalized miner validator permit is not a boolean")
    if raw_permit != typed_permit:
        raise ValueError("finalized miner validator permit mismatch")
    observed_hotkey = str(getattr(neuron, "hotkey", ""))
    return FinalizedMinerEndpoint(
        hotkey=observed_hotkey,
        uid=uid,
        origin=_public_axon_origin(getattr(neuron, "axon", None)),
        validator_permit=typed_permit,
        network="finney",
        genesis_block_hash=genesis_hash,
        finalized_block_number=block_number,
        finalized_block_hash=finalized_hash,
        finalized_block_timestamp_ms=finalized_timestamp_ms,
    )


async def discover_miner(
    hotkey: str,
    *,
    network: str = "finney",
    netuid: int = 78,
) -> MinerEndpoint:
    """Resolve one registered miner endpoint without submitting any transaction."""

    if netuid != 78:
        raise ValueError("the version 0.1 component profile is pinned to SN78")
    import bittensor as bt

    async with bt.Subtensor(network) as client:
        metagraph = await client.subnets.metagraph(netuid=netuid)
    neuron = metagraph.by_hotkey(hotkey)
    if neuron is None:
        raise ValueError("miner hotkey is not registered on SN78")
    if neuron.validator_permit:
        raise ValueError("validator-permit hotkeys are not component miner candidates")
    if neuron.axon is None:
        raise ValueError("miner hotkey has no served endpoint")
    endpoint = str(neuron.axon)
    if endpoint.startswith("https://"):
        origin = endpoint
    elif endpoint.startswith("http://"):
        origin = "https://" + endpoint.removeprefix("http://")
    else:
        origin = "https://" + endpoint
    return MinerEndpoint(
        hotkey=neuron.hotkey,
        uid=neuron.uid,
        origin=origin,
        validator_permit=bool(neuron.validator_permit),
    )
