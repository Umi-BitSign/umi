"""Recover header identities by hashing backwards from an owned finalized anchor.

RPC headers are untrusted. Each encoded header must hash to the parent committed
by the preceding verified header. This does not manufacture observer transcripts
or claim when the historical header was locally received. Timestamp membership
must be verified separately against the recovered state root.
"""

from __future__ import annotations

import json
import re

from .chain_evidence import FinalizedSnapshotRef
from .grandpa_finality import EVIDENCE_CLASS, _decode_header
from .validator_plans import VerifiedFinalizedBlock

MAXIMUM_DISTANCE = 2048
MAXIMUM_HEADER_BYTES = 64 * 1024
MAXIMUM_PATH_BYTES = 1024 * 1024
_HASH = re.compile(r"0x[0-9a-f]{64}")
_HEX = re.compile(r"0x(?:[0-9a-f]{2})*")


def _compact(value):
    if type(value) is not int or not 0 <= value < 2**53:
        raise ValueError("header integer outside bounds")
    if value < 64:
        return bytes((value << 2,))
    if value < 16384:
        return ((value << 2) | 1).to_bytes(2, "little")
    if value < 2**30:
        return ((value << 2) | 2).to_bytes(4, "little")
    size = (value.bit_length() + 7) // 8
    return bytes((((size - 4) << 2) | 3,)) + value.to_bytes(size, "little")


def encode_rpc_header(value):
    """Encode the generic Substrate header, with bounded opaque digest items."""
    if not isinstance(value, dict) or set(value) != {
        "parentHash",
        "number",
        "stateRoot",
        "extrinsicsRoot",
        "digest",
    }:
        raise ValueError("invalid RPC header fields")
    for key in ("parentHash", "stateRoot", "extrinsicsRoot"):
        if not isinstance(value[key], str) or _HASH.fullmatch(value[key]) is None:
            raise ValueError("invalid RPC header hash")
    number = value["number"]
    if not isinstance(number, str) or re.fullmatch(r"0x[0-9a-f]{1,14}", number) is None:
        raise ValueError("invalid RPC header height")
    digest = value["digest"]
    if not isinstance(digest, dict) or set(digest) != {"logs"}:
        raise ValueError("invalid RPC digest")
    logs = digest["logs"]
    if not isinstance(logs, list) or len(logs) > 1024:
        raise ValueError("RPC digest count exceeds bounds")
    encoded = bytearray(bytes.fromhex(value["parentHash"][2:]))
    encoded.extend(_compact(int(number, 16)))
    encoded.extend(bytes.fromhex(value["stateRoot"][2:]))
    encoded.extend(bytes.fromhex(value["extrinsicsRoot"][2:]))
    encoded.extend(_compact(len(logs)))
    for item in logs:
        if (
            not isinstance(item, str)
            or len(item) > 2 + 2 * MAXIMUM_HEADER_BYTES
            or _HEX.fullmatch(item) is None
            or item == "0x"
        ):
            raise ValueError("invalid RPC digest item")
        encoded.extend(bytes.fromhex(item[2:]))
        if len(encoded) > MAXIMUM_HEADER_BYTES:
            raise ValueError("RPC header exceeds byte bound")
    return "0x" + encoded.hex()


async def recover_header_path(anchor, height, request, *, maximum_distance=MAXIMUM_DISTANCE):
    if not isinstance(anchor, VerifiedFinalizedBlock):
        raise TypeError("ancestry requires an owned verified anchor")
    if (
        type(height) is not int
        or type(maximum_distance) is not int
        or not 1 <= maximum_distance <= MAXIMUM_DISTANCE
        or not 1 <= anchor.height - height <= maximum_distance
        or height < 1
    ):
        raise ValueError("historical header outside recovery bounds")
    record = json.loads(anchor.finality_evidence)
    if record.get("evidence_class") != EVIDENCE_CLASS:
        raise ValueError("ancestry anchor must be an original observer record")
    decoded = _decode_header(record["block"]["scale_header"], maximum_bytes=MAXIMUM_HEADER_BYTES)
    if (decoded["number"], decoded["hash"], decoded["state_root"]) != (
        anchor.height,
        anchor.block_hash,
        anchor.state_root,
    ):
        raise ValueError("ancestry anchor identity mismatch")
    path, total = [], 0
    for expected_height in range(anchor.height - 1, height - 1, -1):
        expected_hash = decoded["parent_hash"]
        encoded = encode_rpc_header(await request("chain_getHeader", (expected_hash,)))
        total += (len(encoded) - 2) // 2
        if total > MAXIMUM_PATH_BYTES:
            raise ValueError("historical header path exceeds byte bound")
        decoded = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        if decoded["hash"] != expected_hash or decoded["number"] != expected_height:
            raise ValueError("historical header does not match finalized ancestry")
        path.append(encoded)
    return FinalizedSnapshotRef(
        decoded["number"], decoded["hash"], decoded["parent_hash"], decoded["state_root"]
    ), tuple(path)
