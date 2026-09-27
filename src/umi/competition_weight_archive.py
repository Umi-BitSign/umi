"""Bounded original weight evidence for historical transaction review.

An archive is an untrusted transport. Its caller authenticates the historical
header and runtime, then verifies every retained storage proof before use.
"""

import json

from .competition_reward_transactions import MAX_CONTEXT_BYTES
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext


class WeightStateArchive:
    """Bounded storage answers from one retained snapshot, without RPC fallback."""

    def __init__(self, raw, runtime, config, control_raw=None):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTEXT_BYTES:
            raise ValueError("standing recovery evidence exceeds its bound")
        body = json.loads(raw)
        required = {
            "schema",
            "config_sha256",
            "block",
            "block_hash",
            "state_root",
            "finality",
            "runtime_metadata_sha256",
            "runtime_version",
            "storage_batches",
            "pending_commitment_absence_proven",
        }
        optional = {"storage_codec_mode", "runtime_execution", "registrations_complete"}
        if (
            type(body) is not dict
            or not required <= set(body) <= required | optional
            or canonical_json_bytes(body) != raw
            or body["schema"] != "umi-competition-weight-state-evidence/1"
            or body["config_sha256"] != digest(config)
            or body["pending_commitment_absence_proven"] is not False
            or ("registrations_complete" in body and body["registrations_complete"] is not True)
        ):
            raise ValueError("standing recovery requires exact native weight evidence")
        ref = runtime.snapshot
        finality = body["finality"]
        control_finality = (
            json.loads(control_raw)["finality"] if control_raw is not None else finality
        )
        if (
            (body["block"], body["block_hash"], body["state_root"])
            != (ref.block_number, ref.block_hash, ref.state_root)
            or type(body["block"]) is not int
            or body["runtime_metadata_sha256"] != runtime.metadata_sha256
            or body["runtime_version"] != json.loads(runtime.runtime_version_bytes)
            or body.get("storage_codec_mode", "exact_runtime") != runtime.storage_codec_mode
            or type(finality) is not dict
            or any(
                finality.get(k) != control_finality.get(k)
                for k in ("genesis_hash", "evidence_class", "offline_finality_proof", "block")
            )
        ):
            raise ValueError("standing weight evidence differs from owned historical context")
        self.snapshot, self.values, self.proofs = ref, {}, {}
        batches = body["storage_batches"]
        if type(batches) is not list or not 1 <= len(batches) <= 4:
            raise ValueError("standing weight evidence has invalid batch coverage")
        self.batches = []
        for batch in batches:
            if (
                type(batch) is not dict
                or set(batch) != {"state_root", "claims", "proof"}
                or batch["state_root"] != ref.state_root
                or type(batch["claims"]) is not list
                or not 1 <= len(batch["claims"]) <= 256
            ):
                raise ValueError("standing weight evidence has invalid storage batch")
            keys = []
            for claim in batch["claims"]:
                if type(claim) is not dict or set(claim) != {"key", "value"}:
                    raise ValueError("standing recovery claim is malformed")
                key, value = claim["key"], claim["value"]
                _hex(key, 4096)
                if value is not None:
                    _hex(value, MAX_CONTEXT_BYTES, empty=True)
                if key in self.values and self.values[key] != value:
                    raise ValueError("standing recovery repeats a conflicting claim")
                self.values[key] = value
                keys.append(key)
            if keys != sorted(set(keys)) or tuple(keys) in self.proofs:
                raise ValueError("standing recovery repeats or reorders a proof batch")
            self.proofs[tuple(keys)] = batch["proof"]
            self.batches.append(tuple(bytes.fromhex(k[2:]) for k in keys))
        execution = body.get("runtime_execution")
        if isinstance(runtime, ExecutedRuntimeContext):
            if (
                type(execution) is not dict
                or set(execution)
                != {
                    "executor_sha256",
                    "block",
                    "block_hash",
                    "parent_hash",
                    "state_root",
                    "key",
                    "value",
                    "proof",
                }
                or (
                    execution["block"],
                    execution["block_hash"],
                    execution["parent_hash"],
                    execution["state_root"],
                    execution["key"],
                    execution["executor_sha256"],
                )
                != (
                    ref.block_number,
                    ref.block_hash,
                    ref.parent_hash,
                    ref.state_root,
                    "0x3a636f6465",
                    runtime.executor_sha256,
                )
                or execution["value"] != "0x" + runtime.code_evidence.value.hex()
                or execution["key"] in self.values
            ):
                raise ValueError("standing recovery runtime code differs from owned execution")
            self.values[execution["key"]] = execution["value"]
            self.proofs[(execution["key"],)] = execution["proof"]
        elif execution is not None:
            raise ValueError("standing recovery has unexpected runtime execution evidence")
        self.body = body

    async def request(self, method, params):
        if len(params) != 2 or params[-1] != self.snapshot.block_hash:
            raise ValueError("standing recovery cannot read another snapshot")
        if method == "state_getStorageAt" and params[0] in self.values:
            return self.values[params[0]]
        if method == "state_getReadProof" and tuple(params[0]) in self.proofs:
            return {"at": self.snapshot.block_hash, "proof": self.proofs[tuple(params[0])]}
        raise ValueError("standing recovery lacks the requested original storage evidence")


def _hex(value, maximum, *, empty=False):
    if type(value) is not str or not value.startswith("0x") or len(value) > 2 + maximum * 2:
        raise ValueError("standing recovery storage hex is invalid")
    raw = bytes.fromhex(value[2:])
    if "0x" + raw.hex() != value or (not raw and not empty):
        raise ValueError("standing recovery storage hex is noncanonical")
    return raw
