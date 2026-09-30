"""Real SCALE and signature verification; checkpoint identities are test inputs."""

import gzip
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import bittensor_core
import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.signed_extrinsic import (
    encode_mortal_call,
    encode_verified_mortal_call,
    verify_mortal_call,
)
from umi.validator_chain import FinalizedRuntimePin, PinnedRuntimeContext


@pytest.fixture
def native_encoding():
    root = Path(__file__).parent / "fixtures" / "transaction-codec"
    meta = json.loads((root / "provenance.json").read_text())
    raw = gzip.decompress((root / "metadata.scale.gz").read_bytes())
    assert hashlib.sha256(raw).hexdigest() == meta["metadata_sha256"]
    runtime = PinnedRuntimeContext(
        snapshot=FinalizedSnapshotRef(123, "0x" + "22" * 32, "0x" + "33" * 32, "0x" + "44" * 32),
        pin=FinalizedRuntimePin(
            meta["metadata_sha256"], meta["spec_version"], meta["transaction_version"], 1
        ),
        metadata_bytes=raw,
        runtime_version_bytes=b"{}",
        _runtime=bittensor_core.Runtime(raw, meta["spec_version"], meta["transaction_version"]),
    )
    call = bt.calls.SubtensorModule.set_mechanism_weights(
        netuid=78,
        mecid=0,
        dests=[0, 1, 2],
        weights=[0, 20000, 45535],
        version_key=1,
    )
    signer = bt.sp_core.Keypair.from_uri("//Alice", crypto_type=1)
    return SimpleNamespace(
        call=call,
        signer=signer,
        context=dict(
            runtime=runtime,
            validator_hotkey=signer.ss58_address,
            nonce=4,
            mortality_period=128,
            genesis_hash=meta["genesis_hash"],
        ),
    )


@pytest.mark.parametrize("period", [4, 8, 128, 4096])
@pytest.mark.parametrize("position", ["before_wrap", "wrap", "after_wrap"])
@pytest.mark.parametrize("scheme", [0, 1])
def test_real_encoded_mortality_and_signature_at_wrap_boundaries(
    native_encoding, period, position, scheme
):
    item = native_encoding
    signer = bt.sp_core.Keypair.from_uri("//Alice", crypto_type=scheme)
    birth = 3 * period + {"before_wrap": -1, "wrap": 0, "after_wrap": 1}[position]
    runtime = item.context["runtime"]
    context = {
        **item.context,
        "mortality_period": period,
        "validator_hotkey": signer.ss58_address,
        "runtime": replace(runtime, snapshot=replace(runtime.snapshot, block_number=birth)),
    }
    signed = []

    def sign(payload):
        signed.append(payload)
        return signer.sign(payload)

    port = SimpleNamespace(ss58_address=signer.ss58_address, crypto_type=scheme, sign=sign)
    encoded = encode_verified_mortal_call(item.call, signer=port, **context)
    assert len(signed) == 1
    decoded = runtime._runtime.decode_extrinsic(encoded, True)
    assert decoded["era"] == (period, birth % period)
    assert decoded["nonce"] == context["nonce"]
    arguments = {a["name"]: a["value"] for a in decoded["call"]["call_args"]}
    assert arguments == item.call.params
    assert verify_mortal_call(encoded, item.call, **context).data == encoded
    assert len(signed) == 1  # Rechecking retained bytes never signs again.


@pytest.mark.parametrize(
    "change", ["nonce", "era", "address", "genesis", "checkpoint", "later_cycle", "call", "version"]
)
def test_retained_bytes_cannot_be_rebound_to_another_intent(native_encoding, change):
    item = native_encoding
    encoded = encode_verified_mortal_call(item.call, signer=item.signer, **item.context)
    context, call = dict(item.context), item.call
    runtime = context["runtime"]
    if change == "nonce":
        context["nonce"] += 1
    elif change == "era":
        context["mortality_period"] *= 2
    elif change == "address":
        context["validator_hotkey"] = bt.sp_core.Keypair.from_uri("//Bob").ss58_address
    elif change == "genesis":
        context["genesis_hash"] = "0x" + "55" * 32
    elif change in {"checkpoint", "later_cycle"}:
        snapshot = replace(
            runtime.snapshot,
            block_hash="0x" + "55" * 32,
            block_number=runtime.snapshot.block_number + (128 if change == "later_cycle" else 0),
        )
        context["runtime"] = replace(runtime, snapshot=snapshot)
    elif change == "version":
        context["runtime"] = replace(
            runtime, _runtime=bittensor_core.Runtime(runtime.metadata_bytes, 447, 1)
        )
    else:
        call = bt.calls.SubtensorModule.set_mechanism_weights(
            netuid=78,
            mecid=0,
            dests=[0, 1, 2],
            weights=[0, 20001, 45534],
            version_key=1,
        )
    with pytest.raises(ValueError, match="signed transaction"):
        verify_mortal_call(encoded, call, **context)


@pytest.mark.parametrize(
    "alteration", ["unsigned", "immortal", "tip", "signature", "suffix", "truncated", "length"]
)
def test_changed_encoding_is_rejected(native_encoding, alteration):
    item = native_encoding
    encoded = encode_mortal_call(item.call, signer=item.signer, **item.context)
    runtime = item.context["runtime"]._runtime
    if alteration in {"unsigned", "immortal", "tip", "signature"}:
        decoded = runtime.decode_extrinsic(encoded, True)
        signature = bytes.fromhex(decoded["signature"]["Sr25519"][2:])
        encoded, _ = runtime.encode_signed_extrinsic(
            runtime.compose_call(item.call.module, item.call.function, item.call.params),
            public_key=bytes(item.signer.public_key),
            signature=signature if alteration != "signature" else bytes(64),
            signature_version=1,
            era="00" if alteration == "immortal" else {"period": 128, "current": 123},
            nonce=4,
            tip=1 if alteration == "tip" else 0,
            tip_asset_id=None,
            metadata_hash_enabled=False,
        )
        encoded = bytes(encoded)
        if alteration == "unsigned":
            # This fixture has a two-byte compact body length, then signed v4.
            assert encoded[2] == 0x84
            encoded = encoded[:2] + b"\x04" + encoded[3:]
    elif alteration == "suffix":
        encoded += b"\x00"
    elif alteration == "truncated":
        encoded = encoded[:-1]
    else:
        encoded = bytes([encoded[0] ^ 4]) + encoded[1:]
    with pytest.raises(ValueError):
        verify_mortal_call(encoded, item.call, **item.context)


def test_bad_signer_output_is_never_returned_as_verified(native_encoding):
    item = native_encoding
    signer = SimpleNamespace(
        ss58_address=item.signer.ss58_address, crypto_type=1, sign=lambda _: bytes(64)
    )
    with pytest.raises(ValueError, match="original checkpoint"):
        encode_verified_mortal_call(item.call, signer=signer, **item.context)


@pytest.mark.parametrize("nonce", [0, 63, 64, 16383, 16384, 2**32 - 1])
def test_native_compact_nonce_boundaries(native_encoding, nonce):
    item = native_encoding
    context = {**item.context, "nonce": nonce}
    encoded = encode_verified_mortal_call(item.call, signer=item.signer, **context)
    assert item.context["runtime"]._runtime.decode_extrinsic(encoded, True)["nonce"] == nonce
    assert verify_mortal_call(encoded, item.call, **context).data == encoded
