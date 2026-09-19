"""Encoding uses an authenticated snapshot supplied by its policy owner."""

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.encoding import account_id32
from umi.signed_extrinsic import encode_mortal_call, exact_signed_extrinsic
from umi.validator_chain import (
    FinalizedRuntimePin,
    PinnedRuntimeContext,
    ReviewedStorageCodecContext,
)

_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
_OTHER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
_GENESIS = "0x" + "11" * 32


@pytest.fixture
def encoding():
    calls, signatures = [], []

    class Codec:
        def compose_call(self, module, function, params):
            calls.append(("compose", module, function, params))
            return b"raw-call-including-zero-weights"

        def signature_payload(self, call, **options):
            calls.append(("payload", call, options))
            return b"fixture-payload"

        def encode_signed_extrinsic(self, call, **options):
            calls.append(("encode", call, options))
            encoded = b"fixture-scale:" + call + options["signature"]
            return encoded, hashlib.blake2b(encoded, digest_size=32).digest()

    def sign(payload):
        signatures.append(payload)
        return b"s" * 64

    signer = SimpleNamespace(ss58_address=_HOTKEY, crypto_type=1, sign=sign)
    runtime = PinnedRuntimeContext(
        snapshot=FinalizedSnapshotRef(123, "0x" + "22" * 32, "0x" + "33" * 32, "0x" + "44" * 32),
        pin=FinalizedRuntimePin(hashlib.sha256(b"metadata").hexdigest(), 1, 1, 1),
        metadata_bytes=b"metadata",
        runtime_version_bytes=b"{}",
        _runtime=Codec(),
    )
    return SimpleNamespace(
        call=SimpleNamespace(
            module="SubtensorModule", function="set_mechanism_weights", params={"weights": [0, 1]}
        ),
        runtime=runtime,
        signer=signer,
        calls=calls,
        signatures=signatures,
    )


def encode(item, **changes):
    options = dict(
        runtime=item.runtime,
        signer=item.signer,
        validator_hotkey=_HOTKEY,
        nonce=4,
        mortality_period=8,
        genesis_hash=_GENESIS,
    )
    options.update(changes)
    return encode_mortal_call(item.call, **options)


@pytest.mark.parametrize("period", [4, 8, 4096])
@pytest.mark.parametrize("nonce", [0, 2**32 - 1])
@pytest.mark.parametrize("scheme", [0, 1])
def test_exact_snapshot_nonce_era_call_and_signature_are_used_once(encoding, period, nonce, scheme):
    item = encoding
    item.signer.crypto_type = scheme
    encoded = encode(item, mortality_period=period, nonce=nonce)
    assert item.signatures == [b"fixture-payload"]
    assert item.calls == [
        ("compose", item.call.module, item.call.function, {"weights": [0, 1]}),
        (
            "payload",
            b"raw-call-including-zero-weights",
            {
                "era": {"period": period, "current": 123},
                "nonce": nonce,
                "tip": 0,
                "tip_asset_id": None,
                "genesis_hash": bytes.fromhex(_GENESIS[2:]),
                "era_block_hash": bytes.fromhex(item.runtime.snapshot.block_hash[2:]),
                "metadata_hash": None,
            },
        ),
        (
            "encode",
            b"raw-call-including-zero-weights",
            {
                "public_key": account_id32(_HOTKEY),
                "signature": b"s" * 64,
                "signature_version": scheme,
                "era": {"period": period, "current": 123},
                "nonce": nonce,
                "tip": 0,
                "tip_asset_id": None,
                "metadata_hash_enabled": False,
            },
        ),
    ]
    assert encoded == b"fixture-scale:raw-call-including-zero-weights" + b"s" * 64
    envelope = exact_signed_extrinsic(encoded)
    assert envelope.data is encoded
    assert envelope.extrinsic_hash == "0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("nonce", -1),
        ("nonce", 2**32),
        ("nonce", True),
        ("nonce", 1.0),
        ("mortality_period", 0),
        ("mortality_period", 3),
        ("mortality_period", 12),
        ("mortality_period", 8192),
        ("mortality_period", True),
        ("genesis_hash", "11" * 32),
        ("genesis_hash", "0x" + "AA" * 32),
        ("genesis_hash", None),
        ("validator_hotkey", _OTHER),
    ],
)
def test_bad_context_is_rejected_before_composition_or_signing(encoding, field, value):
    with pytest.raises(ValueError):
        encode(encoding, **{field: value})
    assert not encoding.calls and not encoding.signatures


@pytest.mark.parametrize("crypto_type", [True, 2, None])
def test_bad_signature_scheme_is_rejected_before_composition(encoding, crypto_type):
    encoding.signer.crypto_type = crypto_type
    with pytest.raises(ValueError, match="ed25519 or sr25519"):
        encode(encoding)
    assert not encoding.calls and not encoding.signatures


def test_storage_only_runtime_cannot_sign(encoding):
    old = encoding.runtime
    runtime = ReviewedStorageCodecContext(
        snapshot=old.snapshot,
        pin=old.pin,
        metadata_bytes=old.metadata_bytes,
        runtime_version_bytes=old.runtime_version_bytes,
        _runtime=old._runtime,
    )
    with pytest.raises(ValueError, match="signing runtime"):
        encode(encoding, runtime=runtime)
    assert not encoding.calls and not encoding.signatures


@pytest.mark.parametrize("signature", [b"", b"s" * 63, b"s" * 65, "s" * 64])
def test_bad_signature_never_reaches_extrinsic_encoder(encoding, signature):
    encoding.signer.sign = lambda _: signature
    with pytest.raises(ValueError, match="invalid signature"):
        encode(encoding)
    assert [call[0] for call in encoding.calls] == ["compose", "payload"]


def test_runtime_cannot_return_a_different_extrinsic_hash(encoding):
    codec = encoding.runtime._runtime
    original = codec.encode_signed_extrinsic
    codec.encode_signed_extrinsic = lambda *args, **kwargs: (
        original(*args, **kwargs)[0],
        b"x" * 32,
    )
    with pytest.raises(ValueError, match="inconsistent signed extrinsic hash"):
        encode(encoding)


def test_signing_checkpoint_follows_the_supplied_snapshot(encoding):
    snapshot = replace(encoding.runtime.snapshot, block_number=124, block_hash="0x" + "55" * 32)
    encode(encoding, runtime=replace(encoding.runtime, snapshot=snapshot))
    options = encoding.calls[1][2]
    assert options["era"] == {"period": 8, "current": 124}
    assert options["era_block_hash"] == bytes.fromhex(snapshot.block_hash[2:])


@pytest.mark.parametrize("encoded", [b"", b"x" * (65536 + 1), bytearray(b"x"), "0x01", True])
def test_exact_envelope_requires_bounded_immutable_bytes(encoded):
    with pytest.raises(ValueError, match="immutable bytes"):
        exact_signed_extrinsic(encoded)


def test_exact_envelope_accepts_inclusive_maximum():
    encoded = b"x" * 65536
    assert exact_signed_extrinsic(encoded).data is encoded
