"""Version-independent reads retain pinned decoding, proofs and state constraints."""

import hashlib
import json
from pathlib import Path

import pytest

from umi.competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from umi.competition_origin import FinalizedEndpointProvider
from umi.protocol import canonical_json_bytes
from umi.validator_chain import FinalizedRuntimePin, ValidatorChainError

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_origin import origin_chain as origin_chain
from .test_competition_origin import policy as policy
from .test_validator_chain import FakeRuntime, _collector, _rpc


def configured(chain, tmp_path):
    path = tmp_path.resolve() / "codec.scale"
    path.write_bytes(b"metadata")
    return chain.config.model_copy(
        update={
            "storage_codec_metadata_path": str(path),
            "state_directory": str(tmp_path / "codec-state"),
        }
    )


def version_bump(monkeypatch, rpc):
    original = rpc.request

    async def request(method, params):
        if method == "state_getMetadata":
            raise AssertionError("RPC metadata must never select the storage codec")
        if method == "state_getRuntimeVersion":
            return {"specVersion": 459, "transactionVersion": 7, "stateVersion": 1}
        return await original(method, params)

    monkeypatch.setattr(rpc, "request", request)


def test_legacy_config_serialization_unchanged(chain_config):
    raw = canonical_json_bytes(chain_config)
    assert b"storage_codec_metadata_path" not in raw
    assert canonical_json_bytes(CompetitionChainConfig.model_validate_json(raw)) == raw


@pytest.mark.parametrize("path", ["relative.scale", "/", "/tmp/../codec", "/tmp/\x00codec"])
def test_codec_path_must_be_explicit(chain_config, path):
    body = json.loads(canonical_json_bytes(chain_config))
    body["storage_codec_metadata_path"] = path
    with pytest.raises(ValueError):
        CompetitionChainConfig.model_validate(body)


@pytest.mark.parametrize("bad", ["hash", "empty", "directory", "symlink", "large"])
def test_bad_codec_rejected_before_state_creation(chain, tmp_path, bad):
    config = configured(chain, tmp_path)
    path = Path(config.storage_codec_metadata_path)
    if bad == "hash":
        path.write_bytes(b"other")
    elif bad == "empty":
        path.write_bytes(b"")
    elif bad == "large":
        path.write_bytes(b"x" * (4 * 1024**2 + 1))
    else:
        path.unlink()
        if bad == "directory":
            path.mkdir()
        else:
            target = tmp_path / "target"
            target.write_bytes(b"metadata")
            path.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        FinalizedRegistrationProvider(
            config, chain.policy, finality=chain.finality, proofs=chain.proofs
        )
    assert not Path(config.state_directory).exists()


@pytest.mark.parametrize("bad_proof", [False, True])
async def test_registration_uses_approved_codec_after_runtime_bump(
    chain, tmp_path, monkeypatch, bad_proof
):
    config = configured(chain, tmp_path)
    version_bump(monkeypatch, chain.rpc)
    chain.rpc.bad_proof = bad_proof
    provider = FinalizedRegistrationProvider(
        config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    try:
        if bad_proof:
            with pytest.raises(ValidatorChainError):
                await provider.collect()
        else:
            capture = await provider.collect()
            assert len(capture.snapshot.registrations) == 2
            assert len(chain.verifier.checked) == 3
    finally:
        await provider.aclose()


async def test_origin_proofs_survive_version_bump(origin_chain, tmp_path, monkeypatch):
    item = origin_chain
    config = configured(item, tmp_path)
    version_bump(monkeypatch, item.rpc)
    provider = FinalizedEndpointProvider(
        config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    try:
        capture = await provider.collect_origin(item.signed)
        assert capture.uid == 0
        evidence = json.loads(capture.evidence)
        assert evidence["storage_codec_mode"] == "reviewed_storage_codec/1"
        assert evidence["runtime_version"]["specVersion"] == 459
        assert evidence["runtime_metadata_sha256"] == hashlib.sha256(b"metadata").hexdigest()
    finally:
        await provider.aclose()


@pytest.mark.parametrize("state_version", [0, 2, True, None])
async def test_codec_still_rejects_unsupported_state_versions(monkeypatch, state_version):
    rpc = _rpc()
    rpc.responses["state_getRuntimeVersion"] = {
        "specVersion": 459,
        "transactionVersion": 7,
        "stateVersion": state_version,
    }
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", FakeRuntime)
    collector = _collector(rpc, verifier=lambda **kwargs: True)
    ref = await collector.finalized_snapshot()
    pin = FinalizedRuntimePin(
        metadata_sha256=hashlib.sha256(b"metadata").hexdigest(),
        spec_version=452,
        transaction_version=1,
    )
    with pytest.raises(ValidatorChainError):
        await collector.storage_codec_runtime(ref, pin, b"metadata")
