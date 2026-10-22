"""Large control-proof envelopes preserve published RFC bytes and failures."""

import json
from types import SimpleNamespace

import pytest
import rfc8785

from umi import canonical_reuse
from umi.competition_reward_control import _control_evidence
from umi.open_competition import digest, digest_canonical_bytes
from umi.protocol import canonical_json_bytes, is_canonical_json


def proof_envelope(payload):
    return {
        "schema": "umi-historical-control-writes/1",
        "runtime_metadata": payload,
        "runtime_execution": {"code": payload, "reads": [{"key": "ab", "value": None}]},
        "runtime_version": {"specVersion": 482, "transactionVersion": 1},
        "extrinsics": [payload, "000102"],
        "events": {"value": None, "proof": [payload]},
    }


@pytest.mark.parametrize("length", [0, 16, 512 * 1024], ids=["empty", "small", "large"])
def test_nested_proof_bytes_and_digests_match_original_encoder(length):
    original = proof_envelope("af" * length)
    expected = rfc8785.dumps(original)
    assert canonical_json_bytes(original) == expected
    assert digest(original) == digest_canonical_bytes(expected)
    assert is_canonical_json(expected)


def test_profiled_control_observation_path_avoids_slow_encoder(monkeypatch):
    arguments = dict(
        config={"netuid": 78},
        ref=SimpleNamespace(
            block_number=9340001, block_hash="0x" + "ab" * 32, state_root="0x" + "cd" * 32
        ),
        hotkey="original-control-hotkey",
        control=None,
        committed=None,
        runtime=SimpleNamespace(
            metadata_sha256="1" * 64,
            runtime_version_bytes=b'{"specVersion":482}',
            storage_codec_mode="exact_runtime",
        ),
        batch=SimpleNamespace(evidence=SimpleNamespace(claims=[], proof=[b"\xab" * (512 * 1024)])),
        finality={"block": {"scale_header": "0x1234"}},
    )
    expected = _control_evidence(**arguments)
    assert expected == rfc8785.dumps(json.loads(expected))

    def unexpected(_value):
        raise AssertionError("profiled proof envelope used per-character RFC serialization")

    monkeypatch.setattr(canonical_reuse.rfc8785, "dumps", unexpected)
    assert _control_evidence(**arguments) == expected


@pytest.mark.parametrize(
    "change",
    [True, 1.0, "1", 2**53, -(2**53), 'a\nb"\\', "é😀", "\ud800", ["ab"]],
    ids=[
        "boolean",
        "float",
        "string",
        "large-int",
        "small-int",
        "escapes",
        "unicode",
        "surrogate",
        "list",
    ],
)
def test_large_envelopes_keep_rfc_bytes_or_original_errors(change):
    original = proof_envelope("ab" * (256 * 1024))
    original["edge"] = change
    try:
        expected = rfc8785.dumps(original)
    except Exception as error:
        with pytest.raises(type(error)):
            canonical_json_bytes(original)
    else:
        assert canonical_json_bytes(original) == expected


def test_encoder_budget_is_a_fallback_and_not_an_input_limit(monkeypatch):
    original = proof_envelope("abcd" * 100)
    assert canonical_reuse.small_ascii_json_bytes(original, maximum_bytes=128) is None
    expected = rfc8785.dumps(original)
    monkeypatch.setattr(canonical_reuse, "_PROOF_JSON_BYTES", 128)
    assert canonical_json_bytes(original) == expected


@pytest.mark.parametrize("count,budget", [(100, 100), (30, 80)])
def test_container_structure_also_obeys_the_selected_encoder_budget(count, budget):
    value = [[] for _ in range(count)]
    assert canonical_reuse.small_ascii_json_bytes(value, maximum_bytes=budget) is None


@pytest.mark.parametrize("budget", [-1, True, 1.0])
def test_invalid_encoder_budget_is_rejected(budget):
    with pytest.raises(ValueError, match="byte budget"):
        canonical_reuse.small_ascii_json_bytes({}, maximum_bytes=budget)


def test_large_snapshot_owns_its_content_before_c_serialization(monkeypatch):
    original = proof_envelope("abcd" * (128 * 1024))
    expected = rfc8785.dumps(original)
    encode = canonical_reuse.json.dumps

    def mutate_after_snapshot(value, **kwargs):
        original["runtime_execution"]["reads"][0]["value"] = "東京"
        return encode(value, **kwargs)

    monkeypatch.setattr(canonical_reuse.json, "dumps", mutate_after_snapshot)
    assert canonical_json_bytes(original) == expected
    assert canonical_json_bytes(original) == rfc8785.dumps(original)


def test_source_mutation_inside_reuse_scope_is_not_hidden():
    original = proof_envelope("ab" * (128 * 1024))
    first = rfc8785.dumps(original)
    with canonical_reuse.canonical_json_reuse():
        assert canonical_json_bytes(original) == first
        original["runtime_metadata"] = "cd"
        assert canonical_json_bytes(original) == rfc8785.dumps(original)
        assert canonical_json_bytes(original) != first
