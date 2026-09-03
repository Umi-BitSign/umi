from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785

from umi.grandpa_finality import (
    CARGO_LOCK_SHA256,
    EVIDENCE_CLASS,
    FINNEY_BOOTSTRAP_BLOCK_HASH,
    FINNEY_BOOTSTRAP_BLOCK_NUMBER,
    FINNEY_CHAIN_SPEC_SHA256,
    FINNEY_CHAIN_SPEC_SOURCE_REVISION,
    FINNEY_GENESIS_HASH,
    FIXTURE_SET_SHA256,
    RECORD_SCHEMA,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
    GrandpaFinalityObserver,
    GrandpaFinalityObserverError,
)
from umi.policy import FinalityVerifierPin

_TRANSCRIPT_DOMAIN = b"umi-grandpa-finality-attestation-v1\0"


def _compact(value: int) -> bytes:
    if value < 1 << 6:
        return bytes([value << 2])
    if value < 1 << 14:
        return ((value << 2) | 1).to_bytes(2, "little")
    return ((value << 2) | 2).to_bytes(4, "little")


def _header(number: int, *, parent_hash: str, seed: int) -> dict[str, object]:
    encoded = (
        bytes.fromhex(parent_hash[2:])
        + _compact(number)
        + bytes([seed]) * 32
        + bytes([(seed + 1) % 256]) * 32
        + b"\x00"
    )
    return {
        "number": number,
        "hash": f"0x{hashlib.blake2b(encoded, digest_size=32).hexdigest()}",
        "parent_hash": parent_hash,
        "state_root": f"0x{bytes([seed]).hex() * 32}",
        "extrinsics_root": f"0x{bytes([(seed + 1) % 256]).hex() * 32}",
        "scale_header": f"0x{encoded.hex()}",
        "timestamp_ms": number * 12_000,
    }


def _record(
    config: dict[str, object],
    *,
    block: dict[str, object],
    sequence: int,
    ancestry: list[dict[str, object]],
    complete: bool,
    previous_hash: str | None,
    previous_digest: str,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": RECORD_SCHEMA,
        "request_id": config["request_id"],
        "evidence_class": EVIDENCE_CLASS,
        "offline_finality_proof": False,
        "source_revision": SOURCE_REVISION,
        "sequence": sequence,
        "chain_spec_sha256": config["chain_spec_sha256"],
        "genesis_hash": config["expected_genesis_hash"],
        "bootstrap_block_number": config["bootstrap_block_number"],
        "bootstrap_block_hash": config["bootstrap_block_hash"],
        "bootstrap_source": "grandpa_checkpoint",
        "bootstrap_selected": True,
        "startup_finalized_block_number": block["number"],
        "startup_finalized_block_hash": block["hash"],
        "block": block,
        "ancestry": ancestry,
        "ancestry_complete_since_previous": complete,
        "previous_finalized_hash": previous_hash,
        "previous_transcript_digest": previous_digest,
    }
    return {
        **unsigned,
        "transcript_digest": hashlib.sha256(
            _TRANSCRIPT_DOMAIN + rfc8785.dumps(unsigned)
        ).hexdigest(),
    }


def _write_fixture_executable(path: Path) -> str:
    source = f'''#!{sys.executable}
import hashlib
import json
import rfc8785
import sys

config = json.load(sys.stdin)
number = config["minimum_finalized_block"]
if number < 64:
    compact = bytes([number << 2])
elif number < 1 << 14:
    compact = ((number << 2) | 1).to_bytes(2, "little")
else:
    compact = ((number << 2) | 2).to_bytes(4, "little")
parent = bytes([17]) * 32
encoded = parent + compact + bytes([34]) * 32 + bytes([35]) * 32 + bytes([0])
block_hash = "0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest()
block = {{
    "number": number,
    "hash": block_hash,
    "parent_hash": "0x" + parent.hex(),
    "state_root": "0x" + bytes([34]).hex() * 32,
    "extrinsics_root": "0x" + bytes([35]).hex() * 32,
    "scale_header": "0x" + encoded.hex(),
    "timestamp_ms": number * 12000,
}}
unsigned = {{
    "schema": "{RECORD_SCHEMA}",
    "request_id": config["request_id"],
    "evidence_class": "{EVIDENCE_CLASS}",
    "offline_finality_proof": False,
    "source_revision": "{SOURCE_REVISION}",
    "sequence": 0,
    "chain_spec_sha256": config["chain_spec_sha256"],
    "genesis_hash": config["expected_genesis_hash"],
    "bootstrap_block_number": config["bootstrap_block_number"],
    "bootstrap_block_hash": config["bootstrap_block_hash"],
    "bootstrap_source": "grandpa_checkpoint",
    "bootstrap_selected": True,
    "startup_finalized_block_number": number,
    "startup_finalized_block_hash": block_hash,
    "block": block,
    "ancestry": [{{"number": number, "hash": block_hash, "parent_hash": block["parent_hash"]}}],
    "ancestry_complete_since_previous": False,
    "previous_finalized_hash": None,
    "previous_transcript_digest": "0" * 64,
}}
record = dict(unsigned)
record["transcript_digest"] = hashlib.sha256(
    b"umi-grandpa-finality-attestation-v1\\0" + rfc8785.dumps(unsigned)
).hexdigest()
sys.stdout.buffer.write(rfc8785.dumps(record) + b"\\n")
'''
    path.write_text(source, encoding="utf-8")
    path.chmod(0o500)
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def observer(tmp_path: Path) -> GrandpaFinalityObserver:
    binary = tmp_path / "fake-observer"
    binary_hash = _write_fixture_executable(binary)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    return GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=binary_hash,
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=hashlib.sha256(b"{}").hexdigest(),
        expected_genesis_hash=f"0x{'33' * 32}",
        bootstrap_block_number=1,
        bootstrap_block_hash=f"0x{'44' * 32}",
        record_timeout_seconds=2.0,
    )


def test_subprocess_adapter_accepts_canonical_attestation(
    observer: GrandpaFinalityObserver,
) -> None:
    records = list(
        observer.attestations(
            minimum_finalized_block=10,
            maximum_records=1,
            startup_timeout_seconds=1,
        )
    )
    assert len(records) == 1
    assert records[0].sequence == 0
    assert records[0].block.number == 10
    assert records[0].ancestry_complete_since_previous is False


def test_observer_executes_private_descriptor_copies_when_sources_are_swapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "fake-observer"
    binary_hash = _write_fixture_executable(binary)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    selected = GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=binary_hash,
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=hashlib.sha256(b"{}").hexdigest(),
        expected_genesis_hash=f"0x{'33' * 32}",
        bootstrap_block_number=1,
        bootstrap_block_hash=f"0x{'44' * 32}",
        record_timeout_seconds=2.0,
    )
    real_popen = subprocess.Popen
    invoked: list[Path] = []

    def swapping_popen(command, *args, **kwargs):
        invoked.append(Path(command[0]))
        binary.chmod(0o700)
        binary.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        binary.chmod(0o500)
        chain_spec.chmod(0o600)
        chain_spec.write_bytes(b"malicious")
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr("umi.grandpa_finality.subprocess.Popen", swapping_popen)
    records = list(
        selected.attestations(
            minimum_finalized_block=10,
            maximum_records=1,
            startup_timeout_seconds=1,
        )
    )
    assert len(records) == 1
    assert len(invoked) == 1
    assert invoked[0] != binary
    assert invoked[0].parent != binary.parent


def test_observer_removes_staged_inputs_when_config_write_fails(
    observer: GrandpaFinalityObserver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked: list[Path] = []

    class FailingInput:
        @staticmethod
        def write(_value: bytes) -> int:
            raise OSError("closed pipe")

        @staticmethod
        def close() -> None:
            return None

    class FailedProcess:
        stdin = FailingInput()
        stdout = object()

        @staticmethod
        def poll() -> int:
            return 1

    def failed_popen(command, *_args, **_kwargs):
        invoked.append(Path(command[0]))
        return FailedProcess()

    monkeypatch.setattr("umi.grandpa_finality.subprocess.Popen", failed_popen)
    with pytest.raises(GrandpaFinalityObserverError, match="config_write_failed"):
        list(
            observer.attestations(
                minimum_finalized_block=10,
                maximum_records=1,
                startup_timeout_seconds=1,
            )
        )

    assert len(invoked) == 1
    assert not invoked[0].exists()
    assert not invoked[0].parent.exists()


def test_parser_rejects_wrong_genesis_and_checkpoint_drift(
    observer: GrandpaFinalityObserver,
) -> None:
    config, _ = observer._config(
        minimum_finalized_block=10,
        maximum_records=1,
        startup_timeout_seconds=1,
    )
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=34)
    record = _record(
        config,
        block=block,
        sequence=0,
        ancestry=[{"number": 10, "hash": block["hash"], "parent_hash": block["parent_hash"]}],
        complete=False,
        previous_hash=None,
        previous_digest="0" * 64,
    )
    for field in ("genesis_hash", "bootstrap_block_hash"):
        changed = dict(record)
        changed[field] = f"0x{'99' * 32}"
        unsigned = dict(changed)
        unsigned.pop("transcript_digest")
        changed["transcript_digest"] = hashlib.sha256(
            _TRANSCRIPT_DOMAIN + rfc8785.dumps(unsigned)
        ).hexdigest()
        with pytest.raises(GrandpaFinalityObserverError, match="record_pin_mismatch"):
            observer._parse_record(
                rfc8785.dumps(changed),
                config=config,
                expected_sequence=0,
                previous_hash=None,
                previous_digest="0" * 64,
                previous_number=None,
                previous_timestamp_ms=None,
            )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("bootstrap_source", "genesis", "record_pin_mismatch"),
        ("bootstrap_selected", False, "record_pin_mismatch"),
        ("startup_finalized_block_number", 0, "invalid_startup_finalized_head"),
        ("startup_finalized_block_hash", "0x00", "invalid_startup_finalized_head"),
        ("startup_finalized_block_hash", "0x" + "99" * 32, "invalid_startup_finalized_head"),
    ),
)
def test_parser_rejects_unselected_or_invalid_startup_receipt(
    observer: GrandpaFinalityObserver,
    field: str,
    value: object,
    reason: str,
) -> None:
    config, _ = observer._config(
        minimum_finalized_block=10,
        maximum_records=1,
        startup_timeout_seconds=1,
    )
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=34)
    record = _record(
        config,
        block=block,
        sequence=0,
        ancestry=[{"number": 10, "hash": block["hash"], "parent_hash": block["parent_hash"]}],
        complete=False,
        previous_hash=None,
        previous_digest="0" * 64,
    )
    record[field] = value
    unsigned = dict(record)
    unsigned.pop("transcript_digest")
    record["transcript_digest"] = hashlib.sha256(
        _TRANSCRIPT_DOMAIN + rfc8785.dumps(unsigned)
    ).hexdigest()
    with pytest.raises(GrandpaFinalityObserverError, match=reason):
        observer._parse_record(
            rfc8785.dumps(record),
            config=config,
            expected_sequence=0,
            previous_hash=None,
            previous_digest="0" * 64,
            previous_number=None,
            previous_timestamp_ms=None,
        )


def test_parser_rejects_rollback(observer: GrandpaFinalityObserver) -> None:
    config, _ = observer._config(
        minimum_finalized_block=10,
        maximum_records=2,
        startup_timeout_seconds=1,
    )
    first_block = _header(10, parent_hash=f"0x{'11' * 32}", seed=34)
    first = _record(
        config,
        block=first_block,
        sequence=0,
        ancestry=[
            {
                "number": 10,
                "hash": first_block["hash"],
                "parent_hash": first_block["parent_hash"],
            }
        ],
        complete=False,
        previous_hash=None,
        previous_digest="0" * 64,
    )
    second_block = _header(10, parent_hash=str(first_block["hash"]), seed=35)
    second = _record(
        config,
        block=second_block,
        sequence=1,
        ancestry=[
            {
                "number": 10,
                "hash": second_block["hash"],
                "parent_hash": second_block["parent_hash"],
            }
        ],
        complete=True,
        previous_hash=str(first_block["hash"]),
        previous_digest=str(first["transcript_digest"]),
    )
    with pytest.raises(GrandpaFinalityObserverError, match="finality_rollback"):
        observer._parse_record(
            rfc8785.dumps(second),
            config=config,
            expected_sequence=1,
            previous_hash=str(first_block["hash"]),
            previous_digest=str(first["transcript_digest"]),
            previous_number=10,
            previous_timestamp_ms=120_000,
        )


def test_parser_rejects_malformed_header(observer: GrandpaFinalityObserver) -> None:
    config, _ = observer._config(
        minimum_finalized_block=10,
        maximum_records=1,
        startup_timeout_seconds=1,
    )
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=34)
    block["scale_header"] = "0x00"
    record = _record(
        config,
        block=block,
        sequence=0,
        ancestry=[{"number": 10, "hash": block["hash"], "parent_hash": block["parent_hash"]}],
        complete=False,
        previous_hash=None,
        previous_digest="0" * 64,
    )
    with pytest.raises(GrandpaFinalityObserverError, match="invalid_header_size"):
        observer._parse_record(
            rfc8785.dumps(record),
            config=config,
            expected_sequence=0,
            previous_hash=None,
            previous_digest="0" * 64,
            previous_number=None,
            previous_timestamp_ms=None,
        )


def test_constructor_rejects_symlinked_chain_spec(tmp_path: Path) -> None:
    binary = tmp_path / "fake-observer"
    binary_hash = _write_fixture_executable(binary)
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    target.chmod(0o400)
    link = tmp_path / "link.json"
    os.symlink(target, link)
    with pytest.raises(GrandpaFinalityObserverError, match="unsafe_chain_spec"):
        GrandpaFinalityObserver(
            binary_path=binary,
            expected_binary_sha256=binary_hash,
            chain_spec_path=link,
            expected_chain_spec_sha256=hashlib.sha256(b"{}").hexdigest(),
            expected_genesis_hash=f"0x{'33' * 32}",
            bootstrap_block_number=1,
            bootstrap_block_hash=f"0x{'44' * 32}",
        )


def test_policy_pin_is_the_only_production_bootstrap_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "fake-observer"
    binary_hash = _write_fixture_executable(binary)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    pin = FinalityVerifierPin(
        profile="smoldot-verifier-attested-finality/1",
        evidence_class="verifier_attested_finality",
        offline_finality_proof=False,
        source_revision=SOURCE_REVISION,
        source_tree_sha256=SOURCE_TREE_SHA256,
        cargo_lock_sha256=CARGO_LOCK_SHA256,
        finality_fixture_set_sha256=FIXTURE_SET_SHA256,
        release_sha256_by_target={"aarch64-apple-darwin": binary_hash},
        chain_spec_source_revision=FINNEY_CHAIN_SPEC_SOURCE_REVISION,
        chain_spec_sha256=FINNEY_CHAIN_SPEC_SHA256,
        expected_genesis_hash=FINNEY_GENESIS_HASH,
        bootstrap_kind="grandpa_warp_sync_checkpoint",
        bootstrap_block_number=FINNEY_BOOTSTRAP_BLOCK_NUMBER,
        bootstrap_block_hash=FINNEY_BOOTSTRAP_BLOCK_HASH,
    )

    monkeypatch.setattr(GrandpaFinalityObserver, "_assert_file_integrity", lambda *args, **kw: None)

    bound = GrandpaFinalityObserver.from_policy_pin(
        pin,
        target_triple="aarch64-apple-darwin",
        binary_path=binary,
        chain_spec_path=chain_spec,
        record_timeout_seconds=2,
    )
    config, _encoded = bound._config(
        minimum_finalized_block=FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1,
        maximum_records=1,
        startup_timeout_seconds=1,
    )
    assert config["expected_genesis_hash"] == f"0x{FINNEY_GENESIS_HASH}"
    assert config["bootstrap_block_number"] == FINNEY_BOOTSTRAP_BLOCK_NUMBER
    assert config["bootstrap_block_hash"] == f"0x{FINNEY_BOOTSTRAP_BLOCK_HASH}"

    changed = pin.model_copy(update={"cargo_lock_sha256": "55" * 32})
    with pytest.raises(GrandpaFinalityObserverError, match="policy_build_pin_mismatch"):
        GrandpaFinalityObserver.from_policy_pin(
            changed,
            target_triple="aarch64-apple-darwin",
            binary_path=binary,
            chain_spec_path=chain_spec,
        )

    for field, value in (
        ("chain_spec_source_revision", "ab" * 20),
        ("chain_spec_sha256", "55" * 32),
        ("expected_genesis_hash", "66" * 32),
        ("bootstrap_block_number", FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1),
        ("bootstrap_block_hash", "77" * 32),
    ):
        changed = pin.model_copy(update={field: value})
        with pytest.raises(GrandpaFinalityObserverError, match="policy_chain_pin_mismatch"):
            GrandpaFinalityObserver.from_policy_pin(
                changed,
                target_triple="aarch64-apple-darwin",
                binary_path=binary,
                chain_spec_path=chain_spec,
            )
