from __future__ import annotations

import hashlib
import json
import shutil
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from umi.conformance import (
    ConformanceBinaryPins,
    ConformanceError,
    ConformanceFixturePaths,
    execute_conformance_suite,
)
from umi.protocol import canonical_json_bytes

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "fixtures" / "conformance"
_FINALITY_FIXTURE = _ROOT / "rust" / "grandpa-finality-observer" / "fixtures" / "finality-v1.json"
_PROOF_BINARY = (
    _ROOT
    / "rust"
    / "substrate-proof-verifier"
    / "target"
    / "release"
    / "umi-substrate-proof-verifier"
)
_FINALITY_BINARY = (
    _ROOT
    / "rust"
    / "grandpa-finality-observer"
    / "target"
    / "release"
    / "umi-grandpa-finality-observer"
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _available_binary(name: str) -> Path:
    value = shutil.which(name)
    if value is None:
        pytest.skip(f"{name} is unavailable")
    return Path(value).resolve()


@pytest.fixture(scope="module")
def executable_pins(tmp_path_factory: pytest.TempPathFactory) -> ConformanceBinaryPins:
    binary_directory = tmp_path_factory.mktemp("conformance-binaries")
    ffmpeg = binary_directory / "ffmpeg"
    ffprobe = binary_directory / "ffprobe"
    shutil.copyfile(_available_binary("ffmpeg"), ffmpeg)
    shutil.copyfile(_available_binary("ffprobe"), ffprobe)
    ffmpeg.chmod(0o700)
    ffprobe.chmod(0o700)
    if not _PROOF_BINARY.is_file() or not _FINALITY_BINARY.is_file():
        pytest.skip("release Rust conformance binaries are not built")
    return ConformanceBinaryPins(
        ffmpeg_path=ffmpeg,
        ffmpeg_sha256=_digest(ffmpeg),
        ffprobe_path=ffprobe,
        ffprobe_sha256=_digest(ffprobe),
        storage_proof_verifier_path=_PROOF_BINARY,
        storage_proof_verifier_sha256=_digest(_PROOF_BINARY),
        finality_verifier_path=_FINALITY_BINARY,
        finality_verifier_sha256=_digest(_FINALITY_BINARY),
    )


@pytest.fixture
def fixture_paths(tmp_path: Path) -> ConformanceFixturePaths:
    names = {
        "normalization": "normalization-fixtures.json",
        "media": "frame-digest-fixtures.json",
        "timelock": "timelock-fixtures.json",
        "chain": "chain-fixtures.json",
        "live_chain": "live-chain-fixtures.json",
        "storage_proof": "storage-proof-fixtures.json",
        "finality": "finality-fixtures.json",
    }
    paths: dict[str, Path] = {}
    for category, name in names.items():
        target = tmp_path / name
        source = _FINALITY_FIXTURE if category == "finality" else _FIXTURES / name
        target.write_bytes(source.read_bytes())
        target.chmod(0o600)
        paths[category] = target
    return ConformanceFixturePaths(**paths)


def _replace_json(path: Path, operation) -> None:
    document = json.loads(path.read_bytes())
    operation(document)
    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o600)


def test_all_seven_executors_run_and_report_is_deterministic(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
    tmp_path: Path,
) -> None:
    first = execute_conformance_suite(fixture_paths, binaries=executable_pins)
    second = execute_conformance_suite(fixture_paths, binaries=executable_pins)

    relocated_root = tmp_path / "relocated"
    relocated_root.mkdir()
    relocated_fixtures: dict[str, Path] = {}
    for category in (
        "normalization",
        "media",
        "timelock",
        "chain",
        "live_chain",
        "storage_proof",
        "finality",
    ):
        source = getattr(fixture_paths, category)
        target = relocated_root / f"{category}.json"
        shutil.copyfile(source, target)
        target.chmod(0o600)
        relocated_fixtures[category] = target
    relocated_binaries: dict[str, Path] = {}
    for name in ("ffmpeg", "ffprobe", "storage_proof_verifier", "finality_verifier"):
        source = getattr(executable_pins, f"{name}_path")
        target = relocated_root / name
        shutil.copyfile(source, target)
        target.chmod(0o700)
        relocated_binaries[name] = target
    relocated = execute_conformance_suite(
        ConformanceFixturePaths(**relocated_fixtures),
        binaries=ConformanceBinaryPins(
            ffmpeg_path=relocated_binaries["ffmpeg"],
            ffmpeg_sha256=executable_pins.ffmpeg_sha256,
            ffprobe_path=relocated_binaries["ffprobe"],
            ffprobe_sha256=executable_pins.ffprobe_sha256,
            storage_proof_verifier_path=relocated_binaries["storage_proof_verifier"],
            storage_proof_verifier_sha256=(executable_pins.storage_proof_verifier_sha256),
            finality_verifier_path=relocated_binaries["finality_verifier"],
            finality_verifier_sha256=executable_pins.finality_verifier_sha256,
        ),
    )

    assert first.verified is True
    assert first == second
    assert first == relocated
    assert first.report_sha256 == hashlib.sha256(first.canonical_report_bytes).hexdigest()
    assert set(first.report.fixture_sha256_by_category) == {
        "normalization",
        "media",
        "timelock",
        "chain",
        "live_chain",
        "storage_proof",
        "finality",
    }
    assert len(first.report.cases) == 34


def test_arbitrary_self_asserting_json_is_not_a_fixture(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
) -> None:
    fixture_paths.normalization.write_bytes(
        canonical_json_bytes({"schema": "anything", "verified": True})
    )
    with pytest.raises(ConformanceError) as error:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert error.value.reason_code == "normalization_fixture_invalid"


def test_omitted_required_case_fails_before_execution(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
) -> None:
    _replace_json(
        fixture_paths.timelock,
        lambda value: value["required_case_ids"].pop(),
    )
    with pytest.raises(ConformanceError) as error:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert error.value.reason_code == "timelock_fixture_invalid"


def test_fixture_case_count_and_utf8_byte_limits_are_enforced(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
) -> None:
    _replace_json(
        fixture_paths.normalization,
        lambda value: value["required_case_ids"].append("self-asserted-extra-case"),
    )
    with pytest.raises(ConformanceError) as extra_case:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert extra_case.value.reason_code == "normalization_fixture_invalid"

    fixture_paths.normalization.write_bytes(
        (_FIXTURES / "normalization-fixtures.json").read_bytes()
    )
    _replace_json(
        fixture_paths.normalization,
        lambda value: value["normalization_cases"][0].__setitem__("text", "☃" * 6_000),
    )
    with pytest.raises(ConformanceError) as oversized_text:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert oversized_text.value.reason_code == "normalization_fixture_invalid"


def test_noncanonical_and_tampered_fixture_bytes_fail(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
) -> None:
    fixture_paths.chain.write_bytes(fixture_paths.chain.read_bytes() + b"\n")
    with pytest.raises(ConformanceError) as noncanonical:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert noncanonical.value.reason_code == "chain_fixture_noncanonical"

    fixture_paths.chain.write_bytes((_FIXTURES / "chain-fixtures.json").read_bytes())
    _replace_json(
        fixture_paths.chain,
        lambda value: value["expected_window"].__setitem__(
            "response_deadline_blocks",
            value["expected_window"]["response_deadline_blocks"] + 1,
        ),
    )
    with pytest.raises(ConformanceError) as tampered:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert tampered.value.reason_code == "chain_schedule_output_mismatch"


def test_wrong_expected_output_and_storage_vector_fail(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
) -> None:
    _replace_json(
        fixture_paths.normalization,
        lambda value: value["normalization_cases"][0]["expected"].__setitem__(
            "normalized", "self asserted pass"
        ),
    )
    with pytest.raises(ConformanceError) as wrong_output:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert wrong_output.value.reason_code == "normalization_output_mismatch"

    fixture_paths.normalization.write_bytes(
        (_FIXTURES / "normalization-fixtures.json").read_bytes()
    )

    def mutate_storage(value) -> None:
        encoded = value["vector"]["items"][0]["value"]
        value["vector"]["items"][0]["value"] = "0x00" + encoded[4:]

    _replace_json(fixture_paths.storage_proof, mutate_storage)
    with pytest.raises(ConformanceError) as bad_proof:
        execute_conformance_suite(fixture_paths, binaries=executable_pins)
    assert bad_proof.value.reason_code == "storage_proof_positive_case_failed"


def test_wrong_binary_hash_and_wrong_executable_fail(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
    tmp_path: Path,
) -> None:
    wrong_hash = ("0" if executable_pins.ffmpeg_sha256[0] != "0" else "1") + (
        executable_pins.ffmpeg_sha256[1:]
    )
    with pytest.raises(ConformanceError) as digest_error:
        execute_conformance_suite(
            fixture_paths,
            binaries=replace(executable_pins, ffmpeg_sha256=wrong_hash),
        )
    assert digest_error.value.reason_code == "ffmpeg_digest_mismatch"

    impostor = tmp_path / "not-finality-observer"
    impostor.write_bytes(b"#!/bin/sh\nprintf '%s\\n' '{\"ok\":true}'\n")
    impostor.chmod(0o700)
    with pytest.raises(ConformanceError) as binary_error:
        execute_conformance_suite(
            fixture_paths,
            binaries=replace(
                executable_pins,
                finality_verifier_path=impostor,
                finality_verifier_sha256=_digest(impostor),
            ),
        )
    assert binary_error.value.reason_code == "finality_self_test_output_invalid"


def test_binary_tampering_after_pin_is_detected(
    fixture_paths: ConformanceFixturePaths,
    executable_pins: ConformanceBinaryPins,
    tmp_path: Path,
) -> None:
    copied = tmp_path / "proof-verifier"
    copied.write_bytes(executable_pins.storage_proof_verifier_path.read_bytes())
    copied.chmod(0o700)
    pinned = replace(
        executable_pins,
        storage_proof_verifier_path=copied,
        storage_proof_verifier_sha256=_digest(copied),
    )
    raw = bytearray(copied.read_bytes())
    raw[-1] ^= 1
    copied.write_bytes(bytes(raw))
    copied.chmod(0o700)

    with pytest.raises(ConformanceError) as error:
        execute_conformance_suite(fixture_paths, binaries=pinned)
    assert error.value.reason_code == "storage_proof_verifier_digest_mismatch"


def test_fixture_paths_reject_relative_and_duplicate_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        ConformanceFixturePaths(
            normalization=Path("normalization.json"),
            media=tmp_path / "media.json",
            timelock=tmp_path / "timelock.json",
            chain=tmp_path / "chain.json",
            live_chain=tmp_path / "live.json",
            storage_proof=tmp_path / "storage.json",
            finality=tmp_path / "finality.json",
        )

    duplicate = (tmp_path / "one.json").resolve()
    with pytest.raises(ValueError, match="distinct"):
        ConformanceFixturePaths(
            normalization=duplicate,
            media=duplicate,
            timelock=(tmp_path / "timelock.json").resolve(),
            chain=(tmp_path / "chain.json").resolve(),
            live_chain=(tmp_path / "live.json").resolve(),
            storage_proof=(tmp_path / "storage.json").resolve(),
            finality=(tmp_path / "finality.json").resolve(),
        )


def test_executable_fixture_files_are_canonical_and_not_writable_by_group_or_world() -> None:
    for path in [*sorted(_FIXTURES.glob("*.json")), _FINALITY_FIXTURE]:
        raw = path.read_bytes()
        assert canonical_json_bytes(json.loads(raw)) == raw
        assert not path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
