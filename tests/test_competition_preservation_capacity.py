"""Preservation admits bounded writes without changing native byte authority."""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_open_competition import bundle_at
from tests.test_open_competition import policy as policy_fixture
from umi import competition_artifacts as artifacts
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


@pytest.fixture
def model(tmp_path):
    policy = policy_fixture.__wrapped__().model_copy(update={"maximum_bundle_bytes": 4 * 1024**2})
    source = tmp_path / "source"
    bundle = bundle_at(source)
    body = b"x" * (2 * 1024**2 + 73)
    (source / "weights.txt").write_bytes(body)
    bundle = bundle.model_copy(
        update={
            "files": tuple(
                record.model_copy(
                    update={"sha256": hashlib.sha256(body).hexdigest(), "size_bytes": len(body)}
                )
                if record.path == "weights.txt"
                else record
                for record in bundle.files
            )
        }
    )
    return bundle, source, tmp_path / "archive", policy


def test_capacity_loss_cleans_partial_copy_and_retry_preserves_once(model, tmp_path, monkeypatch):
    bundle, source, archive, policy = model
    previous_source = tmp_path / "previous"
    previous = bundle_at(previous_source, "previous")
    artifacts.preserve_bundle(previous, previous_source, archive, policy)
    admitted, written = [], []

    def admit(size):
        admitted.append(size)
        if sum(admitted) > 1024**2:
            raise OSError("operating reserve exhausted")

    with pytest.raises(OSError, match="reserve exhausted"):
        artifacts.preserve_bundle(
            bundle, source, archive, policy, check_write=admit, on_bytes_written=written.append
        )
    assert 0 < sum(written) < sum(admitted)
    assert max(admitted) <= 1024**2
    assert not (archive / digest(bundle)).exists()
    assert not (archive / (".verified-" + digest(bundle) + ".json")).exists()
    assert not (archive / (".pending-" + digest(bundle))).exists()
    assert artifacts.verify_preserved_bundle(previous, archive, policy) == digest(previous)

    admitted.clear()
    written.clear()
    target = artifacts.preserve_bundle(
        bundle,
        source,
        archive,
        policy,
        check_write=admitted.append,
        on_bytes_written=written.append,
    )
    assert admitted == written
    assert sum(written) == sum(record.size_bytes for record in bundle.files)
    assert len(written) > len(bundle.files)

    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged receipt must not read or admit payload writes")

    monkeypatch.setattr(artifacts, "_copy_verified", forbidden)
    assert artifacts.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    assert (
        artifacts.preserve_bundle(
            bundle,
            tmp_path / "absent-source",
            archive,
            policy,
            check_write=forbidden,
            on_bytes_written=forbidden,
        )
        == target
    )


def test_guarded_copy_keeps_hash_authority_and_never_remembers_corrupt_bytes(model):
    bundle, source, archive, policy = model
    weights = source / "weights.txt"
    weights.write_bytes(b"y" * weights.stat().st_size)
    written = []
    with pytest.raises(ValueError, match="immutable manifest"):
        artifacts.preserve_bundle(
            bundle,
            source,
            archive,
            policy,
            check_write=lambda size: None,
            on_bytes_written=written.append,
        )
    assert written
    assert not (archive / digest(bundle)).exists()
    assert not (archive / (".verified-" + digest(bundle) + ".json")).exists()
    assert not (archive / (".pending-" + digest(bundle))).exists()


def test_progress_interruption_cleans_partial_and_leaves_retry_available(model):
    bundle, source, archive, policy = model

    def interrupted(size):
        raise InterruptedError("transfer interrupted")

    with pytest.raises(InterruptedError, match="transfer interrupted"):
        artifacts.preserve_bundle(bundle, source, archive, policy, on_bytes_written=interrupted)
    assert not (archive / digest(bundle)).exists()
    assert not (archive / (".pending-" + digest(bundle))).exists()
    target = artifacts.preserve_bundle(
        bundle, source, archive, policy, check_write=lambda size: None
    )
    assert target == archive / digest(bundle)


def test_guarded_preservation_receipt_survives_new_process(model, tmp_path):
    bundle, source, archive, policy = model
    artifacts.preserve_bundle(bundle, source, archive, policy, check_write=lambda size: None)
    inputs = tmp_path / "inputs.json"
    inputs.write_bytes(
        canonical_json_bytes(
            {
                "bundle": canonical_json_bytes(bundle).decode(),
                "policy": canonical_json_bytes(policy).decode(),
            }
        )
    )
    code = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from umi import competition_artifacts as a
from umi.open_competition import CompetitionPolicy, ModelBundle, digest
assert Path(a.__file__).is_relative_to(Path(sys.argv[1]))
data = json.loads(Path(sys.argv[2]).read_bytes())
bundle = ModelBundle.model_validate_json(data['bundle'])
policy = CompetitionPolicy.model_validate_json(data['policy'])
archive = Path(sys.argv[3])
def forbidden(*args, **kwargs):
    raise AssertionError('unchanged payload read or write after restart')
a._copy_verified = forbidden
assert a.preserve_bundle(bundle, archive / 'absent', archive, policy,
    check_write=forbidden, on_bytes_written=forbidden) == archive / digest(bundle)
"""
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            code,
            str(Path(artifacts.__file__).resolve().parents[1]),
            str(inputs),
            str(archive),
        ],
        check=True,
        timeout=60,
    )
