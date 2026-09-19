import errno
import hashlib
import os

import pytest

import umi.competition_submission_checkpoint as checkpoints
from umi.protocol import canonical_json_bytes


@pytest.fixture
def directory(tmp_path):
    root = tmp_path / "checkpoint"
    root.mkdir(mode=0o700)
    return root


def checkpoint_file(directory, **options):
    return checkpoints.SubmissionHeadCheckpointFile(
        directory,
        policy_sha256="11" * 32,
        public_launch_sha256="22" * 32,
        **options,
    )


def test_lock_timeout_default_preserves_binding_and_checkpoint_bytes(directory):
    default = checkpoint_file(directory)
    configured = checkpoint_file(directory, lock_timeout_seconds=0.01)
    assert default.lock_timeout_seconds == 5.0
    location = {
        "schema": "umi-competition-submission-checkpoint-location/1",
        "directory": str(directory.resolve()),
        "policy_sha256": "11" * 32,
    }
    expected_binding = hashlib.sha256(canonical_json_bytes(location)).hexdigest()
    assert default.binding_sha256 == configured.binding_sha256 == expected_binding
    checkpoint = checkpoints.build_submission_checkpoint(
        policy_sha256="11" * 32,
        public_launch_sha256="22" * 32,
        submission_sha256s=("33" * 32,),
        admission_record_sha256s=("44" * 32,),
    )
    with default.locked():
        default.replace(checkpoint)
    before = default.path.read_bytes()
    with configured.locked():
        assert configured.load() == checkpoint
        configured.replace(checkpoint)
    assert configured.path.read_bytes() == before == canonical_json_bytes(checkpoint)
    assert configured.status(checkpoint) == default.status(checkpoint)
    assert b"lock_timeout" not in before


@pytest.mark.parametrize("timeout", [0.001, 1, 5.0])
def test_lock_timeout_accepts_positive_finite_numbers(directory, timeout):
    assert checkpoint_file(directory, lock_timeout_seconds=timeout).lock_timeout_seconds == timeout


@pytest.mark.parametrize(
    "timeout",
    [True, False, 0, -0.01, float("nan"), float("inf"), -float("inf"), "5", None, 10**400],
)
def test_lock_timeout_rejects_invalid_values(directory, timeout):
    with pytest.raises(ValueError, match="lock timeout must be finite and positive"):
        checkpoint_file(directory, lock_timeout_seconds=timeout)
    assert not list(directory.iterdir())


def test_contended_lock_times_out_closes_descriptor_and_allows_retry(directory, monkeypatch):
    owner = checkpoint_file(directory)
    contender = checkpoint_file(directory, lock_timeout_seconds=0.01)
    opened = []
    open_lock = checkpoints._open_lock

    def tracked_open_lock(descriptor):
        result = open_lock(descriptor)
        opened.append(result[0])
        return result

    with owner.locked():
        with monkeypatch.context() as patch:
            patch.setattr(checkpoints, "_open_lock", tracked_open_lock)
            with (
                pytest.raises(
                    checkpoints.SubmissionCheckpointError,
                    match=r"^submission checkpoint lock timed out$",
                ),
                contender.locked(),
            ):
                pytest.fail("contender entered the owner's critical section")
        assert len(opened) == 1
        with pytest.raises(OSError) as caught:
            os.fstat(opened[0])
        assert caught.value.errno == errno.EBADF
    with contender.locked():
        assert contender.load() is None
    with owner.locked():
        assert owner.load() is None


@pytest.mark.parametrize("kind", ["public_mode", "hardlink"])
def test_invalid_lock_file_closes_opened_descriptor(directory, monkeypatch, kind):
    checkpoint = checkpoint_file(directory)
    path = directory / "submission-head.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    if kind == "public_mode":
        path.chmod(0o644)
    else:
        os.link(path, directory / "other-link")
    opened = []
    real_open = os.open

    def tracked_open(candidate, *args, **kwargs):
        descriptor = real_open(candidate, *args, **kwargs)
        if candidate == "submission-head.lock":
            opened.append(descriptor)
        return descriptor

    with monkeypatch.context() as patch:
        patch.setattr(checkpoints.os, "open", tracked_open)
        with (
            pytest.raises(
                checkpoints.SubmissionCheckpointError, match="private owned regular file"
            ),
            checkpoint.locked(),
        ):
            pytest.fail("unsafe lock entered the critical section")
    assert len(opened) == 1
    with pytest.raises(OSError) as caught:
        os.fstat(opened[0])
    assert caught.value.errno == errno.EBADF
