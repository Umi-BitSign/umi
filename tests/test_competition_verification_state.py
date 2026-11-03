"""Durability, explicit loss repair and shared authority scope lifecycle."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from umi import competition_verification_reuse as reuse_module
from umi.competition_verification_reuse import VerificationReuse, verified_replay
from umi.protocol import StrictProtocolModel

from .test_open_competition import policy as policy


class Result(StrictProtocolModel):
    value: str


def test_shared_override_migrates_completed_local_work_and_preserves_owner_separation(
    tmp_path, monkeypatch, policy
):
    calls = []

    @verified_replay("shared_verification", Result)
    def verify(policy):
        calls.append(1)
        return Result(value="complete")

    first = VerificationReuse(tmp_path / "settlement", owner="validator_one")
    with first.selected():
        assert verify(policy).value == "complete"
    monkeypatch.setenv("UMI_NATIVE_VERIFICATION_DIRECTORY", str(tmp_path / "shared"))
    migrated = VerificationReuse(tmp_path / "settlement", owner="validator_one")
    with migrated.selected():
        assert verify(policy).value == "complete"
    reviewer = VerificationReuse(tmp_path / "reviewer", owner="validator_one")
    with reviewer.selected():
        assert verify(policy).value == "complete"
    assert len(calls) == 1
    assert migrated.directory == reviewer.directory != first.directory
    assert list(first.directory.glob("*.json"))
    with VerificationReuse(tmp_path / "independent", owner="validator_two").selected():
        assert verify(policy).value == "complete"
    assert len(calls) == 2


def test_missing_completed_receipt_is_explicit_repair(tmp_path, policy, caplog):
    owner = VerificationReuse(tmp_path / "state", owner="one")
    calls = []

    @verified_replay("missing_result", Result)
    def verify(policy):
        calls.append(1)
        return Result(value="complete")

    with owner.selected():
        verify(policy)
    for path in owner.directory.glob("*.json"):
        path.unlink()
    caplog.set_level("INFO", logger="umi.competition.progress")
    with owner.selected():
        assert verify(policy).value == "complete"
    assert len(calls) == 2
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert any(e.get("state") == "repair_required" for e in events)


def test_other_process_cannot_repeat_in_progress_native_work(tmp_path):
    first = VerificationReuse(tmp_path / "owner", owner="one")
    second = VerificationReuse(tmp_path / "owner", owner="one")
    # Independent processes fail fast on the file lock. Same-process threads
    # intentionally serialize and reuse completed work (covered by throughput
    # tests), so waiting for such a thread while retaining its lock deadlocks.
    code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from umi.competition_verification_reuse import VerificationReuse
from umi.private_files import PrivateStateBusyError
try:
    with VerificationReuse(Path(sys.argv[2]), owner="one").exclusive():
        raise AssertionError("another process borrowed an in-progress native scope")
except PrivateStateBusyError:
    print("busy")
"""
    with first.exclusive():
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                code,
                str(Path(__file__).parents[1] / "src"),
                str(tmp_path / "owner"),
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
    assert result.stdout.strip() == "busy"
    with second.exclusive():
        pass


def test_other_thread_waits_for_in_progress_native_work_before_entering(tmp_path):
    first = VerificationReuse(tmp_path / "owner", owner="one")
    second = VerificationReuse(tmp_path / "owner", owner="one")
    attempted, entered, releasing = Event(), Event(), Event()

    def other():
        attempted.set()
        with second.exclusive():
            assert releasing.is_set(), "another thread borrowed in-progress native work"
            entered.set()

    # Same-process owners deliberately serialize. Joining the worker while the
    # parent owns that mutex would deadlock before the process-level lock check.
    # Keep the executor outside the scope so even an assertion releases it first.
    with ThreadPoolExecutor(max_workers=1) as pool:
        with first.exclusive():
            pending = pool.submit(other)
            assert attempted.wait(5)
            assert not pending.done() and not entered.is_set()
            releasing.set()
        pending.result(timeout=5)
    assert entered.is_set()


def test_failed_shared_metadata_migration_retries_without_recomputing_native_work(
    tmp_path, monkeypatch, policy
):
    calls = []

    @verified_replay("shared_migration_failure", Result)
    def verify(policy):
        calls.append(1)
        return Result(value="complete")

    old = VerificationReuse(tmp_path / "local", owner="validator")
    with old.selected():
        verify(policy)
    monkeypatch.setenv("UMI_NATIVE_VERIFICATION_DIRECTORY", str(tmp_path / "shared"))
    migrated = VerificationReuse(tmp_path / "local", owner="validator")

    def no_storage(*args):
        raise OSError("metadata storage unavailable")

    with monkeypatch.context() as fault:
        fault.setattr(migrated, "remember", no_storage)
        with migrated.selected(), pytest.raises(OSError, match="metadata storage unavailable"):
            verify(policy)
    assert len(calls) == 1
    with VerificationReuse(tmp_path / "local", owner="validator").selected():
        assert verify(policy).value == "complete"
    with VerificationReuse(tmp_path / "other-role", owner="validator").selected():
        assert verify(policy).value == "complete"
    assert len(calls) == 1
    assert list(old.directory.glob("*.json"))


def test_interrupted_completion_marker_recovers_existing_result_without_native_recheck(
    tmp_path, monkeypatch, policy
):
    calls = []

    @verified_replay("completion_marker_failure", Result)
    def verify(policy):
        calls.append(1)
        return Result(value="complete")

    owner = VerificationReuse(tmp_path / "state", owner="validator")

    def no_marker(*args):
        raise OSError("completion marker unavailable")

    with monkeypatch.context() as fault:
        fault.setattr(reuse_module, "remember_metadata_completion", no_marker)
        with owner.selected(), pytest.raises(OSError, match="completion marker unavailable"):
            verify(policy)
    assert len(calls) == 1
    assert list(owner.directory.glob("*.json"))
    assert not list(owner.directory.glob("*.complete"))
    with VerificationReuse(tmp_path / "state", owner="validator").selected():
        assert verify(policy).value == "complete"
    assert len(calls) == 1
    assert list(owner.directory.glob("*.complete"))


def test_empty_service_setting_preserves_completed_default_receipts(tmp_path, monkeypatch, policy):
    monkeypatch.delenv("UMI_NATIVE_VERIFICATION_DIRECTORY", raising=False)
    calls = []

    @verified_replay("empty_service_setting", Result)
    def verify(policy):
        calls.append(1)
        return Result(value="complete")

    directory = tmp_path / "native"
    with VerificationReuse(directory, owner="validator").selected():
        verify(policy)
    monkeypatch.setenv("UMI_NATIVE_VERIFICATION_DIRECTORY", "")
    for _ in range(2):
        owner = VerificationReuse(directory, owner="validator")
        assert owner.directory == directory
        with owner.selected():
            assert verify(policy).value == "complete"
    assert len(calls) == 1


@pytest.mark.parametrize("value", ["relative", ".", "../receipts"])
def test_relative_shared_setting_refuses_before_state_changes(tmp_path, monkeypatch, value):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("UMI_NATIVE_VERIFICATION_DIRECTORY", value)
    with pytest.raises(ValueError, match="absolute path"):
        VerificationReuse(tmp_path / "native", owner="validator")
    assert list(tmp_path.iterdir()) == []
