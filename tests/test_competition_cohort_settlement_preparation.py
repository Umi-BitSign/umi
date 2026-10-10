"""Recurring preparation precedes closure and reuses native immutable receipts."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from umi import competition_artifacts as artifacts
from umi import competition_cohort_settlement_preparation as preparation_module
from umi.competition_cohort_settlement_preparation import SettlementArtifactPreparation
from umi.open_competition import digest
from umi.private_files import publish_private_model

from .test_open_competition import bundle_at
from .test_open_competition import policy as policy


def worker(tmp_path, policy, *, batch_size=2):
    config = SimpleNamespace(
        policy=policy,
        series=SimpleNamespace(
            recovery=SimpleNamespace(authority={"fixture": "selected authority"}),
            cohorts=({"fixture": "selected cohort"},),
        ),
    )
    promotion = SimpleNamespace(directory=tmp_path / "promotion")
    return SettlementArtifactPreparation(config, promotion, {}, batch_size=batch_size)


async def test_prepares_legacy_archive_without_closure_and_reuses_after_restart(
    tmp_path, policy, monkeypatch
):
    preparation = worker(tmp_path, policy)
    source = tmp_path / "source"
    bundle = bundle_at(source)
    artifacts.preserve_bundle(bundle, source, preparation.archive, policy)
    receipt = preparation.archive / (".verified-" + digest(bundle) + ".json")
    receipt.unlink()  # Historical archive with no durable verification receipt.
    calls = []
    original = artifacts._copy_verified

    def counted(stream, record, output):
        calls.append(record.path)
        return original(stream, record, output)

    monkeypatch.setattr(artifacts, "_copy_verified", counted)
    report = await preparation.poll_once(asyncio.Event())
    assert report["entries_ready"] == 1 and report["entries_pending"] == 0
    assert calls == [record.path for record in bundle.files]
    assert receipt.exists()
    assert not any(
        report[k]
        for k in ("request_closure_authorized", "scoring_authorized", "chain_submission_authorized")
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("verified model bytes were read again")

    monkeypatch.setattr(artifacts, "_copy_verified", forbidden)
    restarted = worker(tmp_path, policy)
    assert (await restarted.poll_once(asyncio.Event()))["entries_ready"] == 1
    assert artifacts.verify_preserved_bundle(bundle, preparation.archive, policy) == digest(bundle)


async def test_missing_entry_does_not_starve_ready_sibling_and_is_retried(tmp_path, policy):
    preparation = worker(tmp_path, policy, batch_size=1)
    source = tmp_path / "source"
    bundle = bundle_at(source)
    artifacts.preserve_bundle(bundle, source, preparation.archive, policy)
    missing = preparation.archive / ("0" * 64)
    missing.mkdir(mode=0o700)
    stop = asyncio.Event()
    assert (await preparation.poll_once(stop))["entries_pending"] == 1
    assert (await preparation.poll_once(stop))["entries_ready"] == 1
    assert (await preparation.poll_once(stop))["entries_pending"] == 1
    assert (await preparation.poll_once(stop))["entries_ready"] == 1
    stop.set()
    assert (await preparation.poll_once(stop))["entries_checked"] == 0


@pytest.mark.parametrize("fault", ["changed-file", "manifest-identity", "symlink"])
async def test_preparation_never_marks_changed_or_linked_content_ready(tmp_path, policy, fault):
    preparation = worker(tmp_path, policy)
    source = tmp_path / "source"
    bundle = bundle_at(source)
    root = artifacts.preserve_bundle(bundle, source, preparation.archive, policy)
    if fault == "changed-file":
        path = root / "model" / bundle.files[0].path
        path.chmod(0o600)
        path.write_bytes(b"x" * path.stat().st_size)
        path.chmod(0o400)
    elif fault == "manifest-identity":
        root.rename(preparation.archive / ("1" * 64))
    else:
        target = root.with_name("outside-inventory")
        root.rename(target)
        root.symlink_to(target, target_is_directory=True)
    report = await preparation.poll_once(asyncio.Event())
    assert report["entries_ready"] == 0 and report["entries_pending"] == 1


@pytest.mark.parametrize("interval", [0, -1, float("inf"), float("nan")])
async def test_bad_interval_refused_before_work(tmp_path, policy, interval):
    with pytest.raises(ValueError, match="interval"):
        await worker(tmp_path, policy).run(asyncio.Event(), poll_seconds=interval)


async def test_unselected_cohort_publication_is_not_consumed(tmp_path, policy):
    preparation = worker(tmp_path, policy)
    from pydantic import RootModel

    publish_private_model(
        preparation.root / "model-reward-preparation" / ("f" * 64) / ("a" * 64 + ".json"),
        RootModel({"untrusted": "not selected"}),
    )
    assert (await preparation.poll_once(asyncio.Event()))["entries_checked"] == 0


async def test_cancellation_drains_owned_verification_before_exit(tmp_path, policy, monkeypatch):
    preparation = worker(tmp_path, policy)
    source = tmp_path / "source"
    bundle = bundle_at(source)
    root = artifacts.preserve_bundle(bundle, source, preparation.archive, policy)
    entered, release, finished = asyncio.Event(), threading.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    original = artifacts.verify_preserved_bundle

    def slow(*args):
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(120)
        result = original(*args)
        finished.set()
        return result

    monkeypatch.setattr(preparation_module, "verify_preserved_bundle", slow)
    task = asyncio.create_task(preparation._prepare("local/" + digest(bundle), root))
    try:
        await asyncio.wait_for(entered.wait(), 120)
        task.cancel()
        done, _ = await asyncio.wait((task,), timeout=0.05)
        assert not done and not finished.is_set()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert finished.is_set()
