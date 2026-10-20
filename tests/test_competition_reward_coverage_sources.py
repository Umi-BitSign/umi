"""Coverage source transport uses isolated completions, never production authority."""

import hashlib
from types import SimpleNamespace

import pytest

from umi.competition_reward_coverage_intervals import CoveragePoint, _issue_retained_coverage
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_remote_proof_store import EvidenceServer, store
from .test_competition_reward_coverage_export import completed_case
from .test_competition_reward_coverage_intervals import rule


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    c = completed_case(tmp_path, monkeypatch)
    server = EvidenceServer()
    remote_root = tmp_path / "remote"

    def reopen():
        remote = store(remote_root, server)
        return RewardCoverageJournal(
            c.journal.journal.root,
            c.rule,
            expected_rule_sha256=digest(c.rule),
            export_archive=RewardProofArchive(
                c.archive.root, remote=remote, legacy_read_through=True
            ),
        )

    return SimpleNamespace(c=c, server=server, reopen=reopen)


async def test_retained_native_endpoint_does_not_start_source_migration(legacy, monkeypatch):
    h = legacy
    journal = h.reopen()
    original = journal.checkpoints.load(h.c.key)
    # First delivery to a new destination is separate from source migration.
    journal._export(h.c.key, journal.export_archive)
    journal.remote_store.evict_cache()
    h.server.calls.clear()

    def prohibited(*_args, **_kwargs):
        pytest.fail("ordinary native retention started bulk source migration")

    monkeypatch.setattr(journal.externalized, "externalize_many", prohibited)
    retained = _issue_retained_coverage(
        CoveragePoint.model_validate(original["point"]),
        original["package_sha256"],
        digest(original),
    )
    assert await journal.retain_endpoint(retained) == h.c.key
    assert journal.checkpoints.load(h.c.key) == original
    assert not h.server.calls
    with journal.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0


async def test_bounded_migration_resumes_after_restart_without_changing_success(legacy):
    h = legacy
    journal = h.reopen()
    original = journal.checkpoints.load(h.c.key)
    first = await journal.externalize_endpoint_sources(h.c.key, maximum_records=1)
    assert first["replicated_records"] == 1 and first["remaining_local_records"] > 0
    journal = h.reopen()
    assert journal.checkpoints.load(h.c.key) == original
    while first["remaining_local_records"]:
        result = await journal.externalize_endpoint_sources(h.c.key, maximum_records=2)
        assert 0 < result["replicated_records"] <= 2 and result["restored_records"] == 0
        assert result["remaining_local_records"] < first["remaining_local_records"]
        first = result
    h.server.calls.clear()
    assert (await journal.externalize_endpoint_sources(h.c.key))["state"] == "completed"
    assert not h.server.calls and journal.checkpoints.load(h.c.key) == original


async def test_v3_upgrade_preserves_old_aliases_sources_success_and_inode(legacy):
    journal = legacy.reopen()
    original = journal.checkpoints.load(legacy.c.key)
    before = journal.journal.path.stat()
    await journal.externalize_endpoint_sources(legacy.c.key, maximum_records=1)
    with journal.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
    raw = b"new coverage object after the supported upgrade"
    key = hashlib.sha256(raw).hexdigest()
    journal._commit_records([("coverage_object", key, {"hex": raw.hex()})])
    after = journal.journal.path.stat()
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    assert legacy.reopen().checkpoints.load(legacy.c.key) == original
    with journal.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
    assert journal.journal.get("coverage_object", key) is None


async def test_full_legacy_owner_reclaims_large_source_before_small_alias_growth(legacy):
    journal = legacy.reopen()
    original = journal.checkpoints.load(legacy.c.key)
    with journal.journal.read_transaction() as db:
        _count, used, _extra = journal.journal._record_capacity(db)
    journal.journal.maximum_bytes = used
    result = await journal.externalize_endpoint_sources(legacy.c.key, maximum_records=1)
    assert result["replicated_records"] == 1 and result["released_logical_bytes"] > 0
    assert journal.checkpoints.load(legacy.c.key) == original


async def test_interruption_preserves_alias_and_retry_skips_its_payload(legacy, monkeypatch):
    h = legacy
    journal = h.reopen()
    original = journal.checkpoints.load(h.c.key)
    publish, done = journal.externalized.externalize, []

    def interrupted(kind, key):
        if done:
            raise OSError("interrupted after one durable alias")
        result = publish(kind, key)
        done.append((kind, key))
        return result

    monkeypatch.setattr(journal.externalized, "externalize", interrupted)
    with pytest.raises(OSError, match="one durable alias"):
        await journal.externalize_endpoint_sources(h.c.key, maximum_records=2)
    journal = h.reopen()
    raw = journal.journal.get_raw

    def no_old_payload(kind, key, **kwargs):
        assert (kind, key) not in done
        return raw(kind, key, **kwargs)

    monkeypatch.setattr(journal.journal, "get_raw", no_old_payload)
    result = await journal.externalize_endpoint_sources(h.c.key, maximum_records=4096)
    assert result["state"] == "completed" and result["restored_records"] == 0
    assert journal.checkpoints.load(h.c.key) == original


def fresh(tmp_path, *, legacy=False):
    server = EvidenceServer()
    remote = store(tmp_path / "remote", server)
    selected = rule()
    journal = RewardCoverageJournal(
        tmp_path / "coverage",
        selected,
        expected_rule_sha256=digest(selected),
        export_archive=RewardProofArchive(
            tmp_path / "export", remote=remote, legacy_read_through=legacy
        ),
    )
    records = [
        ("coverage_object", hashlib.sha256(raw).hexdigest(), {"hex": raw.hex()})
        for raw in (b"first proof object", b"second proof object")
    ]
    journal._pending_sources["ee" * 32] = [(kind, key) for kind, key, _value in records]
    interval = ("coverage_interval", "aa" * 32, {"fixture": "adjacent interval"})
    return journal, server, records, interval


@pytest.mark.parametrize("legacy", [False, True])
def test_new_sources_are_remote_before_atomic_interval_commit(tmp_path, legacy):
    journal, _server, records, interval = fresh(tmp_path, legacy=legacy)
    journal._commit_records([*records, interval])
    assert journal.journal.get(*interval[:2]) == interval[2]
    for kind, key, value in records:
        assert journal.journal.get(kind, key) is None
        with journal.journal.read_transaction() as db:
            assert journal.externalized.get(kind, key, db=db) == value
    assert journal._pending_tokens["ee" * 32] == [[r[0], r[1], 0] for r in records]
    assert not journal.journal.keys("coverage_verified")


def test_failed_new_source_upload_cannot_commit_interval_and_retries_exactly(tmp_path):
    journal, server, records, interval = fresh(tmp_path)
    server.fail_put_suffix = hashlib.sha256(canonical_json_bytes(records[1][2])).hexdigest()
    with pytest.raises(OSError, match="HTTP 503"):
        journal._commit_records([*records, interval])
    assert journal.journal.get(*interval[:2]) is None
    assert not journal.journal.keys("coverage_remote_source")
    server.fail_put_suffix = None
    journal._commit_records([*records, interval])
    assert journal.journal.get(*interval[:2]) == interval[2]
    assert len(journal.journal.keys("coverage_remote_source")) == len(records)


@pytest.mark.parametrize("kind", ["coverage_object", "coverage_remote_source"])
def test_additional_metadata_cannot_bypass_remote_source_capture(tmp_path, kind):
    journal, server, _records, _interval = fresh(tmp_path)
    with pytest.raises(ValueError, match="cannot bypass"):
        journal.externalized.capture(
            [], index=lambda _db: None, additional_records=[(kind, "aa" * 32, {})]
        )
    assert not server.calls


@pytest.mark.parametrize("maximum", [0, True, 4097])
async def test_migration_rejects_invalid_batch_before_publication(legacy, maximum):
    with pytest.raises(ValueError, match="bounded record batch"):
        await legacy.reopen().externalize_endpoint_sources(legacy.c.key, maximum_records=maximum)
    assert not legacy.server.calls
