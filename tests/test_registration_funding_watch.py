from __future__ import annotations

import json
import os
from types import SimpleNamespace

import httpx
import pytest

from umi import registration_funding_watch as watch
from umi.registration_funding_audit import TransferHistory

from .test_registration_funding_audit import address, histories, page, roster


@pytest.fixture
def cache(tmp_path):
    value = watch.FundingCache(tmp_path / "state")
    try:
        yield value
    finally:
        value.close()


async def test_cached_histories_survive_restart_without_requests(tmp_path):
    path = tmp_path / "cache"
    first = watch.FundingCache(path)
    api = histories()
    try:
        await watch.cycle(roster(), api, first)
        assert len(api.calls) == 3
        first.record_roster(roster())
        assert first.db.execute("SELECT COUNT(*) FROM registrations").fetchone()[0] == 4
    finally:
        first.close()
    second = watch.FundingCache(path)
    try:
        result = await watch.cycle(roster(), api, second)
        assert len(api.calls) == 3
        assert len(result["candidate_groups"]) == 1
        assert result["reward_changes_authorized"] is False
    finally:
        second.close()


async def test_new_uid_identity_gets_a_fresh_history_and_old_uids_stay_cached(cache):
    api = histories()
    original = roster()
    await watch.cycle(original, api, cache)
    changed = original.model_copy(
        update={
            "participants": [
                p.model_copy(update={"hotkey": address(999), "registered_at_block": 160})
                if p.uid == 72
                else p
                for p in original.participants
            ]
        }
    )
    assert watch.registration_key(original.participants[1]) != watch.registration_key(
        changed.participants[1]
    )
    await watch.cycle(changed, api, cache)
    assert len(api.calls) == 4 and api.calls[-1] == (address(3), 160)
    assert cache.db.execute("SELECT COUNT(*) FROM registrations").fetchone()[0] == 5


@pytest.mark.parametrize(
    "update",
    [
        {"hotkey": address(1000)},
        {"coldkey": address(1000)},
        {"registered_at_block": 199},
    ],
)
def test_uid_number_is_never_the_identity_key(update):
    entry = roster().participants[0]
    assert watch.registration_key(entry) != watch.registration_key(entry.model_copy(update=update))


async def test_cycle_limit_queues_uncached_keys_without_calling_api(cache):
    api = histories()
    port = watch.CachedTransfers(api, cache, new_lookups_per_cycle=1)
    assert (await port.history(address(2), 120)).status == "reported_complete"
    assert (await port.history(address(3), 130)).status == "queued"
    assert (await port.history(address(2), 120)).status == "reported_complete"
    assert len(api.calls) == 1
    assert cache.history(address(3), 130) is None


async def test_failed_lookup_retries_after_cooldown_and_stays_ungrouped(cache, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(watch.time, "time", lambda: clock[0])
    api = histories("unverified_history")
    result = await watch.cycle(roster(), api, cache)
    assert not result["candidate_groups"]
    await watch.cycle(roster(), api, cache)
    assert len(api.calls) == 3
    clock[0] += 601
    await watch.cycle(roster(), api, cache)
    assert len(api.calls) == 6


def test_second_worker_cannot_share_locked_state_or_reset_budget(cache):
    cache.set("requests_started", 123)
    with pytest.raises(BlockingIOError):
        watch.FundingCache(cache.root)
    assert cache.get("requests_started", "0") == "123"


def test_private_cache_refuses_symlinks_and_wrong_modes(tmp_path):
    directory = tmp_path / "target"
    directory.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        watch.FundingCache(alias)
    directory.chmod(0o755)
    with pytest.raises(ValueError):
        watch.FundingCache(directory)
    directory.chmod(0o700)
    target = tmp_path / "unrelated"
    target.write_bytes(b"untouched")
    (directory / "funding.sqlite3").symlink_to(target)
    with pytest.raises(OSError):
        watch.FundingCache(directory)
    assert target.read_bytes() == b"untouched"


async def test_bridge_sunset_stops_all_new_queries_but_preserves_cache(cache):
    api = histories()
    await watch.cycle(roster(), api, cache)
    before = cache.db.execute("SELECT COUNT(*) FROM histories").fetchone()[0]
    result = await watch.cycle(
        roster().model_copy(
            update={
                "finalized_block": watch.REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK,
            }
        ),
        api,
        cache,
    )
    assert result["status"] == "bridge_ended" and len(api.calls) == 3
    assert cache.db.execute("SELECT COUNT(*) FROM histories").fetchone()[0] == before


async def test_request_budget_and_restart_throttle_persist(cache, monkeypatch):
    clock, sleeps, calls = [1000.0], [], []
    monkeypatch.setattr(watch.time, "time", lambda: clock[0])

    async def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    monkeypatch.setattr(watch.asyncio, "sleep", sleep)
    cache.set("last_request_unix", 999.0)
    cache.set("requests_started", 9)

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=page([]))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        api = watch.BudgetedTransfers(client, cache, max_requests=10)
        assert (await api.history(address(2), 120)).status == "reported_complete"
        assert sleeps[0] == 11.5
        assert cache.get("requests_started", "0") == "10"
        assert (await api.history(address(3), 120)).status == "unverified_history"
        assert len(calls) == 1


async def test_report_is_private_and_does_not_contain_credentials(cache):
    await watch.cycle(roster(), histories(), cache)
    report_path = cache.root / "report.json"
    report = json.loads(report_path.read_bytes())
    assert report_path.stat().st_mode & 0o777 == 0o600
    assert "Authorization" not in report and "api_key" not in report
    assert report["status"] == "scan_complete"
    assert not (cache.root / "report.next.json").exists()
    assert cache.root.stat().st_uid == os.getuid()


async def test_cache_reuses_owner_history_for_an_additional_uid(cache):
    api = histories()
    original = roster()
    await watch.cycle(original, api, cache)
    extra = original.participants[0].model_copy(
        update={
            "uid": 75,
            "hotkey": address(555),
            "registered_at_block": 190,
        }
    )
    await watch.cycle(
        original.model_copy(update={"participants": [*original.participants, extra]}), api, cache
    )
    assert len(api.calls) == 3


async def test_cache_cannot_convert_queued_or_unknown_history_to_verified(cache):
    async def queued(*_):
        return TransferHistory("unverified_history")

    result = await watch.cycle(roster(), SimpleNamespace(history=queued), cache)
    assert not result["candidate_groups"]
    assert all(h["status"] == "unverified_history" for h in result["histories"])
    assert result["status"] == "scan_complete_with_unknowns"


def test_private_credential_file_rejects_links_and_public_permissions(tmp_path):
    key = tmp_path / "credential"
    key.write_text("test-credential\n")
    key.chmod(0o600)
    assert watch.private_api_key(key) == "test-credential"
    key.chmod(0o400)
    assert watch.private_api_key(key) == "test-credential"
    alias = tmp_path / "alias"
    alias.symlink_to(key)
    with pytest.raises(OSError):
        watch.private_api_key(alias)
    key.chmod(0o644)
    with pytest.raises(ValueError):
        watch.private_api_key(key)
    key.chmod(0o600)
    key.write_bytes(b"x" * 4097)
    with pytest.raises(ValueError):
        watch.private_api_key(key)


def test_invalid_credential_file_does_not_print_its_contents(tmp_path, capsys):
    key = tmp_path / "credential"
    key.write_text("test-secret")
    key.chmod(0o644)
    assert watch.main(["--state-root", str(tmp_path / "state"), "--api-key-file", str(key)]) == 2
    output = capsys.readouterr().out
    assert "unsafe_api_key_file" in output and "test-secret" not in output
