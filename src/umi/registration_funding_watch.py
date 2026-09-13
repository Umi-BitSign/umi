"""Temporary, read-only funding audit queue. No validator or wallet access."""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import getpass
import hashlib
import json
import os
import sqlite3
import stat
import time
from collections import Counter
from pathlib import Path

import httpx

from .protocol import canonical_json_bytes
from .registration_bridge import REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK
from .registration_funding_audit import (
    REQUEST_INTERVAL_SECONDS,
    APIAccessError,
    FundingAuditError,
    TaostatsTransfers,
    TransferHistory,
    audit_funding,
    capture_roster,
)


def _digest(value):
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def registration_key(registration):
    return _digest(
        {
            "network": "finney",
            "netuid": 78,
            "uid": registration.uid,
            "hotkey": registration.hotkey,
            "coldkey": registration.coldkey,
            "registered_at_block": registration.registered_at_block,
        }
    )


class FundingCache:
    """One owner-private SQLite cache, with a process lock and durable rate budget."""

    def __init__(self, root: Path):
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise FundingAuditError("unsafe_funding_cache")
        self.root, self.lock, self.db = root, -1, None
        try:
            self.lock = self._private_file("worker.lock")
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            database = self._private_file("funding.sqlite3")
            os.close(database)
            self.db = sqlite3.connect(root / "funding.sqlite3")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS histories (
                    query_key TEXT PRIMARY KEY, body TEXT NOT NULL, retry_after REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS registrations (
                    registration_key TEXT PRIMARY KEY, body TEXT NOT NULL);
            """)
            version = self.get("schema", "1")
            if version != "1":
                raise FundingAuditError("unsupported_funding_cache")
            self.set("schema", "1")
        except BaseException:
            self.close()
            raise

    def _private_file(self, name):
        descriptor = os.open(self.root / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise FundingAuditError("unsafe_funding_cache_file")
        return descriptor

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock >= 0:
            os.close(self.lock)
            self.lock = -1

    def get(self, name, default):
        row = self.db.execute("SELECT value FROM metadata WHERE name=?", (name,)).fetchone()
        return default if row is None else row[0]

    def set(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (name, str(value)))
        self.db.commit()

    def record_roster(self, roster):
        for registration in roster.participants:
            self.db.execute(
                "INSERT OR IGNORE INTO registrations VALUES (?,?)",
                (
                    registration_key(registration),
                    canonical_json_bytes(registration).decode(),
                ),
            )
        self.db.commit()

    @staticmethod
    def query_key(owner, before):
        return _digest(
            {
                "schema": "funding-query/1",
                "network": "finney",
                "owner": owner,
                "before_block": before,
            }
        )

    def history(self, owner, before):
        row = self.db.execute(
            "SELECT body,retry_after FROM histories WHERE query_key=?",
            (self.query_key(owner, before),),
        ).fetchone()
        if row is None:
            return None
        body = json.loads(row[0])
        result = TransferHistory(
            body["status"], tuple(body["transfers"]), tuple(body["page_sha256"])
        )
        if (
            result.status in {"reported_complete", "registration_at_genesis"}
            or row[1] > time.time()
        ):
            return result
        return None

    def save_history(self, owner, before, history):
        retry = 3600 if history.status == "page_bound_reached" else 600
        payload = {
            "status": history.status,
            "transfers": list(history.transfers),
            "page_sha256": list(history.page_sha256),
        }
        self.db.execute(
            "INSERT OR REPLACE INTO histories VALUES (?,?,?)",
            (
                self.query_key(owner, before),
                canonical_json_bytes(payload).decode(),
                time.time() + retry,
            ),
        )
        self.db.commit()

    def publish(self, report):
        path = self.root / "report.json"
        # The directory is private and locked. Replacement affects this report
        # only; it never follows an existing symlink or edits validator state.
        temporary = self.root / "report.next.json"
        descriptor = self._private_file(temporary.name)
        with os.fdopen(descriptor, "wb") as output:
            output.truncate(0)
            output.write(canonical_json_bytes(report))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class BudgetedTransfers(TaostatsTransfers):
    def __init__(self, client, cache, *, max_requests):
        super().__init__(client)
        self.cache, self.max_requests = cache, max_requests

    async def _page(self, recipient, before_block, page):
        count = int(self.cache.get("requests_started", "0"))
        if count >= self.max_requests:
            raise FundingAuditError("audit_request_budget_exhausted")
        delay = (
            float(self.cache.get("last_request_unix", "0")) + REQUEST_INTERVAL_SECONDS - time.time()
        )
        if delay > 60:
            raise FundingAuditError("audit_clock_moved_backwards")
        await asyncio.sleep(max(0, delay))
        # Reserve before HTTP. A crash consumes a request rather than resetting
        # the rate/budget counter. No API key is stored in this database.
        with self.cache.db:
            self.cache.db.executemany(
                "INSERT OR REPLACE INTO metadata VALUES (?,?)",
                [
                    ("requests_started", str(count + 1)),
                    ("last_request_unix", str(time.time())),
                ],
            )
        return await super()._page(recipient, before_block, page)


class CachedTransfers:
    def __init__(self, api, cache, *, new_lookups_per_cycle=5):
        self.api, self.cache, self.remaining = api, cache, new_lookups_per_cycle

    async def history(self, owner, before):
        stored = self.cache.history(owner, before)
        if stored is not None:
            return stored
        if self.remaining <= 0:
            return TransferHistory("queued")
        self.remaining -= 1
        result = await self.api.history(owner, before)
        self.cache.save_history(owner, before, result)
        return result


async def cycle(roster, api, cache, *, shared_funders=()):
    cache.record_roster(roster)
    if roster.finalized_block >= REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK:
        report = {
            "schema": "umi-registration-funding-watch/1",
            "status": "bridge_ended",
            "finalized_block": roster.finalized_block,
            "reward_changes_authorized": False,
        }
    else:
        report = await audit_funding(
            roster, CachedTransfers(api, cache), shared_funders=shared_funders
        )
        statuses = {h["status"] for h in report["histories"]}
        report["status"] = "scan_complete"
        if statuses & {"unverified_history", "page_bound_reached"}:
            report["status"] = "scan_complete_with_unknowns"
        if "queued" in statuses:
            report["status"] = "collecting"
        report["history_status_counts"] = dict(Counter(h["status"] for h in report["histories"]))
    report["requests_started"] = int(cache.get("requests_started", "0"))
    report["updated_at_unix_ms"] = int(time.time() * 1000)
    cache.publish(report)
    return report


def private_api_key(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or not 1 <= info.st_size <= 4096
        ):
            raise FundingAuditError("unsafe_api_key_file")
        payload = source.read(4097)
    if len(payload) > 4096:
        raise FundingAuditError("unsafe_api_key_file")
    return payload.decode("ascii").strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument(
        "--once", action="store_true", help="process at most five uncached histories"
    )
    key_source = parser.add_mutually_exclusive_group()
    key_source.add_argument("--prompt-api-key", action="store_true")
    key_source.add_argument("--api-key-file", type=Path, help="owner-private credential file")
    parser.add_argument("--shared-funder", action="append", default=[])
    parser.add_argument(
        "--max-requests", type=int, default=1000, help="persistent lifetime API-call cap"
    )
    args = parser.parse_args(argv)
    if not 1 <= args.max_requests <= 10000:
        parser.error("--max-requests must be between 1 and 10000")
    try:
        key = (
            private_api_key(args.api_key_file)
            if args.api_key_file
            else getpass.getpass("Taostats API key: ")
            if args.prompt_api_key
            else os.environ.get("TAOSTATS_API_KEY", "")
        ).strip()
    except (OSError, ValueError):
        print('{"status":"held","reason":"unsafe_api_key_file"}')
        return 2
    if not key:
        print('{"status":"held","reason":"taostats_api_key_missing"}')
        return 2
    cache = None

    async def run():
        async with httpx.AsyncClient(
            headers={"Authorization": key}, timeout=20, follow_redirects=False, trust_env=False
        ) as client:
            api = BudgetedTransfers(client, cache, max_requests=args.max_requests)
            while True:
                roster = await asyncio.wait_for(capture_roster(), 120)
                result = await cycle(roster, api, cache, shared_funders=args.shared_funder)
                print(
                    json.dumps(
                        {
                            k: result[k]
                            for k in ("status", "requests_started", "reward_changes_authorized")
                        }
                    ),
                    flush=True,
                )
                if args.once or result["status"] == "bridge_ended":
                    return
                if result["requests_started"] >= args.max_requests:
                    print('{"status":"held","reason":"audit_request_budget_exhausted"}', flush=True)
                    return
                await asyncio.sleep(30)

    try:
        cache = FundingCache(args.state_root)
        asyncio.run(run())
    except APIAccessError:
        print('{"status":"held","reason":"taostats_access_required"}')
        return 2
    except (ValueError, OSError, RuntimeError, httpx.HTTPError, sqlite3.Error):
        print('{"status":"held","reason":"funding_watch_failed"}')
        return 1
    finally:
        if cache is not None:
            cache.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
