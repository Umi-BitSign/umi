"""Additive transfers coexist with live cursors; imported bytes grant no authority."""

import fcntl
import hashlib
import json
import multiprocessing
import os
import sqlite3
from contextlib import closing

import pytest

from umi import historical_header_hint_import as module
from umi import historical_header_hint_import_cli as cli
from umi.finalized_ancestry import encode_rpc_header
from umi.historical_header_recovery import HistoricalHeaderRecovery

from .test_competition_chain import chain_config as chain_config
from .test_finalized_ancestry import make_headers
from .test_historical_header_recovery import finish
from .test_historical_header_recovery import walk as walk
from .test_open_competition import policy as policy


def database(path, rows=()):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE historical_header_hints (hash TEXT PRIMARY KEY, encoded TEXT NOT NULL)"
        )
        db.executemany("INSERT INTO historical_header_hints VALUES (?,?)", rows)
    path.chmod(0o600)
    return path


def case(tmp_path, count=10):
    headers, heights = make_headers(100, 100 + count - 1)
    rows = [(heights[h], encode_rpc_header(headers[heights[h]])) for h in heights]
    source = database(tmp_path / "source" / "historical-headers.sqlite3", rows)
    target = database(tmp_path / "target" / "historical-headers.sqlite3")
    (target.parent / "owner.lock").touch(mode=0o600)
    return source, target, rows


def importer(source, target, **kwargs):
    return module.HeaderHintImport(
        source,
        target.parent,
        operation="retained-v1",
        maximum_bytes=kwargs.pop("maximum_bytes", 1024**2),
        maximum_database_bytes=1024**2,
        batch_size=3,
        **kwargs,
    )


def all_rows(path):
    with closing(sqlite3.connect(path)) as db:
        return db.execute(
            "SELECT hash,encoded FROM historical_header_hints ORDER BY hash"
        ).fetchall()


def complete(service):
    for _ in range(20):
        result = service.step()
        if result["state"] == "completed":
            return result
    pytest.fail("transfer did not converge")


def test_online_additive_import_preserves_owner_lock_existing_rows_and_source(tmp_path):
    source, target, rows = case(tmp_path)
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    with sqlite3.connect(target) as db:
        db.execute("INSERT INTO historical_header_hints VALUES (?,?)", rows[0])
    fd = os.open(target.parent / "owner.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = complete(importer(source, target))
    finally:
        os.close(fd)
    assert result["inserted_headers"] == 9
    assert result["reused_headers"] == 1
    assert result["finality_authority"] is False
    assert result["native_verification_completed"] is False
    assert all_rows(target) == sorted(rows)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original


def test_restart_uses_atomic_transfer_checkpoint_without_redecoding_completed_rows(
    tmp_path, monkeypatch
):
    source, target, rows = case(tmp_path)
    first = importer(source, target).step()
    assert first["processed_headers"] == 3
    decode, calls = module._decode_header, []

    def counted(encoded, **kwargs):
        calls.append(encoded)
        return decode(encoded, **kwargs)

    monkeypatch.setattr(module, "_decode_header", counted)
    result = complete(importer(source, target))
    assert len(calls) == 7
    assert result["processed_headers"] == 10
    assert complete(importer(source, target))["inserted_headers"] == 10
    assert len(calls) == 7
    assert all_rows(target) == sorted(rows)


def test_conflict_refuses_entire_batch_without_overwrite(tmp_path):
    source, target, rows = case(tmp_path)
    with sqlite3.connect(target) as db:
        db.execute("INSERT INTO historical_header_hints VALUES (?,?)", (rows[1][0], rows[2][1]))
    before = all_rows(target)
    with pytest.raises(ValueError, match="conflicts"):
        importer(source, target).step()
    assert all_rows(target) == before


def test_payload_capacity_rolls_back_batch_and_increase_resumes(tmp_path):
    source, target, rows = case(tmp_path)
    with pytest.raises(sqlite3.OperationalError, match="capacity required"):
        importer(source, target, maximum_bytes=len(rows[0][1])).step()
    assert all_rows(target) == []
    assert complete(importer(source, target))["processed_headers"] == len(rows)


def test_busy_writer_is_bounded_and_retry_preserves_native_addition(tmp_path):
    source, target, rows = case(tmp_path)
    service = importer(source, target, busy_timeout_seconds=0.01)
    with closing(sqlite3.connect(target, isolation_level=None)) as live:
        live.execute("BEGIN IMMEDIATE")
        live.execute("INSERT INTO historical_header_hints VALUES (?,?)", rows[0])
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            service.step()
        live.commit()
    result = complete(service)
    assert result["reused_headers"] == 1
    assert all_rows(target) == sorted(rows)


def _native_writer_process(path, row, channel):
    """Independent OS process running the genuine native hint-save transaction."""

    def connect():
        db = sqlite3.connect(path, isolation_level=None, timeout=0.05)
        db.execute("PRAGMA synchronous=FULL")
        return db

    native = HistoricalHeaderRecovery(connect)
    channel.send("ready")
    try:
        while channel.recv() == "write":
            try:
                native._save(*row)
            except sqlite3.OperationalError as error:
                channel.send(("sqlite_error", getattr(error, "sqlite_errorcode", None)))
            else:
                channel.send(("written", None))
    finally:
        channel.close()


@pytest.mark.parametrize("contended_database", ["source", "target"])
def test_live_native_writer_cannot_enter_importer_transaction_after_identity_recheck(
    tmp_path, monkeypatch, contended_database
):
    source, target, rows = case(tmp_path)
    extra_headers, extra_heights = make_headers(200, 200)
    block_hash = extra_heights[200]
    extra = (block_hash, encode_rpc_header(extra_headers[block_hash]))
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    worker = context.Process(
        target=_native_writer_process,
        args=(source if contended_database == "source" else target, extra, child),
    )
    worker.start()
    child.close()
    try:
        assert parent.poll(10) and parent.recv() == "ready"
        service = importer(source, target)
        recheck, calls, observed = service._recheck, 0, []

        def synchronized_recheck():
            nonlocal calls
            recheck()
            calls += 1
            if calls == 2:
                # This is the path check after inserted hints but before the
                # transfer checkpoint and COMMIT. A raw fd close here releases
                # process-wide POSIX SQLite locks and lets this writer enter.
                parent.send("write")
                assert parent.poll(10)
                observed.append(parent.recv())
                assert observed[-1] == ("sqlite_error", sqlite3.SQLITE_BUSY)

        monkeypatch.setattr(service, "_recheck", synchronized_recheck)
        assert service.step()["processed_headers"] == 3
        assert len(observed) == 1
        parent.send("write")
        assert parent.poll(10) and parent.recv() == ("written", None)
        monkeypatch.setattr(service, "_recheck", recheck)
        assert complete(service)["processed_headers"] == len(rows)
        expected = rows + ([extra] if contended_database == "target" else [])
        assert all_rows(target) == sorted(expected)
        for path in (source, target):
            with closing(sqlite3.connect(path)) as db:
                assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    finally:
        if worker.is_alive():
            parent.send("stop")
        worker.join(10)
        if worker.is_alive():
            worker.terminate()
            worker.join(5)
        parent.close()
    assert worker.exitcode == 0


def test_changed_source_identity_and_target_symlink_refused(tmp_path):
    source, target, rows = case(tmp_path)
    service = importer(source, target)
    moved = source.with_name("old.sqlite3")
    source.rename(moved)
    database(source, rows)
    with pytest.raises(ValueError, match="identity changed"):
        service.step()
    target.rename(target.with_name("old.sqlite3"))
    target.symlink_to(target.with_name("old.sqlite3"))
    with pytest.raises((ValueError, OSError)):
        importer(source, target)


def test_source_append_remains_outside_fixed_operation_scope(tmp_path):
    source, target, rows = case(tmp_path)
    service = importer(source, target)
    assert service.step()["processed_headers"] == 3
    extra_headers, extra_heights = make_headers(200, 200)
    block_hash = extra_heights[200]
    extra = (block_hash, encode_rpc_header(extra_headers[block_hash]))
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO historical_header_hints VALUES (?,?)", extra)
    result = complete(importer(source, target))
    assert result["processed_headers"] == result["total_headers"] == len(rows)
    assert all_rows(target) == sorted(rows)


def test_cli_capacity_reports_unknown_scope_without_false_completion(tmp_path, capsys):
    source, target, _ = case(tmp_path)
    args = [
        "--source",
        str(source),
        "--target-directory",
        str(target.parent),
        "--operation",
        "capacity-v1",
        "--maximum-bytes",
        "1",
        "--maximum-database-bytes",
        str(1024**2),
    ]
    with pytest.raises(SystemExit) as ended:
        cli.main(args)
    assert ended.value.code == 2
    result = json.loads(capsys.readouterr().out.strip())
    assert result["state"] == "capacity_required"
    assert result["percent"] is None
    assert result["eta_seconds"] is None
    assert result["finality_authority"] is False
    assert all_rows(target) == []


def test_cli_resume_and_repeat_complete_without_authority(tmp_path, capsys):
    source, target, rows = case(tmp_path)
    args = [
        "--source",
        str(source),
        "--target-directory",
        str(target.parent),
        "--operation",
        "cli-v1",
        "--maximum-bytes",
        str(1024**2),
        "--maximum-database-bytes",
        str(1024**2),
        "--batch-size",
        "3",
    ]
    cli.main(args)
    first = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert first[-1]["state"] == "completed"
    assert first[-1]["inserted_headers"] == len(rows)
    cli.main(args)
    repeated = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(repeated) == 1
    assert repeated[0]["state"] == "completed"
    assert repeated[0]["native_verification_completed"] is False


@pytest.mark.asyncio
async def test_imported_headers_still_require_native_owned_anchor_walk(walk, tmp_path):
    w = walk
    rows = [(block_hash, encode_rpc_header(header)) for block_hash, header in w.headers.items()]
    source = database(tmp_path / "source" / "historical-headers.sqlite3", rows)
    target = database(tmp_path / "target" / "historical-headers.sqlite3")
    (target.parent / "owner.lock").touch(mode=0o600)

    def connect():
        return sqlite3.connect(target, isolation_level=None)

    recovery = HistoricalHeaderRecovery(connect, batch_size=4)
    from umi.historical_header_recovery import HistoricalHeaderRecoveryProgress

    with pytest.raises(HistoricalHeaderRecoveryProgress):
        await recovery.recover(w.anchor, w.target, w.request)
    assert len(w.calls) == 4
    prior_cursor = dict(recovery.progress)
    complete(importer(source, target))
    assert dict(recovery.progress) == prior_cursor
    assert (await finish(recovery, w)).snapshot == w.target
    assert len(w.calls) == 4
    restarted = HistoricalHeaderRecovery(connect)
    assert restarted._verified == {}
    assert (await finish(restarted, w)).snapshot == w.target
    assert len(w.calls) == 4
