"""Bounded upload scheduling; authenticated payload replay is tested separately."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi import competition_exchange as exchange
from umi.open_competition import digest, identity
from umi.protocol import StrictProtocolModel

from .test_open_competition import wallet


class Payload(StrictProtocolModel):
    counter: int


@pytest.fixture
def uploads(tmp_path, monkeypatch):
    database = tmp_path / "delivery.sqlite3"
    outbox = tmp_path / "outbox"
    outbox.mkdir(mode=0o700)
    hotkey = wallet("Charlie").hotkey.ss58_address
    config = SimpleNamespace(
        outbox_directory=str(outbox), maximum_orders=16, page_size=2, evaluator_hotkey=hotkey
    )

    @contextmanager
    def transaction():
        with sqlite3.connect(database) as db:
            yield db

    worker = SimpleNamespace(config=config, journal=SimpleNamespace(transaction=transaction))
    calls, reads = [], []

    def read(path, model):
        assert model is exchange.SignedExecutionAnnouncement
        reads.append(path.name)
        return Payload.model_validate_json(path.read_bytes())

    monkeypatch.setattr(exchange, "_read", read)

    async def query(operation, **fields):
        assert operation == "put"
        calls.append(fields)
        event = SimpleNamespace(
            order_sha256=fields["order_sha256"],
            kind=fields["kind"],
            author=identity(hotkey),
            payload_sha256=fields["payload_sha256"],
        )
        return SimpleNamespace(items=(event,))

    def client():
        value = exchange.EvaluatorExchangeClient(worker, "https://relay.example")
        value.query = query
        return value

    first = client()

    def add(number, *, sent=False):
        name = f"{number:064x}.{identity(hotkey)}.execution.json"
        payload = Payload(counter=number)
        (outbox / name).write_text(payload.model_dump_json())
        if sent:
            with transaction() as db:
                db.execute(
                    "INSERT INTO exchange_delivery VALUES (?,?)", ("sent:" + name, digest(payload))
                )
        return name

    return SimpleNamespace(
        first=first,
        client=client,
        add=add,
        calls=calls,
        reads=reads,
        transaction=transaction,
        outbox=outbox,
        worker=worker,
    )


@pytest.mark.asyncio
async def test_new_evidence_is_not_delayed_by_old_acknowledged_pages(uploads):
    for number in range(9):
        uploads.add(number, sent=True)
    for number in (20, 21):
        uploads.add(number)
    assert await uploads.first.upload_once() == 2
    assert [call["payload"]["counter"] for call in uploads.calls] == [20, 21]
    assert len(uploads.reads) <= 4  # One upload page and one retained-file audit page.


@pytest.mark.asyncio
async def test_upload_budget_restart_and_new_names_before_the_cursor(uploads):
    for number in range(10, 16):
        uploads.add(number)
    for _ in range(3):
        uploads.reads.clear()
        assert await uploads.first.upload_once() == 2
        assert len(uploads.reads) <= 4
    assert len(uploads.calls) == 6
    restarted = uploads.client()
    assert await restarted.upload_once() == 0
    assert len(uploads.calls) == 6
    uploads.add(1)
    assert await uploads.first.upload_once() == 1
    assert uploads.calls[-1]["payload"]["counter"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("pending", [False, True])
async def test_retained_file_audits_rotate_and_reject_changed_bytes(uploads, pending):
    for number in (1, 2, 3):
        name = uploads.add(number, sent=True)
    if pending:
        for number in (10, 11, 12, 13):
            uploads.add(number)
    assert await uploads.first.upload_once() == (2 if pending else 0)
    (uploads.outbox / name).write_text(json.dumps({"counter": 99}))
    with pytest.raises(ValueError, match="previously delivered evaluator output changed"):
        await uploads.first.upload_once()
    assert len(uploads.calls) == (4 if pending else 0)


@pytest.mark.asyncio
async def test_missing_ack_marker_cannot_turn_an_audit_into_an_extra_upload(uploads, monkeypatch):
    name = uploads.add(1, sent=True)
    original = exchange._read

    def remove_marker(path, model):
        value = original(path, model)
        with uploads.transaction() as db:
            db.execute("DELETE FROM exchange_delivery WHERE name=?", ("sent:" + name,))
        return value

    monkeypatch.setattr(exchange, "_read", remove_marker)
    with pytest.raises(ValueError, match="previously delivered evaluator marker disappeared"):
        await uploads.first.upload_once()
    assert not uploads.calls


@pytest.mark.asyncio
async def test_bad_ack_is_not_retained_and_restart_retries_the_same_payload(uploads):
    name = uploads.add(1)
    original = uploads.first.query

    async def bad_ack(*args, **kwargs):
        result = await original(*args, **kwargs)
        result.items[0].payload_sha256 = "00" * 32
        return result

    uploads.first.query = bad_ack
    with pytest.raises(ValueError, match="acknowledgment mismatch"):
        await uploads.first.upload_once()
    with uploads.transaction() as db:
        assert (
            db.execute(
                "SELECT value FROM exchange_delivery WHERE name=?", ("sent:" + name,)
            ).fetchone()
            is None
        )
    assert await uploads.client().upload_once() == 1
    assert uploads.calls[0] == uploads.calls[1]


@pytest.mark.asyncio
async def test_delivery_marker_scan_has_a_capacity_bound(uploads):
    uploads.worker.config.maximum_orders = 1
    with uploads.transaction() as db:
        db.executemany(
            "INSERT INTO exchange_delivery VALUES (?,?)",
            [(f"sent:{number}", "00" * 32) for number in range(4)],
        )
    with pytest.raises(ValueError, match="delivery marker capacity exceeded"):
        await uploads.first.upload_once()
    assert not uploads.reads and not uploads.calls
