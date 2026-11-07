"""Consistent archived forecast snapshots and resumable explicit offline repair."""

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path

from .competition_forecast_health import (
    health_for_restore,
    initialization_for_restore,
    record_gap,
    write_health,
    write_initialization,
)
from .competition_forecast_io import encode_forecast_json, stream_file
from .competition_transport_verification import TransferProgress
from .file_identity import file_fingerprint
from .private_files import _write_private_bytes, ensure_private_directory, lock_private_file

SCHEMA = "umi-forecast-archive-snapshot/1"
FILES = {
    "forecasts.sqlite3": "forecasts.sqlite3",
    "index.sqlite3": "retention/index/index.sqlite3",
    "binding.json": "retention/index/binding.json",
}
INTENT = "forecast-restore.json"


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path, value):
    _write_private_bytes(path, encode_forecast_json(value))
    _sync(path.parent)


def _read(path, maximum=65536):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError("forecast repair metadata is missing or unbounded")
    return json.loads(path.read_bytes())


def _identity(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("forecast repair file is not regular")
    return list(file_fingerprint(path.stat()))


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _manifest(receipt):
    value = {key: item for key, item in receipt.items() if key != "sha256"}
    if (
        value.get("schema") != SCHEMA
        or set(value.get("files", {})) != set(FILES)
        or hashlib.sha256(encode_forecast_json(value)).hexdigest() != receipt.get("sha256")
    ):
        raise ValueError("forecast archive snapshot receipt is invalid")
    if (
        not _digest(value.get("ledger_sha256"))
        or not isinstance(value.get("head"), list)
        or len(value["head"]) != 2
        or not _digest(value["head"][0])
        or type(value["head"][1]) is not int
        or value["head"][1] < 0
        or any(
            not isinstance(row, dict)
            or set(row) != {"sha256", "bytes"}
            or not _digest(row["sha256"])
            or type(row["bytes"]) is not int
            or row["bytes"] <= 0
            for row in value["files"].values()
        )
        or value.get("bytes") != sum(row["bytes"] for row in value["files"].values())
        or not isinstance(value.get("accounting_health"), dict)
        or value["accounting_health"].get("schema") != "umi-forecast-accounting-health/1"
    ):
        raise ValueError("forecast archive snapshot fields are invalid")
    return value


def _state(path, selection):
    state = _read(path)
    if (
        not isinstance(state, dict)
        or state.get("schema") != "umi-forecast-restore/1"
        or state.get("selection") != selection
        or set(state.get("files", {})) != set(FILES)
        or type(state.get("validated")) is not bool
        or "health" not in state
    ):
        raise ValueError("forecast restoration selection or checkpoint changed")
    for value in state["files"].values():
        if (
            not isinstance(value, dict)
            or set(value)
            != {"prior_sha256", "prior_identity", "staged_identity", "installed_identity"}
            or (value["prior_sha256"] is not None and not _digest(value["prior_sha256"]))
        ):
            raise ValueError("forecast restoration file checkpoint changed")
    return state


def _validate(hot, index, binding, receipt, remote):
    """Validate bounded metadata and durable receipts, without replaying original events."""
    expected = receipt["ledger_sha256"]
    if _read(binding).get("ledger_sha256") != expected:
        raise ValueError("forecast snapshot belongs to another ledger")
    a = sqlite3.connect("file:" + str(hot) + "?mode=ro", uri=True)
    b = sqlite3.connect("file:" + str(index) + "?mode=ro", uri=True)
    try:
        for db in (a, b):
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("forecast snapshot database requires repair")
        if a.execute("SELECT digest,sequence FROM head").fetchall() != [tuple(receipt["head"])]:
            raise ValueError("forecast snapshot original head differs")
        if b.execute("SELECT sequence,digest FROM head").fetchall() != [
            tuple(reversed(receipt["head"]))
        ]:
            raise ValueError("forecast snapshot index head differs")
        if b.execute("SELECT COUNT(*) FROM identities").fetchone()[0] != receipt["head"][1]:
            raise ValueError("forecast snapshot index has missing identities")
        latest = b.execute(
            "SELECT sequence,digest FROM identities ORDER BY sequence DESC LIMIT 1"
        ).fetchone() or (0, "0" * 64)
        if (
            latest != tuple(reversed(receipt["head"]))
            or b.execute(
                "SELECT 1 FROM identities i LEFT JOIN summaries s ON i.scope=s.scope "
                "WHERE s.scope IS NULL LIMIT 1"
            ).fetchone()
        ):
            raise ValueError("forecast snapshot identity or summary is missing")
        previous, previous_digest = 0, "0" * 64
        pending = False
        for first, last, raw, body, reference, released in b.execute(
            "SELECT first_sequence,last_sequence,metadata,body,receipt,released "
            "FROM archives ORDER BY first_sequence"
        ):
            metadata = json.loads(raw)
            if (
                pending
                or first != previous + 1
                or last < first
                or last - first >= 4096
                or metadata["previous_sha256"] != previous_digest
                or b.execute(
                    "SELECT previous FROM identities WHERE sequence=?", (first,)
                ).fetchone()
                != (metadata["previous_sha256"],)
                or b.execute("SELECT digest FROM identities WHERE sequence=?", (last,)).fetchone()
                != (metadata["last_sha256"],)
                or last > receipt["head"][1]
                or (
                    metadata["first_sequence"],
                    metadata["last_sequence"],
                    metadata["ledger_sha256"],
                )
                != (first, last, expected)
            ):
                raise ValueError("forecast snapshot archive interval is damaged")
            if (
                type(metadata.get("bytes")) is not int
                or not 0 < metadata["bytes"] <= 8 * 1024**2
                or not _digest(metadata.get("sha256"))
                or released not in (0, 1)
            ):
                raise ValueError("forecast snapshot archive metadata is invalid")
            if body is not None and (
                len(body) != metadata["bytes"]
                or hashlib.sha256(body).hexdigest() != metadata["sha256"]
            ):
                raise ValueError("forecast snapshot unfinished segment is damaged")
            if released and (reference is None or body is not None):
                raise ValueError("forecast snapshot lost a completed archive receipt")
            if reference is None and body is None:
                raise ValueError("forecast snapshot lost unfinished publication bytes")
            if reference is not None:
                value = json.loads(reference)
                if (value["content_sha256"], value["size_bytes"]) != (
                    metadata["sha256"],
                    metadata["bytes"],
                ):
                    raise ValueError("forecast snapshot archive receipt differs")
                remote.validate_reference(value)
            previous, previous_digest, pending = last, metadata["last_sha256"], not released
        # Only the unarchived tail depends on the hot database. Original
        # archived payload verification remains retained, never replayed here.
        tail = a.execute("SELECT COUNT(*) FROM events WHERE sequence>?", (previous,)).fetchone()[0]
        if tail != receipt["head"][1] - previous:
            raise ValueError("forecast snapshot hot tail is incomplete")
        for seq, identity, scope, body, parent, checksum in a.execute(
            "SELECT sequence,identity,scope,body,previous,digest FROM events"
        ):
            retained = b.execute(
                "SELECT identity,scope,previous,digest FROM identities WHERE sequence=?", (seq,)
            ).fetchone()
            if retained != (identity, scope, parent, checksum) or (
                len(body) > 16 * 1024
                or hashlib.sha256(parent.encode() + body).hexdigest() != checksum
            ):
                raise ValueError("forecast snapshot hot original differs from retained identity")
        for body, checksum in b.execute("SELECT body,digest FROM summaries"):
            if len(body) > 16 * 1024 or hashlib.sha256(body).hexdigest() != checksum:
                raise ValueError("forecast snapshot compact summary is damaged")
    finally:
        a.close()
        b.close()


def snapshot_bundle(ledger, destination):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("forecast snapshot destination already exists")
    retention = ledger.retention
    with ledger.lock, retention.index.lock:
        retention.ensure_ready()
        with tempfile.TemporaryDirectory(
            prefix="forecast-snapshot-", dir=destination.parent
        ) as tmp:
            candidate = Path(tmp) / "bundle"
            candidate.mkdir(mode=0o700)
            receipt = dict(
                schema=SCHEMA,
                ledger_sha256=retention.ledger_sha256,
                head=list(ledger.head),
                accounting_health=dict(ledger.health),
                files={},
            )
            with TransferProgress("forecast_snapshot_bundle", 3, unit="files") as work:
                for name, source in (
                    ("forecasts.sqlite3", ledger.db),
                    ("index.sqlite3", retention.index.db),
                ):
                    target = sqlite3.connect(candidate / name)
                    try:
                        source.backup(target)
                    finally:
                        target.close()
                    os.chmod(candidate / name, 0o600)
                    bound = (
                        ledger.maximum_bytes
                        if name == "forecasts.sqlite3"
                        else retention.index.maximum_bytes
                    )
                    checksum, size = stream_file(candidate / name, maximum_bytes=bound, sync=True)
                    receipt["files"][name] = dict(sha256=checksum, bytes=size)
                    work.advance(1)
                raw = (retention.index.root / "binding.json").read_bytes()
                _write_private_bytes(candidate / "binding.json", raw)
                receipt["files"]["binding.json"] = dict(
                    sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw)
                )
                receipt["bytes"] = sum(row["bytes"] for row in receipt["files"].values())
                receipt["sha256"] = hashlib.sha256(encode_forecast_json(receipt)).hexdigest()
                _validate(
                    candidate / "forecasts.sqlite3",
                    candidate / "index.sqlite3",
                    candidate / "binding.json",
                    receipt,
                    retention.segments.remote,
                )
                _write(candidate / "manifest.json", receipt)
                _sync(candidate)
                os.replace(candidate, destination)
                _sync(destination.parent)
                work.advance(1)
                return receipt


def restore_bundle(
    directory,
    snapshot,
    receipt,
    *,
    remote_store,
    ledger_sha256,
    damaged_files,
    maximum_bytes,
    maximum_index_bytes,
    damaged_health_sha256=None,
    damaged_initialized_sha256=None,
):
    """Resume the exact selected repair; every replaced original remains preserved."""
    directory, snapshot = Path(directory), Path(snapshot)
    manifest = _manifest(receipt)
    if remote_store is None or ledger_sha256 != manifest["ledger_sha256"]:
        raise ValueError("archived forecast repair requires its selected remote owner")
    if snapshot.is_symlink() or _read(snapshot / "manifest.json") != receipt:
        raise ValueError("forecast snapshot manifest differs from its retained receipt")
    bounds = {
        "forecasts.sqlite3": maximum_bytes,
        "index.sqlite3": maximum_index_bytes,
        "binding.json": 4096,
    }
    if any(not 0 < receipt["files"][key]["bytes"] <= bounds[key] for key in FILES):
        raise ValueError("forecast snapshot exceeds selected repair budgets")
    if any(value is not None and not _digest(value) for value in damaged_files.values()):
        raise ValueError("forecast damaged file identity is invalid")
    selection = dict(
        snapshot_sha256=receipt["sha256"],
        ledger_sha256=ledger_sha256,
        damaged_files=damaged_files,
        damaged_health_sha256=damaged_health_sha256,
        damaged_initialized_sha256=damaged_initialized_sha256,
    )
    repair_id = hashlib.sha256(encode_forecast_json(selection)).hexdigest()
    ensure_private_directory(directory)
    owner = lock_private_file(directory / "owner.lock")
    index_owner = None
    intent_path = directory / INTENT
    repair = directory / ("restore-" + repair_id)
    completed = directory / ("restore-" + repair_id + ".completed.json")
    try:
        index_root = directory / "retention" / "index"
        ensure_private_directory(index_root)
        index_owner = lock_private_file(index_root / "owner.lock")
        # Never replace a SQLite file with pending recovery, even with an exact
        # hash for the main file. Its journal may contain newer durable state.
        for relative in FILES.values():
            path = directory / relative
            if path.is_symlink() or any(
                Path(str(path) + suffix).exists() for suffix in ("-journal", "-wal", "-shm")
            ):
                raise ValueError("forecast repair refuses linked or pending SQLite recovery state")
        if intent_path.exists() or intent_path.is_symlink():
            state = _state(intent_path, selection)
        elif completed.exists() or completed.is_symlink():
            state = _state(completed, selection)
            if all(
                _identity(directory / FILES[key]) == value["installed_identity"]
                for key, value in state["files"].items()
            ):
                if repair.exists():
                    repair.rmdir()
                    _sync(directory)
                return dict(status="already_restored", snapshot=receipt)
            raise ValueError("completed forecast repair changed; select a new explicit repair")
        else:
            state = dict(
                schema="umi-forecast-restore/1",
                selection=selection,
                files={},
                health=None,
                validated=False,
            )
            for key, relative in FILES.items():
                path = directory / relative
                prior = None
                if path.exists():
                    prior, _ = stream_file(path, maximum_bytes=bounds[key])
                if prior not in {receipt["files"][key]["sha256"], damaged_files.get(key)}:
                    raise ValueError("forecast repair original identity changed")
                state["files"][key] = dict(
                    prior_sha256=prior,
                    prior_identity=None if prior is None else _identity(path),
                    staged_identity=None,
                    installed_identity=(
                        _identity(path) if prior == receipt["files"][key]["sha256"] else None
                    ),
                )
            _write(intent_path, state)
        ensure_private_directory(repair)
        with TransferProgress("forecast_snapshot_restore", 6, unit="files") as work:
            for key in FILES:
                selected = state["files"][key]
                if selected["installed_identity"] is not None:
                    if _identity(directory / FILES[key]) != selected["installed_identity"]:
                        raise ValueError("completed forecast restoration file changed")
                    work.advance(2, restored=True)
                    continue
                staged = repair / key
                if selected["staged_identity"] is not None:
                    if not staged.exists() and state["validated"]:
                        path = directory / FILES[key]
                        if path.exists():
                            actual, _ = stream_file(path, maximum_bytes=bounds[key])
                            if actual == receipt["files"][key]["sha256"]:
                                selected["installed_identity"] = _identity(path)
                                _write(intent_path, state)
                                work.advance(2, restored=True)
                                continue
                    if _identity(staged) != selected["staged_identity"]:
                        raise ValueError("completed forecast snapshot copy is missing or changed")
                    work.advance(1, restored=True)
                    continue
                partial = repair / (key + ".partial")
                if partial.exists():
                    if partial.is_symlink() or not partial.is_file():
                        raise ValueError("forecast restore partial file changed")
                    partial.unlink()
                try:
                    checksum, size = stream_file(
                        snapshot / key, maximum_bytes=bounds[key], destination=partial
                    )
                    if (checksum, size) != (
                        receipt["files"][key]["sha256"],
                        receipt["files"][key]["bytes"],
                    ):
                        raise ValueError("forecast snapshot file differs from its retained receipt")
                    os.replace(partial, staged)
                    _sync(repair)
                    selected["staged_identity"] = _identity(staged)
                    _write(intent_path, state)
                finally:
                    if partial.exists():
                        partial.unlink()
                work.advance(1)
            if not state["validated"]:
                paths = {
                    key: directory / FILES[key]
                    if state["files"][key]["installed_identity"]
                    else repair / key
                    for key in FILES
                }
                _validate(
                    paths["forecasts.sqlite3"],
                    paths["index.sqlite3"],
                    paths["binding.json"],
                    receipt,
                    remote_store,
                )
                state["validated"] = True
                _write(intent_path, state)
            health_path = directory.with_name(directory.name + ".health")
            marker_path = directory.with_name(directory.name + ".initialized")
            if state["health"] is None:
                health, _ = health_for_restore(health_path, damaged_sha256=damaged_health_sha256)
                historical = receipt["accounting_health"]
                # A missing current marker cannot erase gaps retained in the
                # snapshot. Counts are a lower bound when histories diverge.
                health = {
                    **health,
                    "coverage_complete": health["coverage_complete"]
                    and historical["coverage_complete"],
                    "gap_count": max(health["gap_count"], historical["gap_count"]),
                    "first_gap": historical["first_gap"] or health["first_gap"],
                    "blocked_capacity_bytes": health["blocked_capacity_bytes"]
                    or historical["blocked_capacity_bytes"],
                }
                initialization_for_restore(marker_path, damaged_sha256=damaged_initialized_sha256)
                state["health"] = record_gap(
                    health,
                    reason="snapshot_restoration_coverage_unknown",
                    head=receipt["head"],
                    snapshot=receipt,
                )
                state["health"]["session_open"] = False
                _write(intent_path, state)
            # Record uncertainty before changing either database. A crash can
            # leave an explicit repair hold, never a silently healthy mixed pair.
            write_health(health_path, state["health"])
            write_initialization(marker_path)
            for key, relative in FILES.items():
                selected = state["files"][key]
                if selected["installed_identity"] is not None:
                    continue
                path, staged = directory / relative, repair / key
                ensure_private_directory(path.parent)
                if path.exists():
                    current = _identity(path)
                    if current != selected["prior_identity"]:
                        # Replacement may have completed immediately before its
                        # journal commit. Qualify only this unfinished boundary.
                        actual, _ = stream_file(path, maximum_bytes=bounds[key])
                        if actual == receipt["files"][key]["sha256"] and not staged.exists():
                            selected["installed_identity"] = current
                            _write(intent_path, state)
                            work.advance(1, restored=True)
                            continue
                        if actual != selected["prior_sha256"]:
                            raise ValueError("forecast repair original changed before replacement")
                    preserved = directory / (key + ".damaged-" + selected["prior_sha256"])
                    if not preserved.exists():
                        os.link(path, preserved)
                        _sync(directory)
                    elif not os.path.samefile(path, preserved):
                        retained, _ = stream_file(preserved, maximum_bytes=bounds[key])
                        if retained != selected["prior_sha256"]:
                            raise ValueError("forecast repair preserved original conflicts")
                elif selected["prior_sha256"] is not None:
                    raise ValueError("forecast repair original disappeared before replacement")
                os.replace(staged, path)
                _sync(path.parent)
                selected["installed_identity"] = _identity(path)
                _write(intent_path, state)
                work.advance(1)
            _write(completed, state)
            intent_path.unlink()
            _sync(directory)
            repair.rmdir()
            _sync(directory)
            return dict(
                status="restored",
                snapshot=receipt,
                certification_authority=False,
                unarchived_records_reconstructed=False,
            )
    finally:
        if index_owner is not None:
            os.close(index_owner)
        os.close(owner)
