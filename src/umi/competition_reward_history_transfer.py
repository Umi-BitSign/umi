"""Copy successful local block facts between two authenticated stopped owners.

The original source checkpoint authenticates every copied compact source record.
Only the target's real mutation identities enter its new checkpoint. Source-map
receipts survive restart, so shared unchanged objects are not read again. This
operation grants no history, finality, control or transaction authority: the
ordinary target reader must restore and apply its prefix under fresh finality.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from contextlib import ExitStack

from .competition_evidence_codec import checked_digest
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_history_origin import REASON as ORIGINAL_EXPORT_REASON
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .protocol import canonical_json_bytes

_SCHEMA = "umi-local-history-result-transfer/1"
_MAP = "control_history_transfer_source"
_MAP_DONE = "control_history_transfer_source_done"
_BLOCK = "control_history_transfer_block"
_BLOCK_DONE = "control_history_transfer_block_done"
_ORIGIN = "control_history_original_export_origin"
_COPY_BYTES = 8 * 1024**2
_COPY_RECORDS = 256
_PRIVATE_FIELDS = {"owner", "sources", "exports", "repair"}


def _check_owner(owner, source, target):
    # A serialized selection, caller digest or ordinary filesystem lock is not
    # the original live capability established by the guarded entrypoint.
    from .competition_reward_history_transfer_owner import HistoryTransferOwner

    if type(owner) is not HistoryTransferOwner:
        raise TypeError("history transfer requires its original live owner capability")
    owner.recheck(source, target)
    if source is target or source.checkpoints.owner == target.checkpoints.owner:
        raise ValueError("history transfer requires distinct original journals")
    if (source.hotkey, source.config_sha256, source.first_block) != (
        target.hotkey,
        target.config_sha256,
        target.first_block,
    ) or source.checkpoints.semantics != target.checkpoints.semantics:
        raise ValueError("history transfer reader context or verifier semantics differs")


def _facts(value):
    return {key: item for key, item in value.items() if key not in _PRIVATE_FIELDS}


def _success(value):
    return digest({key: item for key, item in value.items() if key != "exports"})


def _scope(owner, source, target):
    return {
        "schema": _SCHEMA,
        "context": owner.context_sha256,
        "source_owner": source.checkpoints.owner,
        "target_owner": target.checkpoints.owner,
        "semantics": source.checkpoints.semantics,
    }


def _map_key(scope, token):
    # Revisions deliberately do not enter the key: a changed dependency must
    # expose repair, not appear to be an unverified new cache entry.
    return digest([scope, token[:2]])


def _source_mapping(target, scope, token, db):
    key = _map_key(scope, token)
    mapping = target.journal.get(_MAP, key, db=db)
    done = target.journal.get(_MAP_DONE, key, db=db)
    if mapping is None and done is None:
        return key, None
    if (
        type(mapping) is not dict
        or set(mapping) != {"scope", "source", "target", "size", "raw_sha256"}
        or mapping["scope"] != scope
        or mapping["source"] != token
        or type(mapping["target"]) is not list
        or len(mapping["target"]) != 3
        or mapping["target"][:2] != token[:2]
        or type(mapping["target"][2]) is not int
        or mapping["target"][2] < 0
        or type(mapping["size"]) is not int
        or not 0 < mapping["size"] <= target.journal.maximum_record_bytes
        or done != {"mapping_sha256": digest(mapping)}
    ):
        raise HistoryCheckpointRepairRequired(
            "history transfer source mapping is missing or changed"
        )
    try:
        checked_digest(mapping["raw_sha256"])
    except ValueError as error:
        raise HistoryCheckpointRepairRequired(
            "history transfer source mapping digest changed"
        ) from error
    return key, mapping


def _local_only(reader):
    with reader.journal.read_transaction() as db:
        reader.checkpoints.check_schema(db)
        if (
            db.execute("PRAGMA user_version").fetchone()[0] == 3
            or db.execute(
                "SELECT 1 FROM records WHERE kind='control_history_remote_source' LIMIT 1"
            ).fetchone()
        ):
            raise ValueError("history transfer of remote source aliases is not qualified")


def _preflight(owner, source, target, first, last):
    _check_owner(owner, source, target)
    if type(first) is not int or type(last) is not int or not source.first_block <= first <= last:
        raise ValueError("history transfer requires an exact nonempty selected interval")
    for reader in (source, target):
        _local_only(reader)
        admission = reader.completed_admission.load()
        if admission is not None and first <= admission["snapshot"]["block_number"]:
            raise ValueError("history transfer cannot copy or overlap completed admission")
    with source.journal.read_transaction() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM history_checkpoint_index WHERE height>=? AND height<=?",
            (first, last),
        ).fetchone()[0]
        if count != last - first + 1:
            raise HistoryCheckpointRepairRequired("history transfer source interval has a gap")


def _source_batch(owner, source, target, scope, value, tokens):
    """Bounded raw source copy and durable token mappings, atomically per batch."""
    with (
        source.journal.read_transaction() as source_db,
        target.journal.read_transaction() as target_db,
    ):
        source.checkpoints.check_sources(value["sources"], source_db)
        target.checkpoints.check_schema(target_db)
        records, target_tokens, reused, copied_bytes = [], [], [], 0
        for token in tokens:
            key, mapping = _source_mapping(target, scope, token, target_db)
            if mapping is not None:
                reused.append(mapping["target"])
                continue
            kind, record_id, _ = token
            raw = source.journal.get_raw(kind, record_id, db=source_db)
            if type(raw) is not bytes or not 0 < len(raw) <= target.journal.maximum_record_bytes:
                raise HistoryCheckpointRepairRequired(
                    "history transfer source is missing or oversized"
                )
            document = json.loads(raw)
            if canonical_json_bytes(document) != raw:
                raise HistoryCheckpointRepairRequired("history transfer source is not canonical")
            previous = target.journal.get_raw(kind, record_id, db=target_db)
            if previous is not None and previous != raw:
                # Refuse before put_many(), which deliberately persists conflict
                # holds. A transfer must not damage unrelated existing state.
                raise HistoryCheckpointRepairRequired("history transfer target source conflicts")
            if previous is None:
                if target_db.execute(
                    "SELECT 1 FROM history_source_identity WHERE kind=? AND id=?",
                    (kind, record_id),
                ).fetchone():
                    raise HistoryCheckpointRepairRequired(
                        "history transfer target source was deleted"
                    )
                destination = [kind, record_id, 1]
                records.append((kind, record_id, document))
                copied_bytes += len(raw)
            else:
                destination = target.checkpoints.sources(((kind, record_id),), target_db)[0]
            mapping = {
                "scope": scope,
                "source": token,
                "target": destination,
                "size": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            }
            records.extend(
                ((_MAP, key, mapping), (_MAP_DONE, key, {"mapping_sha256": digest(mapping)}))
            )
            target_tokens.append(destination)
        if reused:
            target.checkpoints.check_sources(sorted(reused), target_db)
    if not records:
        return 0, len(reused)

    def index(db):
        _check_owner(owner, source, target)
        target.checkpoints.check_sources(sorted([*target_tokens, *reused]), db)
        # Stopped-owner fences exclude ordinary source writers. Check its latest
        # committed tokens again, not only the earlier copy snapshot.
        with source.journal.read_transaction() as source_db:
            source.checkpoints.check_sources(value["sources"], source_db)

    target.journal.put_many(records, index=index)
    return copied_bytes, len(reused)


def _copy_sources(owner, source, target, scope, value):
    # Work remains bounded by source record sizes; do not accumulate a whole
    # expanded frame or interval. A single allowed source may exceed 8 MiB.
    pending, size, copied_bytes, reused = [], 0, 0, 0
    with source.journal.read_transaction() as db:
        source.checkpoints.check_sources(value["sources"], db)
        sizes = []
        for token in value["sources"]:
            row = db.execute(
                "SELECT LENGTH(body) FROM records WHERE kind=? AND id=?", tuple(token[:2])
            ).fetchone()
            if row is None or type(row[0]) is not int or row[0] <= 0:
                raise HistoryCheckpointRepairRequired("history transfer source bytes are missing")
            sizes.append((token, row[0]))
    for token, amount in sizes:
        if pending and (size + amount > _COPY_BYTES or len(pending) >= _COPY_RECORDS):
            copied, restored = _source_batch(owner, source, target, scope, value, pending)
            copied_bytes += copied
            reused += restored
            pending, size = [], 0
        pending.append(token)
        size += amount
    if pending:
        copied, restored = _source_batch(owner, source, target, scope, value, pending)
        copied_bytes += copied
        reused += restored
    return copied_bytes, reused


def _retain_origin(source, target, value):
    repair = value["repair"]
    if repair is None or repair["reason"] != ORIGINAL_EXPORT_REASON:
        return
    # load() already authenticated the exact root seal and original export
    # namespace. Preserve this dependency; never replace its repair reason.
    with source.journal.read_transaction() as db:
        origin = source.journal.get(_ORIGIN, repair["operation"], db=db)
    with target.journal.read_transaction() as db:
        prior = target.journal.get(_ORIGIN, repair["operation"], db=db)
    if prior is not None and prior != origin:
        raise HistoryCheckpointRepairRequired("history transfer original export origin conflicts")
    target.journal.put(_ORIGIN, repair["operation"], origin)


def _check_completed_transfer(target, scope, value, prior, record):
    if (
        type(record) is not dict
        or set(record) != {"scope", "height", "source_success", "target_success", "sources"}
        or record["scope"] != scope
        or record["height"] != value["snapshot"]["block_number"]
        or record["source_success"] != _success(value)
        or record["target_success"] != _success(prior)
        or record["sources"] != value["sources"]
    ):
        raise HistoryCheckpointRepairRequired("history transfer block completion changed")
    with target.journal.read_transaction() as db:
        mapped = []
        for token in value["sources"]:
            _, mapping = _source_mapping(target, scope, token, db)
            if mapping is None:
                raise HistoryCheckpointRepairRequired("completed history transfer lost its mapping")
            mapped.append(mapping["target"])
        if sorted(mapped) != prior["sources"]:
            raise HistoryCheckpointRepairRequired(
                "completed history transfer source coverage changed"
            )
        target.checkpoints.check_sources(sorted(mapped), db)


def _transfer_block(owner, source, target, scope, height):
    _check_owner(owner, source, target)
    value = source.checkpoints.load(height)
    if value is None:
        raise HistoryCheckpointRepairRequired("history transfer source checkpoint is missing")
    prior = target.checkpoints.load(height)
    key = digest([scope, height])
    with target.journal.read_transaction() as db:
        record = target.journal.get(_BLOCK, key, db=db)
        done = target.journal.get(_BLOCK_DONE, key, db=db)
    if (record is not None or done is not None) and (
        type(record) is not dict or done != {"completion_sha256": digest(record)}
    ):
        raise HistoryCheckpointRepairRequired("history transfer block record is missing or changed")
    if prior is not None:
        if _facts(prior) != _facts(value):
            raise HistoryCheckpointRepairRequired(
                "history transfer overlaps different native facts"
            )
        if record is not None:
            _check_completed_transfer(target, scope, value, prior, record)
        return {"restored": True, "copied_source_bytes": 0, "reused_source_records": 0}
    copied_bytes, reused = _copy_sources(owner, source, target, scope, value)
    _retain_origin(source, target, value)
    _check_owner(owner, source, target)
    if source.checkpoints.load(height) != value:
        raise HistoryCheckpointRepairRequired(
            "history transfer source checkpoint changed during copy"
        )
    with target.journal.read_transaction() as db:
        sources = target.checkpoints.sources((tuple(token[:2]) for token in value["sources"]), db)
    transferred = {**value, "owner": target.checkpoints.owner, "sources": sources, "exports": []}
    completion = {
        "scope": scope,
        "height": height,
        "source_success": _success(value),
        "target_success": _success(transferred),
        "sources": value["sources"],
    }
    if record is not None and record != completion:
        raise HistoryCheckpointRepairRequired(
            "interrupted history transfer changed its selected result"
        )
    # A crash here leaves only immutable source/map/intent records. Repeating
    # resumes those records and never invokes the proof verifier again.
    target.journal.put_many(
        ((_BLOCK, key, completion), (_BLOCK_DONE, key, {"completion_sha256": digest(completion)}))
    )
    _check_owner(owner, source, target)
    target.checkpoints.remember(transferred)
    if target.checkpoints.load(height) != transferred:
        raise HistoryCheckpointRepairRequired("history transfer result changed during completion")
    return {"restored": False, "copied_source_bytes": copied_bytes, "reused_source_records": reused}


def transfer_history_checkpoints(
    source,
    target,
    *,
    owner,
    first_block,
    through_block,
    maximum_blocks=256,
    progress=None,
    stop_requested=None,
):
    """Transfer a bounded window; repeat the exact scope to resume after a stop.

    Both readers must already be opened beneath the genuine stopped-owner
    capability. Existing compound journal locks are held here, in stable order.
    Unsupported remote aliases or aggregate admission intervals refuse before
    mutation. No existing successful target result is overwritten.
    """
    if type(maximum_blocks) is not int or not 1 <= maximum_blocks <= 4096:
        raise ValueError("history transfer requires a bounded block window")
    _check_owner(owner, source, target)
    with ExitStack() as stack:
        for reader in sorted((source, target), key=lambda item: str(item.journal.root.resolve())):
            stack.enter_context(reader.journal.locked())
        _preflight(owner, source, target, first_block, through_block)
        scope = _scope(owner, source, target)
        done = copied = restored = copied_bytes = reused = 0
        total = through_block - first_block + 1
        report = TransferProgress(
            "native_history_result_transfer",
            total,
            progress,
            unit="blocks",
            planning_unit_seconds=(0.01, 3.0),
        )
        try:
            with report:
                for height in range(first_block, through_block + 1):
                    if stop_requested is not None and stop_requested.is_set():
                        break
                    # Restored prefix receipts are cheap metadata work and do
                    # not exhaust the new-work window on repeated invocations.
                    if copied >= maximum_blocks:
                        break
                    result = _transfer_block(owner, source, target, scope, height)
                    done += 1
                    restored += int(result["restored"])
                    copied += int(not result["restored"])
                    copied_bytes += result["copied_source_bytes"]
                    reused += result["reused_source_records"]
                    report.advance(1, restored=result["restored"])
                _check_owner(owner, source, target)
        except (ValueError, sqlite3.DatabaseError):
            report.emit("repair_required", reason="history_transfer_requires_explicit_repair")
            raise
        return {
            "status": "checkpointed" if done < total else "completed",
            "first_block": first_block,
            "through_block": through_block,
            "next_block": first_block + done,
            "completed_blocks": done,
            "total_blocks": total,
            "transferred_blocks": copied,
            "existing_blocks": restored,
            "copied_source_bytes": copied_bytes,
            "reused_source_records": reused,
            "chain_submission_authorized": False,
            "next_action": "ordinary_native_ordered_restore_and_fresh_tip_finality",
        }


def _materialization_path(path, *, directory, private=True):
    """Capture owned path identity, never a payload hash or applied-history claim."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise HistoryCheckpointRepairRequired("materialization path is not canonical")
    value = path.lstat()
    if (
        not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        or value.st_uid != os.getuid()
        or value.st_mode & (0o077 if private else 0o022)
        or (not directory and value.st_nlink != 1)
    ):
        raise HistoryCheckpointRepairRequired("materialization path lost its private owner")
    return {
        "path": str(path),
        "identity": {
            "dev": value.st_dev,
            "ino": value.st_ino,
            "uid": value.st_uid,
            "gid": value.st_gid,
            "mode": stat.S_IMODE(value.st_mode),
        },
    }


def review_history_materialization(
    source,
    target,
    *,
    owner,
    first_block,
    through_block,
    progress=None,
    stop_requested=None,
):
    """Produce a bounded terminal only for a complete contiguous exported interval.

    Original leases and both compound journal locks cover the entire review.
    Native checkpoint/source mutation identities and actual target delivery
    receipts are rechecked without reading or hashing proof payloads. The result
    is an attestation for the root wrapper to seal with its real process/drain
    provenance, not a portable native proof or a report of applied history.
    """
    _check_owner(owner, source, target)
    if target.export_archive is None or target.export_archive.remote is not None:
        raise ValueError("materialization requires the selected local export archive")
    with ExitStack() as locks:
        for reader in sorted((source, target), key=lambda item: str(item.journal.root.resolve())):
            locks.enter_context(reader.journal.locked())
        _preflight(owner, source, target, first_block, through_block)
        paths = {
            "source_journal_directory": (source.journal.root, True),
            "source_journal_database": (source.journal.path, False),
            "journal_directory": (target.journal.root, True),
            "journal_database": (target.journal.path, False),
            "export_directory": (target.export_archive.root, True),
        }
        identities = {
            name: _materialization_path(
                path, directory=directory, private=name != "export_directory"
            )
            for name, (path, directory) in paths.items()
        }
        export = target._export_identity()
        checked_digest(export)
        total = through_block - first_block + 1
        checksum, previous = hashlib.sha256(), None
        report = TransferProgress(
            "history_materialization_inventory",
            total,
            progress,
            unit="blocks",
            planning_unit_seconds=(0.005, 0.1),
        )
        try:
            with report:
                for offset, height in enumerate(range(first_block, through_block + 1)):
                    if stop_requested is not None and stop_requested.is_set():
                        raise InterruptedError("history materialization review interrupted")
                    if offset % 256 == 0:
                        _check_owner(owner, source, target)
                    original = source.checkpoints.load(height)
                    received = target.checkpoints.load(height)
                    if original is None or received is None:
                        raise HistoryCheckpointRepairRequired(
                            "materialization checkpoint interval has a gap"
                        )
                    if _facts(original) != _facts(received):
                        raise HistoryCheckpointRepairRequired("materialization native facts differ")
                    if previous is not None and received["snapshot"]["parent_hash"] != previous:
                        raise HistoryCheckpointRepairRequired(
                            "materialization interval is not contiguous"
                        )
                    if export not in received["exports"]:
                        raise HistoryCheckpointRepairRequired(
                            "materialization target export is incomplete"
                        )
                    # The two success identities include all original source
                    # generations, verifier semantics and legacy dependencies.
                    # New export receipts do not alter their successful facts.
                    success = digest(
                        {"source_success": _success(original), "target_success": _success(received)}
                    )
                    checksum.update(canonical_json_bytes([height, success, export]) + b"\n")
                    previous = received["snapshot"]["block_hash"]
                    report.advance(1)
                if stop_requested is not None and stop_requested.is_set():
                    raise InterruptedError("history materialization review interrupted")
                _check_owner(owner, source, target)
                for name, (path, directory) in paths.items():
                    if (
                        _materialization_path(
                            path, directory=directory, private=name != "export_directory"
                        )
                        != identities[name]
                    ):
                        raise HistoryCheckpointRepairRequired(
                            "materialization original path identity changed"
                        )
                if target._export_identity() != export:
                    raise HistoryCheckpointRepairRequired(
                        "materialization export selection changed"
                    )
        except (ValueError, sqlite3.DatabaseError):
            report.emit(
                "repair_required", reason="history_materialization_requires_explicit_repair"
            )
            raise
        return {
            "schema": "umi-local-history-materialization/1",
            "first_block": first_block,
            "through_block": through_block,
            "checkpoint_blocks": total,
            "source_complete_blocks": total,
            "export_complete_blocks": total,
            "source_owner": source.checkpoints.owner,
            "target_owner": target.checkpoints.owner,
            "context_sha256": owner.context_sha256,
            "verifier_semantics_sha256": target.checkpoints.semantics,
            "inventory_sha256": checksum.hexdigest(),
            "inventory_algorithm": "sha256_canonical_json_lines_height_success_export_v1",
            "target_export_identity": export,
            **identities,
            "newly_applied_blocks": 0,
            "applied_progress": None,
            "applied_progress_basis": "requires_separate_original_owner_capture",
            "export_basis": "native_checkpoint_delivery_receipts",
            "ordered_restore_and_fresh_finality_required": True,
            "chain_submission_authorized": False,
        }
