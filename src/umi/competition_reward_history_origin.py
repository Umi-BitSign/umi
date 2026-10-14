"""Administrator-selected local origin for installed342 successful exports.

This is a local upgrade contract, never a remotely supplied proof or completion
certificate. The administrator explicitly selects the original private output
namespace and its exclusive publisher. A fresh export authenticates the native
verification prefix under the reviewed source control flow; all derived writes,
unresolved effects and ordered continuity still have to be reconstructed.

The running original owner is selected before stop. Migration later requires its
existing stopped-owner locks. Imported/copied/generic archives are unsupported.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import competition_reward_admission_provenance as provenance
from .competition_reward_proof_archive import MAX_FRAME_BYTES, history_archive_key
from .protocol import canonical_json_bytes

ABI = "umi-installed342-original-export-origin/1"
REASON = "installed342_original_successful_export_migration/1"
_KIND = "control_history_original_export_origin"
_EXPORT_ROOT = Path("/var/lib/umi-c5-production-primary/reward-uid54/proof-exports")
_FIELDS = {"slot_evidence", "slot_metadata", "evidence"}


def _read_frame(path, *, owner, ceiling_ns=None):
    before = provenance._metadata(path, owner=owner, immutable=True)
    if (
        not 0 < before["size"] <= MAX_FRAME_BYTES
        or before["mode"] & 0o077
        or (ceiling_ns is not None and max(before["mtime_ns"], before["ctime_ns"]) >= ceiling_ns)
    ):
        raise ValueError("original export changed after origin selection")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (before["dev"], before["ino"]):
            raise ValueError("original export replaced while opening")
        raw = os.read(fd, MAX_FRAME_BYTES + 1)
    finally:
        os.close(fd)
    if (
        len(raw) != before["size"]
        or provenance._metadata(path, owner=owner, immutable=True) != before
    ):
        raise ValueError("original export changed while reading")
    value = json.loads(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError("original export frame is not canonical")
    return value, before


def _frame(value, height, selection):
    key = history_archive_key(selection["chain_config_sha256"], selection["control_hotkey"], height)
    if (
        set(value) != {"schema", "kind", "key", "context", "fields"}
        or value["schema"] != "umi-reward-proof-frame/1"
        or value["kind"] != "history"
        or value["key"] != key
        or value["context"]
        != {
            "block": height,
            "chain_config_sha256": selection["chain_config_sha256"],
            "control_hotkey": selection["control_hotkey"],
        }
        or set(value["fields"]) != _FIELDS
    ):
        raise ValueError("original export domain changed")
    return key


def capture_original_export_origin(
    provenance_path, *, through_block, exclusive_original_namespace: bool
):
    """Root explicitly selects provenance; returned bytes must be root-sealed.

    The boolean is an administrator assertion about deployment/route history,
    not an inferred permission or a substitute for the checked native publisher.
    It must be supported by the retained installation and transport assessment.
    This function never writes a successful checkpoint or opens owner journals.
    """
    if os.geteuid() != provenance._ROOT_UID or exclusive_original_namespace is not True:
        raise ValueError("local original export migration requires explicit root origin selection")
    selected = provenance.load_provenance(Path(provenance_path))
    provenance.validate_provenance(selected, require_stopped=False)
    if provenance._process() != selected["process"] or provenance._systemd() != selected["service"]:
        raise ValueError("original export publisher changed before origin selection")
    config, _ = provenance._configuration()
    root = Path(config.get("proof_export_directory", ""))
    if (
        root != _EXPORT_ROOT
        or root == Path(config.get("proof_import_directory", ""))
        or type(through_block) is not int
        or through_block < selected["first_block"]
    ):
        raise ValueError("origin selection requires the original private export namespace")
    directories = {
        name: provenance._metadata(
            root / name if name else root, owner=selected["owner_uid"], directory=True
        )
        for name in ("", "history", "objects")
    }
    key = history_archive_key(
        selected["chain_config_sha256"], selected["control_hotkey"], through_block
    )
    frame, stamp = _read_frame(root / "history" / (key + ".json"), owner=selected["owner_uid"])
    _frame(frame, through_block, selected)
    if stamp["mtime_ns"] <= provenance.ORIGINAL_STARTED_NS:
        raise ValueError("origin prefix witness was not exported by the selected running owner")
    captured = time.time_ns()
    if max(stamp["mtime_ns"], stamp["ctime_ns"]) >= captured:
        raise ValueError("original export is still in its publication clock tick")
    if provenance._process() != selected["process"] or provenance._systemd() != selected["service"]:
        raise ValueError("original export publisher changed during origin selection")
    return {
        "schema": ABI,
        "provenance_path": str(Path(provenance_path)),
        "provenance_sha256": provenance.provenance_selection_digest(selected),
        "export_root": str(root),
        "directories": directories,
        "captured_at_unix_ns": captured,
        "first_block": selected["first_block"],
        "through_block": through_block,
        "prefix_export": stamp,
        "prefix_export_sha256": provenance._sha(canonical_json_bytes(frame)),
        "exclusive_original_namespace": True,
        "aggregate_completion_claimed": False,
        "origin_semantics": "installed342_native_checks_precede_immutable_export/1",
    }


def load_original_export_origin(path):
    raw, seal = provenance._read_root(Path(path), 64 * 1024, modes={0o444})
    value = provenance._parse(raw)
    if (
        set(value)
        != {
            "schema",
            "provenance_path",
            "provenance_sha256",
            "export_root",
            "directories",
            "captured_at_unix_ns",
            "first_block",
            "through_block",
            "prefix_export",
            "prefix_export_sha256",
            "exclusive_original_namespace",
            "aggregate_completion_claimed",
            "origin_semantics",
        }
        or value.get("schema") != ABI
        or value.get("origin_semantics") != "installed342_native_checks_precede_immutable_export/1"
        or value.get("exclusive_original_namespace") is not True
        or value.get("aggregate_completion_claimed") is not False
        or value.get("export_root") != str(_EXPORT_ROOT)
    ):
        raise ValueError("unsupported original export origin contract")
    selected = provenance.load_provenance(Path(value["provenance_path"]))
    if provenance.provenance_selection_digest(selected) != value["provenance_sha256"]:
        raise ValueError("original export owner selection changed")
    if (
        value["first_block"] != selected["first_block"]
        or type(value["through_block"]) is not int
        or value["through_block"] < value["first_block"]
    ):
        raise ValueError("original export interval changed")
    for name, expected in value["directories"].items():
        if name not in {"", "history", "objects"}:
            raise ValueError("original export namespace changed")
        path = _EXPORT_ROOT / name if name else _EXPORT_ROOT
        if provenance._metadata(path, owner=selected["owner_uid"], directory=True) != expected:
            raise ValueError("original export namespace identity changed")
    if set(value["directories"]) != {"", "history", "objects"}:
        raise ValueError("original export namespace inventory changed")
    expected_path = (
        _EXPORT_ROOT
        / "history"
        / (
            history_archive_key(
                selected["chain_config_sha256"], selected["control_hotkey"], value["through_block"]
            )
            + ".json"
        )
    )
    if value["prefix_export"]["path"] != str(expected_path):
        raise ValueError("original prefix witness is outside its selected export namespace")
    frame, stamp = _read_frame(
        Path(value["prefix_export"]["path"]),
        owner=selected["owner_uid"],
        ceiling_ns=value["captured_at_unix_ns"],
    )
    _frame(frame, value["through_block"], selected)
    if (
        stamp != value["prefix_export"]
        or provenance._sha(canonical_json_bytes(frame)) != value["prefix_export_sha256"]
    ):
        raise ValueError("original successful export witness changed")
    return {**value, "_seal": seal}, selected


def read_original_export(origin, selection, height):
    if not origin["first_block"] <= height <= origin["through_block"]:
        raise ValueError("original export is outside selected prefix")
    key = history_archive_key(selection["chain_config_sha256"], selection["control_hotkey"], height)
    frame, stamp = _read_frame(
        _EXPORT_ROOT / "history" / (key + ".json"),
        owner=selection["owner_uid"],
        ceiling_ns=origin["captured_at_unix_ns"],
    )
    _frame(frame, height, selection)
    return frame, stamp


def retain_original_export_origin(journal, origin):
    key = provenance.provenance_selection_digest(origin)
    record = {"schema": ABI, "path": origin["_seal"]["path"], "sha256": key}
    journal.put_many(((_KIND, key, record),))
    return key


def check_checkpoint_origin(journal, value, db, cache):
    repair = value["repair"]
    if repair is None or repair["reason"] != REASON:
        return
    record = journal.get(_KIND, repair["operation"], db=db)
    if (
        type(record) is not dict
        or set(record) != {"schema", "path", "sha256"}
        or record["schema"] != ABI
        or record["sha256"] != repair["operation"]
    ):
        raise ValueError("original export migration origin is missing")
    cached = cache.get(record["sha256"])
    if cached is not None:
        origin, owner_seal = cached
        current = provenance._metadata(record["path"], owner=provenance._ROOT_UID, immutable=True)
        owner_current = provenance._metadata(
            owner_seal["path"], owner=provenance._ROOT_UID, immutable=True
        )
        if current != {
            k: v for k, v in origin["_seal"].items() if k != "sha256"
        } or owner_current != {k: v for k, v in owner_seal.items() if k != "sha256"}:
            raise ValueError("original export migration root seal changed")
        if (
            not origin["first_block"]
            <= value["snapshot"]["block_number"]
            <= origin["through_block"]
        ):
            raise ValueError("original export migration result escaped selected interval")
        return
    origin, owner = load_original_export_origin(Path(record["path"]))
    if (
        provenance.provenance_selection_digest(origin) != record["sha256"]
        or not origin["first_block"] <= value["snapshot"]["block_number"] <= origin["through_block"]
    ):
        raise ValueError("original export migration origin changed")
    cache[record["sha256"]] = (origin, owner["_seal"])
