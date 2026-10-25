"""Bounded typed reads of unchanged, independently delivered request orders.

Native first reads retain their exact decoded result and accounting in the
existing private verification store. No signing, execution, closure or current
authority is inferred. Changed originals and bounds receive one counted repair;
restart restores the result rather than reading or hashing the original again.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import OrderedDict
from pathlib import Path
from threading import RLock

from .competition_assignment_reuse import AssignmentVerificationReuse
from .competition_cohort_endpoint_archive import MAX_ARCHIVE_OBJECT_BYTES, read_endpoint_object
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
from .competition_cohort_settlement_delivery import MAX_DELIVERY_BYTES
from .competition_transport_verification import TransferProgress, verification_tick
from .competition_verification_reuse import VerificationDependency, VerificationReuse
from .competition_verification_rules import runtime_identity
from .file_identity import file_fingerprint
from .host_memory_request_bounds import (
    capture_stage_json_shapes,
    charge_stage_declaration,
    replay_stage_json_shape,
    stage_shape_identity,
)
from .open_competition import digest
from .private_files import ensure_private_directory, private_path
from .protocol import canonical_json_bytes


def _stamp(path):
    private_path(str(path))
    ensure_private_directory(path.parent)
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.getuid()
        or value.st_nlink != 1
        or value.st_mode & 0o077
    ):
        raise ValueError("request order requires unchanged owned private originals")
    return tuple(str(n) for n in file_fingerprint(value))


def _cache():
    selected = []
    for name, default, ceiling in (
        ("UMI_REQUEST_ORDER_CACHE_BYTES", 256 * 1024**2, 1024**3),
        ("UMI_REQUEST_ORDER_CACHE_ENTRIES", 2048, 16384),
    ):
        raw = os.environ.get(name, str(default))
        if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= ceiling:
            raise ValueError("invalid request order reuse operating budget: " + name)
        selected.append(int(raw))
    return AssignmentVerificationReuse(*selected, purpose="request_order")


class RequestOrderReads:
    def __init__(self, root):
        self.root = Path(root)
        self.cache = _cache()
        self.serial = RLock()
        self.stores = OrderedDict()

    def _store(self, round_sha):
        # One admitted round bounds each directory's order/marker entries.
        with self.serial:
            value = self.stores.pop(round_sha, None)
            if value is None:
                value = VerificationReuse(
                    self.root / ".order-read-verification" / round_sha,
                    owner={
                        "kind": "umi-private-request-order-read/1",
                        "directory": str(self.root),
                        "round_sha256": round_sha,
                        "semantics": runtime_identity(),
                    },
                )
            self.stores[round_sha] = value
            if len(self.stores) > 16:
                self.stores.popitem(last=False)
            return value

    def read(self, files, path, reference, round_, round_sha, submission):
        original = files.objects._path(reference.sha256)
        receipts = self._store(round_sha)
        paths = (path, original)
        try:
            stamps = tuple(_stamp(p) for p in paths)
        except (OSError, ValueError):
            with TransferProgress("request_order_read", 1, unit="orders") as progress:
                progress.emit(
                    "repair_required", reason="request_order_original_unavailable_or_unsafe"
                )
            raise
        context = dict(
            files=[dict(path=str(p), stamp=s) for p, s in zip(paths, stamps, strict=True)],
            round_sha256=round_sha,
            submission_sha256=submission,
            bounds=stage_shape_identity(),
            semantics=receipts.runtime,
        )
        slot = hashlib.sha256(canonical_json_bytes([round_sha, submission])).hexdigest()
        key = canonical_json_bytes(context)
        context = json.loads(key)
        native = False

        def calculate():
            nonlocal native
            with (
                TransferProgress(
                    "request_order_read", 1, unit="orders", planning_unit_seconds=(0.01, 30)
                ) as progress,
                receipts.exclusive(),
            ):
                receipt = receipts.load(slot)
                if receipt is None and (
                    (receipts.directory / (slot + ".json")).exists()
                    or (receipts.directory / (slot + ".complete")).exists()
                ):
                    progress.emit(
                        "repair_required", reason="request_order_retained_result_missing_or_damaged"
                    )
                if receipt is not None:
                    try:
                        if len(receipt.dependencies) != 1:
                            raise ValueError("request order receipt has another dependency set")
                        dependency = receipt.dependencies[0]
                        if dependency.kind != "source" or not (
                            dependency.key == dependency.sha256 == reference.sha256
                        ):
                            raise ValueError("request order receipt changed its object binding")
                        saved = json.loads(dependency.source_identity)
                        if saved["context"] != context:
                            raise ValueError("request order receipt changed its source context")
                        shapes = tuple(saved["shapes"])
                        # Private checksum-bound result; the original order has
                        # not changed. Decode once per process, without source I/O.
                        value = SignedRecoverableEvaluationOrder.model_validate_json(
                            receipt.result_json
                        )
                    except (KeyError, TypeError, ValueError):
                        progress.emit(
                            "repair_required", reason="request_order_dependencies_changed"
                        )
                    else:
                        progress.advance(1, restored=True)
                        return value, shapes, True
                reusable = verification_tick(max(int(s[-1]) for s in stamps), progress)
                if tuple(_stamp(p) for p in paths) != stamps:
                    raise ValueError("request order changed before native reading")
                with capture_stage_json_shapes() as captured:
                    raw = read_endpoint_object(files.objects, reference.sha256)
                    value = SignedRecoverableEvaluationOrder.model_validate_json(raw)
                if (
                    value.order.round != round_
                    or digest(value.order.submission.submission) != submission
                ):
                    raise ValueError(
                        "delivered request order differs from its selected participant"
                    )
                if tuple(_stamp(p) for p in paths) != stamps:
                    raise ValueError("request order changed during native reading")
                shapes = tuple(captured.values())
                if reusable:
                    dependency = VerificationDependency(
                        kind="source",
                        key=reference.sha256,
                        sha256=reference.sha256,
                        source_identity=canonical_json_bytes(
                            dict(context=context, shapes=shapes)
                        ).decode(),
                    )
                    receipts.remember(slot, (dependency,), raw.decode())
                native = True
                progress.advance(1)
                return value, shapes, reusable

        with self.serial:
            found = self.cache.lookup(slot, key)
            if found is None:
                found = calculate()
                if found[2]:
                    self.cache.remember(slot, key, found)
            value, shapes, _ = found
        if tuple(_stamp(p) for p in paths) != stamps:
            raise ValueError("request order changed during retained result selection")
        if not native:
            # Replay every original shape and declaration charge. This is
            # resource accounting, never a second payload or semantic check.
            for shape in shapes:
                maximum = (
                    MAX_DELIVERY_BYTES
                    if shape["kind"] == "declaration"
                    else MAX_ARCHIVE_OBJECT_BYTES
                )
                if not replay_stage_json_shape(**shape, maximum_bytes=maximum):
                    raise ValueError("request order accounting changed its selected bounds")
                if shape["kind"] == "declaration":
                    if shape["size"] != int(stamps[1][6]):
                        raise ValueError("request order declaration differs from its original")
                    charge_stage_declaration(shape["size"])
        return value
