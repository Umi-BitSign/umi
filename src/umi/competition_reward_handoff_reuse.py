"""Private completed legacy verification, separate from fresh writer ownership."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from .competition_verification_reuse import (
    VerificationReceiptUnavailable,
    VerificationReuse,
    metadata_completion,
    read_verification_metadata,
)
from .open_competition import digest
from .private_files import _write_private_bytes
from .protocol import canonical_json_bytes

_LOG = logging.getLogger(__name__)


def repair_required(reason):
    _LOG.warning(
        "%s",
        canonical_json_bytes(
            {
                "schema": "umi-legacy-handoff-repair/1",
                "stage": "legacy_handoff_verification",
                "status": "repair_required",
                "completed": 0,
                "total": 1,
                "unit": "completion_records",
                "elapsed_seconds": 0,
                "eta_seconds": None,
                "eta_basis": "retained_dependency_repair_required",
                "stalled_or_retrying": True,
                "reason_code": reason,
                "certification_authority": False,
            }
        ).decode(),
    )
    return VerificationReceiptUnavailable("legacy handoff repair required: " + reason)


def snapshot_identity(value):
    # Filesystem nanoseconds exceed RFC8785's exact-integer range. Preserve them
    # as a JSON string inside the canonical private receipt, without rounding.
    return json.dumps(value, separators=(",", ":"))


class LegacyHandoffVerification:
    """Only the native stopped-inventory owner may issue these derived receipts.

    Keys preserve unchanged verifier semantics across source upgrades. Contexts
    bind immutable input metadata; a changed or damaged completion requires
    explicit repair, never silent replay of an already completed inventory.
    The caller still acquires and continuously checks both native process locks.
    """

    def __init__(self, runtime, intent):
        marker = runtime.root / "legacy-handoff-verification.json"
        selected = None
        try:
            selected = json.loads(read_verification_metadata(marker))
        except FileNotFoundError:
            pass
        except (ValueError, OSError) as error:
            raise repair_required("verification_binding_damaged") from error
        if selected is not None and (
            type(selected) is not dict
            or set(selected) != {"directory", "owner"}
            or not Path(selected["directory"]).is_dir()
        ):
            raise repair_required("verification_directory_missing")
        self.reuse = VerificationReuse(
            runtime.root / "legacy-handoff-verification",
            owner={"intent": intent, "runtime_binding": runtime._binding},
        )
        current = {"directory": str(self.reuse.directory), "owner": self.reuse.owner}
        if selected is not None and selected != current:
            raise repair_required("verification_owner_or_directory_changed")
        if selected is None:
            _write_private_bytes(marker, canonical_json_bytes(current))
            descriptor = os.open(runtime.root, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _key(self, stage, identity):
        return digest(
            {
                "schema": "umi-legacy-handoff-verification/1",
                "owner": self.reuse.owner,
                "verifier": self.reuse.runtime,
                "stage": stage,
                "identity": identity,
            }
        )

    def load(self, stage, identity, context):
        key = self._key(stage, identity)
        directories = [self.reuse.directory]
        if self.reuse.legacy_directory is not None:
            directories.append(self.reuse.legacy_directory)
        existed = any(
            (directory / (key + ".json")).exists()
            or metadata_completion(directory / (key + ".json")).exists()
            for directory in directories
        )
        receipt = self.reuse.load(key)
        if receipt is None:
            if existed:
                raise repair_required("completion_missing_or_damaged")
            return None
        body = json.loads(receipt.result_json)
        if (
            type(body) is not dict
            or set(body) != {"context", "value"}
            or body["context"] != digest(context)
            or type(body["value"]) is not dict
        ):
            raise repair_required("completion_inputs_changed")
        return body["value"]

    def remember(self, stage, identity, context, value):
        self.reuse.remember(
            self._key(stage, identity),
            (),
            canonical_json_bytes({"context": digest(context), "value": value}).decode(),
        )
