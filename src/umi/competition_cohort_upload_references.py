"""Durable exact-request model references for bounded upload polling.

These small private facts permit deduplication before materializing full signed
requests. They confer no delivery, review, admission, or release authority.
"""

from __future__ import annotations

import hashlib
import os
from typing import Literal

from pydantic import Field

from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import VerificationReuse, metadata_completion
from .open_competition import digest, digest_canonical_bytes
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class UploadReferenceRepairRequired(OSError):
    """A completed upload-reference check needs explicit scoped repair."""


class _Reference(StrictProtocolModel):
    schema_: Literal["umi-upload-model-reference/1"] = Field(alias="schema")
    upload_sha256: Hex32
    model_sha256: Hex32


class UploadModelReferences:
    def __init__(self, journal, binding):
        self.journal, self.binding = journal, binding
        self._shards = {}

    def model(self, key, raw, decode, *, repair=False, report=None):
        # A digest is only an exact-byte fence. A first result still requires
        # native validation of signatures, canonicality and all bundle fields.
        if digest_canonical_bytes(raw) != key:
            raise ValueError("retained model delivery changed")
        shard = key[:2]
        reuse = self._shards.get(shard)
        if reuse is None:
            reuse = VerificationReuse(
                self.journal.root / "upload-model-references" / shard,
                owner={
                    "profile": "umi-upload-model-reference/1",
                    "binding": self.binding,
                    "shard": shard,
                },
            )
            self._shards[shard] = reuse
        receipt_key = hashlib.sha256(
            canonical_json_bytes({"owner": reuse.owner, "runtime": reuse.runtime, "upload": key})
        ).hexdigest()
        with reuse.exclusive():
            path = reuse.directory / (receipt_key + ".json")
            existed = os.path.lexists(path) or metadata_completion(path).exists()
            receipt = reuse.load(receipt_key)
            damaged = existed and receipt is None
            if receipt is not None:
                try:
                    value = _Reference.model_validate_json(receipt.result_json)
                    if receipt.dependencies or value.upload_sha256 != key:
                        raise ValueError("upload reference binding differs")
                except ValueError:
                    damaged = True
                else:
                    return value.model_sha256, False
            if damaged and not repair:
                with TransferProgress("upload_model_reference_repair", 1, report) as progress:
                    progress.emit("repair_required", reason="completed_upload_reference_damaged")
                    raise UploadReferenceRepairRequired(
                        "completed upload reference requires repair"
                    )
            with TransferProgress(
                "upload_model_reference_repair" if damaged else "upload_model_reference",
                1,
                report,
                unit="requests",
                planning_unit_seconds=(0.001, 2.0),
            ) as progress:
                request = decode(key, raw)
                bundle = request.signed_submission.submission.model_bundle
                if bundle is None:
                    raise ValueError("retained model delivery requires a model bundle")
                value = _Reference(
                    schema="umi-upload-model-reference/1",
                    upload_sha256=key,
                    model_sha256=digest(bundle),
                )
                reuse.remember(receipt_key, (), canonical_json_bytes(value).decode())
                progress.advance(1)
            return value.model_sha256, damaged
