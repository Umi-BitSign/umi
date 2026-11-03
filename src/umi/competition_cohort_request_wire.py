"""Assemble an unchanged request-review wire body from owned canonical originals.

The native collector is the authority for its exact bytes and immutable identities.
This module neither accepts a caller-provided digest nor performs semantic replay.
It retains one output buffer, releases each copied collector object, and hashes the
challenged response while writing. A new challenge still requires a new response
hash; it does not require parsing or canonicalizing unchanged evidence again.
"""

import hashlib
import io
import re
from dataclasses import dataclass

from .competition_cohort_object_codec import canonical_endpoint_export_bytes
from .competition_transport_verification import TransferProgress
from .open_competition import _DIGEST_DOMAIN
from .protocol import canonical_json_bytes


@dataclass
class PreparedRequestResponse:
    """Owned bytes and their digest, prepared together by the native exporter."""

    buffer: io.BytesIO
    sha256: str
    maximum_bytes: int
    objects: int
    original_object_bytes: int

    def finish(self, signature) -> bytes:
        suffix = b',"signature":' + canonical_json_bytes(signature) + b"}"
        if self.buffer.tell() + len(suffix) > self.maximum_bytes:
            raise OSError("signed request export exceeds capacity; preserve and retry")
        self.buffer.write(suffix)
        return self.buffer.getvalue()


def prepare_request_response(challenge, metadata, captured, maximum_bytes):
    """Serialize native captured evidence once, without rebuilding its JSON graph.

    ``metadata`` is a fully validated RequestReviewExport with an empty object
    inventory. ``captured`` is the bounded ReplayObjectCollector that the native
    replay filled. Its reads check immutable identity before and after delivery;
    sources without that retained authority use normal canonical/hash validation.
    """
    if metadata.objects:
        raise ValueError("request export metadata must not duplicate its object inventory")
    keys = sorted(captured.values)
    if any(type(key) is not str or re.fullmatch(r"[0-9a-f]{64}", key) is None for key in keys):
        raise ValueError("request export object key is not a canonical digest")
    output = io.BytesIO()
    output.write(b'{"response":')
    hashing = hashlib.sha256(_DIGEST_DOMAIN)

    def write(chunk):
        if output.tell() + len(chunk) > maximum_bytes:
            raise OSError("signed request export exceeds capacity; preserve and retry")
        output.write(chunk)
        hashing.update(chunk)

    write(b'{"challenge":')
    write(canonical_json_bytes(challenge))
    write(b',"evidence":{')
    fields = {
        (field.serialization_alias or name): name
        for name, field in type(metadata).model_fields.items()
    }
    with TransferProgress(
        "request_export_canonical_objects",
        captured.used,
        total_operations=len(keys),
    ) as progress:
        for index, alias in enumerate(sorted(fields, key=lambda key: key.encode("utf-16be"))):
            if index:
                write(b",")
            write(canonical_json_bytes(alias))
            write(b":")
            name = fields[alias]
            if name != "objects":
                # Metadata is typed and already validated. Serialize tuple members
                # separately so records/services do not require another whole copy.
                value = getattr(metadata, name)
                if type(value) is tuple:
                    write(b"[")
                    for position, member in enumerate(value):
                        if position:
                            write(b",")
                        write(canonical_json_bytes(member))
                    write(b"]")
                else:
                    write(canonical_json_bytes(value))
                continue
            write(b"[")
            for position, key in enumerate(keys):
                if position:
                    write(b",")
                raw = captured.values[key]
                write(b'{"sha256":')
                write(canonical_json_bytes(key))
                write(b',"value":')
                write(canonical_endpoint_export_bytes(raw))
                write(b"}")
                # Only this call's ephemeral read buffer is released. Coverage,
                # native receipts, source identities and durable objects remain.
                captured.release_materialized(key)
                progress.advance(len(raw))
                progress.advance_operations(1)
                del raw
            write(b"]")
    write(b'},"schema":"umi-request-review-response/1"}')
    return PreparedRequestResponse(
        output, hashing.hexdigest(), maximum_bytes, len(keys), captured.used
    )
