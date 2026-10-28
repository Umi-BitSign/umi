"""Optional bounded conditional publications; original S3 objects remain readable.

This transport supplies individual acknowledgements, never proof authority or a
packed-object representation. Malformed acknowledgements cannot become receipts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from contextlib import suppress

import httpx

from .protocol import canonical_json_bytes
from .r2_evidence import EvidenceObjectHead

PUBLISH_BATCH_PATH = "/v1/internal/r2/proof-publications"
MAX_PUBLISH_OBJECTS = 8
MAX_PUBLISH_OBJECT_BYTES = 4096
MAX_PUBLISH_BODY_BYTES = 64 * 1024
KEY_PURPOSE = b"umi-r2-proof-publication-key/1"
_LOG = logging.getLogger("umi.competition.progress")


class R2PublishBatchUnavailable(OSError):
    def __init__(self, reason_code, http_status=None):
        self.reason_code, self.http_status = reason_code, http_status
        super().__init__("R2 proof publication batch unavailable")


class R2ProofPublishBatch:
    def __init__(self, client):
        self.client = client
        self.origin = client.signer.credentials.proof_publish_batch_origin
        if self.origin is None:
            raise ValueError("proof publication batch requires explicit selection")

    def publish(self, objects):
        """Return one exact original head,409 conflict,or503 unavailable per key."""
        started = time.monotonic()
        counts = {
            "frontend_request_attempts": 0,
            "frontend_responses": 0,
            "http_status": None,
            "total_objects": len(objects),
            "acknowledged_objects": 0,
            "conflicting_objects": 0,
            "unavailable_objects": 0,
            "unknown_objects": len(objects),
            "fallback_objects": 0,
        }
        status, reason = "refused", "invalid_acknowledgement"
        try:
            results = self._publish(objects, counts)
            counts["acknowledged_objects"] = sum(
                isinstance(v, EvidenceObjectHead) for v in results.values()
            )
            counts["conflicting_objects"] = sum(v == 409 for v in results.values())
            counts["unavailable_objects"] = sum(v == 503 for v in results.values())
            counts["unknown_objects"] = 0
            # Conflicts refuse the graph, including any other unavailable item.
            counts["fallback_objects"] = (
                0 if counts["conflicting_objects"] else counts["unavailable_objects"]
            )
            status = (
                "refused"
                if counts["conflicting_objects"]
                else "retrying"
                if counts["unavailable_objects"]
                else "completed"
            )
            reason = (
                "conditional_conflict"
                if counts["conflicting_objects"]
                else "item_unavailable"
                if counts["unavailable_objects"]
                else "exact_acknowledgements"
            )
            return results
        except R2PublishBatchUnavailable as error:
            status, reason = "retrying", error.reason_code
            counts["fallback_objects"] = len(objects)
            raise
        finally:
            if counts["frontend_request_attempts"]:
                with suppress(Exception):
                    _LOG.info(
                        json.dumps(
                            {
                                "schema": "umi-r2-proof-publication-exchange/1",
                                "stage": "proof_publication_batch_exchange",
                                "status": status,
                                "reason": reason,
                                "elapsed_seconds": time.monotonic() - started,
                                "eta_seconds": 0 if status == "completed" else None,
                                "eta_basis": "completed_exchange"
                                if status == "completed"
                                else "withdrawn_refused_or_retrying",
                                "stalled_or_retrying": status in {"retrying", "refused"},
                                **counts,
                            },
                            separators=(",", ":"),
                        )
                    )

    def _publish(self, objects, counts):
        if not 1 <= len(objects) <= MAX_PUBLISH_OBJECTS:
            raise ValueError("proof publication batch object count exceeds bound")
        expected, items = {}, []
        for key, raw in objects.items():
            if type(raw) is not bytes or not 0 < len(raw) <= MAX_PUBLISH_OBJECT_BYTES:
                raise ValueError("proof publication batch object size exceeds bound")
            sha = hashlib.sha256(raw).hexdigest()
            if not key.endswith("/objects/" + sha):
                raise ValueError("proof publication batch requires original content address")
            self.client.signer.object_url(key)
            md5 = hashlib.md5(raw, usedforsecurity=False).hexdigest()
            expected[key] = EvidenceObjectHead(len(raw), md5, sha)
            items.append(
                dict(key=key, sha256=sha, md5=md5, content_b64=base64.b64encode(raw).decode())
            )
        nonce = secrets.token_hex(16)
        body = canonical_json_bytes(
            dict(
                schema="umi-r2-proof-publication-batch/1",
                nonce=nonce,
                issued_at_unix_ms=int(time.time() * 1000),
                endpoint=self.client.signer.endpoint,
                bucket=self.client.signer.bucket,
                objects=items,
            )
        )
        if len(body) > MAX_PUBLISH_BODY_BYTES:
            raise ValueError("proof publication batch body exceeds bound")
        credentials = self.client.signer.credentials
        purpose_key = hmac.digest(credentials.secret_access_key.encode(), KEY_PURPOSE, "sha256")
        signature = hmac.digest(
            purpose_key, b"POST\n" + PUBLISH_BATCH_PATH.encode() + b"\n" + body, "sha256"
        ).hex()
        headers = {
            "authorization": "UMI-R2-Proof-Publication/1 "
            + credentials.access_key_id
            + ":"
            + signature,
            "content-type": "application/json",
            "cache-control": "no-store",
            "accept-encoding": "identity",
            "user-agent": "umi/r2-proof-publication-batch",
        }
        raw = bytearray()
        try:
            with self.client.connection_scope(), self.client._request_client() as client:
                counts["frontend_request_attempts"] += 1
                with client.stream(
                    "POST", self.origin + PUBLISH_BATCH_PATH, headers=headers, content=body
                ) as response:
                    counts["frontend_responses"] += 1
                    counts["http_status"] = response.status_code
                    if response.status_code != 200:
                        raise R2PublishBatchUnavailable(
                            "r2_publish_batch_http_" + str(response.status_code),
                            response.status_code,
                        )
                    if response.headers.get("content-type", "").split(";", 1)[
                        0
                    ].strip() != "application/json" or response.headers.get(
                        "content-encoding"
                    ) not in (None, "identity"):
                        raise ValueError("proof publication batch acknowledgement type differs")
                    for chunk in response.iter_bytes(chunk_size=8192):
                        if len(raw) + len(chunk) > MAX_PUBLISH_BODY_BYTES:
                            raise ValueError(
                                "proof publication batch acknowledgement exceeds bound"
                            )
                        raw.extend(chunk)
        except httpx.HTTPError as error:
            raise R2PublishBatchUnavailable("r2_publish_batch_transport_error") from error
        try:
            value = json.loads(raw)
            if (
                type(value) is not dict
                or set(value) != {"schema", "nonce", "endpoint", "bucket", "objects"}
                or value["schema"] != "umi-r2-proof-publication-batch-response/1"
                or value["nonce"] != nonce
                or value["endpoint"] != self.client.signer.endpoint
                or value["bucket"] != self.client.signer.bucket
                or type(value["objects"]) is not list
                or len(value["objects"]) != len(items)
            ):
                raise ValueError("proof publication batch acknowledgement binding differs")
            results = {}
            for key, item in zip(objects, value["objects"], strict=True):
                if (
                    type(item) is not dict
                    or item.get("key") != key
                    or type(item.get("status")) is not int
                ):
                    raise ValueError("proof publication batch acknowledgement order differs")
                status = item["status"]
                if status in (409, 503) and set(item) == {"key", "status"}:
                    results[key] = status
                elif (
                    status == 200
                    and set(item) == {"key", "status", "size_bytes", "etag", "sha256"}
                    and type(item["size_bytes"]) is int
                ):
                    head = EvidenceObjectHead(item["size_bytes"], item["etag"], item["sha256"])
                    if head != expected[key]:
                        raise ValueError(
                            "proof publication batch acknowledgement differs from original bytes"
                        )
                    results[key] = head
                else:
                    raise ValueError("proof publication batch acknowledgement fields differ")
            return results
        except (KeyError, TypeError, UnicodeError) as error:
            raise ValueError("proof publication batch acknowledgement malformed") from error
