"""Bounded R2 control transport with atomic conditional cursor publication.

Signed documents establish authority. Object ETags only prevent overwriting a
different generation. This control store never deletes anything, and mutable
writes are restricted to the selected supervisor channel's cursor pages.
"""

from __future__ import annotations

import hashlib
import re

from .r2_evidence import R2EvidenceClient
from .translation_reference_channel import ChannelObject, ReferenceChannelConflict
from .validator_supervisor import MAX_SUPERVISOR_DOCUMENT_BYTES


class R2ReferenceChannelStore:
    def __init__(self, client: R2EvidenceClient, *, channel_prefix: str):
        if (
            re.fullmatch(
                r"validator-supervisor/channels/[0-9a-f]{64}/linux-(?:amd64|arm64)/after/",
                channel_prefix,
            )
            is None
        ):
            raise ValueError("reference channel storage prefix differs")
        self.client, self.prefix = client, channel_prefix

    def _key(self, key):
        if not key.startswith(self.prefix) or not key.endswith(".json"):
            raise ValueError("mutable reference object is outside the selected channel")
        suffix = key.removeprefix(self.prefix).removesuffix(".json").split("/")
        if (
            len(suffix) != 2
            or not suffix[0].isascii()
            or not suffix[0].isdigit()
            or str(int(suffix[0])) != suffix[0]
            or (suffix[0] == "0" and suffix[1] != "initial")
            or (
                suffix[0] != "0"
                and (len(suffix[1]) != 64 or any(c not in "0123456789abcdef" for c in suffix[1]))
            )
        ):
            raise ValueError("reference channel object has an invalid cursor")

    def read(self, key: str) -> ChannelObject | None:
        self._key(key)
        status, headers, raw = self.client._exchange(
            "GET", key, maximum=MAX_SUPERVISOR_DOCUMENT_BYTES, statuses=(200, 404)
        )
        if status == 404:
            return None
        etag = headers.get("etag")
        if (
            type(etag) is not str
            or not 2 < len(etag) < 256
            or not etag.startswith('"')
            or not etag.endswith('"')
            or any(ord(c) < 33 or ord(c) > 126 for c in etag)
        ):
            raise ValueError("reference channel object generation is missing or invalid")
        return ChannelObject(raw, etag)

    def compare_and_swap(self, key, previous, raw):
        self._key(key)
        if previous is not None and (
            type(previous) is not ChannelObject
            or re.fullmatch(r'"[\x21\x23-\x7e]{1,252}"', previous.etag) is None
        ):
            raise ValueError("reference channel comparison generation is invalid")
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_SUPERVISOR_DOCUMENT_BYTES:
            raise ValueError("reference channel payload exceeds its document bound")
        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store, no-cache, must-revalidate, no-transform",
        }
        headers.update({"If-None-Match": "*"} if previous is None else {"If-Match": previous.etag})
        status, _, _ = self.client._exchange(
            "PUT", key, body=raw, headers=headers, maximum=64 * 1024, statuses=(200, 201, 412)
        )
        if status == 412:
            raise ReferenceChannelConflict("reference channel generation advanced")

    def publish_approval(self, key, raw):
        prefix = "validator-supervisor/translation-reference-policies/"
        if (
            not key.startswith(prefix)
            or not key.endswith(".json")
            or len(key.removeprefix(prefix).removesuffix(".json")) != 64
            or any(
                c not in "0123456789abcdef" for c in key.removeprefix(prefix).removesuffix(".json")
            )
        ):
            raise ValueError("immutable approval is outside the typed policy namespace")
        if type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024:
            raise ValueError("immutable approval exceeds its typed bound")
        self.client.publish(key, raw, hashlib.sha256(raw).hexdigest())
