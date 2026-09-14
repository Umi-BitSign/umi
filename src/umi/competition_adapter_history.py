"""Lossless shared storage for retained successor history, without activation authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .competition_supervisor import (
    MAX_SUCCESSOR_DOCUMENT_BYTES,
    MAX_SUCCESSOR_HISTORY_BYTES,
    MAX_SUCCESSOR_HISTORY_RECORDS,
    SignedSuccessorSupervisorDirective,
    parse_canonical_signed_successor_supervisor_directive,
    parse_canonical_successor_supervisor_directive_history,
)
from .protocol import canonical_json_bytes
from .validator_supervisor import MAX_JSON_SAFE_INTEGER, MAX_SUPERVISOR_DIRECTIVES_PER_PAGE

MAX_HISTORY_NODE_BYTES = MAX_SUCCESSOR_DOCUMENT_BYTES + 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PAGE_SCHEMAS = {
    "umi-validator-supervisor-directive-page/4",
    "umi-validator-supervisor-directive-history/1",
}


class RetainedHistoryError(ValueError):
    pass


@dataclass(frozen=True)
class HistoryNode:
    previous: str | None
    signed: SignedSuccessorSupervisorDirective
    signed_size_bytes: int


@dataclass(frozen=True)
class HistoryPrefix:
    count: int
    cursor: tuple[int, int, str]
    signed_size_bytes: int


def _is_hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def encode_history(payload: bytes):
    """Return an exact-page reference and content-addressed prefix nodes."""
    page = parse_canonical_successor_supervisor_directive_history(payload)
    if page.more:
        raise RetainedHistoryError("retained history must end at its selected head")
    nodes, previous = {}, None
    for signed in page.directives:
        body = canonical_json_bytes(
            {
                "schema": "umi-successor-history-node/1",
                "previous": previous,
                "signed": json.loads(canonical_json_bytes(signed)),
            }
        )
        if len(body) > MAX_HISTORY_NODE_BYTES:
            raise RetainedHistoryError("retained history node exceeds its byte bound")
        previous = hashlib.sha256(body).hexdigest()
        nodes[previous] = body
    reference = {
        "schema": "umi-successor-history-reference/1",
        "page_schema": page.schema_,
        "after_version": page.after_version,
        "after_sequence": page.after_sequence,
        "after_directive_sha256": page.after_directive_sha256,
        "count": len(page.directives),
        "tip": previous,
        "page_sha256": hashlib.sha256(payload).hexdigest(),
        "page_size_bytes": len(payload),
    }
    return reference, nodes


def validate_history_reference(value):
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "page_schema",
            "after_version",
            "after_sequence",
            "after_directive_sha256",
            "count",
            "tip",
            "page_sha256",
            "page_size_bytes",
        }
        or value["schema"] != "umi-successor-history-reference/1"
        or not isinstance(value["page_schema"], str)
        or value["page_schema"] not in _PAGE_SCHEMAS
        or type(value["after_version"]) is not int
        or value["after_version"] not in {3, 4}
        or type(value["after_sequence"]) is not int
        or not 1 <= value["after_sequence"] <= MAX_JSON_SAFE_INTEGER
        or not _is_hash(value["after_directive_sha256"])
        or type(value["count"]) is not int
        or not 0 <= value["count"] <= MAX_SUCCESSOR_HISTORY_RECORDS
        or (value["tip"] is not None and not _is_hash(value["tip"]))
        or (value["count"] == 0) != (value["tip"] is None)
        or (value["after_version"] == 3 and value["count"] == 0)
        or not _is_hash(value["page_sha256"])
        or type(value["page_size_bytes"]) is not int
        or not 0 < value["page_size_bytes"] <= MAX_SUCCESSOR_HISTORY_BYTES
        or (
            value["page_schema"] == "umi-validator-supervisor-directive-page/4"
            and (
                value["count"] > MAX_SUPERVISOR_DIRECTIVES_PER_PAGE
                or value["page_size_bytes"] > MAX_SUCCESSOR_DOCUMENT_BYTES
            )
        )
    ):
        raise RetainedHistoryError("retained history reference is corrupt")


def parse_history_node(identity: str, body: bytes) -> HistoryNode:
    if (
        not _is_hash(identity)
        or not isinstance(body, bytes)
        or not 0 < len(body) <= MAX_HISTORY_NODE_BYTES
        or hashlib.sha256(body).hexdigest() != identity
    ):
        raise RetainedHistoryError("retained history node is corrupt")
    value = json.loads(body)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "previous", "signed"}
        or value["schema"] != "umi-successor-history-node/1"
        or canonical_json_bytes(value) != body
        or (value["previous"] is not None and not _is_hash(value["previous"]))
    ):
        raise RetainedHistoryError("retained history node is corrupt")
    signed_bytes = canonical_json_bytes(value["signed"])
    return HistoryNode(
        value["previous"],
        parse_canonical_signed_successor_supervisor_directive(signed_bytes),
        len(signed_bytes),
    )


def summarize_history_nodes(nodes):
    """Check all stored links once, including nodes not selected by a run."""
    result = {}
    for identity in nodes:
        current, trail, visiting = identity, [], set()
        while current is not None and current not in result:
            if current in visiting or len(trail) >= MAX_SUCCESSOR_HISTORY_RECORDS:
                raise RetainedHistoryError(
                    "retained history has a cycle or exceeds its depth bound"
                )
            node = nodes.get(current)
            if node is None:
                raise RetainedHistoryError("retained history node is missing")
            visiting.add(current)
            trail.append(current)
            current = node.previous
        for item in reversed(trail):
            node = nodes[item]
            directive = node.signed.directive
            if node.previous is None:
                prefix = HistoryPrefix(
                    1,
                    (
                        directive.predecessor_version,
                        directive.sequence - 1,
                        directive.previous_directive_sha256,
                    ),
                    node.signed_size_bytes,
                )
            else:
                prior = result[node.previous]
                parent = nodes[node.previous].signed
                if (
                    directive.predecessor_version != 4
                    or directive.sequence != parent.directive.sequence + 1
                    or directive.previous_directive_sha256 != parent.directive_sha256
                ):
                    raise RetainedHistoryError("retained history predecessor differs")
                prefix = HistoryPrefix(
                    prior.count + 1, prior.cursor, prior.signed_size_bytes + node.signed_size_bytes
                )
            if (
                prefix.count > MAX_SUCCESSOR_HISTORY_RECORDS
                or prefix.signed_size_bytes > MAX_SUCCESSOR_HISTORY_BYTES
            ):
                raise RetainedHistoryError("retained history prefix exceeds its bounds")
            result[item] = prefix
    return result


def validate_reference_head(reference, *, head, nodes, prefixes):
    """Validate every run's cursor/head without expanding all histories at once."""
    validate_history_reference(reference)
    cursor = (
        reference["after_version"],
        reference["after_sequence"],
        reference["after_directive_sha256"],
    )
    if reference["count"] == 0:
        if cursor != (4, head.directive.sequence, head.directive_sha256):
            raise RetainedHistoryError("retained empty history head differs")
        return
    tip = reference["tip"]
    prefix = prefixes.get(tip)
    if prefix is None or tip not in nodes:
        raise RetainedHistoryError("retained history node is missing")
    if (
        nodes[tip].signed != head
        or prefix.cursor != cursor
        or prefix.count != reference["count"]
        or prefix.signed_size_bytes + nodes[tip].signed_size_bytes > reference["page_size_bytes"]
    ):
        raise RetainedHistoryError("retained history reference differs from its prefix or head")


def restore_history(reference, *, head, nodes) -> bytes:
    """Reconstruct one original page; neither a reference nor a hash is authority."""
    validate_history_reference(reference)
    current, reversed_records = reference["tip"], []
    total = len(canonical_json_bytes(head))
    for _ in range(reference["count"]):
        node = nodes.get(current)
        if node is None:
            raise RetainedHistoryError("retained history node is missing")
        total += node.signed_size_bytes
        if total > reference["page_size_bytes"]:
            raise RetainedHistoryError("retained history exceeds its recorded byte bound")
        reversed_records.append(node.signed)
        current = node.previous
    if current is not None:
        raise RetainedHistoryError("retained history prefix length differs")
    body = canonical_json_bytes(
        {
            "schema": reference["page_schema"],
            "after_version": reference["after_version"],
            "after_sequence": reference["after_sequence"],
            "after_directive_sha256": reference["after_directive_sha256"],
            "directives": [
                item.model_dump(mode="json", by_alias=True) for item in reversed(reversed_records)
            ],
            "head": head.model_dump(mode="json", by_alias=True),
            "more": False,
        }
    )
    if (
        len(body) != reference["page_size_bytes"]
        or hashlib.sha256(body).hexdigest() != reference["page_sha256"]
    ):
        raise RetainedHistoryError("retained history bytes differ from their recorded binding")
    parse_canonical_successor_supervisor_directive_history(body)
    return body
