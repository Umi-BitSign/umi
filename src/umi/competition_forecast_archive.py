"""Bounded immutable forecast segments retain exact original hash-chain bytes.

Encoding is performed when sealing an unfinished segment. Completed segments
are retained by their transport receipts; ordinary restart and status polling
must not decode them again. Decoding serves explicit history reads and repair.
"""

import hashlib
import json
import re
import zlib
from dataclasses import dataclass
from functools import cached_property

from .competition_forecast_io import encode_forecast_json
from .competition_forecast_summary import ForecastSummary

MAX_SEGMENT_BYTES = 8 * 1024**2
MAX_SEGMENT_RECORDS = 4096
MAX_EVENT_BYTES = 16 * 1024
_MAGIC = b"umi-forecast-segment/1\n"


@dataclass(frozen=True)
class ForecastSegment:
    ledger_sha256: str
    first_sequence: int
    previous_sha256: str
    # Rows retain the original SQLite order and exact event body bytes.
    rows: tuple[tuple[int, str, str, bytes, str, str], ...]

    @property
    def last_sequence(self):
        return self.rows[-1][0]

    @property
    def last_sha256(self):
        return self.rows[-1][-1]

    @property
    def key(self):
        return (
            f"forecasts/{self.ledger_sha256}/{self.first_sequence:016x}-"
            f"{self.last_sequence:016x}-{self.last_sha256}"
        )

    def checked(self):
        _ = self._validated_events
        return self

    @cached_property
    def _validated_events(self):
        for value in (self.ledger_sha256, self.previous_sha256):
            if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError("forecast segment binding is invalid")
        if type(self.first_sequence) is not int or self.first_sequence < 1:
            raise ValueError("forecast segment sequence is invalid")
        if type(self.rows) is not tuple or not 1 <= len(self.rows) <= MAX_SEGMENT_RECORDS:
            raise ValueError("forecast segment record count exceeds its bound")
        previous, identities = self.previous_sha256, set()
        total = 0
        events = []
        for expected, row in enumerate(self.rows, self.first_sequence):
            if type(row) is not tuple or len(row) != 6:
                raise ValueError("forecast segment row is invalid")
            sequence, identity, scope, body, parent, checksum = row
            if (
                type(sequence) is not int
                or sequence != expected
                or type(identity) is not str
                or not identity
                or identity in identities
                or type(scope) is not str
                or not scope
                or type(body) is not bytes
                or not 0 < len(body) <= MAX_EVENT_BYTES
                or parent != previous
                or hashlib.sha256(parent.encode() + body).hexdigest() != checksum
            ):
                raise ValueError("forecast segment chain or identity is damaged")
            total += len(body)
            if total > MAX_SEGMENT_BYTES:
                raise ValueError("forecast segment exceeds its uncompressed bound")
            event = json.loads(body)
            if (
                encode_forecast_json(event) != body
                or event.get("schema") != "umi-forecast-event/1"
                or (event.get("identity"), event.get("scope")) != (identity, scope)
                or event.get("certification_authority") is not False
            ):
                raise ValueError("forecast segment event identity is damaged")
            ForecastSummary().prepare(event)
            events.append(event)
            identities.add(identity)
            previous = checksum
        return tuple(events)


def encode_segment(segment):
    segment.checked()
    value = {
        "schema": "umi-forecast-segment/1",
        "ledger_sha256": segment.ledger_sha256,
        "first_sequence": segment.first_sequence,
        "previous_sha256": segment.previous_sha256,
        "rows": [
            [sequence, identity, scope, body.decode(), parent, checksum]
            for sequence, identity, scope, body, parent, checksum in segment.rows
        ],
    }
    raw = encode_forecast_json(value)
    if len(raw) > MAX_SEGMENT_BYTES:
        raise ValueError("forecast segment envelope exceeds its uncompressed bound")
    encoded = _MAGIC + zlib.compress(raw)
    if len(encoded) > MAX_SEGMENT_BYTES:
        raise ValueError("forecast segment exceeds its transport bound")
    return encoded


def decode_segment(raw, *, ledger_sha256, first_sequence, previous_sha256, last_sha256):
    if type(raw) is not bytes or not len(_MAGIC) < len(raw) <= MAX_SEGMENT_BYTES:
        raise ValueError("forecast segment exceeds its transport bound")
    if not raw.startswith(_MAGIC):
        raise ValueError("unsupported forecast segment encoding")
    decoder = zlib.decompressobj()
    try:
        body = decoder.decompress(raw[len(_MAGIC) :], MAX_SEGMENT_BYTES + 1)
    except zlib.error as error:
        raise ValueError("forecast segment compression is damaged") from error
    if (
        len(body) > MAX_SEGMENT_BYTES
        or not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
    ):
        raise ValueError("forecast segment compression is truncated, oversized or has a tail")
    value = json.loads(body)
    if (
        type(value) is not dict
        or set(value) != {"schema", "ledger_sha256", "first_sequence", "previous_sha256", "rows"}
        or value["schema"] != "umi-forecast-segment/1"
        or encode_forecast_json(value) != body
        or (value["ledger_sha256"], value["first_sequence"], value["previous_sha256"])
        != (ledger_sha256, first_sequence, previous_sha256)
        or type(value["rows"]) is not list
        or not 1 <= len(value["rows"]) <= MAX_SEGMENT_RECORDS
    ):
        raise ValueError("forecast segment differs from its retained binding")
    rows = []
    for row in value["rows"]:
        if type(row) is not list or len(row) != 6 or type(row[3]) is not str:
            raise ValueError("forecast segment row is invalid")
        rows.append((*row[:3], row[3].encode(), *row[4:]))
    segment = ForecastSegment(ledger_sha256, first_sequence, previous_sha256, tuple(rows))
    segment.checked()
    if segment.last_sha256 != last_sha256:
        raise ValueError("forecast segment endpoint differs from its retained binding")
    return segment
