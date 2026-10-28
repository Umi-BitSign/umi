"""Streaming shape checks before native decoding; native validation remains mandatory."""

import hashlib
import json
import re
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

_declarations = ContextVar("requests_stage_declarations", default=None)
_object_bytes = ContextVar("requests_stage_object_bytes", default=None)
_evidence_values = ContextVar("requests_stage_evidence_values", default=None)
_shape_capture = ContextVar("requests_stage_shape_capture", default=None)

_PUNCTUATION = b'{}[],:"'
_SCALAR_END = re.compile(rb'[\s{}\[\],:"]')
_STRING_SPECIAL = re.compile(rb'["\\]')


def stage_bounds():
    from .host_memory_runtime import requests_stage_policy

    policy = requests_stage_policy()
    return None if policy is None else policy.bounds


def stage_limit(name, original):
    bounds = stage_bounds()
    if bounds is None:
        return original
    maximum = min(original, getattr(bounds, name))
    if name == "maximum_declaration_bytes" and _declarations.get() is not None:
        maximum = min(maximum, _declarations.get()[0])
    if name == "maximum_object_bytes" and _object_bytes.get() is not None:
        maximum = min(maximum, _object_bytes.get())
    if maximum <= 0:
        raise ValueError("requests-stage input budget is exhausted")
    return maximum


def stage_count(name, count):
    bounds = stage_bounds()
    if bounds is not None and count > getattr(bounds, name):
        raise ValueError("requests-stage evidence exceeds qualified " + name)


def charge_stage_declaration(size):
    budget = _declarations.get()
    if budget is not None:
        if size > budget[0]:
            raise ValueError("requests-stage declarations exceed qualified aggregate bytes")
        budget[0] -= size


def bounded_stage_declarations(function):
    @wraps(function)
    def bounded(*args, **kwargs):
        bounds = stage_bounds()
        if bounds is None or _declarations.get() is not None:
            return function(*args, **kwargs)
        token = _declarations.set([bounds.maximum_declaration_bytes])
        try:
            with stage_evidence_budget():
                return function(*args, **kwargs)
        finally:
            _declarations.reset(token)

    return bounded


@contextmanager
def stage_object_budget(maximum):
    previous = _object_bytes.get()
    token = _object_bytes.set(maximum if previous is None else min(previous, maximum))
    try:
        yield
    finally:
        _object_bytes.reset(token)


@contextmanager
def stage_evidence_budget():
    """Charge unique raw source values across one owned aggregate operation."""
    bounds = stage_bounds()
    if bounds is None or _evidence_values.get() is not None:
        yield
        return
    token = _evidence_values.set({"remaining": bounds.maximum_json_values, "seen": {}})
    try:
        yield
    finally:
        _evidence_values.reset(token)


def stage_shape_identity():
    """Bind retained shape counts to every selected bound and these check rules."""
    bounds = stage_bounds()
    value = None if bounds is None else bounds.model_dump(mode="json", by_alias=True)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(b"umi-verified-json-shape-v1\0" + raw).hexdigest()


@contextmanager
def capture_stage_json_shapes():
    """Retain the accounting from the first native read, without a second scan."""
    values = {}
    token = _shape_capture.set(values)
    try:
        yield values
    finally:
        _shape_capture.reset(token)


def _capture_shape(raw, kind, values, fingerprint=None):
    captured = _shape_capture.get()
    if captured is not None:
        sha = (fingerprint or hashlib.sha256(raw).digest()).hex()
        captured[sha, kind] = dict(
            byte_sha256=sha,
            size=len(raw),
            values=values,
            bounds_sha256=stage_shape_identity(),
            kind=kind,
        )


def replay_stage_json_shape(
    *, byte_sha256, size, values, bounds_sha256, maximum_bytes, kind="object"
):
    """Account for an owner-authenticated shape descriptor without its payload.

    The caller must establish unchanged immutable bytes and a successful native
    shape check before retaining these fields. A digest supplied by an untrusted
    source is not that authority. Changed bounds return a miss without charging;
    matching bounds still enforce the current byte and aggregate value budgets.
    Ordinary reads and retained descriptors share the raw-byte SHA256 identity.
    This does not charge declaration bytes or replace semantic verification.
    """
    if bounds_sha256 != stage_shape_identity():
        return False
    if (
        type(byte_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", byte_sha256) is None
        or type(size) is not int
        or size <= 0
        or type(maximum_bytes) is not int
        or maximum_bytes <= 0
        or kind not in ("input", "object", "declaration")
    ):
        raise ValueError("invalid retained JSON shape descriptor")
    if size > stage_limit("maximum_" + kind + "_bytes", maximum_bytes):
        raise ValueError("requests-stage JSON exceeds its qualified byte bound")
    bounds = stage_bounds()
    if bounds is None:
        if values is not None:
            raise ValueError("unbounded retained JSON shape has an unexpected value count")
        return True
    if type(values) is not int or not 1 <= values <= bounds.maximum_json_values:
        raise ValueError("invalid retained JSON shape value count")
    aggregate = _evidence_values.get()
    if aggregate is not None:
        fingerprint = bytes.fromhex(byte_sha256)
        if fingerprint in aggregate["seen"]:
            if aggregate["seen"][fingerprint] != values:
                raise ValueError("retained JSON shape changed its verified value count")
        else:
            if values > aggregate["remaining"]:
                raise ValueError("requests-stage JSON exceeds its qualified value count")
            aggregate["seen"][fingerprint] = values
            aggregate["remaining"] -= values
    return True


def _tokens(raw):
    """Linear scan with bounded auxiliary memory, including malformed strings."""
    index = 0
    while index < len(raw):
        first = raw[index]
        if first in b" \t\r\n":
            index += 1
            continue
        start = index
        index += 1
        if first == 34:
            while True:
                special = _STRING_SPECIAL.search(raw, index)
                if special is None:
                    raise ValueError("unterminated requests-stage JSON string")
                index = special.end()
                if raw[special.start()] == 34:
                    break
                index += 1  # Escaped byte; native decoder validates the escape.
        elif first not in _PUNCTUATION:
            end = _SCALAR_END.search(raw, index)
            index = len(raw) if end is None else end.start()
        yield first, start, index


def check_stage_json(raw, *, kind="input"):
    """Bound bytes, value count, depth and named arrays before allocating a graph.

    Original schema, canonical and domain checks still run afterwards. Strings
    are not copied; only short object keys are decoded. Syntax validation here
    prevents malformed framing from bypassing the shape counters.
    """
    bounds = stage_bounds()
    if bounds is None:
        _capture_shape(raw, kind, None)
        return
    if len(raw) > getattr(bounds, "maximum_" + kind + "_bytes"):
        raise ValueError("requests-stage JSON exceeds its qualified byte bound")
    aggregate = _evidence_values.get()
    fingerprint = None if aggregate is None else hashlib.sha256(raw).digest()
    if aggregate is not None and fingerprint in aggregate["seen"]:
        values = aggregate["seen"][fingerprint]
        _capture_shape(raw, kind, values, fingerprint)
        return values
    value_limit = (
        bounds.maximum_json_values
        if aggregate is None
        else min(bounds.maximum_json_values, aggregate["remaining"])
    )
    caps = {
        "records": bounds.maximum_records,
        "objects": bounds.maximum_objects,
        "services": bounds.maximum_services,
        "orders": bounds.maximum_orders,
        "participants": bounds.maximum_participants,
        "catalogs": bounds.maximum_catalogs,
    }
    member_limits = {
        "records": bounds.maximum_object_bytes,
        "objects": bounds.maximum_object_bytes,
        "services": bounds.maximum_object_bytes,
        "orders": bounds.maximum_object_bytes,
        "participants": bounds.maximum_declaration_bytes,
        "catalogs": bounds.maximum_declaration_bytes,
    }
    stack, values, root = [], 0, False
    for first, start, end in _tokens(raw):
        field = None
        parent = stack[-1] if stack else None
        if first in (125, 93):
            if (
                parent is None
                or parent["kind"] != first
                or parent["state"] not in {"first", "comma"}
            ):
                raise ValueError("invalid requests-stage JSON container")
            if end - parent["start"] > parent["span_limit"]:
                raise ValueError("requests-stage JSON element exceeds its qualified byte bound")
            stack.pop()
            continue
        if first == 44:
            if parent is None or parent["state"] != "comma":
                raise ValueError("invalid requests-stage JSON separator")
            parent["state"] = "key" if parent["kind"] == 125 else "value"
            continue
        if first == 58:
            if parent is None or parent["state"] != "colon":
                raise ValueError("invalid requests-stage JSON colon")
            parent["state"] = "value"
            continue
        values += 1
        if values > value_limit:
            raise ValueError("requests-stage JSON exceeds its qualified value count")
        if parent is None:
            if root:
                raise ValueError("multiple requests-stage JSON roots")
            root = True
        elif parent["kind"] == 125 and parent["state"] in {"first", "key"}:
            if first != 34:
                raise ValueError("invalid requests-stage JSON object key")
            parent["key"] = json.loads(raw[start:end]) if end - start <= 128 else None
            parent["state"] = "colon"
            continue
        else:
            if parent["state"] not in {"first", "value"}:
                raise ValueError("invalid requests-stage JSON value")
            if parent["kind"] == 93:
                parent["count"] += 1
                if parent["count"] > parent["maximum"]:
                    raise ValueError("requests-stage JSON inventory exceeds its qualified count")
            else:
                field = parent["key"]
            parent["state"] = "comma"
        span_limit = (
            parent["member_limit"]
            if parent is not None and parent["kind"] == 93
            else bounds.maximum_input_bytes
        )
        if end - start > span_limit:
            raise ValueError("requests-stage JSON element exceeds its qualified byte bound")
        if first in (123, 91):
            if len(stack) >= bounds.maximum_json_depth:
                raise ValueError("requests-stage JSON exceeds its qualified depth")
            stack.append(
                {
                    "kind": 125 if first == 123 else 93,
                    "state": "first",
                    "key": None,
                    "count": 0,
                    "maximum": caps.get(field, bounds.maximum_json_values),
                    "member_limit": member_limits.get(field, bounds.maximum_input_bytes),
                    "start": start,
                    "span_limit": span_limit,
                }
            )
    if stack or not root:
        raise ValueError("incomplete requests-stage JSON")
    if aggregate is not None:
        aggregate["seen"][fingerprint] = values
        aggregate["remaining"] -= values
    _capture_shape(raw, kind, values, fingerprint)
    return values
