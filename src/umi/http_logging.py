"""Redact HTTP capabilities before log records reach any handler.

The record factory covers child loggers and handlers with propagation disabled;
filters on the ``httpcore`` parent alone do not cover those paths. Installation
does not change logger levels, handlers, or request/exception objects.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import urlsplit, urlunsplit

_URL = re.compile(r"https?://[^\s<>\"'\\]+", re.IGNORECASE)
_CLIP = re.compile(r"(?:/|%2f)v1(?:/|%2f)clips(?:/|%2f)[^\s<>\"'\\]*", re.IGNORECASE)
_BEARER = re.compile(r"\b(Bearer)\s+(?!\[redacted\])[^\s\"'\\,;\])]+", re.IGNORECASE)
_VIDEO_FETCH: ContextVar[bool] = ContextVar("umi_video_fetch_logging", default=False)
_INSTALL_LOCK = threading.Lock()


def redact_http_secrets(text: str) -> str:
    """Keep origins and ordinary paths; remove URL credentials and clip grants.

    Every URL query and fragment is treated as private, including unfamiliar
    signing schemes. Relative and percent-encoded clip paths are covered too.
    """

    def url(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            parts = urlsplit(raw)
            authority = parts.netloc
            if "@" in authority:
                authority = "redacted@" + authority.rsplit("@", 1)[1]
            return urlunsplit(
                (
                    parts.scheme,
                    authority,
                    _CLIP.sub("/v1/clips/[redacted]", parts.path),
                    "[redacted]" if parts.query else "",
                    "[redacted]" if parts.fragment else "",
                )
            )
        except ValueError:
            return "[redacted-url]"

    text = _URL.sub(url, text)
    text = _CLIP.sub("/v1/clips/[redacted]", text)
    return _BEARER.sub(r"\1 [redacted]", text)


def _redact_record(record: logging.LogRecord) -> None:
    if _VIDEO_FETCH.get() and (record.name == "httpcore" or record.name.startswith("httpcore.")):
        # HTTPCORE's debug return_value/exception repr can contain arbitrary
        # response headers, echoed request targets, cookies or response bytes.
        # Retain the event name only for this fetch, including its close phase.
        event = record.getMessage().split(" ", 1)[0]
        if re.fullmatch(r"[a-z_]+\.(?:started|complete|failed)", event) is None:
            event = "httpcore"
        record.msg = event + " [video fetch details redacted]"
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
    else:
        record.msg = redact_http_secrets(record.getMessage())
        # A VideoFetchError can retain an HTTPError as its cause. Sanitize the
        # formatted chain too, even when the caller logs after the fetch ends.
        if record.exc_info:
            record.exc_text = redact_http_secrets(
                logging.Formatter().formatException(record.exc_info)
            )
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_http_secrets(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_http_secrets(record.stack_info)
    record.args = ()
    if hasattr(record, "message"):
        record.message = record.msg


def install_http_log_redaction() -> None:
    """Install once, preserving a previously configured record factory.

    Entry points may call this after configuring logging to protect startup
    requests too. The video-fetch boundary installs it itself. Changes affect
    log text only; no URL objects, transport inputs or exception chains mutate.
    Custom formatters that inspect arbitrary ``extra`` objects are outside this
    boundary and must not serialize request objects or credentials themselves.
    """
    with _INSTALL_LOCK:
        previous = logging.getLogRecordFactory()
        if getattr(previous, "_umi_http_redaction", False):
            return

        def factory(*args, **kwargs):
            record = previous(*args, **kwargs)
            _redact_record(record)
            return record

        factory._umi_http_redaction = True
        logging.setLogRecordFactory(factory)


@contextmanager
def video_fetch_logging() -> Iterator[None]:
    """Protect resolution, connection, streaming and close in this async task."""
    install_http_log_redaction()
    token = _VIDEO_FETCH.set(True)
    try:
        yield
    finally:
        _VIDEO_FETCH.reset(token)
