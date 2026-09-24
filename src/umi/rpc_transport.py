"""Operator-selected RPC routes and private header credentials.

Routes change transport only. Signed chain configurations, block requests,
native finality/proof checks and transaction recovery identities stay intact.
The configuration is a local service control, never a network-supplied artifact.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from websockets.asyncio.client import connect
from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

CONFIG_ENV = "UMI_RPC_TRANSPORT_CONFIG"
WORKER_DIRECTORY = "/run/umi-rpc"
CONFIG_FILENAME = "transport.json"
_QUIET_LOGGER = logging.Logger("umi.private_rpc_transport")
_QUIET_LOGGER.disabled = True
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RpcRoute:
    endpoint: str
    authorization_file: Path | None


def _endpoint(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("rpc_transport_endpoint_invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(c) < 33 for c in value)
    ):
        raise ValueError("rpc_transport_endpoint_invalid")
    return value


def _read_file(path: Path, maximum: int, *, private: bool) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in (0, os.geteuid())
                or info.st_mode & (0o077 if private else 0o022)
                or not 0 < info.st_size <= maximum
            ):
                raise ValueError("rpc_transport_file_invalid")
            data = os.read(fd, maximum + 1)
            after = os.fstat(fd)
            fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mode",
                "st_uid",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if len(data) != info.st_size or any(
                getattr(info, f) != getattr(after, f) for f in fields
            ):
                raise ValueError("rpc_transport_file_changed")
            return data
        finally:
            os.close(fd)
    except (OSError, ValueError):
        raise ValueError("rpc_transport_file_unavailable") from None


def transport_config_path() -> Path | None:
    value = os.environ.get(CONFIG_ENV)
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute() or path.name != CONFIG_FILENAME or ".." in path.parts:
        raise ValueError("rpc_transport_config_path_invalid")
    return path


def load_routes(path: Path) -> dict[str, RpcRoute]:
    try:
        document = json.loads(_read_file(path, 64 * 1024, private=False))
        if set(document) != {"schema", "routes"} or document["schema"] != "umi-rpc-transport/1":
            raise ValueError
        records = document["routes"]
        if not isinstance(records, list) or not 1 <= len(records) <= 16:
            raise ValueError
        routes = {}
        for record in records:
            if set(record) != {"source", "endpoint", "authorization_file"}:
                raise ValueError
            source, endpoint = _endpoint(record["source"]), _endpoint(record["endpoint"])
            name = record["authorization_file"]
            if name is not None and (
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) is None
            ):
                raise ValueError
            if source in routes:
                raise ValueError
            routes[source] = RpcRoute(endpoint, None if name is None else path.parent / name)
        return routes
    except (ValueError, TypeError, KeyError):
        raise ValueError("rpc_transport_configuration_invalid") from None


class _PrivateConnect(connect):
    def process_redirect(self, exc: Exception) -> Exception | str:
        # Never forward a bearer header to a redirect destination. Retain only
        # the status and bounded numeric cooldown, not headers or provider text.
        if isinstance(exc, InvalidStatus):
            headers = Headers()
            retry = exc.response.headers.get("Retry-After", "")
            if re.fullmatch(r"[0-9]{1,4}", retry):
                headers["Retry-After"] = retry
            return InvalidStatus(Response(exc.response.status_code, "RPC rejected", headers))
        return exc


def websocket_connect(endpoint: str, **kwargs: Any):
    path = transport_config_path()
    route = None if path is None else load_routes(path).get(endpoint)
    if route is None:
        return connect(endpoint, **kwargs)
    headers = {}
    if route.authorization_file is not None:
        try:
            token = _read_file(route.authorization_file, 4096, private=True).decode("ascii").strip()
            if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ValueError
        except (ValueError, UnicodeError):
            raise ValueError("rpc_transport_credential_unavailable") from None
        headers["Authorization"] = token
    if kwargs.get("additional_headers"):
        raise ValueError("rpc_transport_headers_already_supplied")
    _LOGGER.info(
        json.dumps(
            {
                "schema": "umi-rpc-transport-route/1",
                "source": endpoint,
                "endpoint": route.endpoint,
                "authenticated": bool(headers),
            },
            sort_keys=True,
        )
    )
    kwargs.update(additional_headers=headers, proxy=None, logger=_QUIET_LOGGER)
    return _PrivateConnect(route.endpoint, **kwargs)
