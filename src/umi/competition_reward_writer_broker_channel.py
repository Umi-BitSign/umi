"""Bounded private broker messages authenticated with per-packet Linux credentials."""

from __future__ import annotations

import array
import asyncio
import json
import os
import socket
import struct
from dataclasses import dataclass, field

from .open_competition import digest

_ISSUER = object()
_MAX = 16384


@dataclass(frozen=True, slots=True)
class WriterBrokerMessage:
    action: str
    payload: dict
    _channel: object = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)
    descriptors: tuple[int, ...] = field(default=(), repr=False)

    def seal(self):
        return digest(
            [
                self.action,
                self.payload,
                self._channel.pid,
                self._channel.identity,
                self._channel.peer_pid,
                self._channel.peer_uid,
                id(self._channel),
                self.descriptors,
            ]
        )

    def validate(self, action):
        if (
            type(self) is not WriterBrokerMessage
            or self._issuer is not _ISSUER
            or self.action != action
            or self._binding != self.seal()
        ):
            raise ValueError("writer broker message is not authentic for this transition")
        self._channel.recheck()
        if self._channel.peer_uid != 0:
            raise ValueError("writer selection message must come from the root broker")


class WriterBrokerChannel:
    def __init__(self, endpoint, *, peer_pid, peer_uid):
        if endpoint.family != socket.AF_UNIX or endpoint.type != socket.SOCK_SEQPACKET:
            raise ValueError("writer broker requires a private packet socket")
        self.endpoint = endpoint
        self.peer_pid, self.peer_uid = peer_pid, peer_uid
        self.pid = os.getpid()
        info = os.fstat(endpoint.fileno())
        self.identity = info.st_dev, info.st_ino
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        endpoint.setblocking(False)

    def recheck(self):
        info = os.fstat(self.endpoint.fileno())
        if self.pid != os.getpid() or self.identity != (info.st_dev, info.st_ino):
            raise ValueError("writer broker socket process or identity changed")

    async def send(self, action, *, descriptors=(), **payload):
        self.recheck()
        raw = json.dumps({"action": action, "payload": payload}, separators=(",", ":")).encode()
        if len(raw) > _MAX:
            raise ValueError("writer broker packet exceeds metadata limit")
        if len(descriptors) > 8:
            raise ValueError("writer broker descriptor limit exceeded")
        ancillary = (
            []
            if not descriptors
            else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))]
        )
        loop = asyncio.get_running_loop()
        while True:
            try:
                if self.endpoint.sendmsg([raw], ancillary) != len(raw):
                    raise ValueError("writer broker packet was partially sent")
                return
            except BlockingIOError:
                ready = loop.create_future()
                loop.add_writer(
                    self.endpoint.fileno(),
                    lambda ready=ready: None if ready.done() else ready.set_result(None),
                )
                try:
                    await ready
                finally:
                    loop.remove_writer(self.endpoint.fileno())

    async def receive(self, action=None):
        loop = asyncio.get_running_loop()
        while True:
            self.recheck()
            try:
                raw, ancillary, flags, _ = self.endpoint.recvmsg(
                    _MAX + 1,
                    socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8 * array.array("i").itemsize),
                )
                break
            except BlockingIOError:
                ready = loop.create_future()
                loop.add_reader(
                    self.endpoint.fileno(),
                    lambda ready=ready: None if ready.done() else ready.set_result(None),
                )
                try:
                    await ready
                finally:
                    loop.remove_reader(self.endpoint.fileno())
        descriptors = []
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = array.array("i")
                received.frombytes(value)
                descriptors.extend(received)
        try:
            for descriptor in descriptors:
                os.set_inheritable(descriptor, False)
            return self._message(raw, ancillary, flags, action, descriptors)
        except BaseException:
            for descriptor in descriptors:
                os.close(descriptor)
            raise

    def _message(self, raw, ancillary, flags, action, descriptors):
        if not raw:
            raise ConnectionError("writer broker peer exited")
        credentials = [
            struct.unpack("3i", value)
            for level, kind, value in ancillary
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
        ]
        if (
            flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(raw) > _MAX
            or len(credentials) != 1
        ):
            raise ValueError("writer broker packet or credentials truncated")
        pid, uid, _ = credentials[0]
        if (pid, uid) != (self.peer_pid, self.peer_uid):
            raise ValueError("writer broker packet sender changed")
        data = json.loads(raw)
        if (
            set(data) != {"action", "payload"}
            or type(data["action"]) is not str
            or type(data["payload"]) is not dict
        ):
            raise ValueError("writer broker packet shape differs")
        if action is not None and data["action"] != action:
            raise ValueError("writer broker protocol order differs")
        message = WriterBrokerMessage(
            data["action"], data["payload"], self, _ISSUER, descriptors=tuple(descriptors)
        )
        object.__setattr__(message, "_binding", message.seal())
        return message
