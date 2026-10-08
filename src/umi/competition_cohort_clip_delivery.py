"""Renewable delivery of retained clip bytes through the existing clip Worker.

Capabilities are private journal records. Retrying an upload reuses its URL;
later requests can select a new delivery window without altering signed work.
"""

import asyncio
import hashlib
import re
import secrets
import time
from pathlib import Path
from typing import Annotated, Literal

import httpx
from pydantic import Field, field_validator

from .competition_client import validate_intake_origin
from .competition_execution import read_case_video
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .http_logging import install_http_log_redaction, video_fetch_logging
from .open_competition import digest
from .private_files import Directory
from .private_state_wait import run_private_state_operation
from .protocol import Hex32, StrictProtocolModel, Video, canonical_json_bytes


class ClipDeliveryConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-clip-delivery-config/1"] = Field(alias="schema")
    directory: Directory
    videos_directory: Directory
    origin: str
    upload_token_file: Directory
    timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400
    maximum_bytes: Annotated[int, Field(ge=1024**2, le=1024**3)] = 64 * 1024**2

    _origin = field_validator("origin")(validate_intake_origin)


class ClipDeliveryIntent(StrictProtocolModel):
    video: Video
    start: int
    end: int


class CohortClipDelivery:
    def __init__(
        self, config: ClipDeliveryConfig, client: httpx.AsyncClient, token: str, *, concurrency=4
    ):
        self.config = ClipDeliveryConfig.model_validate_json(canonical_json_bytes(config))
        if not re.fullmatch("[0-9a-f]{64}", token):
            raise ValueError("clip uploader requires its configured upload credential")
        self.client, self.token = client, token
        if type(concurrency) is not int or not 1 <= concurrency <= 32:
            raise ValueError("clip delivery concurrency is outside bounds")
        self.capacity = asyncio.Semaphore(concurrency)
        self.clip_locks = {}
        install_http_log_redaction()
        self.journal = RoundJournal(
            Path(config.directory),
            {"schema": "umi-cohort-clip-delivery/1", "origin": config.origin},
            maximum_rounds=65536,
            maximum_bytes=config.maximum_bytes,
        )

    def _select(self, sha256: Hex32, now: int) -> tuple[str, ClipDeliveryIntent, bytes]:
        if not re.fullmatch("[0-9a-f]{64}", sha256):
            raise ValueError("clip delivery requires an exact content digest")
        # One retained capability per clip/day, valid for at least another day.
        # The public Worker accepts at most seven days. Completed request
        # recovery does not call this port or modify an earlier capability.
        start = now // 86400 * 86400
        end = start + 2 * 86400
        if not 10**9 <= start < end < 10**10:
            raise ValueError("clip delivery clock is outside the transport range")
        body = read_case_video(Path(self.config.videos_directory), sha256, 16 * 1024**2)
        if body[4:8] != b"ftyp":
            raise ValueError("selected clip is not an MP4")
        slot = digest(["umi-cohort-clip-delivery/1", sha256, start])
        with self.journal.locked():
            raw = self.journal.get("intent", slot)
            if raw is None:
                cap = secrets.token_hex(32)
                value = ClipDeliveryIntent(
                    video=Video(
                        url=f"{self.config.origin}/v1/clips/{start}/{end}/{cap}/{sha256}.mp4",
                        sha256=sha256,
                        size_bytes=len(body),
                        media_type="video/mp4",
                    ),
                    start=start,
                    end=end,
                )
                self.journal.put("intent", slot, value)
            else:
                value = ClipDeliveryIntent.model_validate_json(canonical_json_bytes(raw))
            if (
                value.start != start
                or value.end != end
                or value.video.sha256 != sha256
                or value.video.size_bytes != len(body)
                or not re.fullmatch(
                    re.escape(self.config.origin)
                    + f"/v1/clips/{start}/{end}/[0-9a-f]{{64}}/{sha256}[.]mp4",
                    value.video.url,
                )
            ):
                raise ValueError("clip delivery differs from original retained bytes")
        return slot, value, body

    async def _verify(self, video: Video) -> None:
        async with self.client.stream(
            "GET",
            video.url,
            headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"},
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
        ) as response:
            if (
                response.status_code != 200
                or response.headers.get("content-length") != str(video.size_bytes)
                or response.headers.get("content-type") != "video/mp4"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise OSError("selected clip delivery is unavailable")
            size, hashed = 0, hashlib.sha256()
            async for part in response.aiter_bytes():
                size += len(part)
                if size > video.size_bytes:
                    raise ValueError("selected clip delivery exceeds retained size")
                hashed.update(part)
            if size != video.size_bytes or hashed.hexdigest() != video.sha256:
                raise ValueError("selected clip delivery differs from retained digest")

    async def _publish(self, sha256: Hex32, now: int) -> Video:
        slot, value, body = await run_private_state_operation(
            self._select, sha256, now, timeout=self.config.timeout_seconds
        )
        # Even retained delivery is checked before a new signed request. If an
        # object was lost, republish the exact retained URL and bytes.
        try:
            await self._verify(value.video)
        except OSError:
            async with self.client.stream(
                "PUT",
                value.video.url,
                content=body,
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "video/mp4"},
                timeout=self.config.timeout_seconds,
                follow_redirects=False,
            ) as response:
                if response.status_code not in (200, 201):
                    raise OSError("selected clip upload is unavailable") from None
            await self._verify(value.video)
        if not value.start <= int(time.time()) < value.end - 3600:
            raise OSError("clip delivery window elapsed during publication")
        await run_owned_thread(self.journal.put, "complete", slot, {"intent": digest(value)})
        return value.video

    async def __call__(self, sha256: Hex32) -> Video:
        if not isinstance(sha256, str) or not re.fullmatch("[0-9a-f]{64}", sha256):
            raise ValueError("clip delivery requires an exact content digest")
        lock, users = self.clip_locks.get(sha256, (asyncio.Lock(), 0))
        self.clip_locks[sha256] = (lock, users + 1)
        try:
            # Duplicate clips keep one publication owner. Unrelated clips share
            # bounded capacity without waiting for a stalled peer's transfer.
            async with lock, self.capacity:
                with video_fetch_logging():
                    try:
                        return await wait_for_owned(
                            self._publish(sha256, int(time.time())),
                            timeout=self.config.timeout_seconds,
                        )
                    except httpx.RequestError as error:
                        # Retry the original intent; a transport failure does not
                        # establish missing bytes or authorize a new capability.
                        raise OSError("selected clip transport is unavailable") from error
        finally:
            retained_lock, users = self.clip_locks[sha256]
            assert retained_lock is lock
            if users == 1:
                del self.clip_locks[sha256]
            else:
                self.clip_locks[sha256] = (lock, users - 1)
