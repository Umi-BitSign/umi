"""Explicit host-local transport for an unchanged signed HTTPS origin."""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field, model_validator

from . import competition_host_artifacts as host_artifacts
from .protocol import StrictProtocolModel, canonical_json_bytes
from .validator_supervisor_adapters import (
    PinnedHTTPSClient,
    ValidatorSupervisorAdapterError,
    _canonical_https_url,
    _HTTPSession,
)


class SuccessorCohostDeliveryConfig(StrictProtocolModel):
    schema_: Literal["umi-successor-cohost-delivery/1"] = Field(alias="schema")
    origin: Annotated[str, Field(min_length=9, max_length=2048)]
    loopback_port: Annotated[int, Field(ge=1024, le=65535)]
    timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 300

    @model_validator(mode="after")
    def exact_origin(self):
        try:
            _canonical_https_url(self.origin + "/cohost-origin-pin")
        except ValidatorSupervisorAdapterError as error:
            raise ValueError("cohost delivery requires an exact HTTPS origin") from error
        parsed = urlsplit(self.origin)
        if self.origin != "https://" + parsed.netloc or parsed.path:
            raise ValueError("cohost delivery requires an exact HTTPS origin")
        return self


class CohostSuccessorClient(PinnedHTTPSClient):
    """Use the root-bound local service only for its explicitly selected origin.

    URL identities, object bounds, hashes and signatures remain unchanged.
    Other origins retain the normal public-address HTTPS restrictions.
    """

    def __init__(self, config: SuccessorCohostDeliveryConfig):
        self.cohost = SuccessorCohostDeliveryConfig.model_validate_json(
            config.model_dump_json(by_alias=True)
        )
        super().__init__(timeout_seconds=self.cohost.timeout_seconds)

    @asynccontextmanager
    async def _session(self, parsed):
        if "https://" + parsed.netloc != self.cohost.origin:
            async with super()._session(parsed) as session:
                yield session
            return
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds), follow_redirects=False, trust_env=False
        ) as client:
            yield _HTTPSession(
                client,
                f"http://127.0.0.1:{self.cohost.loopback_port}",
                parsed.hostname,
                None,
            )


HOST_DELIVERY_PATH = "artifacts/successor-delivery.json"
_HOST_PARENT = Path("/opt/umi-validator-supervisor-hosts")


def successor_delivery_client(config, signed_host, *, expected_manifest_sha256):
    """Load only a transport file covered by the approved signed host artifact.

    Keeping this host-only file outside worker inputs preserves compatibility
    with an already selected worker and its original observer-config schema.
    """
    host_artifacts.verify_host_artifact_authority(
        signed_host, config=config, expected_manifest_sha256=expected_manifest_sha256
    )
    record = next(
        (item for item in signed_host.manifest.files if item.path == HOST_DELIVERY_PATH), None
    )
    if record is None:
        return PinnedHTTPSClient()
    if record.mode != 0o444 or not 0 < record.size_bytes <= 65536:
        raise ValueError("signed host delivery configuration exceeds its bounds")
    root = _HOST_PARENT / signed_host.manifest.umi_git_revision
    path = root / HOST_DELIVERY_PATH
    if path.resolve() != path:
        raise ValueError("signed host delivery path contains a symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        host_artifacts._immutable_owner(before, 0o444, directory=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size != record.size_bytes:
            raise ValueError("signed host delivery configuration is not sealed")
        payload = os.read(descriptor, 65537)

        def identity(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if (
            identity(os.fstat(descriptor)) != identity(before)
            or hashlib.sha256(payload).hexdigest() != record.sha256
        ):
            raise ValueError("signed host delivery configuration changed")
    finally:
        os.close(descriptor)
    cohost = SuccessorCohostDeliveryConfig.model_validate_json(payload)
    if canonical_json_bytes(cohost) != payload:
        raise ValueError("signed host delivery configuration is not canonical")
    parsed = urlsplit(_canonical_https_url(config.directive_url))
    if cohost.origin != "https://" + parsed.netloc:
        raise ValueError("cohost delivery differs from the installed directive origin")
    return CohostSuccessorClient(cohost)
