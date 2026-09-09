"""Bounded local publication for validator-supervisor directive pages.

The public observer is only a transport for these records.  Authority signatures
inside each directive remain the trust root, and every validator applies its own
installed consent policy before accepting one.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .crypto import verify_response_signature
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    MAX_JSON_SAFE_INTEGER,
    MAX_SUPERVISOR_AUTHORITIES,
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    SUPERVISOR_TRUST_POLICY_SCHEMA,
    SignedSupervisorDirective,
    SupervisorAuthority,
    SupervisorDirectivePage,
    SupervisorTrustPolicy,
    parse_canonical_supervisor_directive_page,
    supervisor_directive_digest,
)

OBSERVER_DIRECTIVE_FEED_CONFIG_SCHEMA = "umi-observer-validator-directive-feed-config/1"
MAX_OBSERVER_DIRECTIVE_FEED_CONFIG_BYTES = 256 * 1024
MAX_OBSERVER_DIRECTIVE_CHANNELS = 256
MAX_OBSERVER_DIRECTIVE_READINESS_PAGES = 256

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


class ObserverDirectiveFeedError(RuntimeError):
    """Stable rejection from the public directive transport."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ObserverDirectiveChannel(StrictProtocolModel):
    """Public verification inputs for one validator-specific sequence chain."""

    validator_account_id32: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    channel_id: Hex32
    signature_threshold: Annotated[int, Field(ge=1, le=MAX_SUPERVISOR_AUTHORITIES)]
    trusted_authorities: Annotated[
        list[SupervisorAuthority],
        Field(min_length=1, max_length=MAX_SUPERVISOR_AUTHORITIES),
    ]
    initial_directive_sha256: Hex32
    initial_page_sha256: Hex32
    readiness_head_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    readiness_head_directive_sha256: Hex32

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_channel(self) -> Self:
        if account_id32(self.validator_hotkey).hex() != self.validator_account_id32:
            raise ValueError("directive-feed validator identity does not match its account ID")
        if self.readiness_head_sequence == 1 and not hmac.compare_digest(
            self.readiness_head_directive_sha256,
            self.initial_directive_sha256,
        ):
            raise ValueError(
                "directive-feed sequence-1 readiness head is not the initial directive"
            )
        self.trust_policy()
        return self

    def trust_policy(self) -> SupervisorTrustPolicy:
        return SupervisorTrustPolicy(
            schema=SUPERVISOR_TRUST_POLICY_SCHEMA,
            channel_id=self.channel_id,
            signature_threshold=self.signature_threshold,
            authorities=self.trusted_authorities,
        )


class ObserverDirectiveFeedConfig(StrictProtocolModel):
    """Static public-only configuration for all served validator channels."""

    schema_: Literal[OBSERVER_DIRECTIVE_FEED_CONFIG_SCHEMA] = Field(alias="schema")
    route_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    channels: Annotated[
        list[ObserverDirectiveChannel],
        Field(min_length=1, max_length=MAX_OBSERVER_DIRECTIVE_CHANNELS),
    ]

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        root = Path(self.route_root)
        if not root.is_absolute() or self.route_root != os.path.normpath(self.route_root):
            raise ValueError("directive-feed route root must be absolute and normalized")
        accounts = [item.validator_account_id32 for item in self.channels]
        if accounts != sorted(accounts) or len(accounts) != len(set(accounts)):
            raise ValueError("directive-feed channels must be unique and account-ID sorted")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedDirectivePage:
    """Exact canonical bytes and public identities for one verified route."""

    data: bytes
    sha256: str
    head_directive_sha256: str
    head_sequence: int


@dataclass(frozen=True, slots=True)
class ObserverDirectiveFeed:
    """Serve validated local pages from a fixed, read-only directory tree."""

    config_path: Path
    config_sha256: str
    route_root: Path
    channels: Mapping[str, ObserverDirectiveChannel]
    additional_trusted_owner_uid: int | None = None

    def verify_readiness(self) -> None:
        """Reject config drift and require every pinned head to remain reachable."""

        try:
            config_payload = _read_absolute_regular_file(
                self.config_path,
                maximum_bytes=MAX_OBSERVER_DIRECTIVE_FEED_CONFIG_BYTES,
                additional_trusted_owner_uid=self.additional_trusted_owner_uid,
            )
        except ObserverDirectiveFeedError:
            raise
        except OSError as error:
            raise ObserverDirectiveFeedError("directive_feed_config_unavailable") from error
        if not hmac.compare_digest(
            hashlib.sha256(config_payload).hexdigest(),
            self.config_sha256,
        ):
            raise ObserverDirectiveFeedError("directive_feed_config_changed")

        self.verify_initial_pages()
        for channel in self.channels.values():
            self._verify_reachable_head(channel)

    def verify_initial_pages(self) -> None:
        """Reread every pinned sequence-1 hold and reject any runtime drift."""

        for channel in self.channels.values():
            page = self.read_page(
                channel.validator_account_id32,
                after_sequence=0,
                cursor="initial",
            )
            if page is None:
                raise ObserverDirectiveFeedError("directive_feed_initial_page_missing")
            parsed = parse_canonical_supervisor_directive_page(page.data)
            if (
                len(parsed.directives) != 1
                or parsed.more
                or parsed.head.directive.sequence != 1
                or parsed.head.directive.mode != "hold"
                or parsed.head.directive.previous_directive_sha256 is not None
            ):
                raise ObserverDirectiveFeedError("directive_feed_initial_hold_invalid")

    def _verify_reachable_head(self, channel: ObserverDirectiveChannel) -> None:
        """Walk canonical cursor pages from sequence 1 to a terminal signed head."""

        cursor_sequence = 1
        cursor_digest = channel.initial_directive_sha256
        expected = (
            channel.readiness_head_sequence,
            channel.readiness_head_directive_sha256,
        )
        expected_reached = expected == (cursor_sequence, cursor_digest)
        for _ in range(MAX_OBSERVER_DIRECTIVE_READINESS_PAGES):
            verified = self.read_page(
                channel.validator_account_id32,
                after_sequence=cursor_sequence,
                cursor=cursor_digest,
            )
            if verified is None:
                raise ObserverDirectiveFeedError("directive_feed_readiness_page_missing")
            page = parse_canonical_supervisor_directive_page(verified.data)
            for signed in page.directives:
                identity = (signed.directive.sequence, signed.directive_sha256)
                if identity == expected:
                    expected_reached = True
            if not page.more:
                if not expected_reached:
                    raise ObserverDirectiveFeedError("directive_feed_readiness_head_unreachable")
                return
            cursor_sequence = page.head.directive.sequence
            cursor_digest = page.head.directive_sha256
        raise ObserverDirectiveFeedError("directive_feed_readiness_page_limit")

    def read_page(
        self,
        validator_account_id32: str,
        *,
        after_sequence: int,
        cursor: str,
    ) -> VerifiedDirectivePage | None:
        if _HEX32_RE.fullmatch(validator_account_id32) is None:
            raise ObserverDirectiveFeedError("directive_feed_validator_invalid")
        channel = self.channels.get(validator_account_id32)
        if channel is None:
            return None
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or not 0 <= after_sequence <= MAX_JSON_SAFE_INTEGER
            or (after_sequence == 0) != (cursor == "initial")
            or (cursor != "initial" and _HEX32_RE.fullmatch(cursor) is None)
        ):
            raise ObserverDirectiveFeedError("directive_feed_cursor_invalid")
        relative_parts = (
            validator_account_id32,
            "after",
            str(after_sequence),
            f"{cursor}.json",
        )
        try:
            payload = _read_route_file(
                self.route_root,
                relative_parts,
                additional_trusted_owner_uid=self.additional_trusted_owner_uid,
            )
        except FileNotFoundError:
            return None
        except ObserverDirectiveFeedError:
            raise
        except OSError as error:
            raise ObserverDirectiveFeedError("directive_feed_route_unavailable") from error
        try:
            page = parse_canonical_supervisor_directive_page(payload)
            _verify_page(page, channel=channel)
        except ObserverDirectiveFeedError:
            raise
        except Exception as error:
            raise ObserverDirectiveFeedError("directive_feed_page_invalid") from error
        expected_cursor = None if cursor == "initial" else cursor
        if page.after_sequence != after_sequence or page.after_directive_sha256 != expected_cursor:
            raise ObserverDirectiveFeedError("directive_feed_route_binding_mismatch")
        verified = VerifiedDirectivePage(
            data=payload,
            sha256=hashlib.sha256(payload).hexdigest(),
            head_directive_sha256=page.head.directive_sha256,
            head_sequence=page.head.directive.sequence,
        )
        if after_sequence == 0 and (
            verified.sha256 != channel.initial_page_sha256
            or verified.head_directive_sha256 != channel.initial_directive_sha256
        ):
            raise ObserverDirectiveFeedError("directive_feed_initial_hash_mismatch")
        return verified


def build_observer_directive_feed(
    path: str | Path,
    *,
    additional_trusted_owner_uid: int | None = None,
) -> ObserverDirectiveFeed:
    """Load a root-owned config and require every sequence-1 hold route.

    Production callers omit ``additional_trusted_owner_uid`` so the observer
    process cannot own or mutate any file in its directive trust boundary.  The
    override exists for isolated tests whose temporary trees cannot be root-owned.
    """

    if isinstance(additional_trusted_owner_uid, bool) or (
        additional_trusted_owner_uid is not None
        and (not isinstance(additional_trusted_owner_uid, int) or additional_trusted_owner_uid < 0)
    ):
        raise ObserverDirectiveFeedError("directive_feed_owner_policy_invalid")

    config_path = Path(path)
    if not config_path.is_absolute() or config_path != Path(os.path.normpath(config_path)):
        raise ObserverDirectiveFeedError("directive_feed_config_path_invalid")
    try:
        payload = _read_absolute_regular_file(
            config_path,
            maximum_bytes=MAX_OBSERVER_DIRECTIVE_FEED_CONFIG_BYTES,
            additional_trusted_owner_uid=additional_trusted_owner_uid,
        )
        config = ObserverDirectiveFeedConfig.model_validate_json(payload)
    except ObserverDirectiveFeedError:
        raise
    except Exception as error:
        raise ObserverDirectiveFeedError("directive_feed_config_invalid") from error
    if canonical_json_bytes(config) != payload:
        raise ObserverDirectiveFeedError("directive_feed_config_noncanonical")
    route_root = Path(config.route_root)
    _require_safe_directory(
        route_root,
        additional_trusted_owner_uid=additional_trusted_owner_uid,
    )
    feed = ObserverDirectiveFeed(
        config_path=config_path,
        config_sha256=hashlib.sha256(payload).hexdigest(),
        route_root=route_root,
        channels=MappingProxyType({item.validator_account_id32: item for item in config.channels}),
        additional_trusted_owner_uid=additional_trusted_owner_uid,
    )
    feed.verify_readiness()
    return feed


def _verify_page(
    page: SupervisorDirectivePage,
    *,
    channel: ObserverDirectiveChannel,
) -> None:
    seen: set[str] = set()
    for signed in (*page.directives, page.head):
        if signed.directive_sha256 in seen:
            continue
        seen.add(signed.directive_sha256)
        _verify_signed_directive(signed, channel=channel)


def _verify_signed_directive(
    signed: SignedSupervisorDirective,
    *,
    channel: ObserverDirectiveChannel,
) -> None:
    directive = signed.directive
    validator_account = account_id32(channel.validator_hotkey)
    if directive.channel_id != channel.channel_id:
        raise ObserverDirectiveFeedError("directive_feed_channel_mismatch")
    if [account_id32(item) for item in directive.validator_hotkeys] != [validator_account]:
        raise ObserverDirectiveFeedError("directive_feed_validator_mismatch")
    authorities = {account_id32(item.hotkey): item for item in channel.trusted_authorities}
    digest = supervisor_directive_digest(directive)
    verified = 0
    for signature in signed.signatures:
        authority = authorities.get(account_id32(signature.hotkey))
        if authority is None:
            raise ObserverDirectiveFeedError("directive_feed_signer_untrusted")
        if signature.signature_scheme != authority.signature_scheme:
            raise ObserverDirectiveFeedError("directive_feed_signature_scheme_mismatch")
        if not verify_response_signature(
            digest,
            hotkey_ss58=signature.hotkey,
            scheme=signature.signature_scheme,
            signature=signature.signature,
        ):
            raise ObserverDirectiveFeedError("directive_feed_signature_invalid")
        verified += 1
    if verified < channel.signature_threshold:
        raise ObserverDirectiveFeedError("directive_feed_signature_threshold_not_met")


def _read_absolute_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    additional_trusted_owner_uid: int | None,
) -> bytes:
    parent_descriptor = _open_absolute_directory(
        path.parent,
        additional_trusted_owner_uid=additional_trusted_owner_uid,
    )
    try:
        return _read_regular_at(
            parent_descriptor,
            path.name,
            maximum_bytes=maximum_bytes,
            additional_trusted_owner_uid=additional_trusted_owner_uid,
        )
    finally:
        os.close(parent_descriptor)


def _read_route_file(
    root: Path,
    parts: tuple[str, ...],
    *,
    additional_trusted_owner_uid: int | None,
) -> bytes:
    descriptor = _open_absolute_directory(
        root,
        additional_trusted_owner_uid=additional_trusted_owner_uid,
    )
    try:
        for component in parts[:-1]:
            next_descriptor = _open_directory_at(
                descriptor,
                component,
                additional_trusted_owner_uid=additional_trusted_owner_uid,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return _read_regular_at(
            descriptor,
            parts[-1],
            maximum_bytes=MAX_SUPERVISOR_DOCUMENT_BYTES,
            additional_trusted_owner_uid=additional_trusted_owner_uid,
        )
    finally:
        os.close(descriptor)


def _open_absolute_directory(
    path: Path,
    *,
    additional_trusted_owner_uid: int | None,
) -> int:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ObserverDirectiveFeedError("directive_feed_path_invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = _open_directory_at(
                descriptor,
                component,
                additional_trusted_owner_uid=additional_trusted_owner_uid,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    additional_trusted_owner_uid: int | None,
) -> int:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ObserverDirectiveFeedError("directive_feed_path_invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        _require_safe_metadata(
            os.fstat(descriptor),
            directory=True,
            additional_trusted_owner_uid=additional_trusted_owner_uid,
        )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    maximum_bytes: int,
    additional_trusted_owner_uid: int | None,
) -> bytes:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ObserverDirectiveFeedError("directive_feed_path_invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        before = os.fstat(descriptor)
        _require_safe_metadata(
            before,
            directory=False,
            additional_trusted_owner_uid=additional_trusted_owner_uid,
        )
        if not 0 < before.st_size <= maximum_bytes:
            raise ObserverDirectiveFeedError("directive_feed_file_size_invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ObserverDirectiveFeedError("directive_feed_file_size_invalid")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise ObserverDirectiveFeedError("directive_feed_file_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_safe_directory(
    path: Path,
    *,
    additional_trusted_owner_uid: int | None,
) -> None:
    descriptor = _open_absolute_directory(
        path,
        additional_trusted_owner_uid=additional_trusted_owner_uid,
    )
    os.close(descriptor)


def _require_safe_metadata(
    metadata: os.stat_result,
    *,
    directory: bool,
    additional_trusted_owner_uid: int | None,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    trusted_owner_uids = {0}
    if additional_trusted_owner_uid is not None:
        trusted_owner_uids.add(additional_trusted_owner_uid)
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid not in trusted_owner_uids
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (not directory and metadata.st_nlink != 1)
    ):
        raise ObserverDirectiveFeedError("directive_feed_path_unsafe")


__all__ = [
    "MAX_OBSERVER_DIRECTIVE_CHANNELS",
    "MAX_OBSERVER_DIRECTIVE_FEED_CONFIG_BYTES",
    "MAX_OBSERVER_DIRECTIVE_READINESS_PAGES",
    "OBSERVER_DIRECTIVE_FEED_CONFIG_SCHEMA",
    "ObserverDirectiveChannel",
    "ObserverDirectiveFeed",
    "ObserverDirectiveFeedConfig",
    "ObserverDirectiveFeedError",
    "VerifiedDirectivePage",
    "build_observer_directive_feed",
]
