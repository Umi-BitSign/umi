"""Bounded, read-only GitHub client for public-pilot coordinator authorizations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .public_pilot_github_wire import readiness_confirmation_lines_match

GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
MAX_GITHUB_BODY_BYTES = 128 * 1024
MAX_GITHUB_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_GITHUB_TOKEN_BYTES = 1_024
MAX_GITHUB_BACKOFF_SECONDS = 3_600

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_MODEL_REVISION = re.compile(r"^[0-9a-f]{64}$")
_BEARER_TOKEN = re.compile(r"^[A-Za-z0-9._~+/\-]+=*$")


class GithubRateLimitError(RuntimeError):
    """A bounded signal telling the controller when GitHub may be queried again."""

    def __init__(self, retry_after_seconds: int, *, status_code: int) -> None:
        super().__init__("GitHub API rate limit requires backoff")
        self.retry_after_seconds = retry_after_seconds
        self.status_code = status_code


class GithubNotFoundError(ValueError):
    """A GitHub resource that cannot be recovered by retrying the same request."""

    def __init__(self) -> None:
        super().__init__("GitHub API resource was not found")
        self.status_code = 404


def _validated_github_token(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("GitHub read token is invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("GitHub read token is invalid") from error
    if len(encoded) > MAX_GITHUB_TOKEN_BYTES or _BEARER_TOKEN.fullmatch(value) is None:
        raise ValueError("GitHub read token is invalid")
    return value


def load_github_token(path: Path) -> str:
    """Load one bounded bearer token without placing it in config or environment."""

    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError("GitHub read-token credential path must be absolute")
    try:
        descriptor = os.open(
            expanded,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise ValueError("GitHub read-token credential file is unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size > MAX_GITHUB_TOKEN_BYTES + 2
        ):
            raise ValueError("GitHub read-token credential file is unsafe")
        raw = os.read(descriptor, MAX_GITHUB_TOKEN_BYTES + 3)
        if len(raw) != metadata.st_size:
            raise ValueError("GitHub read-token credential changed while it was read")
    finally:
        os.close(descriptor)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("GitHub read token is invalid") from error
    return _validated_github_token(token)


@dataclass(frozen=True, slots=True)
class GithubActor:
    id: int
    login: str
    type: str


@dataclass(frozen=True, slots=True)
class GithubIssue:
    id: int
    node_id: str
    number: int
    state: str
    title: str
    body: str
    user: GithubActor
    labels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GithubComment:
    id: int
    node_id: str
    body: str
    created_at: str
    updated_at: str
    user: GithubActor


@dataclass(frozen=True, slots=True)
class PublicPilotEnrollment:
    uid: int
    miner_hotkey: str
    model_revision: str


def github_body_sha256(body: str) -> str:
    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_GITHUB_BODY_BYTES:
        raise ValueError("GitHub body exceeds the public-pilot byte ceiling")
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def parse_public_pilot_enrollment(body: str) -> PublicPilotEnrollment:
    """Extract the immutable enrollment fields from the issue-form body."""

    github_body_sha256(body)
    sections: dict[str, str] = {}
    current: str | None = None
    values: list[str] = []
    for line in body.splitlines():
        if line.startswith("### "):
            if current is not None:
                if current in sections:
                    raise ValueError("public-pilot enrollment repeats a heading")
                sections[current] = "\n".join(values).strip()
            current = line[4:].strip()
            values = []
        elif current is not None:
            values.append(line)
    if current is not None:
        if current in sections:
            raise ValueError("public-pilot enrollment repeats a heading")
        sections[current] = "\n".join(values).strip()

    try:
        uid_text = sections["SN78 UID"]
        miner_hotkey = sections["Miner hotkey"]
        model_revision = sections["Model revision"]
        confirmations = sections["Readiness confirmations"]
    except KeyError as error:
        raise ValueError("public-pilot enrollment omits a required heading") from error
    if not uid_text.isdecimal() or uid_text != str(int(uid_text)):
        raise ValueError("public-pilot enrollment UID is not canonical")
    uid = int(uid_text)
    if not 0 <= uid <= 65_535:
        raise ValueError("public-pilot enrollment UID is out of range")
    from .encoding import account_id32

    try:
        account_id32(miner_hotkey)
    except ValueError as error:
        raise ValueError("public-pilot enrollment hotkey is invalid") from error
    if _MODEL_REVISION.fullmatch(model_revision) is None:
        raise ValueError("public-pilot enrollment model revision is invalid")
    checklist = tuple(confirmations.splitlines())
    if not readiness_confirmation_lines_match(checklist):
        raise ValueError("public-pilot enrollment confirmations are incomplete")
    return PublicPilotEnrollment(
        uid=uid,
        miner_hotkey=miner_hotkey,
        model_revision=model_revision,
    )


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"GitHub {label} is invalid")
    return value


def _bounded_text(value: Any, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"GitHub {label} is invalid")
    return value


def _actor(value: Any) -> GithubActor:
    if not isinstance(value, dict):
        raise ValueError("GitHub actor is invalid")
    return GithubActor(
        id=_positive_integer(value.get("id"), "actor ID"),
        login=_bounded_text(value.get("login"), "actor login", 128),
        type=_bounded_text(value.get("type"), "actor type", 32),
    )


def _timestamp(value: Any, label: str) -> str:
    text = _bounded_text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"GitHub {label} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"GitHub {label} is not UTC")
    return text


def _comment(value: Any) -> GithubComment:
    if not isinstance(value, dict):
        raise ValueError("GitHub comment is invalid")
    return GithubComment(
        id=_positive_integer(value.get("id"), "comment ID"),
        node_id=_bounded_text(value.get("node_id"), "comment node ID", 256),
        body=_bounded_text(value.get("body"), "comment body", MAX_GITHUB_BODY_BYTES),
        created_at=_timestamp(value.get("created_at"), "comment creation time"),
        updated_at=_timestamp(value.get("updated_at"), "comment update time"),
        user=_actor(value.get("user")),
    )


def _issue(value: Any) -> GithubIssue:
    if not isinstance(value, dict):
        raise ValueError("GitHub issue is invalid")
    labels_raw = value.get("labels")
    if not isinstance(labels_raw, list) or len(labels_raw) > 100:
        raise ValueError("GitHub issue labels are invalid")
    labels: list[str] = []
    for label in labels_raw:
        if not isinstance(label, dict):
            raise ValueError("GitHub issue label is invalid")
        labels.append(_bounded_text(label.get("name"), "issue label", 128))
    return GithubIssue(
        id=_positive_integer(value.get("id"), "issue ID"),
        node_id=_bounded_text(value.get("node_id"), "issue node ID", 256),
        number=_positive_integer(value.get("number"), "issue number"),
        state=_bounded_text(value.get("state"), "issue state", 16),
        title=_bounded_text(value.get("title"), "issue title", 512),
        body=_bounded_text(value.get("body"), "issue body", MAX_GITHUB_BODY_BYTES),
        user=_actor(value.get("user")),
        labels=tuple(labels),
    )


class PublicPilotGithubClient:
    """Read exact public issue state, optionally with a least-privilege token."""

    def __init__(
        self,
        repository: str,
        *,
        client: httpx.Client | None = None,
        user_agent_revision: str,
        token: str | None = None,
    ) -> None:
        if _REPOSITORY.fullmatch(repository) is None:
            raise ValueError("GitHub repository name is invalid")
        if _HEX40.fullmatch(user_agent_revision) is None:
            raise ValueError("GitHub client revision is invalid")
        read_token = None if token is None else _validated_github_token(token)
        self.repository = repository
        self._rate_limit_failures = 0
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
        )
        self._headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": f"umi-public-pilot-coordinator/{user_agent_revision}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if read_token is not None:
            self._headers["Authorization"] = f"Bearer {read_token}"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> PublicPilotGithubClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _decimal_header(response: httpx.Response, name: str) -> int | None:
        value = response.headers.get(name)
        if value is None or len(value) > 20 or not value.isdecimal():
            return None
        parsed = int(value)
        return parsed if parsed >= 0 else None

    @staticmethod
    def _body_reports_rate_limit(body: bytes) -> bool:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        message = payload.get("message") if isinstance(payload, dict) else None
        return isinstance(message, str) and "rate limit" in message.lower()

    def _rate_limit_delay(self, response: httpx.Response) -> int:
        self._rate_limit_failures += 1
        retry_after = self._decimal_header(response, "Retry-After")
        reset = self._decimal_header(response, "X-RateLimit-Reset")
        if retry_after is not None:
            delay = retry_after
        elif response.headers.get("X-RateLimit-Remaining") == "0" and reset is not None:
            delay = reset - int(time.time()) + 1
        else:
            exponent = min(self._rate_limit_failures - 1, 6)
            delay = 60 * (2**exponent)
        return min(max(1, delay), MAX_GITHUB_BACKOFF_SECONDS)

    def _get_json(self, path: str, *, params: dict[str, str] | None = None) -> Any:
        with self._client.stream(
            "GET",
            f"{GITHUB_API_ORIGIN}{path}",
            headers=self._headers,
            params=params,
        ) as response:
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_GITHUB_RESPONSE_BYTES:
                    raise RuntimeError("GitHub response exceeds the public-pilot byte ceiling")
                chunks.append(chunk)
            body = b"".join(chunks)
            rate_limited = response.status_code == 429 or (
                response.status_code == 403
                and (
                    response.headers.get("Retry-After") is not None
                    or response.headers.get("X-RateLimit-Remaining") == "0"
                    or self._body_reports_rate_limit(body)
                )
            )
            if rate_limited:
                raise GithubRateLimitError(
                    self._rate_limit_delay(response),
                    status_code=response.status_code,
                )
            self._rate_limit_failures = 0
            if response.status_code == 404:
                raise GithubNotFoundError()
            response.raise_for_status()
            if content_type != "application/json":
                raise RuntimeError("GitHub returned an unexpected content type")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("GitHub returned invalid JSON") from error

    def issue(self, number: int) -> GithubIssue:
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            raise ValueError("GitHub issue number is invalid")
        return _issue(self._get_json(f"/repos/{self.repository}/issues/{number}"))

    def comment(self, comment_id: int) -> GithubComment:
        if isinstance(comment_id, bool) or not isinstance(comment_id, int) or comment_id <= 0:
            raise ValueError("GitHub comment ID is invalid")
        return _comment(self._get_json(f"/repos/{self.repository}/issues/comments/{comment_id}"))

    def comments_page(self, since: str, *, page: int) -> tuple[GithubComment, ...]:
        """Read one durable-cursor page ordered from oldest to newest."""

        _timestamp(since, "since time")
        if isinstance(page, bool) or not isinstance(page, int) or page <= 0:
            raise ValueError("GitHub comment page is invalid")
        payload = self._get_json(
            f"/repos/{self.repository}/issues/comments",
            params={
                "sort": "created",
                "direction": "asc",
                "since": since,
                "per_page": "100",
                "page": str(page),
            },
        )
        if not isinstance(payload, list) or len(payload) > 100:
            raise RuntimeError("GitHub comment listing is invalid")
        comments = tuple(_comment(item) for item in payload)
        deduplicated = {comment.id: comment for comment in comments}
        return tuple(sorted(deduplicated.values(), key=lambda item: (item.created_at, item.id)))

    def comments_since(self, since: str) -> tuple[GithubComment, ...]:
        """Compatibility helper for one bounded comment page."""

        return self.comments_page(since, page=1)


__all__ = [
    "GITHUB_API_ORIGIN",
    "GithubActor",
    "GithubComment",
    "GithubIssue",
    "GithubNotFoundError",
    "GithubRateLimitError",
    "PublicPilotEnrollment",
    "PublicPilotGithubClient",
    "github_body_sha256",
    "load_github_token",
    "parse_public_pilot_enrollment",
]
