"""Bounded local ingestion for explicitly nonconforming component pilots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Self

from .audit import (
    MAX_COMPONENT_MANIFEST_BYTES,
    MAX_COMPONENT_TOTAL_OBJECT_BYTES,
    EvidenceStore,
    ObjectRef,
    _read_bounded_regular_file,
)
from .component import BUNDLE_SCHEMA, MAX_COMPONENT_REQUESTS, NOT_REACHED
from .component_pilot import validate_public_pilot_video_url
from .encoding import account_id32
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator import replay_bundle_detailed

PILOT_FEED_CONFIG_SCHEMA = "umi-observer-pilot-feed-config/1"
PILOT_EVIDENCE_CLASS = "component_test_no_weight"
MAX_PILOTS = 8
MAX_PILOT_CONFIG_BYTES = 64 * 1024
MAX_PILOT_FEED_BYTES = 128 * 1024 * 1024

_MANIFEST_FIELDS = {
    "activation_evidence",
    "ground_truth_envelope",
    "ground_truth_plaintext",
    "mechanism_id",
    "miner_hotkey",
    "miner_origin",
    "netuid",
    "not_reached",
    "outcomes",
    "protocol_conformance",
    "schema",
    "scoring",
    "scoring_environment",
    "terminal_code",
    "translation_weights_active",
}
_OUTCOME_FIELDS = {
    "authentication_record",
    "challenge_id",
    "failure_code",
    "received_at_unix_ns",
    "received_bytes_sha256",
    "request",
    "response_envelope",
    "response_plaintext",
    "response_signature",
}
_OBJECT_REF_FIELDS = {"media_type", "sha256", "size_bytes"}
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


class PilotFeedConfig(StrictProtocolModel):
    schema_: Literal[PILOT_FEED_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[PILOT_EVIDENCE_CLASS]
    translation_weights_active: Literal[False]
    protocol_conformance: Literal[False]
    activation_evidence: Literal[False]
    public_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    bundle_roots: Annotated[list[str], Field(min_length=1, max_length=MAX_PILOTS)]

    @model_validator(mode="after")
    def validate_paths_and_origin(self) -> Self:
        _normalized_https_origin(self.public_origin)
        parsed: list[Path] = []
        for raw in self.bundle_roots:
            path = Path(raw)
            if (
                not path.is_absolute()
                or os.path.normpath(raw) != str(path)
                or len(raw.encode("utf-8")) > 4_096
            ):
                raise ValueError("pilot bundle roots must be normalized absolute paths")
            parsed.append(path)
        if len(parsed) != len(set(parsed)):
            raise ValueError("pilot bundle roots must be unique")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedPilotObject:
    sha256: str
    media_type: str
    data: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.data)


@dataclass(frozen=True, slots=True)
class VerifiedPilotSolution:
    batch_id: str
    challenge_id: str
    validator_hotkey: str
    miner_hotkey: str
    video_sha256: str
    stratum: str
    metric: str
    response_plaintext_valid: bool
    response_status: str | None
    hypothesis: str | None
    response_error_code: str | None
    model_revision: str | None
    references: tuple[str, ...]
    failure_code: str | None
    score_numerator: int
    score_denominator: int
    score_trace: dict[str, Any] | None
    request_sha256: str
    authentication_record_sha256: str
    response_envelope_sha256: str | None
    response_signature_sha256: str | None
    response_plaintext_sha256: str | None
    ground_truth_envelope_sha256: str
    ground_truth_plaintext_sha256: str
    scoring_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedComponentPilot:
    pilot_id: str
    public_origin: str
    manifest_bytes: bytes
    objects: Mapping[str, VerifiedPilotObject]
    bundle_bytes: int
    validator_hotkey: str
    miner_hotkey: str
    missing_stages: tuple[str, ...]
    solutions: tuple[VerifiedPilotSolution, ...]

    @property
    def manifest_sha256(self) -> str:
        return self.pilot_id


@dataclass(frozen=True, slots=True)
class ObserverPilotFeed:
    pilots: tuple[VerifiedComponentPilot, ...]

    def get(self, pilot_id: str) -> VerifiedComponentPilot | None:
        return next((pilot for pilot in self.pilots if pilot.pilot_id == pilot_id), None)


def _normalized_https_origin(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("pilot public origin contains a control character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("pilot public origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or not parsed.hostname.isascii()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or value.endswith("/")
        or value != f"{parsed.scheme}://{parsed.netloc}"
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("pilot public origin must be one normalized HTTPS origin")
    return value


def _component_miner_origin(value: Any) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 8_192:
        raise ValueError("pilot miner origin is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("pilot miner origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("pilot miner origin is invalid") from error
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or value.endswith("/")
        or value != f"{parsed.scheme}://{parsed.netloc}"
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("pilot miner origin must be one normalized HTTP(S) origin")
    return value


def _require_safe_owned_path(
    path: Path,
    *,
    directory: bool,
    require_single_link: bool = False,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"pilot evidence path is unavailable: {path.name}") from error
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if path.is_symlink() or not expected(metadata.st_mode):
        raise ValueError(f"pilot evidence path has an unsafe type: {path.name}")
    if metadata.st_uid != os.geteuid():
        raise ValueError(f"pilot evidence path has a different owner: {path.name}")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"pilot evidence path is group/world writable: {path.name}")
    if require_single_link and metadata.st_nlink != 1:
        raise ValueError(f"pilot evidence file must have one hard link: {path.name}")


def _parse_config(path: Path) -> PilotFeedConfig:
    if not path.is_absolute():
        raise ValueError("pilot feed config path must be absolute")
    _require_safe_owned_path(path, directory=False, require_single_link=True)
    encoded = _read_bounded_regular_file(path, MAX_PILOT_CONFIG_BYTES)
    try:
        decoded = json.loads(encoded)
        config = PilotFeedConfig.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("pilot feed config is not valid JSON") from error
    if canonical_json_bytes(config) != encoded:
        raise ValueError("pilot feed config must be RFC 8785 canonical JSON")
    return config


def _strict_ref(value: Any) -> ObjectRef:
    if not isinstance(value, dict) or set(value) != _OBJECT_REF_FIELDS:
        raise ValueError("pilot bundle object reference has an invalid schema")
    if (
        not isinstance(value["sha256"], str)
        or _HEX32_RE.fullmatch(value["sha256"]) is None
        or value["media_type"] not in {"application/json", "application/octet-stream"}
        or isinstance(value["size_bytes"], bool)
        or not isinstance(value["size_bytes"], int)
        or value["size_bytes"] < 0
    ):
        raise ValueError("pilot bundle object reference has invalid values")
    reference = ObjectRef(
        sha256=value["sha256"],
        media_type=value["media_type"],
        size_bytes=value["size_bytes"],
    )
    if len(reference.media_type.encode("utf-8")) > 256:
        raise ValueError("pilot bundle object media type is too long")
    return reference


def _bundle_refs(manifest: dict[str, Any]) -> tuple[ObjectRef, ...]:
    if set(manifest) != _MANIFEST_FIELDS:
        raise ValueError("pilot bundle manifest has an invalid schema")
    outcomes = manifest.get("outcomes")
    if not isinstance(outcomes, list) or not 1 <= len(outcomes) <= MAX_COMPONENT_REQUESTS:
        raise ValueError("pilot bundle outcome count is invalid")
    refs = [
        _strict_ref(manifest["ground_truth_envelope"]),
        _strict_ref(manifest["ground_truth_plaintext"]),
        _strict_ref(manifest["scoring"]),
    ]
    for outcome in outcomes:
        if not isinstance(outcome, dict) or set(outcome) != _OUTCOME_FIELDS:
            raise ValueError("pilot bundle outcome has an invalid schema")
        refs.extend(
            (
                _strict_ref(outcome["request"]),
                _strict_ref(outcome["authentication_record"]),
            )
        )
        for field in ("response_envelope", "response_signature", "response_plaintext"):
            if outcome[field] is not None:
                refs.append(_strict_ref(outcome[field]))
    by_digest: dict[str, ObjectRef] = {}
    for reference in refs:
        previous = by_digest.setdefault(reference.sha256, reference)
        if previous != reference:
            raise ValueError("pilot bundle gives one digest inconsistent metadata")
    return tuple(by_digest[digest] for digest in sorted(by_digest))


def _load_pilot(root: Path, public_origin: str) -> VerifiedComponentPilot:
    _require_safe_owned_path(root, directory=True)
    _require_safe_owned_path(root / "objects", directory=True)
    _require_safe_owned_path(
        root / "manifest.json",
        directory=False,
        require_single_link=True,
    )
    store = EvidenceStore(root)
    manifest, manifest_bytes = store.load_manifest_with_bytes()
    if manifest.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("pilot bundle has the wrong schema")
    if manifest.get("terminal_code") != PILOT_EVIDENCE_CLASS:
        raise ValueError("pilot bundle has the wrong terminal code")
    if type(manifest.get("netuid")) is not int or manifest["netuid"] != 78:
        raise ValueError("pilot bundle netuid is invalid")
    if type(manifest.get("mechanism_id")) is not int or manifest["mechanism_id"] != 0:
        raise ValueError("pilot bundle mechanism ID is invalid")
    for field in ("translation_weights_active", "protocol_conformance", "activation_evidence"):
        if manifest.get(field) is not False:
            raise ValueError(f"pilot bundle safety field is invalid: {field}")
    if not isinstance(manifest.get("miner_hotkey"), str) or not manifest["miner_hotkey"]:
        raise ValueError("pilot bundle miner hotkey is invalid")
    _component_miner_origin(manifest.get("miner_origin"))
    if manifest.get("not_reached") != list(NOT_REACHED):
        raise ValueError("pilot bundle must declare every missing canonical stage")
    references = _bundle_refs(manifest)

    # Run the canonical verifier before any projection becomes visible.
    replay = replay_bundle_detailed(root)
    if replay.manifest != manifest:
        raise ValueError("pilot replay did not bind the loaded manifest")
    if account_id32(replay.validator_hotkey) == account_id32(replay.miner_hotkey):
        raise ValueError("pilot validator and miner hotkeys must be distinct")
    for outcome in replay.outcomes:
        validate_public_pilot_video_url(str(outcome.request.video.url))

    objects: dict[str, VerifiedPilotObject] = {}
    for reference in references:
        _require_safe_owned_path(
            root / "objects" / reference.sha256,
            directory=False,
            require_single_link=True,
        )
        data = store.read(reference)
        objects[reference.sha256] = VerifiedPilotObject(
            sha256=reference.sha256,
            media_type=reference.media_type,
            data=data,
        )
    total_bytes = len(manifest_bytes) + sum(item.size_bytes for item in objects.values())
    if total_bytes > MAX_COMPONENT_MANIFEST_BYTES + MAX_COMPONENT_TOTAL_OBJECT_BYTES:
        raise ValueError("pilot bundle exceeds its aggregate byte ceiling")

    truth_by_id = {item.challenge_id: item for item in replay.ground_truth.items}
    clips = replay.scoring.get("per_clip")
    if not isinstance(clips, list) or len(clips) != len(replay.outcomes):
        raise ValueError("pilot replay produced an invalid clip projection")
    score_by_id: dict[str, dict[str, Any]] = {}
    for clip in clips:
        if not isinstance(clip, dict) or set(clip) != {
            "challenge_id",
            "failure_code",
            "metric",
            "score",
            "stratum",
            "trace",
        }:
            raise ValueError("pilot replay clip has an invalid schema")
        challenge_id = clip.get("challenge_id")
        if not isinstance(challenge_id, str) or challenge_id in score_by_id:
            raise ValueError("pilot replay clip IDs are invalid")
        score_by_id[challenge_id] = clip

    ground_truth_envelope = _strict_ref(manifest["ground_truth_envelope"])
    ground_truth_plaintext = _strict_ref(manifest["ground_truth_plaintext"])
    scoring = _strict_ref(manifest["scoring"])
    solutions: list[VerifiedPilotSolution] = []
    for outcome in replay.outcomes:
        request = outcome.request
        item = truth_by_id[request.challenge_id]
        clip = score_by_id[request.challenge_id]
        score = clip.get("score")
        if (
            not isinstance(score, dict)
            or set(score) != {"denominator", "numerator"}
            or isinstance(score["numerator"], bool)
            or isinstance(score["denominator"], bool)
            or not isinstance(score["numerator"], int)
            or not isinstance(score["denominator"], int)
            or score["numerator"] < 0
            or score["denominator"] <= 0
            or score["numerator"] > score["denominator"]
        ):
            raise ValueError("pilot replay score is invalid")
        response = outcome.response
        solutions.append(
            VerifiedPilotSolution(
                batch_id=request.batch_id,
                challenge_id=request.challenge_id,
                validator_hotkey=replay.validator_hotkey,
                miner_hotkey=replay.miner_hotkey,
                video_sha256=request.video.sha256,
                stratum=request.task.stratum,
                metric=item.metric,
                response_plaintext_valid=response is not None,
                response_status=None if response is None else response.status,
                hypothesis=None if response is None else response.hypothesis,
                response_error_code=None if response is None else response.error_code,
                model_revision=None if response is None else response.model_revision,
                references=tuple(item.references),
                failure_code=outcome.failure_code or clip.get("failure_code"),
                score_numerator=score["numerator"],
                score_denominator=score["denominator"],
                score_trace=clip.get("trace"),
                request_sha256=_strict_ref(outcome.request_ref).sha256,
                authentication_record_sha256=_strict_ref(outcome.authentication_record_ref).sha256,
                response_envelope_sha256=(
                    None
                    if outcome.response_envelope_ref is None
                    else _strict_ref(outcome.response_envelope_ref).sha256
                ),
                response_signature_sha256=(
                    None
                    if outcome.response_signature_ref is None
                    else _strict_ref(outcome.response_signature_ref).sha256
                ),
                response_plaintext_sha256=(
                    None
                    if outcome.response_plaintext_ref is None
                    else _strict_ref(outcome.response_plaintext_ref).sha256
                ),
                ground_truth_envelope_sha256=ground_truth_envelope.sha256,
                ground_truth_plaintext_sha256=ground_truth_plaintext.sha256,
                scoring_sha256=scoring.sha256,
            )
        )
    pilot_id = hashlib.sha256(manifest_bytes).hexdigest()
    return VerifiedComponentPilot(
        pilot_id=pilot_id,
        public_origin=public_origin,
        manifest_bytes=manifest_bytes,
        objects=MappingProxyType(objects),
        bundle_bytes=total_bytes,
        validator_hotkey=replay.validator_hotkey,
        miner_hotkey=replay.miner_hotkey,
        missing_stages=NOT_REACHED,
        solutions=tuple(solutions),
    )


def build_observer_pilot_feed(config_path: str | Path) -> ObserverPilotFeed:
    """Load, fully replay, and freeze every configured component pilot."""

    config = _parse_config(Path(config_path))
    pilots = tuple(
        sorted(
            (_load_pilot(Path(root), config.public_origin) for root in config.bundle_roots),
            key=lambda pilot: pilot.pilot_id,
        )
    )
    if len({pilot.pilot_id for pilot in pilots}) != len(pilots):
        raise ValueError("pilot feed contains the same bundle more than once")
    if sum(pilot.bundle_bytes for pilot in pilots) > MAX_PILOT_FEED_BYTES:
        raise ValueError("pilot feed exceeds its aggregate byte ceiling")
    return ObserverPilotFeed(pilots=pilots)


__all__ = [
    "MAX_PILOTS",
    "PILOT_EVIDENCE_CLASS",
    "PILOT_FEED_CONFIG_SCHEMA",
    "ObserverPilotFeed",
    "VerifiedComponentPilot",
    "VerifiedPilotObject",
    "VerifiedPilotSolution",
    "build_observer_pilot_feed",
]
