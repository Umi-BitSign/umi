"""Tool-free Claude mediator diagnostic over retained model hypotheses.

This module has no cohort, wallet, validator, scoring, or chain-write capability.
Callers supply an already durable hypothesis and retain the returned provider
wrapper before using the structured diagnostic. Miner text is always stdin data;
it never enters CLI arguments, settings, paths, environment, or the system prompt.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator

from .private_files import private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_MAXIMUM_TEXT_BYTES = 16 * 1024
_MAXIMUM_PROVIDER_BYTES = 1024 * 1024
_MAXIMUM_ERROR_BYTES = 64 * 1024


class _ProviderModelChanged(ValueError):
    pass


class _ProviderOutputLimit(ValueError):
    pass


def _untrusted_text(value: str) -> str:
    if len(value.encode("utf-8")) > _MAXIMUM_TEXT_BYTES:
        raise ValueError("mediator text exceeds its UTF-8 byte bound")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ValueError("mediator text contains a disallowed control character")
    return value


def _optional_untrusted_text(value: str | None) -> str | None:
    return None if value is None else _untrusted_text(value)


class MediatorRequest(StrictProtocolModel):
    """Local source binding; only its two text fields cross the provider boundary."""

    schema_: Literal["umi-mediator-request/1"] = Field(alias="schema")
    source_evidence_sha256: Hex32
    source_output_sha256: Hex32
    approved_context_sha256: Hex32
    source_hypothesis: Annotated[str, Field(min_length=1, max_length=8192)]
    public_context: Annotated[str, Field(max_length=8192)] = ""

    _bounded_hypothesis = field_validator("source_hypothesis")(_untrusted_text)
    _bounded_context = field_validator("public_context")(_untrusted_text)


class MediatorProviderRequest(StrictProtocolModel):
    """The complete and exclusive external-provider request body."""

    schema_: Literal["umi-mediator-provider-request/1"] = Field(alias="schema")
    source_hypothesis: Annotated[str, Field(min_length=1, max_length=8192)]
    public_context: Annotated[str, Field(max_length=8192)] = ""

    _bounded_hypothesis = field_validator("source_hypothesis")(_untrusted_text)
    _bounded_context = field_validator("public_context")(_untrusted_text)


def provider_request(value: MediatorRequest) -> MediatorProviderRequest:
    return MediatorProviderRequest(
        schema="umi-mediator-provider-request/1",
        source_hypothesis=value.source_hypothesis,
        public_context=value.public_context,
    )


class MediatorOutput(StrictProtocolModel):
    schema_: Literal["umi-mediator-output/1"] = Field(alias="schema")
    source_evidence_spans: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=300)], ...],
        Field(min_length=1, max_length=8),
    ]
    entities: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=80)], ...], Field(max_length=16)
    ]
    events: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=180)], ...], Field(max_length=16)
    ]
    time_expressions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=80)], ...], Field(max_length=8)
    ]
    negated_claims: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=180)], ...], Field(max_length=8)
    ]
    intent: Literal["statement", "question", "request", "command", "unclear"]
    confidence: Literal["low", "medium", "high"]
    alternatives: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=180)], ...], Field(max_length=4)
    ]
    unsupported_claims: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=180)], ...], Field(max_length=8)
    ]
    semantic_summary: Annotated[str, Field(min_length=1, max_length=300)]
    explanation: Annotated[str, Field(min_length=1, max_length=500)]
    clarification_question: Annotated[str, Field(min_length=1, max_length=300)] | None
    untrusted_instruction_detected: bool
    followed_untrusted_instruction: Literal[False]

    @field_validator(
        "entities",
        "events",
        "time_expressions",
        "negated_claims",
        "alternatives",
        "unsupported_claims",
        "source_evidence_spans",
    )
    @classmethod
    def _bounded_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _untrusted_text(item)
        return value

    _bounded_summary = field_validator("semantic_summary", "explanation")(_untrusted_text)
    _bounded_question = field_validator("clarification_question")(_optional_untrusted_text)


def _validate_source_evidence(output: MediatorOutput, request: MediatorRequest) -> None:
    """Require ordered, non-overlapping verbatim grounding in the source hypothesis."""
    cursor = 0
    for span in output.source_evidence_spans:
        if span != span.strip():
            raise ValueError("mediator source evidence has surrounding whitespace")
        offset = request.source_hypothesis.find(span, cursor)
        if offset < 0:
            raise ValueError("mediator source evidence is not an ordered verbatim span")
        cursor = offset + len(span)


class MediatorInvocation(StrictProtocolModel):
    schema_: Literal["umi-mediator-invocation/1"] = Field(alias="schema")
    runner_sha256: Hex32
    cli_sha256: Hex32
    cli_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    model: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")]
    system_prompt_sha256: Hex32
    output_schema_sha256: Hex32
    maximum_cost_microusd: Annotated[int, Field(ge=1, le=1_000_000)]
    timeout_seconds: Annotated[int, Field(ge=1, le=600)]


class MediatorReceipt(StrictProtocolModel):
    schema_: Literal["umi-mediator-receipt/1"] = Field(alias="schema")
    request_sha256: Hex32
    invocation_sha256: Hex32
    provider_response_sha256: Hex32
    provider_model: str
    output: MediatorOutput
    output_sha256: Hex32
    reported_turns: Annotated[int, Field(ge=1, le=32)]
    input_tokens: Annotated[int, Field(ge=0, le=10_000_000)]
    output_tokens: Annotated[int, Field(ge=0, le=10_000_000)]
    duration_ms: Annotated[int, Field(ge=0, le=3_600_000)]
    duration_api_ms: Annotated[int, Field(ge=0, le=3_600_000)]
    total_cost_usd: Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")]
    chain_writes_authorized: Literal[False] = False
    scoring_authorized: Literal[False] = False


class MediatorUnavailable(StrictProtocolModel):
    schema_: Literal["umi-mediator-unavailable/1"] = Field(alias="schema")
    request_sha256: Hex32
    invocation_sha256: Hex32
    reason: Literal[
        "runner_changed",
        "cli_changed",
        "ambient_instructions_present",
        "cli_failed",
        "provider_timeout",
        "provider_response_invalid",
        "provider_model_changed",
        "prior_outcome_unknown",
    ]
    stdout_sha256: Hex32 | None = None
    stderr_sha256: Hex32 | None = None
    chain_writes_authorized: Literal[False] = False
    scoring_authorized: Literal[False] = False


def output_json_schema() -> dict:
    """Return the closed provider schema corresponding to ``MediatorOutput``."""
    schema = MediatorOutput.model_json_schema(by_alias=True)
    # The provider receives one self-contained object, without local model metadata.
    schema.pop("title", None)
    return schema


def invocation(
    *,
    runner_sha256: str,
    cli_sha256: str,
    cli_version: str,
    model: str,
    system_prompt: str,
    maximum_cost_microusd: int,
    timeout_seconds: int,
) -> MediatorInvocation:
    schema = canonical_json_bytes(output_json_schema())
    return MediatorInvocation(
        schema="umi-mediator-invocation/1",
        runner_sha256=runner_sha256,
        cli_sha256=cli_sha256,
        cli_version=cli_version,
        model=model,
        system_prompt_sha256=hashlib.sha256(system_prompt.encode()).hexdigest(),
        output_schema_sha256=hashlib.sha256(schema).hexdigest(),
        maximum_cost_microusd=maximum_cost_microusd,
        timeout_seconds=timeout_seconds,
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: StrictProtocolModel) -> str:
    return _sha256(canonical_json_bytes(value))


def _regular_digest(path: Path, *, executable: bool, maximum_bytes: int) -> str:
    private_path(str(path))
    if path.is_symlink():
        raise ValueError("mediator dependency must not be a symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
            or (executable and not info.st_mode & 0o111)
            or not 1 <= info.st_size <= maximum_bytes
        ):
            raise ValueError("mediator dependency must be an owned bounded regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1)):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _cli(path: Path, expected_sha256: str) -> None:
    if _regular_digest(path, executable=True, maximum_bytes=1024**3) != expected_sha256:
        raise ValueError("mediator CLI digest changed")


def _runner(working_directory: Path, expected_sha256: str) -> None:
    path = working_directory.parent / "runner-release.json"
    if _regular_digest(path, executable=False, maximum_bytes=64 * 1024) != expected_sha256:
        raise ValueError("mediator runner release changed")


def command(cli: Path, value: MediatorInvocation, *, system_prompt: str) -> tuple[str, ...]:
    if _sha256(system_prompt.encode()) != value.system_prompt_sha256:
        raise ValueError("mediator system prompt changed")
    schema = canonical_json_bytes(output_json_schema()).decode()
    if _sha256(schema.encode()) != value.output_schema_sha256:
        raise ValueError("mediator output schema changed")
    budget = f"{Decimal(value.maximum_cost_microusd) / Decimal(1_000_000):f}"
    return (
        str(cli),
        "-p",
        "--output-format",
        "json",
        "--max-turns",
        "1",
        "--tools",
        "",
        "--restricted",
        "--safe-mode",
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--permission-prompts",
        "none",
        "--permission-mode",
        "dontAsk",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--no-chrome",
        "--model",
        value.model,
        "--effort",
        "low",
        "--max-budget-usd",
        budget,
        "--system-prompt",
        system_prompt,
        "--json-schema",
        schema,
    )


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("provider response contains a duplicate JSON key")
        result[key] = value
    return result


def _provider_response(
    raw: bytes, request: MediatorRequest, value: MediatorInvocation
) -> MediatorReceipt:
    if not 1 <= len(raw) <= _MAXIMUM_PROVIDER_BYTES:
        raise ValueError("provider response exceeds its byte bound")
    wrapper = json.loads(raw, object_pairs_hook=_unique, parse_float=Decimal)
    if not isinstance(wrapper, dict) or wrapper.get("is_error") is not False:
        raise ValueError("provider returned an error")
    models = wrapper.get("modelUsage")
    if not isinstance(models, dict) or set(models) != {value.model}:
        raise _ProviderModelChanged("provider model changed")
    structured = wrapper.get("structured_output")
    if not isinstance(structured, dict):
        raise ValueError("provider response lacks structured output")
    output = MediatorOutput.model_validate_json(
        json.dumps(structured, separators=(",", ":"), ensure_ascii=False)
    )
    _validate_source_evidence(output, request)
    usage = wrapper.get("usage")
    if not isinstance(usage, dict):
        raise ValueError("provider response lacks usage")
    try:
        cost = Decimal(wrapper["total_cost_usd"])
    except (InvalidOperation, KeyError, TypeError) as error:
        raise ValueError("provider response has invalid cost") from error
    if cost < 0 or cost * 1_000_000 > value.maximum_cost_microusd:
        raise ValueError("provider exceeded the invocation budget")
    return MediatorReceipt(
        schema="umi-mediator-receipt/1",
        request_sha256=_digest(request),
        invocation_sha256=_digest(value),
        provider_response_sha256=_sha256(raw),
        provider_model=value.model,
        output=output,
        output_sha256=_digest(output),
        reported_turns=wrapper["num_turns"],
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
        duration_ms=wrapper["duration_ms"],
        duration_api_ms=wrapper["duration_api_ms"],
        total_cost_usd=format(cost, "f"),
    )


def _directory(path: Path, *, read_only: bool) -> None:
    private_path(str(path))
    if path.is_symlink():
        raise ValueError("mediator directory must not be a symlink")
    info = path.stat()
    required_mode = 0o500 if read_only else None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or (required_mode is not None and stat.S_IMODE(info.st_mode) != required_mode)
        or (not read_only and info.st_mode & 0o022)
    ):
        raise ValueError("mediator directory ownership or mode differs")


def _ambient_instruction_paths(working_directory: Path, home: Path) -> tuple[Path, ...]:
    """Return every Claude memory path that could alter the fixed system prompt."""
    paths = [
        home / ".claude.json",
        home / ".mcp.json",
        home / ".claude" / "CLAUDE.md",
        home / ".claude" / "CLAUDE.local.md",
        home / ".claude" / "rules",
        home / ".claude" / "agents",
        home / ".claude" / "commands",
        home / ".claude" / "hooks",
        home / ".claude" / "plugins",
        home / ".claude" / "projects",
        home / ".claude" / "skills",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        Path("/etc/claude-code/CLAUDE.md"),
        Path("/etc/claude-code/managed-settings.json"),
        Path("/etc/claude-code/managed-mcp.json"),
    ]
    current = working_directory
    while True:
        paths.extend(
            (
                current / "CLAUDE.md",
                current / "CLAUDE.local.md",
                current / "AGENTS.md",
                current / ".mcp.json",
                current / ".claude" / "CLAUDE.md",
                current / ".claude" / "AGENTS.md",
                current / ".claude" / "rules",
                current / ".claude" / "agents",
                current / ".claude" / "commands",
                current / ".claude" / "hooks",
                current / ".claude" / "plugins",
                current / ".claude" / "skills",
                current / ".claude" / "settings.json",
                current / ".claude" / "settings.local.json",
            )
        )
        if current == current.parent:
            break
        current = current.parent
    return tuple(paths)


def _no_ambient_instructions(working_directory: Path, home: Path) -> None:
    for path in _ambient_instruction_paths(working_directory, home):
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise ValueError("Claude memory input is present")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.wait()


def _communicate_bounded(
    process: subprocess.Popen[bytes], payload: bytes, *, timeout_seconds: int
) -> tuple[bytes, bytes, int]:
    """Write one request and drain both child pipes within fixed byte bounds."""
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    deadline = time.monotonic() + timeout_seconds
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": _MAXIMUM_PROVIDER_BYTES, "stderr": _MAXIMUM_ERROR_BYTES}
    position = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                for key, _ in events:
                    stream, name = key.fileobj, key.data
                    if name == "stdin":
                        try:
                            written = os.write(
                                stream.fileno(), payload[position : position + 65536]
                            )
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            written = len(payload) - position
                        position += written
                        if position == len(payload):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    maximum = limits[name]
                    try:
                        chunk = os.read(
                            stream.fileno(), min(65536, maximum + 1 - len(buffers[name]))
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    buffers[name].extend(chunk)
                    if len(buffers[name]) > maximum:
                        raise _ProviderOutputLimit(f"mediator {name} exceeds its byte bound")
            return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        return bytes(buffers["stdout"]), bytes(buffers["stderr"]), return_code
    except BaseException:
        _terminate(process)
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def execute(
    request: MediatorRequest,
    value: MediatorInvocation,
    *,
    cli: Path,
    system_prompt: str,
    working_directory: Path,
    home: Path,
) -> tuple[MediatorReceipt | MediatorUnavailable, bytes]:
    """Invoke one tool-free diagnostic and return its exact provider bytes.

    Callers must durably reserve this exact request/invocation before entering
    and retain the returned bytes before reporting success. An interrupted call
    has unknown outcome and must not be retried under the same scoring identity.
    """
    request = MediatorRequest.model_validate_json(canonical_json_bytes(request))
    value = MediatorInvocation.model_validate_json(canonical_json_bytes(value))
    request_sha256, invocation_sha256 = _digest(request), _digest(value)
    try:
        _runner(working_directory, value.runner_sha256)
    except (OSError, ValueError):
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="runner_changed",
            ),
            b"",
        )
    try:
        _cli(cli, value.cli_sha256)
    except (OSError, ValueError):
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="cli_changed",
            ),
            b"",
        )
    _directory(working_directory, read_only=True)
    _directory(home, read_only=False)
    if any(working_directory.iterdir()):
        raise ValueError("mediator working directory must be empty")
    try:
        _no_ambient_instructions(working_directory, home)
    except (OSError, ValueError):
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="ambient_instructions_present",
            ),
            b"",
        )
    environment = {
        "HOME": str(home),
        "USER": str(home.name),
        "LOGNAME": str(home.name),
        "LANG": "C.UTF-8",
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    }
    try:
        process = subprocess.Popen(
            command(cli, value, system_prompt=system_prompt),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        stdout, stderr, return_code = _communicate_bounded(
            process,
            canonical_json_bytes(provider_request(request)),
            timeout_seconds=value.timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="provider_timeout",
            ),
            b"",
        )
    except (_ProviderOutputLimit, OSError):
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="cli_failed",
            ),
            b"",
        )
    if return_code != 0 or stderr:
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="cli_failed",
                stdout_sha256=_sha256(stdout),
                stderr_sha256=_sha256(stderr),
            ),
            stdout,
        )
    try:
        receipt = _provider_response(stdout, request, value)
    except _ProviderModelChanged:
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="provider_model_changed",
                stdout_sha256=_sha256(stdout),
                stderr_sha256=_sha256(stderr),
            ),
            stdout,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return (
            MediatorUnavailable(
                schema="umi-mediator-unavailable/1",
                request_sha256=request_sha256,
                invocation_sha256=invocation_sha256,
                reason="provider_response_invalid",
                stdout_sha256=_sha256(stdout),
                stderr_sha256=_sha256(stderr),
            ),
            stdout,
        )
    return receipt, stdout
