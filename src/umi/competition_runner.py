"""Offline-model evaluation boundary for a separate wallet-free worker.

Runtime integration is explicit and opt-in. This module is not wired into the
installed bootstrap supervisor. Unit tests do not certify a host's isolation.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import math
import os
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, TypeAdapter, model_validator
from typing_extensions import Self

from .competition_artifacts import verify_preserved_bundle
from .competition_model_interface import model_python_entrypoint
from .competition_native import OfflineMpsRuntime
from .concurrency import kill_and_reap
from .open_competition import CaseOutput, CompetitionPolicy, ModelBundle, digest
from .private_files import ensure_private_directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .competition_evaluation_runtime import AuthorizedEvaluationRuntime


class OfflineCpuRuntime(StrictProtocolModel):
    schema_: Literal["umi-offline-cpu-runtime/1", "umi-offline-cpu-runtime/2"] = Field(
        alias="schema"
    )
    image: Annotated[
        str,
        Field(
            pattern=r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9/_.-]+@sha256:[0-9a-f]{64}$", max_length=512
        ),
    ]
    cpus: Annotated[int, Field(ge=1, le=8)]
    memory_bytes: Annotated[int, Field(ge=128 * 1024**2, le=64 * 1024**3)]
    scratch_bytes: Annotated[int, Field(ge=1024**2, le=4 * 1024**3)]
    pids_limit: Annotated[int, Field(ge=16, le=256)] = 256
    maximum_video_bytes: Annotated[int, Field(ge=1, le=64 * 1024**2)]

    @model_validator(mode="after")
    def bound_scratch(self) -> Self:
        if self.scratch_bytes > self.memory_bytes // 4:
            raise ValueError("scratch space exceeds one quarter of the memory budget")
        return self


OfflineRuntime = Annotated[OfflineCpuRuntime | OfflineMpsRuntime, Field(discriminator="schema_")]
OFFLINE_RUNTIME = TypeAdapter(OfflineRuntime)


class EvaluationInfrastructureError(RuntimeError):
    pass


class OfflineCaseExecution(StrictProtocolModel):
    """Bounded raw stdout and the classification of one sandbox invocation.

    This is host-observed evidence, not remote attestation of host isolation.
    The raw prefix contains at most the output limit plus one overflow byte.
    """

    schema_: Literal["umi-offline-case-execution/1"] = Field(alias="schema")
    model_sha256: Hex32
    runtime_sha256: Hex32
    video_sha256: Hex32
    output: CaseOutput
    stdout_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$", max_length=8194)]
    reason: Literal["ok", "deadline", "output_limit", "invalid_utf8", "process_failed"]
    returncode: Annotated[int, Field(ge=-65536, le=65536)] | None


def validate_case_execution(
    record: OfflineCaseExecution,
    policy: CompetitionPolicy,
    *,
    runtime_authorization: AuthorizedEvaluationRuntime | None = None,
) -> None:
    """Replay output parsing/classification without trusting a supplied hypothesis."""
    from .competition_evaluation_runtime import validate_evaluation_runtime_authorization

    record = OfflineCaseExecution.model_validate_json(canonical_json_bytes(record))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    raw = bytes.fromhex(record.stdout_hex)
    output = record.output
    try:
        validate_evaluation_runtime_authorization(
            runtime_authorization, policy=policy, runtime_sha256=record.runtime_sha256
        )
    except ValueError as error:
        raise ValueError("execution runtime mismatch") from error
    if record.returncode in {125, 126, 127}:
        raise ValueError("runtime failures cannot become miner failures")
    if len(raw) > policy.maximum_output_bytes + 1:
        raise ValueError("execution stdout exceeds its retained prefix bound")
    if record.reason == "ok":
        if (
            record.returncode != 0
            or output.status != "ok"
            or len(raw) > policy.maximum_output_bytes
            or output.elapsed_ms > policy.maximum_inference_ms
            or raw.decode("utf-8", errors="strict").strip() != output.hypothesis
        ):
            raise ValueError("execution success does not match retained stdout")
    else:
        if output.status != "miner_failure":
            raise ValueError("execution failure has the wrong classification")
        if record.reason == "deadline" and output.elapsed_ms < policy.maximum_inference_ms:
            raise ValueError("deadline receipt precedes the inference deadline")
        if record.reason == "output_limit" and len(raw) != policy.maximum_output_bytes + 1:
            raise ValueError("execution overflow has no retained overflow byte")
        if record.reason == "invalid_utf8":
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                pass
            else:
                raise ValueError("execution UTF-8 failure has valid stdout")
            if record.returncode != 0 or len(raw) > policy.maximum_output_bytes:
                raise ValueError("execution UTF-8 failure preceded normal process completion")
        if record.reason == "process_failed" and record.returncode in {None, 0, 125, 126, 127}:
            raise ValueError("runtime failures cannot become miner process failures")


def _mount_path(path: Path) -> str:
    if not path.is_absolute() or any(x in str(path) for x in (",", "\n", "\r", "\x00")):
        raise ValueError("unsafe Podman bind-mount source")
    return str(path)


def model_command(
    runtime: OfflineCpuRuntime,
    *,
    name: str,
    model: Path,
    inputs: Path,
    entrypoint: str,
    maximum_inference_ms: int,
    cidfile: Path | None = None,
) -> tuple[str, ...]:
    if type(maximum_inference_ms) is not int or not 1 <= maximum_inference_ms <= 3_600_000:
        raise ValueError("invalid inference deadline")
    if not name.startswith("umi-evaluation-") or len(name) != len("umi-evaluation-") + 32:
        raise ValueError("evaluation container name must be freshly allocated")
    if any(c not in "0123456789abcdef" for c in name[len("umi-evaluation-") :]):
        raise ValueError("invalid evaluation container identity")
    # Entrypoint must be selected from an already validated manifest path.
    from .open_competition import BundleFile

    BundleFile(path=entrypoint, role="inference", sha256="00" * 32, size_bytes=0)
    temporary_mounts = (
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size={runtime.scratch_bytes},mode=1777",
    )
    if runtime.schema_ == "umi-offline-cpu-runtime/2":
        # POSIX semaphores used by CPU frameworks need writable /dev/shm.
        # Divide the existing budget, never add an unaccounted shared-memory
        # allowance. Use 64 KiB units for the supported Linux architectures'
        # 4/16/64 KiB pages, so tmpfs rounding stays within the budget.
        unit = 64 * 1024
        shared = min(runtime.scratch_bytes // 4, 64 * 1024**2) // unit * unit
        temporary = (runtime.scratch_bytes - shared) // unit * unit
        temporary_mounts = (
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,noexec,size={temporary},mode=1777",
            "--tmpfs",
            f"/dev/shm:rw,nosuid,nodev,noexec,size={shared},mode=1777",
        )
    return (
        "/usr/bin/podman",
        "run",
        "--name",
        name,
        "--pull=never",
        "--rm",
        *(("--cidfile", _mount_path(cidfile)) if cidfile is not None else ()),
        # conmon enforces this even if the Python evaluator is killed. The
        # finer-grained scoring deadline still includes container startup.
        f"--timeout={math.ceil(maximum_inference_ms / 1000)}",
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--userns=keep-id",
        "--user",
        str(os.getuid()),
        "--pid=private",
        "--ipc=private",
        "--uts=private",
        "--image-volume=ignore",
        "--http-proxy=false",
        "--log-driver=none",
        "--pids-limit",
        str(runtime.pids_limit),
        "--cpus",
        str(runtime.cpus),
        "--memory",
        str(runtime.memory_bytes),
        "--memory-swap",
        str(runtime.memory_bytes),
        "--ulimit=core=0:0",
        "--ulimit=nofile=256:256",
        *temporary_mounts,
        "--mount",
        f"type=bind,src={_mount_path(model)},dst=/model,ro=true",
        "--mount",
        f"type=bind,src={_mount_path(inputs)},dst=/input,ro=true",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONUNBUFFERED=1",
        "--env=HF_HUB_OFFLINE=1",
        "--env=TRANSFORMERS_OFFLINE=1",
        "--workdir=/model",
        "--entrypoint=/usr/local/bin/python3",
        runtime.image,
        f"/model/{entrypoint}",
        "/input/video.mp4",
    )


async def _small_command(arguments: tuple[str, ...], *, timeout: float = 10) -> tuple[int, bytes]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:

        async def collect():
            assert process.stdout is not None
            output = bytearray()
            while chunk := await process.stdout.read(min(65536, 256 * 1024 + 1 - len(output))):
                output.extend(chunk)
                if len(output) > 256 * 1024:
                    raise EvaluationInfrastructureError(
                        "container runtime output exceeded its bound"
                    )
            code = await process.wait()
            return code, bytes(output)

        return await asyncio.wait_for(collect(), timeout)
    finally:
        if process.returncode is None:
            await kill_and_reap(process)


async def verify_runtime(
    runtime: OfflineRuntime,
    policy: CompetitionPolicy,
    *,
    runtime_authorization: AuthorizedEvaluationRuntime | None = None,
) -> None:
    from .competition_evaluation_runtime import validate_evaluation_runtime_authorization

    try:
        validate_evaluation_runtime_authorization(
            runtime_authorization, policy=policy, runtime_sha256=digest(runtime)
        )
    except ValueError as error:
        raise EvaluationInfrastructureError(
            "offline runtime does not match the signed policy or authorized amendment"
        ) from error
    if isinstance(runtime, OfflineMpsRuntime):
        from .competition_native import verify_native_runtime

        await verify_native_runtime(runtime, policy)
        return
    if sys.platform != "linux" or os.geteuid() == 0:
        raise EvaluationInfrastructureError("offline evaluation requires a non-root Linux operator")
    try:
        code, output = await _small_command(
            ("/usr/bin/podman", "info", "--format=json"), timeout=60
        )
        info = json.loads(output)
        host = info["host"]
        if (
            code
            or host["security"]["rootless"] is not True
            or str(host["cgroupVersion"]).lower() not in {"v2", "2"}
        ):
            raise EvaluationInfrastructureError("rootless Podman with cgroup v2 is required")
        code, _ = await _small_command(
            ("/usr/bin/podman", "image", "exists", runtime.image), timeout=60
        )
        if code:
            raise EvaluationInfrastructureError("pinned offline runtime image is not installed")
    except (OSError, KeyError, TypeError, ValueError, asyncio.TimeoutError) as error:
        raise EvaluationInfrastructureError("offline runtime preflight failed") from error


async def _drain_cleanup(awaitable):
    """Do not leave a shielded cleanup task orphaned after repeated cancellation."""
    task = asyncio.create_task(awaitable)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError()
    return result


def invocation_container_name(invocation_sha256: str) -> str:
    """An owner-retained invocation identity names only its case container."""
    if (
        type(invocation_sha256) is not str
        or len(invocation_sha256) != 64
        or any(c not in "0123456789abcdef" for c in invocation_sha256)
    ):
        raise ValueError("invalid retained invocation identity")
    return "umi-evaluation-" + invocation_sha256[:32]


async def stop_retained_cpu_invocation(invocation_sha256: str) -> None:
    name = invocation_container_name(invocation_sha256)
    code, _ = await _small_command(
        ("/usr/bin/podman", "rm", "--force", "--ignore", "--time=0", name)
    )
    if code:
        raise EvaluationInfrastructureError("retained evaluation container cleanup failed")


def _read_container_id(path: Path) -> str | None:
    """Read only the bounded CID file created by this invocation's Podman."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) & 0o022
            or details.st_size > 65
        ):
            raise ValueError("invocation container identity file differs")
        raw = os.read(descriptor, 66)
    finally:
        os.close(descriptor)
    if len(raw) < 64:
        return None  # Podman may have created the file before its single write.
    value = raw.decode("ascii").removesuffix("\n")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("invocation requires a complete container identity")
    return value


def _capacity_container_path(raw: bytes, container_id: str, name: str) -> str | None:
    records = json.loads(raw)
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise ValueError("container inspection must identify exactly one invocation")
    record = records[0]
    if record.get("Id") != container_id or record.get("Name") not in {name, "/" + name}:
        raise ValueError("container inspection differs from its invocation")
    state = record.get("State", {})
    if state.get("Running") is not True or not state.get("CgroupPath"):
        return None
    value = state["CgroupPath"]
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ValueError("container inspection has an invalid kernel path")
    path = Path(value)
    if path.name == "container":
        path = path.parent
    if path.name != f"libpod-{container_id}.scope":
        raise ValueError("container cgroup differs from its full identity")
    if not path.is_relative_to("/sys/fs/cgroup"):
        path = Path("/sys/fs/cgroup") / str(path).lstrip("/")
    return str(path / "container")


async def _bind_invocation_capacity(process, cidfile, name, native_capacity):
    """Optional accounting evidence; uncertainty retains the full container charge."""
    try:
        container_id = cgroup = None
        while process.returncode is None:
            if container_id is None:
                container_id = _read_container_id(cidfile)
            if container_id is not None and cgroup is None:
                code, raw = await _small_command(
                    ("/usr/bin/podman", "container", "inspect", "--format=json", container_id),
                    timeout=2,
                )
                if code:
                    return
                cgroup = _capacity_container_path(raw, container_id, name)
            if cgroup is not None and native_capacity.bind_container(container_id, cgroup):
                return
            await asyncio.sleep(0.1)
    except Exception as error:
        # This optimization does not alter execution classification or deadlines.
        # Do not log untrusted Podman output or treat PID similarity as ownership.
        _LOG.info("model_capacity_binding conservative reason=%s", type(error).__name__)


async def execute_offline_case(
    *,
    bundle: ModelBundle,
    archive: Path,
    runtime: OfflineRuntime,
    policy: CompetitionPolicy,
    case_id: Hex32,
    video_sha256: Hex32,
    video: bytes,
    invocation_sha256: Hex32 | None = None,
    workspace: Path | None = None,
    runtime_authorization: AuthorizedEvaluationRuntime | None = None,
    native_capacity=None,
) -> OfflineCaseExecution:
    """Run a verified model on one clip, with no reference text passed to it.

    Cold start and sandbox initialization are included in the case deadline.
    The selected declared Python entrypoint reads argv[1] and emits one UTF-8
    English hypothesis to stdout. Routed bundles use the root umi_inference.py
    wrapper when they declare additional inference helpers.
    """
    runtime = OFFLINE_RUNTIME.validate_json(canonical_json_bytes(runtime))
    if (invocation_sha256 is None) != (workspace is None):
        raise ValueError("retained CPU invocation requires its identity and workspace")
    if invocation_sha256 is not None:
        invocation_container_name(invocation_sha256)
        if not isinstance(runtime, OfflineCpuRuntime):
            raise EvaluationInfrastructureError("retained invocation requires a CPU runtime")
        ensure_private_directory(workspace)
    if isinstance(runtime, OfflineMpsRuntime):
        if runtime_authorization is not None:
            raise EvaluationInfrastructureError("CPU runtime amendment cannot authorize MPS")
        from .competition_native import execute_native_case

        return await execute_native_case(
            bundle=bundle,
            archive=archive,
            runtime=runtime,
            policy=policy,
            case_id=case_id,
            video_sha256=video_sha256,
            video=video,
        )
    bundle = ModelBundle.model_validate_json(canonical_json_bytes(bundle))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if (
        len(video) > runtime.maximum_video_bytes
        or hashlib.sha256(video).hexdigest() != video_sha256
    ):
        raise EvaluationInfrastructureError("video bytes do not match the assignment")
    await verify_runtime(runtime, policy, runtime_authorization=runtime_authorization)
    verify_preserved_bundle(bundle, archive, policy)
    try:
        entrypoint = model_python_entrypoint(bundle)
    except ValueError as error:
        raise EvaluationInfrastructureError(str(error)) from error
    name = (
        "umi-evaluation-" + uuid.uuid4().hex
        if invocation_sha256 is None
        else invocation_container_name(invocation_sha256)
    )
    process = binding = None
    with tempfile.TemporaryDirectory(prefix="umi-evaluation-input-", dir=workspace) as scratch:
        inputs = Path(scratch)
        path = inputs / "video.mp4"
        path.write_bytes(video)
        path.chmod(0o400)
        cidfile = (
            inputs / "container.cid"
            if native_capacity is not None and invocation_sha256 is not None
            else None
        )
        command = model_command(
            runtime,
            name=name,
            model=archive / digest(bundle) / "model",
            inputs=inputs,
            entrypoint=entrypoint,
            maximum_inference_ms=policy.maximum_inference_ms,
            **({"cidfile": cidfile} if cidfile is not None else {}),
        )
        started = time.monotonic()
        status, hypothesis = "miner_failure", ""
        chunks = bytearray()
        reason = "process_failed"
        returncode = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if cidfile is not None:
                binding = asyncio.create_task(
                    _bind_invocation_capacity(process, cidfile, name, native_capacity)
                )

            async def collect():
                nonlocal returncode, reason
                assert process is not None and process.stdout is not None
                while data := await process.stdout.read(
                    min(4096, policy.maximum_output_bytes + 1 - len(chunks))
                ):
                    chunks.extend(data)
                    if len(chunks) > policy.maximum_output_bytes:
                        reason = "output_limit"
                        raise ValueError("model output exceeded the policy limit")
                code = await process.wait()
                returncode = code
                if code in {125, 126, 127}:
                    raise EvaluationInfrastructureError(
                        "container runtime could not execute the profile"
                    )
                if code:
                    raise ValueError("model execution failed")
                reason = "invalid_utf8"
                return bytes(chunks).decode("utf-8", errors="strict").strip()

            try:
                hypothesis = await asyncio.wait_for(collect(), policy.maximum_inference_ms / 1000)
                status = "ok"
                reason = "ok"
            except asyncio.TimeoutError:
                reason = "deadline"
            except ValueError:
                pass
            elapsed = math.ceil((time.monotonic() - started) * 1000)
            if elapsed > policy.maximum_inference_ms:
                status, hypothesis = "miner_failure", ""
                reason = "deadline"
        except OSError as error:
            raise EvaluationInfrastructureError("container process could not start") from error
        finally:
            # Killing the Podman client alone does not establish container exit.
            # Remove only this case container; never --all or a
            # validator container name. Failure stops evaluation as infrastructure.
            async def cleanup():
                if binding is not None:
                    binding.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await binding
                try:
                    code, _ = await _small_command(
                        ("/usr/bin/podman", "rm", "--force", "--ignore", "--time=0", name),
                    )
                    if code:
                        raise EvaluationInfrastructureError("evaluation container cleanup failed")
                finally:
                    if native_capacity is not None:
                        # A failed rm loses the live binding, so any surviving
                        # container is fully charged before this lease releases.
                        native_capacity.clear_container()

            try:
                await _drain_cleanup(cleanup())
            finally:
                if process is not None and process.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                        await _drain_cleanup(process.wait())
        record = OfflineCaseExecution(
            schema="umi-offline-case-execution/1",
            model_sha256=digest(bundle),
            runtime_sha256=digest(runtime),
            video_sha256=video_sha256,
            output=CaseOutput(
                case_id=case_id,
                status=status,
                hypothesis=hypothesis,
                elapsed_ms=min(elapsed, 86_400_000),
            ),
            stdout_hex=bytes(chunks).hex(),
            reason=reason,
            returncode=returncode,
        )
        validate_case_execution(record, policy, runtime_authorization=runtime_authorization)
        return record


async def evaluate_offline_case(**kwargs) -> CaseOutput:
    """Compatibility wrapper for callers that only need the scored output."""
    return (await execute_offline_case(**kwargs)).output
