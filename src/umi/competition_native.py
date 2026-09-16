"""Opt-in native MPS evaluator installation and execution boundary.

The native profile has sampled RSS/storage ceilings and prohibits child
processes. It is a different signed runtime from the Linux cgroup profile.
No native installation or policy is selected automatically.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import os
import platform
import shutil
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_native_inventory import checked_roots, inventory
from .competition_native_sandbox import native_profile
from .open_competition import CompetitionPolicy, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class OfflineMpsRuntime(StrictProtocolModel):
    schema_: Literal["umi-offline-mps-runtime/1"] = Field(alias="schema")
    installation_sha256: Hex32
    os_build: Annotated[str, Field(pattern=r"^[0-9A-Z][0-9A-Za-z.]{2,31}$")]
    python_abi: Literal["cp310"]
    cpu_threads: Annotated[int, Field(ge=1, le=8)]
    maximum_video_bytes: Annotated[int, Field(ge=1, le=64 * 1024**2)]
    rss_watchdog_bytes: Annotated[int, Field(ge=128 * 1024**2, le=64 * 1024**3)]
    scratch_watchdog_bytes: Annotated[int, Field(ge=1024**2, le=4 * 1024**3)]
    cold_start_in_deadline: Literal[True]


@contextlib.contextmanager
def _case_directory():
    root = Path(tempfile.mkdtemp(prefix="umi-native-case-")).resolve(strict=True)
    # Only normal completion deletes scratch. Exceptions, cancellation or
    # uncertain guard cleanup retain the exact namespace for operator review.
    yield root
    shutil.rmtree(root)


def _private_json(path: Path, maximum: int) -> tuple[dict, bytes]:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("native installation config must be a canonical absolute file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > maximum
        ):
            raise ValueError("native installation config is not bounded and owner-private")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("native installation config exceeds its byte bound")
    document = json.loads(raw)
    if not isinstance(document, dict) or canonical_json_bytes(document) != raw:
        raise ValueError("native installation config must be a canonical JSON object")
    return document, raw


def verify_installation(runtime: OfflineMpsRuntime) -> dict[str, Path]:
    """Read local path bindings, then independently hash every installed file."""
    document, _ = _private_json(Path(os.environ.get("UMI_NATIVE_EVALUATOR_CONFIG", "")), 65536)
    if (
        set(document) != {"schema", "roots", "manifest"}
        or document["schema"] != "umi-native-evaluator-paths/1"
    ):
        raise ValueError("unsupported native evaluator path binding")
    roots = checked_roots({name: Path(value) for name, value in document["roots"].items()})
    manifest, raw = _private_json(Path(document["manifest"]), 12 * 1024**2)
    if hashlib.sha256(raw).hexdigest() != runtime.installation_sha256:
        raise ValueError("native installation manifest differs from the signed runtime")
    if (
        set(manifest) != {"schema", "entries"}
        or manifest["schema"] != "umi-native-evaluator-installation/1"
    ):
        raise ValueError("unsupported native installation manifest")
    if inventory(roots) != manifest["entries"]:
        raise ValueError("native installed files differ from the signed runtime")
    python = roots["environment"] / "bin/python"
    resolved = python.resolve(strict=True)
    if not any(resolved.is_relative_to(root) for root in roots.values()) or not os.access(
        python, os.X_OK
    ):
        raise ValueError("native interpreter is outside the reviewed installation")
    return roots


async def verify_native_runtime(
    runtime: OfflineMpsRuntime, policy: CompetitionPolicy
) -> dict[str, Path]:
    from .competition_runner import EvaluationInfrastructureError, _small_command

    if sys.platform != "darwin" or platform.machine() != "arm64" or os.geteuid() == 0:
        raise EvaluationInfrastructureError("MPS evaluation requires a non-root macOS arm64 host")
    if digest(runtime) != policy.evaluation_runtime_sha256:
        raise EvaluationInfrastructureError("native runtime does not match the signed policy")
    code, raw = await _small_command(("/usr/sbin/sysctl", "-n", "kern.osversion"))
    if code or raw.decode().strip() != runtime.os_build:
        raise EvaluationInfrastructureError("native evaluator OS build differs from its profile")
    try:
        return verify_installation(runtime)
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise EvaluationInfrastructureError("native installation verification failed") from error


async def execute_native_case(*, bundle, archive, runtime, policy, case_id, video_sha256, video):
    from .competition_artifacts import verify_preserved_bundle
    from .competition_runner import (
        EvaluationInfrastructureError,
        OfflineCaseExecution,
        _drain_cleanup,
        validate_case_execution,
    )
    from .open_competition import CaseOutput, ModelBundle

    bundle = ModelBundle.model_validate_json(canonical_json_bytes(bundle))
    runtime = OfflineMpsRuntime.model_validate_json(canonical_json_bytes(runtime))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if (
        len(video) > runtime.maximum_video_bytes
        or hashlib.sha256(video).hexdigest() != video_sha256
    ):
        raise EvaluationInfrastructureError("video bytes do not match the native assignment")
    roots = await verify_native_runtime(runtime, policy)
    verify_preserved_bundle(bundle, archive, policy)
    entries = [entry.path for entry in bundle.files if entry.role == "inference"]
    if len(entries) != 1 or not entries[0].endswith(".py"):
        raise EvaluationInfrastructureError(
            "native runtime requires one declared Python entrypoint"
        )
    model = (archive / digest(bundle) / "model").resolve(strict=True)
    prelude = Path(__file__).with_name("competition_native_entrypoint.py").resolve(strict=True)
    guard = Path(__file__).with_name("competition_native_watchdog.py").resolve(strict=True)
    python = roots["environment"] / "bin/python"
    suffix = "org.umi.evaluation-" + uuid.uuid4().hex
    cache_base = Path(os.confstr(65538)).resolve(strict=True)
    cache = cache_base / suffix
    # No persistent shared model/cache state across cases or competing bundles.
    with _case_directory() as root:
        scratch, inputs = root / "scratch", root / "input"
        scratch.mkdir(mode=0o700)
        inputs.mkdir(mode=0o700)
        cache.mkdir(mode=0o700)
        video_path = inputs / "video.mp4"
        video_path.write_bytes(video)
        video_path.chmod(0o400)
        profile = native_profile(
            python=python.resolve(strict=True),
            readonly=(*roots.values(), model, inputs),
            readable_files=(prelude,),
            scratch=scratch,
            metal_cache=cache,
        )
        profile_path = root / "worker.sb"
        profile_path.write_text(profile)
        command = (
            sys.executable,
            "-I",
            "-B",
            str(guard),
            "--deadline-ms",
            str(policy.maximum_inference_ms),
            "--rss-ceiling",
            str(runtime.rss_watchdog_bytes),
            "--scratch-ceiling",
            str(runtime.scratch_watchdog_bytes),
            "--scratch",
            str(scratch),
            "--extra-scratch",
            str(cache),
            "--",
            "/usr/bin/sandbox-exec",
            "-f",
            str(profile_path),
            str(python),
            "-I",
            "-B",
            str(prelude),
            str(model / entries[0]),
            str(video_path),
            str(roots["overlay"]),
            suffix,
            str(runtime.scratch_watchdog_bytes),
        )
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            "TMPDIR": str(scratch),
            "HOME": str(scratch),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "HF_HOME": str(scratch / "hf"),
            "TORCH_HOME": str(scratch / "torch"),
            "XDG_CACHE_HOME": str(scratch / "cache"),
            "MPLCONFIGDIR": str(scratch / "mpl"),
            "OMP_NUM_THREADS": str(runtime.cpu_threads),
            "OPENBLAS_NUM_THREADS": str(runtime.cpu_threads),
            "MKL_NUM_THREADS": str(runtime.cpu_threads),
            "UMI_EVALUATION_DEVICE": "mps",
            "PYTORCH_ENABLE_MPS_FALLBACK": "1",
            "PYTORCH_MPS_HIGH_WATERMARK_RATIO": "0.25",
            "PYTORCH_MPS_LOW_WATERMARK_RATIO": "0.20",
        }
        process = None
        chunks = bytearray()
        reason, status, hypothesis, returncode = "process_failed", "miner_failure", "", None
        started = time.monotonic()
        try:
            creation = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    *command,
                    env=environment,
                    cwd=scratch,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    start_new_session=True,
                )
            )
            cancelled = False
            while not creation.done():
                try:
                    await asyncio.shield(creation)
                except asyncio.CancelledError:
                    cancelled = True
            process = creation.result()
            if cancelled:
                raise asyncio.CancelledError()

            async def collect():
                nonlocal returncode, reason
                while data := await process.stdout.read(
                    min(4096, policy.maximum_output_bytes + 1 - len(chunks))
                ):
                    chunks.extend(data)
                    if len(chunks) > policy.maximum_output_bytes:
                        reason = "output_limit"
                        raise ValueError("native model output exceeded the policy bound")
                returncode = await process.wait()
                if returncode in {125, 126, 127}:
                    raise EvaluationInfrastructureError(
                        "native guard could not execute the profile"
                    )
                if returncode == 124:
                    raise asyncio.TimeoutError()
                if returncode:
                    raise ValueError("native model process failed")
                reason = "invalid_utf8"
                return bytes(chunks).decode("utf-8", errors="strict").strip()

            try:
                hypothesis = await asyncio.wait_for(collect(), policy.maximum_inference_ms / 1000)
                status, reason = "ok", "ok"
            except asyncio.TimeoutError:
                reason = "deadline"
            except ValueError:
                pass
            elapsed = math.ceil((time.monotonic() - started) * 1000)
            if reason == "deadline":
                elapsed = max(elapsed, policy.maximum_inference_ms)
            if elapsed > policy.maximum_inference_ms:
                status, reason, hypothesis = "miner_failure", "deadline", ""
        except OSError as error:
            raise EvaluationInfrastructureError("native guard could not start") from error
        finally:
            if process is not None:
                process.stdin.close()

                async def cleanup():
                    # Drain bounded pipe buffers after the guard sees control EOF.
                    total = 0
                    while data := await process.stdout.read(65536):
                        total += len(data)
                        if total > 256 * 1024:
                            raise EvaluationInfrastructureError(
                                "native guard cleanup exceeded its bound"
                            )
                    await process.wait()

                await _drain_cleanup(asyncio.wait_for(cleanup(), timeout=10))
            # Deliberately retain the unique Metal cache on uncertain cleanup.
            # Successful cleanup permits only this freshly-created path's removal.
            shutil.rmtree(cache)
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
        validate_case_execution(record, policy)
        return record
