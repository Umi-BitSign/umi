"""Explicit wallet-free Podman checks for CPU framework shared memory."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid

import pytest

from umi.competition_runner import OfflineCpuRuntime, model_command

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not os.environ.get("UMI_OFFLINE_TEST_IMAGE"),
    reason="requires an installed pinned Python image on a wallet-free Linux test host",
)


@pytest.mark.parametrize("version", [1, 2])
def test_real_cpu_lock_with_private_bounded_shared_memory(tmp_path, version):
    assert os.geteuid() != 0
    runtime = OfflineCpuRuntime(
        schema=f"umi-offline-cpu-runtime/{version}",
        image=os.environ["UMI_OFFLINE_TEST_IMAGE"],
        cpus=1,
        memory_bytes=256 * 1024**2,
        scratch_bytes=16 * 1024**2,
        pids_limit=32,
        maximum_video_bytes=1024,
    )
    model = tmp_path / "model"
    model.mkdir(mode=0o700)
    inputs = tmp_path / "input"
    inputs.mkdir(mode=0o700)
    (inputs / "video.mp4").write_bytes(b"inert fixture")
    probe = f"""
import errno, multiprocessing, os
from pathlib import Path
for path in ('/model', '/input'):
    try:
        Path(path, 'forbidden-write').write_bytes(b'x')
    except OSError as error:
        assert error.errno == errno.EROFS
    else:
        raise AssertionError('model/input mount is writable')
if {version} == 1:
    try:
        multiprocessing.Lock()
    except OSError as error:
        assert error.errno == errno.EROFS
    else:
        raise AssertionError('v1 shared-memory behavior changed')
else:
    from multiprocessing.shared_memory import SharedMemory
    with multiprocessing.Lock():
        memory = SharedMemory(create=True, size=4096)
        try:
            memory.buf[:4] = b'test'
            assert bytes(memory.buf[:4]) == b'test'
        finally:
            memory.close()
            memory.unlink()
    total = sum(os.statvfs(p).f_blocks * os.statvfs(p).f_frsize
                for p in ('/tmp', '/dev/shm'))
    assert total <= {runtime.scratch_bytes}
    Path('/tmp/scratch').write_bytes(b'private scratch')
print('bounded-private-shared-memory-ok')
"""
    (model / "infer.py").write_text(probe)
    name = "umi-evaluation-" + uuid.uuid4().hex
    command = model_command(
        runtime,
        name=name,
        model=model,
        inputs=inputs,
        entrypoint="infer.py",
        maximum_inference_ms=60_000,
    )
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=90,
            check=False,
        )
        assert result.returncode == 0, result.stderr[-4096:]
        assert result.stdout == b"bounded-private-shared-memory-ok\n"
        assert not (model / "forbidden-write").exists()
        assert not (inputs / "forbidden-write").exists()
    finally:
        subprocess.run(
            ["/usr/bin/podman", "rm", "--force", "--ignore", "--time=0", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
