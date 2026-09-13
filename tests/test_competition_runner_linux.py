"""Explicit wallet-free Podman checks for CPU framework shared memory."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import uuid
from pathlib import Path

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


async def test_endpoint_incumbent_job_runs_real_containers_and_retains_receipts(tmp_path):
    """Inert model/video fixtures; boundary port is synthetic, execution is real."""
    from tests.test_competition_execution import boundary
    from tests.test_open_competition import bundle_at, round_for, submission, wallet
    from tests.test_open_competition import policy as policy_fixture
    from umi.competition_artifacts import preserve_bundle
    from umi.competition_execution import (
        EndpointIncumbentJob,
        ExecutionCase,
        ExecutionJournal,
        execution_key,
        run_endpoint_incumbent,
    )
    from umi.open_competition import BundleFile, EvaluationCase, EvaluationSuite, digest

    assert os.geteuid() != 0
    runtime = OfflineCpuRuntime(
        schema="umi-offline-cpu-runtime/2",
        image=os.environ["UMI_OFFLINE_TEST_IMAGE"],
        cpus=1,
        memory_bytes=256 * 1024**2,
        scratch_bytes=16 * 1024**2,
        pids_limit=32,
        maximum_video_bytes=1024,
    )
    policy = policy_fixture.__wrapped__().model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "maximum_inference_ms": 60_000,
        }
    )
    source = tmp_path / "source"
    bundle = bundle_at(source)
    entry = next(f for f in bundle.files if f.role == "inference")
    code = (
        b"from pathlib import Path\nimport sys\n"
        b"assert Path(sys.argv[1]).read_bytes().startswith(b'inert')\nprint('hello')\n"
    )
    (source / entry.path).rename(source / "infer.py")
    (source / "infer.py").write_bytes(code)
    bundle = bundle.model_copy(
        update={
            "files": tuple(
                BundleFile(
                    path="infer.py",
                    role=f.role,
                    sha256=hashlib.sha256(code).hexdigest(),
                    size_bytes=len(code),
                )
                if f.role == "inference"
                else f
                for f in bundle.files
            )
        }
    )
    archive = tmp_path / "archive"
    preserve_bundle(bundle, source, archive, policy)
    videos = tmp_path / "videos"
    videos.mkdir(mode=0o700)
    cases = []
    for i, stratum in enumerate(("fingerspelling", "short_utterance", "continuous")):
        raw = f"inert-{i}".encode()
        sha = hashlib.sha256(raw).hexdigest()
        (videos / (sha + ".mp4")).write_bytes(raw)
        cases.append(
            EvaluationCase(
                case_id=f"{i:064x}",
                video_sha256=sha,
                stratum=stratum,
                references=("hello", "hi", "greetings"),
            )
        )
    suite = EvaluationSuite(
        schema="umi-competition-suite/1", policy_sha256=digest(policy), cases=tuple(cases)
    )
    signed = submission(policy)
    round_ = round_for(policy, suite, (signed,), incumbent=digest(bundle))
    job = EndpointIncumbentJob(
        schema="umi-endpoint-incumbent-job/1",
        round=round_,
        submission=signed,
        incumbent=bundle,
        runtime=runtime,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        cases=tuple(
            ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
            for c in cases
        ),
    )
    journal = ExecutionJournal(tmp_path / "journal", policy)

    async def observe():
        return boundary(125)

    result = await run_endpoint_incumbent(
        job=job,
        policy=policy,
        archive=archive,
        videos=videos,
        journal=journal,
        boundary_provider=observe,
    )
    assert len(result.steps) == 3
    assert all(
        s.role == "incumbent"
        and s.execution.output.hypothesis == "hello"
        and s.execution.reason == "ok"
        for s in result.steps
    )
    assert journal.status(execution_key(job))["status"] == "complete"

    async def forbidden():
        pytest.fail("completed receipt recovery accessed finality")

    assert (
        await run_endpoint_incumbent(
            job=job,
            policy=policy,
            archive=tmp_path / "unavailable",
            videos=tmp_path / "missing",
            journal=journal,
            boundary_provider=forbidden,
        )
        == result
    )

    # Drive the same real runtime through the continuous two-operator model
    # path. Chain captures and the ASGI socket boundary are test ports;
    # execution, authenticated HTTP delivery and agreement replay are real.
    from types import SimpleNamespace

    import httpx

    from tests.test_competition_chain import chain_config as chain_fixture
    from tests.test_competition_evaluator import (
        Provider,
        completed,
        make_driver,
        put,
        signed_order,
    )
    from tests.test_competition_exchange import finish
    from umi.competition_exchange import (
        EvaluatorExchangeClient,
        ExchangeConfig,
        create_exchange_app,
    )
    from umi.competition_execution import ModelEvaluationJob

    model_submission = submission(policy, bundle=bundle)
    model_job = ModelEvaluationJob(
        schema="umi-model-evaluation-job/1",
        round=round_for(policy, suite, (model_submission,), incumbent=digest(bundle)),
        submission=model_submission,
        incumbent=bundle,
        runtime=runtime,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        cases=job.cases,
    )
    signers = (wallet("Charlie"), wallet("Dave"))
    order = signed_order(model_job, signers)
    chain = chain_fixture.__wrapped__(policy, tmp_path)
    drivers = tuple(
        make_driver(tmp_path / f"real-worker-{i}", chain, policy, archive, videos, signer)
        for i, signer in enumerate(signers)
    )
    relay_config = ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(policy),
        chain=chain.model_copy(
            update={
                "collection_timeout_seconds": 10,
                "state_directory": str(tmp_path / "relay-chain"),
            }
        ),
        state_directory=str(tmp_path / "relay-state"),
        order_directory=str(tmp_path / "relay-orders"),
        reveal_directory=str(tmp_path / "relay-reveals"),
    )
    provider = Provider()
    app = create_exchange_app(relay_config, policy, provider_factory=lambda *_: provider)
    clients = tuple(
        EvaluatorExchangeClient(d, "https://relay.example", transport=httpx.ASGITransport(app=app))
        for d in drivers
    )
    try:
        put(Path(relay_config.order_directory) / (digest(order.order) + ".json"), order)
        put(Path(relay_config.reveal_directory) / (digest(suite) + ".json"), suite)
        await finish(
            SimpleNamespace(drivers=drivers, order=order, provider=provider, clients=clients)
        )
        certificates = [completed(driver)[0] for driver in drivers]
        assert certificates[0] == certificates[1]
        assert all(
            output.hypothesis == "hello"
            for output in certificates[0].attested_result.result.candidate
        )
    finally:
        for driver in drivers:
            await driver.aclose()
