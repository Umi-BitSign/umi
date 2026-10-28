"""The shared selector never guesses among submitted helper programs."""

import asyncio
import hashlib
from types import SimpleNamespace

import pytest

from umi.competition_model_interface import model_python_entrypoint
from umi.open_competition import BundleFile
from umi.protocol import canonical_json_bytes

from .test_open_competition import bundle_at
from .test_open_competition import policy as policy


def routed_bundle(tmp_path, paths):
    original = bundle_at(tmp_path / "bundle")
    records = [f for f in original.files if f.role != "inference"]
    records.extend(
        BundleFile(path=p, role="inference", sha256="ab" * 32, size_bytes=0) for p in paths
    )
    return original.model_copy(update={"files": tuple(sorted(records, key=lambda f: f.path))})


@pytest.mark.parametrize(
    "paths,expected",
    [
        (("infer.py",), "infer.py"),
        (("nested/infer.py",), "nested/infer.py"),
        (("fs/route_child.py", "umi_inference.py"), "umi_inference.py"),
        (("a.py", "c6_runtime.py", "umi_inference.py", "z.py"), "umi_inference.py"),
    ],
)
def test_entrypoint_selection_preserves_original_signed_manifest(tmp_path, paths, expected):
    bundle = routed_bundle(tmp_path, paths)
    raw = canonical_json_bytes(bundle)
    assert model_python_entrypoint(bundle) == expected
    assert canonical_json_bytes(bundle) == raw


@pytest.mark.parametrize(
    "paths",
    [
        ("first.py", "second.py"),
        ("fs/umi_inference.py", "other.py"),
        ("infer.sh",),
    ],
)
def test_ambiguous_or_non_python_interface_is_explicit(tmp_path, paths):
    with pytest.raises(ValueError, match="declared Python inference entrypoint"):
        model_python_entrypoint(routed_bundle(tmp_path, paths))


def test_canonical_name_must_have_the_signed_inference_role(tmp_path):
    bundle = routed_bundle(tmp_path, ("a.py", "b.py"))
    bundle = bundle.model_copy(
        update={
            "files": tuple(
                sorted(
                    (
                        *bundle.files,
                        BundleFile(
                            path="umi_inference.py",
                            role="dependency",
                            sha256="ab" * 32,
                            size_bytes=0,
                        ),
                    ),
                    key=lambda f: f.path,
                )
            )
        }
    )
    with pytest.raises(ValueError, match="declared Python inference entrypoint"):
        model_python_entrypoint(bundle)


@pytest.mark.asyncio
async def test_native_adapter_uses_same_root_wrapper_without_changing_receipt_contract(
    tmp_path, monkeypatch, policy
):
    from umi import competition_artifacts as artifacts
    from umi import competition_native as native
    from umi.competition_runner import validate_case_execution
    from umi.open_competition import digest

    bundle = routed_bundle(tmp_path, ("fs/route_child.py", "umi_inference.py"))
    model = tmp_path / digest(bundle) / "model"
    model.mkdir(parents=True)
    environment = tmp_path / "environment"
    (environment / "bin").mkdir(parents=True)
    (environment / "bin/python").touch()
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    runtime = native.OfflineMpsRuntime(
        schema="umi-offline-mps-runtime/1",
        installation_sha256="ab" * 32,
        os_build="25F84",
        python_abi="cp310",
        cpu_threads=4,
        maximum_video_bytes=1024,
        rss_watchdog_bytes=1024**3,
        scratch_watchdog_bytes=16 * 1024**2,
        cold_start_in_deadline=True,
    )
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})

    async def verify(*args):
        return {"environment": environment, "overlay": overlay}

    monkeypatch.setattr(native, "verify_native_runtime", verify)
    monkeypatch.setattr(artifacts, "verify_preserved_bundle", lambda *args: None)
    monkeypatch.setattr(native.os, "confstr", lambda _: str(tmp_path))
    calls = []
    stdout = asyncio.StreamReader()
    stdout.feed_data(b"hello")
    stdout.feed_eof()

    async def wait():
        return 0

    async def spawn(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=stdout, stdin=SimpleNamespace(close=lambda: None), wait=wait)

    monkeypatch.setattr(native.asyncio, "create_subprocess_exec", spawn)
    result = await native.execute_native_case(
        bundle=bundle,
        archive=tmp_path,
        runtime=runtime,
        policy=policy,
        case_id="ab" * 32,
        video_sha256=hashlib.sha256(b"video").hexdigest(),
        video=b"video",
    )
    assert str(model / "umi_inference.py") in calls[0]
    assert result.reason == "ok" and result.output.hypothesis == "hello"
    validate_case_execution(result, policy)
