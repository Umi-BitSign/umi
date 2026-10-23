"""Rebuild one immutable upstream runtime on a disposable CI runner.

An exact match establishes only source/build correspondence to the supplied
native code identity. It does not qualify reward semantics, authenticate that
native identity, select a profile, or authorize signing/deployment. No key,
production state, native journal or credential is used by this tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def validate_build(raw, build, *, revision, code_sha256, spec_version):
    """Check actual built bytes, immutable source, production profile and version."""
    actual = sha(raw)
    if not raw.startswith(bytes.fromhex("52bc537646db8e05")):
        raise ValueError("runtime artifact is not the expected compressed Wasm")
    if (
        build.get("commit") != revision
        or build.get("info", {}).get("git", {}).get("commit") != revision
        or build.get("pkg") != "node-subtensor-runtime"
        or build.get("info", {}).get("profile") != "production"
        or build.get("gen") != "srtool v0.18.3"
        or not build.get("rustc", "").startswith("rustc 1.89.0 ")
    ):
        raise ValueError("runtime build source, package, profile or toolchain differs")
    if build.get("sha256") != "0x" + actual:
        raise ValueError("srtool digest differs from the actual built bytes")
    if (
        build.get("runtimes", {})
        .get("compressed", {})
        .get("subwasm", {})
        .get("core_version", {})
        .get("specVersion")
        != spec_version
    ):
        raise ValueError("built runtime spec differs from native execution")
    if actual != code_sha256:
        raise ValueError("built runtime bytes differ from the native code identity")
    return {
        "source_revision": revision,
        "runtime_code_sha256": actual,
        "spec_version": spec_version,
        "runtime_bytes": len(raw),
        "source_build_correspondence_established": True,
        "native_input_identity_authenticated_by_this_tool": False,
        "reward_semantics_qualified": False,
        "profile_authorized": False,
        "transaction_submitted": False,
    }


def run_phase(arguments, *, source, output, stage, completed, planning):
    start = changed = time.monotonic()
    log = output / (stage + ".log")
    last_size = 0
    with log.open("xb") as stream:
        process = subprocess.Popen(arguments, cwd=source, stdout=stream, stderr=stream)
        while True:
            code = process.poll()
            elapsed = time.monotonic() - start
            size = log.stat().st_size
            if size != last_size:
                changed, last_size = time.monotonic(), size
            overdue = elapsed > planning[1]
            print(
                json.dumps(
                    {
                        "schema": "umi-runtime-source-build-progress/1",
                        "at_utc": datetime.now(timezone.utc).isoformat(),
                        "stage": stage,
                        "completed": completed + int(code == 0),
                        "total": 4,
                        "count_scope": "completed phases; not overall time percent",
                        "elapsed_seconds": elapsed,
                        "status": "running"
                        if code is None
                        else "completed"
                        if code == 0
                        else "failed",
                        "log_bytes": size,
                        "output_quiet_seconds": time.monotonic() - changed,
                        "planning_eta_seconds": None
                        if overdue or code not in (None, 0)
                        else [max(0, n - elapsed) for n in planning]
                        if code is None
                        else [0, 0],
                        "eta_basis": "withdrawn_phase_exceeded_planning_range"
                        if overdue
                        else (
                            "planning_clean_srtool_image_and_single_production_runtime_build; "
                            "no calibrated confidence"
                        ),
                        "eta_scope": "this build phase only; excludes reward readiness",
                        "stalled_or_retrying": overdue,
                    }
                ),
                flush=True,
            )
            if code is not None:
                if code:
                    raise RuntimeError("runtime source build phase failed: " + stage)
                return
            time.sleep(30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--code-sha256", required=True)
    parser.add_argument("--spec-version", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{40}", args.revision) or not re.fullmatch(
        "[0-9a-f]{64}", args.code_sha256
    ):
        raise ValueError("exact immutable source and native code identities required")
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("source and result directories must be disjoint")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    start = time.monotonic()
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source, text=True
        ).strip()
        if revision != args.revision:
            raise ValueError("checkout differs from the immutable selected source")
        builder = source / "scripts/srtool/build-srtool-image.sh"
        dockerfile = source / "scripts/srtool/Dockerfile"
        save(
            output / "source-selection.json",
            {
                "revision": revision,
                "expected_native_code_sha256": args.code_sha256,
                "expected_spec_version": args.spec_version,
                "srtool_builder_sha256": sha(builder.read_bytes()),
                "srtool_dockerfile_sha256": sha(dockerfile.read_bytes()),
                "production_services_changed": False,
            },
        )
        image = "umi-runtime-source:" + revision[:12]
        run_phase(
            ["bash", str(builder), image],
            source=source,
            output=output,
            stage="srtool_image",
            completed=1,
            planning=(60, 3600),
        )
        link = source / "runtime/node-subtensor"
        if not link.exists():
            link.symlink_to(".")
        if not link.is_symlink() or os.readlink(link) != ".":
            raise ValueError("upstream runtime directory alias differs")
        cargo = output / "cargo"
        cargo.mkdir(mode=0o700)
        run_phase(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "root",
                "--platform=linux/amd64",
                "-e",
                "PACKAGE=node-subtensor-runtime",
                "-e",
                "BUILD_OPTS=--features=metadata-hash",
                "-e",
                "PROFILE=production",
                "-v",
                str(cargo) + ":/cargo-home",
                "-v",
                str(source) + ":/build",
                image,
                "bash",
                "-c",
                "git config --global --add safe.directory /build && "
                "/srtool/build --app > /build/runtime/srtool-output.log",
            ],
            source=source,
            output=output,
            stage="runtime_compile",
            completed=2,
            planning=(600, 10800),
        )
        build_log = source / "runtime/srtool-output.log"
        if build_log.stat().st_size > 64 * 1024**2:
            raise ValueError("srtool output exceeds its qualification bound")
        build = json.loads(build_log.read_bytes().splitlines()[-1])
        save(output / "subtensor-digest.json", build)
        artifacts = [
            p
            for p in (source / "runtime").rglob("node_subtensor_runtime.compact.compressed.wasm")
            if "srtool" in p.parts and "production" in p.parts and not p.is_symlink()
        ]
        if len(artifacts) != 1 or not 0 < artifacts[0].stat().st_size <= 16 * 1024**2:
            raise ValueError("built runtime artifact identity or size is ambiguous")
        raw = artifacts[0].read_bytes()
        (output / "subtensor.wasm").write_bytes(raw)
        result = validate_build(
            raw,
            build,
            revision=revision,
            code_sha256=args.code_sha256,
            spec_version=args.spec_version,
        )
        result.update(
            schema="umi-runtime-source-build-comparison/1", elapsed_seconds=time.monotonic() - start
        )
        save(output / "result.json", result)
        print(json.dumps({"stage": "completed", "completed": 4, "total": 4, **result}), flush=True)
    except Exception as error:
        save(
            output / "failure.json",
            {
                "schema": "umi-runtime-source-build-comparison-refusal/1",
                "error_type": type(error).__name__,
                "elapsed_seconds": time.monotonic() - start,
                "source_build_correspondence_established": False,
                "profile_authorized": False,
            },
        )
        raise
    finally:
        build_log = source / "runtime/srtool-output.log"
        if build_log.exists() and build_log.stat().st_size <= 64 * 1024**2:
            shutil.copyfile(build_log, output / "srtool.log")


if __name__ == "__main__":
    main()
