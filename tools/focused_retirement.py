"""One bounded source qualification with durable individual test outcomes."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit

BASE = "f382e2a264666c267484ff0d4f9e652af967d784"
STYLE_PATHS = (
    "src/umi/competition_cpu_timing.py",
    "src/umi/host_cpu_conditions.py",
    "src/umi/host_cpu_partition.py",
    "src/umi/host_cpu_timing.py",
    "tests/test_competition_cpu_timing.py",
    "tests/test_cpu_partition_restoration.py",
    "tests/test_host_cpu_timing.py",
    "tests/test_host_cpu_core_classes.py",
)
TESTS = (
    "tests/test_competition_cohort_native_pipeline.py::test_accepted_model_reaches_native_reward_package[normal-precommit_model_inventory]",
    "tests/test_competition_cohort_native_pipeline.py::test_accepted_model_reaches_native_reward_package[outage-restart-precommit_model_inventory]",
    "tests/test_competition_imported_proof_retirement.py",
    "tests/test_competition_verification_rules.py",
    "tests/test_host_cpu_core_classes.py",
    "tests/test_host_cpu_timing.py",
    "tests/test_cpu_partition_restoration.py::test_restored_shared_slot_has_no_quota_but_owned_payloads_keep_exact_limit",
    "tests/test_competition_cpu_timing.py::test_owned_parent_preserves_accounting_after_short_container_exit",
    "tests/test_competition_cpu_timing.py::test_sampler_detects_changed_kernel_profile",
    "tests/test_competition_cpu_timing.py::test_sampler_rejects_missing_counters_or_changed_cpu_identity",
    "tests/test_competition_cpu_timing.py::test_sampler_refuses_symlink_cgroup_and_files",
    "tests/test_competition_cpu_timing.py::test_finite_shared_ancestor_quota_refuses_even_when_large",
    "tests/test_competition_cpu_timing.py::test_restored_ancestor_quota_cannot_hide_throttling",
    "tests/test_competition_cpu_timing.py::test_ancestor_usage_and_old_throttling_do_not_reject_owned_model_cost",
    "tests/test_competition_cpu_timing.py::test_ancestor_controls_cannot_disappear_or_reset",
    "tests/test_competition_cpu_timing.py::test_ancestry_depth_is_bounded_before_opening_kernel_directories",
    "tests/test_competition_cpu_timing.py::test_failed_ancestry_open_closes_all_pinned_descriptors",
)


def main():
    if os.geteuid() == 0 or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("isolated nonroot Python -I -B required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    scratch, output = args.scratch.resolve(strict=True), args.output.resolve(strict=True)
    if scratch != Path("/run/umi-retirement-public-v1") or any(scratch.iterdir()):
        raise ValueError("fresh service-owned scratch required")
    if any(output.iterdir()):
        raise ValueError("results already exist; completed work must not be replayed")
    if len(TESTS) != len(set(TESTS)):
        raise ValueError("duplicate selectors")
    os.chdir(source)
    os.environ.update(
        TMPDIR=str(scratch),
        XDG_CACHE_HOME=str(scratch / "cache"),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    started, stage = time.monotonic(), "format_and_manifest"

    def durable_file(path, data):
        with path.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def event(kind, **values):
        row = dict(
            schema="umi-focused-source-test-event/1",
            kind=kind,
            stage=stage,
            elapsed_seconds=round(time.monotonic() - started, 6),
            observed_utc=datetime.now(timezone.utc).isoformat(),
            planning_eta_seconds=[0, 1800],
            eta_basis="planning: two prior early failures, retirement boundary and bounded CPU metadata tests; no whole-suite throughput assumption",
            stalled_or_retrying=False,
        )
        row.update(values)
        with (output / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps(row, sort_keys=True), flush=True)

    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    manifest = source / "src/umi/competition_verification_rules.json"
    external = json.loads(manifest.read_bytes())["external_distributions"]
    result = dict(revision=revision, public_base=BASE, selectors=TESTS, passed=False)
    event("run_start", revision=revision, selectors=TESTS)
    try:
        try:
            for arguments in (
                [str(source / ".venv/bin/ruff"), "format", "--no-cache", *STYLE_PATHS],
                [str(source / ".venv/bin/ruff"), "check", "--no-cache", *STYLE_PATHS],
                [sys.executable, "-I", "-B", "tools/verification_manifest.py"],
            ):
                subprocess.run(arguments, check=True, timeout=120)
            if json.loads(manifest.read_bytes())["external_distributions"] != external:
                raise ValueError("qualified external dependency versions changed")
            durable_file(output / "competition_verification_rules.json", manifest.read_bytes())
        finally:
            patch = subprocess.check_output(
                ["git", "diff", "--binary", "--", "src", "tests"], timeout=30
            )
            durable_file(output / "public-output.patch", patch)

        stage = "focused_fixtures"
        binding = dict(
            revision=revision,
            source_tree=subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
            verification_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            qualification_patch_sha256=hashlib.sha256(patch).hexdigest(),
            locked_environment_sha256=hashlib.sha256((source / "uv.lock").read_bytes()).hexdigest(),
            interpreter=sys.version,
            resource_limits=dict(memory_max_bytes=1610612736, swap_max_bytes=0, cpu_quota_percent=200, runtime_max_seconds=2100),
            selectors=TESTS,
        )
        durable_file(output / "binding.json", (json.dumps(binding, indent=2) + "\n").encode())
        event("binding", **binding)

        def audit(name, arguments):
            if name != "sqlite3.connect":
                return
            value = os.fsdecode(arguments[0])
            if value == ":memory:":
                return
            if value.startswith("file:"):
                parsed = urlsplit(value)
                if parsed.netloc:
                    raise ValueError("SQLite URI authority is not fixture-local")
                if parse_qs(parsed.query).get("mode") == ["memory"]:
                    return
                value = unquote(parsed.path)
            if not Path(value).resolve().is_relative_to(scratch):
                raise ValueError("SQLite access must stay within test scratch")

        sys.addaudithook(audit)
        sys.path[:0] = [str(source / "src"), str(source)]
        import pytest
        import umi

        if not Path(umi.__file__).resolve().is_relative_to(source / "src"):
            raise ValueError("fixtures imported another source tree")

        class Progress:
            def __init__(self):
                self.nodes = []
                self.phases = {}
                self.completed = {}

            def pytest_collection_finish(self, session):
                self.nodes = [item.nodeid for item in session.items]
                if len(self.nodes) != len(set(self.nodes)):
                    raise ValueError("duplicate expanded test identities")
                if self.nodes[:2] != list(TESTS[:2]):
                    raise ValueError("the two native diagnostic cases must execute first")
                durable_file(output / "collected-nodes.json", (json.dumps(self.nodes, indent=2) + "\n").encode())
                event("collection", completed=0, total=len(self.nodes), nodeids=self.nodes)

            def pytest_runtest_logstart(self, nodeid, location):
                self.phases[nodeid] = {}
                event("case_start", nodeid=nodeid, completed=len(self.completed), total=len(self.nodes))

            def pytest_runtest_logreport(self, report):
                detail = report.longreprtext if report.longrepr is not None else None
                row = dict(nodeid=report.nodeid, phase=report.when, outcome=report.outcome, duration_seconds=report.duration)
                if detail:
                    name = hashlib.sha256((report.nodeid + "\0" + report.when).encode()).hexdigest() + ".txt"
                    durable_file(output / name, detail.encode())
                    row.update(failure_detail=detail, failure_detail_path=name, failure_detail_sha256=hashlib.sha256(detail.encode()).hexdigest())
                event("phase_outcome", **row)
                self.phases.setdefault(report.nodeid, {})[report.when] = report.outcome
                if report.when != "teardown":
                    return
                phases = self.phases[report.nodeid]
                if "failed" in phases.values():
                    outcome = "failed"
                elif "skipped" in phases.values():
                    outcome = "skipped"
                elif phases == dict(setup="passed", call="passed", teardown="passed"):
                    outcome = "passed"
                else:
                    outcome = "incomplete"
                self.completed[report.nodeid] = outcome
                event("case_terminal", nodeid=report.nodeid, outcome=outcome, phases=phases, completed=len(self.completed), total=len(self.nodes), counts={kind: list(self.completed.values()).count(kind) for kind in ("passed", "failed", "skipped", "incomplete")})

        progress = Progress()
        code = pytest.main(
            ["-q", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin", "-c", str(source / "pyproject.toml"), "--basetemp=" + str(scratch / "pytest"), "--junitxml=" + str(output / "results.xml"), *TESTS],
            plugins=[progress],
        )
        result.update(passed=code == 0, pytest_exit_code=int(code), completed=progress.completed, incomplete=[node for node in progress.nodes if node not in progress.completed])
        return int(code)
    except BaseException as error:
        result["error"] = repr(error)
        event("run_exception", error=repr(error))
        raise
    finally:
        result.update(stage=stage, elapsed_seconds=round(time.monotonic() - started, 6))
        durable_file(output / "result.json", (json.dumps(result, indent=2) + "\n").encode())
        event("run_terminal", **result)


if __name__ == "__main__":
    raise SystemExit(main())
