"""Collect once and execute four exact lifetime cases with durable phase receipts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not sys.flags.isolated or not sys.dont_write_bytecode or os.geteuid() == 0:
        raise ValueError("nonroot isolated Python required")
    source = Path(__file__).resolve().parents[1]
    request = json.loads(args.request.read_text())
    output = args.output.resolve(strict=True)
    if any(output.iterdir()):
        raise ValueError("retained outputs exist; reuse completed cases before continuation")
    started = time.monotonic()

    def emit(kind, **values):
        row = dict(
            schema="umi-targeted-lifetime-test-event/1", kind=kind,
            observed_utc=datetime.now(timezone.utc).isoformat(),
            elapsed_seconds=round(time.monotonic() - started, 6),
            planning_eta_seconds=[0, 300],
            eta_basis="planning; four exact fixture cases including interpreter imports",
            stalled_or_retrying=False,
        )
        row.update(values)
        with (output / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps(row), flush=True)

    def save(name, value):
        with (output / name).open("w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    emit("runner_entered", completed=0, total=4, interpreter=sys.version)
    completed = {}
    result = dict(passed=False, completed=completed, requested_nodes=request["expected_nodes"])
    try:
        if ".".join(map(str, sys.version_info[:3])) != request["python"]:
            raise ValueError("request interpreter differs")
        if hashlib.sha256((source / request["module"]).read_bytes()).hexdigest() != request["module_sha256"]:
            raise ValueError("reviewed test bytes changed")
        os.chdir(source)
        os.environ.update(
            PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
            TMPDIR=str(args.scratch), XDG_CACHE_HOME=str(args.scratch / "cache"),
        )
        sys.path[:0] = [str(source / "src"), str(source)]
        emit("pytest_import_start")
        import pytest
        emit("pytest_import_complete")
        emit("umi_import_start")
        import umi
        if not Path(umi.__file__).resolve().is_relative_to(source / "src"):
            raise ValueError("wrong source tree imported")
        emit("umi_import_complete")

        class Progress:
            def __init__(self):
                self.nodes = []
                self.phases = {}
                self.collect_failed = False

            def pytest_collectstart(self, collector):
                emit("collector_start", nodeid=collector.nodeid)

            def pytest_collectreport(self, report):
                emit("collector_report", nodeid=report.nodeid, outcome=report.outcome)
                if report.failed:
                    self.collect_failed = True
                    save("collection-error.json", dict(nodeid=report.nodeid, detail=report.longreprtext))

            def pytest_itemcollected(self, item):
                self.nodes.append(item.nodeid)
                emit("item_collected", nodeid=item.nodeid, completed=len(self.nodes), total=4)

            def pytest_collection_finish(self, session):
                nodes = [item.nodeid for item in session.items]
                if self.collect_failed or len(nodes) != 4 or set(nodes) != set(request["expected_nodes"]):
                    raise ValueError("collection differs from the four reviewed cases; no test execution")
                save("collected-nodes.json", nodes)
                emit("collection_complete", completed=4, total=4, nodeids=nodes)

            def pytest_runtest_logstart(self, nodeid, location):
                self.phases[nodeid] = {}
                emit("case_start", nodeid=nodeid, completed=len(completed), total=4)

            def pytest_runtest_logreport(self, report):
                row = dict(nodeid=report.nodeid, phase=report.when, outcome=report.outcome, duration_seconds=report.duration)
                if report.longrepr is not None:
                    name = hashlib.sha256((report.nodeid + "\0" + report.when).encode()).hexdigest() + ".json"
                    save(name, dict(detail=report.longreprtext))
                    row["detail_file"] = name
                emit("phase_outcome", **row)
                self.phases.setdefault(report.nodeid, {})[report.when] = report.outcome
                if report.when == "teardown":
                    phases = self.phases[report.nodeid]
                    outcome = "passed" if phases == dict(setup="passed", call="passed", teardown="passed") else "failed" if "failed" in phases.values() else "skipped" if "skipped" in phases.values() else "incomplete"
                    completed[report.nodeid] = outcome
                    emit("case_terminal", nodeid=report.nodeid, outcome=outcome, phases=phases, completed=len(completed), total=4)

        progress = Progress()
        emit("pytest_start", completed=0, total=4)
        code = pytest.main([
            "-q", "-p", "no:cacheprovider", "-p", "anyio.pytest_plugin", "-p", "pytest_asyncio.plugin",
            "-c", str(source / "pyproject.toml"), "--basetemp=" + str(args.scratch / "pytest"),
            "--junitxml=" + str(output / "results.xml"), request["selector"],
        ], plugins=[progress])
        result.update(pytest_exit_code=int(code), passed=code == 0 and len(completed) == 4 and set(completed.values()) == {"passed"})
        return int(code)
    except BaseException as error:
        result["error"] = repr(error)
        emit("runner_exception", error_type=type(error).__name__, detail=str(error))
        raise
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - started, 6)
        save("result.json", result)
        emit("runner_terminal", **result)


if __name__ == "__main__":
    raise SystemExit(main())
