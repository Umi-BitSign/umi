"""Collect selected functions once and execute reviewed callspecs with phase receipts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from types import FunctionType


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
    total = request["expected_count"]
    runtime_seconds = request["service_runtime_seconds"]
    if runtime_seconds not in (300, 600, 900):
        raise ValueError("unreviewed runtime bound")

    def parameter(value):
        if value is None or type(value) in (str, bool, int, float):
            return value
        if type(value) in (list, tuple):
            return [parameter(v) for v in value]
        if isinstance(value, FunctionType):
            return {"python_function": value.__module__ + "." + value.__qualname__}
        raise ValueError("unsupported callspec value type: " + type(value).__name__)
    output = args.output.resolve(strict=True)
    if any(output.iterdir()):
        raise ValueError("retained outputs exist; reuse completed cases before continuation")
    started = time.monotonic()

    def emit(kind, **values):
        row = dict(
            schema="umi-targeted-selected-test-event/1", kind=kind,
            observed_utc=datetime.now(timezone.utc).isoformat(),
            elapsed_seconds=round(time.monotonic() - started, 6),
            planning_eta_seconds=[0, max(0, runtime_seconds - int(time.monotonic() - started))],
            eta_basis="planning; bounded selected cases including interpreter imports",
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

    emit("runner_entered", completed=0, total=total, interpreter=sys.version)
    completed = {}
    result = dict(passed=False, completed=completed, requested_selections=request["selections"])
    try:
        if ".".join(map(str, sys.version_info[:3])) != request["python"]:
            raise ValueError("request interpreter differs")
        for module, expected in request["module_sha256"].items():
            if hashlib.sha256((source / module).read_bytes()).hexdigest() != expected:
                raise ValueError("reviewed test bytes changed: " + module)
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
                self.selected = []

            def pytest_collectstart(self, collector):
                emit("collector_start", nodeid=collector.nodeid)

            def pytest_collectreport(self, report):
                emit("collector_report", nodeid=report.nodeid, outcome=report.outcome)
                if report.failed:
                    self.collect_failed = True
                    save("collection-error.json", dict(nodeid=report.nodeid, detail=report.longreprtext))

            def pytest_itemcollected(self, item):
                self.nodes.append(item.nodeid)
                emit("item_collected", nodeid=item.nodeid, completed=len(self.nodes), total=request["expected_collected_count"])

            def pytest_collection_modifyitems(self, session, config, items):
                selected, deselected, identities = [], [], []
                found = {spec["selector"]: [] for spec in request["selections"]}
                selected_by_function = {spec["selector"]: [] for spec in request["selections"]}
                for item in items:
                    selector = item.nodeid.split("[", 1)[0]
                    specs = [s for s in request["selections"] if s["selector"] == selector]
                    if len(specs) != 1:
                        raise ValueError("unreviewed function collected: " + item.nodeid)
                    spec = specs[0]
                    params = {key: parameter(value) for key, value in getattr(getattr(item, "callspec", None), "params", {}).items()}
                    signature = json.dumps(params, sort_keys=True, separators=(",", ":"))
                    select_all = spec.get("select_all") is True
                    allowed = None if select_all else {json.dumps(p, sort_keys=True, separators=(",", ":")) for p in spec["allowed_collected_parameters"]}
                    wanted = None if select_all else {json.dumps(p, sort_keys=True, separators=(",", ":")) for p in spec["selected_parameters"]}
                    if (allowed is not None and signature not in allowed) or signature in found[selector]:
                        raise ValueError("unreviewed or duplicate callspec: " + item.nodeid)
                    found[selector].append(signature)
                    choose = select_all or signature in wanted
                    identities.append(dict(nodeid=item.nodeid, selector=selector, parameters=params, selected=choose))
                    if choose:
                        if item.nodeid in request["excluded_completed_nodes"]:
                            raise ValueError("completed case would be repeated: " + item.nodeid)
                        selected.append(item)
                        selected_by_function[selector].append(signature)
                    else:
                        deselected.append(item)
                for spec in request["selections"]:
                    selector = spec["selector"]
                    if spec.get("select_all") is True:
                        if len(found[selector]) != spec["expected_count"] or len(selected_by_function[selector]) != spec["expected_count"]:
                            raise ValueError("reviewed full-function count changed: " + selector)
                        if "expected_nodeids" in spec and {x["nodeid"] for x in identities if x["selector"] == selector} != set(spec["expected_nodeids"]):
                            raise ValueError("retained exact node identities changed: " + selector)
                        continue
                    expected = {json.dumps(p, sort_keys=True, separators=(",", ":")) for p in spec["allowed_collected_parameters"]}
                    wanted = {json.dumps(p, sort_keys=True, separators=(",", ":")) for p in spec["selected_parameters"]}
                    if set(found[selector]) != expected or set(selected_by_function[selector]) != wanted:
                        raise ValueError("callspec coverage differs from reviewed request: " + selector)
                if self.collect_failed or len(items) != request["expected_collected_count"] or len(selected) != total:
                    raise ValueError("case counts differ; no test execution")
                save("collected-identities.json", identities)
                save("selected-nodes.json", [item.nodeid for item in selected])
                save("deselected-nodes.json", [item.nodeid for item in deselected])
                self.selected = [item.nodeid for item in selected]
                items[:] = selected
                config.hook.pytest_deselected(items=deselected)
                emit("selection_complete", completed=total, total=total, selected=self.selected, deselected=[item.nodeid for item in deselected])

            def pytest_collection_finish(self, session):
                nodes = [item.nodeid for item in session.items]
                if self.collect_failed or len(nodes) != total or nodes != self.selected:
                    raise ValueError("collection differs from reviewed selection; no test execution")
                save("collected-nodes.json", nodes)
                emit("collection_complete", completed=total, total=total, nodeids=nodes)

            def pytest_runtest_logstart(self, nodeid, location):
                self.phases[nodeid] = {}
                emit("case_start", nodeid=nodeid, completed=len(completed), total=total)

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
                    emit("case_terminal", nodeid=report.nodeid, outcome=outcome, phases=phases, completed=len(completed), total=total)

        progress = Progress()
        emit("pytest_start", completed=0, total=total)
        code = pytest.main([
            "-q", "-p", "no:cacheprovider", "-p", "anyio.pytest_plugin", "-p", "pytest_asyncio.plugin",
            "-c", str(source / "pyproject.toml"), "--basetemp=" + str(args.scratch / "pytest"),
            "--junitxml=" + str(output / "results.xml"), *[node for s in request["selections"] for node in s.get("pytest_selectors", [s["selector"]])],
        ], plugins=[progress])
        result.update(pytest_exit_code=int(code), passed=code == 0 and len(completed) == total and set(completed.values()) == {"passed"})
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
