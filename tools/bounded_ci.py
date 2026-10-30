"""Recover only original failed nodes; collection is never a test-pass claim."""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys


def save(path, value):
    with path.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def event(stage, **values):
    print(json.dumps(dict(
        schema="umi-bounded-ci-selection-progress/1", stage=stage,
        observed_utc=datetime.now(timezone.utc).isoformat(),
        planning_eta_seconds=[0, 900],
        eta_basis="planning; bounded collection and identity mapping only, excludes selected execution",
        stalled_or_retrying=False, **values,
    )), flush=True)


def collect(args, spec):
    source = args.source.resolve(strict=True)
    os.chdir(source)
    sys.path[:0] = [str(source / "src"), str(source)]
    import pytest
    import umi
    if not Path(umi.__file__).resolve().is_relative_to(source / "src"):
        raise ValueError("collection imported the wrong source")
    if hashlib.sha256((source / "uv.lock").read_bytes()).hexdigest() != spec["uv_lock_sha256"]:
        raise ValueError("original and target locks must match the retained environment")
    nodes = []

    class Collection:
        def pytest_collection_finish(self, session):
            nodes.extend(item.nodeid for item in session.items)

    code = pytest.main([
        "--collect-only", "-q", "-p", "no:cacheprovider", "-p", "anyio.pytest_plugin",
        "-p", "pytest_asyncio.plugin", "-c", str(source / "pyproject.toml"),
        "--basetemp=" + str(args.scratch / "pytest"), *spec["modules"],
    ], plugins=[Collection()])
    if code or len(nodes) != len(set(nodes)):
        raise ValueError("collection failed or returned duplicate node identities")
    by_module = {module: [] for module in spec["modules"]}
    for node in nodes:
        by_module[node.split("::", 1)[0]].append(node)
    save(args.output, dict(
        schema="umi-bounded-ci-collection/1", collection_only=True, tests_executed=0,
        interpreter=sys.version, python=".".join(map(str, sys.version_info[:3])),
        packages={name: importlib.metadata.version(name) for name in ("pytest", "pytest-asyncio", "anyio", "pluggy")},
        uv_lock_sha256=spec["uv_lock_sha256"], modules=by_module,
    ))
    event("collection_complete", source=str(source), completed=len(nodes), total=len(nodes))


def pair(args, spec):
    source = args.source.resolve(strict=True)
    if args.scratch != Path("/run/umi-bounded-ci-v1") or any(args.scratch.iterdir()):
        raise ValueError("fresh service-owned scratch required")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if subprocess.check_output(["git", "rev-parse", "HEAD:src"], cwd=source, text=True).strip() != spec["target_src_tree"]:
        raise ValueError("production source differs from the reviewed target")
    if subprocess.check_output(["git", "rev-parse", "HEAD:tests"], cwd=source, text=True).strip() != spec["target_tests_tree"]:
        raise ValueError("test tree differs from the reviewed target")
    subprocess.run(["git", "merge-base", "--is-ancestor", spec["target_revision"], revision], cwd=source, check=True)
    for file, expected in spec["test_followup_files"].items():
        if hashlib.sha256((source / file).read_bytes()).hexdigest() != expected:
            raise ValueError("reviewed test fix changed: " + file)
    actual_python = ".".join(map(str, sys.version_info[:3]))
    if actual_python not in spec["python_versions"].values():
        raise ValueError("original CI interpreter patch version required")
    original = args.scratch / "original"
    original.mkdir()
    archive = subprocess.Popen(["git", "archive", spec["original_revision"]], cwd=source, stdout=subprocess.PIPE)
    try:
        subprocess.run(["tar", "-x", "-C", str(original)], stdin=archive.stdout, check=True, timeout=120)
    finally:
        archive.stdout.close()
    if archive.wait(timeout=30):
        raise ValueError("original source archive failed")
    args.output.mkdir(exist_ok=True)
    for label, tree in (("original", original), ("target", source)):
        event("collection_start", source=label, completed=0, total=len(spec["modules"]))
        subprocess.run([
            sys.executable, "-I", "-B", "-u", str(Path(__file__).resolve()), "collect",
            "--spec", str(args.spec.resolve()), "--source", str(tree),
            "--scratch", str(args.scratch), "--output", str(args.output / (label + ".json")),
        ], check=True, timeout=360)
    save(args.output / "binding.json", dict(
        workflow_revision=revision, target_revision=spec["target_revision"],
        original_revision=spec["original_revision"], python=actual_python,
        selection_input_sha256=hashlib.sha256(args.spec.read_bytes()).hexdigest(), tests_executed=0,
    ))


def plan(args, spec):
    pairs = {}
    workflow_revisions = set()
    for binding_path in sorted(args.collections.glob("*/binding.json")):
        binding = json.loads(binding_path.read_text())
        workflow_revisions.add(binding["workflow_revision"])
        version = binding["python"]
        if version in pairs or binding["target_revision"] != spec["target_revision"]:
            raise ValueError("duplicate or differently bound collection")
        if binding["selection_input_sha256"] != hashlib.sha256(args.spec.read_bytes()).hexdigest():
            raise ValueError("collection selected another input")
        old, new = [json.loads((binding_path.parent / (label + ".json")).read_text()) for label in ("original", "target")]
        if old["packages"] != new["packages"] or old["python"] != version or new["python"] != version:
            raise ValueError("original/target collection environment differs")
        if old["modules"] != new["modules"]:
            raise ValueError("original/target node count or identity/order changed; explicit mapping repair required")
        pairs[version] = new["modules"]
    if set(pairs) != set(spec["python_versions"].values()):
        raise ValueError("all three original interpreter collections required")
    if len(workflow_revisions) != 1:
        raise ValueError("collection jobs selected different workflow revisions")
    failed_versions, mapping = defaultdict(set), []
    for row in spec["original_markers"]:
        version = spec["python_versions"][row["python_minor"]]
        nodes = pairs[version][row["module"]]
        markers = row["markers"]
        if not row["subsequent_file_observed"] or len(nodes) != len(markers):
            raise ValueError("incomplete or mismatched module marker sequence: " + row["module"])
        for index, marker in enumerate(markers):
            if marker == "F":
                node = nodes[index]
                failed_versions[node].add(version)
                mapping.append(dict(nodeid=node, zero_based_position=index, job=row["job"], python=version))
    explicit = {}
    for row in spec["explicit"]:
        selector = row["selector"]
        nodes = pairs[row["python"]][selector.split("::")[0]]
        matched = [n for n in nodes if n == selector or n.startswith(selector + "[")]
        if len(matched) != row["expected_count"]:
            raise ValueError("explicit corrected-case expansion mismatch: " + selector)
        for node in matched:
            if node in explicit and explicit[node] != row["python"]:
                raise ValueError("conflicting explicit interpreter")
            explicit[node] = row["python"]
    excluded = set(spec["excluded_completed_nodes"])
    if excluded.intersection(explicit):
        raise ValueError("changed case was marked reused; explicit dependency review required")
    chosen = {}
    for node in set(failed_versions).union(explicit) - excluded:
        versions = failed_versions[node]
        version = explicit.get(node) or ("3.12.15" if "3.12.15" in versions else sorted(versions)[0])
        if node not in pairs[version][node.split("::")[0]]:
            raise ValueError("selected node absent on execution interpreter")
        chosen[node] = version
    groups = {}
    for node, version in sorted(chosen.items()):
        module = node.split("::")[0]
        native = "test_competition_cohort_native_" in module
        label = Path(module).stem.removeprefix("test_competition_cohort_") if native else "remaining_" + str(hashlib.sha256(module.encode()).digest()[0] % 4)
        name = version.replace(".", "_") + "_" + label
        group = groups.setdefault(name, dict(python=version, limit_seconds=3600 if native else 1800, format_fixture=False, nodes=[]))
        group["nodes"].append(node)
    args.output.mkdir(exist_ok=True)
    selection = dict(schema="umi-focused-source-groups/1", workflow_revision=next(iter(workflow_revisions)), qualified_runtime_revision=spec["qualified_runtime_revision"], manifest_sha256=spec["manifest_sha256"], groups=groups)
    save(args.output / "selection.json", selection)
    save(args.output / "mapping.json", dict(mapping=mapping, explicit_nodes=explicit, excluded_intersection=sorted(excluded.intersection(failed_versions)), selected_nodes=chosen, tests_executed=0))
    matrix = dict(include=[dict(group=n, python=g["python"], seconds=g["limit_seconds"]) for n, g in groups.items()])
    save(args.output / "matrix.json", matrix)
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
    event("selection_prepared", completed=len(chosen), total=len(chosen), group_count=len(groups), tests_executed=0)


def main():
    if not sys.flags.isolated or not sys.dont_write_bytecode or os.geteuid() == 0:
        raise ValueError("nonroot isolated Python -I -B required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "pair", "plan"))
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--collections", type=Path)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text())
    os.environ.update(PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    if args.scratch is not None:
        os.environ.update(TMPDIR=str(args.scratch), XDG_CACHE_HOME=str(args.scratch / "cache"))
    {"collect": collect, "pair": pair, "plan": plan}[args.mode](args, spec)


if __name__ == "__main__":
    main()
