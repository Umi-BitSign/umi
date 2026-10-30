"""Direct requirement promotion keeps signed dependency contents unchanged."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from tests.test_build_successor_host import _build, _inventory, builder
from tests.test_build_successor_host import case as case
from tests.test_competition_host_artifacts import sign
from umi import competition_host_artifacts as artifacts
from umi.protocol import canonical_json_bytes

SITE = ".venv/lib/python3.12/site-packages"
REQUIREMENT = "transitive>=2,<3"
OLD_LOCK = """version = 1
revision = 3
requires-python = ">=3.10,<3.15"

[[package]]
name = "example"
version = "1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "transitive" }]

[[package]]
name = "transitive"
version = "2.5"
source = { registry = "https://pypi.org/simple" }
wheels = [
 { url = "https://f.example/transitive-2.5-py3-none-any.whl", hash = "sha256:abcd", size = 100 },
]

[[package]]
name = "umi-subnet"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "example" }]

[package.optional-dependencies]
dev = [{ name = "pytest" }]

[package.metadata]
requires-dist = [
 { name = "example", specifier = "==1" },
 { name = "pytest", marker = "extra == 'dev'", specifier = ">=9" },
]
provides-extras = ["dev"]
"""
NEW_LOCK = OLD_LOCK.replace(
    'dependencies = [{ name = "example" }]',
    'dependencies = [{ name = "example" }, { name = "transitive" }]',
).replace(
    "requires-dist = [",
    'requires-dist = [{ name = "transitive", specifier = ">=2,<3" }, ',
)


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o644)
    path.write_bytes(body if isinstance(body, bytes) else body.encode())
    path.chmod(0o444)


def resign(case):
    rows = [
        artifacts.HostArtifactFile(
            path=path.relative_to(case.previous).as_posix(),
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            size_bytes=path.stat().st_size,
            mode=path.stat().st_mode & 0o777,
        )
        for path in sorted(case.previous.rglob("*"))
        if path.is_file()
    ]
    rows.sort(key=lambda row: row.path)
    manifest = case.signed.manifest.model_copy(
        update={"files": rows, "total_size_bytes": sum(row.size_bytes for row in rows)}
    )
    case.signed = sign(manifest)
    case.arguments["maintenance_path"].write_bytes(
        canonical_json_bytes({"signed_host": case.signed.model_dump(mode="json", by_alias=True)})
    )
    case.arguments["previous_manifest_sha256"] = case.signed.manifest_sha256


def promotion(case):
    previous_project = (
        (case.previous / "pyproject.toml")
        .read_bytes()
        .replace(b'name = "umi-subnet"\n', b'name = "umi-subnet"\nversion = "0.1.0"\n')
    )
    candidate_project = previous_project.replace(
        b'dependencies = ["example==1"]',
        b'dependencies = ["example==1", "transitive>=2,<3"]',
    )
    write(case.previous / "pyproject.toml", previous_project)
    write(case.source / "pyproject.toml", candidate_project)
    write(case.previous / "uv.lock", OLD_LOCK)
    write(case.source / "uv.lock", NEW_LOCK)
    write(
        case.previous / SITE / "transitive-2.5.dist-info/METADATA",
        "Name: transitive\nVersion: 2.5\n",
    )
    write(case.previous / SITE / "transitive/__init__.py", "unchanged_dependency = True\n")
    resign(case)
    return case


def plan(case):
    return builder.project_metadata_migration(
        case.previous,
        {name: (case.source / name).read_bytes() for name in ("pyproject.toml", "uv.lock")},
        {item.path: item for item in case.signed.manifest.files},
    )


def test_promotion_reuses_signed_payloads_and_added_command_then_repeat(case):
    promotion(case)
    project = case.source / "pyproject.toml"
    write(project, project.read_bytes() + b'umi-extra = "umi.extra:main"\n')
    before = _inventory(case.previous)
    result = _build(case)
    tree = case.arguments["output_root"] / "unsigned-host/tree"
    assert result["uninstalled_added_project_scripts"] == ["umi-extra"]
    assert result["locked_dependency_migrations"] == []
    report = result["direct_dependency_promotions"]
    assert len(report) == 1
    assert report[0]["requirement"] == REQUIREMENT
    assert report[0]["version"] == "2.5"
    assert report[0]["dependency_payloads_changed"] is False
    assert report[0]["project_metadata_layout"] == "source_only_umi_pth"
    assert (tree / SITE / "transitive/__init__.py").read_bytes() == (
        case.previous / SITE / "transitive/__init__.py"
    ).read_bytes()
    assert _inventory(case.previous) == before
    prior = case.hosts / case.arguments["revision"]
    shutil.copytree(tree, prior)
    manifest = artifacts.SuccessorHostArtifactManifest.model_validate_json(
        (tree.parent / "host-manifest.unsigned.json").read_bytes()
    )
    case.arguments["maintenance_path"].write_bytes(
        canonical_json_bytes({"signed_host": sign(manifest).model_dump(mode="json", by_alias=True)})
    )
    repeated = _build(
        case,
        previous_revision=case.arguments["revision"],
        revision="ef" * 20,
        previous_manifest_sha256=result["manifest_sha256"],
        output_root=case.arguments["output_root"].with_name("repeat"),
    )
    assert repeated["direct_dependency_promotions"] == []
    assert repeated["uninstalled_added_project_scripts"] == []
    assert _inventory(case.previous) == before


def test_promotion_planning_reads_only_authenticated_metadata(case, monkeypatch):
    promotion(case)
    native = Path.read_bytes
    payload = case.previous / SITE / "transitive/__init__.py"

    def metadata_only(path):
        if path == payload:
            pytest.fail("promotion preflight must not verify dependency payloads again")
        return native(path)

    monkeypatch.setattr(Path, "read_bytes", metadata_only)
    assert plan(case)[1][0]["name"] == "transitive"


@pytest.mark.parametrize(
    "damage",
    [
        "changed_requirement",
        "removed_requirement",
        "extra",
        "marker",
        "url",
        "unsatisfied",
        "duplicate",
        "package_version",
        "package_source",
        "package_edges",
        "wheel_identity",
        "new_package",
        "missing_package",
        "ambiguous_package",
        "resolution",
        "root_source",
        "root_version",
        "root_optional",
        "root_marker",
        "requirement_marker",
        "missing_declaration",
        "duplicate_declaration",
        "unreachable",
        "direct_already",
        "other_project_metadata",
    ],
)
def test_promotion_refuses_unsupported_metadata_before_candidate(case, damage):
    promotion(case)
    project = (case.source / "pyproject.toml").read_text()
    locked = (case.source / "uv.lock").read_text()
    if damage == "changed_requirement":
        project = project.replace("example==1", "example==2")
    elif damage == "removed_requirement":
        project = project.replace('"example==1", ', "")
    elif damage in {"extra", "marker", "url", "unsatisfied", "duplicate"}:
        replacement = {
            "extra": "transitive[feature]>=2,<3",
            "marker": "transitive>=2,<3; python_version > '3.10'",
            "url": "transitive @ https://example/transitive.whl",
            "unsatisfied": "transitive>=3",
            "duplicate": 'transitive>=2,<3", "Transitive>=2',
        }[damage]
        project = project.replace(REQUIREMENT, replacement)
    elif damage == "package_version":
        locked = locked.replace('version = "2.5"', 'version = "2.6"')
    elif damage == "package_source":
        locked = locked.replace(
            'registry = "https://pypi.org/simple"', 'registry = "https://other/simple"', 1
        )
    elif damage == "package_edges":
        locked = locked.replace('dependencies = [{ name = "transitive" }]', "dependencies = []", 1)
    elif damage == "wheel_identity":
        locked = locked.replace("sha256:abcd", "sha256:other")
    elif damage == "new_package":
        locked += '\n[[package]]\nname="new"\nversion="1"\n'
    elif damage == "missing_package":
        locked = locked.replace(
            'name = "transitive"\nversion = "2.5"', 'name = "removed"\nversion = "2.5"'
        )
    elif damage == "ambiguous_package":
        locked += '\n[[package]]\nname="transitive"\nversion="3"\n'
    elif damage == "resolution":
        locked = locked.replace("revision = 3", "revision = 4")
    elif damage == "root_source":
        locked = locked.replace('editable = "."', 'editable = "elsewhere"')
    elif damage == "root_version":
        locked = locked.replace('version = "0.1.0"', 'version = "0.2.0"')
    elif damage == "root_optional":
        locked = locked.replace('provides-extras = ["dev"]', 'provides-extras = ["dev", "other"]')
    elif damage == "root_marker":
        locked = locked.replace(
            '{ name = "example" }, { name = "transitive" }',
            '{ name = "example" }, { name = "transitive", marker = "python_version > \'3.10\'" }',
        )
    elif damage == "requirement_marker":
        locked = locked.replace(
            'specifier = ">=2,<3"', 'specifier = ">=2,<3", marker = "extra == \'dev\'"'
        )
    elif damage == "missing_declaration":
        locked = locked.replace('{ name = "transitive", specifier = ">=2,<3" }, ', "")
    elif damage == "duplicate_declaration":
        locked = locked.replace(
            '{ name = "example" }, { name = "transitive" }',
            '{ name = "example" }, { name = "transitive" }, { name = "transitive" }',
        )
    elif damage == "unreachable":
        before = OLD_LOCK.replace(
            'dependencies = [{ name = "transitive" }]', "dependencies = []", 1
        )
        write(case.previous / "uv.lock", before)
        locked = locked.replace('dependencies = [{ name = "transitive" }]', "dependencies = []", 1)
        resign(case)
    elif damage == "direct_already":
        write(
            case.previous / "uv.lock",
            OLD_LOCK.replace(
                'dependencies = [{ name = "example" }]',
                'dependencies = [{ name = "example" }, { name = "transitive" }]',
            ),
        )
        resign(case)
    else:
        project = project.replace('version = "0.1.0"', 'version = "0.1.0"\ndescription = "changed"')
    write(case.source / "pyproject.toml", project)
    write(case.source / "uv.lock", locked)
    before = _inventory(case.previous)
    with pytest.raises(ValueError):
        _build(case)
    assert _inventory(case.previous) == before
    assert not case.arguments["output_root"].exists()


@pytest.mark.parametrize(
    "relative",
    ["pyproject.toml", "uv.lock", SITE + "/transitive-2.5.dist-info/METADATA", SITE + "/umi.pth"],
)
def test_promotion_requires_exact_signed_predecessor_metadata(case, relative):
    promotion(case)
    path = case.previous / relative
    write(path, path.read_bytes() + b"\ntampered\n")
    with pytest.raises(ValueError, match=r"selected signed.*metadata"):
        _build(case)
    assert not case.arguments["output_root"].exists()


@pytest.mark.parametrize(
    "kind",
    ["version", "name", "duplicate_name", "duplicate_version", "own_dist_info", "own_egg_info"],
)
def test_authenticated_metadata_cannot_contradict_promotion(case, kind):
    promotion(case)
    metadata = case.previous / SITE / "transitive-2.5.dist-info/METADATA"
    if kind == "version":
        write(metadata, "Name: transitive\nVersion: 2.4\n")
    elif kind == "name":
        write(metadata, "Name: other\nVersion: 2.5\n")
    elif kind == "duplicate_name":
        write(metadata, metadata.read_bytes() + b"Name: transitive\n")
    elif kind == "duplicate_version":
        write(metadata, metadata.read_bytes() + b"Version: 2.5\n")
    elif kind == "own_dist_info":
        write(
            case.previous / SITE / "umi_subnet-0.1.0.dist-info/METADATA",
            "Name: umi-subnet\nVersion: 0.1.0\nRequires-Dist: example==1\n",
        )
    else:
        write(case.previous / SITE / "umi_subnet.egg-info", "Name: umi-subnet\n")
    resign(case)
    with pytest.raises(ValueError, match="metadata"):
        _build(case)
    assert not case.arguments["output_root"].exists()


def test_promotion_does_not_mask_a_simultaneous_wheel_change(case):
    promotion(case)
    with pytest.raises(ValueError, match="cannot be combined"):
        _build(case, dependency_wheels=(case.source / "unread.whl",))
    assert not case.arguments["output_root"].exists()


@pytest.mark.parametrize("field", ["edges", "requirements"])
def test_two_promotions_cannot_substitute_one_name_alias_for_another(case, field):
    promotion(case)
    old = OLD_LOCK.replace(
        'dependencies = [{ name = "transitive" }]',
        'dependencies = [{ name = "transitive" }, { name = "another" }]',
        1,
    )
    old += '\n[[package]]\nname="another"\nversion="2.5"\nsource={registry="https://pypi.org/simple"}\n'
    new = old.replace(
        'dependencies = [{ name = "example" }]',
        'dependencies = [{ name = "example" }, { name = "transitive" }, { name = "another" }]',
    ).replace(
        "requires-dist = [",
        'requires-dist = [{ name = "transitive", specifier = ">=2,<3" }, '
        '{ name = "another", specifier = ">=2,<3" }, ',
    )
    write(case.previous / "uv.lock", old)
    write(case.source / "uv.lock", new)
    project = (
        (case.source / "pyproject.toml")
        .read_text()
        .replace('"transitive>=2,<3"', '"transitive>=2,<3", "another>=2,<3"')
    )
    write(case.source / "pyproject.toml", project)
    write(case.previous / SITE / "another-2.5.dist-info/METADATA", "Name: another\nVersion: 2.5\n")
    resign(case)
    assert {row["name"] for row in plan(case)[1]} == {"transitive", "another"}
    if field == "edges":
        new = new.replace(
            '{ name = "example" }, { name = "transitive" }, { name = "another" }',
            '{ name = "example" }, { name = "transitive" }, { name = "Transitive" }',
        )
    else:
        new = new.replace(
            '{ name = "another", specifier = ">=2,<3" }',
            '{ name = "Transitive", specifier = ">=2,<3" }',
        )
    write(case.source / "uv.lock", new)
    with pytest.raises(ValueError, match="missing or duplicate root declarations"):
        _build(case)
    assert not case.arguments["output_root"].exists()


def test_promotion_refuses_multiple_installed_distribution_versions(case):
    promotion(case)
    write(
        case.previous / SITE / "transitive-3.0.dist-info/METADATA",
        "Name: transitive\nVersion: 3.0\n",
    )
    resign(case)
    with pytest.raises(ValueError, match="installation is missing or ambiguous"):
        _build(case)
    assert not case.arguments["output_root"].exists()


def test_retained_project_and_lock_metadata_shape(case):
    evidence = json.loads(
        (Path(__file__).parent / "fixtures/host_direct_requirement_metadata.json").read_text()
    )
    for role, root in (("previous", case.previous), ("candidate", case.source)):
        write(root / "pyproject.toml", evidence[role + "_project"])
        write(root / "uv.lock", evidence[role + "_lock_excerpt"])
    write(
        case.previous / SITE / "anyio-4.15.0.dist-info/METADATA",
        "Metadata-Version: 2.4\nName: anyio\nVersion: 4.15.0\n",
    )
    resign(case)
    scripts, promotions = plan(case)
    assert scripts == []
    assert [(row["name"], row["version"]) for row in promotions] == [("anyio", "4.15.0")]
    assert b'"umi-subnet"' in (case.previous / "uv.lock").read_bytes()
    assert "python_full_version" in evidence["previous_lock_excerpt"]
    assert "provides-extras" in evidence["previous_lock_excerpt"]
