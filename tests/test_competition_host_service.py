from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_service as service
from umi.competition_host_anchor import MaterializedSuccessorAnchor
from umi.competition_host_artifacts import VerifiedHostTree
from umi.competition_host_upgrade import StoppedSupervisor


def _fixture_capability(kind, **values):
    result = object.__new__(kind)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


@pytest.fixture
def case(monkeypatch):
    # Capability issuers, root ownership, signatures and stopped journals are
    # tested in their modules. This fixture replaces those checks to exercise
    # exact service rendering and cross-capability bindings without systemd.
    events = []
    monkeypatch.setattr(StoppedSupervisor, "recheck_stopped", lambda self: events.append("stopped"))
    monkeypatch.setattr(
        MaterializedSuccessorAnchor, "recheck", lambda self: events.append("anchor")
    )
    monkeypatch.setattr(VerifiedHostTree, "recheck", lambda self: events.append("tree"))
    monkeypatch.setattr(
        service, "verify_host_artifact_authority", lambda *a, **kw: events.append("authority")
    )
    user = SimpleNamespace(
        pw_name="umi-validator", pw_uid=1001, pw_dir="/var/lib/umi-validator-supervisor/home"
    )
    monkeypatch.setattr(service.pwd, "getpwuid", lambda uid: user)
    config = SimpleNamespace(
        state_root="/var/lib/umi-validator-supervisor/state",
        validator_hotkey="public-hotkey-only",
        target_platform="linux/arm64",
    )
    receipt = SimpleNamespace(
        source_config_sha256="11" * 32,
        legacy_installation_sha256="22" * 32,
        host_manifest_sha256="33" * 32,
        host_umi_git_revision="44" * 20,
        checkpoint_sha256="55" * 32,
    )
    chain = SimpleNamespace(
        target_triple="aarch64-unknown-linux-gnu",
        proof_binary_sha256="66" * 32,
        finality_pin=SimpleNamespace(
            release_sha256_by_target={"aarch64-unknown-linux-gnu": "77" * 32},
            chain_spec_sha256="88" * 32,
        ),
    )
    records = [
        SimpleNamespace(
            path="artifacts/umi-grandpa-finality-observer", sha256="77" * 32, mode=0o555
        ),
        SimpleNamespace(
            path="artifacts/umi-substrate-proof-verifier", sha256="66" * 32, mode=0o555
        ),
        SimpleNamespace(path="artifacts/raw_spec_finney.json", sha256="88" * 32, mode=0o444),
        SimpleNamespace(path=".venv/bin/umi-competition-supervisor", sha256="99" * 32, mode=0o555),
        SimpleNamespace(
            path=".venv/bin/umi-competition-supervisor-cleanup", sha256="aa" * 32, mode=0o555
        ),
    ]
    signed = SimpleNamespace(
        manifest=SimpleNamespace(
            umi_git_revision=receipt.host_umi_git_revision,
            target_platform="linux/arm64",
            files=records,
        )
    )
    stopped = _fixture_capability(
        StoppedSupervisor,
        config_sha256=receipt.source_config_sha256,
        installation_sha256=receipt.legacy_installation_sha256,
        service_uid=1001,
        validator_hotkey=config.validator_hotkey,
        unit_name="umi-validator-supervisor.service",
        _lease=SimpleNamespace(config_path=Path("/etc/umi/validator-supervisor.json")),
    )
    anchor = _fixture_capability(
        MaterializedSuccessorAnchor,
        config=config,
        receipt=receipt,
        service_uid=1001,
        observer_config=SimpleNamespace(chain=chain),
        source_root=Path(config.state_root) / "successor-v4/activation-source",
    )
    tree = _fixture_capability(
        VerifiedHostTree,
        manifest_sha256=receipt.host_manifest_sha256,
        umi_git_revision=receipt.host_umi_git_revision,
        target_platform="linux/arm64",
        path=Path("/opt/umi-validator-supervisor-hosts") / receipt.host_umi_git_revision,
    )
    return SimpleNamespace(
        stopped=stopped, anchor=anchor, tree=tree, signed=signed, user=user, events=events
    )


def _plan(case):
    return service.plan_successor_service_switch(
        stopped=case.stopped, anchor=case.anchor, host_tree=case.tree, signed_host=case.signed
    )


def test_plan_binds_parent_mount_exact_hotkey_service_and_cleanup_without_writes(case, monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("service planning mutated disk or started a process")

    monkeypatch.setattr(Path, "write_bytes", denied)
    result = _plan(case)
    text = result.drop_in_bytes.decode()
    assert result.drop_in_path == Path(
        "/etc/systemd/system/umi-validator-supervisor.service.d/50-umi-successor.conf"
    )
    assert result.drop_in_sha256 == hashlib.sha256(result.drop_in_bytes).hexdigest()
    assert result.cleanup_unit_name == "umi-validator-supervisor-successor-cleanup.service"
    assert result.cleanup_unit_path == Path("/etc/systemd/system") / result.cleanup_unit_name
    assert result.cleanup_unit_sha256 == hashlib.sha256(result.cleanup_unit_bytes).hexdigest()
    cleanup_text = result.cleanup_unit_bytes.decode()
    assert "OnFailure=" + result.cleanup_unit_name in text
    assert "User=umi-validator\n" in cleanup_text
    assert "Type=oneshot\n" in cleanup_text and "Restart=no\n" in cleanup_text
    assert "Bind" not in cleanup_text and "ProtectHome=" not in cleanup_text
    assert (
        "umi-competition-supervisor-cleanup --config /etc/umi/validator-supervisor.json"
        in cleanup_text
    )
    assert "Requires=user@1001.service" in text
    assert f"BindReadOnlyPaths={case.anchor.source_root}:/run/umi-successor-activation" in text
    assert "activation-source/current:" not in text
    assert "successor-observer:/var/lib/umi-competition/finality" in text
    assert "umi-competition-supervisor-cleanup --config /etc/umi/validator-supervisor.json" in text
    assert "/run/user/1001" in text
    assert "ProtectHome=tmpfs\n" in text
    assert "BindPaths=/run/user/1001\n" in text
    assert "BindPaths=/run/user\n" not in text
    assert "ExecStopPost=+/usr/sbin/runuser -u umi-validator -- /usr/bin/env -i " in text
    assert "PYTHONPATH" not in text and "coldkey" not in text
    assert "User=" not in text and "Group=" not in text
    assert case.events == ["stopped", "anchor", "tree", "authority", "stopped", "anchor", "tree"]


@pytest.mark.parametrize(
    "value",
    [
        "relative",
        "/",
        "/var//lib",
        "/var/../etc",
        "/var/lib/a b",
        "/var/lib/a%h",
        "/var/lib/a\nExecStart=x",
        "/var/lib/a:b",
        "/var/lib/$HOME",
    ],
)
def test_unit_paths_cannot_inject_systemd_tokens(value):
    with pytest.raises(ValueError):
        service._path(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("config_sha256", "ab" * 32),
        ("installation_sha256", "ab" * 32),
        ("service_uid", 1002),
        ("validator_hotkey", "another-validator"),
    ],
)
def test_cross_validator_or_installation_plan_is_rejected(case, field, value):
    object.__setattr__(case.stopped, field, value)
    with pytest.raises(ValueError, match="different installations"):
        _plan(case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_sha256", "ab" * 32),
        ("umi_git_revision", "ab" * 20),
        ("target_platform", "linux/amd64"),
    ],
)
def test_other_host_tree_rejected(case, field, value):
    object.__setattr__(case.tree, field, value)
    with pytest.raises(ValueError, match="different installations"):
        _plan(case)


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4])
def test_missing_observer_or_cleanup_executable_rejected(case, index):
    case.signed.manifest.files.pop(index)
    with pytest.raises(ValueError, match="host manifest lacks"):
        _plan(case)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_observer_must_match_installed_hash_not_just_filename(case, index):
    case.signed.manifest.files[index].sha256 = "ff" * 32
    with pytest.raises(ValueError, match="exact installed observer"):
        _plan(case)


@pytest.mark.parametrize("home", ["/home/sam", "/var/lib", "/", "/Users/sam"])
def test_unreviewed_home_layout_rejected(case, home):
    case.user.pw_dir = home
    with pytest.raises(ValueError):
        _plan(case)


def test_non_capability_json_cannot_produce_plan(case):
    with pytest.raises(TypeError, match="genuine verified"):
        service.plan_successor_service_switch(
            stopped={"stopped": True},
            anchor=case.anchor,
            host_tree=case.tree,
            signed_host=case.signed,
        )


def test_closed_stopped_lease_prevents_plan(case, monkeypatch):
    def closed(self):
        raise ValueError("closed stopped lease")

    monkeypatch.setattr(StoppedSupervisor, "recheck_stopped", closed)
    with pytest.raises(ValueError, match="closed stopped lease"):
        _plan(case)
    assert case.events == []
