"""Retained startup compatibility and isolated upgrade/restart/repeat qualification.

The Studio startup is exact retained evidence. OS discovery, runtime installation,
service activation and enrollment are explicit synthetic ports. The parser,
secure startup reader, migration selection and local grant journal are native.
No test reads the retained startup's production directory.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from umi import miner as native_miner
from umi.competition_authorization import validate_transport_cohort
from umi.competition_cohort_miner_startup import CohortMinerStartupConfig
from umi.competition_cohort_service_work import (
    ServiceWorkClaim,
    SignedServiceWorkClaim,
    verify_service_claim,
)
from umi.competition_round_journal import RoundJournal
from umi.open_competition import CompetitionPolicy, sign_object
from umi.policy import ScoringPolicy
from umi.protocol import canonical_json_bytes

from .test_miner_upgrade import ROOT, SCRIPT, _manifest, _status, upgrade
from .test_open_competition import wallet

# Reconstructed from the retained 2026-10-12 Studio inspection; hash matches the
# original startup. Embedding avoids a dependency on private operational paths.
RETAINED_STARTUP = (
    b'{"authority":{"cohorts":[{"authority_sha256":"57d4bc831ba36a0bb45f690476f07df5cf12df9'
    b'23d403314fd03efbde22e6fad","cohort_sha256":"5dab3bfb836a91898f010bd229115e3e1c0406c3e'
    b'17498d3b3b1975adab71428"}],"directory":"/Users/sam/.local/share/umi/competition-studi'
    b'o-c5-ea32437/state/grants","maximum_bytes":1073741824,"maximum_grants":4096,"miner_ho'
    b'tkey":"5ELi42xAPAm2vDyvRoe2qpXbCeyPqqyB8rJzjkBxyEJXijXM","model_revision":"b1c104b801'
    b'331fc6ccb816f042760e34636c1808ac96e28864a46c3449a6c8bb","policy_sha256":"61f6c0514380'
    b'4c297aed524b6e067233567d30fe4eb50ab3289e7bfdad8e26fa","read_timeout_seconds":300,"sch'
    b'ema":"umi-cohort-service-miner-config/1","service_terms_sha256":"5364a993a30a7e06defc'
    b'c117d1447fbb000aa2894eae6224b57af7ae43dcb479","serving_origin":"https://studio-miner.'
    b'sam-sn78.workers.dev","transport_policy_sha256":"f182c1cbfa3985338944735cc55b52b46b12'
    b'b0207436d79dd5978087483f01a8"},"history_origin":"https://api.umi.vision","history_own'
    b'er_hotkey":"5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ","schema":"umi-cohort-mi'
    b'ner-startup/1"}'
)
RETAINED_STARTUP_SHA256 = "b351a019571dee3fd3021693f44a63a6c11b3b2f2d894321101e854e09408d80"
LOCAL_LIMITS = {
    "maximum_grants": (1, 65536),
    "maximum_bytes": (1024, 16 * 1024**3),
    "read_timeout_seconds": (1, 3600),
}


def _identity():
    authority = json.loads(RETAINED_STARTUP)["authority"]
    return tuple(authority[name] for name in ("miner_hotkey", "model_revision", "serving_origin"))


def _arguments(startup_path):
    _, model, origin = _identity()
    return [
        "/old/bin/python",
        "-I",
        "-B",
        "-m",
        "umi.miner",
        "--competition-cohort-config",
        str(startup_path),
        "--model-revision",
        model,
        "--serving-origin",
        origin,
        "--port",
        "8091",
        "--wallet-name",
        "miner",
        "--hotkey",
        "miner",
        "--wallet-path",
        "wallets",
        "--nonce-db",
        "protocol/nonces.sqlite3",
        "--assignment-db",
        "protocol/assignments.sqlite3",
        "--finality-state",
        "protocol/finality.sqlite3",
    ]


def _migrate(tmp_path, raw):
    source = tmp_path / "startup.json"
    source.write_bytes(raw)
    source.chmod(0o600)
    before = source.stat()
    target = tmp_path / "target"
    result = upgrade.migration_startup(
        _arguments("startup.json"), _manifest(), target, *_identity(), tmp_path
    )
    assert source.read_bytes() == raw
    assert source.stat().st_ino == before.st_ino
    assert not target.exists()
    return result


def test_exact_retained_studio_startup_is_native_valid_and_preserved(tmp_path):
    assert upgrade.sha256(RETAINED_STARTUP) == RETAINED_STARTUP_SHA256
    parsed = CohortMinerStartupConfig.model_validate_json(RETAINED_STARTUP)
    assert parsed.authority.maximum_grants == 4096
    assert parsed.authority.maximum_bytes == 1024**3
    assert parsed.authority.read_timeout_seconds == 300
    expected = (RETAINED_STARTUP, "cohort_runtime_in_place")
    assert _migrate(tmp_path, RETAINED_STARTUP) == expected
    assert _migrate(tmp_path, RETAINED_STARTUP) == expected


@pytest.mark.parametrize("field", tuple(LOCAL_LIMITS))
@pytest.mark.parametrize("selection", ["omitted", "minimum", "maximum"])
def test_native_optional_limits_keep_exact_values_and_omissions(tmp_path, field, selection):
    value = json.loads(RETAINED_STARTUP)
    if selection == "omitted":
        value["authority"].pop(field)
    else:
        value["authority"][field] = LOCAL_LIMITS[field][selection == "maximum"]
    raw = canonical_json_bytes(value)
    CohortMinerStartupConfig.model_validate_json(raw)
    retained, kind = _migrate(tmp_path, raw)
    assert retained == raw and kind == "cohort_runtime_in_place"
    assert json.loads(retained) == value


@pytest.mark.parametrize("field", tuple(LOCAL_LIMITS))
@pytest.mark.parametrize("invalid", ["below", "above", "bool", "float", "str", "null"])
def test_invalid_optional_limits_refuse_before_writes(tmp_path, field, invalid):
    minimum, maximum = LOCAL_LIMITS[field]
    value = json.loads(RETAINED_STARTUP)
    value["authority"][field] = {
        "below": minimum - 1,
        "above": maximum + 1,
        "bool": True,
        "float": float(minimum),
        "str": str(minimum),
        "null": None,
    }[invalid]
    # json.dumps deliberately retains the JSON float token; RFC 8785 would
    # render an integral float as an integer before the strict parser saw it.
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValidationError):
        CohortMinerStartupConfig.model_validate_json(raw)
    source = tmp_path / "startup.json"
    source.write_bytes(raw)
    with pytest.raises(ValueError, match="unsupported installed cohort"):
        upgrade.migration_startup(
            _arguments(source), _manifest(), tmp_path / "target", *_identity(), tmp_path
        )
    assert source.read_bytes() == raw
    assert not (tmp_path / "target").exists()


@pytest.mark.parametrize(
    ("where", "field", "replacement"),
    [
        ("startup", "schema", "unsupported-startup/9"),
        ("startup", "unknown", 1),
        ("startup", "history_origin", "https://changed.example"),
        ("authority", "unknown", 1),
        ("authority", "schema", "unsupported-authority/9"),
        ("authority", "policy_sha256", "ab" * 32),
        ("authority", "transport_policy_sha256", "ab" * 32),
        ("authority", "service_terms_sha256", "ab" * 32),
        ("authority", "miner_hotkey", wallet("Alice").hotkey.ss58_address),
        ("authority", "cohorts", []),
        ("authority", "directory", "relative/grants"),
        ("authority", "directory", "/"),
        ("authority", "directory", "/tmp/parent/../grants"),
    ],
)
def test_unsupported_authority_or_layout_refuses_without_reset(tmp_path, where, field, replacement):
    value = json.loads(RETAINED_STARTUP)
    selected = value if where == "startup" else value["authority"]
    selected[field] = replacement
    raw = canonical_json_bytes(value)
    source = tmp_path / "startup.json"
    source.write_bytes(raw)
    original = source.stat()
    with pytest.raises(ValueError, match="unsupported installed"):
        upgrade.migration_startup(
            _arguments(source), _manifest(), tmp_path / "target", *_identity(), tmp_path
        )
    assert source.read_bytes() == raw
    assert source.stat().st_ino == original.st_ino
    assert not (tmp_path / "target").exists()


def test_sidecar_relative_config_uses_its_service_working_directory(tmp_path, monkeypatch):
    state = tmp_path / "state"
    (state / "inputs").mkdir(parents=True)
    service_cwd = tmp_path / "model-cwd"
    service_cwd.mkdir()
    caller_cwd = tmp_path / "caller-cwd"
    caller_cwd.mkdir()
    monkeypatch.chdir(caller_cwd)
    socket = str(tmp_path / "old.sock")
    transport = "ab" * 32
    Path(socket + ".capacity.json").write_bytes(
        canonical_json_bytes(
            {
                "process_id": 123,
                "scoring_policy_sha256": transport,
                "model_revision": "cd" * 32,
                "maximum_inference_milliseconds": 120000,
            }
        )
    )
    original = canonical_json_bytes(
        {
            "schema": "umi-community-model-service/1",
            "socket_path": socket,
            "scoring_policy_sha256": transport,
            "validator_slot_count": 1,
            "workers": [
                {
                    "inference_seconds": 120,
                    "model_revision": "cd" * 32,
                    "command": ["/model/python", "worker.py"],
                    "scratch_directory": "scratch",
                }
            ],
        }
    )
    config = service_cwd / "model.json"
    config.write_bytes(original)
    (caller_cwd / "model.json").write_bytes(b"wrong cwd must never be consulted")
    account = SimpleNamespace(pw_name="miner", pw_uid=os.getuid(), pw_gid=os.getgid())
    sidecar = upgrade.Service(
        name="umi-model.service",
        pid=123,
        user=account.pw_name,
        arguments=[
            "/model/python",
            "--config",
            "model.json",
            "--expected-config-sha256",
            upgrade.sha256(original),
        ],
        working_directory=service_cwd,
    )
    arguments = ["/new/python", "-m", "umi.miner", "--translator-unix-socket", socket]
    monkeypatch.setattr(upgrade, "runtime_inference_seconds", lambda *_: 600)
    monkeypatch.setattr(upgrade, "unit_for_pid", lambda _: sidecar.name)
    monkeypatch.setattr(upgrade, "service", lambda _: sidecar)
    selected, updated, new_socket = upgrade.prepare_sidecar(arguments, state, account, transport)
    assert selected.user == sidecar.user
    assert selected.working_directory == service_cwd
    assert config.read_bytes() == original
    assert upgrade.option(sidecar.arguments, "--config") == "model.json"
    new_config = Path(upgrade.option(selected.arguments, "--config"))
    document = json.loads(new_config.read_bytes())
    assert document["workers"][0] == {
        "inference_seconds": 600,
        "model_revision": "cd" * 32,
        "command": ["/model/python", "worker.py"],
        "scratch_directory": "scratch",
    }
    assert upgrade.option(updated, "--translator-unix-socket") == str(new_socket)


def _main_harness(tmp_path, monkeypatch, *, cohort=True, account_name="miner"):
    """Synthetic service ports with real files, native config checks and journal."""
    manifest = _manifest()
    state = tmp_path / "managed" / manifest["policy"]["value_sha256"][:16]
    inputs = state / "inputs"
    inputs.mkdir(parents=True)
    cwd = tmp_path / "original-service-cwd"
    cwd.mkdir()
    (cwd / "protocol").mkdir()
    raw_value = json.loads(RETAINED_STARTUP)
    # This is a new local fixture binding, never a relocated production journal.
    raw_value["authority"]["directory"] = str(cwd / "grants")
    startup_raw = canonical_json_bytes(raw_value)
    startup_path = cwd / "startup.json"
    startup_path.write_bytes(startup_raw)
    startup_path.chmod(0o600)
    arguments = _arguments("startup.json")
    if not cohort:
        upgrade.remove_option(arguments, "--competition-cohort-config")
    account = SimpleNamespace(
        pw_name=account_name, pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(cwd)
    )
    current = [upgrade.Service("umi-miner.service", 123, account_name, arguments, cwd)]
    policy_raw = (ROOT / "docs/competition/C5_POLICY.json").read_bytes()
    transport_raw = (ROOT / "docs/competition/C5_TRANSPORT_POLICY.json").read_bytes()
    for name, raw in (("competition-policy", policy_raw), ("transport-policy", transport_raw)):
        (inputs / (name + ".json")).write_bytes(raw)
    monkeypatch.setattr(upgrade, "ROOT", state.parent)
    monkeypatch.setattr(upgrade, "RUNTIME_ROOT", tmp_path / "runtimes")
    target_python = upgrade.runtime_directory(manifest["runtime"], inputs / "transport-policy.json")
    target_python = target_python / "venv/bin/python"
    responses = {
        upgrade.DEFAULT_MANIFEST: canonical_json_bytes(manifest),
        upgrade.DEFAULT_STATUS: canonical_json_bytes(_status(manifest)),
        manifest["policy"]["url"]: policy_raw,
        manifest["transport"]["url"]: transport_raw,
    }
    monkeypatch.setattr(upgrade, "fetch", lambda url, **_: responses[url])
    monkeypatch.setattr(upgrade, "discover_miner", lambda: current[0])
    if not cohort:
        monkeypatch.setattr(upgrade, "miner_identity", lambda *_: _identity())
    monkeypatch.setattr(upgrade.pwd, "getpwnam", lambda _: account)
    monkeypatch.setattr(upgrade.sys, "platform", "linux")
    monkeypatch.setattr(upgrade.shutil, "which", lambda _: "/bin/systemctl")
    real_euid = os.geteuid
    monkeypatch.setattr(upgrade.os, "geteuid", lambda: 0)
    monkeypatch.setattr(upgrade, "acquire_upgrade_lock", lambda: None)
    monkeypatch.setattr(
        upgrade,
        "unit_controls",
        lambda entry: {"files": {}, "working_directory": str(entry.working_directory)},
    )
    monkeypatch.setattr(upgrade.os, "chown", lambda *_: None)

    def secure_directory(path):
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.chmod(0o755)

    monkeypatch.setattr(upgrade, "secure_root", secure_directory)
    monkeypatch.setattr(upgrade, "install_launcher", lambda *_: None)
    monkeypatch.setattr(upgrade, "prepare_sidecar", lambda command, *_: (None, command, None))
    monkeypatch.setattr(
        upgrade, "runtime_limits", lambda *_: {"inference_seconds": 600, "startup_seconds": 3600}
    )
    installed, activated, validated, enrolled = [], [], [], []

    def install(_old, _runtime, selected_account, _transport):
        assert selected_account is account
        installed.append(target_python)
        return target_python

    def validate(command, selected_account, working_directory, hotkey, selected_manifest):
        assert selected_account is account
        assert selected_manifest == manifest
        assert working_directory == cwd
        with monkeypatch.context() as native:
            native.setattr(os, "geteuid", real_euid)
            native.chdir(working_directory)
            documents = {
                flag: native_miner._read_startup_file(upgrade.option(command, flag))
                for flag in ("--policy", "--competition-policy", "--competition-cohort-config")
            }
            assert upgrade.sha256(documents["--competition-policy"]) == manifest["policy"]["sha256"]
            assert upgrade.sha256(documents["--policy"]) == manifest["transport"]["sha256"]
            policy = CompetitionPolicy.model_validate_json(documents["--competition-policy"])
            transport = ScoringPolicy.model_validate_json(documents["--policy"])
            startup = CohortMinerStartupConfig.model_validate_json(
                documents["--competition-cohort-config"]
            )
            validate_transport_cohort(policy, transport)
            startup.check(
                policy=policy,
                transport=transport,
                miner_hotkey=hotkey,
                model_revision=upgrade.option(command, "--model-revision"),
                serving_origin=upgrade.option(command, "--serving-origin"),
                state_files=[
                    upgrade.option(command, flag)
                    for flag in ("--nonce-db", "--assignment-db", "--finality-state")
                ],
            )
        validated.append(documents)

    def activate(**kwargs):
        assert validated, "native startup validation must precede service activation"
        assert kwargs["miner"].user == account_name
        assert kwargs["miner"].working_directory == cwd
        command = json.loads(kwargs["miner_command_path"].read_bytes())["arguments"]
        activated.append(command)
        current[0] = replace(current[0], arguments=command)
        return {"ok": True}

    def health(*_args, **_kwargs):
        assert len(validated) > len(activated), "repeat must validate before accepting health"
        return {"ok": True}

    def enroll(**kwargs):
        assert kwargs["account"] is account
        enrolled.append(kwargs)
        return {"status": "retained_request_reused"}

    monkeypatch.setattr(upgrade, "install_runtime", install)
    monkeypatch.setattr(upgrade, "validate_startup", validate)
    monkeypatch.setattr(upgrade, "activate_services", activate)
    monkeypatch.setattr(upgrade, "wait_health", health)
    monkeypatch.setattr(upgrade, "install_endpoint_enrollment", enroll)
    monkeypatch.setattr(upgrade, "run", lambda *_a, **_k: pytest.fail("unexpected OS service call"))
    monkeypatch.setattr(upgrade.sys, "argv", [str(SCRIPT), "--public-model-track", "no"])
    return SimpleNamespace(
        manifest=manifest,
        state=state,
        cwd=cwd,
        startup_raw=startup_raw,
        current=current,
        target_python=target_python,
        installed=installed,
        activated=activated,
        validated=validated,
        enrolled=enrolled,
    )


@pytest.mark.parametrize(
    ("cohort", "prior_status"),
    [(False, "miner_upgrade_verified"), (False, "upgrade_failed"), (True, "upgrade_failed")],
)
def test_current_runtime_receipt_cannot_skip_required_migration(
    tmp_path, monkeypatch, capsys, cohort, prior_status
):
    p = _main_harness(tmp_path, monkeypatch, cohort=cohort)
    p.current[0].arguments[0] = str(p.target_python)
    prior = {
        "policy_sha256": p.manifest["policy"]["value_sha256"],
        "runtime_revision": p.manifest["runtime"]["revision"],
        "status": prior_status,
    }
    (p.state / "upgrade-receipt.json").write_bytes(canonical_json_bytes(prior))
    upgrade.main()
    assert json.loads(capsys.readouterr().out)["status"] == "miner_upgrade_verified"
    assert len(p.installed) == len(p.activated) == len(p.validated) == 1
    assert upgrade.option(p.current[0].arguments, "--competition-cohort-config") is not None


@pytest.mark.parametrize("account_name", ["root", "miner"])
def test_upgrade_restart_and_repeat_preserve_native_journal_and_relative_bindings(
    tmp_path, monkeypatch, capsys, account_name
):
    p = _main_harness(tmp_path, monkeypatch, account_name=account_name)
    config = CohortMinerStartupConfig.model_validate_json(p.startup_raw)
    authority = config.authority
    binding = authority.model_dump(mode="json", by_alias=True, exclude=set(LOCAL_LIMITS))
    journal = RoundJournal(Path(authority.directory), binding)
    signer = wallet("Alice")
    claim = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256="ab" * 32,
        hotkey=signer.hotkey.ss58_address,
        submission_sha256="cd" * 32,
        nonce="ef" * 32,
    )
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, signer))
    signed_raw = canonical_json_bytes(signed)
    journal.put("upgrade-test-claim", "retained", signed)
    protocol_paths = [
        p.cwd / upgrade.option(p.current[0].arguments, flag)
        for flag in ("--nonce-db", "--assignment-db", "--finality-state")
    ]
    for path in protocol_paths:
        path.write_bytes(b"opaque preexisting protocol state: " + path.name.encode())
    enrollment = p.state / "enrollment"
    enrollment.mkdir(mode=0o700)
    signed_path = enrollment / "signed-request.json"
    signed_path.write_bytes(signed_raw)
    protected = [
        p.cwd / "startup.json",
        journal.path,
        journal.lock_path,
        signed_path,
        *protocol_paths,
    ]
    originals = {path: (path.stat().st_ino, path.read_bytes()) for path in protected}
    directory_identity = Path(authority.directory).stat().st_ino

    for iteration in range(2):
        upgrade.main()
        result = json.loads(capsys.readouterr().out)
        assert result["status"] == (
            "miner_upgrade_verified" if iteration == 0 else "already_upgraded"
        )
        assert len(p.activated) == len(p.installed) == 1
        assert len(p.validated) == len(p.enrolled) == iteration + 1
        assert p.current[0].user == account_name
        assert p.current[0].working_directory == p.cwd
        for flag, original_path in zip(
            ("--nonce-db", "--assignment-db", "--finality-state"), protocol_paths, strict=True
        ):
            value = upgrade.option(p.current[0].arguments, flag)
            assert not Path(value).is_absolute()
            assert p.cwd / value == original_path
        assert {path: (path.stat().st_ino, path.read_bytes()) for path in protected} == originals
        assert Path(authority.directory).stat().st_ino == directory_identity
        assert p.validated[-1]["--competition-cohort-config"] == p.startup_raw
        # Reopening is an actual native journal restart under the original
        # binding; the updater never opens or rebinds it.
        reopened = RoundJournal(Path(authority.directory), binding)
        assert reopened.get_raw("upgrade-test-claim", "retained") == signed_raw
        verify_service_claim(
            SignedServiceWorkClaim.model_validate_json(
                reopened.get_raw("upgrade-test-claim", "retained")
            )
        )
        reopened.put("upgrade-test-claim", "retained", signed)
        with reopened.read_transaction() as db:
            assert db.execute("SELECT body FROM binding").fetchone()[0] == canonical_json_bytes(
                binding
            )
        assert journal.path.stat().st_ino == originals[journal.path][0]
