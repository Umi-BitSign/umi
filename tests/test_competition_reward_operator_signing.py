"""Real isolated fixture signers and unchanged root publication semantics."""

import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor.keyfiles import serialized_keypair_to_keyfile_data

from umi import competition_reward_operator_signing as signing
from umi import competition_reward_transition_cli as cli
from umi.competition_reward_transition_controls import approval_path
from umi.protocol import canonical_json_bytes
from umi.substrate_proof import SubstrateProofVerifierError

from .test_competition_reward_transition_controls import (  # noqa: F401
    chain,
    chain_config,
    control,
    inputs,
    policy,
    public_deployment,
    selected,
    series_case,
    signed,
)
from .test_competition_reward_transition_controls import controls_case as controls_case
from .test_open_competition import wallet


@pytest.fixture
def operator(controls_case, tmp_path):
    case = controls_case
    key = tmp_path / "fixture-hotkey"
    key.write_bytes(bytes(serialized_keypair_to_keyfile_data(wallet("Ferdie").hotkey)))
    key.chmod(0o400)
    body = signed(case).approval
    config = SimpleNamespace(
        role="coordinator",
        reward_transition=case.config,
        series=case.series,
        policy=case.policy,
        control_key_file=str(key),
    )
    args = dict(
        predecessor=body.predecessor_decision_sha256,
        cohort=body.successor_cohort_sha256,
        package=body.successor_package_sha256,
        reason=body.reason,
    )
    return SimpleNamespace(case=case, key=key, body=body, config=config, args=args)


@pytest.mark.skipif(os.geteuid() != 0, reason="real service-owner child requires root")
@pytest.mark.parametrize("owner", ["root", "nobody"])
def test_actual_owner_child_root_publishes_and_exact_retry_never_signs(
    operator, owner, tmp_path, pytestconfig, monkeypatch, caplog
):
    op = operator
    account = pwd.getpwnam(owner)
    # Only this test's task-scoped ancestry becomes traversable by the fixture
    # service user. No production key or account-owned directory is changed.
    base = Path(pytestconfig.getoption("basetemp"))
    parent = tmp_path
    while parent.is_relative_to(base):
        parent.chmod(0o755)
        if parent == base:
            break
        parent = parent.parent
    os.chown(op.key, account.pw_uid, account.pw_gid)
    before = op.key.stat()
    caplog.set_level("INFO", logger="umi.competition.progress")
    first = cli.approve_successor(op.config, **op.args)
    path = Path(first["approval_path"])
    assert path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o444
    assert op.key.stat().st_uid == before.st_uid
    assert stat.S_IMODE(op.key.stat().st_mode) == 0o400
    assert first["chain_submission_authorized"] is False
    assert "reward_operator_signing" in caplog.text
    assert "planning" in caplog.text and "completed" in caplog.text
    receipt = path.read_bytes()
    monkeypatch.setattr(signing.subprocess, "Popen", lambda *a, **k: pytest.fail("repeat signer"))
    assert cli.approve_successor(op.config, **op.args) == first
    assert path.read_bytes() == receipt


@pytest.mark.parametrize("damage", ["writable", "symlink", "hardlink"])
def test_unsafe_key_metadata_refuses_before_child(operator, monkeypatch, damage):
    op = operator
    monkeypatch.setattr(signing.os, "geteuid", lambda: 0)
    monkeypatch.setattr(signing.subprocess, "Popen", lambda *a, **k: pytest.fail("unsafe signer"))
    if damage == "writable":
        op.key.chmod(0o600)
    elif damage == "hardlink":
        os.link(op.key, op.key.with_name("fixture-alias"))
    else:
        op.key.rename(op.key.with_name("fixture-target"))
        op.key.symlink_to(op.key.with_name("fixture-target"))
    with pytest.raises((ValueError, OSError)):
        signing.sign_operator_approval(op.config, op.body)


def test_nonroot_fresh_approval_refuses_before_key_open(operator, monkeypatch):
    monkeypatch.setattr(signing.os, "geteuid", lambda: 12345)
    monkeypatch.setattr(signing, "_open_without_links", lambda *a: pytest.fail("opened key"))
    with pytest.raises(ValueError, match="root publisher"):
        signing.sign_operator_approval(operator.config, operator.body)


@pytest.mark.parametrize("failure", ["exit", "different_body", "wrong_signer", "oversize"])
def test_child_failure_or_invalid_signature_never_publishes(operator, monkeypatch, failure):
    op = operator
    monkeypatch.setattr(signing.os, "geteuid", lambda: 0)
    value = signed(
        op.case,
        signer="Charlie" if failure == "wrong_signer" else "Ferdie",
        reason="changed" if failure == "different_body" else op.body.reason,
    )
    output = (
        canonical_json_bytes(value)
        if failure != "oversize"
        else b"x" * (signing.MAX_APPROVAL_BYTES + 1)
    )
    monkeypatch.setattr(
        signing.subprocess,
        "Popen",
        lambda *a, **k: SimpleNamespace(
            returncode=1 if failure == "exit" else 0,
            stdout=output,
            stderr=b"fixture-private-diagnostic",
        ),
    )
    monkeypatch.setattr(signing, "_communicate_bounded", lambda *a, **k: output)
    with pytest.raises(ValueError) as error:
        cli.approve_successor(op.config, **op.args)
    assert "fixture-private-diagnostic" not in str(error.value)
    assert not approval_path(op.case.config, op.args["cohort"], op.args["package"]).exists()


def test_hold_appearing_during_child_prevents_publication(operator, monkeypatch):
    op = operator

    def hold_then_sign(*args):
        held = op.case.settlement.model_copy(
            update={"automatic_progression_hold_cohorts": (op.args["cohort"],)}
        )
        op.case.save(Path(op.case.config.settlement_config), canonical_json_bytes(held))
        return signed(op.case)

    monkeypatch.setattr(cli, "sign_operator_approval", hold_then_sign)
    with pytest.raises(ValueError, match="became explicitly held"):
        cli.approve_successor(op.config, **op.args)
    assert not approval_path(op.case.config, op.args["cohort"], op.args["package"]).exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="real isolated fixture child requires root")
@pytest.mark.parametrize("failure", ["oversize", "timeout"])
def test_noisy_or_stalled_child_is_bounded_reaped_and_never_published(
    operator, monkeypatch, failure
):
    op = operator
    original_popen = subprocess.Popen
    collector = signing._communicate_bounded
    children = []

    def fixture_child(command, **kwargs):
        assert kwargs["stderr"] is subprocess.DEVNULL
        script = (
            "import os,sys,time;sys.stdin.buffer.read();"
            "os.write(2,b'fixture-noisy-diagnostic'*65536);"
            + ("os.write(1,b'x'*20000);" if failure == "oversize" else "")
            + "time.sleep(60)"
        )
        child = original_popen([sys.executable, "-I", "-B", "-c", script], **kwargs)
        children.append(child)
        return child

    def bounded_fixture(process, raw, *, maximum_response_bytes, timeout_seconds):
        assert maximum_response_bytes == signing.MAX_APPROVAL_BYTES
        assert timeout_seconds == 90
        return collector(
            process,
            raw,
            maximum_response_bytes=maximum_response_bytes,
            timeout_seconds=0.1 if failure == "timeout" else 5,
        )

    monkeypatch.setattr(signing.subprocess, "Popen", fixture_child)
    monkeypatch.setattr(signing, "_communicate_bounded", bounded_fixture)
    with pytest.raises((SubstrateProofVerifierError, subprocess.TimeoutExpired)):
        cli.approve_successor(op.config, **op.args)
    assert len(children) == 1 and children[0].poll() is not None
    assert not approval_path(op.case.config, op.args["cohort"], op.args["package"]).exists()
