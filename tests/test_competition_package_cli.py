from __future__ import annotations

from pathlib import Path

import pytest

from umi.competition_cli import (
    IndependentReplayEntry,
    PublicationEvidenceInputs,
    PublicationRoster,
    _parser,
    execute,
)
from umi.protocol import canonical_json_bytes

from .test_competition_operations_cli import put
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy


def arguments(command, policy_path, values):
    result = ["--policy", policy_path, command]
    for name, value in values.items():
        result += ["--" + name, str(value)]
    return result


@pytest.fixture
def package_commands(
    tmp_path, policy, replay_limits, package_limits, release_identity, worker_capacity
):
    scenario = _scenario(policy, tmp_path, replay_limits)
    policy_path = put(tmp_path, "cli-policy.json", policy)
    identity_path = put(tmp_path, "cli-release.json", release_identity)
    limits_path = put(tmp_path, "cli-package-limits.json", package_limits)
    prepared_paths: set[Path] = set()
    prepare = arguments(
        "prepare-settlement-package",
        policy_path,
        {
            "cutoff-certificate": put(tmp_path, "cli-cutoff.json", scenario.cutoff_certificate),
            "certificate": put(tmp_path, "cli-certificate.json", scenario.settlement_certificate),
            "retained-settlement": put(tmp_path, "cli-settlement.json", scenario.settlement),
            "roster": put(
                tmp_path, "cli-roster.json", PublicationRoster(submissions=scenario.submissions)
            ),
            "evidence": put(
                tmp_path,
                "cli-evidence.json",
                PublicationEvidenceInputs(
                    entries=tuple(
                        IndependentReplayEntry(submission=signed, evidence=evidence)
                        for signed, evidence in scenario.evidence
                    )
                ),
            ),
            "replay-limits": put(tmp_path, "cli-replay-limits.json", replay_limits),
            "release-identity": identity_path,
            "package-limits": limits_path,
            "destination": tmp_path / "packages",
        },
    )

    def replay(prepared):
        prepared_paths.add(Path(prepared["package_path"]))
        return arguments(
            "replay-settlement-package",
            policy_path,
            {
                "package": prepared["package_path"],
                "expected-package-sha256": prepared["package_sha256"],
                "release-identity": identity_path,
                "package-limits": limits_path,
                "worker-capacity": put(tmp_path, "cli-worker-capacity.json", worker_capacity),
                "state": tmp_path / "replay-worker",
            },
        )

    try:
        yield prepare, replay
    finally:
        for path in prepared_paths:
            assert path.parent == tmp_path / "packages"
            assert not path.is_symlink()
            path.chmod(0o700)


def test_prepare_replay_and_restart_need_no_wallet_network_or_subprocess(
    package_commands, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("settlement replay attempted an external operation")

    monkeypatch.setattr("bittensor.Wallet", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    prepare, replay = package_commands
    prepared = execute(_parser().parse_args(prepare))
    first = execute(_parser().parse_args(replay(prepared)))
    second = execute(_parser().parse_args(replay(prepared)))

    assert first["receipt"]["status"] == "replayed_no_weight"
    assert first["receipt"]["chain_submission_authorized"] is False
    assert first["receipt"]["runtime_identity_authenticated"] is False
    assert first["current_status"]["held"] is False
    assert second["current_status"]["held"] is False
    assert canonical_json_bytes(first["receipt"]) == canonical_json_bytes(second["receipt"])


@pytest.mark.parametrize("mismatch", ["package", "policy", "release"])
def test_replay_cli_rejects_mismatched_expected_bindings(
    package_commands, tmp_path, policy, release_identity, mismatch
):
    prepare, replay = package_commands
    prepared = execute(_parser().parse_args(prepare))
    argv = replay(prepared)
    if mismatch == "package":
        name, replacement = "--expected-package-sha256", "00" * 32
    elif mismatch == "policy":
        name = "--policy"
        replacement = put(
            tmp_path,
            "other-policy.json",
            policy.model_copy(update={"endpoint_reward_bps": 6000, "model_reward_bps": 4000}),
        )
    else:
        name = "--release-identity"
        replacement = put(
            tmp_path,
            "other-release.json",
            release_identity.model_copy(update={"release_bundle_sha256": "ae" * 32}),
        )
    argv[argv.index(name) + 1] = replacement
    with pytest.raises(ValueError):
        execute(_parser().parse_args(argv))


def test_replay_cli_cannot_accept_wallet_options(package_commands):
    prepare, replay = package_commands
    prepared = execute(_parser().parse_args(prepare))
    with pytest.raises(SystemExit) as error:
        _parser().parse_args([*replay(prepared), "--wallet-name", "not-used"])
    assert error.value.code == 2
