from __future__ import annotations

import os

import pytest

from umi.competition_cli import (
    IndependentReplayEntry,
    PublicationEvidenceInputs,
    PublicationRoster,
    _parser,
    execute,
)
from umi.competition_publication import cutoff_publication_digest, settlement_publication_digest
from umi.protocol import canonical_json_bytes

from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_upgrade import inputs as inputs
from .test_competition_upgrade import installed as installed
from .test_open_competition import policy as policy


def put(root, name, value):
    path = root / name
    path.write_bytes(canonical_json_bytes(value))
    return str(path)


@pytest.mark.parametrize("settlement", [False, True])
def test_cli_replays_signed_publications_without_weight_authority(
    tmp_path,
    policy,
    replay_limits,
    settlement,
):
    s = _scenario(policy, tmp_path, replay_limits)
    argv = [
        "--policy",
        put(tmp_path, "policy.json", policy),
        "verify-settlement-publication" if settlement else "verify-cutoff-publication",
        "--certificate",
        put(
            tmp_path,
            "certificate.json",
            s.settlement_certificate if settlement else s.cutoff_certificate,
        ),
        "--roster",
        put(tmp_path, "roster.json", PublicationRoster(submissions=s.submissions)),
        "--replay-limits",
        put(tmp_path, "limits.json", replay_limits),
    ]
    if settlement:
        argv += [
            "--cutoff-certificate",
            put(tmp_path, "cutoff.json", s.cutoff_certificate),
            "--retained-settlement",
            put(tmp_path, "retained.json", s.settlement),
            "--evidence",
            put(
                tmp_path,
                "evidence.json",
                PublicationEvidenceInputs(
                    entries=tuple(
                        IndependentReplayEntry(submission=signed, evidence=evidence)
                        for signed, evidence in s.evidence
                    )
                ),
            ),
        ]
    result = execute(_parser().parse_args(argv))
    assert result["chain_submission_authorized"] is False
    assert result["publication_timing_proven"] is False
    assert result["publication_sha256"] == (
        settlement_publication_digest(s.settlement_publication)
        if settlement
        else cutoff_publication_digest(s.cutoff_publication)
    )


def test_cli_upgrade_inspection_never_authorizes_mutation(installed, tmp_path, policy):
    args = _parser().parse_args(
        [
            "--policy",
            put(tmp_path, "policy.json", policy),
            "inspect-host-upgrade",
            "--config",
            str(installed.config_path),
            "--accepted-directive",
            put(tmp_path, "accepted.json", installed.signed),
            "--expected-hotkey",
            installed.config.validator_hotkey,
            "--expected-platform",
            installed.config.target_platform,
            "--service-uid",
            str(os.geteuid()),
            "--staged-directory",
            str(installed.staged_root),
        ]
    )
    result = execute(args)
    assert result["readiness"] == "hold"
    assert result["may_stop_service"] is False
    assert result["host_upgrade_authorized"] is False
    assert result["chain_submission_authorized"] is False
    assert result["verified_checks"]
    assert str(tmp_path) not in canonical_json_bytes(result).decode()


def test_feed_cli_binds_only_loopback_with_connection_limits(tmp_path, monkeypatch, policy):
    from .test_competition_authorization import build_authorization_fixture

    fixture = build_authorization_fixture(policy)
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: calls.append(kwargs))
    args = _parser().parse_args(
        [
            "--policy",
            put(tmp_path, "policy.json", fixture.policy),
            "serve-assignment-feed",
            "--legacy-policy",
            put(tmp_path, "legacy.json", fixture.legacy_policy),
            "--state",
            str(tmp_path / "journal"),
            "--nonce-path",
            str(tmp_path / "nonces" / "nonce.db"),
        ]
    )
    result = execute(args)
    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 8099,
            "limit_concurrency": 32,
            "backlog": 64,
            "timeout_keep_alive": 5,
        }
    ]
    assert result["chain_submission_authorized"] is False
