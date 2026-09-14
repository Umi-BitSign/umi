"""Mixed CLI replay uses synthetic evidence and grants no chain-write authority."""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path

import pytest
from pydantic import ValidationError

from umi.competition_cli import _parser, execute
from umi.competition_package import CompetitionPackageEvidence
from umi.competition_publication import build_settlement_publication
from umi.competition_settlement import CompetitionSettlement
from umi.protocol import canonical_json_bytes

from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_operations_cli import put
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_package_cli import arguments
from .test_competition_publication import _certificate
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_void_settlement import mixed as mixed
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import snapshot


def encoded_entries(pairs):
    return [
        {
            "submission": signed.model_dump(mode="json", by_alias=True),
            "evidence": evidence.model_dump(mode="json", by_alias=True),
        }
        for signed, evidence in pairs
    ]


async def test_mixed_cli_settle_verify_prepare_replay_and_retry(
    mixed, tmp_path, replay_limits, package_limits, release_identity, worker_capacity, monkeypatch
):
    store, round_, suite, submissions, pairs, void, cutoff = mixed
    policy_path = put(tmp_path, "policy.json", store.policy)
    entries = encoded_entries(pairs)
    settle_args = arguments(
        "settle-round",
        policy_path,
        {
            "state": store.directory,
            "inputs": put(
                tmp_path,
                "settlement-inputs.json",
                {
                    "round": round_.model_dump(mode="json", by_alias=True),
                    "suite": suite.model_dump(mode="json", by_alias=True),
                    "entries": entries,
                },
            ),
            "snapshot": put(tmp_path, "snapshot.json", snapshot(160)),
            "current-block": 160,
        },
    )
    # A parseable certificate still needs an actual retained cutoff receipt.
    with pytest.raises(ValueError, match="first observed after cutoff"):
        execute(_parser().parse_args(settle_args))
    store.record_void_evaluation(evidence=void, suite=suite, observed_block=150)
    first = execute(_parser().parse_args(settle_args))
    assert execute(_parser().parse_args(settle_args)) == first
    settlement = CompetitionSettlement.model_validate_json(canonical_json_bytes(first))
    assert settlement.schema_ == "umi-competition-settlement/2"
    assert settlement.roster == round_.roster and len(settlement.results) == 3
    assert {
        a.uid: Fraction(int(a.numerator), int(a.denominator))
        for a in settlement.projection.allocations
    } == {6: Fraction(7, 10), 247: Fraction(3, 10)}
    certificate = _certificate(
        build_settlement_publication(
            cutoff_certificate=cutoff,
            retained_settlement=settlement,
            submissions=submissions,
            evidence=pairs,
            policy=store.policy,
            limits=replay_limits,
        )
    )
    common = {
        "cutoff-certificate": put(tmp_path, "cutoff.json", cutoff),
        "certificate": put(tmp_path, "certificate.json", certificate),
        "retained-settlement": put(tmp_path, "settlement.json", settlement),
        "roster": put(
            tmp_path,
            "roster.json",
            {"submissions": [s.model_dump(mode="json", by_alias=True) for s in submissions]},
        ),
        "evidence": put(tmp_path, "evidence.json", {"entries": entries}),
        "replay-limits": put(tmp_path, "replay-limits.json", replay_limits),
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("CLI replay attempted a wallet, network, or subprocess operation")

    monkeypatch.setattr("bittensor.Wallet", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    verified = execute(
        _parser().parse_args(arguments("verify-settlement-publication", policy_path, common))
    )
    assert verified["status"] == "publication_replayed"
    assert verified["chain_submission_authorized"] is False
    assert verified["publication_timing_proven"] is False
    limits_path = put(tmp_path, "package-limits.json", package_limits)
    release_path = put(tmp_path, "release.json", release_identity)
    prepare_args = arguments(
        "prepare-settlement-package",
        policy_path,
        {
            **common,
            "package-limits": limits_path,
            "release-identity": release_path,
            "destination": tmp_path / "packages",
        },
    )
    prepared = execute(_parser().parse_args(prepare_args))
    package_path = Path(prepared["package_path"])
    try:
        assert execute(_parser().parse_args(prepare_args)) == prepared
        payload = CompetitionPackageEvidence.model_validate_json(
            (package_path / "evidence.json").read_bytes()
        )
        assert payload.schema_ == "umi-competition-replay-evidence/2"
        replay_args = arguments(
            "replay-settlement-package",
            policy_path,
            {
                "package": package_path,
                "expected-package-sha256": prepared["package_sha256"],
                "package-limits": limits_path,
                "release-identity": release_path,
                "worker-capacity": put(tmp_path, "capacity.json", worker_capacity),
                "state": tmp_path / "worker",
            },
        )
        replayed = execute(_parser().parse_args(replay_args))
        assert execute(_parser().parse_args(replay_args)) == replayed
        assert replayed["receipt"]["status"] == "replayed_no_weight"
        assert replayed["receipt"]["chain_submission_authorized"] is False
        assert replayed["current_status"]["held"] is False
    finally:
        # Only restore permissions on the directory created by this fixture.
        assert package_path.parent == tmp_path / "packages" and not package_path.is_symlink()
        package_path.chmod(0o700)


@pytest.mark.parametrize(
    "command", ["replay-independent-evaluation", "record-independent-evaluation"]
)
async def test_void_cli_does_not_treat_void_as_a_score(mixed, tmp_path, command):
    store, round_, suite, _, _, void, _ = mixed
    values = {
        "submission": put(tmp_path, "submission.json", void.order.order.submission),
        "evaluation": put(tmp_path, "void.json", void),
        "round": put(tmp_path, "round.json", round_),
        "suite": put(tmp_path, "suite.json", suite),
    }
    if command == "record-independent-evaluation":
        values.update({"state": store.directory, "observed-block": 150})
    else:
        values["current-block"] = 150
    with pytest.raises(ValidationError):
        execute(
            _parser().parse_args(
                arguments(command, put(tmp_path, "policy.json", store.policy), values)
            )
        )
