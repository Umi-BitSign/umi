"""Authoritative hold configs and retained operator approval never imply a row."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_transition_controls as controls
from umi.competition_cohort_admission_host import AdmissionOwnerConfig
from umi.competition_cohort_intake import CohortIntakeConfig
from umi.competition_cohort_lifecycle_host import LifecycleHostConfig
from umi.competition_cohort_request_start import RequestStartConfig
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_host import ServiceAdmissionHostConfig
from umi.competition_cohort_settlement_config import (
    SettlementOriginalSources,
    SettlementServiceConfig,
)
from umi.competition_reward_timing import IMMEDIATE_ACTIVATION_RULE
from umi.competition_service import CompetitionServiceConfig, RetainedIntakeState
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_settlement_boot import chain as chain
from .test_competition_cohort_settlement_boot import chain_config as chain_config
from .test_competition_cohort_settlement_boot import control as control
from .test_competition_cohort_settlement_boot import inputs as inputs
from .test_competition_cohort_settlement_boot import policy as policy
from .test_competition_cohort_settlement_boot import selected as selected
from .test_competition_cohort_settlement_boot import series_case as series_case
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import wallet


@pytest.fixture
def controls_case(selected, public_deployment, tmp_path):
    v = selected.config
    root = tmp_path / "admission-service"
    who = wallet("Charlie").hotkey.ss58_address
    intake = CohortIntakeConfig(
        directory=str(root / "intake"),
        cohorts=tuple(
            dict(cohort_sha256=key, authority_sha256=digest(v.series.recovery.authority))
            for key in sorted(digest(p) for p in v.series.cohorts)
        ),
    )
    source = SettlementOriginalSources(
        intake=intake,
        eligible_tracks=("endpoint", "model"),
        **{
            key: str(root / key)
            for key in (
                "round_directory",
                "objects_directory",
                "catalogs_directory",
                "transport_directory",
                "pulses_directory",
            )
        },
    )
    service = ServiceAdmissionHostConfig(
        schema="umi-cohort-service-admission-host/5",
        series=v.series,
        manifest=v.manifest,
        queue_directory=str(root / "queue"),
        inputs_directory=str(root / "inputs"),
        admission_owner=AdmissionOwnerConfig(
            schema="umi-cohort-admission-owner/1",
            directory=str(root / "owner"),
            owner_hotkey=who,
            owner_key_file=str(root / "owner-key"),
            export_token_file=str(root / "export-token"),
            listen_port=18090,
            reviewers=(
                CohortReviewPeerConfig(
                    signer=wallet("Dave").hotkey.ss58_address,
                    origin="https://reviewer.example",
                    token_file=str(root / "peer-token"),
                ),
            ),
        ),
        lifecycle=LifecycleHostConfig(
            schema="umi-cohort-lifecycle-host/1",
            directory=str(root / "lifecycle"),
            request_start=RequestStartConfig(
                schema="umi-cohort-request-start-config/1",
                directory=str(root / "request-start"),
                first_cohort_not_before_unix_ms=1,
            ),
            request_completion_directory=str(root / "completion"),
            settlement_history_directory=str(root / "history"),
            proof_export_directory=str(root / "proof-export"),
            sources=source,
            public_origin="https://intake.example",
        ),
    )
    admission = CompetitionServiceConfig(
        schema="umi-competition-service-config/3",
        mode="intake_no_weight",
        policy_sha256=digest(v.policy),
        public_deployment=public_deployment,
        retained_state=RetainedIntakeState(
            schema="umi-competition-retained-intake-state/1",
            baseline_promotion_sha256="11" * 32,
            required_submission_sha256s=(),
        ),
        state_directory=str(root / "state"),
        submission_head_checkpoint_directory=str(root / "checkpoint"),
        chain=v.chain,
        recoverable_intake=intake,
        recoverable_service=service,
    )
    path = tmp_path / "admission.json"
    selected.save(path, canonical_json_bytes(admission))
    approvals = tmp_path / "approvals"
    approvals.mkdir(mode=0o755)
    config = controls.RewardTransitionControls(
        admission_config=str(path),
        settlement_config=str(selected.path),
        operator_approval_directory=str(approvals),
    )
    reader = controls.RewardTransitionControlReader(config, series=v.series, policy=v.policy)
    return SimpleNamespace(
        config=config,
        reader=reader,
        admission=admission,
        settlement=v,
        series=v.series,
        policy=v.policy,
        cohorts=[digest(p) for p in v.series.cohorts],
        save=selected.save,
    )


def signed(c, *, signer="Ferdie", reason="Operator requests the certified successor now"):
    body = controls.RewardTransitionApproval(
        schema="umi-reward-transition-approval/1",
        series_sha256=digest(c.series),
        predecessor_decision_sha256="ab" * 32,
        successor_cohort_sha256=c.cohorts[1],
        successor_package_sha256="cd" * 32,
        reason=reason,
    )
    return controls.SignedRewardTransitionApproval(
        approval=body, signature=sign_object(body, wallet(signer))
    )


def test_holds_union_authoritative_sources_and_reuse_unchanged_full_loads(
    controls_case, monkeypatch
):
    c = controls_case
    lifecycle = c.admission.recoverable_service.lifecycle.model_copy(
        update={"automatic_progression_hold_cohorts": (c.cohorts[1],)}
    )
    admission = c.admission.model_copy(
        update={
            "recoverable_service": c.admission.recoverable_service.model_copy(
                update={"lifecycle": lifecycle}
            )
        }
    )
    settlement = c.settlement.model_copy(
        update={"automatic_progression_hold_cohorts": (c.cohorts[2],)}
    )
    c.save(Path(c.config.admission_config), canonical_json_bytes(admission))
    c.save(Path(c.config.settlement_config), canonical_json_bytes(settlement))
    assert c.reader.held(c.cohorts[1]) and c.reader.held(c.cohorts[2])
    assert not c.reader.held(c.cohorts[0])
    with monkeypatch.context() as unchanged:

        def repeated(*args):
            pytest.fail("unchanged authoritative hold config reloaded or rebound")

        unchanged.setattr(controls, "_admission", repeated)
        unchanged.setattr(controls, "_settlement", repeated)
        unchanged.setattr(c.reader, "_series", repeated)
        assert c.reader.held(c.cohorts[1])
    c.save(Path(c.config.admission_config), canonical_json_bytes(c.admission))
    assert not c.reader.held(c.cohorts[1]) and c.reader.held(c.cohorts[2])


@pytest.mark.parametrize(
    "damage", ["missing", "malformed", "writable", "symlink", "wrong_authority"]
)
def test_hold_damage_never_becomes_unheld(controls_case, damage):
    c = controls_case
    assert not c.reader.held(c.cohorts[1])
    path = Path(c.config.admission_config)
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        c.save(path, b"{")
    elif damage == "writable":
        path.chmod(0o644)
    elif damage == "symlink":
        original = path.with_suffix(".original")
        path.rename(original)
        path.symlink_to(original)
    else:
        intake = c.admission.recoverable_intake
        bad = intake.model_copy(
            update={
                "cohorts": tuple(
                    x.model_copy(update={"authority_sha256": "ff" * 32}) for x in intake.cohorts
                )
            }
        )
        c.save(
            path, canonical_json_bytes(c.admission.model_copy(update={"recoverable_intake": bad}))
        )
    with pytest.raises((ValueError, OSError)):
        c.reader.held(c.cohorts[1])


@pytest.mark.parametrize("role", ["admission", "settlement"])
def test_independent_hold_reader_never_traverses_owner_private_paths(
    controls_case, monkeypatch, role
):
    c = controls_case
    owner = c.admission if role == "admission" else c.settlement
    value = json.loads(canonical_json_bytes(owner))

    def private_paths(item):
        if isinstance(item, str) and item.startswith("/"):
            return "/other-private-owner" + item
        if isinstance(item, list):
            return [private_paths(child) for child in item]
        if isinstance(item, dict):
            return {key: private_paths(child) for key, child in item.items()}
        return item

    value = private_paths(value)
    if role == "admission":
        value["recoverable_service"]["lifecycle"]["automatic_progression_hold_cohorts"] = [
            c.cohorts[1]
        ]
    else:
        value["automatic_progression_hold_cohorts"] = [c.cohorts[1]]
    raw = canonical_json_bytes(value)
    path = Path(getattr(c.config, role + "_config"))
    c.save(path, raw)

    def retained_identity(info):
        # Ordinary reads may advance filesystem access time.
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    before = retained_identity(path.stat())
    probes = []
    for name in ("is_symlink", "resolve", "stat", "lstat"):
        original = getattr(Path, name)

        def probe(path, *args, method=original, **kwargs):
            if str(path).startswith("/other-private-owner"):
                probes.append(str(path))
                raise PermissionError("another service owns this private path")
            return method(path, *args, **kwargs)

        monkeypatch.setattr(Path, name, probe)
    full = CompetitionServiceConfig if role == "admission" else SettlementServiceConfig
    with pytest.raises(PermissionError, match="another service"):
        full.model_validate_json(raw)
    assert probes  # Reproduce the old full-config loader failure first.
    probes.clear()
    assert c.reader.held(c.cohorts[1])
    assert not c.reader.held(c.cohorts[2])
    assert probes == []
    assert retained_identity(path.stat()) == before and path.read_bytes() == raw
    with monkeypatch.context() as repeated:
        repeated.setattr(controls, "_admission", lambda *a: pytest.fail("admission reloaded"))
        repeated.setattr(controls, "_settlement", lambda *a: pytest.fail("settlement reloaded"))
        assert c.reader.held(c.cohorts[1])


@pytest.mark.parametrize("role", ["admission", "settlement"])
@pytest.mark.parametrize(
    "damage",
    [
        "duplicate_hold",
        "unknown_hold",
        "chain_policy",
        "manifest",
        "series",
        "role",
        "duplicate_json",
    ],
)
def test_read_only_hold_source_keeps_policy_authority_and_hold_validation(
    controls_case, role, damage
):
    c = controls_case
    value = json.loads(canonical_json_bytes(c.admission if role == "admission" else c.settlement))
    selected = value["recoverable_service"] if role == "admission" else value
    lifecycle = selected["lifecycle"] if role == "admission" else selected
    if damage == "duplicate_hold":
        lifecycle["automatic_progression_hold_cohorts"] = [c.cohorts[1], c.cohorts[1]]
    elif damage == "unknown_hold":
        lifecycle["automatic_progression_hold_cohorts"] = ["fe" * 32]
    elif damage == "chain_policy":
        value["chain"]["policy_sha256"] = "fe" * 32
    elif damage == "manifest":
        selected["manifest"]["policy_sha256"] = "fe" * 32
    elif damage == "series":
        selected["series"]["recovery"]["authority"]["policy_sha256"] = "fe" * 32
    elif damage == "role":
        value["mode" if role == "admission" else "role"] = "reviewer"
    raw = canonical_json_bytes(value)
    if damage == "duplicate_json":
        raw = raw[:-1] + b',"chain":' + canonical_json_bytes(value["chain"]) + b"}"
    c.save(Path(getattr(c.config, role + "_config")), raw)
    with pytest.raises(ValueError):
        c.reader.held(c.cohorts[1])


@pytest.mark.parametrize("field", ["intake", "lifecycle_intake", "execution"])
def test_read_only_hold_source_refuses_changed_bound_authority(controls_case, field):
    c = controls_case
    role = "settlement" if field == "execution" else "admission"
    value = json.loads(canonical_json_bytes(c.settlement if role == "settlement" else c.admission))
    if field == "intake":
        bindings = value["recoverable_intake"]["cohorts"]
    elif field == "lifecycle_intake":
        bindings = value["recoverable_service"]["lifecycle"]["sources"]["intake"]["cohorts"]
    else:
        bindings = value["executions"][0]["cohorts"]
    bindings[0]["authority_sha256"] = "fe" * 32
    c.save(Path(getattr(c.config, role + "_config")), canonical_json_bytes(value))
    with pytest.raises(ValueError):
        c.reader.held(c.cohorts[1])


def test_signed_approval_roundtrip_reuse_and_exact_conflict(controls_case, monkeypatch):
    c = controls_case
    value = signed(c)
    b = value.approval
    args = (b.successor_cohort_sha256, b.predecessor_decision_sha256, b.successor_package_sha256)
    assert c.reader.approval(*args) is None
    path = controls.publish_reward_transition_approval(c.config, value, series=c.series)
    before = path.stat()
    assert c.reader.approval(*args) == value
    assert controls.publish_reward_transition_approval(c.config, value, series=c.series) == path
    assert path.stat() == before
    with monkeypatch.context() as unchanged:
        unchanged.setattr(
            controls, "verify_signature", lambda *a: pytest.fail("unchanged approval reverified")
        )
        assert c.reader.approval(*args) == value
    with pytest.raises(ValueError, match="different signed request"):
        controls.publish_reward_transition_approval(
            c.config, signed(c, reason="changed"), series=c.series
        )
    with pytest.raises(ValueError, match="exact predecessor"):
        c.reader.approval(args[0], "ef" * 32, args[2])
    path.unlink()
    with pytest.raises(ValueError, match="lost"):
        c.reader.approval(*args)


def test_approval_rejects_wrong_signer_tampering_and_proposal_mismatch(controls_case):
    c = controls_case
    with pytest.raises(ValueError, match="authority"):
        controls.verify_transition_approval(signed(c, signer="Charlie"), series=c.series)
    value = signed(c)
    invalid = value.model_copy(
        update={"signature": value.signature.model_copy(update={"signature": "0x" + "00" * 64})}
    )
    with pytest.raises(ValueError):
        controls.verify_transition_approval(invalid, series=c.series)
    b = value.approval
    proposal = SimpleNamespace(
        series_sha256=b.series_sha256,
        cohort_sha256=b.successor_cohort_sha256,
        package_sha256=b.successor_package_sha256,
        activation_rule=None,
        early_release=SimpleNamespace(
            predecessor_decision_sha256=b.predecessor_decision_sha256, reason=b.reason
        ),
    )
    assert controls.verify_transition_approval(value, series=c.series, proposal=proposal) == value
    proposal.early_release.reason = "changed"
    with pytest.raises(ValueError, match="exact proposed release"):
        controls.verify_transition_approval(value, series=c.series, proposal=proposal)


def test_publication_recovers_pending_file_and_preserves_unrelated_hardlink(controls_case):
    c = controls_case
    value = signed(c)
    b = value.approval
    path = controls.approval_path(c.config, b.successor_cohort_sha256, b.successor_package_sha256)
    pending = path.with_name(path.name + ".pending")
    c.save(pending, b"interrupted partial bytes")
    controls.publish_reward_transition_approval(c.config, value, series=c.series)
    assert not pending.exists()
    assert path.read_bytes() == canonical_json_bytes(value)
    path.unlink()
    unrelated = path.parent / "keep"
    unrelated.write_bytes(b"preserve")
    import os

    os.link(unrelated, pending)
    with pytest.raises(ValueError, match="independently owned"):
        controls.publish_reward_transition_approval(c.config, value, series=c.series)
    assert unrelated.read_bytes() == b"preserve"


def test_operator_cli_reuses_retained_request_without_reopening_key(controls_case, monkeypatch):
    from umi import competition_reward_transition_cli as cli

    c = controls_case
    config = SimpleNamespace(
        role="coordinator",
        reward_transition=c.config,
        series=c.series,
        policy=c.policy,
        control_key_file="/unused/operator-key",
    )
    body = signed(c).approval
    args = dict(
        predecessor=body.predecessor_decision_sha256,
        cohort=body.successor_cohort_sha256,
        package=body.successor_package_sha256,
        reason=body.reason,
    )
    opened = []

    def sign(_config, request):
        opened.append(request)
        return controls.SignedRewardTransitionApproval(
            approval=request, signature=sign_object(request, wallet("Ferdie"))
        )

    monkeypatch.setattr(cli, "sign_operator_approval", sign)
    first = cli.approve_successor(config, **args)
    assert first["chain_submission_authorized"] is False and len(opened) == 1
    assert opened[0].schema_ == "umi-reward-transition-approval/2"
    assert first["activation_rule"] == IMMEDIATE_ACTIVATION_RULE
    with monkeypatch.context() as repeated:
        repeated.setattr(
            cli,
            "sign_operator_approval",
            lambda *a: pytest.fail("re-signed exact retained request"),
        )
        assert cli.approve_successor(config, **args) == first
        with pytest.raises(ValueError, match="different exact"):
            cli.approve_successor(config, **(args | {"reason": "changed"}))
        config.role = "reviewer"
        with pytest.raises(ValueError, match="coordinator"):
            cli.approve_successor(config, **args)
        config.role = "coordinator"
        held = c.settlement.model_copy(
            update={"automatic_progression_hold_cohorts": (body.successor_cohort_sha256,)}
        )
        c.save(Path(c.config.settlement_config), canonical_json_bytes(held))
        with pytest.raises(ValueError, match="explicitly held"):
            cli.approve_successor(config, **args)


def test_operator_cli_keeps_legacy_approval_bytes_and_timing(controls_case, monkeypatch):
    from umi import competition_reward_transition_cli as cli

    c = controls_case
    original = signed(c)
    path = controls.publish_reward_transition_approval(c.config, original, series=c.series)
    raw = path.read_bytes()
    config = SimpleNamespace(
        role="coordinator", reward_transition=c.config, series=c.series, policy=c.policy
    )
    monkeypatch.setattr(
        cli, "sign_operator_approval", lambda *args: pytest.fail("legacy approval was re-signed")
    )
    body = original.approval
    result = cli.approve_successor(
        config,
        predecessor=body.predecessor_decision_sha256,
        cohort=body.successor_cohort_sha256,
        package=body.successor_package_sha256,
        reason=body.reason,
    )
    assert result["activation_rule"] is None
    assert path.read_bytes() == raw and b'"activation_rule"' not in raw
