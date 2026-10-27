"""Native publication/restart; finality and model evaluation are explicit fixtures."""

import hashlib
import json
from types import SimpleNamespace

import pytest

from umi import competition_store
from umi.competition_cli import _parser, execute
from umi.competition_cohort_baseline_review import cohort_baseline_record
from umi.competition_commands import cohort_baseline as command
from umi.competition_evaluator import EvaluatorConfig
from umi.competition_publication import PublicationReplayLimits
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_runtime_port import baseline_record_digest
from umi.competition_service import CompetitionServiceConfig, RetainedIntakeState
from umi.competition_store_migration_cli import migrate
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_baseline_history import (
    base_policy as base_policy,
)
from .test_competition_cohort_baseline_history import (
    certify,
)
from .test_competition_cohort_baseline_history import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_baseline_history import (
    model_case as model_case,
)
from .test_competition_cohort_baseline_history import (
    model_parent_context as model_parent_context,
)
from .test_competition_cohort_baseline_history import (
    policy as policy,
)
from .test_competition_cohort_baseline_history import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_baseline_history import (
    recovery as recovery,
)
from .test_competition_cohort_baseline_history import (
    retained_case as retained_case,
)
from .test_competition_cohort_baseline_history import (
    review_case as review_case,
)
from .test_competition_cohort_baseline_history import (
    runtime as runtime,
)
from .test_competition_cohort_review_boot import config_for
from .test_competition_cohort_settlement_boot import selected as selected
from .test_competition_reward_boot import (
    chain as chain,
)
from .test_competition_reward_boot import (
    chain_config as chain_config,
)
from .test_competition_reward_boot import (
    control as control,
)
from .test_competition_reward_boot import (
    inputs as inputs,
)
from .test_competition_reward_boot import (
    series_case as series_case,
)
from .test_competition_rounds import OwnedProvider
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("model_case", [("best", 2)], indirect=True),
]


@pytest.fixture(
    params=("intake", "reviewer", "settlement-coordinator", "settlement-reviewer", "evaluator")
)
def publication_case(request, retained_case, model_case, chain_config, public_deployment, tmp_path):
    source, review, baseline, b = retained_case
    policy = source.policy
    service_chain = chain_config.model_copy(
        update={"policy_sha256": digest(policy), "state_directory": str(tmp_path / "service-chain")}
    )
    if request.param == "intake":
        for participant in b["roster"].participants:
            source.admit(
                participant.record.request.signed_submission,
                participant.record.snapshot,
                participant.record.snapshot.block,
            )
        required = tuple(
            sorted(
                digest(p.record.request.signed_submission.submission)
                for p in b["roster"].participants
            )
        )
        config = CompetitionServiceConfig(
            schema="umi-competition-service-config/2",
            mode="intake_no_weight",
            policy_sha256=digest(policy),
            public_deployment=public_deployment,
            retained_state=RetainedIntakeState(
                schema="umi-competition-retained-intake-state/1",
                baseline_promotion_sha256=baseline_record_digest(baseline),
                required_submission_sha256s=required,
            ),
            state_directory=str(source.directory),
            submission_head_checkpoint_directory=str(tmp_path / "checkpoint"),
            chain=service_chain,
        )
        (tmp_path / "checkpoint").mkdir(mode=0o700)
        migrate(source.directory, policy, confirmed=True, service_config=config)
        source = command._open_store(config, policy, read_only=False)
        source.verify_retained_intake_state(
            baseline_promotion_sha256=baseline_record_digest(baseline),
            required_submission_sha256s=required,
        )
        config = config.model_copy(
            update={
                "retained_state": config.retained_state.model_copy(
                    update={
                        "baseline_promotion_sha256": baseline_record_digest(
                            cohort_baseline_record(review)
                        )
                    }
                )
            }
        )
    elif request.param == "reviewer" or request.param.startswith("settlement-"):
        if request.param == "reviewer":
            configured = config_for(request.getfixturevalue("inputs").value, tmp_path / "phase")
        else:
            configured = request.getfixturevalue("selected").config
            if request.param == "settlement-reviewer":
                peer = next(
                    e.hotkey
                    for e in configured.policy.evaluators
                    if e.hotkey != configured.proposer_hotkey
                )
                configured = configured.model_copy(
                    update={
                        "role": "reviewer",
                        "signer_hotkey": peer,
                        "executions": tuple(
                            e.model_copy(update={"signer": peer}) for e in configured.executions
                        ),
                    }
                )
        config = configured.model_copy(update={"promotion_directory": str(source.directory)})
        plans = config.series.cohorts
        review = review.model_copy(
            update={
                "series_sha256": digest(config.series),
                "source_sequence": plans[0].sequence,
                "source_cohort_sha256": digest(plans[0]),
                "target_sequence": plans[1].sequence,
                "target_cohort_sha256": digest(plans[1]),
            }
        )
        service_chain = config.chain
    else:
        limits = PublicationReplayLimits(
            maximum_roster_bytes=1_000_000,
            maximum_evidence_bytes=1_000_000,
            maximum_certificate_bytes=1_000_000,
        )
        source = EvaluatorReviewStore(tmp_path / "peer-history", policy, limits=limits)
        original = b["scenarios"][0]["artifacts"][0].job.incumbent
        source.initialize_baseline(original, model_case[-1])
        config = EvaluatorConfig(
            schema="umi-evaluator-config/1",
            policy_sha256=digest(policy),
            chain=service_chain,
            evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
            wallet_name="test",
            hotkey_name="test",
            archive_directory=str(tmp_path / "archive"),
            video_directory=str(tmp_path / "videos"),
            settlement_review_directory=str(source.directory),
            settlement_replay_limits=limits,
            round_coordinator_origin="https://rounds.example.com",
            **{
                name: str(tmp_path / name)
                for name in (
                    "wallet_path",
                    "state_directory",
                    "order_directory",
                    "reveal_directory",
                    "peer_directory",
                    "outbox_directory",
                )
            },
        )
    observer = service_chain.model_copy(
        update={"state_directory": str(tmp_path / "observer"), "collection_timeout_seconds": 10}
    )
    files = {}
    for name, value in (
        ("policy", policy),
        ("certificate", certify(review)),
        ("config", config),
        ("chain", observer),
    ):
        path = tmp_path / (name + ".json")
        path.write_bytes(canonical_json_bytes(value))
        files[name] = path
    args = _parser().parse_args(
        [
            "--policy",
            str(files["policy"]),
            "apply-cohort-baseline",
            "--confirm-quiesced-backup",
            "--certificate",
            str(files["certificate"]),
            "--" + request.param.split("-", 1)[0] + "-config",
            str(files["config"]),
            "--chain-config",
            str(files["chain"]),
        ]
    )
    return SimpleNamespace(
        source=source,
        review=review,
        baseline=baseline,
        policy=policy,
        config=config,
        args=args,
        files=files,
        observer=observer,
        kind=request.param,
    )


def install_provider(monkeypatch, heads=(230, 230)):
    events = []
    heights = iter(heads)

    class Provider(OwnedProvider):
        async def start(self):
            events.append("start")

        async def wait_ready(self):
            events.append("ready")

        async def collect(self):
            events.append("collect")
            self.block = next(heights)
            return await super().collect()

        async def aclose(self):
            events.append("close")

    monkeypatch.setattr(command, "FinalizedRegistrationProvider", lambda *_: Provider())
    return events


def forbid(*args, **kwargs):
    raise AssertionError(
        "completed/metadata-only publication must not read payloads or start finality"
    )


def test_command_publishes_and_restarts_without_repeating_completed_work(
    publication_case, monkeypatch, caplog
):
    c = publication_case
    caplog.set_level("INFO", logger="umi.competition.progress")
    monkeypatch.setattr(competition_store, "verify_preserved_bundle", forbid)
    events = install_provider(monkeypatch)
    result = execute(c.args)
    assert result["status"] == "cohort_baseline_applied"
    assert result["promotion_sha256"] == baseline_record_digest(cohort_baseline_record(c.review))
    assert result["model_sha256"] == c.review.candidate.model_sha256
    assert result["contributor_hotkey"] == c.review.candidate.contributor_hotkey
    assert not result["chain_submission_authorized"] and not result["cohort_holds_changed"]
    assert events == ["start", "ready", "collect", "collect", "close"]
    monkeypatch.setattr(command, "FinalizedRegistrationProvider", forbid)
    # Fresh command/store construction reuses the original authenticated receipt,
    # even if a new observation could no longer fit the original application window.
    repeated = execute(c.args)
    assert repeated == {**result, "status": "cohort_baseline_already_applied"}
    reader = command._open_store(c.config, c.policy, read_only=True)
    assert reader.cohort_baseline_application_status(certify(c.review)) == "completed"
    stages = [
        json.loads(r.message)
        for r in caplog.records
        if r.name == "umi.competition.progress" and r.message.startswith("{")
    ]
    for name in (
        "cohort_baseline_publication_preflight",
        "cohort_baseline_publication_finality",
        "cohort_baseline_history_append",
    ):
        stage = [r for r in stages if r.get("stage") == name]
        assert stage and stage[0]["planning_eta_seconds"] is not None
        assert stage[-1]["status"] == "completed" and stage[-1]["eta_seconds"] == 0
        assert stage[-1]["elapsed_seconds"] >= 0
    if c.kind == "intake":
        # Reopening the service's replacement binding preserves every retained
        # signed submission and its exact original required-submission list.
        expected_head = c.source.retained_submission_head()
        writer = command._open_store(c.config, c.policy, read_only=False)
        writer.verify_retained_intake_state(
            baseline_promotion_sha256=result["promotion_sha256"],
            required_submission_sha256s=c.config.retained_state.required_submission_sha256s,
        )
        assert writer.retained_submission_head() == expected_head


def test_check_only_is_existing_only_and_does_not_need_quiescence(publication_case, monkeypatch):
    c = publication_case
    c.args.check_only = True
    c.args.confirm_quiesced_backup = False
    monkeypatch.setattr(command, "FinalizedRegistrationProvider", forbid)
    monkeypatch.setattr(competition_store, "verify_preserved_bundle", forbid)
    before = hashlib.sha256(c.source.path.read_bytes()).hexdigest()
    result = execute(c.args)
    assert result["status"] == "cohort_baseline_preflight_passed" and result["application_pending"]
    assert not result["current_finalized_window_checked"]
    # Check the readonly command before reopening the fixture's writable owner:
    # that owner can legitimately checkpoint its WAL on a later connection.
    assert hashlib.sha256(c.source.path.read_bytes()).hexdigest() == before
    assert command._open_store(c.config, c.policy, read_only=True).baseline() == c.baseline


@pytest.mark.parametrize("heads", [(219,), (251,), (230, 251)])
def test_owned_window_refusal_preserves_baseline_and_closes_provider(
    publication_case, monkeypatch, heads
):
    c = publication_case
    events = install_provider(monkeypatch, heads)
    with pytest.raises(ValueError, match="application window"):
        execute(c.args)
    assert c.source.baseline() == c.baseline
    assert events == ["start", "ready", *("collect" for _ in heads), "close"]


def test_missing_ledger_is_not_recreated(publication_case, monkeypatch, tmp_path):
    c = publication_case
    missing = tmp_path / "missing"
    field = {
        "intake": "state_directory",
        "reviewer": "promotion_directory",
        "settlement-coordinator": "promotion_directory",
        "settlement-reviewer": "promotion_directory",
        "evaluator": "settlement_review_directory",
    }[c.kind]
    c.files["config"].write_bytes(
        canonical_json_bytes(c.config.model_copy(update={field: str(missing)}))
    )
    monkeypatch.setattr(command, "FinalizedRegistrationProvider", forbid)
    with pytest.raises((ValueError, FileNotFoundError)):
        execute(c.args)
    assert not missing.exists()


def test_damaged_completed_receipt_requires_repair_without_resigning_or_replay(
    publication_case, monkeypatch
):
    c = publication_case
    install_provider(monkeypatch)
    execute(c.args)
    key = "cohort_baseline_receipt:" + str(c.review.previous.sequence + 1)
    with c.source._transaction() as db:
        db.execute("DELETE FROM metadata WHERE key=?", (key,))
    monkeypatch.setattr(command, "FinalizedRegistrationProvider", forbid)
    with pytest.raises(ValueError, match="receipt missing"):
        execute(c.args)


def test_observer_cannot_use_service_state_or_checkpoints(publication_case, monkeypatch):
    c = publication_case
    forbidden = (
        c.config.submission_head_checkpoint_directory
        if c.kind == "intake"
        else c.config.signing.directory
        if c.kind == "reviewer"
        else c.config.executions[0].directory
        if c.kind.startswith("settlement-")
        else c.config.wallet_path
    )
    c.files["chain"].write_bytes(
        canonical_json_bytes(c.observer.model_copy(update={"state_directory": forbidden}))
    )
    monkeypatch.setattr(command, "FinalizedRegistrationProvider", forbid)
    with pytest.raises(ValueError, match="separate history and finality"):
        execute(c.args)
    assert c.source.baseline() == c.baseline


def test_unauthorized_certificate_is_rejected_before_opening_source(publication_case, monkeypatch):
    c = publication_case
    c.files["certificate"].write_bytes(canonical_json_bytes(certify(c.review, ("Charlie",))))
    monkeypatch.setattr(command, "_open_store", forbid)
    with pytest.raises(ValueError):
        execute(c.args)


def test_command_never_accepts_an_operator_block_override(retained_case):
    with pytest.raises(SystemExit):
        _parser().parse_args(
            [
                "--policy",
                "policy.json",
                "apply-cohort-baseline",
                "--certificate",
                "cert.json",
                "--chain-config",
                "chain.json",
                "--reviewer-config",
                "reviewer.json",
                "--current-block",
                "230",
            ]
        )
